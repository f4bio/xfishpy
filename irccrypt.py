#!/usr/bin/env python
##
## irccrypt.py - various cryptographic methods for IRC + IRCSRP reference
## implementation.
##
## Copyright (c) 2009, Bjorn Edstrom <be@bjrn.se>
## 
## Permission to use, copy, modify, and distribute this software for any
## purpose with or without fee is hereby granted, provided that the above
## copyright notice and this permission notice appear in all copies.
## 
## THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
## WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
## MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
## ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
## WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
## ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
## OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
##
""" Library for various common cryptographic methods used on IRC.
Currently supports:
* blowcrypt - as used by for Fish et al.
* Mircryption-CBC - an improvement of blowcrypt using the CBC mode.
* DH1080 - A Diffie Hellman key exchange adapted for IRC usage.
Additionally, implements the new IRCSRP method as described at
http://www.bjrn.se/ircsrp
Sample usage:
blowcrypt, Fish etc
-------------------
>>> b = Blowfish("password")
>>> blowcrypt_pack("Hi bob!", b)
'+OK BRurM1bWPZ1.'
>>> blowcrypt_unpack(_, b)
'Hi bob!'
Mircryption-CBC
---------------
>>> b = BlowfishCBC("keyTest")
>>> mircryption_cbc_pack("12345678", b)
'+OK *oXql/CRQbadX+5kl68g1uQ=='
DH1080
------
>>> alice = DH1080Ctx()
>>> bob = DH1080Ctx()
>>> dh1080_pack(alice)
'DH1080_INIT qStH1LjBpb47s0XY80W9e3efrVSh2Qfq...<snip>
>>> dh1080_unpack(_, bob)
True
>>> dh1080_pack(bob)
'DH1080_FINISH mjyk//fqPoEwp5JfbJtzDmlfpzmtME...<snip>
>>> dh1080_unpack(_, alice)
True
>>> dh1080_secret(alice)
'tfu4Qysoy56OYeckat1HpJWzi+tJVx/cm+Svzb6eunQ'
>>> dh1080_secret(bob)
'tfu4Qysoy56OYeckat1HpJWzi+tJVx/cm+Svzb6eunQ'
For more information, see the accompanying article at http://www.bjrn.se/
"""
__author__ = "Bjorn Edstrom <be@bjrn.se>"
__date__ = "2009-01-25"
__version__ = "0.1.1"
import base64
import hashlib
import struct
import time
from math import log
try:
    import Crypto.Cipher.Blowfish
    import Crypto.Cipher.AES
except ImportError:
    print("This module requires PyCrypto / The Python Cryptographic Toolkit.")
    print("Get it from http://www.dlitz.net/software/pycrypto/.")
    raise
from os import urandom
##
## Preliminaries.
##
class MalformedError(Exception):
    pass
def sha256(s):
    """sha256"""
    return hashlib.sha256(s).digest()
	
def int2bytes(n):
    """Integer to variable length big endian."""
    if n == 0:
        return "\x00"
    b = ""
    while n:
        b = chr(n % 256) + b
        n /= 256
    return b
	
def bytes2int(b):
    """Variable length big endian to integer."""
    n = 0
    for p in b:
        n *= 256
        n += ord(p)
    return n
	
# FIXME! Only usable for really small a with b near 16^x.
def randint(a, b):
    """Random integer in [a,b]."""
    bits = int(log(b, 2) + 1) / 8
    candidate = 0
    while True:
        candidate = bytes2int(urandom(bits))
        if a <= candidate <= b:
            break
    assert a <= candidate <= b
    return candidate
	
def padto(msg, length):
    """Pads "msg" with zeroes until it's length is divisible by 'length'.
    If the length of msg is already a multiple of 'length', does nothing."""
    L = len(msg)
    if L % length:
        msg += "\x00" * (length - L % length)
    assert len(msg) % length == 0
    return msg
	
def xorstring(a, b, blocksize): # Slow.
	"""xor string a and b, both of length blocksize."""
	xored = ''
	for i in range(blocksize):
		#xored += chr(a[i] ^ b[i])
		xored += chr(ord(a[i]) ^ ord(b[i]))
	return xored
	
def cbc_encrypt(func, data, blocksize):
    """The CBC mode. The randomly generated IV is prefixed to the ciphertext.
    'func' is a function that encrypts data in ECB mode. 'data' is the
    plaintext. 'block-size' is the block size of the cipher."""
    assert len(data) % blocksize == 0
    
    IV = urandom(blocksize)
    assert len(IV) == blocksize
    
    ciphertext = IV
    for block_index in range(len(data) // blocksize):
        xored = xorstring(str(data), str(IV), blocksize)
        enc = func(xored)
        
        ciphertext += enc
        IV = enc
        data = data[blocksize:]
    assert len(ciphertext) % blocksize == 0
    return ciphertext
	
def cbc_decrypt(func, data, blocksize):
    """See cbc_encrypt."""
    assert len(data) % blocksize == 0
    
    IV = data[0:blocksize]
    data = data[blocksize:]
    plaintext = ""
    for block_index in range(len(data) // int(blocksize)):
        temp = func(data[0:blocksize])
        temp2 = xorstring(str(temp), str(IV), blocksize)
        plaintext += temp2
        IV = data[0:blocksize]
        data = data[blocksize:]
    
    assert len(plaintext) % blocksize == 0
    return plaintext
	
class Blowfish:    
    def __init__(self, key=None):
        if key:
            self.blowfish = Crypto.Cipher.Blowfish.new(key)
			
    def decrypt(self, data):
        return self.blowfish.decrypt(data)
    
    def encrypt(self, data):
        return self.blowfish.encrypt(data)
		
class BlowfishCBC:
    def __init__(self, key=None):
        if key:
            self.blowfish = Crypto.Cipher.Blowfish.new(key)
			
    def decrypt(self, data):
        return cbc_decrypt(self.blowfish.decrypt, data, 8)
    
    def encrypt(self, data):
        return cbc_encrypt(self.blowfish.encrypt, data, 8)
		
class AESCBC:    
    def __init__(self, key):
        self.aes = Crypto.Cipher.AES.new(key)
    def decrypt(self, data):
        return cbc_decrypt(self.aes.decrypt, data, 16)
    
    def encrypt(self, data):
        return cbc_encrypt(self.aes.encrypt, data, 16)
##
## blowcrypt, Fish etc.
##
# XXX: Unstable.
def blowcrypt_b64encode(s):
    """A non-standard base64-encode."""
    B64 = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    res = ""
    while s:
        left, right = struct.unpack(">LL", s[:8])
        for i in range(6):
            res += B64[right & 0x3f]
            right >>= 6
        for i in range(6):
            res += B64[left & 0x3f]
            left >>= 6
        s = s[8:]
    return res
	
def blowcrypt_b64decode(s):
    """A non-standard base64-decode."""
    B64 = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    res = ""
    while s:
        left, right = 0, 0
        for i, p in enumerate(s[0:6]):
            right |= B64.index(p) << (i * 6)
        for i, p in enumerate(s[6:12]):
            left |= B64.index(p) << (i * 6)
        res += str(struct.pack(">LL", left, right))
        s = s[12:]
    return res
	
def blowcrypt_pack(msg, cipher):
    """."""
    return "+OK " + str(blowcrypt_b64encode(cipher.encrypt(padto(msg, 8))), "UTF-8")
	
def blowcrypt_unpack(msg, cipher):
    """."""
    if not (msg.upper().startswith("+OK ") or msg.upper().startswith("MCPS ")):
        raise ValueError
    _, rest = msg.split(" ", 1)
    if (len(rest) % 12):
        raise MalformedError
    try:
        raw = blowcrypt_b64decode(rest)
    except TypeError:
        raise MalformedError
    if not raw:
        raise MalformedError
    try:
        plain = cipher.decrypt(raw)
    except ValueError:
        raise MalformedError
    
    return plain.strip("\x00")
##
## Mircryption-CBC
##
def mircryption_cbc_pack(msg, cipher):
    """."""
    padded = padto(msg, 8)
    return "+OK *" + str(base64.b64encode(cipher.encrypt(padded)), "UTF-8")
	
def mircryption_cbc_unpack(msg, cipher):
	"""."""
	if not (msg.upper().startswith("+OK *") or msg.upper().startswith("MCPS *")):
		raise ValueError
	try:
		_, coded = msg.split("*", 1)
		raw = base64.b64decode(coded)
	except TypeError:
		raise MalformedError
		
	if not raw:
		raise MalformedError
	try:
		padded = cipher.decrypt(raw)
		print("{0}".format(str(padded)))
		
	except ValueError:
		raise MalformedError
	if not padded:
		raise MalformedError
	plain = padded.strip("\x00")
	return plain
##
## DH1080
##
g_dh1080 = 2
p_dh1080 = int("FBE1022E23D213E8ACFA9AE8B9DFAD"
					"A3EA6B7AC7A7B7E95AB5EB2DF85892"
					"1FEADE95E6AC7BE7DE6ADBAB8A783E"
					"7AF7A7FA6A2B7BEB1E72EAE2B72F9F"
					"A2BFB2A2EFBEFAC868BADB3E828FA8"
					"BADFADA3E4CC1BE7E8AFE85E9698A7"
					"83EB68FA07A77AB6AD7BEB618ACF9C"
					"A2897EB28A6189EFA07AB99A8A7FA9"
					"AE299EFA7BA66DEAFEFBEFBF0B7D8B", 16)
q_dh1080 = (p_dh1080 - 1) // 2

# XXX: It is probably possible to implement dh1080 base64 using Pythons own, by
# considering padding, lengths etc... The dh1080 implementation is basically the
# standard one but with the padding character "=" removed. A trailing "A"
# is also added sometimes.
def dh1080_b64encode(s):
    """A non-standard base64-encode."""
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    d = [0]*len(s)*2
    L = len(s) * 8
    m = 0x80
    i, j, k, t = 0, 0, 0, 0
    while i < L:
        if ord(s[i >> 3]) & m:
            t |= 1
        j += 1
        m >>= 1
        if not m:
            m = 0x80
        if not j % 6:
            d[k] = b64[t]
            t &= 0
            k += 1
        t <<= 1
        t %= 0x100
        #
        i += 1
    m = 5 - j % 6
    t <<= m
    t %= 0x100
    if m:
        d[k] = b64[t]
        k += 1
    d[k] = 0
    res = ""
    for q in d:
        if q == 0:
            break
        res += q
    return res
	
def dh1080_b64decode(s):
    """A non-standard base64-encode."""
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    buf = [0]*256
    for i in range(64):
        buf[ord(b64[i])] = i
    L = len(s)
    if L < 2:
        raise ValueError
    for i in reversed(range(L-1)):
        if buf[ord(s[i])] == 0:
            L -= 1
        else:
            break
    if L < 2:
        raise ValueError
    d = [0]*L
    i, k = 0, 0
    while True:
        i += 1
        if k + 1 < L:
            d[i-1] = buf[ord(s[k])] << 2
            d[i-1] %= 0x100
        else:
            break
        k += 1
        if k < L:
            d[i-1] |= buf[ord(s[k])] >> 4
        else:
            break
        i += 1
        if k + 1 < L:
            d[i-1] = buf[ord(s[k])] << 4
            d[i-1] %= 0x100
        else:
            break
        k += 1
        if k < L:
            d[i-1] |= buf[ord(s[k])] >> 2
        else:
            break
        i += 1
        if k + 1 < L:
            d[i-1] = buf[ord(s[k])] << 6
            d[i-1] %= 0x100
        else:
            break
        k += 1
        if k < L:
            d[i-1] |= buf[ord(s[k])] % 0x100
        else:
            break
        k += 1
    return "".join(map(chr, d[0:i-1]))
def dh_validate_public(public, q, p):
    """See RFC 2631 section 2.1.5."""
    return 1 == pow(public, q, p)

class DH1080Ctx:
    """DH1080 context."""
    def __init__(self):
        self.public = 0
        self.private = 0
        self.secret = 0
        self.state = 0
        
        bits = 1080
        while True:
            self.private = bytes2int(urandom(bits/8))
            self.public = pow(g_dh1080, self.private, p_dh1080)
            if 2 <= self.public <= p_dh1080 - 1 and \
               dh_validate_public(self.public, q_dh1080, p_dh1080) == 1:
                break
				
def dh1080_pack(ctx):
    """."""
    cmd = None
    if ctx.state == 0:
        ctx.state = 1
        cmd = "DH1080_INIT "
    else:
        cmd = "DH1080_FINISH "
    return cmd + dh1080_b64encode(int2bytes(ctx.public))
	
def dh1080_unpack(msg, ctx):
    """."""
    if not msg.startswith("DH1080_"):
        raise ValueError
    invalidmsg = "Key does not validate per RFC 2631. This check is not " \
                 "performed by any DH1080 implementation, so we use the key " \
                 "anyway. See RFC 2785 for more details."
    if ctx.state == 0:
        if not msg.startswith("DH1080_INIT "):
            raise MalformedError
        ctx.state = 1
        try:
            cmd, public_raw = msg.split(" ", 1)
            public = bytes2int(dh1080_b64decode(public_raw))
            if not 1 < public < p_dh1080:
                raise MalformedError
            
            if not dh_validate_public(public, q_dh1080, p_dh1080):
                #print invalid msg
                pass
                
            ctx.secret = pow(public, ctx.private, p_dh1080)
        except:
            raise MalformedError
        
    elif ctx.state == 1:
        if not msg.startswith("DH1080_FINISH "):
            raise MalformedError
        ctx.state = 1
        try:
            cmd, public_raw = msg.split(" ", 1)
            public = bytes2int(dh1080_b64decode(public_raw))
            if not 1 < public < p_dh1080:
                raise MalformedError
            if not dh_validate_public(public, q_dh1080, p_dh1080):
                #print invalid msg
                pass
            
            ctx.secret = pow(public, ctx.private, p_dh1080)
        except:
            raise MalformedError
    return True
        
def dh1080_secret(ctx):
    """."""
    if ctx.secret == 0:
        raise ValueError
    return dh1080_b64encode(sha256(int2bytes(ctx.secret)))