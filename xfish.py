#!/usr/bin/env python
###
#
# FiSH/Mircryption clone for (He)X-Chat in 100% Python
#
# Requirements: PyCrypto, and Python 3.3+
#
# Copyright 2010 Nam T. Nguyen
# Released under the BSD license
#
# irccrypt module is copyright 2009 Bjorn Edstrom
# with modification from Nam T. Nguyen
#
###
from __future__ import with_statement
__module_name__ = 'xFiSHpy'
__module_version__ = '1.0'
__module_description__ = 'fish encryption in pure python'
import os
import irccrypt
import pickle
import threading

KEY_MAP = {}
LOCK_MAP = {}
class SecretKey(object):
	def __init__(self, dh, key=None):
		self.dh = dh
		self.key = key
		self.cbc_mode = False
def set_processing():
	id = xchat.get_info('server')
	LOCK_MAP[id] = True
def unset_processing():
	id = xchat.get_info('server')
	LOCK_MAP[id] = False
	
def is_processing():
	id = xchat.get_info('server')
	return LOCK_MAP.get(id, False)

def get_id(ctx):
	return (ctx.get_info('server'), ctx.get_info('channel'))

def get_nick(full):
	if full[0] == ':':
		full = full[1 : ]
	return full[ : full.index('!')]

def unload(userdata):
	tmp_map = {}
	for id in KEY_MAP.keys():
		if KEY_MAP[id].key:
			tmp_map[id] = KEY_MAP[id]
	with open(os.path.join(xchat.get_info('xchatdir'), 'fish.pickle'), 'wb') as f:
		pickle.dump(tmp_map, f)
	print('xFiSHpy unloaded')

def decrypt(key, inp):
	decrypt_clz = irccrypt.Blowfish
	decrypt_func = irccrypt.blowcrypt_unpack
	if 3 <= inp.find(' *') <= 4:
		decrypt_clz = irccrypt.BlowfishCBC
		decrypt_func = irccrypt.mircryption_cbc_unpack
	b = decrypt_clz(key.key)
	return decrypt_func(inp, b)

def encrypt(key, inp):
	encrypt_clz = irccrypt.Blowfish
	encrypt_func = irccrypt.blowcrypt_pack
	if key.cbc_mode:
		encrypt_clz = irccrypt.BlowfishCBC
		encrypt_func = irccrypt.mircryption_cbc_pack
	b = encrypt_clz(key.key)
	return encrypt_func(inp, b)

def decrypt_print(word, word_eol, userdata):
	if is_processing():
		return xchat.EAT_NONE
	ctx = xchat.get_context()
	id = get_id(ctx)
	if id not in KEY_MAP:
		return xchat.EAT_NONE
	speaker, message = word[0], word_eol[1]
	# if there is mode char, remove it from the message
	if len(word_eol) >= 3:
		message = message[ : -(len(word_eol[2]) + 1)]
	if message.startswith('+OK ') or message.startswith('mcps '):
		message = decrypt(KEY_MAP[id], message)
		set_processing()
		ctx.emit_print(userdata, speaker, message)
		unset_processing()
		return xchat.EAT_XCHAT
	else:
		return xchat.EAT_NONE

def encrypt_privmsg(word, word_eol, userdata):
	message = word_eol[0]
	ctx = xchat.get_context()
	id = get_id(ctx)
	if id not in KEY_MAP:
		return xchat.EAT_NONE
	key = KEY_MAP[id]
	if not key.key:
		return xchat.EAT_NONE
	cipher = encrypt(key, message)
	xchat.command('PRIVMSG %s :%s' % (id[1], cipher))
	xchat.emit_print('Your Message', xchat.get_info('nick'), message)
	return xchat.EAT_ALL

def key(word, word_eol, userdata):
	ctx = xchat.get_context()
	target = ctx.get_info('channel')
	if len(word) >= 2:
		target = word[1]
	id = (ctx.get_info('server'), target)
	try:
		key = KEY_MAP[id]
	except KeyError:
		key = SecretKey(None)
	if len(word) >= 3:
		key.key = word_eol[2]
		KEY_MAP[id] = key
	print('Key for', target, 'set to', key.key)
	return xchat.EAT_ALL

def key_exchange(word, word_eol, userdata):
	ctx = xchat.get_context()
	target = ctx.get_info('channel')
	if len(word) >= 2:
		target = word[1]
	id = (ctx.get_info('server'), target)
	dh = irccrypt.DH1080Ctx()
	KEY_MAP[id] = SecretKey(dh)
	ctx.command('NOTICE %s %s' % (target, irccrypt.dh1080_pack(dh)))
	return xchat.EAT_ALL

def dh1080_finish(word, word_eol, userdata):
	ctx = xchat.get_context()
	speaker, command, target, message = word[0], word[1], word[2], word_eol[3]
	id = (ctx.get_info('server'), get_nick(speaker))
	if id not in KEY_MAP:
		return xchat.EAT_NONE
	key = KEY_MAP[id]
	irccrypt.dh1080_unpack(message[1 : ], key.dh)
	key.key = irccrypt.dh1080_secret(key.dh)
	print("Key for", id[1], 'set to', key.key)
	return xchat.EAT_ALL

def dh1080_init(word, word_eol, userdata):
	ctx = xchat.get_context()
	speaker, command, target, message = word[0], word[1], word[2], word_eol[3]
	id = (ctx.get_info('server'), get_nick(speaker))
	key = SecretKey(None)
	dh = irccrypt.DH1080Ctx()
	irccrypt.dh1080_unpack(message[1 : ], dh)
	key.key = irccrypt.dh1080_secret(dh)
	xchat.command('NOTICE %s %s' % (id[1], irccrypt.dh1080_pack(dh)))
	KEY_MAP[id] = key
	print('Key for', id[1], 'set to', key.key)
	return xchat.EAT_ALL

def dh1080(word, word_eol, userdata):
	if word_eol[3].startswith(':DH1080_FINISH'):
		return dh1080_finish(word, word_eol, userdata)
	elif word_eol[3].startswith(':DH1080_INIT'):
		return dh1080_init(word, word_eol, userdata)
	return xchat.EAT_NONE

def load():
	global KEY_MAP
	try:
		with open(os.path.join(xchat.get_info('xchatdir'),
			'fish.pickle'), 'rb') as f:
			KEY_MAP = pickle.load(f)
	except IOError:
		pass
	print('xFiSHpy loaded')

def key_list(word, word_eol, userdata):
	for id in KEY_MAP.keys():
		print(id, KEY_MAP[id].key, bool(KEY_MAP[id].cbc_mode))
	return xchat.EAT_ALL

def key_remove(word, word_eol, userdata):
	id = (xchat.get_info('server'), word[1])
	try:
		del KEY_MAP[id]
	except KeyError:
		print('Key not found')
	else:
		print('Key removed')
	return xchat.EAT_ALL

def key_cbc(word, word_eol, userdata):
	id = (xchat.get_info('server'), word[1])
	try:
		KEY_MAP[id].cbc_mode = int(word[2])
		print('CBC mode', bool(KEY_MAP[id].cbc_mode))
	except KeyError:
		print('Key not found')
	return xchat.EAT_ALL

# handle topic line
def server_332(word, word_eol, userdata):
	if is_processing():
		return xchat.EAT_NONE
	id = get_id(xchat.get_context())
	if id not in KEY_MAP:
		return xchat.EAT_NONE
	key = KEY_MAP[id]
	server, cmd, nick, channel, topic = word[0], word[1], word[2], word[3], word_eol[4]
	if topic[0] == ':':
		topic = topic[1 : ]
	if not (topic.startswith('+OK ') or topic.startswith('mcps ')):
		return xchat.EAT_NONE
	topic = decrypt(key, topic)
	set_processing()
	xchat.command('RECV %s %s %s %s :%s' % (server, cmd, nick, channel, topic))
	unset_processing()
	return xchat.EAT_ALL

def change_nick(word, word_eol, userdata):
	old, new = word[0], word[1]
	ctx = xchat.get_context()
	old_id = (xchat.get_info('server'), old)
	new_id = (old_id[0], new)
	try:
		KEY_MAP[new_id] = KEY_MAP[old_id]
		del KEY_MAP[old_id]
	except KeyError:
		pass
	return xchat.EAT_NONE

import xchat
xchat.hook_command('key', key, help='show information or set key, /key <nick> [new_key]')
xchat.hook_command('key_exchange', key_exchange, help='exchange a new key, /key_exchange <nick>')
xchat.hook_command('key_list', key_list, help='list keys, /key_list')
xchat.hook_command('key_remove', key_remove, help='remove key, /key_remove <nick>')
xchat.hook_command('key_cbc', key_cbc, help='set cbc mode, /key_cbc <nick> <0|1>')
xchat.hook_server('notice', dh1080)
xchat.hook_print('Channel Message', decrypt_print, 'Channel Message')
xchat.hook_print('Change Nick', change_nick)
xchat.hook_print('Private Message to Dialog', decrypt_print, 'Private Message to Dialog')
xchat.hook_server('332', server_332)
xchat.hook_command('', encrypt_privmsg)
xchat.hook_unload(unload)
load()