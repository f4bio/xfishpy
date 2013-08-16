###
#
# FiSH/Mircryption clone for X-Chat in 100% Python
#
# Requirements: PyCrypto, Python 3.2+
#				XChat with Python3 support
#				e.g.: HexChat 2.9.6 (http://hexchat.github.io/downloads.html)
#
# Copyright 2010 Nam T. Nguyen
# Released under the BSD license
#
# irccrypt module is copyright 2009 Bjorn Edstrom
# with modification from Nam T. Nguyen
#
###
__module_name__ = "xFiSHpy"
__module_version__ = "1.0py3_0.1"
__module_description__ = "fish encryption in pure python"
import os
import threading
import sys
import traceback
import pickle
import config.addons.xFiSHpy.irccrypt as irccrypt

KEY_MAP = {}
LOCK_MAP = {}

PRINT_PREFIX = "+"

PICKLE_NAME = "xfish.pickle"
PLUGIN_PATH = os.path.join("config", "addons", "xFiSHpy")
PICKLE_PATH = os.path.join(PLUGIN_PATH, PICKLE_NAME)

CMD_HELP = dict({	"starting point": "/key <COMMAND> [ARGS]",
					"details": "<MANDATORY> [OPTIONAL='DEFAULT']",
					"help text (this)": "/key help|h", 
					"list all saved keys": "/key list|ls",
					"remove specific key": "/key remove|rm <key>",
					"exchange key (diffie hellman)": "/key exchange|ex [chan='#current']"
					"set or change key": "/key set <key> [chan='#current'] [CBC-mode='true']"
				})

class SecretKey:
	""" Secret key class """
	dh = None
	key = None
	cbc = True	
	def __init__(self, key):
		self.key = key
		
### initialize
def set_processing():
	id = xchat.get_info("server")
	LOCK_MAP[id] = True
	
def unset_processing():
	id = xchat.get_info("server")
	LOCK_MAP[id] = False
	
def is_processing():
	id = xchat.get_info("server")
	return LOCK_MAP.get(id, False)
	
def get_id(ctx):
	return (ctx.get_info("server"), ctx.get_info("channel"))
	
def get_nick(full):
	if full[0] == ':':
		full = full[1 : ]
	return full[ : full.index('!')]
	
def formatMsg(msg):
	return "- xFiSHpy: {0} -".format(msg)
	
### loading / unloading
def load():
	global KEY_MAP
	msg = ""
	KEY_MAP = {}
	
	if not os.path.exists(PICKLE_PATH):
		msg = "pickle-file '{0}' does not exist, no keys loaded".format(
				os.path.relpath(PICKLE_PATH))

	elif os.path.getsize(PICKLE_PATH) == 0:
		msg = "0byte pickle-file '{0}', ignoring, no keys loaded".format(
				os.path.relpath(PICKLE_PATH))
		
	else:	
		with open(PICKLE_PATH, "rb") as file:
			try:
				KEY_MAP = pickle.load(file)
				msg = "keys loaded!"
			except EOFError:
				raise
			
	print(formatMsg(msg))
	
def unload():
	msg = ""
	tmp_map = {}
	for id, key in KEY_MAP.items():
		print(type(key))
		if key:
			tmp_map[id] = SecretKey(key)
	
	if not tmp_map:
		msg = "no keys saved, nothing to store"
	else:
		with open(PICKLE_PATH, "wb") as file:		
			pickle.dump(tmp_map, file)
			msg = "keys dumped!"
	print(formatMsg(msg))
	
### encryption
def decrypt(key, inp):
	if 3 <= inp.find(" *") <= 4:
		decrypt_clz = irccrypt.BlowfishCBC
		decrypt_func = irccrypt.mircryption_cbc_unpack
	else:
		decrypt_clz = irccrypt.Blowfish
		decrypt_func = irccrypt.blowcrypt_unpack
		
	b = decrypt_clz(key.key)
	print(b)
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
		
	speaker = word[0]
	message = word_eol[1]
	# if there is mode char, remove it from the message
	if len(word_eol) >= 3:
		message = message[ : -(len(word_eol[2]) + 1)]
		
	if message.upper().startswith("+OK ") or message.upper().startswith("MCPS "):
		message = decrypt(KEY_MAP[id], message)
		set_processing()
		ctx.emit_print(userdata, speaker, message)
		unset_processing()
		return xchat.EAT_ALL
	else:
		return xchat.EAT_NONE

def encrypt_privmsg(word, word_eol, userdata):
	message = word_eol[0]
	ctx = xchat.get_context()
	id = get_id(ctx)
	nick = ctx.get_info("nick")
	
	if id not in KEY_MAP:
		return xchat.EAT_NONE
	key = KEY_MAP[id]
	if not key.key:
		return xchat.EAT_NONE
		
	cipher = encrypt(key, message)
	xchat.command("PRIVMSG {0} {1}".format(id[1], cipher))
	xchat.emit_print("Your Message", xchat.get_info("nick"), message)
	return xchat.EAT_ALL
	
##### key operations
def key_set(args):
	# <key> [chan='#current'] [CBC-mode='true']
	ctx = xchat.get_context()
	target = ctx.get_info("channel")
	
	if len(args) == 1:
		id = (ctx.get_info("server"), target)
		secKey = SecretKey(args[1])
		
	elif len(args) == 2:
		id = (args.get_info("server"), args[1])
		secKey = SecretKey(args[2])

	elif len(args) == 3:
		id = (args.get_info("server"), args[1])
		secKey = SecretKey(args[2])
		secKey.cbc_mode = bool(args[3])
			
	else:
		msg = "syntax error: /key set [nick|#chan] key [CBC-mode]"
		print(formatMsg(msg))
		
	msg = "BF-Key for '{0}' set to {1} (CBC: {2})".format(
			target, key.key, key.cbc_mode)
	print(formatMsg(msg))
	return xchat.EAT_ALL

def key_exchange(args):
	ctx = xchat.get_context()	
	target = ctx.get_info("channel")
	
	if len(args) == 1:
		target = args[1]
		
	id = (ctx.get_info("server"), target)
	dh = irccrypt.DH1080Ctx()
	secKey = SecretKey()
	secKey.dh = dh
	KEY_MAP[id] = secKey
	
	ctx.command("NOTICE {0} {1}".format(target, irccrypt.dh1080_pack(dh)))
	return xchat.EAT_ALL

def key_help():
	for id, key in CMD_HELP.items():
		print("{0}: {1}".format(id, key))
	
	return xchat.EAT_ALL
	
def key_list():

	if not KEY_MAP:
		msg = "No keys saved!"
		
	else:
		for id, key in KEY_MAP.items():
			msg = "Key for '{1}' ('{0}'): '{2}' (CBC: {3})".format(
					id[0], id[1], key.key, key.cbc_mode)
			
	print(formatMsg(msg))
	return xchat.EAT_ALL
	
def key_remove(key):
	id = (xchat.get_info("server"), word[1])
	try:
		del KEY_MAP[id]
	except KeyError:
		msg = "Key not found"
		print(formatMsg(msg))
	else:
		msg = "Key removed"
		print(formatMsg(msg))
	return xchat.EAT_ALL
	
def key_cbc(word, word_eol, userdata):
	id = (xchat.get_info("server"), word[1])
	try:
		KEY_MAP[id].cbc_mode = int(word[2])
		msg = "CBC mode set to %s".format(bool(KEY_MAP[id].cbc_mode))
		print(formatMsg(msg))
	except KeyError:
		msg = "Key not found"
		print(formatMsg(msg))
	return xchat.EAT_ALL
	
# diffie hellman
def dh1080_finish(word, word_eol, userdata):
	ctx = xchat.get_context()
	speaker, command, target, message = word[0], word[1], word[2], word_eol[3]
	id = (ctx.get_info('server'), get_nick(speaker))
	if id not in KEY_MAP:
		return xchat.EAT_NONE
	key = KEY_MAP[id]
	irccrypt.dh1080_unpack(message[1 : ], key.dh)
	key.key = irccrypt.dh1080_secret(key.dh)
	
	msg = "Finished DH-Key for '{0}' set to {1} (CBC: {2})".format(
			id[1], key.key, key.cbc_mode)
	print(formatMsg(msg))
	return xchat.EAT_ALL
	
def dh1080_init(word, word_eol, userdata):
	ctx = xchat.get_context()
	speaker, command, target, message = word[0], word[1], word[2], word_eol[3]
	id = (ctx.get_info('server'), get_nick(speaker))
	key = SecretKey(None)
	dh = irccrypt.DH1080Ctx()
	irccrypt.dh1080_unpack(message[1 : ], dh)
	key.key = irccrypt.dh1080_secret(dh)
	xchat.command("NOTICE {0} {1}".format(id[1], irccrypt.dh1080_pack(dh)))
	KEY_MAP[id] = key
	
	msg = "Initiated DH-Key for '{0}' set to {1} (CBC: {2})".format(id[1], key.key, key.cbc_mode)
	print(formatMsg(msg))
	return xchat.EAT_ALL
	
def dh1080(word, word_eol, userdata):
	if word_eol[3].startswith(":DH1080_FINISH"):
		return dh1080_finish(word, word_eol, userdata)
	elif word_eol[3].startswith(":DH1080_INIT"):
		return dh1080_init(word, word_eol, userdata)
	return xchat.EAT_NONE
	
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
	if not (topic.upper().startswith("+OK ") or topic.upper().startswith("MCPS ")):
		return xchat.EAT_NONE
	topic = decrypt(key, topic)
	set_processing()
	
	xchat.command("RECV {0} {1} {2} {3} :{4}".format(server, cmd, nick, channel, topic))
	unset_processing()
	return xchat.EAT_ALL
	
def change_nick(word, word_eol, userdata):
	old, new = word[0], word[1]
	ctx = xchat.get_context()
	old_id = (xchat.get_info("server"), old)
	new_id = (old_id[0], new)
	try:
		KEY_MAP[new_id] = KEY_MAP[old_id]
		del KEY_MAP[old_id]
	except KeyError:
		pass
	return xchat.EAT_NONE

def commandParser(word, word_eol, userdata):

	# /key list
	if word[1] == "list" or word[1] == "ls":
		key_list()
		
	# / key help
	elif word[1] == "help" or word[1] == "h":
		key_help()
		
	# /key exchange <nick>
	if word[1] == "exchange" or word[1] == "ex":
		key_exchange(word[2])

	# /key remove <nick|#chan>
	elif word[1] == "remove" or word[1] == "rm":
		key_list(word[2])
		
	# /key set [nick|#chan] [key] [CBC-mode]
	elif word[1] == "set":
			key_set(word_eol[2])
	else:
		print("syntax error -> /key help")	
		
	
	
		
import xchat
# set
xchat.hook_command("key", commandParser, help="show information or set key, /key <command> [arg1|...] [yourKey]")
# exchange
#xchat.hook_command("key_exchange", key_exchange, help="exchange a new key, /key exchange <nick>")
#xchat.hook_command("keyex", key_exchange, help="alias for /key_exchange, exchange a new key, /keyex <nick>")
# list
#xchat.hook_command("key_list", key_list, help="list keys, /key_list")
#xchat.hook_command("keyls", key_list, help="alias for /key_list, list keys, /keyls")
# remove
#xchat.hook_command("key_remove", key_remove, help="remove key, /key_remove <nick>")
#xchat.hook_command("keyrm", key_remove, help="alias for /key_remove, remove key, /keyrm <nick>")
# change mode
#xchat.hook_command("key_cbc", key_cbc, help="set CBC mode, /key_cbc <nick/chan> <0|1>")
#xchat.hook_command("keycbc", key_cbc, help="alias for /key_cbc, set CBC mode, /keycbc <nick/chan> <0|1>")
# server
xchat.hook_server("notice", dh1080)
xchat.hook_server("332", server_332)
# prints
xchat.hook_print("Channel Message", decrypt_print, "Channel Message")
xchat.hook_print("Change Nick", change_nick)
xchat.hook_print("Private Message to Dialog", decrypt_print, "Private Message to Dialog")
# other, unload, load
xchat.hook_command("", encrypt_privmsg)
xchat.hook_unload(unload)
load()