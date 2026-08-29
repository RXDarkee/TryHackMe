# CCT 2019 CTF Challenge Series Full Writeup

> **Author:** r4s4n
> 
> **Platform:** TryHackMe
> 
> **Category:** PCAP Analysis / Forensics / Reverse Engineering / Cryptography

---

## Table of Contents

- [Overview](#overview)
- [Part 1 — pcap2: The USB Rabbit Hole](#part-1--pcap2-the-usb-rabbit-hole)
- [Part 2 — re3: The Slider Lock](#part-2--re3-the-slider-lock)
- [Part 3 — for1: The Onion of Obfuscation](#part-3--for1-the-onion-of-obfuscation)
- [Part 4 — crypto1: Three-Part Cryptography Suite](#part-4--crypto1-three-part-cryptography-suite)
- [Summary of All Flags](#summary-of-all-flags)
- [Key Takeaways](#key-takeaways)

---

## Overview

This writeup covers the complete CCT 2019 Naval Cyber Competition Team Assessment challenge series, originally created for the U.S. Navy Cyber Competition Team and made available to the community via TryHackMe. The series consists of four distinct challenge categories:

| Part | Challenge | Category |
|------|-----------|----------|
| 1 | pcap2 | USB packet capture analysis → hidden ELF binary → flag |
| 2 | re3 | .NET reverse engineering of a GUI slider challenge |
| 3 | for1 | Multi-layer JPEG forensics — steganography + Enigma encryption |
| 4 | crypto1 | Three-part crypto: keyboard cipher, rail fence, binary encoding |

Each part rewards methodical thinking and familiarity with a broad range of security analysis techniques.

---

## Part 1 — pcap2: The USB Rabbit Hole

**Flag format:** `CCT{****_*_****_******_*****_***_***_**_**_*_*****}`

---

### Step 1.1 — Identifying the Capture Type

```bash
file pcap2.pcapng
# pcapng capture file - version 1.0
```

Inspecting the Interface Description Block (IDB) of the pcapng reveals:

| Field | Value |
|-------|-------|
| Link type | 249 (`LINKTYPE_USB_LINUX_MMAPPED`) |
| Total packets | 20 |
| Capture duration | ~0.11 seconds |

This is a USB bulk transfer capture. The relevant packets are those going **from** device `1.7.1` (bus 1, device 7, endpoint 1) **to** the host. The `usb.capdata` field contains the actual payload data.

---

### Step 1.2 — Extracting USB Capture Data

The pcapng format stores packets in Enhanced Packet Blocks (EPBs). The USB header within each packet is **27 bytes** — the actual `usb.capdata` begins at byte offset 27.

```python
import struct

with open('pcap2.pcapng', 'rb') as f:
    raw = f.read()

pos = 0
epb_packets = []
while pos < len(raw) - 8:
    block_type = struct.unpack('<I', raw[pos:pos+4])[0]
    block_len  = struct.unpack('<I', raw[pos+4:pos+8])[0]
    if block_len < 12 or pos + block_len > len(raw):
        break
    if block_type == 0x00000006:  # Enhanced Packet Block
        cap_len  = struct.unpack('<I', raw[pos+20:pos+24])[0]
        pkt_data = raw[pos+28:pos+28+cap_len]
        epb_packets.append(pkt_data)
    pos += block_len

# Skip packet 0 (OUT/control), collect capdata from all IN packets
all_capdata = b''.join(p[27:] for p in epb_packets[1:])

with open('raw_capdata.bin', 'wb') as f:
    f.write(all_capdata)
```

---

### Step 1.3 — Extracting the Embedded PCAP

Running `binwalk` on the resulting binary reveals an embedded ZIP archive containing `pcap_chal.pcap`:

```bash
binwalk -e raw_capdata.bin
```

We verify the extraction is correct — the inner pcap contains exactly **4588 packets**, matching the challenge hint.

---

### Step 1.4 — Reading the Hidden ICMP Conversation

Filtering for short ICMP frames (`frame.len < 98`) exposes a covert channel conversation. Decoding all payload fragments:

```
bro, what you up to?
n2mh / why?
you didn't send that thing yet
oh... well, not over this
if not this, then what?
let's use cryptcat instead
we need to pick a key to use
I know just the one
okay, I found it. use the metasploit port to receive
listener is up. send it.
okay, it's sent
7181f4d45de00ae35b6cf8201c8d852b
hash is good
```

A separate ICMP packet (no matching reply — detectable via `icmp.resp_not_found`) contains the key clue:

```
Angela Bennett uses it to log into the Bethesda Naval Hospital
```

This references the 1995 film **The Net**, in which the password `BER5348833` is used. This is the cryptcat decryption key.

> **Red herring:** Another ICMP packet references a PNG image on fotoforensics.com. This is a dead end.

---

### Step 1.5 — Extracting the Encrypted Data

The conversation confirms encrypted data was sent to the **metasploit default port 4444**. We extract all TCP payload data destined for that port:

```python
tcp_data = b''
pos = 0
while pos < len(raw) - 8:
    block_type = struct.unpack('<I', raw[pos:pos+4])[0]
    block_len  = struct.unpack('<I', raw[pos+4:pos+8])[0]
    if block_len < 12 or pos + block_len > len(raw):
        break
    if block_type == 0x00000006:
        cap_len  = struct.unpack('<I', raw[pos+20:pos+24])[0]
        pkt_data = raw[pos+28:pos+28+cap_len]
        if len(pkt_data) >= 14:
            eth_type = struct.unpack('>H', pkt_data[12:14])[0]
            if eth_type == 0x0800 and len(pkt_data) >= 24:
                proto = pkt_data[23]
                if proto == 6:  # TCP
                    ip_hl    = (pkt_data[14] & 0x0F) * 4
                    dst_port = struct.unpack('>H', pkt_data[14+ip_hl+2:14+ip_hl+4])[0]
                    if dst_port == 4444:
                        tcp_hl  = ((pkt_data[14+ip_hl+12] >> 4) & 0xF) * 4
                        payload = pkt_data[14+ip_hl+tcp_hl:]
                        if payload:
                            tcp_data += payload
    pos += block_len

with open('tcp4444_data.bin', 'wb') as f:
    f.write(tcp_data)
```

---

### Step 1.6 — Decrypting with Cryptcat

Cryptcat uses the Twofish cipher. Decryption uses the classic cryptcat listener / netcat sender pattern:

```bash
# Terminal 1 — listener
cryptcat -vv -k BER5348833 -l -p 1337 > decrypted_elf.bin

# Terminal 2 — sender
nc -vv -w 2 localhost 1337 < tcp4444_data.bin
```

Verifying:

```bash
file decrypted_elf.bin
# ELF 64-bit LSB pie executable, x86-64

md5sum decrypted_elf.bin
# 7181f4d45de00ae35b6cf8201c8d852b  ← matches the ICMP-announced hash exactly
```

---

### Step 1.7 — Extracting the Flag from the ELF

The binary connects to an IRC server (`irc.cct`) and posts the flag to a channel. However, the flag can be recovered entirely statically.

Running `strings` on the binary reveals fragments of an encoded string embedded via x86-64 `movabs` instructions (`0x48 0xb8` / `0x48 0xba`), each loading 8 bytes:

```
gf1j7_n_
r6_bg_g0
t_f4u_re
3ug_qe@m
1j_c@pc_
n_f'f3u
```

The binary applies **ROT13 then reverses** the plaintext before wrapping with `CCT{}`. To decode, we invert: apply ROT13, then reverse:

```python
import codecs

encoded = "gf1j7_n_r6_bg_g0t_f4u_re3ug_qe@m1j_c@pc_n_f'f3u"
rot13   = codecs.encode(encoded, 'rot_13')
flag    = rot13[::-1]
print(f"CCT{{{flag}}}")
```

**Flag:** `CCT{h3s's_a_pc@p_w1z@rd_th3re_h4s_g0t_to_6e_a_7w1st}`

> A Harry Potter meets pcap pun — "He's a pcap wizard, there has got to be a twist."

---

## Part 2 — re3: The Slider Lock

**Flag format:** 32-character hex string (no `CCT{}` wrapper)

---

### Step 2.1 — File Identification

```bash
file re3.exe
# PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
```

This is a .NET assembly. Decompile with JetBrains dotPeek or ILSpy to get near-source-quality output.

---

### Step 2.2 — Decompiling the Logic

The application presents four horizontal scroll bars and a **Check!** button. The click handler enforces three conditions:

```csharp
int num1 = 711;
int num2 = 711000000;

if (bar1 + bar2 + bar3 + bar4 == num1 &&
    bar1 * bar2 * bar3 * bar4 == num2 &&
    bar1 > bar2 && bar2 > bar3 && bar3 > bar4)
{
    MessageBox.Show(goodBoy(bar2, byteA.Clone()));
}
```

The `goodBoy` function decrypts the key by XORing `byteA` with `(c ^ bar2)` where `c = 177`:

```csharp
private string goodBoy(int A_1, byte[] A_3)
{
    for (int index = 0; index < A_3.Length; ++index)
        A_3[index] = (byte)((uint)A_3[index] ^ (uint)(byte)(this.c ^ A_1));
    return Encoding.ASCII.GetString(A_3);
}
```

---

### Step 2.3 — Solving the Constraints

We need four positive integers where:
- sum = 711
- product = 711,000,000
- strictly decreasing
- each ≤ 1032 (bar maximum)

Factoring: `711,000,000 = 2^6 × 3^2 × 5^6 × 79`

```python
target_sum  = 711
target_prod = 711000000

divisors = [i for i in range(1, target_sum) if target_prod % i == 0]

for a4 in divisors:
    rem3 = target_prod // a4
    for a2 in divisors:
        if a2 <= a4 or rem3 % a2 != 0:
            continue
        rem2 = rem3 // a2
        for a1 in divisors:
            if a1 <= a2 or rem2 % a1 != 0:
                continue
            a0 = target_sum - a4 - a2 - a1
            if a0 > a1 and a0 > 0 and rem2 // a1 == a0:
                print(f"bar1={a0}, bar2={a1}, bar3={a2}, bar4={a4}")
                # bar1=316, bar2=150, bar3=125, bar4=120
```

There is exactly **one valid solution**: `bar1=316, bar2=150, bar3=125, bar4=120`

---

### Step 2.4 — Recovering the Key

```python
byteA = bytearray([
    20, 22, 100, 23, 21, 99, 100, 97, 99, 98, 21, 97, 100, 97, 16, 21,
    16, 23, 22, 17, 98, 21, 102, 16, 23, 18, 19, 101, 17, 99, 102, 18
])
c   = 177
A_1 = 150  # bar2.Value

xor_val = (c ^ A_1) & 0xFF  # 177 ^ 150 = 39
key = bytes(b ^ xor_val for b in byteA).decode('ascii')
print(key)
```

**Key:** `31C02DCFDE2FCF727016E2A7054B6DA5`

---

## Part 3 — for1: The Onion of Obfuscation

**Flag format:** `CCT{****_****_******_****_*_*****_***_***_***}`

---

### Step 3.1 — EXIF Metadata Analysis

```bash
exiftool for1.jpg
```

| Field | Value |
|-------|-------|
| Artist | Ed |
| Copyright | CCT 2019 |
| Description | `.--- ..- ... - .- .-- .- .-. -- ..- .--. .-. .. --. .... - ..--..` |

The Description field is **Morse code**. Decoded: `JUSTAWARMUPRIGHT?`

This is **password #1**.

---

### Step 3.2 — Extracting the Trailing ZIP

A ZIP archive is appended to the JPEG after the end-of-image marker (`0xFF 0xD9`):

```python
with open('for1.jpg', 'rb') as f:
    data = f.read()

pk_pos = data.find(b'PK\x03\x04')
with open('trailing.zip', 'wb') as f:
    f.write(data[pk_pos:])
```

```bash
unzip -P "justawarmupright?" trailing.zip
cat fakeflag.txt
```

```
I didn't say it would be easy, Neo. Peer into the Matrix...
- Morpheus
PW: Z10N0101
```

**Password #2:** `Z10N0101`

---

### Step 3.3 — Steghide Extraction

```bash
steghide extract -sf for1.jpg -p "Z10N0101"
# wrote extracted data to "archive.zip"
```

---

### Step 3.4 — Extracting the Archive

```bash
unzip -P "0ni0n_0f_0bfu5c@ti0n" archive.zip
```

**Password #3** (`0ni0n_0f_0bfu5c@ti0n`) was found during image analysis. The archive contains:

- `cipher.txt` — Enigma ciphertext
- `config.txt` — Enigma machine configuration
- `flag.zip` — Password-protected final archive

---

### Step 3.5 — Enigma Machine Decryption

`config.txt`:
```
C G. VI. VII. VIII. AMTU RING AM BY CH DR EL FX GO IV JN KU PS QT WZ
```

| Component | Value |
|-----------|-------|
| Reflector | C-Thin |
| Rotors | Gamma, VI, VII, VIII |
| Starting display | AMTU |
| Ring settings | R I N G |
| Plugboard | AM BY CH DR EL FX GO IV JN KU PS QT WZ |

`cipher.txt` (corrected ciphertext per challenge update):
```
JHSL PGLW YSQO DQVL PFAO TPCY KPUD TF
```

```python
from enigma.machine import EnigmaMachine
import enigma.plugboard

enigma.plugboard.MAX_PAIRS = 13

machine = EnigmaMachine.from_key_sheet(
    rotors='Gamma VI VII VIII',
    reflector='C-Thin',
    ring_settings='R I N G',
    plugboard_settings='AM BY CH DR EL FX GO IV JN KU PS QT WZ')

machine.set_display('AMTU')

ciphertext = 'JHSLPGLWYSQODQVLPFAOTPCYKPUDTF'
plaintext  = machine.process_text(ciphertext)
print(plaintext.lower())
# ctfforensicsisnotrealforensics
```

---

### Step 3.6 — Extracting the Flag

```bash
unzip -P "ctfforensicsisnotrealforensics" flag.zip
cat flag.txt
```

**Flag:** `CCT{Well_that_wasn't_such_a_chore_now_was_it?}`

---

## Part 4 — crypto1: Three-Part Cryptography Suite

---

### Part 4a — Keyboard Layout Cipher

**Flag format:** `CCT{********_*_******}`

The ciphertext has a distinctive punctuation pattern — periods where commas should appear, and angle brackets for parentheses. This is a **Dvorak-to-QWERTY keyboard mapping cipher**: each character was typed on a QWERTY keyboard while treating it as Dvorak.

After remapping, the plaintext reads:

```
An easy technique for solving Caesar substitution ciphers will only get you so far
because of punctuation symbols. Still, it should get you close enough to figure out
the rest. But can you figure out the key which happens to be the name of the "layout"
which created this. Actually, you had better enter it thrice just to be safe (all
lower-case if you please).
```

The key is `dvorak` entered three times: **`dvorakdvorakdvorak`**

```bash
unzip -P "dvorakdvorakdvorak" crypto1a.zip
```

**Flag:** `CCT{Actu411y_a_w@rmup}`

---

### Part 4b — Rail Fence Cipher

**Flag format:** `CCT{****_***_***_****_*******}`

The hint is explicit: "Don't straddle the fence or you'll end up riding a rail or five. It'll hurt from the bottom up."

Configuration:
- Rails: **5**
- Offset: **4** (= rails − 1, reading from the bottom up)

```python
def rail_number(position, rails, offset):
    position = (position + offset) % (rails * 2 - 2)
    return position if position < rails else 2 * rails - position - 2

def decrypt(enc, rails, offset):
    result = ['+'] * len(enc)
    k = 0
    for i in range(rails):
        for j in range(len(enc)):
            if rail_number(j, rails, offset) == i:
                result[j] = enc[k]
                k += 1
    return ''.join(result)

print(decrypt(enc, 5, 4))
```

The plaintext reveals the password is how the **goose spells "terrific"** in the 1973 animated film *Charlotte's Web*:

> "T, double-E, double-R, double-R, double-I, double-F, double-I, double-C, C, C"

The text specifies "it's probably six" (Cs): **`teerrrriiffiicccccc`**

```bash
unzip -P "teerrrriiffiicccccc" crypto1b.zip
```

**Flag:** `CCT{th@t_w4s_th4_ea5y_bu770n!}`

---

### Part 4c — Run-Length Binary Encoding

**Flag format:** `CCT{*_***_****_*******_***_***_****}`

The ciphertext is a long numeric string. The challenge hint says: "start with 0 not 1."

This is a **run-length encoding of a binary string**:

- Even-indexed digits → runs of `0` bits
- Odd-indexed digits → runs of `1` bits

Each digit specifies how many consecutive copies of its corresponding bit to output. The resulting binary string is then decoded as ASCII.

```python
enc = "11122112141311112123131222211121621211124112213221112162..."

result = ""
for i, ch in enumerate(enc):
    bit = '0' if i % 2 == 0 else '1'
    result += bit * int(ch)

flag_bytes = int(result, 2).to_bytes((len(result) + 7) // 8, byteorder='big')
print(flag_bytes.decode('ascii'))
```

**Flag:** `CCT{I_see_dead_ciphers_all_the_time}`

---

## Summary of All Flags

| Challenge | Flag |
|-----------|------|
| pcap2 | `CCT{h3s's_a_pc@p_w1z@rd_th3re_h4s_g0t_to_6e_a_7w1st}` |
| re3 | `31C02DCFDE2FCF727016E2A7054B6DA5` |
| for1 | `CCT{Well_that_wasn't_such_a_chore_now_was_it?}` |
| crypto1a | `CCT{Actu411y_a_w@rmup}` |
| crypto1b | `CCT{th@t_w4s_th4_ea5y_bu770n!}` |
| crypto1c | `CCT{I_see_dead_ciphers_all_the_time}` |

---

## Key Takeaways

**Network forensics goes deeper than protocol headers.** The pcap challenge required understanding USB bulk transfer structure at the byte level, reassembling fragmented data across pcapng EPB blocks, and recognizing covert ICMP channels — skills that go well beyond basic Wireshark filtering.

**Reverse engineering .NET assemblies is accessible.** The .NET runtime stores considerable metadata in readable form, and tools like dotPeek or ILSpy produce near-source-quality code. The real challenge is reading the logic and formulating the correct mathematical constraints to satisfy the unlock condition.

**Layered steganography rewards patience.** The for1 challenge stacked four distinct hiding techniques — EXIF metadata, an appended ZIP, steghide embedding, and Enigma encryption — each layer revealing the credential for the next. Methodical enumeration is more valuable than brute force.

**Unconventional encoding schemes require first-principles thinking.** The crypto1c run-length binary encoding has no dedicated online tool. Solving it required reading the hint carefully, recognizing the alternating bit pattern, and writing a short decoder from scratch.

---

*Writeup by r4s4n — TryHackMe CCT 2019 CTF Series*
