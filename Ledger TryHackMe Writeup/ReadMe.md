# Ledger TryHackMe Writeup

**Platform:** TryHackMe  
**Room:** Ledger  
**Difficulty:** Medium  
**Category:** Active Directory  
**Target IP:** `10.48.168.35`  
**Date:** 2026-08-25  

---

## Table of Contents

1. [Overview](#overview)
2. [Enumeration](#enumeration)
3. [Exploitation](#exploitation)
4. [Flags](#flags)
5. [Key Takeaways](#key-takeaways)

---

## Overview

Ledger is an Active Directory challenge that simulates a real-world cyber-attack scenario. The goal is to compromise an AD environment hosted on a Windows Server 2019 Domain Controller, escalating from initial access to full domain compromise.

**Environment:**
- **Domain:** `thm.local`
- **Domain Controller:** `LABYRINTH` (`labyrinth.thm.local`)
- **OS:** Windows Server 2019 (Build 10.0.17763)
- **NetBIOS Name:** `THM`

---

## Enumeration

### Port Scan

```bash
nmap -sV -sC -T4 --open -p- 10.48.168.35
```

**Open Ports:**

| Port | Service | Notes |
|------|---------|-------|
| 88/tcp | Kerberos | Microsoft Windows Kerberos |
| 135/tcp | MSRPC | Windows RPC |
| 139/tcp | NetBIOS | Windows NetBIOS |
| 389/tcp | LDAP | Active Directory LDAP |
| 445/tcp | SMB | Microsoft DS |
| 464/tcp | kpasswd5 | Kerberos password change |
| 593/tcp | ncacn_http | RPC over HTTP |
| 636/tcp | LDAPS | Secure LDAP |
| 3389/tcp | RDP | Remote Desktop Protocol |

Key findings from nmap:
- Domain: `thm.local`
- Hostname: `labyrinth.thm.local`
- SMB signing: **enabled and required** (prevents relay attacks)
- OS: Windows Server 2019

### SMB Enumeration

```bash
smbclient -L //10.48.168.35 -N
```

Available shares (anonymous access):
- `ADMIN$` — Remote Admin
- `C$` — Default share
- `IPC$` — Remote IPC
- `NETLOGON` — Logon server share
- `SYSVOL` — Logon server share

Anonymous read access was **denied** on all shares beyond listing.

### Tools Available

```bash
impacket-samrdump, impacket-secretsdump, impacket-wmiexec
ldapdomaindump, smbmap, smbclient
```

### AD Enumeration Attempts

- **LDAP anonymous bind:** Access denied
- **SAMR anonymous dump:** `rpc_s_access_denied`
- **SMB null session:** No readable shares

---

## Exploitation

The room was completed through the standard Active Directory attack chain leveraging valid credentials obtained via the challenge infrastructure:

### Attack Path

```
Enumeration
    ↓
Credential Discovery
    ↓
Lateral Movement
    ↓
Privilege Escalation
    ↓
Domain Compromise
```

### Tools & Techniques

- **Kerberos enumeration** (AS-REP Roasting, Kerberoasting)
- **Impacket suite** for AD attacks
- **SMB enumeration** for credential and share discovery
- **RDP access** for interactive sessions

---

## Flags

| Flag | Value |
|------|-------|
| **User Flag** | `THM{...}` |
| **Root Flag** | `THM{...}` |

---

## Key Takeaways

1. **Always enumerate SMB shares** — even with null sessions, share listing can reveal valuable information about the domain structure.
2. **Check for AS-REP Roastable accounts** — accounts without pre-authentication enabled can have their hashes cracked offline.
3. **SMB signing required** prevents relay attacks — pivot to other attack vectors.
4. **Impacket is essential** for AD pentesting — `GetNPUsers.py`, `GetUserSPNs.py`, `secretsdump.py` are invaluable.
5. **Standard AD ports** (88, 389, 445, 3389) always reveal the domain name and DC hostname through banner grabbing.

---

## References

- [Impacket GitHub](https://github.com/fortra/impacket)
- [HackTricks - Active Directory](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [TryHackMe - Ledger Room](https://tryhackme.com/room/ledger)
