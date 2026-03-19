# LoveLetter Locker - CTF Writeup

## Challenge Information
- **Challenge Name:** My Dearest Hacker
- **Target:** `http://10.81.130.195:5000`
- **Vulnerability:** IDOR (Insecure Direct Object Reference)

## Reconnaissance

Initial nmap scan revealed two open ports:
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
5000/tcp open  http    Werkzeug/3.1.5 Python/3.12.3
```

The web application "LoveLetter Locker" is running on port 5000 - described as a service to "keep your love letters safe."

## Vulnerability Analysis

The challenge title and description hinted at a potential IDOR vulnerability, suggesting we could access letters that weren't meant for us.

## Exploitation

### Step 1: Registration and Initial Access
1. Registered a new account on the web application
2. Created a test love letter
3. Upon accessing the letter, noticed the URL structure: `http://10.81.130.195:5000/letter/3`

### Step 2: IDOR Testing
The sequential ID in the URL (`/letter/3`) indicated a potential IDOR vulnerability. By simply changing the ID parameter, we could access other users' letters.

### Step 3: Flag Discovery
Navigated to previous letter IDs:
- `/letter/2` - (likely another user's letter)
- `/letter/1` - **Found the flag!**

Letter #1 contents:
```
💌 To my secret Valentine ❤️
Letter #1
Archived: 2026-01-19 10:46:35

My dearest...
THM{...}

Forever yours,
Gonz0
```

## Flag Retrieval
Upon accessing Letter #1, the flag was displayed in Gonz0's love letter.

## Attack Chain Summary

1. **Reconnaissance** → Identified Werkzeug/Flask application on port 5000
2. **Registration** → Created account and wrote test letter
3. **IDOR Discovery** → Noticed sequential ID pattern in URL (`/letter/3`)
4. **Exploitation** → Manually decremented letter IDs to access other users' letters
5. **Flag Capture** → Retrieved flag from Letter #1 (Gonz0's letter)

## Key Vulnerabilities

1. **IDOR (Insecure Direct Object Reference)** - No authorization checks on letter access
2. **Predictable Resource IDs** - Sequential integer IDs instead of UUIDs
3. **Missing Access Control** - Any authenticated user can access any letter by ID