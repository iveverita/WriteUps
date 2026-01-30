# Root-Me CTF Writeups

A collection of detailed writeups for various challenges on [Root-Me](https://www.root-me.org/), a platform for learning and practicing cybersecurity skills.

## 📋 About

This repository contains my solutions and explanations for Root-Me challenges across different categories. Each writeup includes:
- Challenge description and objectives
- Source code analysis (when applicable)
- Step-by-step exploitation process
- Command examples and screenshots
- Key takeaways and learning points

## 🎯 Categories Covered

### App - Script (9 challenges)
Privilege escalation and command injection challenges focusing on:
- PATH manipulation and binary exploitation
- Command injection in Bash, Perl, PowerShell, and Python
- Cron job exploitation
- LaTeX input vulnerabilities
- Sudo misconfigurations

### Web - Server (19 challenges)
Web application security challenges including:
- Authentication bypass techniques
- HTTP header manipulation
- Command injection and code execution
- File upload vulnerabilities
- API security flaws (IDOR, Mass Assignment, Broken Access)
- Server misconfigurations (Nginx, directory indexing)
- CRLF injection and cookie manipulation

## 📚 Challenge Index

### App - Script
1. **Bash - System 1** - PATH manipulation for privilege escalation
2. **Sudo - weak configuration** - Exploiting wildcard in sudo permissions
3. **Bash - System 2** - PATH hijacking with temporary directories
4. **Powershell - Command Injection** - Exploiting semicolon pipe in Windows shell
5. **LaTeX - Input** - Reading files using `\verbatiminput` directive
6. **Bash - Unquoted Expression Injection** - Exploiting unquoted variables in test
7. **Perl - Command Injection** - Exploiting 2-argument `open()` function
8. **Python - input()** - Python2 `input()` vulnerability with `__import__`
9. **Bash - cron** - Creating malicious scripts in world-writable cron directory

### Web - Server
1. **HTML - Source Code** - Finding credentials in HTML comments
2. **Weak password** - Default credentials (admin/admin)
3. **HTTP - User-agent** - Modifying User-Agent header
4. **HTTP - Open redirect** - Manipulating redirect URL and hash
5. **HTTP - IP restriction bypass** - Using X-Forwarded-For header
6. **PHP - Command injection** - Exploiting unsanitized command execution
7. **API - Broken Access** - IDOR vulnerability in REST API
8. **Backup File** - Discovering exposed backup files
9. **HTTP - Directory indexing** - Navigating through indexed directories
10. **HTTP - Headers** - Manipulating custom authentication headers
11. **HTTP - POST** - Tampering with POST data
12. **HTTP - Improper redirect** - Race condition in PHP redirects
13. **HTTP - Verb tampering** - Testing non-standard HTTP methods
14. **Install files** - Accessing installation scripts
15. **Nginx - Alias Misconfiguration** - Path traversal via misconfigured alias
16. **Nginx - Root Location Misconfiguration** - Accessing server config files
17. **CRLF** - Log injection using CRLF characters
18. **File upload - Double extensions** - Bypassing upload filters with double extensions
19. **File upload - MIME type** - Manipulating Content-Type header
20. **HTTP - Cookie** - Cookie manipulation for privilege escalation
21. **Insecure Code Management** - Extracting credentials from exposed .git directory
22. **API - Mass Assignment** - Modifying user roles via mass assignment

## 🛠️ Tools Used

- **Burp Suite** - HTTP request interception and modification
- **curl** - Command-line HTTP client
- **wget** - Downloading exposed repositories
- **GitKraken** - Visualizing Git repository history
- **bash/python/perl** - Scripting and exploitation

## 💡 Key Concepts & Techniques

### Privilege Escalation
- PATH environment variable manipulation
- SUID binary exploitation
- Sudo misconfiguration abuse
- Cron job hijacking

### Web Application Security
- Input validation bypass
- HTTP header manipulation
- Authentication and authorization flaws
- Command injection techniques
- File upload filter evasion
- API security vulnerabilities (IDOR, Mass Assignment)

### Server Misconfigurations
- Directory indexing
- Nginx alias/root misconfigurations
- Exposed sensitive files (.git, backups, install scripts)

### Code Injection
- OS command injection (bash, PHP)
- Script language vulnerabilities (Perl, Python2, PowerShell)
- LaTeX input exploitation
- CRLF injection

## 🚀 Getting Started

To use these writeups:

1. Clone this repository:
```bash
git clone https://github.com/yourusername/rootme-writeups.git
cd rootme-writeups
```

2. Browse the writeups by category
3. Try solving the challenges yourself first on [Root-Me](https://www.root-me.org/)
4. Use the writeups as a reference if you get stuck

## ⚠️ Disclaimer

These writeups are for educational purposes only. The techniques demonstrated should only be used on platforms like Root-Me where you have explicit permission to practice. Never use these techniques on systems you don't own or have permission to test.

## 📖 Learning Resources

- [Root-Me Platform](https://www.root-me.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

## 📬 Contact

If you have questions or suggestions, feel free to open an issue or reach out!

---

**Happy Hacking! 🔐**
