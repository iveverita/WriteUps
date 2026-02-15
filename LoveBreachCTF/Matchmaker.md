# Matchmaker - CTF Writeup

## Challenge Information
- **Challenge Name:** Matchmaker
- **Target:** `http://10.80.137.239`
- **Vulnerability:** MD5 Hash Collision
- **Difficulty:** Medium

## Reconnaissance

The challenge presented a Valentine's Day themed dog matchmaking service called "Matchmaker" that used MD5 hashing to pair users with their ideal dog companions.

**Challenge Description Key Points:**
- "comparing **MD5** fingerprints"
- "The algorithm is completely **transparent**"
- "hash chemistry"
- "two MD5s lock eyes"

These clues strongly indicated an MD5 collision attack vector.

### Initial Enumeration

Port scan revealed two open services:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
80/tcp open  http    nginx
```

Directory enumeration identified key endpoints:
```
/static    - Static assets (Status: 301)
/upload    - File upload endpoint (Status: 405 - POST only)
```

## Vulnerability Analysis

### MD5 Cryptographic Weakness

MD5 (Message Digest 5) is a cryptographic hash function that produces a 128-bit hash value. However, MD5 has been cryptographically broken since 2004 when researchers demonstrated practical collision attacks.

**Key Vulnerability:**
- MD5 collisions allow two different inputs to produce the same hash output
- Applications relying on MD5 for file integrity or deduplication can be exploited
- Collision attacks are computationally feasible with modern techniques

### Application Logic

The Matchmaker application appeared to:
1. Accept file uploads from users
2. Calculate MD5 hash of uploaded files
3. Use MD5 hash to match users with dogs
4. Implement duplicate detection based on MD5 hash
5. Potentially detect or reward hash collision attempts

## Exploitation

### Step 1: Understanding MD5 Collision Attack

An MD5 collision attack involves creating two different files that produce identical MD5 hash values. This exploits the mathematical weakness in MD5's compression function.

**Attack Requirements:**
- Generate or obtain two files with different content
- Both files must produce the same MD5 hash
- Files should be valid for upload (if format restrictions exist)

### Step 2: Generating Collision Files

Created a Python script to generate MD5 collision blocks using known collision techniques from Marc Stevens' research:

```python
#!/usr/bin/env python3
import hashlib

# Verified collision blocks that produce identical MD5 hashes
# Source: https://www.mscs.dal.ca/~selinger/md5collision/

prefix = b""

# First collision block
block1_part1 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
)

# Second collision block (differs in only a few bytes)
block2_part1 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
)

with open("collision1.bin", "wb") as f:
    f.write(prefix + block1_part1)

with open("collision2.bin", "wb") as f:
    f.write(prefix + block2_part1)

hash1 = hashlib.md5(open("collision1.bin", "rb").read()).hexdigest()
hash2 = hashlib.md5(open("collision2.bin", "rb").read()).hexdigest()

print(f"[+] File 1 MD5: {hash1}")
print(f"[+] File 2 MD5: {hash2}")
print(f"[+] Collision: {hash1 == hash2}")
```

**Execution Result:**
```bash
$ python3 create_collision_v2.py
[+] File 1 MD5: 79054025255fb1a26e4bc422aef54eb4
[+] File 2 MD5: 79054025255fb1a26e4bc422aef54eb4
[+] Collision: True
[+] SUCCESS! Collision files created
```

**Verification:**
```bash
$ md5sum collision1.bin collision2.bin
79054025255fb1a26e4bc422aef54eb4  collision1.bin
79054025255fb1a26e4bc422aef54eb4  collision2.bin

$ diff collision1.bin collision2.bin && echo "Files identical" || echo "Files different"
Files different
```

Both files produced identical MD5 hashes despite having different content.

### Step 3: First Upload - Establishing Baseline

Uploaded the first collision file to establish a baseline hash in the system:

```bash
curl -X POST http://10.80.137.239/upload \
  -F "file=@collision1.bin" \
  -v
```

**Response:**
```
HTTP/1.1 302 FOUND
Location: /upload_success/0c0421c8-39ad-4e64-8b5f-b6cc6d605875
```

**Result Page:**
```html
<title>Matchmaker / Already uploaded</title>
<h1>Your photo already lives here</h1>
<p>We already received that exact snapshot, so there is no need to upload it again.</p>
```

The server stored the file and its MD5 hash, implementing duplicate detection.

### Step 4: Second Upload - Triggering Collision Detection

Uploaded the second collision file with the same MD5 hash but different content:

```bash
curl -X POST http://10.80.137.239/upload \
  -F "file=@collision2.bin" \
  -v
```

**Response:**
```
HTTP/1.1 302 FOUND
Location: /upload_success/2ebaf105-bb2e-4a45-abbd-2d89b9522603
```

**Result Page:**
```html
<title>Matchmaker / Match in progress</title>
<h1>We are pairing you with a pup</h1>
<p>The MD5 match is loading, and the dogs are already sniffing around.</p>

<div class="match-result" aria-live="polite" data-match="true">
  <i class="fa"></i>
  <p class="match-result-text">
    <span class="match-flag">
      <i class="fa fa-dog"></i> THM{hash_puppies_4_all}
    </span>
  </p>
</div>
```

### Step 5: Flag Capture

The application detected the MD5 collision:
- Same MD5 hash as the first upload
- Different file content
- System recognized the collision and revealed the flag

**Flag Retrieved:**
```
THM{...}
```

## Attack Chain Summary

1. **Reconnaissance** → Identified MD5-based matching system
2. **Vulnerability Analysis** → Recognized MD5 collision opportunity
3. **Collision Generation** → Created two files with identical MD5 hashes
4. **First Upload** → Established baseline hash in database
5. **Second Upload** → Triggered collision detection with different content
6. **Flag Discovery** → Application rewarded hash collision demonstration
7. **Flag Capture** → Successfully extracted flag from match result page

## Key Vulnerabilities

1. **MD5 Hash Collisions** - Using cryptographically broken MD5 algorithm
2. **File Integrity Reliance** - Trusting MD5 for file deduplication
3. **Weak Hash Function** - No migration to secure alternatives (SHA-256, SHA-3)
4. **Predictable Behavior** - Collision detection revealing sensitive information
5. **Algorithm Transparency** - Openly advertising vulnerable hash function

