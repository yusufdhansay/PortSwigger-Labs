# Vulnerability Report: Username Enumeration and Credential Brute-Force via Differential Authentication Responses

* **Vulnerability Type:** Improper Authentication (CWE-287) / Information Exposure Through Discrepancies in Authentication Responses (CWE-204) / Missing Rate Limiting (CWE-307)

* **Severity:** High

* **Target Component:** Authentication Module (`POST /login`)

* **OWASP Top 10 Mapping:** A07:2021 – Identification and Authentication Failures

## 1. Executive Summary

A security vulnerability in the application's authentication module permits remote attackers to enumerate valid user accounts and subsequently execute password brute-force attacks. When an authentication request fails, the application returns subtle response discrepancies (such as distinct error strings or variations in response body length) depending on whether the submitted username exists in the system. Coupled with an absolute absence of rate-limiting or account lockout controls, an attacker can automate username harvesting and perform targeted dictionary attacks to compromise accounts.

## 2. Technical Analysis & Root Cause

The flaw consists of two main security weaknesses:

1. **Information Leakage via Response Differential:** The backend authentication handler evaluates credentials sequentially. If the username does not exist in the database, the server returns a specific error message (or response body size). If the username exists but the password is incorrect, a different error response is generated.

2. **Absence of Anti-Automation / Rate Limiting:** The login endpoint does not restrict the frequency of failed login attempts per IP address or account, enabling rapid dictionary enumeration.

```
[ Attacker / Intruder ]
          |
          | 1. POST /login (username=user1, password=dummy)
          v
[ Auth Handler ] ---> Checks Username -> NOT FOUND -> Response: "Invalid username" (Len: 1240)
          |
          | 2. POST /login (username=admin_user, password=dummy)
          v
[ Auth Handler ] ---> Checks Username -> FOUND -> Checks Password -> INVALID
          |
          v
[ Differential Response ] ---> Response: "Incorrect password" (Len: 1255)
          |
          | 3. Brute-Force Password for "admin_user" until HTTP 302 Found
          v
[ Account Compromise ]

```

## 3. Proof of Concept (PoC)

1. Intercept a login request using an HTTP proxy (e.g., Burp Suite):

   ```
   POST /login HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded

   username=invalid_test_user&password=password123
   ```

2. Send the request to **Burp Intruder** and set a payload position on the `username` field.

3. Load the candidate username list and launch the attack.

4. Inspect the attack results. Observe that one request generates a unique response length / string compared to all other candidates, confirming the presence of a valid username in the database.

5. Update the login payload structure in Intruder to set the validated username as a static value while targeting the `password` parameter:

   ```
   POST /login HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded

   username=valid_harvested_user&password=§PAYLOAD§
   ```

6. Load the candidate password wordlist and execute the brute-force attack.

7. Identify the successful login attempt by filtering for an `HTTP 302 Found` response status code (or a distinct session creation payload).

8. **Result:** Authenticate successfully using the enumerated credentials.

## 4. Impact

* **Account Takeover:** Valid user accounts can be programmatically enumerated and brute-forced.

* **Reconnaissance Facilitation:** Attackers can build lists of valid system usernames for downstream phishing or password spraying campaigns.

* **Authentication Safeguard Evasion:** Complete failure of authentication integrity due to missing rate limits and verbose responses.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Implement Generic Authentication Error Messages:**
   Ensure all failed authentication attempts return generic, uniform error messages (e.g., `"Invalid username or password"`) with identical HTTP status codes and uniform response lengths.

2. **Enforce Rate Limiting and Account Lockouts:**
   Implement strict rate limiting (e.g., IP-based throttling via Nginx/WAF or application middleware) and temporary account lockouts after a fixed number of failed login attempts.

3. **Protect Authentication Endpoints with Anti-Automation Controls:**
   Deploy CAPTCHA or risk-based challenge-response mechanisms when suspicious authentication activity is detected.

#### Secure Code Implementation Example (Python / Flask)

```
from flask import Flask, request, render_template, redirect, url_for, session
from werkzeug.security import check_password_hash

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Generic error message variable
    generic_error = "Invalid username or password"
    
    # 1. Fetch user from DB
    user = db_get_user(username)
    
    # Constant-time comparison / dummy password check to prevent timing & differential analysis
    if user is None:
        # Perform dummy hash verification to normalize response timing
        check_password_hash("pbkdf2:sha256:260000$dummy$hash", password)
        return render_template('login.html', error=generic_error), 400
        
    if not check_password_hash(user.password_hash, password):
        return render_template('login.html', error=generic_error), 400
        
    # Successful authentication
    session['user_id'] = user.id
    return redirect(url_for('account_dashboard'))
```

## 6. References

* **CWE-204:** [Response Discrepancy Information Exposure](https://cwe.mitre.org/data/definitions/204.html)

* **CWE-307:** [Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

* **OWASP:** [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)