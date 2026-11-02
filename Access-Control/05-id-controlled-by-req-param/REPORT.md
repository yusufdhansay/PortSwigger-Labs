# Vulnerability Report: Horizontal Privilege Escalation via Insecure Direct Object Reference (IDOR)

* **Vulnerability Type:** Insecure Direct Object Reference (IDOR) (CWE-639) / Broken Object Level Authorization (CWE-284)

* **Severity:** High

* **Target Component:** Account Management Endpoint (`/my-account?id=`)

* **OWASP Top 10 Mapping:** A01:2021 – Broken Access Control

## 1. Executive Summary

A critical horizontal privilege escalation vulnerability was identified in the user account management module. The application relies on an unvalidated user-controlled query parameter (`id`) to determine which profile data to display. Because the backend fails to verify that the requesting user's active session matches the requested account parameter, an authenticated user can view private account details—including sensitive API tokens—belonging to any other user registered on the application.

## 2. Technical Analysis & Root Cause

The vulnerability stems from a lack of session-to-object ownership verification on sensitive user data endpoints.

### Vulnerability Architecture

1. **Direct Parameter Lookup:** When a user navigates to `/my-account?id=wiener`, the controller reads the `id` parameter directly from the URL.

2. **Decoupled Session Context:** Although the user presents a valid session cookie, the backend logic queries the database solely based on the URL parameter (`SELECT * FROM users WHERE username = request.get('id')`).

3. **Missing Authorization Layer:** The application lacks middleware or server-side checks to enforce that `session.user_id` matches `request.get('id')`.

```
[ Authenticated User: wiener ]
              |
              | GET /my-account?id=carlos
              v
[ Application Server ]
              |
              | (Session check: Valid user wiener)
              | (Authorization check: MISSING)
              | (Query: FETCH profile WHERE username = 'carlos')
              v
[ Sensitive Profile Data Exposed ] ---> Returns API key for carlos
```

## 3. Proof of Concept (PoC)

1. Log in to the target application using valid user credentials (`wiener:peter`).

2. Navigate to **My Account** and capture the HTTP GET request using an HTTP proxy (e.g., Burp Suite):

   ```http
   GET /my-account?id=wiener HTTP/1.1
   Host: target-app.net
   Cookie: session=vX9z...
   ```

3. Send the request to **Burp Repeater**. Modify the `id` parameter to target user `carlos`:

   ```http
   GET /my-account?id=carlos HTTP/1.1
   Host: target-app.net
   Cookie: session=vX9z...
   ```

4. Submit the request and observe the `HTTP/1.1 200 OK` response.

5. Search the HTML response body for the sensitive API key section:

   ```html
   <div id="account-details">
       <p>Your API key is: <code>aB3x9K...</code></p>
   </div>
   ```

6. **Result:** User `carlos`'s API key is successfully exfiltrated via horizontal privilege escalation.

## 4. Impact

* **Horizontal Privilege Escalation:** Any authenticated user can access the private profile data of any other application user.

* **Sensitive Data Exposure:** Exposure of API keys, PII, account tokens, and administrative data.

* **Account Compromise:** Stolen API tokens or account data can lead to complete downstream takeover of API endpoints and user sessions.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Derive Identity from Authenticated Session:**
   Do not rely on client-supplied parameters (`id`, `username`, `user_id`) to identify target user accounts. Retrieve object details using the authenticated user identity stored securely in the server-side session.

2. **Enforce Object-Level Authorization Checks:**
   If referencing resource IDs explicitly in URLs is required, enforce authorization logic verifying that the requesting session owns the target resource before returning data.

#### Secure Code Implementation Example (Python / Flask)

```python
from flask import Flask, request, session, abort, render_template

app = Flask(__name__)

@app.route('/my-account', methods=['GET'])
def view_account():
    # 1. Retrieve identity strictly from server-side session
    authenticated_user = session.get('username')
    if not authenticated_user:
        abort(401)  # Unauthorized
        
    # 2. Derive requested resource ID
    requested_id = request.args.get('id')
    
    # 3. Enforce strict Object-Level Access Control (IDOR Protection)
    if requested_id != authenticated_user:
        abort(403)  # Forbidden - Block horizontal access attempts
        
    # Fetch account data safely for authorized user
    user_data = db_get_user_profile(authenticated_user)
    return render_template('account.html', user=user_data)
```

## 6. References

* **CWE-639:** [Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

* **CWE-284:** [Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

* **OWASP API Security:** [API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)