# Vulnerability Report: Vertical Privilege Escalation via Flawed Referer-Based Authorization Checks

* **Vulnerability Type:** Broken Access Control (CWE-284) / Improper Authorization via Client-Controlled Headers (CWE-290) / Missing Function Level Access Control (CWE-306)

* **Severity:** High

* **Target Component:** Role Administration Endpoint (`/admin-roles`)

* **OWASP Top 10 Mapping:** A01:2021 – Broken Access Control

## 1. Executive Summary

A critical vertical privilege escalation vulnerability was identified in the application's role management module (`/admin-roles`). The application uses the HTTP `Referer` header as its primary mechanism for verifying administrative authority. Requests containing a `Referer` header pointing to `/admin` are treated as authorized, regardless of the role permissions attached to the requesting user's session. An authenticated non-administrative user can manipulate the request parameters while preserving an administrative `Referer` header to promote their own account to an administrative role.

## 2. Technical Analysis & Root Cause

The vulnerability originates from treating client-controlled HTTP headers as trusted security assertions rather than enforcing server-side role validation.

### Vulnerability Architecture

1. **Flawed Authorization Logic:** Upon receiving a request to `/admin-roles`, the application inspects the HTTP request headers:
   `if request.headers.get('Referer') contains '/admin' -> Grant Access`.

2. **Client Header Tampering:** The HTTP `Referer` header is supplied by the client's browser and can be arbitrarily crafted or spoofed using intercepting proxies like Burp Suite or custom scripts.

3. **Session Decoupling:** The application evaluates the `Referer` header in isolation without validating whether the user session ID in the `Cookie` header corresponds to a user with administrative permissions.

```
[ Low-Privileged User: wiener ]
              |
              | GET /admin-roles?username=wiener&action=upgrade
              | Cookie: session=wiener_session
              | Referer: https://target-app.net/admin  <-- Spoofed/Retained Admin Header
              v
[ Web Application Server ]
              |
              | 1. Evaluates Referer header: Contains "/admin"? YES
              | 2. Session validation check: OMITTED / Bypassed
              v
[ Database / Privilege Upgrade ] ---> Grants Admin Rights to "wiener"

```

## 3. Proof of Concept (PoC)

1. Authenticate as an administrative user (`administrator:admin`) and navigate to the administrative dashboard.

2. Trigger a role promotion for user `carlos` and capture the request using Burp Suite:

   ```
   GET /admin-roles?username=carlos&action=upgrade HTTP/1.1
   Host: target-app.net
   Cookie: session=admin_session_val
   Referer: https://target-app.net/admin
   
   ```

3. Log out of the `administrator` account and authenticate as standard user `wiener:peter`.

4. Retrieve `wiener`'s session token from the browser cookie store.

5. Send the captured request to **Burp Repeater** and make the following modifications:
   * Replace the `Cookie` header value with `wiener`'s session token.
   * Change the target `username` parameter to `wiener`.
   * Keep the `Referer: https://target-app.net/admin` header unchanged.

   ```
   GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
   Host: target-app.net
   Cookie: session=wiener_session_val
   Referer: https://target-app.net/admin
   
   ```

6. Submit the request and observe the `HTTP/1.1 200 OK` response.

7. Refresh the web session in the browser to confirm that `wiener` has been successfully granted administrative privileges.

## 4. Impact

* **Vertical Privilege Escalation:** Any authenticated standard user can elevate their privilege level to full administrator.

* **Complete System Takeover:** Administrative privileges enable total control over user management, application data, and internal configurations.

* **Fundamental Access Control Breakdown:** Failure to enforce server-side, session-bound authorization controls.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Remove Header-Based Authorization Checks:**
   Never use `Referer`, `Origin`, or other client-controlled HTTP request headers to make access control or authorization decisions.

2. **Enforce Session-Based Role Verification:**
   Validate user permissions exclusively using server-side session data tied securely to the authenticated user ID.

3. **Implement Centralized Authorization Middleware:**
   Apply consistent authorization logic at the application controller level prior to executing privileged functions.

#### Secure Code Implementation Example (Python / Flask)

```
from flask import Flask, request, session, abort, jsonify

app = Flask(__name__)

@app.route('/admin-roles', methods=['GET'])
def update_user_role():
    # Retrieve user identity and role directly from the authenticated server-side session
    current_username = session.get('username')
    user_role = session.get('role')
    
    # Strictly reject non-admin users regardless of Referer or Origin headers
    if not current_username or user_role != 'ADMIN':
        abort(403)  # Forbidden

    target_user = request.args.get('username')
    action = request.args.get('action')

    # Execute privileged role modification logic safely
    db_modify_role(target_user, action)
    return jsonify({"status": "success", "message": f"User {target_user} role updated."}), 200

```

## 6. References

* **CWE-284:** [Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

* **CWE-290:** [Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

* **CWE-306:** [Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

* **OWASP:** [Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)