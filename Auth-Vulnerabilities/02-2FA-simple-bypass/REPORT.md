# Vulnerability Report: Two-Factor Authentication (2FA) Bypass via Direct Navigation

* **Vulnerability Type:** Improper Authentication (CWE-287) / Execution with Unreachable Code / Flawed 2FA Enforcement (CWE-306)

* **Severity:** High

* **Target Component:** Authentication Workflow (`/login` & `/login2`)

* **OWASP Top 10 Mapping:** A07:2021 – Identification and Authentication Failures

## 1. Executive Summary

A critical authentication flaw was identified in the application's multi-factor authentication (2FA) implementation. Upon verifying primary credentials (username and password) via the initial login endpoint (`POST /login`), the backend server immediately grants full session privileges before the user completes secondary verification. Because protected internal routes (such as `/my-account`) fail to enforce a mandatory check for completed 2FA validation, an attacker who possesses a victim's primary credentials can bypass the 2FA prompt completely by directly navigating to protected application URLs.

## 2. Technical Analysis & Root Cause

The vulnerability is caused by improper session state management during multi-stage authentication workflows.

### Flawed Authentication Architecture

1. **Premature Session Authorization:** Upon successful password verification at Step 1 (`POST /login`), the application generates a fully privileged session cookie and returns a redirect to the 2FA verification page (`/login2`).

2. **Decoupled 2FA Enforcement:** The server relies on the client front-end to sequentially navigate from `/login2` to `/my-account` upon submitting the correct code, rather than blocking access to `/my-account` at the authorization layer.

3. **Missing Workflow Authorization Check:** Protected route controllers only evaluate the presence of a valid session cookie, ignoring whether secondary authentication (`2FA_VERIFIED = True`) was ever executed.

```
[ Attacker / Client ]
          |
          | 1. POST /login (username=carlos, password=montoya)
          v
[ Auth Server ] ---> Validates password -> Issues FULL SESSION Cookie -> Redirects to /login2
          |
          | 2. GET /my-account (Direct Navigation — Skips /login2)
          v
[ Protected Resource Handler ]
          |
          | 3. Checks session cookie -> VALID (2FA completion state check MISSING!)
          v
[ Access Granted to Victim Account ]


```

## 3. Proof of Concept (PoC)

1. Authenticate using known user credentials (`wiener:peter`).

2. Complete the 2FA challenge via the provided email client and observe the resulting account page URL structure (`/my-account`).

3. Log out of the account.

4. Submit a login request for target user `carlos` using valid primary credentials (`carlos:montoya`):

   ```
   POST /login HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded
   
   username=carlos&password=montoya
   
   
   ```

5. Observe the HTTP response issuing a session cookie (`Set-Cookie: session=...`) and redirecting to the 2FA prompt page (`/login2`).

6. Instead of submitting a 2FA code to `/login2`, issue a direct `GET` request to the protected account page using the newly acquired session cookie:

   ```
   GET /my-account HTTP/1.1
   Host: target-app.net
   Cookie: session=carlos_session_id
   
   
   ```

7. **Observe Response:** The server responds with `HTTP/1.1 200 OK`, returning the full account interface for user `carlos`.

8. **Result:** Full 2FA bypass and account takeover achieved.

## 4. Impact

* **Multi-Factor Authentication Failure:** Renders the 2FA security layer completely ineffective against credential theft.

* **Account Takeover:** Anyone possessing valid primary credentials can bypass 2FA controls and gain full account access.

* **Broken Workflow Logic:** Highlights improper session management design across multi-stage processes.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Implement Partial Session States for 2FA:**
   Do not issue fully authenticated session tokens after Step 1. Issue a temporary, low-privilege token (e.g., `2FA_PENDING`) that strictly permits access *only* to the `/login2` validation endpoint.

2. **Enforce Mandatory 2FA Completion Verification:**
   Ensure protected resource handlers verify that the active session maintains a fully validated state (`session['2fa_verified'] == True`) before returning data.

3. **Invalidate Unfinished 2FA Sessions:**
   Set short expiration timeouts on pending 2FA states and destroy sessions if verification is skipped or abandoned.

#### Secure Code Implementation Example (Python / Flask)

```
from flask import Flask, request, session, redirect, url_for, abort, render_template

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login_step1():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if verify_password(username, password):
        # Set a TEMPORARY, limited session state — DO NOT grant full access yet
        session['user_id'] = username
        session['2fa_verified'] = False
        return redirect(url_for('login_step2'))
        
    return render_template('login.html', error="Invalid credentials"), 400

@app.route('/my-account', methods=['GET'])
def my_account():
    # Enforce strict 2FA state check on all protected routes
    if not session.get('user_id'):
        return redirect(url_for('login_step1'))
        
    if not session.get('2fa_verified', False):
        # Reject access if 2FA has not been completed
        return redirect(url_for('login_step2'))
        
    user_data = db_get_profile(session['user_id'])
    return render_template('account.html', user=user_data)


```

## 6. References

* **CWE-287:** [Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

* **CWE-306:** [Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

* **OWASP:** [Multi-Factor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)