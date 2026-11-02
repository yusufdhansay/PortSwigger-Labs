# Vulnerability Report: Horizontal Privilege Escalation via IDOR and Unpredictable Identifier Leakage

* **Vulnerability Type:** Insecure Direct Object Reference (IDOR) (CWE-639) / Information Exposure Through Readable Identifiers (CWE-200)

* **Severity:** High

* **Target Component:** Account Profile Handler (`/my-account?id=`) & Blog Author Links

* **OWASP Top 10 Mapping:** A01:2021 – Broken Access Control

## 1. Executive Summary

An Insecure Direct Object Reference (IDOR) vulnerability exists in the account management functionality. While the application attempts to mitigate parameter guessing by using Globally Unique Identifiers (GUIDs) instead of sequential integers, it exposes these GUIDs publicly across other features (such as blog post author attribution). Once an attacker retrieves a target user's GUID from public content, they can query the private account management endpoint using that GUID to access sensitive profile data and API tokens belonging to other users.

## 2. Technical Analysis & Root Cause

The vulnerability demonstrates the weakness of relying on random identifiers (GUIDs/UUIDs) as a substitute for explicit access control checks.

### Information Exposure and Access Control Breakdown

1. **Identifier Leakage:** Public features, such as blog post author links, expose internal user GUIDs to unauthenticated or standard users.

2. **Lack of Ownership Checks:** When processing `/my-account?id=[GUID]`, the backend retrieves the database object associated with `[GUID]` without verifying whether `session.user_guid == request.args.get('id')`.

3. **Ineffective Obscurity:** The randomness of a GUID prevents brute-force enumeration, but fails to prevent exploitation once the identifier is leaked or discovered through alternative endpoints.

```
[ Attacker: wiener ]
        |
        | 1. Read Public Blog Post -> Extract author link containing Carlos's GUID
        v
[ Leaked Identifier: carlos-guid ]
        |
        | 2. GET /my-account?id=carlos-guid
        v
[ Web Server ]
        |
        | (Session check: Valid user 'wiener')
        | (Authorization check: MISSING)
        | (Data Retrieval: SELECT * FROM users WHERE id = 'carlos-guid')
        v
[ Private Profile Response ] ---> API Key Exfiltrated

```

## 3. Proof of Concept (PoC)

1. Authenticate with standard credentials (`wiener:peter`).

2. Navigate to the application home page and inspect published blog posts to locate an article written by user `carlos`.

3. Click on or inspect the author link for `carlos` to extract the destination parameter containing his GUID:

   ```
   GET /posts?author=carlos HTTP/1.1
   Host: target-app.net
   
   ```

   *Observed Navigation URL:* `/my-account?id=b2a9e4d1-8f3c-4b2a-9e1d-8f3c4b2a9e1d`

4. Issue an HTTP GET request to the account profile endpoint using Carlos's harvested GUID:

   ```
   GET /my-account?id=b2a9e4d1-8f3c-4b2a-9e1d-8f3c4b2a9e1d HTTP/1.1
   Host: target-app.net
   Cookie: session=vX9z...
   
   ```

5. **Observe Response:** The server processes the request with `HTTP 200 OK`, returning the HTML account dashboard for Carlos.

6. Inspect the page contents to retrieve the sensitive API key:

   ```
   <div id="account-details">
       <p>Your API key is: <code>x7K9pQ2m...</code></p>
   </div>
   
   ```

## 4. Impact

* **Horizontal Privilege Escalation:** Any authenticated user can view sensitive profile data of any user whose GUID is exposed within public application features.

* **Exposure of API Credentials:** Exfiltrated API keys can be leveraged to impersonate victims across REST/GraphQL API endpoints.

* **Flawed Defense-in-Depth:** Demonstrates that high-entropy identifiers do not constitute access control.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Context-Based Access Control Checks:**
   Always enforce explicit server-side authorization checks verifying that `session.user_id` matches the requested object's owner identifier before returning response data.

2. **Session-Driven Identity Lookup:**
   Avoid accepting user identifiers via URL parameters for single-tenant profile pages. Query the logged-in user's data directly using identity attributes stored in the server session.

3. **Separate Public and Private Identifiers:**
   If public profile URLs require identifiers, use distinct public slugs or public aliases rather than internal database keys or primary GUIDs.

#### Secure Code Implementation Example (Python / Flask)

```
from flask import Flask, request, session, abort, render_template

app = Flask(__name__)

@app.route('/my-account', methods=['GET'])
def get_user_account():
    # Retrieve user GUID directly from authenticated session state
    session_user_guid = session.get('user_guid')
    if not session_user_guid:
        abort(401)  # Unauthorized
        
    requested_guid = request.args.get('id')
    
    # Enforce Object-Level Authorization Check regardless of GUID complexity
    if requested_guid != session_user_guid:
        abort(403)  # Forbidden - Prevent cross-account data access
        
    user_profile = db_fetch_profile(session_user_guid)
    return render_template('account.html', profile=user_profile)

```

## 6. References

* **CWE-639:** [Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

* **CWE-200:** [Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

* **OWASP API Security:** [API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)