# Lab 4 - SSRF with filter bypass via open redirection vulnerability

## Given
The lab has a stock check feature which fetches data from an internal system

## End Goal
Change the stock check URL to access the admin interface at `http://192.168.0.12:8080/admin` and delete the user `carlos`. The stock checker has been restricted to only access the local application, so you will need to find an open redirect affecting the application first

## Quick Steps
1. Intercept the stock check, next product link request and send it to **Burp Repeater**
2. Rename both the requests appropriately to avoid confusion
3. `stockApi` in `stock-check` only accepts relative path structures, blocking external URLs
4. Test the `next-product` endpoint (`/product/nextProduct?currentProductId=1&path=...`) for open redirection by supplying an arbitrary URL (e.g., `&path=https://google.com`). Confirm that the server follows the redirect, indicating open redirect vulnerability
5. URL-encode the payload and send it within the `stockApi` parameter to access the admin panel
6. Add the user deletion parameter and encode it to delete the user and solve the lab

## Payload and Mechanics
- **Payload to access admin panel:** `/product/nextProduct?currentProductId=1&path=192.168.0.12:8080/admin`
- **Payload to delete user `carlos`:** `/product/nextProduct?currentProductId=1&path=192.168.0.12:8080/admin/delete?username=carlos`

(**Make sure to URL-encode the path using `Ctrl + U` / `Cmd + U`**)

## Why it works
- **Flawed Path Validation:** The stock checker enforces a rule that `stockApi` must begin with a local path (`/product/...`), preventing direct insertion of `http://...`
- **Chained Redirection:** Because the open redirect handler (`/product/nextProduct`) is a valid local path, it passes the input filter. When the server-side HTTP client issues a request to that local path, it receives an HTTP `302 Found` response pointing to the internal IP (`192.168.0.12:8080`), which the client follows

## Result
The filter is successfully bypassed via redirection, resulting in deletion of user `carlos`