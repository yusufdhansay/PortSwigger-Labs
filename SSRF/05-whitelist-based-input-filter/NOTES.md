# Lab 5 - SSRF with whitelist-based input filter

## Given
The lab has a stock check feature which fetches data from an internal system

## End Goal
Change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`. The developer has deployed an anti-SSRF defense that we need to bypass

## Quick Steps
1. Intercept the stock check request in **Burp Suite** and send it to **Repeater**.
2. `stockApi` strictly validates the URL against an allowed host whitelist (`stock.weliketoshop.net`). So we cannot modify the URL to our liking
3. Test credential syntax: `http://localhost@stock.weliketoshop.net/`. This bypasses whitelist parsing, but targets `stock.weliketoshop.net` with user `localhost`
4. Introduce fragment delimiter to treat the whitelist string as part of the fragment: `http://localhost#@stock.weliketoshop.net/`.
5. Apply double URL encoding to the `#` character (`#` -> `%23` -> `%2523`) so the filter permits the string and routes the request to `localhost`.
6. Access administrative endpoint (`http://localhost%2523@stock.weliketoshop.net/admin`) and delete the user named `carlos`

## Payload and Mechanics
- **Unencoded Payload:** `http://localhost#@stock.weliketoshop.net/admin`
- **Double URL-Encoded Payload:** `http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos`

## Why it works
- URL parsers handle `@` (user info indicator) and `#` (fragment delimiter) differently

## Result
The whitelist-based filter is bypassed via URL parser differentials, user `carlos` is deleted. Lab solved
