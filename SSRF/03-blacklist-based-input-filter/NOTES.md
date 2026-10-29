# Lab 3 - SSRF with blacklist-based input filter

## Given
The lab has a stock check feature which fetches data from an internal system

## End Goal
Access admin interface and delete the user named `**carlos**`. The developer has deployed two weak anti-SSRF defences that we have to bypass

## Quick Steps
1. Intercept the stock check request in **Burp Suite** and send it to **Repeater**
2. URL-decode `stockApi`
3. Attempt basic bypasses against the blocked `127.0.0.1` and `localhost` domains
4. Replace `localhost` with `127.1` (shortened loopback notation) to bypass the host filter
5. Bypass path filtering by double URL-encoding any letter in `admin` string (Example: `%2561dmin`)
6. Access the administrative page (`http://127.1/%2561dmin`) and issue the deletion request (`http://127.1/%2561dmin/delete?username=carlos`)

## Payload and Mechanics
- `127.1` evaluates to `127.0.0.1`
- `%2561dmin` (Double-encoded `admin`: `a` $\rightarrow$ `%61` $\rightarrow$ `%2561`)

## Why it works
- **IP Format Normalization:** The input filter performs string-matching against standard loopback strings (`127.0.0.1`, `localhost`) but fails to resolve alternative IP representations before evaluation
- **Double Decoding Flaw:** The input filter checks the request payload *after* one layer of URL decoding. Passing `%2561dmin` causes the filter to see `%61dmin` (which passes inspection), but the backend application server performs a second decoding step prior to fetching the resource, resulting in `/admin`

## Result
Both anti-SSRF defences are bypassed, allowing deletion of user. Lab solved



locahost ==> http://127.1/
admin interface ==> https://127.1/%25%36%31dmin
delete user ==> http://127.1/%25%36%31dmin/delete?username=carlos