# Lab 3 - User role controlled by request parameter

## Given
The lab has an admin panel at `/admin`, which identifies administrators using a forgeable cookie. Log in to your own account using the following credentials: **`wiener:peter`**

## End Goal
Access the admin panel and delete the user `carlos`

## Quick Steps
1. Log in using the given credentials: (`wiener:peter`)
2. Intercept the request to `/myaccount` and send it to **Burp Repeater**
3. Inspect HTTP header for admin cookie
4. Modify the request cookie parameter from `Admin=false` to `Admin=true`
5. Update the endpoint path from `/myaccount` to `/admin`
6. Access the admin panel and issue carlos user deletion

## Payload and Mechanics
- **Original Cookie:** `Cookie: Admin=false; session=...`
- **Tampered Cookie:** `Cookie: Admin=true; session=...`
- **Target Endpoint:** `GET /admin/delete?username=carlos`

## Why it works
- The application trusts state flags passed directly from the browser instead of verifying roles on the server side using securely managed session storage or signed tokens
- The cookie values are sent in plain text without HMAC signatures or JWT structures, allowing arbitrary modification.

## Result
Admin panel is accessed via parameter tampering, enabling deletion of user `carlos`. Lab solved