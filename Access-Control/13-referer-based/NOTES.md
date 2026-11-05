# Lab 13 - Referer-based access control

## Given
The lab controls access to certain admin functionality based on the Referer header. Familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`

## End Goal
Log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator

## Quick Steps
1. Authenticate using administrative credentials (`administrator:admin`)
2. Promote user `carlos` to administrator and intercept the request in **Burp Suite**. Send it to **Repeater**
3. Log out of `administrator` and log in as standard user `wiener:peter`
4. Copy `wiener`'s session cookie from browser developer tools
5. In **Burp Repeater**, replace the administrative session cookie with `wiener`'s session cookie
6. Change the target username parameter to `wiener`: `GET /admin-roles?username=wiener&action=upgrade`
7. Keep the admin `Referer` header intact (`Referer: https://target-app.net/admin`)
8. Send the request and observe `200 OK`. User `wiener` is now promoted to an admin

## Payload & Mechanics
- **Original Request:**
  `GET /admin-roles?username=carlos&action=upgrade`
  `Cookie: session=admin_session`
  `Referer: https://target-app.net/admin`
- **Exploit Request:**
  `GET /admin-roles?username=wiener&action=upgrade`
  `Cookie: session=wiener_session`
  `Referer: https://target-app.net/admin`

### Why it works:
- The server checks `request.headers.get('Referer')` to determine whether the request originated from `/admin`. Because HTTP headers are fully client-controlled, any user or attacker can forge or retain this header in their requests
- The endpoint fails to verify if the session associated with the request cookie belongs to an account with administrative privileges.

## Result
User `wiener` is promoted to an admin by exploiting the vertical access control vulnerability. Lab solved