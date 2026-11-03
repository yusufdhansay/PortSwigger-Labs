# Lab 11 - Method-based access control can be circumvented

## Given
This lab implements access controls based partly on the HTTP method of requests. You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`

## End Goal
Log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator

## Quick Steps
1. Log in using admin credentials (`administrator:admin`) and capture a legitimate role promotion request (`POST /admin-roles`) in **Burp Suite**
2. Log in as wiener user (`wiener:peter`) and retrieve the active session cookie from `/my-account`
3. In **Burp Repeater**, replace the admin session token with the wiener user's session token
4. Attempt to resend the `POST /admin-roles` request; observe that access is denied `403 Forbidden`
5. Change the HTTP request method from `POST` to `GET` and convert parameters into query string format: `GET /admin-roles?username=wiener&action=upgrade`
6. Send the request to execute the privilege escalation

## Payload & Mechanics
- **Blocked Request:** `POST /admin-roles` with body `username=wiener&action=upgrade`
- **Bypass Request:** `GET /admin-roles?username=wiener&action=upgrade`

### Why it works:
- The access control layer is configured with method-specific security rules, leaving other HTTP verbs (`GET`, `HEAD`) uninspected
- The backend framework handles request parameters flexibly, mapping both query parameters (`GET`) and body parameters (`POST`) into the same controller action

## Result
User `wiener` is promoted to admin by switching the HTTP method from `POST` to `GET`. Lab solved