# Lab 5 - User ID controlled by request parameter

## Given
The lab has a horizontal privilege escalation vulnerability on the user account page. Log in using credentials `wiener:peter`

## End Goal
Obtain the API key for user `carlos` and submit it as solution

## Quick Steps
1. Log in using the given credentials `wiener:peter`
2. Naviagate to **My Account** page, intercept the request and send it to **Burp Repeater**
3. Change the `id` parameter from `id=wiener` to `id=carlos`
4. Submit the request and inspect the `200 OK` response to confirm the presence of Carlos's API Key
5. Submit the retrieved API key into the solution field

## Payload and Mechanics
- **Original Request:** `GET my-account?id=wiener`
- **IDOR Payload:** `GET my-account?id=carlos`

## Why it works
- The application handler uses the `id` query parameter value directly to fetch account records from the database instead of deriving identity from the authenticated session
- No authorization check confirms whether `session.username == request.params.id`

## Result
Horizontal privilege escalation is achieved, exposing user `carlos's` API Key. Lab solved