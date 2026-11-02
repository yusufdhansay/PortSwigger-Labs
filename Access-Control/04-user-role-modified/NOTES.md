# Lab 4 - User role can be modified in user profile

## Given
The lab has an admin panel at `/admin`. It's only accessible to logged-in users with a roleid of 2. Log in using credentials `wiener:peter`

## End Goal
Access the admin panel and delete the user `carlos`

## Quick Steps
1. Log in using given credentials `wiener:peter`
2. Submit email change request in `My Account`, find it in **Burp HTTP History** and send it to **Burp Repeater**
3. Send the POST request. In the response tab, identify the `roleid` paramater
4. Add the `"roleid":2` parameter below the email parameter in the request and send
5. Refresh `My Account` in the browser. Access the admin panel and delete `carlos` user

## Payload and Mechanics
- **Original JSON Payload:** `"email": "user@example.com"`
- **Modified Payload:** `"email": "user@example.com", "roleid": 2`
- **Target Deletion Endpoint:** `GET /admin/delete?username=carlos`

## Why it works
- The backend endpoint automatically binds incoming JSON key-value pairs directly to internal user fields without filtering against a strict field whitelist
- Authorization roles `(roleid)` are stored as mutable object attributes editable via generic update routes, rather than being strictly assigned and validated server-side during administrative operations

## Result
User wiener is assigned `roleid:2` and admin privilege. User carlos is deleted. Lab solved