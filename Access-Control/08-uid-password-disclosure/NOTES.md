# Lab 8 - User ID controlled by request parameter with password disclosure

## Given
The lab has user account page that contains the current user's existing password, prefilled in a masked input. Log in to your own account using the following credentials: `wiener:peter`

## Quick Steps
1. Log in using given credentials (`wiener:peter`)
2. Intercept the request to **My Account** (`GET /my-account?id=wiener`) in **Burp Suite** and send to **Repeater**
3. Modify the `id` parameter to target the administrator account: `GET /my-account?id=administrator`
4. Send the request and inspect the response body HTML to locate administrator's password
5. Log out of `wiener` and log in as `administrator` using the extracted password
6. Access `/admin` and execute the deletion of user `carlos`

## Payload and Mechanics
- **Target Vector:** `GET /my-account?id=administrator`
- **Admin Action:** `GET /admin/delete?username=carlos`

## Why it works
- The application renders passwords directly into client HTML markup instead of omitting them or handling credential verification server-side
- The server trusts the `id=administrator` URL parameter and returns full account details without verifying session ownership

## Result
Administrator credentials are retrieved, user carlos is deleted. Lab solved