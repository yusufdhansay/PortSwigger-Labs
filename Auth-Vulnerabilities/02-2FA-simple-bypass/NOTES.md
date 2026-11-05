# Lab 2 - 2FA simple bypass

## Given
The lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code

- Your credentials: `wiener:peter`
- Victim's credentials: `carlos:montoya`

## End Goal
Access `carlos`'s account page

## Quick Steps
1. Log in using the given credentials (`wiener:peter`)
2. Use the built-in email client when prompted for the 2FA code and note the endpoint URL of the account dashboard (`/my-account`)
3. Log out and initiate a login using the victim's credentials (`carlos:montoya`)
4. When prompted for the 2FA code, manually modify the URL in the address bar and add `/my-account` at the end
5. The server returns Carlos's account page

## Payload and Mechanics
- **Step 1:** Submit `POST /login` (`username=carlos&password=montoya`) $\rightarrow$ Server sets authenticated session cookie
- **Step 2 (Bypass Vector):** Request `GET /my-account` directly, bypassing `/login2`

## Why it works
- The backend sets the session state to fully authenticated after Step 1, rather than marking it with a temporary `2FA_PENDING` flag
- Protected routes like `/my-account` only check if a session cookie exists, failing to verify whether the session has successfully completed 2FA validation

## Result
User `carlos`'s account dashboard is accessed without supplying the required 2FA verification code. Lab solved