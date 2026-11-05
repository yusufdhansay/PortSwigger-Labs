# Lab 1 - Username enumeration via different responses

## Given
The lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

- Candidate usernames
- Candidate passwords

## End Goal
Enumerate a valid username, brute-force the user's password, then access their account page

## Quick Steps
1. Submit a dummy login attempt (`username=test&password=test`), capture and send the request to **Burp Intruder**
3. Set the payload position on the `username` parameter and load the candidate usernames wordlist
4. Run attack and filter the results by **Response Length** or **Status Code**. Identify the unique entry indicating a valid username
5. Update the `username` parameter in Intruder to the valid username discovered in Step 4
6. Change the payload position to the `password` parameter, load the candidate passwords wordlist, and execute the attack
7. Identify the successful password entry by filtering for `302 Found` and log into the account

## Payload & Mechanics
- **Phase 1 (Username Enumeration):** `POST /login` $\rightarrow$ `username=§USER§&password=invalid`
- **Phase 2 (Password Brute-Force):** `POST /login` $\rightarrow$ `username=valid_user&password=§PASS§`

## Why it works:
- The application logic handles invalid usernames separately from invalid passwords, returning distinct error messages or response structures
- The authentication endpoint does not restrict brute-force attempts, IP throttling or account lockout mechanisms

## Result
Valid credentials are discovered through automated brute-forcing. Lab solved