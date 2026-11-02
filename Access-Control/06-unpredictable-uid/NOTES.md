# Lab 6 - User ID controlled by request parameter, with unpredictable user IDs

## Given
The lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs. Log in using following credentials `wiener:peter`

## End Goal
Find the GUID for user `carlos` and submit his API key as solution

## Quick Steps
1. Log in using given credentials `wiener:peter`
2. Access `My Account` page to observe the GUID structure in the `id` parameter (`my-account?id=[GUID]`)
3. Browse the blog posts to find the blog written by carlos user
4. Once found, inspect the author's profile link to extract GUID from the URL parameters
5. Send the new request `GET /my-account?id=[carlos's GUID]`
6. Retrieve the API key from the response

## Payload and Mechanics
- **Target Identification Vector:** Public Author Link (`GET /blogs?author=carlos` -> `/my-account?id=carlos-guid-value`)
- **IDOR Payload:** `GET /my-account?id=carlos-guid-value`

## Why it works
- Using GUIDs/UUIDs creates pseudo-anonymity against guessing attacks, but does not enforce authorization boundaries on server endpoints
- Blog pages map identities to the same internal GUIDs used for private profile endpoints without restricting endpoint access based on session ownership

## Result
User `carlos's` GUID is discovered, allowing horizontal privelege escalation to retrieve his API key. Lab solved