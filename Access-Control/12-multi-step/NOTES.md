# Lab 12 - Multi-step process with no access control on one step

## Given
The lab has an admin panel with a flawed multi-step process for changing a user's role. Familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`

## End Goal
Log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator

## Quick Steps
1. Authenticate as `administrator:admin` and navigate to the admin panel
2. Promote a target user (e.g., `carlos`) and capture the multi-step HTTP traffic in **Burp Suite**
3. Identify the two distinct requests:
   - **Step 1:** Initial promotion request (`POST /admin-roles` with `username=carlos&action=upgrade`)
   - **Step 2:** Confirmation request (`POST /admin-roles` with `username=carlos&action=upgrade&confirmed=true`)
4. Log out of `administrator` and log in as standard user `wiener:peter`. Copy `wiener`'s session cookie
5. In **Burp Repeater**, replace the administrative session cookie with `wiener`'s session cookie in both requests
6. Submit Step 1: Observe a `403 Forbidden` / access restriction response
7. Submit Step 2 directly with `wiener`'s session cookie and payload `username=wiener&action=upgrade&confirmed=true`. Observe a `200 OK` response confirming privilege escalation

## Payload & Mechanics
- **Step 1 Request (Blocked for Standard Users):**
  `POST /admin-roles` -> `username=wiener&action=upgrade`
- **Step 2 Request (Bypass Vector - Missing Authorization Check):**
  `POST /admin-roles` -> `username=wiener&action=upgrade&confirmed=true`

## Why it works:
- Developers often assume that users can only reach Step 2 by successfully completing Step 1. Consequently, authorization middleware is applied to Step 1, while Step 2 relies solely on the presence of the confirmation parameter without verifying session role privileges
- The server processes Step 2 independently without checking if the active session possesses an administrative role or a validated server-side state token from Step 1

## Result
Standard user `wiener` is promoted to an administrator by skipping Step 1 and directly executing Step 2. Lab solved