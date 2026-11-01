# Lab 2 - Unprotected admin functionality with unpredictable URL

## Given
The lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application

## End Goal
Access the admin panel and delete the user named `carlos`

## Quick Steps
1. Open the lab and view it's source code using the browser developer tools
2. Inspect client-side `<script>` tags to locate inline JavaScript logic
3. Identify the hardcoded administrative endpoint variable (e.g., `/admin-xxxx`)
4. Append the newly found admin endpoint variable directly in the URL and access the admin panel
5. Locate and delete user `carlos`

## Payload and Mechanics
- **Reconnaissance Vector:** Client-side HTML/JavaScript Source Code Inspection
- **Disclosed Endpoint:** `/admin-[unpredictable-hash]`
- **Action Endpoint:** `/admin-[unpredictable-hash]/delete?username=carlos`

## Why it works
- Any business logic or configuration variables delivered to the user's browser in HTML/JS source code must be considered fully public
- Assigning random or high-entropy string paths does not replace access control checks
- The server-side route handler fails to verify user credentials or administrative roles upon request execution

## Result
Access to the unpredictable admin panel is achieved, user carlos is deleted. Lab solved

