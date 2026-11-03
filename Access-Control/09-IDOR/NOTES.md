# Lab 9 - Insecure direct object references

## Given
The lab stores user chat logs directly on the server's file system, and retrieves them using static URLs

## End Goal
Find password for the user `carlos`, and log into their account

## Quick Steps
1. Access the live chat feature, send a few messages and trigger the transcript download
2. Intercept the download request (e.g., `GET /download-transcript/2.txt`) in **Burp Suite** and send to **Repeater**
3. Identify the sequential naming convention (`2.txt`) used for stored logs
4. Change the parameter to query previous transcripts (`GET /download-transcript/1.txt`)
5. Send the request and analyze the response body to extract the password
6. Log into carlos's account using the retrieved password

## Payload & Mechanics
- **Original Download Request:** `GET /download-transcript/2.txt`
- **IDOR Path Traversal / Enumeration Target:** `GET /download-transcript/1.txt`

## Why it works:
- Static files stored on the file system are served using direct, predictable filenames or sequential IDs (`1.txt`, `2.txt`).
- The application server serves requested file resources directly without verifying if the user's session ID matches the owner or participant of the chat transcript.

## Result
Access to historical chat transcripts belonging to other users is obtained, leading to sensitive data exposure and account takeover. Lab solved