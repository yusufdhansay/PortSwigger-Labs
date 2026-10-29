# Lab 1 - Basic SSRF against the local server

## Given
The lab has a vulnerable stock check feature that fetches data from an internal system

## End Goal
Change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`

## Quick Steps
1. Navigate to any product page, click on the stock check feature and intercept the request in **Burp Suite**
2. Send the request to **Burp Repeater** and locate the vulnerable POST parameter in the body: `stockApi=http://...`
3. Modify `stockApi` to point to `http://localhost/admin` to access the restricted admin panel
4. Inspect the HTTP response to locate the user management endpoints
5. Use `http://localhost/admin/delete?username=carlos` to execute the deletion of the user

## Payload and Mechanics
- **Internal Admin Access Payload:** `http://localhost/admin`
- **User Deletion Payload:** `http://localhost/admin/delete?username=carlos`

## Why it works
- **Trust Boundary Flaw:** The application trusts the requests originating from its own loopback address (`127.0.0.1` / `localhost`)
- **Missing Access Control on Backend:** The internal `admin` handler relies on network location rather than session authentication, granting full access to local requests

## Result
User `carlos` is deleted via the loopback SSRF vector. Lab solved