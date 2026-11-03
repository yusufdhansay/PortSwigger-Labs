# Lab 10 - URL-based access control can be circumvented

## Given
The website has an unauthenticated admin panel at `/admin`, but a front-end system has been configured to block external access to that path. However, the back-end application is built on a framework that supports the `X-Original-URL` header

## End Goal
Access the admin panel and delete the user `carlos`

## Quick Steps
1. Click on **Admin Panel**, intercept the request and send it to **Burp Repeater**
2. Add the custom header `X-Original-URL: /admin` to the request and change the main request URL line to `GET /`
3. Submit the modified request to verify access to the admin panel
4. Set the override header to `X-Original-URL: /admin/delete` and pass query parameters on the request line: `GET /?username=carlos`

## Payload and Mechanics
- **Header Injection:** `X-Original-URL: /admin`
- **Action Payload Header:** `X-Original-URL: /admin/delete`
- **Request Line:** `GET /?username=carlos HTTP/1.1`

## Why it works
- The front-end reverse proxy/WAF validates routing rules against the URL present in the HTTP request line (`GET /`), allowing it through
- Certain web frameworks support legacy override headers like `X-Original-URL` or `X-Rewrite-URL` to determine the target controller internally, effectively ignoring the front-end path check

## Result
Front-end access controls are bypassed, allowing unauthorized deletion of carlos user. Lab solved