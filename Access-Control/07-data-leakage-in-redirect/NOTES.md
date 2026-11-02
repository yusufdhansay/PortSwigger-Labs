# Lab 7 - User ID controlled by request parameter with data leakage in redirect

## Given
The lab contains an access control vulnerability where sensitive information is leaked in the body of a redirect response. Log in using following credentials `wiener:peter`

## End Goal
Obtain API key for user `carlos` and submit it as solution

## Quick Steps
1. Log in using given credentials `wiener:peter`
2. Intercept the request to **My Account** (`GET my-account?id=wiener`) and send it to **Burp Repeater**
3. Modify the request's parameter to target `carlos` : `GET my-account?id=carlos`
4. Send the request and inspect the HTTP response
5. Extract the API key from the response body and submit it as the solution

## Payload and Mechanics
- **Target Vector:** `GET /my-account?id=carlos`
- **Vulnerable Response Condition:** `HTTP/1.1 302 Found` carrying complete response body content

## Why it works
- The backend server logic triggers a redirect directive but fails to explicitly terminate script execution
- Browsers automatically follow `302 Found` redirects without rendering the accompanying body. Interception proxies capture the full HTTP response stream, revealing the leaked data

## Result
Carlos's API key is retrieved from the response body. Lab solved