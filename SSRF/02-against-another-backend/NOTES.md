# Lab 2 - Basic SSRF against another back-end system

## Given
The lab has a vulnerable stock check feature which fetches data from an internal system

## End Goal
Use the stock check functionality to scan the internal `192.168.0.x` range for an admin interface on port `8080`, then use it to delete the user `carlos`

## Quick Steps
1. Trigger the stock check feature on any product, intercept the request and send it to **Burp Repeater**
2. Identify the encoded `stockApi` parameter and URL-decode it (`Ctr+Shift+U` / `Cmd+Shift+U`) to manipulate the target IP address
3. Send the request to **Burp Intruder** to brute-force the final octet of the IP address (`192.168.0.x`) across port `8080`
4. Look for a unique HTTP status code, indicating the active admin server
5. Modify the `stockApi` parameter to point to the admin endpoint and delete user `carlos`

## Payload and Mechanics
- **Base SSRF Template:** `stockApi=192.168.0.x:8080/`
- **Admin Panel Discovery:** `stockApi=192.168.0.x:8080/admin`
- **User Deletion Payload:** `stockApi=192.168.0.x:8080/admin/delete?username="carlos"`

## Why it works
- **Internal Network Visibility:** The application server resides inside a private corporate subnet (`192.168.0.x`) and can freely communicate with internal machines that are blocked from external public access
- **Implicit Trust:** Internal back-end systems on port `8080` often lack authentication mechanisms, assuming that any request originating from the internal network is trusted

## Result
The internal admin panel is discovered and user `carlos` is successfully deleted. Lab solved