# Vulnerability Report: Insecure Direct Object Reference (IDOR) in Static File Access Leading to Credential Disclosure

* **Vulnerability Type:** Insecure Direct Object Reference (IDOR) (CWE-639) / Information Exposure Through Directory Listing or Static Files (CWE-552)

* **Severity:** High

* **Target Component:** Chat Transcript Download Handler (`/download-transcript/{id}.txt`)

* **OWASP Top 10 Mapping:** A01:2021 – Broken Access Control

## 1. Executive Summary

An Insecure Direct Object Reference (IDOR) vulnerability was identified in the live chat log download feature. The application stores user chat transcripts as static text files named using predictable, sequential numerical identifiers (e.g., `1.txt`, `2.txt`). Because the backend fails to validate whether the requesting user was a participant in the requested chat session, an attacker can modify the requested filename parameter to access historic chat logs belonging to other users. This results in the exposure of sensitive data—including plain-text credentials shared during support interactions—and leads to full account compromise.

## 2. Technical Analysis & Root Cause

The security flaw stems from serving static assets or file system resources via direct, predictable user-supplied keys without enforcing object-level permissions.

### Vulnerability Mechanism

1. **Predictable File Naming:** Chat transcripts are stored using incremental integer identifiers (`1.txt`, `2.txt`, `3.txt`).

2. **Direct File System Mapping:** The application endpoint maps incoming URL request segments directly to local file system paths without applying authorization logic.

3. **Missing Permission Check:** The backend does not maintain an association between the user's active session and the transcript file being requested, allowing any client to read arbitrary files by incrementing or decrementing the filename index.

```
[ Attacker Session ]
         |
         | GET /download-transcript/1.txt
         v
[ Web Server ]
         |
         | (No Authorization / Session Ownership Validation)
         | (Fetches file directly from disk: /var/transcripts/1.txt)
         v
[ Static Transcript File Returned ] ---> Contains Sensitive Chat Log & Plaintext Password

```

## 3. Proof of Concept (PoC)

1. Access the application's live chat interface and initiate a conversation.

2. Click the **Download Transcript** button and capture the outgoing request in an HTTP proxy (e.g., Burp Suite):

   ```
   GET /download-transcript/2.txt HTTP/1.1
   Host: target-app.net
   Cookie: session=vX9z...
   
   ```

3. Send the request to **Burp Repeater**. Modify the target filename from `2.txt` to `1.txt`:

   ```
   GET /download-transcript/1.txt HTTP/1.1
   Host: target-app.net
   Cookie: session=vX9z...
   
   ```

4. **Observe Response:** The server returns `HTTP 200 OK` along with the contents of transcript `1.txt`.

5. Inspect the transcript content to locate sensitive information:

   ```
   [User: carlos]: Hello, I am having trouble logging in.
   [Support Agent]: Please verify your password for confirmation.
   [User: carlos]: My password is "s3cr3t_p@ss123".
   
   ```

6. Navigate to the login page and authenticate as `carlos` using the exfiltrated password.

7. **Result:** Account takeover confirmed.

## 4. Impact

* **Horizontal Privilege Escalation / Data Exposure:** Unauthorized access to private chat transcripts of all users.

* **Credential Exfiltration:** Exposure of sensitive user-supplied data, leading to downstream account takeover.

* **Insecure File Handling:** Predictable file paths expose static assets to automated enumeration scripts.

## 5. Remediation & Developer Guidance

### Primary Fixes

1. **Use Indirect Object References (GUIDs / Random Hashes):**
   Do not store or reference files using sequential or predictable names. Use high-entropy Universally Unique Identifiers (UUIDs/GUIDs) generated at file creation time (e.g., `e4d2a1b9-8f3c-4b2a-9e1d-8f3c4b2a9e1d.txt`).

2. **Enforce Access Control Validation:**
   Before serving any file, verify server-side that the authenticated session user is authorized to read the specific resource (e.g., check `db.transcripts.find({id: file_id, user_id: current_user_id})`).

3. **Serve Files via Authenticated Streams:**
   Store transcripts outside the public web root directory and serve content through an internal gateway route that validates credentials prior to streaming file bytes.

#### Secure Code Implementation Example (Python / Flask)

```
import os
from flask import Flask, request, session, abort, send_from_directory

app = Flask(__name__)
TRANSCRIPT_DIR = "/var/protected_transcripts"

@app.route('/download-transcript/<transcript_id>')
def download_transcript(transcript_id):
    user_id = session.get('user_id')
    if not user_id:
        abort(401)  # Unauthorized
        
    # Query database to check if this user OWNS the requested transcript ID
    transcript_record = db_get_transcript_meta(transcript_id)
    
    if not transcript_record or transcript_record['owner_id'] != user_id:
        abort(403)  # Forbidden - Prevent unauthorized access
        
    # Serve file securely using validated internal path
    return send_from_directory(TRANSCRIPT_DIR, f"{transcript_record['secure_uuid']}.txt")

```

## 6. References

* **CWE-639:** [Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

* **CWE-552:** [Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

* **OWASP API Security:** [API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)