# Lab 3 - SQL injection attack, querying the database type and version on Oracle

## Given
The lab contains an SQL injection vulnerability in the product category filter

## End Goal
Use UNION attack to retrieve results from an injected query and display the database version string

## Quick Steps
1. Intercept a category filter request in **Burp Suite** and send it to **Repeater**
2. **Determine Column Count:** Append `' ORDER BY 1--`, incrementing the number until an error occurs (error at 3 -> 2 columns)
3. **Determine Data Types:** Inject `' UNION SELECT 'a','a' FROM DUAL--` to test column types. A `200 OK` response confirms both columns accept strings
4. **Extract Version:** Use Oracle-specific command to display the version string

## Payload and Mechanics
- **Column Count:** `' ORDER BY 1--`, `' ORDER BY 2--`, `' ORDER BY 3--` (Error)
- **Data Type Verification:** `' UNION SELECT 'a','a' FROM DUAL--`
- **Final Exploit Payload:** `' UNION SELECT banner,NULL from v$version`

## Why it works
- **`UNION`**: Combines original query result with injected query
- **`v$version`**: Oracle specific command to display version info
- **`banner`**: Contains version description text
- **`FROM DUAL`**: Mandatory dummy table in Oracle, required for queries that don't select from a real table 

## Result
The database type and version is displayed on the page. Lab solved
