# Lab 2 - SQL injection vulnerability allowing login bypass

## Given
The lab contains SQL injection vulnerability in the login function

## End Goal
Perform SQL injection attack and log in as the administrator

## Analysis
1. Navigate to the application login page
2. Test for vulnerabilities by typing a single quote (`'`) into the username field and any random value into the password field
3. The page responses with an internal server error, confirming the presence of SQLi vulnerability
4. Input the bypass payload into the username field and hit submit

## Payload and Mechanics
- **Username Payload:** `administrator'--`
- **Password:** Any random characters (the backend will ignore it)

## Why it works
- **`administrator`**: Targets the specific priveleged user account
- **`'`**: Closes the string expected by the database query for username
- **`--`**: Comments out the remainder of the query

## Result
The database query evaluates to true for the username while ignoring the password check, logging you in as the `administrator`. Lab solved