# Lab 1 - SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

## Given
The lab contains SQL injection vulnerability in the product category filter

## End Goal
Perform SQL Injection attack, causing the application to display one or more unreleased products

## Quick Steps
1. Intercept product category filter request in **Burp Suite**
2. Send request to **Repeater**
3. Inject payload into the `category` parameter

## Payload and Mechanics
- **Payload:** `' OR 1=1--`
- **Full URL Example:** `/filter?category='' OR 1=1--`

## Why it works
- **`'`**: Closes the original string value in the SQL query
- **`OR 1=1`**: Forces the query condition to be true for every row
- **`--`**: Comments out the remaining database logic, preventing SQL syntax error

## Result
Returns all products, including unreleased (hidden) items. **Lab Solved**

