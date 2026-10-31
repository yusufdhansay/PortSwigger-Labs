# Lab 1 - Unprotected admin functionality

## Given
The lab has an unprotected admin panel

## End Goal
Access the admin panel and delete the user named `carlos`

## Quick Steps
1. Navigate to `robots.txt` in the target application
2. Identify the path to admin panel listed under `Disallow` => `Disallow: /administrator-panel`
3. Navigate to the admin panel by appending `/administrator-panel` in the URL
4. Find and delete user `carlos`

## Payload and Mechanics
- **Reconnaissance Vector:** `GET /robots.txt`
- **Target Admin Path:** `/administrator-panel`
- **Action Endpoint:** `/administrator-panel/delete?username=carlos`

## Why it works
- The developer attempted to protect the administrative portal by omitting links to it from public pages, rather than enforcing authorization controls
- The `robots.txt` file explicitly disclosed the location of the hidden administration panel
- The administrative routing logic fails to verify session authentication or administrative role privileges upon request execution

## Result
Unrestricted access to the admin panel is obtained, carlos user is deleted. Lab solved