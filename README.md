# 🛡️ PortSwigger Web Security Academy — Labs & Exploitation Portfolio

Welcome to my personal web application security and penetration testing portfolio! This repository contains detailed technical write-ups, professional vulnerability reports, and custom Python automation scripts (Proof-of-Concept exploits) developed while solving labs from the **PortSwigger Web Security Academy**.

---

## 🎯 Portfolio Objectives
- **Vulnerability Analysis:** Document step-by-step methodologies for identifying, analyzing, and exploiting web security vulnerabilities.
- **Enterprise Reporting:** Structure findings into clear, developer-focused penetration test reports adhering to **CWE** standards and **OWASP Top 10** risk ratings.
- **Python Exploit Automation:** Write reusable, efficient Python scripts using `requests` and `BeautifulSoup` to automate manual exploitation steps.

---

## 📂 Repository Structure

Each module contains dedicated lab folders organized by short topic slugs. Every lab directory follows a standardized layout:

```text
PortSwigger-Labs/
│
├── README.md                          <-- Root Portfolio & Progress Tracker
│
├── sqli/                              <-- Vulnerability Topic
│   └── 04-db-version-query/           <-- Lab Specific Directory
│       ├── README.md                  <-- Vulnerability Report (Description, Impact, Fix) & Notes
│       └── exploit.py                 <-- Python PoC Script
│
├── xss/
│   └── 01-reflected-xss-html/
│       ├── README.md
│       └── exploit.py
│
└── authentication/
    └── 01-username-enumeration/
        ├── README.md
        └── exploit.py
```

---

## 📊 Learning & Exploitation Progress

### 🔴 High-Yield / Core Vulnerabilities
- [ ] **SQL Injection (SQLi)**
  - [x] `sqli/04-db-version-query` — Querying the database type and version on MySQL/Microsoft
- [ ] **Cross-Site Scripting (XSS)**
- [ ] **Authentication Vulnerabilities**
- [ ] **Access Control & IDOR**
- [ ] **Server-Side Request Forgery (SSRF)**
- [ ] **Business Logic Vulnerabilities**

### 🟡 APIs & Modern Auth
- [ ] **JWT Attacks**
- [ ] **OAuth 2.0 Vulnerabilities**
- [ ] **API & GraphQL Vulnerabilities**

### 🔵 Advanced & High-Payout Topics
- [ ] **HTTP Request Smuggling**
- [ ] **Web Cache Poisoning**
- [ ] **Race Conditions**
- [ ] **Server-Side Template Injection (SSTI)**

---

## 🛠️ Tooling & Stack

* **Proxies & Tools:** Burp Suite Community Edition, Browser DevTools
* **Scripting Language:** Python 3.x
* **Key Python Libraries:** `requests`, `beautifulsoup4`, `argparse`
* **Standards & Frameworks:** OWASP Top 10, MITRE CWE, CVSS v3.1

---

## 📄 License & Responsible Disclosure
This repository is strictly for educational, portfolio, and security research purposes. All labs and exercises are performed within the isolated sandbox environment provided by PortSwigger Web Security Academy.