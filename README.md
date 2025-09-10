## 🚨 WARNING — DO NOT USE IN PRODUCTION
--------------------------------------

This is an **experimental proof of concept**. The code is **unstable**, **unaudited**, and **not security-hardened**.
**Production use is strictly discouraged** (risk of bugs, data loss, and security issues).

Purpose
-------

Enable Windows workstation enrollment with Microsoft Active Directory Certificate Services (AD CS)
via **Certificate Enrollment Policy (CEP)** and **Certificate Enrollment Services (CES)**:

- Discover CEP policy to obtain enrollment templates and CA information.
- Build and validate PKCS#10 CSRs, then submit/sign via CES.

Status
------

- **POC / unstable**
- Minimal tests
- Many TODOs and rough edges
