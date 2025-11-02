# 🧠 Web Application Penetration Test – DVWA  
**Author:** Millie Dion — SOC Analyst  
**Skills:** Web Application Security, OWASP Top 10, Exploit Development  
**Tools:** Burp Suite, OWASP ZAP, SQLMap, Nikto, curl, Firefox (FoxyProxy)  
**Date:** November 2025  

---

## 🧩 Project Summary

This project demonstrates a complete **web application penetration test** of the **Damn Vulnerable Web Application (DVWA)** hosted in an isolated lab. The objective was to identify and exploit vulnerabilities mapped to the **OWASP Top 10**, assess their risk using **CVSS v3.1**, and provide remediation guidance with developer-friendly examples.

> ⚠️ All testing was performed in a controlled lab environment for educational purposes only.

**Key Results:**
- Identified **SQL Injection**, **Cross-Site Scripting (XSS)**, and **Cross-Site Request Forgery (CSRF)** vulnerabilities  
- Provided validated proof-of-concept exploits and remediation code samples  
- Scored risks using CVSS v3.1 and aligned findings to OWASP Top 10  

---

## 🧱 Environment Setup

| Component | Description |
|------------|--------------|
| **Target App** | Damn Vulnerable Web Application (DVWA) |
| **Host OS** | Ubuntu 22.04 (Host) |
| **Deployment** | Docker container `vulnerables/web-dvwa:latest` |
| **Browser** | Firefox + FoxyProxy (routing through Burp) |
| **Tools** | Burp Suite, OWASP ZAP, SQLMap, Nikto |
| **Network Mode** | Localhost (isolated lab, non-internet-facing) |

🧭 Scope & Methodology

Scope

Target: http://127.0.0.1/dvwa

Testing allowed: Active and passive testing of DVWA instance

Excluded: No attacks outside lab scope or external targets

Approach

Reconnaissance (Nikto, manual browsing)

Mapping & input enumeration

Automated scanning (OWASP ZAP)

Manual testing & payload crafting (Burp Repeater, Intruder)

Exploit validation & proof collection

Risk scoring (CVSS v3.1)

Documentation & remediation planning


### Deployment Example
```bash
# Run DVWA locally
docker run --rm -it -p 80:80 vulnerables/web-dvwa
# Access it on http://localhost/setup.php
# Create DB and set DVWA security level to "low"


