# Web Infrastructure Hardening: ModSecurity WAF & SSL/TLS Integration

## 📖 Project Overview
This project demonstrates the transition from a vulnerable web environment to a hardened, enterprise-ready infrastructure. I built a **LAMP stack** to host the **Damn Vulnerable Web Application (DVWA)** and implemented a **ModSecurity Web Application Firewall (WAF)**. The goal was to demonstrate how "Virtual Patching" can protect insecure code from OWASP Top 10 threats while ensuring data confidentiality through **SSL/TLS encryption**.

## 🛠️ Phase 1: Infrastructure Build & Baseline Setup
I began by building the target environment from the ground up on an Ubuntu server.

### **Key Actions:**
* **LAMP Stack Deployment:** Installed **Apache2**, **MariaDB (MySQL)**, and **PHP**.
* **DVWA Integration:** Configured the MySQL database and PHP permissions to allow DVWA to run in its native vulnerable state.
* **WAF Installation:** Installed `libapache2-mod-security2` and cloned the **OWASP Core Rule Set (CRS)** to provide baseline defense signatures.
* **Initial Posture:** I set the WAF to `DetectionOnly` mode to establish a baseline for vulnerability testing.

**DVWA RUNNING**
> ![Dvwa homepage diagram prove of installation](images/dvwa_homepage.png)
>
**Terminal showing the  /etc/apache2/modsecurity-srs directory**
> ![Dvwa homepage diagram prove of installation](images/csr_tested_rules.png)

---
## 🧪 Phase 2: Vulnerability Validation (The "Before" State)
With the server live but unprotected, I conducted manual penetration tests over **HTTP** to prove the application was vulnerable to common exploits.

### **Attack Scenarios:**
* **SQL Injection (SQLi):** Successfully bypassed login logic using `1' OR 1=1 #`.
* **Cross-Site Scripting (XSS):** Injected `<script>alert('Hacked by Ofeoritse')</script>`, triggering unauthorized JavaScript execution.
* **Command Injection:** Executed `127.0.0.1; whoami` to prove OS-level command access.

**Observation:** All attacks were successful. The WAF logged these events but did not intervene, simulating an exposed production environment.

**Successful SQL injection**
> ![SQL injection success](images/sql_injection_success.png)
> 
**Successful cross site scripting**
> ![Xss success](images/xss_success.png)
> 
**Successful command injection**
> ![Command injection success](images/command_injection_success.png)


