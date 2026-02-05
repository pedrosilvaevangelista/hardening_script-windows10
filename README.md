# 🛡️ Windows 10 Hardening Suite

This project is a **Hardening** script for Windows 10, specifically designed to reduce the attack surface on home desktops. It transforms the system from a default configuration (focused on convenience) to a setup focused on **proactive security and privacy**.

## 🎯 Objective

The script applies rigorous controls based on international frameworks to prevent the exploitation of known vulnerabilities, block common attack vectors (such as Ransomware via VBS), and mitigate excessive data collection.

---

## 🔍 Detailed Features and Functionality

### 1. Attack Surface Reduction via Services

Windows runs several background processes that increase entry points for an attacker. This script disables the following services:

* **RemoteRegistry:** Prevents the Windows Registry from being modified remotely (a critical vector for lateral movement).
* **Fax:** Disables support for legacy and obsolete hardware.
* **DiagTrack (Telemetry):** Stops the collection and transmission of usage data to Microsoft.
* **XblGameSave & XboxNetApiSvc:** Removes Xbox integration processes unnecessary for productivity and security.
* **MapsBroker:** Disables background location monitoring for offline maps.
* **WerSvc:** Blocks the sending of error reports that may contain sensitive fragments of data from RAM.

### 2. Legacy Protocols: Disabling SMBv1

The SMBv1 protocol has design flaws dating back 30 years.

* **Impact:** Protection against remote code execution attacks, such as the infamous **WannaCry** and **EternalBlue**. The script removes both the SMBv1 client and server.

### 3. Patch Management: Windows Update

Enforces Windows Update behavior to ensure the system is never left vulnerable due to forgetfulness.

* **Configuration:** Sets automatic update downloads and installation notifications, ensuring that critical security patches are applied as quickly as possible.

### 4. Identity Strengthening: Password Policy

Increases resistance against Brute Force attacks.

* **Rules:** Requires a minimum length of **12 characters**, enables mandatory complexity, and implements a **Lockout Policy** (account lockout for 15 minutes after 5 incorrect attempts).

### 5. Perimeter Defense: Total Firewall

Ensures that the Windows Firewall is never "relaxed" by the user when switching networks.

* **Action:** Enables the Firewall on all three profiles: **Domain, Private, and Public**.

### 6. Malware Protection: WSH Blocking

Many phishing attacks deliver `.vbs` or `.js` files.

* **What it does:** Disables the *Windows Script Host*.
* **Result:** Prevents malicious scripts from being executed directly by the user when clicking on fake email attachments.

### 7. Privilege Control: Maximum UAC

User Account Control is the last barrier between a common process and administrative control.

* **Configuration:** Sets the maximum notification level on the **Secure Desktop**. This prevents software from attempting to simulate clicks or elevate privileges without your direct interaction in a protected area of the system.

### 8. Privacy and Integrity: Cloudflare DNS

Redirects your name queries to a secure infrastructure.

* **DNS 1.1.1.1:** Protects against **DNS Hijacking** (redirection to fake websites) and prevents your Internet Service Provider (ISP) from mapping your browsing history through DNS queries.

### 9. Memory Protection: Exploit Protection

Applies Kernel-level defense techniques that make it difficult to create functional exploits.

* **DEP (Data Execution Prevention):** Prevents malicious code from running in memory areas reserved only for data.
* **ASLR (Address Space Layout Randomization):** Randomizes where system code is loaded into memory, making the target of a buffer overflow attack unpredictable.

### 10. Visual Transparency: File Extensions

Configures the system to always display the full file extension (e.g., `file.pdf.exe`).

* **Security:** Allows the user to identify malicious files disguised with fake document icons.

---

## 🚀 How to Run

The script uses **"Audit-First"** logic: it checks if the system is already secure before asking if you want to apply the fix.

Open **PowerShell as Administrator** and execute the command below:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pedrosilvaevangelista/hardening_script-windows10/main/hardening-win10.ps1'))

```

---

## ⚠️ Attention and Responsibility

Applying Hardening involves a **trade-off** between security and convenience.

* Disabling Xbox services will affect games that rely on the Live network.
* Blocking WSH may prevent the execution of old administrative scripts.
* The password policy requires you to use strong passwords to avoid being locked out.

**Review each topic during interactive execution to ensure it meets your needs.**

---

## 📚 References

* [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
* [CIS Benchmarks for Windows 10](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)

---
