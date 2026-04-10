# Windows 10 Hardening

A straightforward PowerShell automation script designed to sharply reduce the attack surface of Windows 10 home machines, enforcing a robust cybersecurity posture aligned with **NIST** and **CIS** guidelines.

## Objective

Shift Windows from a convenience-first operating system to a proactive security environment. This prevents data leaks, stops ransomware deployment vectors, and neutralizes lateral network pivoting techniques gracefully.

---

## Security Baselines

This project applies thirteen critical security baselines natively:

1. **Unnecessary Services Disabled**
   Neutralizes `RemoteRegistry`, `DiagTrack` (Telemetry), legacy Fax, and arbitrary Xbox hooks to block unseen exploitation paths.
2. **SMBv1 Deprecation**
   Eradicates the 30-year-old vulnerable file-sharing flaw that accelerated the WannaCry crisis.
3. **Firm Patch Management**
   Locks Windows Update behavior into strict notifications, ensuring urgent patches deploy without auto-reboot workspace disruptions.
4. **Identity Strengthening**
   Demands 12-character complex passwords and enforces tight account lockout policies (15-minute lockout after 5 failing tries).
5. **Universal Firewall Guarantee**
   Assures that Domain, Private, and Public profiles are strictly loaded and switched on persistently.
6. **WSH Automation Truncation**
   Halts the Windows Script Host to deny drive-by `.vbs` and `.js` malware scripts from parsing.
7. **UAC Maximum Alert Constraint**
   Forces administrative consent strictly over a secure desktop space to barricade silent privilege escalation.
8. **Cloudflare Privacy DNS**
   Sets global `1.1.1.1` endpoints to neutralize ISP routing sniffing and severe internal DNS Hijacking tools.
9. **Hardware Exploit Mitigations**
   Activates severe base DEP/ASLR randomization at the underlying OS engine to defend against zero-day anomalies.
10. **Visible Extensions Imposed**
    Drops the curtain hiding the true executable extensions (stops fake `.pdf.exe` targeted payloads).
11. **PowerShell Advanced Tracing**
    Injects transparent event auditing logs to trace every powershell process behavior deployed natively or stealthily.
12. **Corporate Telemetry Eradicator**
    Drops root analytic collections explicitly enforcing `AllowTelemetry = 0` throughout system layers.
13. **AutoPlay Zero Trust Mechanism**
    Defeats physical infected USB delivery attacks natively shutting down interactive/background drive mountings.

---

## Quick Deployment

All commands below must be run in a **PowerShell terminal as Administrator**.

---

### 🔒 Apply Hardening

The deployment uses an interactive **Audit First** concept. A fast UI checks security layers and will gently ask consent (`Y/N`) to harden and apply registry keys securely.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pedrosilvaevangelista/hardening_script-windows10/main/hardening-win10.ps1'))
```

> **Recommendation:** Allow an immediate system restart when completed to bind registry configurations flawlessly.

---

### ✅ Verify Hardening

Runs the Pester-based test suite to validate whether all 13 security controls are correctly applied on the current machine. Requires [Pester](https://pester.dev) (`Install-Module Pester -Force`).

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pedrosilvaevangelista/hardening_script-windows10/main/hardening-win10.tests.ps1'))
```

---