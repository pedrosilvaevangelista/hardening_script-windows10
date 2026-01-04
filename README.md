# 🛡️ Windows 10 Hardening Scripts

A complete set of PowerShell scripts to apply and verify security hardening configurations on Windows 10 workstations.

## 📋 Contents

* **`hardening-win10.ps1`** – Main script that applies security configurations
* **`hardening-check.ps1`** – Verification script that confirms whether the configurations were correctly applied

## ⚡ Quick Execution

```powershell
# 1. Apply hardening
.\hardening-win10.ps1

# 2. Verify configurations
.\hardening-check.ps1
```

## 🔧 hardening-win10.ps1

### What does it do?

This script applies **10 main categories** of security configurations:

#### 1. 🛑 Disables Unnecessary Services

* **Xbox** (XblGameSave, XboxNetApiSvc, XboxGipSvc)
* **Telemetry** (DiagTrack, dmwappushservice)
* **Media** (WMPNetworkSvc)
* **Others** (RemoteRegistry, Fax, RetailDemo, WerSvc, MapsBroker, SharedAccess, TrkWks, PhoneSvc)

#### 2. 🚫 Removes SMBv1 (Vulnerable Protocol)

* Disables SMBv1 client and server
* Enforces SMB security signing
* Removes SMBv1 Windows features

#### 3. 🔄 Configures Windows Update

* Enables automatic download and installation
* Prevents automatic reboot while users are logged in

#### 4. 🔐 Strong Password Policies

* **Minimum length:** 12 characters
* **Expiration:** 90 days
* **History:** 24 previous passwords
* **Lockout:** 5 attempts → lock for 15 minutes
* **Complexity:** Enabled via secedit

#### 5. 🔥 Windows Firewall

* Enables protection on **all profiles** (Domain, Private, Public)
* Enables logging of allowed and blocked connections

#### 6. 🛑 UAC (User Account Control)

* Forces confirmation for administrators
* Prompts for credentials for standard users
* Keeps UAC always enabled

#### 7. 📜 Event Auditing

* **Logon/Logoff** (success and failure)
* **Account lockout**
* **User management**
* **Process creation**
* **System events**

#### 8. 🛡️ Windows Defender

* Real-time protection always enabled
* Daily scan at **02:00**
* Advanced MAPS reporting
* Automatic submission of suspicious samples

#### 9. ⚙️ Additional Security Settings

* **LM Hash disabled** (prevents hash-based attacks)
* **Idle timeout:** 15 minutes
* **AutoRun disabled** (USB drives do not execute automatically)
* **Windows Script Host disabled** (blocks .vbs, .js)

#### 10. 💻 PowerShell Execution Policy

* Sets policy to **RemoteSigned** (only local or signed scripts can run)

### Prerequisites

* Windows 10
* **Run as Administrator** (mandatory)
* PowerShell 5.0 or higher

### How to use

```powershell
# Clone or download the script
# Open PowerShell as Administrator
# Run:
.\hardening-win10.ps1
```

### Expected Output

```
[INFO] Starting Windows 10 hardening process...
[SUCCESS] RemoteRegistry service disabled
[SUCCESS] SMBv1 successfully disabled
[SUCCESS] Windows Update configured
[SUCCESS] Password policies configured
[SUCCESS] Windows Firewall configured and enabled
[SUCCESS] UAC configured
[SUCCESS] Auditing configured
[SUCCESS] Windows Defender configured
[SUCCESS] Additional security settings applied
[SUCCESS] PowerShell Execution Policy configured

[WARNING] IMPORTANT: Reboot the system for all changes to take full effect.
[INFO] Hardening process completed!

Do you want to restart the system now? (Y/N)
```

---

## 🔍 hardening-check.ps1

### What does it do?

A **verification and auditing** script that confirms whether all hardening configurations were correctly applied.

### Checks performed

#### ✅ Service Status

* Confirms that all listed services are **disabled** and **stopped**

#### 🛡️ SMB Configuration

* Verifies mandatory signing on client and server
* Confirms SMBv1 feature is disabled

#### 🔄 Windows Update

* Checks automatic installation settings
* Verifies reboot policies

#### 🔐 Password Policies

* Validates minimum length (≥12 characters)
* Confirms lockout threshold (≤5 attempts)
* Verifies LM Hash is disabled

#### 🔥 Windows Firewall

* Confirms firewall is enabled on all profiles
* Verifies logging configuration

#### 🛑 UAC

* Validates settings for administrators and standard users
* Confirms UAC is enabled

#### 📜 Auditing

* Verifies all audit categories are active
* Confirms success and failure logs

#### 🛡️ Windows Defender

* Confirms real-time protection
* Verifies reporting and sample submission settings
* Checks overall antivirus status

#### ⚙️ Additional Settings

* Idle timeout
* AutoRun disabled
* Windows Script Host blocked

#### 💻 PowerShell

* Confirms Execution Policy is set to RemoteSigned

### How to use

```powershell
# After running hardening-win10.ps1
# Run the verification:
.\hardening-check.ps1
```

### Expected Output

```
============================================================
1. DISABLED SERVICES VERIFICATION
============================================================
[OK] RemoteRegistry service is disabled
[OK] DiagTrack service is disabled
[INFO] Fax service does not exist on this system

============================================================
FINAL VERIFICATION REPORT
============================================================
[INFO] Total checks: 45
[OK] Passed checks: 42
[WARNING] Checks with warnings: 2
[FAIL] Failed checks: 1
[INFO] Success rate: 93.3%

[OK] CONGRATULATIONS! All essential security configurations are applied!
```

### Status Codes

* **[OK]** 🟢 – Configuration correctly applied
* **[WARNING]** 🟡 – Partial configuration or requires attention
* **[FAIL]** 🔴 – Configuration not applied or incorrect
* **[INFO]** 🔵 – Additional information

---

## ⚠️ Impacts and Considerations

### 🎮 Games and Xbox

* **Xbox services disabled** → Xbox features and some games may not work
* **Solution:** Manually re-enable if needed

### 📡 Network and Legacy Devices

* **SMBv1 disabled** → Old printers or legacy NAS devices may stop working
* **Restrictive firewall** → Some applications may require manual rules
* **Solution:** Configure specific exceptions or update devices

### 🔒 Usability

* **UAC always enabled** → More confirmation prompts
* **Strict password policies** → Complex passwords required
* **AutoRun disabled** → USB drives do not auto-execute
* **Scripts blocked** → .vbs/.js files will not run

### 📊 Performance

* **Auditing enabled** → Detailed logs (may consume disk space)
* **Windows Defender** → Daily scan at 2 AM (may affect performance)

### 🔄 Reboot

* **Mandatory** → Some settings only apply after restart

---

## 🚀 Usage Guide

### 1. Preparation

```powershell
# Download the scripts
# Open PowerShell as Administrator
# Navigate to the script folder
cd C:\path\to\scripts
```

### 2. Hardening Execution

```powershell
# Run hardening
.\hardening-win10.ps1

# Restart the system when prompted
```

### 3. Verification

```powershell
# After reboot, run verification
.\hardening-check.ps1

# Optional: Save the report
# The script will ask if you want to save it to a file
```

### 4. Interpreting Results

#### Success Rate

* **90–100%** 🟢 Excellent – System well protected
* **75–89%** 🟡 Good – Some improvements needed
* **<75%** 🔴 Poor – Re-run the hardening

---

## 🎯 Usage Scenarios

### 🏢 Corporate Environment

* **Recommended:** Run on all workstations
* **Benefits:** Security policy compliance
* **Caution:** Test on a pilot group first

### 🏠 Personal Use

* **Evaluate:** Some restrictions may be inconvenient
* **Customize:** Relax password policies if necessary
* **Benefits:** Extra protection against malware

### 🧪 Test Environment

* **Ideal:** Validate configurations before production
* **Use:** Verification script for audits

---

## 🆘 Troubleshooting

### Error: “Script must be run as Administrator”

```powershell
# Right-click PowerShell
# Select "Run as administrator"
```

### Error: “Execution Policy”

```powershell
# Temporarily run:
Set-ExecutionPolicy Bypass -Scope Process -Force
.\hardening-win10.ps1
```

### Legacy devices stop working

```powershell
# Re-enable SMBv1 (NOT RECOMMENDED):
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client"
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server"
```

### Reverting settings

* No automatic rollback script
* Use `gpedit.msc` or `regedit` for manual changes
* Restore system backup if available

---

## 📋 Validation Checklist

After running both scripts, confirm:

* [ ] Success rate > 90%
* [ ] No critical failures in essential services
* [ ] Network devices functioning
* [ ] Critical applications working
* [ ] System backup created (recommended)

---

## 📚 References

* [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
* [CIS Benchmarks for Windows 10](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## 📄 License

Scripts provided for educational and security purposes. Always test in a controlled environment before applying in production.

---

## 🤝 Contributions

Suggestions for improvements are welcome. Remember to:

* Test in an isolated environment
* Document changes
* Maintain Windows 10 compatibility

---

**⚠️ IMPORTANT:** Always back up the system before applying hardening in production.
