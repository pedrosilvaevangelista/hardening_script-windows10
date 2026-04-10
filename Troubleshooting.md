### To undo the hardening and return to default Windows settings, run these commands in **PowerShell as Administrator**:

#### **Step 1: Reactivate Critical Services**

```powershell
# DiagTrack and MapsBroker default to Automatic; the rest default to Manual
Set-Service -Name "DiagTrack" -StartupType Automatic
Set-Service -Name "MapsBroker" -StartupType Automatic
Set-Service -Name "RemoteRegistry" -StartupType Manual
Set-Service -Name "Fax" -StartupType Manual
Set-Service -Name "XblGameSave" -StartupType Manual
Set-Service -Name "XboxNetApiSvc" -StartupType Manual
Set-Service -Name "WerSvc" -StartupType Manual

```

#### **Step 2: Reactivate SMBv1**

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 1 -Force
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart

```

#### **Step 3: Restore Windows Update Defaults**

```powershell
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
Remove-ItemProperty -Path $path -Name "AUOptions" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $path -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue

```

#### **Step 4: Reset Password Policy**

```powershell
# Uses secedit to properly reset PasswordComplexity (net accounts cannot do this)
$policy = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 0
PasswordComplexity = 0
PasswordHistorySize = 0
MaximumPasswordAge = 42
MinimumPasswordAge = 0
LockoutBadCount = 0
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
$policy | Out-File -Encoding Unicode "$env:TEMP\reset.inf"
secedit /configure /db "$env:TEMP\reset.sdb" /cfg "$env:TEMP\reset.inf" /areas SECURITYPOLICY /quiet
Remove-Item "$env:TEMP\reset.inf", "$env:TEMP\reset.sdb" -Force -ErrorAction SilentlyContinue
gpupdate /force

```

#### **Step 5: Restore Firewall Profiles to Default**

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
# (Note: Windows default is 'True', but this ensures they are back to normal)

```

#### **Step 6: Reactivate Windows Script Host (.VBS/.JS)**

```powershell
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue

```

#### **Step 7: Restore UAC to Default Level**

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5

```

#### **Step 8: Reset DNS to Automatic (DHCP)**

```powershell
Get-NetAdapter | Where-Object Status -eq 'Up' | Set-DnsClientServerAddress -ResetServerAddresses

```

#### **Step 9: Exploit Protection (DEP/ASLR)**

> **Note:** DEP and ASLR are **enabled by default** in Windows 10. The hardening script only reinforced their enforcement level. No action is needed to restore defaults — they remain active and safe as-is.

#### **Step 10: Hide File Extensions Again**

```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1; Start-Process explorer

```

#### **Step 11: Remove PowerShell Advanced Logging**

```powershell
$psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
Remove-Item -Path "$psPath\ScriptBlockLogging" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$psPath\ModuleLogging" -Recurse -Force -ErrorAction SilentlyContinue

```

#### **Step 12: Restore Telemetry**

```powershell
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
Remove-ItemProperty -Path $path -Name "AllowTelemetry" -ErrorAction SilentlyContinue

```

#### **Step 13: Re-enable AutoRun/AutoPlay**

```powershell
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 0 -Type DWord

```