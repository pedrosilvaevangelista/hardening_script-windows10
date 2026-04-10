### To undo the hardening and return to default Windows settings, run these commands in **PowerShell as Administrator**:

#### **Step 1: Reactivate Critical Services**

```powershell
$services = @("RemoteRegistry", "Fax", "XblGameSave", "DiagTrack", "XboxNetApiSvc", "MapsBroker", "WerSvc")
foreach ($s in $services) { Set-Service -Name $s -StartupType Manual }

```

#### **Step 2: Reactivate SMBv1**

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart

```

#### **Step 3: Restore Windows Update Defaults**

```powershell
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
Remove-ItemProperty -Path $path -Name "AUOptions" 
Remove-ItemProperty -Path $path -Name "NoAutoRebootWithLoggedOnUsers"

```

#### **Step 4: Reset Password Policy**

```powershell
# Removes complexity and length requirements
cmd /c "net accounts /minpwlen:0 /maxpwage:unlimited /uniquepw:0 /lockoutthreshold:0"

```

#### **Step 5: Restore Firewall Profiles to Default**

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True 
# (Note: Windows default is 'True', but this ensures they are back to normal)

```

#### **Step 6: Reactivate Windows Script Host (.VBS/.JS)**

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 1

```

#### **Step 7: Restore UAC to Default Level**

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5

```

#### **Step 8: Reset DNS to Automatic (DHCP)**

```powershell
Get-NetAdapter | Where-Object Status -eq 'Up' | Set-DnsClientServerAddress -ResetServerAddresses

```

#### **Step 9: Disable System-wide Exploit Protection**

```powershell
Set-ProcessMitigation -System -Disable DEP, BottomUp

```

#### **Step 10: Hide File Extensions Again**

```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1
Stop-Process -Name explorer -Force

```