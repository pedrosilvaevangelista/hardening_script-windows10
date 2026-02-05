#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Decisive Hardening (Final Stability Release)
#>

# 1. SETUP & ENCODING
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "SilentlyContinue"

function Write-Header {
    param([string]$Text)
    Write-Host "`n============================================================" -ForegroundColor DarkCyan
    Write-Host " $Text" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor DarkCyan
}

# 2. INTELLIGENCE FUNCTION
function Manage-Step {
    param(
        [string]$Title,
        [string]$Description,
        [string]$Risk,
        [ScriptBlock]$CheckScript,
        [ScriptBlock]$ActionScript
    )

    Write-Host "`nProcessing: $Title..." -NoNewline -ForegroundColor Gray

    # EXECUTE AUDIT
    $isSecure = & $CheckScript

    if ($isSecure) {
        Write-Host "`r[V] $Title" -ForegroundColor Green -NoNewline
        Write-Host " - ALREADY SECURED (Skipping)" -ForegroundColor DarkGray
        return
    }

    # IF VULNERABLE -> ASK USER
    Write-Host "`r[X] $Title" -ForegroundColor Red -NoNewline
    Write-Host " - VULNERABLE/DEFAULT" -ForegroundColor Red
    
    Write-Host "    INFO: $Description" -ForegroundColor Gray
    Write-Host "    RISK: $Risk" -ForegroundColor Yellow
    
    $choice = Read-Host "    >> Apply Fix? (Y/N)"
    
    if ($choice -eq 'Y' -or $choice -eq 'y') {
        Write-Host "    Applying fix..." -ForegroundColor Cyan
        & $ActionScript
        Write-Host "    Done." -ForegroundColor Green
    } else {
        Write-Host "    Skipped by user." -ForegroundColor DarkGray
    }
}

Clear-Host
Write-Header "WINDOWS HARDENING"
Write-Host "Mode: Audit-First. Asking only when necessary." -ForegroundColor Gray

# ==============================================================================
# STEP 1: SERVICES
# ==============================================================================
Manage-Step -Title "Critical Services" `
    -Description "Disable RemoteRegistry, Fax, Xbox, Telemetry." `
    -Risk "Xbox App and legacy Fax machines will stop working." `
    -CheckScript {
        $svcs = @("RemoteRegistry", "Fax", "DiagTrack", "XblGameSave")
        $allDisabled = $true
        foreach ($s in $svcs) { 
            if ((Get-Service $s).StartType -ne 'Disabled') { $allDisabled = $false } 
        }
        return $allDisabled
    } `
    -ActionScript {
        $services = @("RemoteRegistry", "Fax", "XblGameSave", "DiagTrack", "XboxNetApiSvc", "MapsBroker", "WerSvc")
        foreach ($s in $services) {
            Stop-Service -Name $s -Force
            Set-Service -Name $s -StartupType Disabled
        }
    }

# ==============================================================================
# STEP 2: SMBv1 PROTOCOL
# ==============================================================================
Manage-Step -Title "SMBv1 Protocol" `
    -Description "Disable 30-year-old vulnerable file sharing protocol." `
    -Risk "Very old NAS (pre-2010) or ancient printers may lose connection." `
    -CheckScript {
        # Verifica se o recurso está desabilitado ou se o registro já bloqueia o SMB1
        $feature = (Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol").State
        $reg = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue).SMB1
        return ($feature -eq 'Disabled') -and ($reg -eq 0)
    } `
    -ActionScript {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null
        
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        Set-ItemProperty -Path $regPath -Name "SMB1" -Value 0 -Force
        
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -WarningAction SilentlyContinue | Out-Null
        
        Write-Host "    SMBv1 disabled via Registry and Feature management." -ForegroundColor Cyan
    }

# ==============================================================================
# STEP 3: WINDOWS UPDATE
# ==============================================================================
Manage-Step -Title "Windows Update Control" `
    -Description "Set updates to Notify-Only (Prevent Auto-Reboot)." `
    -Risk "Requires discipline to install updates manually when notified." `
    -CheckScript {
        $val = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU").AUOptions
        return $val -eq 4
    } `
    -ActionScript {
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "AUOptions" -Value 4
        Set-ItemProperty -Path $path -Name "NoAutoRebootWithLoggedOnUsers" -Value 1
    }

# ==============================================================================
# STEP 4: PASSWORD POLICY
# ==============================================================================
Manage-Step -Title "Password Hardening" `
    -Description "Enforce Complexity, Min 12 chars, Lockout logic." `
    -Risk "15-min lockout if you forget password. Complex passwords required." `
    -CheckScript {
        $tempFile = "$env:TEMP\secpol_check.cfg"
        secedit /export /cfg "$tempFile" /quiet
        $content = Get-Content $tempFile
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        
        $minLen = ($content | Select-String "MinimumPasswordLength\s*=\s*(\d+)").Matches.Groups[1].Value
        $complexity = ($content | Select-String "PasswordComplexity\s*=\s*(\d+)").Matches.Groups[1].Value
        
        return ([int]$minLen -ge 12) -and ([int]$complexity -eq 1)
    } `
    -ActionScript {
        $secpolContent = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 12
PasswordComplexity = 1
PasswordHistorySize = 24
MaximumPasswordAge = 90
MinimumPasswordAge = 1
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
        $secpolFile = "$env:TEMP\password_policy.inf"
        $secpolDb = "$env:TEMP\secedit.sdb"
        
        Remove-Item $secpolFile -Force -ErrorAction SilentlyContinue
        Remove-Item $secpolDb -Force -ErrorAction SilentlyContinue
        
        $secpolContent | Out-File -Encoding Unicode -FilePath $secpolFile
        secedit /configure /db "$secpolDb" /cfg "$secpolFile" /areas SECURITYPOLICY /quiet
        
        Remove-Item $secpolFile -Force -ErrorAction SilentlyContinue
        Remove-Item $secpolDb -Force -ErrorAction SilentlyContinue
        
        gpupdate /force | Out-Null
    }

# ==============================================================================
# STEP 5: FIREWALL
# ==============================================================================
Manage-Step -Title "Firewall Profiles" `
    -Description "Ensure Domain, Private, and Public firewalls are ON." `
    -Risk "May block unconfigured local network apps." `
    -CheckScript {
        return (Get-NetFirewallProfile -Profile Domain,Private,Public | Where-Object {$_.Enabled -eq 'True'}).Count -eq 3
    } `
    -ActionScript {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    }

# ==============================================================================
# STEP 6: WINDOWS SCRIPT HOST
# ==============================================================================
Manage-Step -Title "Block WSH (.VBS/.JS)" `
    -Description "Prevents execution of malicious VBS scripts." `
    -Risk "High. Some legacy installers or admin scripts might fail." `
    -CheckScript {
        return (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings").Enabled -eq 0
    } `
    -ActionScript {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
        if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "Enabled" -Value 0
    }

# ==============================================================================
# STEP 7: UAC
# ==============================================================================
Manage-Step -Title "UAC Maximum Level" `
    -Description "Always notify on Secure Desktop for Admin tasks." `
    -Risk "More frequency of permission prompts." `
    -CheckScript {
        return (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").ConsentPromptBehaviorAdmin -eq 2
    } `
    -ActionScript {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
    }

# ==============================================================================
# STEP 8: SECURE DNS
# ==============================================================================
Manage-Step -Title "Secure DNS (1.1.1.1)" `
    -Description "Use Cloudflare DNS for privacy and speed." `
    -Risk "Low. Internet may fail if Cloudflare goes down globally." `
    -CheckScript {
        return (Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses -contains "1.1.1.1"
    } `
    -ActionScript {
        Get-NetAdapter | Where-Object Status -eq 'Up' | Set-DnsClientServerAddress -ServerAddresses ("1.1.1.1", "1.0.0.1")
    }

# ==============================================================================
# STEP 9: EXPLOIT PROTECTION
# ==============================================================================
Manage-Step -Title "Exploit Protection (DEP/ASLR)" `
    -Description "Enforce Memory randomization and Data Execution Prevention." `
    -Risk "May crash extremely old software (Windows XP era code)." `
    -CheckScript {
        $m = Get-ProcessMitigation -System
        return ($m.Dep.Enable -ne 0) -and ($m.BottomUpAslr.Enable -ne 0)
    } `
    -ActionScript {
        Set-ProcessMitigation -System -Enable DEP, BottomUp
    }

# ==============================================================================
# STEP 10: FILE EXTENSIONS
# ==============================================================================
Manage-Step -Title "Show File Extensions" `
    -Description "Reveal hidden extensions (e.g., prevents fake .jpg.exe)." `
    -Risk "None. Visual change only." `
    -CheckScript {
        return (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced").HideFileExt -eq 0
    } `
    -ActionScript {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
        Stop-Process -Name explorer -Force
    }

# ==============================================================================
# CONCLUSION
# ==============================================================================
Write-Header "HARDENING COMPLETE"
Write-Host "All steps processed." -ForegroundColor Cyan

$reboot = Read-Host "`nA system restart is required to apply all locks. Restart now? (Y/N)"
if ($reboot -eq 'Y' -or $reboot -eq 'y') {
    Write-Host "Rebooting..." -ForegroundColor Yellow
    Restart-Computer -Force
}