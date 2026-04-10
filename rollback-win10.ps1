#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Hardening Rollback — Reverts all security configurations applied by hardening-win10.ps1
.DESCRIPTION
    This script undoes every change made by the hardening script, restoring default Windows 10 behavior.
    Each step asks for confirmation (Y/N) before reverting.
    Run in PowerShell as Administrator.
#>

# ==============================================================================
# SETUP & ENCODING
# ==============================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "SilentlyContinue"

function Write-Header {
    param([string]$Text)
    Write-Host "`n============================================================" -ForegroundColor DarkYellow
    Write-Host " $Text" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor DarkYellow
}

function Rollback-Step {
    param(
        [string]$Title,
        [string]$Description,
        [string]$Warning,
        [ScriptBlock]$ActionScript
    )

    Write-Host "`n[~] $Title" -ForegroundColor Yellow
    Write-Host "    INFO: $Description" -ForegroundColor Gray
    Write-Host "    WARNING: $Warning" -ForegroundColor Red

    $choice = Read-Host "    >> Revert this setting? (Y/N)"

    if ($choice -eq 'Y' -or $choice -eq 'y') {
        Write-Host "    Reverting..." -ForegroundColor Cyan
        & $ActionScript
        Write-Host "    Done." -ForegroundColor Green
    } else {
        Write-Host "    Skipped by user." -ForegroundColor DarkGray
    }
}

Clear-Host
Write-Header "WINDOWS HARDENING ROLLBACK"
Write-Host "Mode: Selective Revert. Each step requires confirmation." -ForegroundColor Gray
Write-Host "WARNING: Reverting these settings will reduce your system's security posture." -ForegroundColor Red

# ==============================================================================
# STEP 1: RE-ENABLE SERVICES
# Hardening set all to Disabled. Restoring to their Windows 10 default StartupType.
# DiagTrack  -> Automatic (Delayed)  | RemoteRegistry -> Manual (Trigger Start)
# Fax        -> Manual               | WerSvc         -> Manual
# XblGameSave -> Manual              | XboxNetApiSvc  -> Manual
# MapsBroker -> Automatic (Delayed)
# ==============================================================================
Rollback-Step -Title "Re-enable Services" `
    -Description "Restores RemoteRegistry, Fax, Xbox, DiagTrack, MapsBroker and WerSvc to their Windows 10 default startup types." `
    -Warning "Restoring DiagTrack and MapsBroker re-enables telemetry and location services." `
    -ActionScript {
        $serviceDefaults = @{
            "DiagTrack"    = "Automatic"
            "MapsBroker"   = "Automatic"
            "RemoteRegistry" = "Manual"
            "Fax"          = "Manual"
            "XblGameSave"  = "Manual"
            "XboxNetApiSvc" = "Manual"
            "WerSvc"       = "Manual"
        }

        foreach ($entry in $serviceDefaults.GetEnumerator()) {
            $svc = Get-Service $entry.Key -ErrorAction SilentlyContinue
            if ($null -ne $svc) {
                Set-Service -Name $entry.Key -StartupType $entry.Value -ErrorAction SilentlyContinue
                Write-Host "    Set $($entry.Key) -> $($entry.Value)." -ForegroundColor DarkGray
            } else {
                Write-Host "    $($entry.Key) not found on this system (skipped)." -ForegroundColor DarkGray
            }
        }
    }

# ==============================================================================
# STEP 2: RE-ENABLE SMBv1
# ==============================================================================
Rollback-Step -Title "Re-enable SMBv1 Protocol" `
    -Description "Re-enables the legacy SMB1 file-sharing protocol via registry and Windows Feature." `
    -Warning "CRITICAL: SMBv1 is highly vulnerable (WannaCry/EternalBlue). Only restore if required for legacy devices." `
    -ActionScript {
        Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force | Out-Null

        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        Set-ItemProperty -Path $regPath -Name "SMB1" -Value 1 -Type DWord -Force

        Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -WarningAction SilentlyContinue | Out-Null
        Write-Host "    SMBv1 re-enabled. A restart may be required to take effect." -ForegroundColor DarkGray
    }

# ==============================================================================
# STEP 3: RESTORE WINDOWS UPDATE DEFAULTS
# Hardening created the AU policy key and set AUOptions=2 and NoAutoRebootWithLoggedOnUsers=1.
# Rollback: remove those properties; if the key was newly created by the hardening script, remove it entirely.
# ==============================================================================
Rollback-Step -Title "Restore Windows Update Defaults" `
    -Description "Removes the custom AU policy that prevents auto-reboot after updates." `
    -Warning "Windows Update may restart your machine automatically after installing patches." `
    -ActionScript {
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (Test-Path $path) {
            Remove-ItemProperty -Path $path -Name "AUOptions" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $path -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue

            # Remove the key itself if it is now empty (was created by the hardening script)
            $remaining = Get-Item -Path $path | Select-Object -ExpandProperty Property
            if ($null -eq $remaining -or $remaining.Count -eq 0) {
                Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
                Write-Host "    AU policy key removed (was empty)." -ForegroundColor DarkGray
            } else {
                Write-Host "    AU policy properties removed. Key kept (other values exist)." -ForegroundColor DarkGray
            }
        } else {
            Write-Host "    AU policy key not found. Nothing to revert." -ForegroundColor DarkGray
        }
    }

# ==============================================================================
# STEP 4: RESTORE DEFAULT PASSWORD POLICY
# Windows 10 Home defaults: MinLen=0, NoComplexity, NoHistory, MaxAge=42, NoLockout
# ==============================================================================
Rollback-Step -Title "Restore Default Password Policy" `
    -Description "Reverts minimum password length, complexity, history and lockout settings to Windows 10 Home defaults." `
    -Warning "Accounts will accept weak or empty passwords again. High security risk." `
    -ActionScript {
        $secpolContent = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 0
PasswordComplexity = 0
PasswordHistorySize = 0
MaximumPasswordAge = 42
MinimumPasswordAge = 0
LockoutBadCount = 0
ResetLockoutCount = 30
LockoutDuration = 30
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
        $secpolFile = "$env:TEMP\rollback_password_policy.inf"
        $secpolDb   = "$env:TEMP\rollback_secedit.sdb"

        Remove-Item $secpolFile -Force -ErrorAction SilentlyContinue
        Remove-Item $secpolDb  -Force -ErrorAction SilentlyContinue

        $secpolContent | Out-File -Encoding Unicode -FilePath $secpolFile
        secedit /configure /db "$secpolDb" /cfg "$secpolFile" /areas SECURITYPOLICY /quiet

        Remove-Item $secpolFile -Force -ErrorAction SilentlyContinue
        Remove-Item $secpolDb  -Force -ErrorAction SilentlyContinue

        gpupdate /force | Out-Null
        Write-Host "    Password policy reset to Windows 10 defaults." -ForegroundColor DarkGray
    }

# ==============================================================================
# STEP 5: FIREWALL — intentionally not rolled back
# Disabling the firewall is never safe; no rollback offered.
# ==============================================================================
Write-Host "`n[V] Firewall Profiles — Skipped intentionally. Disabling the firewall is unsafe." -ForegroundColor DarkGray

# ==============================================================================
# STEP 6: RE-ENABLE WINDOWS SCRIPT HOST (WSH)
# Hardening created the key (if missing) and set Enabled=0.
# Rollback: if the key existed before, set Enabled=1. If it was created by the script, remove it entirely
# so that the system falls back to the default permissive state without a residual registry key.
# ==============================================================================
Rollback-Step -Title "Re-enable Windows Script Host (WSH)" `
    -Description "Removes the WSH block, allowing .VBS and .JS scripts to run system-wide." `
    -Warning "Malicious scripts delivered via email or browser downloads can execute again." `
    -ActionScript {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
        if (Test-Path $path) {
            $keyProps = Get-Item -Path $path | Select-Object -ExpandProperty Property
            # If "Enabled" is the only value the hardening script set, remove the key entirely.
            # Otherwise just remove the Enabled value so other settings are preserved.
            if ($keyProps.Count -le 1 -and $keyProps -contains "Enabled") {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "    WSH Settings key removed. System default (WSH enabled) applies." -ForegroundColor DarkGray
            } else {
                Remove-ItemProperty -Path $path -Name "Enabled" -ErrorAction SilentlyContinue
                Write-Host "    WSH 'Enabled' restriction removed. Other settings kept." -ForegroundColor DarkGray
            }
        } else {
            Write-Host "    WSH Settings key not found. Nothing to revert." -ForegroundColor DarkGray
        }
    }

# ==============================================================================
# STEP 7: RESTORE UAC DEFAULT
# Windows 10 default: ConsentPromptBehaviorAdmin = 5 (Prompt for consent for non-Windows binaries)
# Hardening set it to 2 (Always prompt on secure desktop)
# ==============================================================================
Rollback-Step -Title "Restore UAC Default Level" `
    -Description "Reverts UAC from 'Always notify (Secure Desktop)' to Windows default (notify only for app installs)." `
    -Warning "UAC will no longer prompt for changes made by Windows-signed binaries. Slight privilege escalation risk." `
    -ActionScript {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "ConsentPromptBehaviorAdmin" -Value 5
        Write-Host "    UAC reset to default (ConsentPromptBehaviorAdmin = 5)." -ForegroundColor DarkGray
    }

# ==============================================================================
# STEP 8: RESTORE AUTOMATIC DNS (DHCP)
# ==============================================================================
Rollback-Step -Title "Restore Automatic DNS (DHCP)" `
    -Description "Removes the static Cloudflare DNS (1.1.1.1 / 1.0.0.1) and returns to ISP-provided DNS via DHCP." `
    -Warning "DNS privacy depends entirely on your ISP or router after this change." `
    -ActionScript {
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
            Write-Host "    DNS reset on adapter: $($_.Name)." -ForegroundColor DarkGray
        }
    }

# ==============================================================================
# STEP 9: RESTORE EXPLOIT PROTECTION DEFAULTS
# FIX: Use explicit array @() to avoid parsing ambiguity with the comma operator.
# ==============================================================================
Rollback-Step -Title "Restore Exploit Protection Defaults" `
    -Description "Disables the forced system-wide DEP (OptOut) and BottomUp ASLR overrides." `
    -Warning "Without these overrides, per-process settings control DEP/ASLR. Some zero-day protection is reduced." `
    -ActionScript {
        Set-ProcessMitigation -System -Disable @("DEP", "BottomUp")
        Write-Host "    System-wide DEP/ASLR overrides removed." -ForegroundColor DarkGray
    }

# ==============================================================================
# STEP 10: HIDE FILE EXTENSIONS (WINDOWS DEFAULT)
# FIX: Start Explorer explicitly after killing it so the user isn't left with no desktop.
# ==============================================================================
Rollback-Step -Title "Hide File Extensions (Windows Default)" `
    -Description "Returns to the Windows default of hiding known file extensions in Explorer." `
    -Warning "Disguised executables (e.g. invoice.pdf.exe shown as invoice.pdf) will be hidden again." `
    -ActionScript {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
            -Name "HideFileExt" -Value 1
        Write-Host "    Registry updated. Restarting Explorer to apply..." -ForegroundColor DarkGray
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) {
            Start-Process explorer
        }
        Write-Host "    File extensions hidden. Explorer restarted." -ForegroundColor DarkGray
    }

# ==============================================================================
# STEP 11: DISABLE POWERSHELL ADVANCED LOGGING
# Correctly removes the ModuleNames subkey first, then sets flags to 0
# (removes keys only if they were empty to avoid breaking other policies).
# ==============================================================================
Rollback-Step -Title "Disable PowerShell Advanced Logging" `
    -Description "Turns off ScriptBlock Logging and Module Logging policies." `
    -Warning "PowerShell-based attacks will no longer be recorded in Event Viewer." `
    -ActionScript {
        $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
        $sbPath = "$psPath\ScriptBlockLogging"
        $mlPath = "$psPath\ModuleLogging"
        $moPath = "$mlPath\ModuleNames"

        # Remove ModuleNames subkey first (child of ModuleLogging)
        if (Test-Path $moPath) {
            Remove-Item -Path $moPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "    ModuleNames subkey removed." -ForegroundColor DarkGray
        }

        if (Test-Path $sbPath) {
            Set-ItemProperty -Path $sbPath -Name "EnableScriptBlockLogging" -Value 0
            Write-Host "    ScriptBlockLogging disabled." -ForegroundColor DarkGray
        }

        if (Test-Path $mlPath) {
            Set-ItemProperty -Path $mlPath -Name "EnableModuleLogging" -Value 0
            Write-Host "    ModuleLogging disabled." -ForegroundColor DarkGray
        }
    }

# ==============================================================================
# STEP 12: RESTORE WINDOWS TELEMETRY
# Hardening created the DataCollection key (if missing) and set AllowTelemetry=0.
# Rollback: remove the value; remove key entirely if now empty.
# ==============================================================================
Rollback-Step -Title "Restore Windows Telemetry" `
    -Description "Removes the AllowTelemetry=0 override, restoring Microsoft diagnostic data collection." `
    -Warning "Microsoft may collect usage and diagnostic telemetry data again." `
    -ActionScript {
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        if (Test-Path $path) {
            Remove-ItemProperty -Path $path -Name "AllowTelemetry" -ErrorAction SilentlyContinue

            $remaining = Get-Item -Path $path | Select-Object -ExpandProperty Property
            if ($null -eq $remaining -or $remaining.Count -eq 0) {
                Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
                Write-Host "    DataCollection key removed (was empty)." -ForegroundColor DarkGray
            } else {
                Write-Host "    AllowTelemetry removed. Key kept (other values exist)." -ForegroundColor DarkGray
            }
        } else {
            Write-Host "    DataCollection key not found. Nothing to revert." -ForegroundColor DarkGray
        }
    }

# ==============================================================================
# STEP 13: RE-ENABLE AUTORUN / AUTOPLAY
# Hardening set NoDriveTypeAutoRun=255 on HKLM and HKCU, and DisableAutoplay=1 on HKCU.
# Rollback: remove NoDriveTypeAutoRun (which restores Windows default behaviour);
#           reset DisableAutoplay to 0.
# ==============================================================================
Rollback-Step -Title "Re-enable AutoRun/AutoPlay" `
    -Description "Removes the AutoRun block, restoring automatic media handling for USB drives and optical disks." `
    -Warning "Infected USB drives can auto-execute malware upon insertion after this change." `
    -ActionScript {
        $policiesHKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        $policiesHKCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        $autoplayHKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"

        if (Test-Path $policiesHKLM) {
            Remove-ItemProperty -Path $policiesHKLM -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
            Write-Host "    NoDriveTypeAutoRun removed from HKLM." -ForegroundColor DarkGray
        }
        if (Test-Path $policiesHKCU) {
            Remove-ItemProperty -Path $policiesHKCU -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
            Write-Host "    NoDriveTypeAutoRun removed from HKCU." -ForegroundColor DarkGray
        }
        if (Test-Path $autoplayHKCU) {
            Set-ItemProperty -Path $autoplayHKCU -Name "DisableAutoplay" -Value 0 -Type DWord
            Write-Host "    DisableAutoplay set to 0 (AutoPlay re-enabled)." -ForegroundColor DarkGray
        }
    }

# ==============================================================================
# CONCLUSION
# ==============================================================================
Write-Header "ROLLBACK COMPLETE"
Write-Host "All selected settings have been reverted." -ForegroundColor Cyan
Write-Host "Your system's security posture has been reduced. Use with caution." -ForegroundColor Yellow

$reboot = Read-Host "`nA system restart is recommended to fully apply all changes. Restart now? (Y/N)"
if ($reboot -eq 'Y' -or $reboot -eq 'y') {
    Write-Host "Rebooting..." -ForegroundColor Yellow
    Restart-Computer -Force
}
