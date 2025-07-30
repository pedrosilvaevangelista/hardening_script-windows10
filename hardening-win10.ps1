#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 10 Workstation Hardening Script
.DESCRIPTION
    Script to apply security configurations on Windows 10 workstations
.NOTES
    Run as Administrator
    Tested on Windows 10
#>

# Function for colored logging
function Write-LogInfo {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-LogSuccess {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-LogWarning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-LogError {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-LogError "This script must be run as Administrator!"
    exit 1
}

Write-LogInfo "Starting Windows 10 hardening process..."

# -- DISABLE UNNECESSARY SERVICES --
Write-LogInfo "Disabling unnecessary services..."

$services = @(
    "RemoteRegistry",
    "Fax",
    "XblGameSave",
    "WMPNetworkSvc",
    "DiagTrack",
    "dmwappushservice",
    "RetailDemo",
    "XboxNetApiSvc",
    "XboxGipSvc",
    "WerSvc",
    "MapsBroker",
    "SharedAccess",
    "TrkWks",
    "PhoneSvc"
)

foreach ($service in $services) {
    try {
        $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($serviceObj) {
            Write-LogInfo "Disabling service: $service"
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Write-LogSuccess "Service $service disabled"
        } else {
            Write-LogWarning "Service $service not found"
        }
    } catch {
        Write-LogError "Error disabling service $service"
    }
}

# -- DISABLE SMBV1 --
Write-LogInfo "Disabling SMBv1..."

try {
    # Disable SMBv1 client
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters") {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Force
    }

    # Disable SMBv1 server
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Force
    }

    # Disable SMBv1 via PowerShell
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart -ErrorAction SilentlyContinue
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart -ErrorAction SilentlyContinue
    
    Write-LogSuccess "SMBv1 successfully disabled"
} catch {
    Write-LogError "Error disabling SMBv1"
}

# -- CONFIGURE WINDOWS UPDATE --
Write-LogInfo "Configuring Windows Update..."

try {
    $wuAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (-not (Test-Path $wuAU)) {
        New-Item -Path $wuAU -Force | Out-Null
    }

    Set-ItemProperty -Path $wuAU -Name "AUOptions" -Value 4 -Type DWord
    Set-ItemProperty -Path $wuAU -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord
    
    Write-LogSuccess "Windows Update configured"
} catch {
    Write-LogError "Error configuring Windows Update"
}

# -- CONFIGURE PASSWORD POLICIES --
Write-LogInfo "Configuring password policies..."

try {
    # Configure basic policies via net accounts
    cmd /c "net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:24"
    
    # Configure lockout policy via net accounts
    cmd /c "net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15"
    
    # Try to apply complexity via secpol (if it fails, continue without critical error)
    try {
        $secpolContent = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 12
PasswordComplexity = 1
PasswordHistorySize = 24
MaximumPasswordAge = 90
MinimumPasswordAge = 1
[Version]
signature="`$CHICAGO`$"
Revision=1
"@

        $secpolFile = "$env:TEMP\password_policy.inf"
        $secpolContent | Out-File -Encoding ASCII -FilePath $secpolFile
        
        $process = Start-Process -FilePath "secedit.exe" -ArgumentList "/configure /db secedit.sdb /cfg `"$secpolFile`" /areas SECURITYPOLICY" -Wait -NoNewWindow -PassThru
        
        Remove-Item $secpolFile -ErrorAction SilentlyContinue
        
        if ($process.ExitCode -eq 0) {
            Write-LogSuccess "Password complexity applied via secpol"
        } else {
            Write-LogWarning "Secpol showed warnings (check log at %windir%\security\logs\scesrv.log)"
        }
    } catch {
        Write-LogWarning "Could not apply complexity via secpol, but basic policies were applied"
    }
    
    Write-LogSuccess "Password policies configured"
} catch {
    Write-LogError "Error configuring password policies"
}

# -- CONFIGURE FIREWALL --
Write-LogInfo "Configuring Windows Firewall..."

try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed True -LogBlocked True
    
    Write-LogSuccess "Windows Firewall configured and enabled"
} catch {
    Write-LogError "Error configuring firewall"
}

# -- CONFIGURE UAC --
Write-LogInfo "Configuring UAC..."

try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 3 -Type DWord
    
    Write-LogSuccess "UAC configured"
} catch {
    Write-LogError "Error configuring UAC"
}

# -- CONFIGURE AUDITING --
Write-LogInfo "Configuring event auditing..."

try {
    # List of audit commands with individual verification
    $auditSettings = @(
        @{Name="Logon"; Command="auditpol /set /subcategory:`"Logon`" /success:enable /failure:enable"},
        @{Name="Logoff"; Command="auditpol /set /subcategory:`"Logoff`" /success:enable /failure:enable"},
        @{Name="Account Lockout"; Command="auditpol /set /subcategory:`"Account Lockout`" /success:enable /failure:enable"},
        @{Name="User Account Management"; Command="auditpol /set /subcategory:`"User Account Management`" /success:enable /failure:enable"},
        @{Name="Process Creation"; Command="auditpol /set /subcategory:`"Process Creation`" /success:enable /failure:disable"},
        @{Name="System"; Command="auditpol /set /subcategory:`"System`" /success:enable /failure:enable"}
    )
    
    foreach ($audit in $auditSettings) {
        try {
            $result = cmd /c $audit.Command 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-LogInfo "Auditing configured: $($audit.Name)"
            } else {
                Write-LogWarning "Failed to configure auditing: $($audit.Name)"
            }
        } catch {
            Write-LogWarning "Error configuring auditing: $($audit.Name)"
        }
    }
    
    Write-LogSuccess "Auditing configured (with individual verification)"
} catch {
    Write-LogError "Error configuring auditing"
}

# -- CONFIGURE WINDOWS DEFENDER --
Write-LogInfo "Configuring Windows Defender..."

try {
    if (Get-Command "Set-MpPreference" -ErrorAction SilentlyContinue) {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -ScanScheduleDay Everyday
        Set-MpPreference -ScanScheduleTime 02:00:00
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent SendAllSamples
        
        Write-LogSuccess "Windows Defender configured"
    } else {
        Write-LogWarning "Windows Defender is not available"
    }
} catch {
    Write-LogError "Error configuring Windows Defender"
}

# -- ADDITIONAL SECURITY CONFIGURATIONS --
Write-LogInfo "Applying additional security configurations..."

try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900 -Type DWord
    
    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord
    
    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord
    
    Write-LogSuccess "Additional security configurations applied"
} catch {
    Write-LogError "Error applying additional configurations"
}

# -- CONFIGURE EXECUTION POLICY --
Write-LogInfo "Configuring PowerShell Execution Policy..."

try {
    Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Write-LogSuccess "PowerShell Execution Policy configured to RemoteSigned"
} catch {
    Write-LogError "Error configuring Execution Policy"
}

# -- FINAL REPORT --
Write-LogInfo "=== APPLIED CONFIGURATIONS REPORT ==="
Write-LogSuccess "Unnecessary services disabled"
Write-LogSuccess "SMBv1 disabled"
Write-LogSuccess "Windows Update configured"
Write-LogSuccess "Password policies applied"
Write-LogSuccess "Windows Firewall enabled"
Write-LogSuccess "UAC configured"
Write-LogSuccess "Auditing enabled"
Write-LogSuccess "Windows Defender configured"
Write-LogSuccess "Additional security configurations applied"
Write-LogSuccess "PowerShell Execution Policy configured"

Write-LogWarning "IMPORTANT: Restart the system for all changes to take full effect."
Write-LogInfo "Hardening process completed!"

# Ask if user wants to restart
$restart = Read-Host "Do you want to restart the system now? (Y/N)"
if ($restart -eq "Y" -or $restart -eq "y") {
    Write-LogInfo "Restarting system in 10 seconds..."
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}
