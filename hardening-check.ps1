#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 10 Security Configuration Verification Script
.DESCRIPTION
    Script to verify all security configurations applied by hardening
.NOTES
    Run as Administrator
    Generates complete security configuration report
#>

# Functions for colored logging
function Write-StatusOK {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-StatusFAIL {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Write-StatusWARN {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-StatusINFO {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "-- $Title --" -ForegroundColor Blue
    Write-Host "-" * ($Title.Length + 6) -ForegroundColor Blue
}

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-StatusFAIL "This script must be run as Administrator!"
    exit 1
}

# Variables for counters
$totalChecks = 0
$passedChecks = 0
$failedChecks = 0
$warningChecks = 0

function Update-Counters {
    param([string]$Status)
    $script:totalChecks++
    switch ($Status) {
        "OK" { $script:passedChecks++ }
        "FAIL" { $script:failedChecks++ }
        "WARN" { $script:warningChecks++ }
    }
}

Write-StatusINFO "Starting complete security configuration verification..."
Write-StatusINFO "Date/Time: $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
Write-StatusINFO "System: $env:COMPUTERNAME"

# -- VERIFY DISABLED SERVICES --
Write-SectionHeader "1. DISABLED SERVICES VERIFICATION"

$servicesToCheck = @(
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

foreach ($serviceName in $servicesToCheck) {
    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.StartType -eq "Disabled" -and $service.Status -eq "Stopped") {
                Write-StatusOK "Service $serviceName is disabled"
                Update-Counters "OK"
            } elseif ($service.StartType -eq "Disabled") {
                Write-StatusWARN "Service $serviceName is disabled but still running"
                Update-Counters "WARN"
            } else {
                Write-StatusFAIL "Service $serviceName is NOT disabled (StartType: $($service.StartType))"
                Update-Counters "FAIL"
            }
        } else {
            Write-StatusINFO "Service $serviceName does not exist on this system"
            Update-Counters "OK"
        }
    } catch {
        Write-StatusWARN "Error checking service $serviceName"
        Update-Counters "WARN"
    }
}

# -- VERIFY SMBV1 --
Write-SectionHeader "2. SMBV1 VERIFICATION"

try {
    # Check SMBv1 client
    $smbClientSig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
    if ($smbClientSig -and $smbClientSig.RequireSecuritySignature -eq 1) {
        Write-StatusOK "SMB Client - Required security signature enabled"
        Update-Counters "OK"
    } else {
        Write-StatusFAIL "SMB Client - Security signature NOT required"
        Update-Counters "FAIL"
    }

    # Check SMBv1 server
    $smbServerSig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
    if ($smbServerSig -and $smbServerSig.RequireSecuritySignature -eq 1) {
        Write-StatusOK "SMB Server - Required security signature enabled"
        Update-Counters "OK"
    } else {
        Write-StatusFAIL "SMB Server - Security signature NOT required"
        Update-Counters "FAIL"
    }

    # Check SMBv1 features
    $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -ErrorAction SilentlyContinue
    if ($smb1Feature -and $smb1Feature.State -eq "Disabled") {
        Write-StatusOK "SMBv1-Client feature is disabled"
        Update-Counters "OK"
    } else {
        Write-StatusFAIL "SMBv1-Client feature is NOT disabled"
        Update-Counters "FAIL"
    }

} catch {
    Write-StatusWARN "Error checking SMB configurations"
    Update-Counters "WARN"
}

# -- VERIFY WINDOWS UPDATE --
Write-SectionHeader "3. WINDOWS UPDATE VERIFICATION"

try {
    $wuAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (Test-Path $wuAU) {
        $auOptions = Get-ItemProperty -Path $wuAU -Name "AUOptions" -ErrorAction SilentlyContinue
        if ($auOptions -and $auOptions.AUOptions -eq 4) {
            Write-StatusOK "Windows Update configured for automatic download and install"
            Update-Counters "OK"
        } else {
            Write-StatusWARN "Windows Update configuration different from expected"
            Update-Counters "WARN"
        }

        $noAutoReboot = Get-ItemProperty -Path $wuAU -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
        if ($noAutoReboot -and $noAutoReboot.NoAutoRebootWithLoggedOnUsers -eq 1) {
            Write-StatusOK "Automatic reboot with logged users disabled"
            Update-Counters "OK"
        } else {
            Write-StatusWARN "Automatic reboot configuration not found"
            Update-Counters "WARN"
        }
    } else {
        Write-StatusWARN "Windows Update registry key not found"
        Update-Counters "WARN"
    }
} catch {
    Write-StatusWARN "Error checking Windows Update configurations"
    Update-Counters "WARN"
}

# -- VERIFY PASSWORD POLICIES --
Write-SectionHeader "4. PASSWORD POLICIES VERIFICATION"

try {
    # Execute net accounts and capture output
    $netAccountsOutput = cmd /c "net accounts" 2>&1
    
    # Parse output line by line
    $minPwLen = $null
    $maxPwAge = $null
    $lockoutThreshold = $null
    $lockoutDuration = $null
    
    foreach ($line in $netAccountsOutput) {
        if ($line -like "*Minimum password length*") {
            $minPwLen = ($line -split ":")[1].Trim()
        }
        if ($line -like "*Maximum password age*") {
            $maxPwAge = ($line -split ":")[1].Trim()
        }
        if ($line -like "*Lockout threshold*") {
            $lockoutThreshold = ($line -split ":")[1].Trim()
        }
        if ($line -like "*Lockout duration*") {
            $lockoutDuration = ($line -split ":")[1].Trim()
        }
    }

    # Check minimum password length
    if ($minPwLen -and [int]$minPwLen -ge 12) {
        Write-StatusOK "Minimum password length: $minPwLen characters"
        Update-Counters "OK"
    } else {
        Write-StatusFAIL "Inadequate minimum password length: $minPwLen"
        Update-Counters "FAIL"
    }

    # Check lockout threshold
    if ($lockoutThreshold -and [int]$lockoutThreshold -le 5 -and [int]$lockoutThreshold -gt 0) {
        Write-StatusOK "Login attempt limit: $lockoutThreshold attempts"
        Update-Counters "OK"
    } else {
        Write-StatusFAIL "Inadequate attempt limit: $lockoutThreshold"
        Update-Counters "FAIL"
    }

    # Check lockout duration
    if ($lockoutDuration -and $lockoutDuration -ne "Never") {
        Write-StatusOK "Account lockout duration: $lockoutDuration"
        Update-Counters "OK"
    } else {
        Write-StatusWARN "Lockout duration: $lockoutDuration"
        Update-Counters "WARN"
    }

    # Check LM Hash
    $noLMHash = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -ErrorAction SilentlyContinue
    if ($noLMHash -and $noLMHash.NoLMHash -eq 1) {
        Write-StatusOK "LM Hash disabled"
        Update-Counters "OK"
    } else {
        Write-StatusFAIL "LM Hash is NOT disabled"
        Update-Counters "FAIL"
    }

} catch {
    Write-StatusWARN "Error checking password policies"
    Update-Counters "WARN"
}

# -- VERIFY FIREWALL --
Write-SectionHeader "5. WINDOWS FIREWALL VERIFICATION"

try {
    $firewallProfiles = Get-NetFirewallProfile
    
    foreach ($profile in $firewallProfiles) {
        if ($profile.Enabled -eq $true) {
            Write-StatusOK "Firewall $($profile.Name) profile: ENABLED"
            Update-Counters "OK"
        } else {
            Write-StatusFAIL "Firewall $($profile.Name) profile: DISABLED"
            Update-Counters "FAIL"
        }
        
        if ($profile.LogAllowed -eq $true -and $profile.LogBlocked -eq $true) {
            Write-StatusOK "Firewall $($profile.Name) profile: Logging enabled"
            Update-Counters "OK"
        } else {
            Write-StatusWARN "Firewall $($profile.Name) profile: Logging not configured"
            Update-Counters "WARN"
        }
    }
} catch {
    Write-StatusWARN "Error checking firewall configurations"
    Update-Counters "WARN"
}

# -- VERIFY UAC --
Write-SectionHeader "6. UAC VERIFICATION"

try {
    $uacAdmin = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
    if ($uacAdmin -and $uacAdmin.ConsentPromptBehaviorAdmin -eq 2) {
        Write-StatusOK "UAC for administrators: Consent prompt enabled"
        Update-Counters "OK"
    } else {
        Write-StatusFAIL "UAC for administrators NOT configured correctly"
        Update-Counters "FAIL"
    }

    $uacEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($uacEnabled -and $uacEnabled.EnableLUA -eq 1) {
        Write-StatusOK "UAC is enabled"
        Update-Counters "OK"
    } else {
        Write-StatusFAIL "UAC is NOT enabled"
        Update-Counters "FAIL"
    }

    $uacUser = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -ErrorAction SilentlyContinue
    if ($uacUser -and $uacUser.ConsentPromptBehaviorUser -eq 3) {
        Write-StatusOK "UAC for standard users: Credential prompt enabled"
        Update-Counters "OK"
    } else {
        Write-StatusWARN "UAC for users with different configuration"
        Update-Counters "WARN"
    }
} catch {
    Write-StatusWARN "Error checking UAC configurations"
    Update-Counters "WARN"
}

# -- VERIFY AUDITING --
Write-SectionHeader "7. AUDITING VERIFICATION"

try {
    $auditCategories = @(
        "Logon",
        "Logoff", 
        "Account Lockout",
        "User Account Management",
        "Process Creation",
        "System"
    )

    foreach ($category in $auditCategories) {
        $auditResult = cmd /c "auditpol /get /subcategory:`"$category`"" 2>&1
        
        if ($auditResult -like "*Success and Failure*" -or $auditResult -like "*Success*") {
            Write-StatusOK "Auditing $category is enabled"
            Update-Counters "OK"
        } elseif ($auditResult -like "*No Auditing*") {
            Write-StatusFAIL "Auditing $category is NOT enabled"
            Update-Counters "FAIL"
        } else {
            Write-StatusWARN "Auditing $category status undetermined"
            Update-Counters "WARN"
        }
    }
} catch {
    Write-StatusWARN "Error checking auditing configurations"
    Update-Counters "WARN"
}

# -- VERIFY WINDOWS DEFENDER --
Write-SectionHeader "8. WINDOWS DEFENDER VERIFICATION"

try {
    if (Get-Command "Get-MpPreference" -ErrorAction SilentlyContinue) {
        $defenderPrefs = Get-MpPreference
        
        if (-not $defenderPrefs.DisableRealtimeMonitoring) {
            Write-StatusOK "Windows Defender - Real-time protection: ENABLED"
            Update-Counters "OK"
        } else {
            Write-StatusFAIL "Windows Defender - Real-time protection: DISABLED"
            Update-Counters "FAIL"
        }

        if ($defenderPrefs.MAPSReporting -eq 2) {
            Write-StatusOK "Windows Defender - MAPS reporting: Advanced"
            Update-Counters "OK"
        } else {
            Write-StatusWARN "Windows Defender - MAPS reporting not configured"
            Update-Counters "WARN"
        }

        if ($defenderPrefs.SubmitSamplesConsent -eq 1) {
            Write-StatusOK "Windows Defender - Sample submission: Enabled"
            Update-Counters "OK"
        } else {
            Write-StatusWARN "Windows Defender - Sample submission not configured"
            Update-Counters "WARN"
        }

        # Check general Defender status
        $defenderStatus = Get-MpComputerStatus
        if ($defenderStatus.AntivirusEnabled) {
            Write-StatusOK "Windows Defender - Antivirus: ENABLED"
            Update-Counters "OK"
        } else {
            Write-StatusFAIL "Windows Defender - Antivirus: DISABLED"
            Update-Counters "FAIL"
        }

    } else {
        Write-StatusWARN "Windows Defender is not available or was removed"
        Update-Counters "WARN"
    }
} catch {
    Write-StatusWARN "Error checking Windows Defender"
    Update-Counters "WARN"
}

# -- VERIFY ADDITIONAL CONFIGURATIONS --
Write-SectionHeader "9. ADDITIONAL CONFIGURATIONS VERIFICATION"

try {
    # Check inactivity timeout
    $inactivityTimeout = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue
    if ($inactivityTimeout -and $inactivityTimeout.InactivityTimeoutSecs -le 900) {
        Write-StatusOK "Inactivity timeout configured: $($inactivityTimeout.InactivityTimeoutSecs) seconds"
        Update-Counters "OK"
    } else {
        Write-StatusWARN "Inactivity timeout not configured or too high"
        Update-Counters "WARN"
    }

    # Check AutoRun disabled
    $autoRun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    if ($autoRun -and $autoRun.NoDriveTypeAutoRun -eq 0xFF) {
        Write-StatusOK "AutoRun disabled for all drives"
        Update-Counters "OK"
    } else {
        Write-StatusFAIL "AutoRun is NOT disabled"
        Update-Counters "FAIL"
    }

    # Check Windows Script Host
    $scriptHost = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
    if ($scriptHost -and $scriptHost.Enabled -eq 0) {
        Write-StatusOK "Windows Script Host disabled"
        Update-Counters "OK"
    } else {
        Write-StatusWARN "Windows Script Host was not disabled"
        Update-Counters "WARN"
    }

} catch {
    Write-StatusWARN "Error checking additional configurations"
    Update-Counters "WARN"
}

# -- VERIFY EXECUTION POLICY --
Write-SectionHeader "10. POWERSHELL EXECUTION POLICY VERIFICATION"

try {
    $execPolicy = Get-ExecutionPolicy -Scope LocalMachine
    if ($execPolicy -eq "RemoteSigned" -or $execPolicy -eq "AllSigned") {
        Write-StatusOK "PowerShell Execution Policy: $execPolicy"
        Update-Counters "OK"
    } else {
        Write-StatusWARN "PowerShell Execution Policy: $execPolicy (may be insecure)"
        Update-Counters "WARN"
    }
} catch {
    Write-StatusWARN "Error checking Execution Policy"
    Update-Counters "WARN"
}

# -- FINAL VERIFICATION REPORT --
Write-SectionHeader "FINAL VERIFICATION REPORT"

Write-StatusINFO "Completion Date/Time: $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
Write-StatusINFO "Total verifications: $totalChecks"
Write-StatusOK "Passed verifications: $passedChecks"
Write-StatusWARN "Warning verifications: $warningChecks"
Write-StatusFAIL "Failed verifications: $failedChecks"

$successRate = [math]::Round(($passedChecks / $totalChecks) * 100, 1)
Write-StatusINFO "Success rate: $successRate%"

Write-Host ""
if ($failedChecks -eq 0) {
    Write-StatusOK "CONGRATULATIONS! All essential security configurations are applied!"
} elseif ($failedChecks -le 3) {
    Write-StatusWARN "Security configurations in good shape, but some improvements are needed."
} else {
    Write-StatusFAIL "ATTENTION! Several security configurations need to be corrected!"
}

Write-Host ""
Write-StatusINFO "For more details about failed configurations, run the hardening script again."
Write-StatusINFO "Verification completed!"

# Generate log file (optional)
$logChoice = Read-Host "Do you want to save this report to a file? (Y/N)"
if ($logChoice -eq "Y" -or $logChoice -eq "y") {
    $logPath = "$env:USERPROFILE\Desktop\Security_Check_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    Start-Transcript -Path $logPath -Append
    Write-Host "Report saved to: $logPath"
    Stop-Transcript
}
