
<#
.SYNOPSIS
    Testing Suite for Windows Decisive Hardening
.DESCRIPTION
    Validates if the hardening script successfully applied all security configurations.
    Must be run via Invoke-Pester:
    Invoke-Pester -Path .\hardening-win10.tests.ps1
#>

$ErrorActionPreference = "SilentlyContinue"

Describe "Windows 10 Hardening Tests" {
    
    Context "1. Services" {
        It "Should disable vulnerable/telemetry services" {
            $svcs = @("RemoteRegistry", "Fax", "XblGameSave", "DiagTrack", "XboxNetApiSvc", "MapsBroker", "WerSvc")
            foreach ($s in $svcs) { 
                $svc = Get-Service $s -ErrorAction SilentlyContinue
                if ($null -ne $svc) {
                    $svc.StartType | Should Be 'Disabled'
                }
            }
        }
    }

    Context "2. SMBv1 Protocol" {
        It "Should have SMB1Protocol feature disabled" {
            $feature = (Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue).State
            if ($null -ne $feature) {
                $feature | Should Be 'Disabled'
            }
        }

        It "Should have SMB1 blocked in Registry" {
            $reg = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue).SMB1
            $reg | Should Be 0
        }
    }

    Context "3. Windows Update Control" {
        It "Should notify for updates (Prevent Auto-Reboot) - AUOptions=2" {
            $val = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue).AUOptions
            $val | Should Be 2
        }
        It "Should have NoAutoRebootWithLoggedOnUsers=1" {
            $val = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue).NoAutoRebootWithLoggedOnUsers
            $val | Should Be 1
        }
    }

    Context "4. Password Policy" {
        It "Should enforce minimum 12 characters and complexity" {
            $tempFile = "$env:TEMP\secpol_test_eval.cfg"
            secedit /export /cfg "$tempFile" /quiet
            $content = Get-Content $tempFile -ErrorAction SilentlyContinue
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

            $hasContent = [string]::IsNullOrEmpty($content) -eq $false
            $hasContent | Should Be $true

            $minLen = 0
            $complexity = 0

            if ($content) {
                $matchLen = ($content | Select-String "MinimumPasswordLength\s*=\s*(\d+)").Matches.Groups[1].Value
                $matchComp = ($content | Select-String "PasswordComplexity\s*=\s*(\d+)").Matches.Groups[1].Value
                if ($null -ne $matchLen) { $minLen = [int]$matchLen }
                if ($null -ne $matchComp) { $complexity = [int]$matchComp }
            }

            ($minLen -ge 12) | Should Be $true
            $complexity | Should Be 1
        }
    }

    Context "5. Firewall Profiles" {
        It "Should have Domain, Private, and Public profiles enabled" {
            $profiles = Get-NetFirewallProfile -Profile Domain,Private,Public | Where-Object {$_.Enabled -eq 'True'}
            $profiles.Count | Should Be 3
        }
    }

    Context "6. Windows Script Host" {
        It "Should block WSH execution (.VBS/.JS)" {
            $wsh = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -ErrorAction SilentlyContinue).Enabled
            $wsh | Should Be 0
        }
    }

    Context "7. UAC" {
        It "Should set ConsentPromptBehaviorAdmin to 2 (Prompt for consent on the secure desktop)" {
            $uac = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
            $uac | Should Be 2
        }
    }

    Context "8. Secure DNS" {
        It "Should use Cloudflare DNS (1.1.1.1)" {
            $dns = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
            $containsDNS = $dns -contains "1.1.1.1"
            $containsDNS | Should Be $true
        }
    }

    Context "9. Exploit Protection" {
        It "Should enable DEP and BottomUp ASLR" {
            $m = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
            if ($null -ne $m) {
                ($m.Dep.Enable -ne 0) | Should Be $true
                ($m.BottomUpAslr.Enable -ne 0) | Should Be $true
            }
        }
    }

    Context "10. File Extensions" {
        It "Should show hidden file extensions" {
            $ext = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction SilentlyContinue).HideFileExt
            $ext | Should Be 0
        }
    }

    Context "11. PowerShell Logging" {
        It "Should enable ScriptBlockLogging" {
            $sb = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
            $sb | Should Be 1
        }
        It "Should enable ModuleLogging" {
            $ml = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging
            $ml | Should Be 1
        }
        It "Should enforce ModuleNames=*" {
            $mo = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ErrorAction SilentlyContinue)."*"
            $mo | Should Be "1"
        }
    }

    Context "12. Telemetry" {
        It "Should block OS Telemetry" {
            $tel = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorAction SilentlyContinue).AllowTelemetry
            $tel | Should Be 0
        }
    }

    Context "13. AutoRun / AutoPlay" {
        It "Should disable AutoRun on HKLM and HKCU" {
            $val1 = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
            $val2 = (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
            $val1 | Should Be 255
            $val2 | Should Be 255
        }
        It "Should disable AutoPlay in Explorer Handlers" {
            $val3 = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -ErrorAction SilentlyContinue).DisableAutoplay
            $val3 | Should Be 1
        }
    }
}
