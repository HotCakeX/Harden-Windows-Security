
<#PSScriptInfo

.VERSION 2022.12.9

.GUID d435a293-c9ee-4217-8dc1-4ad2318a5770

.AUTHOR HotCakeX

.COMPANYNAME HotCakeX Corp.

.COPYRIGHT N\A

.TAGS Windows Hardening Security Bitlocker Windows Defender Firewall

.LICENSEURI 

.PROJECTURI https://github.com/HotCakeX/Harden-Windows-Security

.ICONURI https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/ICONURI%20.jpg

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
Version 2022.12.8: Improved the script
Version 2022.12.9: Configured LSASS process to run as a protected process with UEFI Lock

#>

<# 

.SYNOPSIS
    Harden Windows 11 Safely and Securely without breaking anything or causing problems

.DESCRIPTION
Harden Windows 11 Safely, securely and without breaking anything 🔐
This is suitable for tech-savvy and non-tech-savvy users and it is recommended to be run and applied to every Windows system.

Above each command there are comments (lines starting with # or <# are comments in PowerShell) that explain what it does and I provided links to additional resources where necessary to help understand it better.

This script will be kept up-to-date. always tested on latest available version of Windows (stable and insider builds). so make sure you always download and use the latest version of it.

This script should be run for each user individually to be effective. admins should run it with Administrator privileges and standard users run it with standard privileges, in PowerShell.

This script can be run infinite number of times without causing any problem, it does not make any duplicate modification.

Things with #TopSecurity tag can break functionalities or cause difficulties so this script does NOT enable them by default. press Control + F and search for #TopSecurity in the script to find those commands and how to enable them if you want.

When the script is running for the first time, please keep an eye on the PowerShell console because you might need to provide input for Bitlocker activation etc.

This script is available and mirrored on both PowerShell Gallery and GitHub

https://www.powershellgallery.com/packages/Harden-Windows-Security/

https://github.com/HotCakeX/Harden-Windows-Security

🎯 if you have any questions, requests, suggestions etc. about this script, please open a new discussion in Github:

https://github.com/HotCakeX/Harden-Windows-Security/discussions

.EXAMPLE

  
   type: "Set-ExecutionPolicy bypass" without quotes, in an Elevated PowerShell, to allow running this script.
   
.NOTES
    When the script is running as Admin, please keep an eye on the PowerShell console because you might need to provide input for Bitlocker activation if it's not already set up with Startup-key key protector.

#>



Function Test-IsAdmin

{

  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()

 $principal = New-Object Security.Principal.WindowsPrincipal $identity

 $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

}

 
if(-NOT (Test-IsAdmin))

   { write-host "Skipping Admin commands" -ForegroundColor Magenta }

else {
  
Set-MpPreference -DisableRemovableDriveScanning 0
<# Specifies whether to enable file hash computation. When this feature is enabled, Windows Defender computes hashes for files it scans.
 In Windows 10 2004, Microsoft Defender Antivirus provides a new setting known as 'Enable file hash computation feature'
 designed to allow admins to force the anti-malware solution to "compute file hashes for every executable file that is scanned
 if it wasn't previously computed" to "improve blocking for custom indicators in Microsoft Defender Advanced Threat Protection (Microsoft Defender ATP). #>
Set-MpPreference -efhc 1 
# good source of info: https://answers.microsoft.com/en-us/protect/forum/all/windows-defender/e23367ac-e99c-48f5-8b11-68a3fa0abff7
# increases level of Cloud Protection
Set-MpPreference -CloudBlockLevel ZeroTolerance
# This increases the allotted analysis time:
Set-MpPreference -CloudExtendedTimeout 50
<# Indicates whether Windows Defender runs catch-up scans for scheduled quick scans. 
 A computer can miss a scheduled scan, usually because the computer is off at the scheduled time. 
 If you specify a value of $False, after the computer misses two scheduled quick scans,
 Windows Defender runs a catch-up scan the next time someone logs onto the computer.
 If you specify a value of $True, the computer does not run catch-up scans for scheduled quick scans. #>
Set-MpPreference -DisableCatchupQuickScan $False
<# Indicates whether to check for new virus and spyware definitions before Windows Defender runs a scan. 
 If you specify a value of $True, Windows Defender checks for new definitions. 
 If you specify $False or don't specify a value, the scan begins with existing definitions. 
 This value applies to scheduled scans and to scans that you start from the command line, 
 but it doesn't affect scans that you start from the user interface. #>
Set-MpPreference -CheckForSignaturesBeforeRunningScan 1
<# Specifies the interval, in hours, at which to check for definition updates. 
 The acceptable values for this parameter are: integers from 1 through 24. 
 If you do not specify a value for this parameter, Windows Defender checks at the default interval. 
 You can use this parameter instead of the SignatureScheduleDay parameter and SignatureScheduleTime parameter. #>
Set-MpPreference -SignatureUpdateInterval 2
<# Indicates whether Windows Defender parses the mailbox and mail files, according to their specific format, 
 in order to analyze mail bodies and attachments. Windows Defender supports several formats, 
 including .pst, .dbx, .mbx, .mime, and .binhex. If you specify a value of $False or do not specify a value, 
 Windows Defender performs email scanning. If you specify a value of $True, Windows Defender does not perform email scanning. #>
Set-MpPreference -DisableEmailScanning $false
# Indicates whether to disable scanning of restore points. If you specify a value of $False or do not specify a value, Windows Defender restore point is enabled.
Set-MpPreference -DisableRestorePoint $false
# Specifies how the network protection service handles web-based malicious threats, including phishing and malware. Possible values are Disabled, Enabled, and AuditMode.
Set-MpPreference -EnableNetworkProtection enabled
# Specifies the number of days to keep items in the Quarantine folder. If you specify a value of zero or do not specify a value for this parameter, items stay in the Quarantine folder indefinitely.
Set-MpPreference -QuarantinePurgeItemsAfterDelay 5
# Disable CPU THrottling for Windows Defender Scans; Specifies the maximum percentage CPU usage for a scan. 
# The acceptable values for this parameter are: integers from 5 through 100, and the value 0, which disables CPU throttling.
# Windows Defender does not exceed the percentage of CPU usage that you specify. The default value is 50.
Set-MpPreference -ScanAvgCPULoadFactor 70
# Specifies how Windows Defender checks for user consent for certain samples. 3: Send all samples automatically
Set-MpPreference -SubmitSamplesConsent 3
# Indicates whether to scan mapped network drives. If you specify a value of $False or do not specify a value, Windows Defender scans mapped network drives. If you specify a value of $True, Windows Defender does not scan mapped network drives.
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $false
# Specifies whether to update managed devices to update through metered connections. Data charges may apply.
Set-MpPreference -MeteredConnectionUpdates $true
# Specifies the type of membership in Microsoft Active Protection Service. Highest: 2: Advanced membership.
Set-MpPreference -MAPSReporting 2



# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


# ASR Rules, All 16 available rules are set to Enabled which means Block.
# Block abuse of exploited vulnerable signed drivers
Set-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
# Block Adobe Reader from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
# Block all Office applications from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Enabled
# Block credential stealing from the Windows local security authority subsystem (lsass.exe)
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
# Block executable content from email client and webmail
Add-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions Enabled
# Block executable files from running unless they meet a prevalence, age, or trusted list criterion #TopSecurity set to AuditMode 
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions AuditMode
# Block execution of potentially obfuscated scripts
Add-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions Enabled
# Block JavaScript or VBScript from launching downloaded executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions Enabled
# Block Office applications from creating executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions Enabled
# Block Office applications from injecting code into other processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions Enabled
# Block Office communication application from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
# Block persistence through WMI event subscription * File and folder exclusions not supported.
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
# Block process creations originating from PSExec and WMI commands
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled
# Block untrusted and unsigned processes that run from USB
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
# Block Win32 API calls from Office macros
Add-MpPreference -AttackSurfaceReductionRules_Ids 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b -AttackSurfaceReductionRules_Actions Enabled
# Use advanced protection against ransomware
Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled
#
# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#
# Enable early launch antimalware driver for scanning of boot-start drivers
# 3 is the default which allows good, unknown and 'bad but critical'.
# 1 is for 'good and unknown' , 8 is for 'good only', used in this command
# https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220813
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
$Name         = 'DriverLoadPolicy'
$Value        = '8'
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null }
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force



# disable NetBIOS over TCP/IP on all network interfaces, virtual and physical . need to run it every time after installing new VPN software or network adapaters, virtual or physical.
# https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-netbt-interfaces-interface-netbiosoptions

$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |ForEach-Object { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 }

# disable the LLMNR protocol on a Windows
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient  -Force
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value 0 -PropertyType DWORD  -Force


# disable LMHOSTS lookup protocol on all network adapters
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 
$Name         = 'EnableLMHOSTS' 
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 




} #end of the 1st Admin test function



# Show known file extensions
$RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'  
$Name         = 'HideFileExt'  
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force





# Show hidden files, folders and drives (toggles the control panel folder options item)
$RegistryPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'  
$Name         = 'Hidden'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force





# Disable websites accessing local language list
$RegistryPath = 'HKCU:\Control Panel\International\User Profile'  
$Name         = 'HttpAcceptLanguageOptOut'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force





# turn off safe search in Windows search. from Windows settings > privacy and security > search permissions > safe search
$RegistryPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings'
$Name         = 'SafeSearchMode'
$Value        = '0'
If (-NOT (Test-Path $RegistryPath)) {  New-Item -Path $RegistryPath -Force | Out-Null} 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force





if(-NOT (Test-IsAdmin))

   { write-host "Skipping Admin commands" -ForegroundColor Magenta }

else {






# Disable Location services from Windows - affects Windows settings privacy section
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'  
$Name         = 'DisableLocation'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force





# Enable Hibernate
powercfg /hibernate on

# Set Hibnernate mode to full
powercfg /h /type full

# Add Hibernate option to Start menu's power options
$RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
$Name         = 'ShowHibernateOption'
$Value        = '1'
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null
}
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force


<# Disable Sleep (Power states S1-S3) - doing this also removes the Sleep option from Start menu and even using commands to put the computer to sleep won't work.
 https://learn.microsoft.com/en-us/windows/win32/power/system-power-states#sleep-state-s1-s3
 also is suggested to disable it for Bitlocker protection at the bottom of this page: 
 https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures#attacker-with-skill-and-lengthy-physical-access
 2 registry keys are required for disabling Sleep.
 the registry keys location: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.PowerManagement::AllowStandbyStatesDC_2
 computer restart is required for the changes to take effect
#>


# Disable sleep for when plugged in
$RegistryPath = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
$Name         = 'ACSettingIndex'
$Value        = '0'
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null
}
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force


# Disable sleep for when on battery
$RegistryPath = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
$Name         = 'DCSettingIndex'
$Value        = '0'
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null
}
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force







<#
 BitLocker software will bring you a real security against the theft of your computer if you strictly abide by the following basic rule:
 As soon as you have finished working, completly shut Windows down and allow for every shadow of information to disappear
 (from RAM, disk caches) within 2 minutes.
#>

# Bitlocker Drive Encryption settings: setting the encryption algorithm and cipher options
# https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures

# Set OS drive Encryption algorithm and Cipher | XTS-AES 256-bit
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 
$Name         = 'EncryptionMethodWithXtsOs' 
$Value        = '7' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 

# Set Fixed drive Encryption algorithm and Cipher | XTS-AES 256-bit
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 
$Name         = 'EncryptionMethodWithXtsFdv' 
$Value        = '7' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 

# Set removable drives data Encryption algorithm and Cipher | XTS-AES 256-bit
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
$Name         = 'EncryptionMethodWithXtsRdv'
$Value        = '7' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 

# Bitlocker: Allow Enhanced PINs for startup 
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 
$Name         = 'UseEnhancedPin' 
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force

# Enforce drive encryption type on operating system drives: full drive encryption
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 
$Name         = 'OSEncryptionType' 
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}  
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force

# Bitlocker: use Advanced Startup - Require additional authentication at startup
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 
$Name         = 'UseAdvancedStartup' 
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force

# Bitlocker: Don't allow Bitlocker with no TPM
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 
$Name         = 'EnableBDEWithNoTPM'
$Value        = '0'
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 

# Bitlocker: Allow/Use startup key with TPM
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 
$Name         = 'UseTPMKey' 
$Value        = '2' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 

# Bitlocker: Allow/Use startup PIN with TPM
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 
$Name         = 'UseTPMPIN' 
$Value        = '2' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 

# Bitlocker: Allow/Use startup key and PIN with TPM
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 
$Name         = 'UseTPMKeyPIN' 
$Value        = '2' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 

# Bitlocker: Allow/Use TPM
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 
$Name         = 'UseTPM' 
$Value        = '2' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 






<#
 Enable Mandatory ASLR, there are more options in this official chart:
https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-exploit-protection?view=o365-worldwide
You can add a (Mandatory ASLR) override for any program you trust (usually portable programs have problems) using the command below or in the Program Settings section of Exploit Protection in Windows Defender app. 
#> 
set-processmitigation -System -Enable ForceRelocateImages


# Set your trusted program to be exempt from Mandatory ASLR
# Set-ProcessMitigation -Name "D:\program.exe" -Disable ForceRelocateImages


# Set the Network Location of all connections to Public
 Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Public






# UAC Hardening: https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#registry-key-settings
# These 3 changes harden UAC and also set its slider in control panel to highest level, but go beyond that too and harden even more.
# setting it to 1 asks for Admin credentials, setting it to 2 asks for Accept/Deny for Admin tasks in Admin account.
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 
$Name         = 'ConsentPromptBehaviorAdmin' 
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 

# Next one - this automatically denies all UAC prompts on Standard accounts when set to "0". good for forcing log out of Standard account and logging in Admin account to perform actions. 1 = Prompt for credentials on the secure desktop #topSecurity
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 
$Name         = 'ConsentPromptBehaviorUser' 
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 

# Last one, Enforce cryptographic signatures on any interactive application that requests elevation of privilege.
# it can prevent certain programs from running
# I set it to 0, only set it to 1 for #TopSecurity
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 
$Name         = 'ValidateAdminCodeSignatures' 
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) { 
  New-Item -Path $RegistryPath -Force | Out-Null 
}   
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force








# Lock Screen Hardening
# Automatically lock computer after X seconds, set to 120 seconds in this command.
# https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$Name         = 'InactivityTimeoutSecs'
$Value        = '120'
If (-NOT (Test-Path $RegistryPath)) {  New-Item -Path $RegistryPath -Force | Out-Null} 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 
# https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-do-not-require-ctrl-alt-del
# forces CAD requirement, CTRL + ALT + DELETE at Windows Lock screen to be pressed to show sign in fields
# Interactive logon: Do not require CTRL+ALT+DEL - when set to '0', CAD is required
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$Name         = 'DisableCAD'
$Value        = '0'
If (-NOT (Test-Path $RegistryPath)) {  New-Item -Path $RegistryPath -Force | Out-Null} 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 
# https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-account-lockout-threshold
# The security setting allows you to set a threshold for the number of failed sign-in attempts that causes the device to be locked by using BitLocker.
# This threshold means, if the specified maximum number of failed sign-in attempts is exceeded,
# the device will invalidate the Trusted Platform Module (TPM) protector and any other protector
# except the 48-digit recovery password, and then reboot. During Device Lockout mode,
# the computer or device only boots into the touch-enabled Windows Recovery Environment (WinRE) until an authorized user enters the recovery password to restore full access.
# it can provide security against brute force methods
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$Name         = 'MaxDevicePasswordFailedAttempts'
$Value        = '30'
If (-NOT (Test-Path $RegistryPath)) {  New-Item -Path $RegistryPath -Force | Out-Null} 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 
# https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-display-user-information-when-the-session-is-locked
# https://www.itsecdb.com/oval/definition/oval/gov.nist.3/def/5002/Interactive-logon-Display-user-information-when-the-session.html
# hides email address of the Microsoft account on lock screen
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$Name         = 'DontDisplayLockedUserId'
$Value        = '3'
If (-NOT (Test-Path $RegistryPath)) {  New-Item -Path $RegistryPath -Force | Out-Null} 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 
# If the policy is enabled and a user signs in as Other user, the full name of the user is not displayed during sign-in.
# In the same context, if users type their email address and password at the sign in screen and press Enter,
# the displayed text "Other user" remains unchanged, and is no longer replaced by the user’s first and last name
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$Name         = 'DontDisplayUserName'
$Value        = '1'
If (-NOT (Test-Path $RegistryPath)) {  New-Item -Path $RegistryPath -Force | Out-Null} 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force 
# https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-do-not-display-last-user-name
# Don't display last signed-in: this will stop showing Any info about Windows accounts; users need to manually enter username and password/Pin to sign in #TopSecurity causes annoyance - Disabled here - to enable it, change it to 1
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'  
$Name         = 'dontdisplaylastusername'  
$Value        = '0'
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




} #end of the 2nd Admin test function





# prevent showing notifications in Lock screen - this is the same as toggling the button in Windows settings > system > notifications > show notifications in the lock screen
$RegistryPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings'  
$Name         = 'NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK'  
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force

# prevent showing notifications in Lock screen, 2nd reg key - this is the same as toggling the button in Windows settings > system > notifications > show notifications in the lock screen
$RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications'  
$Name         = 'LockScreenToastEnabled'  
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force







if(-NOT (Test-IsAdmin))

   { write-host "Skipping Admin commands" -ForegroundColor Magenta }

else {



# Don't show network (like WiFi) icon on lock screen
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'  
$Name         = 'DontDisplayNetworkSelectionUI'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force





# Enable svchost.exe mitigation options - more info: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-servicecontrolmanager
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SCMConfig'  
$Name         = 'EnableSvchostMitigationPolicy'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force





# Set Power Plan to "Ultimate Performance". replace it with "High Performance" if wanted.
$p = Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -Filter "ElementName = 'Ultimate Performance'"      
powercfg /setactive ([string]$p.InstanceID).Replace("Microsoft:PowerPlan\{","").Replace("}","")






# Turn on Enhanced mode search for Windows indexer. the default is classic mode.
# this causes some UI elements in the search settings in Windows settings to become unavailable for Standard users to view.
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows Search'  
$Name         = 'EnableFindMyFiles'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




} #end of the 3rd Admin test function




# Enable Clipboard History for the current user
$RegistryPath = 'HKCU:\Software\Microsoft\Clipboard'  
$Name         = 'EnableClipboardHistory'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force
# 2 commands to enable sync of Clipboard history in Windows between devices
$RegistryPath = 'HKCU:\Software\Microsoft\Clipboard'
$Name         = 'CloudClipboardAutomaticUpload'
$Value        = '1'
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null }
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force
# last one, to enable Clipboard sync
$RegistryPath = 'HKCU:\Software\Microsoft\Clipboard'
$Name         = 'EnableCloudClipboard'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force







if(-NOT (Test-IsAdmin))

   { write-host "Skipping Admin commands" -ForegroundColor Magenta }

else {




<# \\\\\\\\\\\\\\\\\\\\\\\\\Device Guard settings \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
 source: https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity  #>

# To enable VBS
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$Name         = 'EnableVirtualizationBasedSecurity'
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force


# To enable VBS and require Secure boot only (value 1)
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$Name         = 'RequirePlatformSecurityFeatures'
$Value        = '1'
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null }
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force



# To enable VBS with UEFI lock (value 1)
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$Name         = 'Locked'
$Value        = '1'
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null }
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




# To enable virtualization-based protection of Code Integrity policies
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
$Name         = 'Enabled'
$Value        = '1'
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null }
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




# To enable virtualization-based protection of Code Integrity policies with UEFI lock (value 1)
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
$Name         = 'Locked'
$Value        = '1'
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null }
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force


# \\\\\\\\\\\\\\\\\\\\\\\\\ End of Device Guard settings - there are more settings available in Group Policy Device Guard section that these modifications do Not enable, should enable them manually \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\





# this is phishing protection mitigation - affects only people who have Windows Driver Kit installed.

try {
$RegistryPath = 'HKLM:\SOFTWARE\Classes\.devicemetadata-ms'  
  Remove-Item -Path $RegistryPath -Force  -ErrorAction stop
}
catch
{
write-host "phishing mitigation for WDK (Windows Driver Kit) not applicable, it's probably not installed `n" -ForegroundColor Magenta
}

try {
$RegistryPath = 'HKLM:\SOFTWARE\Classes\.devicemanifest-ms'  
  Remove-Item -Path $RegistryPath -Force  -ErrorAction stop
}
catch
{
write-host "phishing mitigation for WDK (Windows Driver Kit) not applicable, it's probably not installed `n" -ForegroundColor Magenta
}




# Enforce the Administrator role for adding printer drivers. This is a frequent exploit attack vector. 
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'  
$Name         = 'AddPrinterDrivers'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force
# Forces Installer NOT to use elevated privileges during installs by default, which prevents escalation of privileges vulnerabilities and attacks
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'  
$Name         = 'AlwaysInstallElevated'  
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force


# Enable SMB/LDAP Signing
# Sources:  http://eddiejackson.net/wp/?p=15812  and https://en.hackndo.com/ntlm-relay/ 
# 1
$RegistryPath = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters'  
$Name         = 'RequireSecuritySignature'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force
# 2
$RegistryPath = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters'  
$Name         = 'EnableSecuritySignature'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force
# 3
$RegistryPath = 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters'  
$Name         = 'RequireSecuritySignature'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force
# 4
$RegistryPath = 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters'  
$Name         = 'EnableSecuritySignature'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force






#######################################################################
# Enable Windows Firewall and configure some advanced options
# Block Win32/64 binaries (LOLBins) from making Internet connections when they shouldn't
# this website also lists them as well: https://lolbas-project.github.io
# THESE COMMANDS CHECK IF THE RULE ALREADY EXISTS BEFORE ADDING THEM TO WINDOWS FIREWALL

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True



function Firewallblock {
    param ($n , $p)


                $r = Get-NetFirewallRule -DisplayName $n 2> $null; 
                if ($r) { 
                write-host "Firewall rule already exists, skipping to the next one" -ForegroundColor Magenta ; 
                } 
                else { 
                New-NetFirewallRule -DisplayName $n -Protocol "TCP" -Program $p -Action Block -Direction Outbound -Profile Any -Enabled True -Group "LOLBins Blocking" 
                }

}
 

# LOLBins-01 Block appvlp.exe netconns
Firewallblock -n "LOLBins-01 Block appvlp.exe netconns" -p "C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe"

# LOLBins-02 Block appvlp.exe netconns
Firewallblock -n  "LOLBins-02 Block appvlp.exe netconns" -p "C:\Program Files\Microsoft Office\root\client\AppVLP.exe"

# LOLBins-03 Block certutil.exe netconns
Firewallblock -n  "LOLBins-03 Block certutil.exe netconns" -p "%systemroot%\system32\certutil.exe"

# LOLBins-04 Block certutil.exe netconns
Firewallblock -n  "LOLBins-04 Block certutil.exe netconns" -p "%systemroot%\SysWOW64\certutil.exe"

# LOLBins-05 Block cmstp.exe netconns
Firewallblock -n  "LOLBins-05 Block cmstp.exe netconns" -p "%systemroot%\system32\cmstp.exe"

# LOLBins-06 Block cmstp.exe netconns
Firewallblock -n  "LOLBins-06 Block cmstp.exe netconns" -p "%systemroot%\SysWOW64\cmstp.exe"

# LOLBins-07 Block cscript.exe netconns
Firewallblock -n  "LOLBins-07 Block cscript.exe netconns" -p "%systemroot%\system32\cscript.exe"

# LOLBins-08 Block cscript.exe netconns
Firewallblock -n  "LOLBins-08 Block cscript.exe netconns" -p "%systemroot%\SysWOW64\cscript.exe"

# LOLBins-09 Block esentutl.exe netconns
Firewallblock -n  "LOLBins-09 Block esentutl.exe netconns" -p "%systemroot%\system32\esentutl.exe"

# LOLBins-10 Block esentutl.exe netconns
Firewallblock -n  "LOLBins-10 Block esentutl.exe netconns" -p "%systemroot%\SysWOW64\esentutl.exe"

# LOLBins-11 Block expand.exe netconns
Firewallblock -n  "LOLBins-11 Block expand.exe netconns" -p "%systemroot%\system32\expand.exe"

# LOLBins-12 Block expand.exe netconns
Firewallblock -n  "LOLBins-12 Block expand.exe netconns" -p "%systemroot%\SysWOW64\expand.exe"

# LOLBins-13 Block extrac32.exe netconns
Firewallblock -n  "LOLBins-13 Block extrac32.exe netconns" -p "%systemroot%\system32\extrac32.exe"

# LOLBins-14 Block extrac32.exe netconns
Firewallblock -n  "LOLBins-14 Block extrac32.exe netconns" -p "%systemroot%\SysWOW64\extrac32.exe"

# LOLBins-15 Block findstr.exe netconns
Firewallblock -n  "LOLBins-15 Block findstr.exe netconns" -p "%systemroot%\system32\findstr.exe"

# LOLBins-16 Block findstr.exe netconns
Firewallblock -n  "LOLBins-16 Block findstr.exe netconns" -p "%systemroot%\SysWOW64\findstr.exe"

# LOLBins-17 hh.exe netconns
Firewallblock -n  "LOLBins-17 hh.exe netconns" -p "%systemroot%\system32\hh.exe"

# LOLBins-18 hh.exe netconns
Firewallblock -n  "LOLBins-18 hh.exe netconns" -p "%systemroot%\SysWOW64\hh.exe"

# LOLBins-19 Block makecab.exe netconns
Firewallblock -n  "LOLBins-19 Block makecab.exe netconns" -p "%systemroot%\system32\makecab.exe"

# LOLBins-20 Block makecab.exe netconns
Firewallblock -n  "LOLBins-20 Block makecab.exe netconns" -p "%systemroot%\SysWOW64\makecab.exe"

# LOLBins-21 mshta.exe netconns
Firewallblock -n  "LOLBins-21 mshta.exe netconns" -p "%systemroot%\system32\mshta.exe"

# LOLBins-22 mshta.exe netconns
Firewallblock -n  "LOLBins-22 mshta.exe netconns" -p "%systemroot%\SysWOW64\mshta.exe"

# LOLBins-23 Block msiexec.exe netconns
Firewallblock -n  "LOLBins-23 Block msiexec.exe netconns" -p "%systemroot%\system32\msiexec.exe"

# LOLBins-24 Block msiexec.exe netconns
Firewallblock -n  "LOLBins-24 Block msiexec.exe netconns" -p "%systemroot%\SysWOW64\msiexec.exe"

# LOLBins-25 Block nltest.exe netconns
Firewallblock -n  "LOLBins-25 Block nltest.exe netconns" -p "%systemroot%\system32\nltest.exe"

# LOLBins-26 Block nltest.exe netconns
Firewallblock -n  "LOLBins-26 Block nltest.exe netconns" -p "%systemroot%\SysWOW64\nltest.exe"

# LOLBins-27 Block Notepad.exe netconns
Firewallblock -n  "LOLBins-27 Block Notepad.exe netconns" -p "%systemroot%\system32\notepad.exe"

# LOLBins-28 Block Notepad.exe netconns
Firewallblock -n  "LOLBins-28 Block Notepad.exe netconns" -p "%systemroot%\SysWOW64\notepad.exe"

# LOLBins-29 Block odbcconf.exe netconns
Firewallblock -n  "LOLBins-29 Block odbcconf.exe netconns" -p "%systemroot%\system32\odbcconf.exe"

# LOLBins-30 Block odbcconf.exe netconns
Firewallblock -n  "LOLBins-30 Block odbcconf.exe netconns" -p "%systemroot%\SysWOW64\odbcconf.exe"

# LOLBins-31 Block pcalua.exe netconns
Firewallblock -n  "LOLBins-31 Block pcalua.exe netconns" -p "%systemroot%\system32\pcalua.exe"

# LOLBins-32 Block pcalua.exe netconns
Firewallblock -n  "LOLBins-32 Block pcalua.exe netconns" -p "%systemroot%\SysWOW64\pcalua.exe"

# LOLBins-33 Block regasm.exe netconns
Firewallblock -n  "LOLBins-33 Block regasm.exe netconns" -p "%systemroot%\system32\regasm.exe"

# LOLBins-34 Block regasm.exe netconns
Firewallblock -n  "LOLBins-34 Block regasm.exe netconns" -p "%systemroot%\SysWOW64\regasm.exe"

# LOLBins-35 lock regsvr32.exe netconns
Firewallblock -n  "LOLBins-35 lock regsvr32.exe netconns" -p "%systemroot%\system32\regsvr32.exe"

# LOLBins-36 lock regsvr32.exe netconns
Firewallblock -n  "LOLBins-36 lock regsvr32.exe netconns" -p "%systemroot%\SysWOW64\regsvr32.exe"

# LOLBins-37 Block replace.exe netconns
Firewallblock -n  "LOLBins-37 Block replace.exe netconns" -p "%systemroot%\system32\replace.exe"

# LOLBins-38 Block replace.exe netconns
Firewallblock -n  "LOLBins-38 Block replace.exe netconns" -p "%systemroot%\SysWOW64\replace.exe"

# LOLBins-39 Block rpcping.exe netconns
Firewallblock -n  "LOLBins-39 Block rpcping.exe netconns" -p "%systemroot%\SysWOW64\rpcping.exe"

# LOLBins-40 Block rundll32.exe netconns
Firewallblock -n  "LOLBins-40 Block rundll32.exe netconns" -p "%systemroot%\system32\rundll32.exe"

# LOLBins-41 Block rundll32.exe netconns
Firewallblock -n  "LOLBins-41 Block rundll32.exe netconns" -p "%systemroot%\SysWOW64\rundll32.exe"

# LOLBins-42 Block runscripthelper.exe netconns
Firewallblock -n  "LOLBins-42 Block runscripthelper.exe netconns" -p "%systemroot%\system32\runscripthelper.exe"

# LOLBins-43 Block runscripthelper.exe netconns
Firewallblock -n  "LOLBins-43 Block runscripthelper.exe netconns" -p "%systemroot%\SysWOW64\runscripthelper.exe"

# LOLBins-44 Block scriptrunner.exe netconns
Firewallblock -n  "LOLBins-44 Block scriptrunner.exe netconns" -p "%systemroot%\system32\scriptrunner.exe"

# LOLBins-45 Block scriptrunner.exe netconns
Firewallblock -n  "LOLBins-45 Block scriptrunner.exe netconns" -p "%systemroot%\SysWOW64\scriptrunner.exe"

# LOLBins-46 Block SyncAppvPublishingServer.exe netconns
Firewallblock -n  "LOLBins-46 Block SyncAppvPublishingServer.exe netconns" -p "%systemroot%\system32\SyncAppvPublishingServer.exe"

# LOLBins-47 Block SyncAppvPublishingServer.exe netconns
Firewallblock -n  "LOLBins-47 Block SyncAppvPublishingServer.exe netconns" -p "%systemroot%\SysWOW64\SyncAppvPublishingServer.exe"

# LOLBins-48 Block wmic.exe netconns
Firewallblock -n  "LOLBins-48 Block wmic.exe netconns" -p "%systemroot%\system32\wbem\wmic.exe"

# LOLBins-49 Block wmic.exe netconns
Firewallblock -n  "LOLBins-49 Block wmic.exe netconns" -p "%systemroot%\SysWOW64\wbem\wmic.exe"

# LOLBins-50 Block wscript.exe netconns
Firewallblock -n  "LOLBins-50 Block wscript.exe netconns" -p "%systemroot%\system32\wscript.exe"

# LOLBins-51 Block wscript.exe netconns
Firewallblock -n  "LOLBins-51 Block wscript.exe netconns" -p "%systemroot%\SysWOW64\wscript.exe"




<#
 Disable "Use my sign in info to automatically finish setting up after an update".
 when this option is enabled (default value), and the everyday account is Standard, it causes the other admin account to be 
 automatically signed into and in the lock screen when logging into Standard account, you have to double sign in, asks twice for the Windows Pin.
#>

$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'  
$Name         = 'DisableAutomaticRestartSignOn'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force

# Set Microsoft Edge to update over Metered connections - toggles the button in edge://settings/help
$RegistryPath = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientStateMedium\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'  
$Name         = 'allowautoupdatesmetered'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force

# Download Windows Updates over metered connections - responsible for the toggle in Windows settings => Windows Update => Advanced options
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'  
$Name         = 'AllowAutoWindowsUpdateDownloadOverMeteredNetwork'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force


# Enable notify me when a restart is required to finish updating - responsible for the toggle in Windows settings => Windows Update => Advanced options
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'  
$Name         = 'RestartNotificationsAllowed2'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force







} #end of the 4th Admin test function



# creates Custom Views for Event Viewer in "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\"


# attack surface reduction rules events
$path_0 = "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_0.xml"
if (-NOT (Test-Path $path_0)) {
New-Item -Path $path_0 -ItemType File -Force

$View_0 =
@"
<ViewerConfig><QueryConfig><QueryParams><UserQuery /></QueryParams><QueryNode><Name LanguageNeutralValue="attack surface reduction rule events">attack surface reduction rule events</Name><QueryList><Query Id="0" Path="Microsoft-Windows-Windows Defender/Operational"><Select Path="Microsoft-Windows-Windows Defender/Operational">*[System[(EventID=1121 or EventID=1122 or EventID=5007)]]</Select><Select Path="Microsoft-Windows-Windows Defender/WHC">*[System[(EventID=1121 or EventID=1122 or EventID=5007)]]</Select></Query></QueryList></QueryNode></QueryConfig><ResultsConfig><Columns><Column Name="Level" Type="System.String" Path="Event/System/Level" Visible="">111</Column><Column Name="Keywords" Type="System.String" Path="Event/System/Keywords">70</Column><Column Name="Date and Time" Type="System.DateTime" Path="Event/System/TimeCreated/@SystemTime" Visible="">190</Column><Column Name="Source" Type="System.String" Path="Event/System/Provider/@Name" Visible="">215</Column><Column Name="Event ID" Type="System.UInt32" Path="Event/System/EventID" Visible="">124</Column><Column Name="Task Category" Type="System.String" Path="Event/System/Task" Visible="">74</Column><Column Name="User" Type="System.String" Path="Event/System/Security/@UserID">50</Column><Column Name="Operational Code" Type="System.String" Path="Event/System/Opcode">110</Column><Column Name="Log" Type="System.String" Path="Event/System/Channel">80</Column><Column Name="Computer" Type="System.String" Path="Event/System/Computer">170</Column><Column Name="Process ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessID">70</Column><Column Name="Thread ID" Type="System.UInt32" Path="Event/System/Execution/@ThreadID">70</Column><Column Name="Processor ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessorID">90</Column><Column Name="Session ID" Type="System.UInt32" Path="Event/System/Execution/@SessionID">70</Column><Column Name="Kernel Time" Type="System.UInt32" Path="Event/System/Execution/@KernelTime">80</Column><Column Name="User Time" Type="System.UInt32" Path="Event/System/Execution/@UserTime">70</Column><Column Name="Processor Time" Type="System.UInt32" Path="Event/System/Execution/@ProcessorTime">100</Column><Column Name="Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@ActivityID">85</Column><Column Name="Relative Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@RelatedActivityID">140</Column><Column Name="Event Source Name" Type="System.String" Path="Event/System/Provider/@EventSourceName">140</Column></Columns></ResultsConfig></ViewerConfig>
"@
Add-Content -Path "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_0.xml" -Value $View_0
}

# controlled folder access events
$path_1 = "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_1.xml"
if (-NOT (Test-Path $path_1)) {
New-Item -Path $path_1 -ItemType File

$View_1 =
@"
<ViewerConfig><QueryConfig><QueryParams><UserQuery /></QueryParams><QueryNode><Name LanguageNeutralValue="controlled folder access events">controlled folder access events</Name><QueryList><Query Id="0" Path="Microsoft-Windows-Windows Defender/Operational"><Select Path="Microsoft-Windows-Windows Defender/Operational">*[System[(EventID=1123 or EventID=1124 or EventID=5007)]]</Select><Select Path="Microsoft-Windows-Windows Defender/WHC">*[System[(EventID=1123 or EventID=1124 or EventID=5007)]]</Select></Query></QueryList></QueryNode></QueryConfig></ViewerConfig>
"@
Add-Content -Path "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_1.xml" -Value $View_1
}
# exploit protection events
$path_2 = "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_2.xml"
if (-NOT (Test-Path $path_2)) {
New-Item -Path $path_2 -ItemType File

$View_2 =
@"
<ViewerConfig><QueryConfig><QueryParams><UserQuery /></QueryParams><QueryNode><Name LanguageNeutralValue="exploit protection events">exploit protection events</Name><SortConfig Asc="0"><Column Name="Date and Time" Type="System.DateTime" Path="Event/System/TimeCreated/@SystemTime" Visible="">275</Column></SortConfig><QueryList><Query Id="0" Path="Microsoft-Windows-Security-Mitigations/KernelMode"><Select Path="Microsoft-Windows-Security-Mitigations/KernelMode">*[System[Provider[@Name='Microsoft-Windows-Security-Mitigations' or @Name='Microsoft-Windows-WER-Diag' or @Name='Microsoft-Windows-Win32k' or @Name='Win32k'] and ( (EventID &gt;= 1 and EventID &lt;= 24)  or EventID=5 or EventID=260)]]</Select><Select Path="Microsoft-Windows-Win32k/Concurrency">*[System[Provider[@Name='Microsoft-Windows-Security-Mitigations' or @Name='Microsoft-Windows-WER-Diag' or @Name='Microsoft-Windows-Win32k' or @Name='Win32k'] and ( (EventID &gt;= 1 and EventID &lt;= 24)  or EventID=5 or EventID=260)]]</Select><Select Path="Microsoft-Windows-Win32k/Contention">*[System[Provider[@Name='Microsoft-Windows-Security-Mitigations' or @Name='Microsoft-Windows-WER-Diag' or @Name='Microsoft-Windows-Win32k' or @Name='Win32k'] and ( (EventID &gt;= 1 and EventID &lt;= 24)  or EventID=5 or EventID=260)]]</Select><Select Path="Microsoft-Windows-Win32k/Messages">*[System[Provider[@Name='Microsoft-Windows-Security-Mitigations' or @Name='Microsoft-Windows-WER-Diag' or @Name='Microsoft-Windows-Win32k' or @Name='Win32k'] and ( (EventID &gt;= 1 and EventID &lt;= 24)  or EventID=5 or EventID=260)]]</Select><Select Path="Microsoft-Windows-Win32k/Operational">*[System[Provider[@Name='Microsoft-Windows-Security-Mitigations' or @Name='Microsoft-Windows-WER-Diag' or @Name='Microsoft-Windows-Win32k' or @Name='Win32k'] and ( (EventID &gt;= 1 and EventID &lt;= 24)  or EventID=5 or EventID=260)]]</Select><Select Path="Microsoft-Windows-Win32k/Power">*[System[Provider[@Name='Microsoft-Windows-Security-Mitigations' or @Name='Microsoft-Windows-WER-Diag' or @Name='Microsoft-Windows-Win32k' or @Name='Win32k'] and ( (EventID &gt;= 1 and EventID &lt;= 24)  or EventID=5 or EventID=260)]]</Select><Select Path="Microsoft-Windows-Win32k/Render">*[System[Provider[@Name='Microsoft-Windows-Security-Mitigations' or @Name='Microsoft-Windows-WER-Diag' or @Name='Microsoft-Windows-Win32k' or @Name='Win32k'] and ( (EventID &gt;= 1 and EventID &lt;= 24)  or EventID=5 or EventID=260)]]</Select><Select Path="Microsoft-Windows-Win32k/Tracing">*[System[Provider[@Name='Microsoft-Windows-Security-Mitigations' or @Name='Microsoft-Windows-WER-Diag' or @Name='Microsoft-Windows-Win32k' or @Name='Win32k'] and ( (EventID &gt;= 1 and EventID &lt;= 24)  or EventID=5 or EventID=260)]]</Select><Select Path="Microsoft-Windows-Win32k/UIPI">*[System[Provider[@Name='Microsoft-Windows-Security-Mitigations' or @Name='Microsoft-Windows-WER-Diag' or @Name='Microsoft-Windows-Win32k' or @Name='Win32k'] and ( (EventID &gt;= 1 and EventID &lt;= 24)  or EventID=5 or EventID=260)]]</Select><Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Security-Mitigations' or @Name='Microsoft-Windows-WER-Diag' or @Name='Microsoft-Windows-Win32k' or @Name='Win32k'] and ( (EventID &gt;= 1 and EventID &lt;= 24)  or EventID=5 or EventID=260)]]</Select><Select Path="Microsoft-Windows-Security-Mitigations/UserMode">*[System[Provider[@Name='Microsoft-Windows-Security-Mitigations' or @Name='Microsoft-Windows-WER-Diag' or @Name='Microsoft-Windows-Win32k' or @Name='Win32k'] and ( (EventID &gt;= 1 and EventID &lt;= 24)  or EventID=5 or EventID=260)]]</Select></Query></QueryList></QueryNode></QueryConfig><ResultsConfig><Columns><Column Name="Level" Type="System.String" Path="Event/System/Level" Visible="">225</Column><Column Name="Keywords" Type="System.String" Path="Event/System/Keywords">70</Column><Column Name="Date and Time" Type="System.DateTime" Path="Event/System/TimeCreated/@SystemTime" Visible="">275</Column><Column Name="Source" Type="System.String" Path="Event/System/Provider/@Name" Visible="">242</Column><Column Name="Event ID" Type="System.UInt32" Path="Event/System/EventID" Visible="">185</Column><Column Name="Task Category" Type="System.String" Path="Event/System/Task" Visible="">188</Column><Column Name="User" Type="System.String" Path="Event/System/Security/@UserID">50</Column><Column Name="Operational Code" Type="System.String" Path="Event/System/Opcode">110</Column><Column Name="Log" Type="System.String" Path="Event/System/Channel">80</Column><Column Name="Computer" Type="System.String" Path="Event/System/Computer">170</Column><Column Name="Process ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessID">70</Column><Column Name="Thread ID" Type="System.UInt32" Path="Event/System/Execution/@ThreadID">70</Column><Column Name="Processor ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessorID">90</Column><Column Name="Session ID" Type="System.UInt32" Path="Event/System/Execution/@SessionID">70</Column><Column Name="Kernel Time" Type="System.UInt32" Path="Event/System/Execution/@KernelTime">80</Column><Column Name="User Time" Type="System.UInt32" Path="Event/System/Execution/@UserTime">70</Column><Column Name="Processor Time" Type="System.UInt32" Path="Event/System/Execution/@ProcessorTime">100</Column><Column Name="Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@ActivityID">85</Column><Column Name="Relative Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@RelatedActivityID">140</Column><Column Name="Event Source Name" Type="System.String" Path="Event/System/Provider/@EventSourceName">140</Column></Columns></ResultsConfig></ViewerConfig>
"@
Add-Content -Path "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_2.xml" -Value $View_2
}
# network protection events
$path_3 = "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_3.xml"
if (-NOT (Test-Path $path_3)) {
New-Item -Path $path_3 -ItemType File

$View_3 =
@"
<ViewerConfig><QueryConfig><QueryParams><UserQuery /></QueryParams><QueryNode><Name LanguageNeutralValue="network protection events">network protection events</Name><QueryList><Query Id="0" Path="Microsoft-Windows-Windows Defender/Operational"><Select Path="Microsoft-Windows-Windows Defender/Operational">*[System[(EventID=1125 or EventID=1126 or EventID=5007)]]</Select><Select Path="Microsoft-Windows-Windows Defender/WHC">*[System[(EventID=1125 or EventID=1126 or EventID=5007)]]</Select></Query></QueryList></QueryNode></QueryConfig><ResultsConfig><Columns><Column Name="Level" Type="System.String" Path="Event/System/Level" Visible="">225</Column><Column Name="Keywords" Type="System.String" Path="Event/System/Keywords">70</Column><Column Name="Date and Time" Type="System.DateTime" Path="Event/System/TimeCreated/@SystemTime" Visible="">275</Column><Column Name="Source" Type="System.String" Path="Event/System/Provider/@Name" Visible="">242</Column><Column Name="Event ID" Type="System.UInt32" Path="Event/System/EventID" Visible="">185</Column><Column Name="Task Category" Type="System.String" Path="Event/System/Task" Visible="">188</Column><Column Name="User" Type="System.String" Path="Event/System/Security/@UserID">50</Column><Column Name="Operational Code" Type="System.String" Path="Event/System/Opcode">110</Column><Column Name="Log" Type="System.String" Path="Event/System/Channel">80</Column><Column Name="Computer" Type="System.String" Path="Event/System/Computer">170</Column><Column Name="Process ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessID">70</Column><Column Name="Thread ID" Type="System.UInt32" Path="Event/System/Execution/@ThreadID">70</Column><Column Name="Processor ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessorID">90</Column><Column Name="Session ID" Type="System.UInt32" Path="Event/System/Execution/@SessionID">70</Column><Column Name="Kernel Time" Type="System.UInt32" Path="Event/System/Execution/@KernelTime">80</Column><Column Name="User Time" Type="System.UInt32" Path="Event/System/Execution/@UserTime">70</Column><Column Name="Processor Time" Type="System.UInt32" Path="Event/System/Execution/@ProcessorTime">100</Column><Column Name="Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@ActivityID">85</Column><Column Name="Relative Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@RelatedActivityID">140</Column><Column Name="Event Source Name" Type="System.String" Path="Event/System/Provider/@EventSourceName">140</Column></Columns></ResultsConfig></ViewerConfig>
"@
Add-Content -Path "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_3.xml" -Value $View_3
}
# MSI and Scripts for WDAC Auditing events
$path_4 = "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_4.xml"
if (-NOT (Test-Path $path_4)) {
New-Item -Path $path_4 -ItemType File

$View_4 =
@"
<ViewerConfig><QueryConfig><QueryParams><Simple><Channel>Microsoft-Windows-AppLocker/MSI and Script</Channel><RelativeTimeInfo>0</RelativeTimeInfo><BySource>False</BySource></Simple></QueryParams><QueryNode><Name LanguageNeutralValue="MSI and Scripts for WDAC Auditing">MSI and Scripts for WDAC Auditing</Name><QueryList><Query Id="0" Path="Microsoft-Windows-AppLocker/MSI and Script"><Select Path="Microsoft-Windows-AppLocker/MSI and Script">*</Select></Query></QueryList></QueryNode></QueryConfig><ResultsConfig><Columns><Column Name="Level" Type="System.String" Path="Event/System/Level" Visible="">225</Column><Column Name="Keywords" Type="System.String" Path="Event/System/Keywords">70</Column><Column Name="Date and Time" Type="System.DateTime" Path="Event/System/TimeCreated/@SystemTime" Visible="">275</Column><Column Name="Source" Type="System.String" Path="Event/System/Provider/@Name" Visible="">185</Column><Column Name="Event ID" Type="System.UInt32" Path="Event/System/EventID" Visible="">185</Column><Column Name="Task Category" Type="System.String" Path="Event/System/Task" Visible="">188</Column><Column Name="User" Type="System.String" Path="Event/System/Security/@UserID">50</Column><Column Name="Operational Code" Type="System.String" Path="Event/System/Opcode">110</Column><Column Name="Log" Type="System.String" Path="Event/System/Channel">80</Column><Column Name="Computer" Type="System.String" Path="Event/System/Computer">170</Column><Column Name="Process ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessID">70</Column><Column Name="Thread ID" Type="System.UInt32" Path="Event/System/Execution/@ThreadID">70</Column><Column Name="Processor ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessorID">90</Column><Column Name="Session ID" Type="System.UInt32" Path="Event/System/Execution/@SessionID">70</Column><Column Name="Kernel Time" Type="System.UInt32" Path="Event/System/Execution/@KernelTime">80</Column><Column Name="User Time" Type="System.UInt32" Path="Event/System/Execution/@UserTime">70</Column><Column Name="Processor Time" Type="System.UInt32" Path="Event/System/Execution/@ProcessorTime">100</Column><Column Name="Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@ActivityID">85</Column><Column Name="Relative Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@RelatedActivityID">140</Column><Column Name="Event Source Name" Type="System.String" Path="Event/System/Provider/@EventSourceName">140</Column></Columns></ResultsConfig></ViewerConfig>
"@
Add-Content -Path "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_4.xml" -Value $View_4
}
# Sudden Shut down events
$path_5 = "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_5.xml"
if (-NOT (Test-Path $path_5)) {
New-Item -Path $path_5 -ItemType File

$View_5 =
@"
<ViewerConfig><QueryConfig><QueryParams><Simple><Channel>System</Channel><EventId>41,6008</EventId><RelativeTimeInfo>0</RelativeTimeInfo><BySource>False</BySource></Simple></QueryParams><QueryNode><Name LanguageNeutralValue="Sudden Shut down events">Sudden Shut down events</Name><Description>41= Unexpected Power loss or crash | 6008 = dirty shut down</Description><QueryList><Query Id="0" Path="System"><Select Path="System">*[System[(EventID=41 or EventID=6008)]]</Select></Query></QueryList></QueryNode></QueryConfig><ResultsConfig><Columns><Column Name="Level" Type="System.String" Path="Event/System/Level" Visible="">227</Column><Column Name="Keywords" Type="System.String" Path="Event/System/Keywords">70</Column><Column Name="Date and Time" Type="System.DateTime" Path="Event/System/TimeCreated/@SystemTime" Visible="">277</Column><Column Name="Source" Type="System.String" Path="Event/System/Provider/@Name" Visible="">187</Column><Column Name="Event ID" Type="System.UInt32" Path="Event/System/EventID" Visible="">187</Column><Column Name="Task Category" Type="System.String" Path="Event/System/Task" Visible="">188</Column><Column Name="User" Type="System.String" Path="Event/System/Security/@UserID">50</Column><Column Name="Operational Code" Type="System.String" Path="Event/System/Opcode">110</Column><Column Name="Log" Type="System.String" Path="Event/System/Channel">80</Column><Column Name="Computer" Type="System.String" Path="Event/System/Computer">170</Column><Column Name="Process ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessID">70</Column><Column Name="Thread ID" Type="System.UInt32" Path="Event/System/Execution/@ThreadID">70</Column><Column Name="Processor ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessorID">90</Column><Column Name="Session ID" Type="System.UInt32" Path="Event/System/Execution/@SessionID">70</Column><Column Name="Kernel Time" Type="System.UInt32" Path="Event/System/Execution/@KernelTime">80</Column><Column Name="User Time" Type="System.UInt32" Path="Event/System/Execution/@UserTime">70</Column><Column Name="Processor Time" Type="System.UInt32" Path="Event/System/Execution/@ProcessorTime">100</Column><Column Name="Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@ActivityID">85</Column><Column Name="Relative Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@RelatedActivityID">140</Column><Column Name="Event Source Name" Type="System.String" Path="Event/System/Provider/@EventSourceName">140</Column></Columns></ResultsConfig></ViewerConfig>
"@
Add-Content -Path "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_5.xml" -Value $View_5
}
# Code Integrity Operational events
$path_6 = "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_6.xml"
if (-NOT (Test-Path $path_6)) {
New-Item -Path $path_6 -ItemType File

$View_6 =
@"
<ViewerConfig><QueryConfig><QueryParams><Simple><Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel><RelativeTimeInfo>0</RelativeTimeInfo><BySource>False</BySource></Simple></QueryParams><QueryNode><Name LanguageNeutralValue="Code Integrity Operational">Code Integrity Operational</Name><QueryList><Query Id="0" Path="Microsoft-Windows-CodeIntegrity/Operational"><Select Path="Microsoft-Windows-CodeIntegrity/Operational">*</Select></Query></QueryList></QueryNode></QueryConfig><ResultsConfig><Columns><Column Name="Level" Type="System.String" Path="Event/System/Level" Visible="">227</Column><Column Name="Keywords" Type="System.String" Path="Event/System/Keywords">70</Column><Column Name="Date and Time" Type="System.DateTime" Path="Event/System/TimeCreated/@SystemTime" Visible="">277</Column><Column Name="Source" Type="System.String" Path="Event/System/Provider/@Name" Visible="">187</Column><Column Name="Event ID" Type="System.UInt32" Path="Event/System/EventID" Visible="">187</Column><Column Name="Task Category" Type="System.String" Path="Event/System/Task" Visible="">188</Column><Column Name="User" Type="System.String" Path="Event/System/Security/@UserID">50</Column><Column Name="Operational Code" Type="System.String" Path="Event/System/Opcode">110</Column><Column Name="Log" Type="System.String" Path="Event/System/Channel">80</Column><Column Name="Computer" Type="System.String" Path="Event/System/Computer">170</Column><Column Name="Process ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessID">70</Column><Column Name="Thread ID" Type="System.UInt32" Path="Event/System/Execution/@ThreadID">70</Column><Column Name="Processor ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessorID">90</Column><Column Name="Session ID" Type="System.UInt32" Path="Event/System/Execution/@SessionID">70</Column><Column Name="Kernel Time" Type="System.UInt32" Path="Event/System/Execution/@KernelTime">80</Column><Column Name="User Time" Type="System.UInt32" Path="Event/System/Execution/@UserTime">70</Column><Column Name="Processor Time" Type="System.UInt32" Path="Event/System/Execution/@ProcessorTime">100</Column><Column Name="Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@ActivityID">85</Column><Column Name="Relative Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@RelatedActivityID">140</Column><Column Name="Event Source Name" Type="System.String" Path="Event/System/Provider/@EventSourceName">140</Column></Columns></ResultsConfig></ViewerConfig>
"@
Add-Content -Path "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\View_6.xml" -Value $View_6
}





# turn on "Show text suggestions when typing on the physical keyboard" for the current user, toggles the option in Windows settings
$RegistryPath = 'HKCU:\Software\Microsoft\Input\Settings'  
$Name         = 'EnableHwkbTextPrediction'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force


# turn on "Multilingual text suggestions" for the current user, toggles the option in Windows settings
$RegistryPath = 'HKCU:\Software\Microsoft\Input\Settings'  
$Name         = 'MultilingualEnabled'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force


# Disable Autoplay - responsible for the toggle in Windows settings => Bluetooth & devices => Autoplay
$RegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'  
$Name         = 'DisableAutoplay'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force





# turn off sticky key shortcut of pressing shift key 5 time fast
$RegistryPath = 'HKCU:\Control Panel\Accessibility\StickyKeys'  
$Name         = 'Flags'  
$Value        = '506' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType string -Force





if(-NOT (Test-IsAdmin))

   { write-host "Skipping Admin commands" -ForegroundColor Magenta }

else {




# Disable Autoplay page in settings - responsible for the toggle in Windows settings to become unavailable for users to change
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowAutoPlay'  
$Name         = 'value'  
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force






# Allow all Windows users to use Hyper-V and Windows Sandbox by adding all Windows users to the "Hyper-V Administrators" security group
# this is a recommended security feature, it's good to allow non-admin users to use Windows Sandbox and Hyper-V features as well.

$usernames = Get-LocalUser | Where-Object{$_.enabled -EQ "True"} | Select-Object "Name"
$usernames | ForEach-Object {

try {

 Add-LocalGroupMember -Group "Hyper-V Administrators" -Member $_.Name -ErrorAction Stop
 
 }
 catch  
 { 
 write-host "user account is already part of the Hyper-V Administrators group `n" -ForegroundColor Magenta
 
 } 
 
 }




<#
 Disable Printing over HTTP
https://www.stigviewer.com/stig/microsoft_windows_server_2012_member_server/2013-07-25/finding/WN12-CC-000039
https://www.windows-security.org/6a6bdc56768622d3fd84f1719d330d12/turn-off-printing-over-http
#>
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'  
$Name         = 'DisableHTTPPrinting'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force


# Turn off downloading of print drivers over HTTP
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'  
$Name         = 'DisableWebPnPDownload'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force


# Disable Multicast DNS
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'  
$Name         = 'EnableMulticast'  
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force



<# Turn off smart multi-homed name resolution in Windows

While the feature makes sense from a performance point of view, it introduces an issue from a privacy one.
If you connect to a VPN network on a Windows machine for instance, smart multi-homed name resolution may lead to DNS leakage.
Since requests are sent out to all network adapters at the same time,
all configured DNS servers receive the requests and with them information on the sites that you visit. 
https://www.windows-security.org/2718dc40b3ecea129213e7eca29b7357/turn-off-smart-multi-homed-name-resolution
#>
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'  
$Name         = 'DisableSmartNameResolution'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force


<# The value is 1 to disable DNS A and AAAA queries from executing in parallel on all configured DNS servers,
with the fastest response being theoretically accepted first.
benefits of disabling this are the same as "DisableSmartNameResolution" #>
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'  
$Name         = 'DisableParallelAandAAAA'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force


<# Disable IP Source Routing
After applying this and restarting computer, "Source Routing Behavior" in "netsh int IPv4 show global" shows "Drop"
which is what the value "2" does.#>

$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'  
$Name         = 'DisableIPSourceRouting'  
$Value        = '2' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




<#
https://support.microsoft.com/en-us/topic/security-configuration-guidance-support-ea9aef24-347f-15fa-b94f-36f967907f2f
Allow the computer to ignore NetBIOS name release requests except from WINS servers" to organizational standards
#>
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'  
$Name         = 'NoNameReleaseOnDemand'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force



<# Disable PowerShell v2
https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/ #>
# Enable Windows Defender Application Guard optional feature
# Enable Windows Sandbox optional feature

# since PowerShell Core has problem with these commands (There are Github issues for it already),
# letting the built-in PowerShell handle them

$arguments = @"
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart
Enable-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard -norestart
Enable-WindowsOptionalFeature -online -FeatureName Containers-DisposableClientVM -All -norestart
"@

if ($PSVersionTable.PSVersion -gt [version]"5.1") {

    

    Start-Process -FilePath "PowerShell.exe" -ArgumentList $arguments
  }






# change Windows time sync interval from every 7 days to every 2 days (= every 172800 seconds)
$RegistryPath = 'HKLM:\SYSTEM\ControlSet001\Services\W32Time\TimeProviders\NtpClient'  
$Name         = 'SpecialPollInterval'  
$Value        = '172800' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




# Enable Windows Firewall logging for Private and Public profiles, set the log file size to max 32.767 MB, log only dropped packets.
Set-NetFirewallProfile -Name private, Public -LogBlocked True -LogMaxSizeKilobytes 32767 -LogFileName %systemroot%\system32\LogFiles\Firewall\pfirewall.log





# Disable TCP timestamping
# https://www.kicksecure.com/wiki/Disable_TCP_and_ICMP_Timestamps
netsh int tcp set global timestamps=disabled




# Disallow standard users from changing the Bitlocker Startup PIN or password
# this is complementary for the Bitlocker activation and verification script below to work properly and should run first.
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
$Name         = 'DisallowStandardUserPINReset'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force











# set-up Bitlocker encryption for C drive (OS Drive) with TPMandPIN and recovery password keyprotectors and Verify its implementation
# https://learn.microsoft.com/en-us/powershell/module/bitlocker/remove-bitlockerkeyprotector?view=windowsserver2022-ps





<#
 Safely compares two SecureString objects without decrypting them.
 Outputs $true if they are equal, or $false otherwise.
#>



function Compare-SecureString {
    param(
      [Security.SecureString] $secureString1,
      [Security.SecureString] $secureString2
    )
    try {
      $bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString1)
      $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString2)
      $length1 = [Runtime.InteropServices.Marshal]::ReadInt32($bstr1, -4)
      $length2 = [Runtime.InteropServices.Marshal]::ReadInt32($bstr2, -4)
      if ( $length1 -ne $length2 ) {
        return $false
      }
      for ( $i = 0; $i -lt $length1; ++$i ) {
        $b1 = [Runtime.InteropServices.Marshal]::ReadByte($bstr1, $i)
        $b2 = [Runtime.InteropServices.Marshal]::ReadByte($bstr2, $i)
        if ( $b1 -ne $b2 ) {
          return $false
        }
      }
      return $true
    }
    finally {
      if ( $bstr1 -ne [IntPtr]::Zero ) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
      }
      if ( $bstr2 -ne [IntPtr]::Zero ) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
      }
    }
  }










if ((Get-BitLockerVolume -MountPoint "C:").ProtectionStatus -eq "on")  { 

    if ((Get-BitLockerVolume -MountPoint "C:").EncryptionPercentage -eq "100") {
             
                
               
        $KeyProtectors = (Get-BitLockerVolume -MountPoint "C:").KeyProtector.keyprotectortype

        if ($KeyProtectors -contains 'Tpmpin' -and $KeyProtectors -contains 'recoveryPassword') {
            
            Write-Host "Bitlocker is fully and securely enabled" -ForegroundColor black -BackgroundColor Green
        
        }
        else {
                
                       
                   
                
                if ($KeyProtectors -contains 'Tpmpin' -and $KeyProtectors -notcontains 'recoveryPassword') {
                    Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector *> "D:\Drive C recovery password.txt"
                    Write-Host "TPM and Startup Pin are available but the recovery password is missing, adding it now... `n the recovery password will be saved in D:\Drive C recovery password.txt" -ForegroundColor black -BackgroundColor yellow
                }
                    

                if($KeyProtectors -notcontains 'Tpmpin' -and $KeyProtectors -contains 'recoveryPassword') {
                
                    Write-Host "TPM and Start up key protectors are missing but recovery password key protector is in place, `n adding TPM and Start up key protectors now..." -ForegroundColor black -BackgroundColor yellow
                    



                    do  {

                        $pin1 =  read-host "Enter a Pin for Bitlocker startup (at least 6 digits)" -AsSecureString
                        $pin2 = read-host "Confirm your Bitlocker Startup Pin (at least 6 digits)" -AsSecureString
                        
                      
                      $theyMatch = Compare-SecureString $pin1 $pin2
                         
                      
                      if ( $theyMatch  ) {
                      
                       $pin = $pin1
                      
                      }
                      
                      else {Write-Host "the Pins you entered didn't match, try again" -ForegroundColor Black -BackgroundColor red}
                      
                      }
                      
                      until (
                          $theyMatch
                      )


                    Add-BitLockerKeyProtector -MountPoint "C:" -TpmAndPinProtector -Pin $pin
                }

            
            }


        
        }

        else {
         $EncryptionPercentage = (Get-BitLockerVolume -MountPoint "C:").encryptionpercentage
        Write-Host "Bitlocker is enabled but the C Drive is only" $EncryptionPercentage "percent encrypted" -ForegroundColor black -BackgroundColor yellow
            
        }

     
}

    

else {
    Write-Host "Bitlocker is Not enabled for C Drive, activating now... `n the recovery password will be saved in D:\Drive C recovery password.txt  " -ForegroundColor black -BackgroundColor yellow



        do  {

        $pin1 =  read-host "Enter a Pin for Bitlocker startup (at least 6 digits)" -AsSecureString
        $pin2 = read-host "Confirm your Bitlocker Startup Pin (at least 6 digits)" -AsSecureString
        
      
        $theyMatch = Compare-SecureString $pin1 $pin2
      
      
         if ( $theyMatch  ) {
      
          $pin = $pin1
      
         }
      
         else {Write-Host "the Pins you entered didn't match, try again" -ForegroundColor Black -BackgroundColor red}
      
         }
      
         until (
            $theyMatch
          )



     enable-bitlocker -MountPoint "C:" -EncryptionMethod XtsAes256 -pin $pin -TpmAndPinProtector -SkipHardwareTest

     Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector *> "D:\Drive C recovery password.txt" 

     Resume-BitLocker -MountPoint "C:" 

     Write-Host "Bitlocker is now fully and securely enabled" -ForegroundColor black -BackgroundColor Green

}





# =========================================================================================================================
# ==========================================TLS Security Settings==========================================================
# =========================================================================================================================


<#

Resources used:

https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-
These registry settings only affect things that use Microsoft Schannel, such as Windows components and Microsoft software.
other 3rd party software might use a portable TLS stack implementation that won't be affected by these settings. 

  
  https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations#Portability_concerns


  https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-schannel/ba-p/259233


  https://dirteam.com/sander/2019/07/30/howto-disable-weak-protocols-cipher-suites-and-hashing-algorithms-on-web-application-proxies-ad-fs-servers-and-windows-servers-running-azure-ad-connect/

  https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices

  https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-11
  
  #>

# Disable TLS v1
# step 1
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'  
$Name         = 'DisabledByDefault'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force
# step 2
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'  
$Name         = 'Enabled'  
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force
# step 3
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'  
$Name         = 'DisabledByDefault'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force
# step 4
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'  
$Name         = 'Enabled'  
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force






# Disable TLS v1.1
# step 1
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'  
$Name         = 'DisabledByDefault'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force
# step 2
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'  
$Name         = 'Enabled'  
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force
# step 3
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'  
$Name         = 'DisabledByDefault'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force
# step 4
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'  
$Name         = 'Enabled'  
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force



# Enable TLS_CHACHA20_POLY1305_SHA256 Cipher Suite which is available but not enabled by default in Windows 11
Enable-TlsCipherSuite -Name "TLS_CHACHA20_POLY1305_SHA256" -Position 0




# Disabling weak cipher suites


try {
  # Disable NULL Cipher Suites - 1 
  Disable-TlsCipherSuite TLS_RSA_WITH_NULL_SHA256
  # Disable NULL Cipher Suites - 2
  Disable-TlsCipherSuite TLS_RSA_WITH_NULL_SHA
  # Disable NULL Cipher Suites - 3
  Disable-TlsCipherSuite TLS_PSK_WITH_NULL_SHA384
  # Disable NULL Cipher Suites - 4
  Disable-TlsCipherSuite TLS_PSK_WITH_NULL_SHA256
  
  
  
  Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_GCM_SHA384"
  Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_GCM_SHA256"
  Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA256" 
  Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA256"
  Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA"
  Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA"
  Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_GCM_SHA384" 
  Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_GCM_SHA256"
  Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_CBC_SHA384"
  Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_CBC_SHA256" 
  }
  catch {
      Write-Host "All weak TLS Cipher Suites have been disabled" -ForegroundColor Magenta
  }



# Enabling Diffie–Hellman based Cipher Suits

# TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
# must be already available by default according to Microsoft Docs but it isn't, on Windows 11 insider dev build 25247
# https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-11
Enable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"



# TLS_DHE_RSA_WITH_AES_128_CBC_SHA
# Not enabled by default on Windows 11 according to the Microsoft Docs above
Enable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"


# TLS_DHE_RSA_WITH_AES_256_CBC_SHA
# Not enabled by default on Windows 11 according to the Microsoft Docs above
Enable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"









# Disabling weak and unsecure ciphers



# NULL

$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL\'  
$Name         = 'Enabled'  
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




# DES 56-bit
 
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56')
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" 
$Name         = 'Enabled'  
$Value        = '0' 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




# RC2 40-bit

([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128')
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128' 
$Name         = 'Enabled'  
$Value        = '0' 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




# RC2 56-bit

([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128')
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128' 
$Name         = 'Enabled'  
$Value        = '0' 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




# RC2 128-bit

([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128')
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128' 
$Name         = 'Enabled'  
$Value        = '0'
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




# RC4 40-bit

([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128')
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128'
$Name         = 'Enabled'  
$Value        = '0' 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




# RC4 56-bit

([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128')
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128'
$Name         = 'Enabled'  
$Value        = '0' 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




# RC4 64-bit

([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128')
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128'
$Name         = 'Enabled'  
$Value        = '0'
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force




# RC4 128-bit

([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128')
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128'
$Name         = 'Enabled'  
$Value        = '0'
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force



# 3DES 168-bit (Triple DES 168)

([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168')
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168'
$Name         = 'Enabled'  
$Value        = '0'
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force


# Disable MD5 Hashing Algorithm

$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5'  
$Name         = 'Enabled'  
$Value        = '0' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force











# =========================================================================================================================
# ==========================================End of TLS Security Settings===================================================
# =========================================================================================================================





# Optimizing Network Protection Performance of Windows Defender - this was off by default on Windows 11 insider build 25247
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/network-protection?view=o365-worldwide#optimizing-network-protection-performance
Set-MpPreference -AllowSwitchToAsyncInspection $True




# Setting Edge Traversal policy for All Firewall rules to Block (only inbound rules have that) 
# https://learn.microsoft.com/en-us/windows/win32/teredo/receiving-unsolicited-traffic-over-teredo

Get-NetFirewallRule | Where-Object {$_.EdgeTraversalPolicy -notmatch "Block"} | ForEach-Object { Set-NetFirewallRule -Name $_.Name -EdgeTraversalPolicy Block}

$badrules = Get-NetFirewallRule | Where-Object {$_.EdgeTraversalPolicy -notmatch "Block"}

Write-Host "There are currently" $badrules.count "Firewall rules that allow Edge Traversal" -ForegroundColor Magenta








# Configure LSASS process to run as a protected process with UEFI Lock
$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'  
$Name         = 'RunAsPPL'  
$Value        = '1' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force







} #end of the 5th Admin test function




#











