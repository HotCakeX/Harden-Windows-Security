<#PSScriptInfo

.VERSION 2023.1.13.1

.GUID d435a293-c9ee-4217-8dc1-4ad2318a5770

.AUTHOR HotCakeX

.COMPANYNAME HotCakeX Corp.

.COPYRIGHT 2023

.TAGS Windows Hardening Security Bitlocker Defender Firewall Edge Protection

.LICENSEURI 

.PROJECTURI https://github.com/HotCakeX/Harden-Windows-Security

.ICONURI https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/ICONURI.png

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
Version 2022.12.8: Improved the script
Version 2022.12.9: Configured LSASS process to run as a protected process with UEFI Lock
Version 2022.12.9.1: Added new icon for the script
Version 2022.12.10: Enabled ECH (Encrypted Client Hello of TLS) feature for Edge browser
Version 2022.12.25: Entirely changed and organized the script's style to be easier to read and find commands
Version 2022.12.26: Further improved the script with explanatory comments and improved the Optional Windows Features section
Version 2022.12.26.1: Significantly improved Bitlocker script block, logic and style
Version 2022.12.26.2: Optimized the script by performing registry modifications using a function and saved 600 lines of code
Version 2023.1: The script now allows you to run each hardening category separately and added 2 more categories, 1) certificates and 2) Country IP Blocking
Version 2023.1.1: added a checking process to the country IP blocking category so that if the list is empty, no rule will be created.
Version 2023.1.1.1: Changed description of the PowerShell Gallery's page
Version 2023.1.10: Removed old unnecessary outdated commands, removed most of the links and all descriptions from the script file, USE GITHUB PAGE FOR THE REFERENCE AND PROPER EXPLANATION.
Version 2023.1.12: changed Firewall LOLBin blocking section to be faster with Parallel operations and added Secured-core PC compliancy
Version 2023.1.12.1: Fixed description text in PowerShell Gallery
Version 2023.1.13: Fixed the Country IP blocking list and made it fully compliant with https://www.state.gov/state-sponsors-of-terrorism/
Version 2023.1.13.1: Removed the ECH related commands, were causing problems with ASR rules, they weren't official methods anyway. removed Russia in country IP blocking since it wasn't mentioned in https://www.state.gov/state-sponsors-of-terrorism/ . changed Windows time sync interval from every 7 days to every 4 days (previous script value was 2).
#>

<# 

.SYNOPSIS
    Harden Windows 11 safely, securely and without breaking anything

.DESCRIPTION

💠 Features of this Hardening script:

  ✅ Running this script makes your PC compliant with Secured-core PC specifications (providing that you use a modern hardware that supports the latest Windows security features).
  ✅ Always up-to-date and works with the latest build of Windows (Currently Windows 11 - compatible and rigorously tested on stable and Insider Dev builds)
  ✅ Doesn't break anything
  ✅ Doesn't remove or disable Windows functionalities against Microsoft's recommendation
  ✅ The Readme page on GitHub is used as the reference for all of the commands used in the script. the order in which they appear there is the same as the one in the script file.
  ✅ When a hardening command is no longer necessary because it's applied by default by Microsoft on new builds of Windows, it will also be removed from this script in order to prevent any problems and because it won't be necessary anymore.
  ✅ The script can be run infinite number of times, it's made in a way that it won't make any duplicate changes at all.
  

🛑 Warning: Windows by default is secure and safe, this script does not imply nor claim otherwise. just like anything, you have to use it wisely and don't compromise yourself with reckless behavior and bad user configuration; Nothing is foolproof. this script only uses the tools and features that have already been implemented by Microsoft in Windows OS to fine-tune it towards the highest security and locked-down state, using well-documented, supported, often recommended and official methods. continue reading for comprehensive info.

🛑 Requires PowerShell 7.3, download the latest version from Microsoft Store or GitHub: https://github.com/PowerShell/PowerShell/releases/latest

💠 Hardening Categories from top to bottom: (🔺Detailed info about each of them at my Github🔻)

⏹ Commands that require Administrator Privileges
  ✅ Windows Security aka Defender
  ✅ Attack surface reduction rules
  ✅ Bitlocker Settings
  ✅ TLS Security
  ✅ Lock Screen
  ✅ UAC (User Account Control)
  ✅ Device Guard
  ✅ Windows Firewall
  ✅ Optional Windows Features
  ✅ Windows Networking
  ✅ Miscellaneous Configurations
  ✅ Certificate Checking Commands
  ✅ Country IP Blocking
⏹ Commands that don't require Administrator Privileges
  ✅ Non-Admin Commands that only affect the current user and do not make machine-wide changes.


💎 Note: if there are multiple Windows user accounts in your computer, it's recommended to run this script in each of them, without administrator privileges, because Non-admin commands only apply to the current user and are not machine wide.

💎 Note: The script asks for confirmation, in the PowerShell console, before running each hardening category, so you can selectively run (or don't run) each of them.

💎 Note: Things with #TopSecurity tag can break functionalities or cause difficulties so this script does NOT enable them by default. press Control + F and search for #TopSecurity in the GitHub page or in the script to find those commands and how to enable them if you want.

🏴 if you have any questions, requests, suggestions etc. about this script, please open a new discussion in Github:

🟡 https://github.com/HotCakeX/Harden-Windows-Security/discussions

.EXAMPLE

  
   type: "Set-ExecutionPolicy Bypass -Scope Process" without quotes, in an Elevated PowerShell, to allow running this script for the current session.
   
.NOTES
    
    Check out GitHub page for more security recommendations: https://github.com/HotCakeX/Harden-Windows-Security

#>


 
 
 
 # Source https://github.com/HotCakeX/Harden-Windows-Security
 <# 
Hardening Categories from top to bottom:

  Commands that require Administrator Privileges
  -Windows Security aka Defender
  -Attack surface reduction rules
  -Bitlocker Settings
  -TLS Security
  -Lock Screen
  -UAC (User Account Control)
  -Device Guard
  -Windows Firewall
  -Optional Windows Features
  -Windows Networking
  -Miscellaneous Configurations
  -Certificate Checking Commands
  -Country IP Blocking
 Commands that don't require Administrator Privileges
  -Non-Admin Commands that only affect the current user and do not make machine-wide changes.

 #>
 
 

  
 <#
    .Synopsis
        Tests if the user is an administrator
    .Description
        Returns true if a user is an administrator, false if the user is not an administrator   
    .Example
        Test-IsAdmin
  https://devblogs.microsoft.com/scripting/use-function-to-determine-elevation-of-powershell-console/
    #>



  # Function to modify registry, only DWORD property Types, checks before modification
function ModifyRegistry {
  param ($RegPath, $RegName, $RegValue )

  If (-NOT (Test-Path $RegPath)) { 
New-Item -Path $RegPath -Force | Out-Null
  }
  New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType DWORD -Force
}


 # Function to test if current session has administrator privileges
Function Test-IsAdmin
{
 $identity = [Security.Principal.WindowsIdentity]::GetCurrent()

 $principal = New-Object Security.Principal.WindowsPrincipal $identity

 $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}



 
if(-NOT (Test-IsAdmin))

   { write-host "Skipping commands that require Administrator privileges" -ForegroundColor Magenta }

else {





# =========================================================================================================================
# ==========================================Windows Security aka Defender==================================================
# =========================================================================================================================
do { $WindowsSecurityQuestion = $(write-host "Run Windows Security (aka Defender) section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($WindowsSecurityQuestion) {   
    "y" { 





# Indicates whether to scan for malicious and unwanted software in removable drives, such as flash drives, during a full scan.
Set-MpPreference -DisableRemovableDriveScanning 0

# Enables file hash computation
Set-MpPreference -efhc 1 

# increases level of Cloud Protection - this sets it to 6 which is currently the highest possible
Set-MpPreference -CloudBlockLevel ZeroTolerance

# This increases the allotted analysis time to max:
Set-MpPreference -CloudExtendedTimeout 50

# Enable Windows Defender catch-up scans for scheduled, but missed, quick scans
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
Set-MpPreference -SignatureUpdateInterval 3


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


# Optimizing Network Protection Performance of Windows Defender - this was off by default on Windows 11 insider build 25247
Set-MpPreference -AllowSwitchToAsyncInspection $True


}"N" {Break}   }}  until ($WindowsSecurityQuestion -eq "y" -or $WindowsSecurityQuestion -eq "N")
# =========================================================================================================================
# =========================================End of Windows Security aka Defender============================================
# =========================================================================================================================







# =========================================================================================================================
# ==========================================Attack surface reduction rules=================================================
# =========================================================================================================================
do { $ASRulesQuestion = $(write-host "Run Attack Surface Reduction Rules section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($ASRulesQuestion) {   
    "y" { 




# You can manually turn off any of them by changing them from Enabled to AuditMode or Disabled

# ASR Rules, All 16 available rules are set to Enabled which means Block
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
# Block executable files from running unless they meet a prevalence, age, or trusted list criteria 
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
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



} "N" {Break}   }}  until ($ASRulesQuestion -eq "y" -or $ASRulesQuestion -eq "N")
# =========================================================================================================================
# =========================================End of Attack surface reduction rules===========================================
# =========================================================================================================================







# =========================================================================================================================
# ==========================================Bitlocker Settings=============================================================
# =========================================================================================================================
do { $BitlockerQuestion = $(write-host "Run Bitlocker section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($BitlockerQuestion) {   
    "y" { 



# Set OS drive Encryption algorithm and Cipher | XTS-AES 256-bit
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'EncryptionMethodWithXtsOs' -RegValue '7'

# Set Fixed drive Encryption algorithm and Cipher | XTS-AES 256-bit
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'EncryptionMethodWithXtsFdv' -RegValue '7'

# Set removable drives data Encryption algorithm and Cipher | XTS-AES 256-bit
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'EncryptionMethodWithXtsRdv' -RegValue '7'

# Bitlocker: Allow Enhanced PINs for startup 
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'UseEnhancedPin' -RegValue '1'

# Enforce drive encryption type on operating system drives: full drive encryption
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'OSEncryptionType' -RegValue '1'

# Bitlocker: use Advanced Startup - Require additional authentication at startup
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'UseAdvancedStartup' -RegValue '1'

# Bitlocker: Don't allow Bitlocker with no TPM
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'EnableBDEWithNoTPM' -RegValue '0'

# Bitlocker: Allow/Use startup key with TPM
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'UseTPMKey' -RegValue '2'

# Bitlocker: Allow/Use startup PIN with TPM
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'UseTPMPIN' -RegValue '2'

# Bitlocker: Allow/Use startup key and PIN with TPM
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'UseTPMKeyPIN' -RegValue '2'

# Bitlocker: Allow/Use TPM
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'UseTPM' -RegValue '2'








# bootDMAProtection check - checks for Kernel DMA Protection status in System information or msinfo32
$bootDMAProtectionCheck =
@"
  namespace SystemInfo
    {
      using System;
      using System.Runtime.InteropServices;

      public static class NativeMethods
      {
        internal enum SYSTEM_DMA_GUARD_POLICY_INFORMATION : int
        {
            /// </summary>
            SystemDmaGuardPolicyInformation = 202
        }

        [DllImport("ntdll.dll")]
        internal static extern Int32 NtQuerySystemInformation(
          SYSTEM_DMA_GUARD_POLICY_INFORMATION SystemDmaGuardPolicyInformation,
          IntPtr SystemInformation,
          Int32 SystemInformationLength,
          out Int32 ReturnLength);

        public static byte BootDmaCheck() {
          Int32 result;
          Int32 SystemInformationLength = 1;
          IntPtr SystemInformation = Marshal.AllocHGlobal(SystemInformationLength);
          Int32 ReturnLength;

          result = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SYSTEM_DMA_GUARD_POLICY_INFORMATION.SystemDmaGuardPolicyInformation,
                    SystemInformation,
                    SystemInformationLength,
                    out ReturnLength);

          if (result == 0) {
            byte info = Marshal.ReadByte(SystemInformation, 0);
            return info;
          }

          return 0;
        }
      }
    }
"@

Add-Type -TypeDefinition $bootDMAProtectionCheck

# returns true or false depending on whether Kernel DMA Protection is on or off
$bootDMAProtection = ([SystemInfo.NativeMethods]::BootDmaCheck()) -ne 0


# Enables or disables DMA protection from Bitlocker Countermeasures based on the status of Kernel DMA protection.
if ($bootDMAProtection) {

    ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'DisableExternalDMAUnderLock' -RegValue '1'

}
else {

    ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'DisableExternalDMAUnderLock' -RegValue '0'
}






# Disallow standard users from changing the Bitlocker Startup PIN or password
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'DisallowStandardUserPINReset' -RegValue '1'













# set-up Bitlocker encryption for OS Drive with TPMandPIN and recovery password keyprotectors and Verify its implementation
# https://learn.microsoft.com/en-us/powershell/module/bitlocker/remove-bitlockerkeyprotector?view=windowsserver2022-ps
# Once it's done, it saves the recovery password in a text file called "Drive C recovery password.txt" in Drive D:\
# Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access.




<#
https://stackoverflow.com/questions/48809012/compare-two-credentials-in-powershell


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




 # first make sure Bitlocker isn't in the middle of any decryption/encryption operation
if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage -ne "100" -and (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage -ne "0") {

    $kawai = (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage
    Write-Host "Please wait for Bitlocker operation to finish encrypting or decrypting the disk" -ForegroundColor Magenta -BackgroundColor white
    Write-Host $env:SystemDrive" drive encryption is currently at" $kawai -ForegroundColor Magenta -BackgroundColor white

}

else {




    # check if Bitlocker is enabled for the system drive
if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq "on")  { 
                 
               
    $KeyProtectors = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector.keyprotectortype
    # check if TPM, PIN and recovery password are being used with Bitlocker which are the safest settings
    if ($KeyProtectors -contains 'Tpmpin' -and $KeyProtectors -contains 'recoveryPassword') {
        
        Write-Host "Bitlocker is fully and securely enabled" -ForegroundColor black -BackgroundColor Green
    
    }
    else {       
            # check if Bitlocker is using TPM and PIN but not recovery password as key protector
            if ($KeyProtectors -contains 'Tpmpin' -and $KeyProtectors -notcontains 'recoveryPassword')
             {

                 if (Test-Path D:){
                    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> "D:\Drive C recovery password.txt"
                    Write-Host "TPM and Startup Pin are available but the recovery password is missing, adding it now... `nthe recovery password will be saved in a Text file in D:\Drive C recovery password.txt" -ForegroundColor Magenta -BackgroundColor yellow
                    Write-Host "Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." -ForegroundColor Magenta -BackgroundColor white

                }
                 elseif (Test-Path E:) {
                    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> "E:\Drive C recovery password.txt"
                    Write-Host "TPM and Startup Pin are available but the recovery password is missing, adding it now... `nthe recovery password will be saved in a Text file in E:\Drive C recovery password.txt" -ForegroundColor Magenta -BackgroundColor yellow
                    Write-Host "Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." -ForegroundColor Magenta -BackgroundColor white
                
                }


                 else {

                    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> "C:\Drive C recovery password.txt"
                    Write-Host "TPM and Startup Pin are available but the recovery password is missing, adding it now... `nthe recovery password will be saved in a Text file in C:\Drive C recovery password.txt" -ForegroundColor Magenta -BackgroundColor yellow
                    Write-Host "Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." -ForegroundColor Magenta -BackgroundColor white
                }
                
                
             }
                
                # check if Bitlocker is using recovery password but not TPM and PIN
            if($KeyProtectors -notcontains 'Tpmpin' -and $KeyProtectors -contains 'recoveryPassword') {
            
                Write-Host "TPM and Start up PIN key protectors are missing but recovery password key protector is in place, `nadding TPM and Start up PIN key protectors now..." -ForegroundColor Magenta -BackgroundColor white
                


                do  {

                    $pin1 = $(write-host "Enter a Pin for Bitlocker startup (at least 6 digits)" -ForegroundColor Magenta -BackgroundColor white; Read-Host -AsSecureString)
                    $pin2 = $(write-host "Confirm your Bitlocker Startup Pin (at least 6 digits)" -ForegroundColor Magenta -BackgroundColor white; Read-Host -AsSecureString)
                    
                  
                    $theyMatch = Compare-SecureString $pin1 $pin2
                     
                  
                    if ( $theyMatch  ) {
                  
                    $pin = $pin1
                  
                     }
                  
                    else {Write-Host "the PINs you entered didn't match, try again" -ForegroundColor Black -BackgroundColor red}
                  
                  }
                  
                  until (
                      $theyMatch
                  )


                Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinProtector -Pin $pin
                Write-Host "PINs matched, enabling TPM and startup PIN now" -ForegroundColor DarkMagenta -BackgroundColor White
            }
     
        }
    
     
}

   
else {
    Write-Host "Bitlocker is Not enabled for the System Drive Drive, activating now..." -ForegroundColor Magenta -BackgroundColor yellow
    
        do  {

            $pin1 = $(write-host "Enter a Pin for Bitlocker startup (at least 6 digits)" -ForegroundColor Magenta -BackgroundColor white; Read-Host -AsSecureString)
            $pin2 = $(write-host "Confirm your Bitlocker Startup Pin (at least 6 digits)" -ForegroundColor Magenta -BackgroundColor white; Read-Host -AsSecureString)

      
        $theyMatch = Compare-SecureString $pin1 $pin2
      
      
         if ( $theyMatch  ) {
      
          $pin = $pin1
      
         }
      
         else {Write-Host "the Pins you entered didn't match, try again" -ForegroundColor Black -BackgroundColor red}
      
         }
      
         until (
            $theyMatch
          )



     enable-bitlocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -pin $pin -TpmAndPinProtector -SkipHardwareTest

     

        if(Test-Path D:){
            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> "D:\Drive C recovery password.txt" 
            Resume-BitLocker -MountPoint $env:SystemDrive
            Write-Host "the recovery password will be saved in a Text file in D:\Drive C recovery password.txt `nMake sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." -ForegroundColor Magenta -BackgroundColor white
            Write-Host "Bitlocker is now fully and securely enabled" -ForegroundColor black -BackgroundColor Green
        }

        elseif(Test-Path E:){
            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> "E:\Drive C recovery password.txt" 
            Resume-BitLocker -MountPoint $env:SystemDrive
            Write-Host "the recovery password will be saved in a Text file in E:\Drive C recovery password.txt `nMake sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." -ForegroundColor Magenta -BackgroundColor white
            Write-Host "Bitlocker is now fully and securely enabled" -ForegroundColor black -BackgroundColor Green
        
        }

        else {
            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> "C:\Drive C recovery password.txt" 
            Resume-BitLocker -MountPoint $env:SystemDrive
            Write-Host "the recovery password will be saved in a Text file in C:\Drive C recovery password.txt `nMake sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." -ForegroundColor Magenta -BackgroundColor white
            Write-Host "Bitlocker is now fully and securely enabled" -ForegroundColor black -BackgroundColor Green
            
        }
     
     

}


}



} "N" {Break}   }}  until ($BitlockerQuestion -eq "y" -or $BitlockerQuestion -eq "N")
# =========================================================================================================================
# ==========================================End of Bitlocker Settings======================================================
# =========================================================================================================================





# =========================================================================================================================
# ==============================================TLS Security===============================================================
# =========================================================================================================================
do { $TLSQuestion = $(write-host "Run TLS Security section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($TLSQuestion) {   
    "y" { 



# Disable TLS v1
# step 1
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -RegName 'DisabledByDefault' -RegValue '1'
# step 2
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -RegName 'Enabled' -RegValue '0'
# step 3
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -RegName 'DisabledByDefault' -RegValue '1'
# step 4
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -RegName 'Enabled' -RegValue '0'


# Disable TLS v1.1
# step 1
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -RegName 'DisabledByDefault' -RegValue '1'
# step 2
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -RegName 'Enabled' -RegValue '0'
# step 3
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -RegName 'DisabledByDefault' -RegValue '1'
# step 4
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -RegName 'Enabled' -RegValue '0'



# Enable TLS_CHACHA20_POLY1305_SHA256 Cipher Suite which is available but not enabled by default in Windows 11
Enable-TlsCipherSuite -Name "TLS_CHACHA20_POLY1305_SHA256" -Position 0





# disabling weak cipher suites


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



# Enabling Diffie–Hellman based key exchange algorithms

# TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
# must be already available by default according to Microsoft Docs but it isn't, on Windows 11 insider dev build 25272
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
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL\' -RegName 'Enabled' -RegValue '0'


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
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -RegName 'Enabled' -RegValue '0'




} "N" {Break}   }}  until ($TLSQuestion -eq "y" -or $TLSQuestion -eq "N")
# =========================================================================================================================
# ==========================================End of TLS Security============================================================
# =========================================================================================================================





# =========================================================================================================================
# ==============================================Lock Screen================================================================
# =========================================================================================================================
do { $LockScreenQuestion = $(write-host "Run Lock Screen section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($LockScreenQuestion) {   
    "y" { 



# Automatically lock computer after X seconds, set to 120 seconds in this command.
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'InactivityTimeoutSecs' -RegValue '120'

# forces CAD requirement, CTRL + ALT + DELETE at Windows Lock screen to be pressed to show sign in fields
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'DisableCAD' -RegValue '0'

# set a threshold for the number of failed sign-in attempts that causes the device to be locked by using BitLocker.
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'MaxDevicePasswordFailedAttempts' -RegValue '6'

# hides email address of the Microsoft account on lock screen
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'DontDisplayLockedUserId' -RegValue '3'

# Don't display username at sign-in when user signs in as Other user
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'DontDisplayUserName' -RegValue '1'

# Don't display last signed-in #TopSecurity
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'dontdisplaylastusername' -RegValue '0'

# Don't show network (like WiFi) icon on lock screen
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -RegName 'DontDisplayNetworkSelectionUI' -RegValue '1'


} "N" {Break}   }}  until ($LockScreenQuestion -eq "y" -or $LockScreenQuestion -eq "N")
# =========================================================================================================================
# ==============================================End of Lock Screen=========================================================
# =========================================================================================================================




# =========================================================================================================================
# ==============================================UAC (User Account Control)=================================================
# =========================================================================================================================
do { $UACQuestion = $(write-host "Run UAC section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($UACQuestion) {   
    "y" { 




# setting it to 1 asks for Admin credentials, setting it to 2 asks for Accept/Deny for Admin tasks in Admin account.
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'ConsentPromptBehaviorAdmin' -RegValue '1'

# this automatically denies all UAC prompts on Standard accounts when set to "0", 1 = Prompt for credentials on the secure desktop #TopSecurity
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'ConsentPromptBehaviorUser' -RegValue '1'

# Enforce cryptographic signatures on any interactive application that requests elevation of privilege #TopSecurity
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'ValidateAdminCodeSignatures' -RegValue '0'




} "N" {Break}   }}  until ($UACQuestion -eq "y" -or $UACQuestion -eq "N")
# =========================================================================================================================
# ============================================End of UAC (User Account Control)============================================
# =========================================================================================================================





# =========================================================================================================================
# ======================================================Device Guard=======================================================
# =========================================================================================================================
do { $DeviceGuardQuestion= $(write-host "Run Device Guard section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($DeviceGuardQuestion) {   
    "y" { 




# To enable VBS
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -RegName 'EnableVirtualizationBasedSecurity' -RegValue '1'

# To require Secure boot and DMA protection for VBS
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -RegName 'RequirePlatformSecurityFeatures' -RegValue '3'

# To turn on UEFI lock for VBS
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -RegName 'Locked' -RegValue '1'

# To enable virtualization-based protection of Code Integrity policies
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -RegName 'Enabled' -RegValue '1'

# To turn on UEFI lock for virtualization-based protection of Code Integrity policies
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -RegName 'Locked' -RegValue '1'

# To Require UEFI Memory Attributes Table
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -RegName 'HVCIMATRequired' -RegValue '1'

# To Enable Windows Defender Credential Guard with UEFI Lock
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -RegName 'LsaCfgFlags' -RegValue '1'

# To Enable System Guard Secure Launch and SMM protection
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard' -RegName 'Enabled' -RegValue '1'

# To Enable Kernel-mode Hardware-enforced Stack Protection
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks' -RegName 'Enabled' -RegValue '1'

# To disable Audit Mode for Kernel-mode Hardware-enforced Stack Protection
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks' -RegName 'AuditModeEnabled' -RegValue '0'




} "N" {Break}   }}  until ($DeviceGuardQuestion -eq "y" -or $DeviceGuardQuestion -eq "N")
# =========================================================================================================================
# ====================================================End of Device Guard==================================================
# =========================================================================================================================






# =========================================================================================================================
# ====================================================Windows Firewall=====================================================
# =========================================================================================================================
do { $WinFirewallQuestion= $(write-host "Run Windows Firewall section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($WinFirewallQuestion) {   
    "y" { 




# make sure Firewall for all 3 profiles is enabled
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# set inbound and outbound default actions for Domain Firewall Profile to Block
Set-NetFirewallProfile -Name Domain -DefaultInboundAction Block -DefaultOutboundAction Block


# measure execution time of Firewall LOLBins blocking section
$fsw = [Diagnostics.Stopwatch]::StartNew()


# list all the LOLBin programs in an array
$programs = @("C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe",
"C:\Program Files\Microsoft Office\root\client\AppVLP.exe",
"%systemroot%\system32\certutil.exe",
"%systemroot%\SysWOW64\certutil.exe",
"%systemroot%\system32\cmstp.exe",
"%systemroot%\SysWOW64\cmstp.exe",
"%systemroot%\system32\cscript.exe",
"%systemroot%\SysWOW64\cscript.exe",
"%systemroot%\system32\esentutl.exe",
"%systemroot%\SysWOW64\esentutl.exe",
"%systemroot%\system32\expand.exe",
"%systemroot%\SysWOW64\expand.exe",
"%systemroot%\system32\extrac32.exe",
"%systemroot%\SysWOW64\extrac32.exe",
"%systemroot%\system32\findstr.exe",
"%systemroot%\SysWOW64\findstr.exe",
"%systemroot%\system32\hh.exe",
"%systemroot%\SysWOW64\hh.exe",
"%systemroot%\system32\makecab.exe",
"%systemroot%\SysWOW64\makecab.exe",
"%systemroot%\system32\mshta.exe",
"%systemroot%\SysWOW64\mshta.exe",
"%systemroot%\system32\msiexec.exe",
"%systemroot%\SysWOW64\msiexec.exe",
"%systemroot%\system32\nltest.exe",
"%systemroot%\SysWOW64\nltest.exe",
"%systemroot%\system32\notepad.exe",
"%systemroot%\SysWOW64\notepad.exe",
"%systemroot%\system32\odbcconf.exe",
"%systemroot%\SysWOW64\odbcconf.exe",
"%systemroot%\system32\pcalua.exe",
"%systemroot%\SysWOW64\pcalua.exe",
"%systemroot%\system32\regasm.exe",
"%systemroot%\SysWOW64\regasm.exe",
"%systemroot%\system32\regsvr32.exe",
"%systemroot%\SysWOW64\regsvr32.exe",
"%systemroot%\system32\replace.exe",
"%systemroot%\SysWOW64\replace.exe",
"%systemroot%\SysWOW64\rpcping.exe",
"%systemroot%\system32\rundll32.exe",
"%systemroot%\SysWOW64\rundll32.exe",
"%systemroot%\system32\runscripthelper.exe",
"%systemroot%\SysWOW64\runscripthelper.exe",
"%systemroot%\system32\scriptrunner.exe",
"%systemroot%\SysWOW64\scriptrunner.exe",
"%systemroot%\system32\SyncAppvPublishingServer.exe",
"%systemroot%\SysWOW64\SyncAppvPublishingServer.exe",
"%systemroot%\system32\wbem\wmic.exe",
"%systemroot%\SysWOW64\wbem\wmic.exe",
"%systemroot%\system32\wscript.exe",
"%systemroot%\SysWOW64\wscript.exe")



$programs | ForEach-Object -parallel {

    $program = $_     

    if (-NOT (Get-NetFirewallApplicationFilter -All | Select-Object * | Where-Object { $_.AppPath -eq $program }))
     {

    New-NetFirewallRule -DisplayName "LOLBin blocking rule for $program" -Protocol "TCP" -Program $program -Action Block -Direction Outbound -Profile Any -Enabled True -Group "LOLBins Blocking"
               
        }

}

# show the execution time on the console
$fsw.Stop()
$fsw.Elapsed




# Enable Windows Firewall logging for Private and Public profiles, set the log file size to max 32.767 MB, log only dropped packets.
Set-NetFirewallProfile -Name private, Public -LogBlocked True -LogMaxSizeKilobytes 32767 -LogFileName %systemroot%\system32\LogFiles\Firewall\pfirewall.log

# Disables Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles
Disable-NetFirewallRule -DisplayName "mDNS (UDP-In)"



} "N" {Break}   }}  until ($WinFirewallQuestion -eq "y" -or $WinFirewallQuestion -eq "N")
# =========================================================================================================================
# =================================================End of Windows Firewall=================================================
# =========================================================================================================================






# =========================================================================================================================
# =================================================Optional Windows Features===============================================
# =========================================================================================================================
do { $OptionalFeaturesQuestion= $(write-host "Run Optional Windows Features section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($OptionalFeaturesQuestion) {   
    "y" { 




if ($PSVersionTable.PSVersion.Major,$PSVersionTable.PSVersion.Minor -join "." -gt 5.1)


# since PowerShell Core (only if installed from Microsoft Store) has problem with these commands, letting the built-in PowerShell handle them
# There are Github issues for it already: https://github.com/PowerShell/PowerShell/issues/13866


{ 

# Disable PowerShell v2 (needs 2 commands)
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart}else{Write-Host 'MicrosoftWindowsPowerShellV2 is already disabled' -ForegroundColor Darkgreen}"
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart}else{Write-Host 'MicrosoftWindowsPowerShellV2Root is already disabled' -ForegroundColor Darkgreen}"

# Disable Work Folders client
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -norestart}else{Write-Host 'WorkFolders-Client is already disabled' -ForegroundColor Darkgreen}"

# Disable Internet Printing Client
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features -norestart}else{Write-Host 'Printing-Foundation-Features is already disabled' -ForegroundColor Darkgreen}"

# Disable Windows Media Player (legacy)
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -norestart}else{Write-Host 'WindowsMediaPlayer is already disabled' -ForegroundColor Darkgreen}"

# Enable Windows Defender Application Guard
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -norestart}else{Write-Host 'Windows-Defender-ApplicationGuard is already enabled' -ForegroundColor Darkgreen}"

# Enable Windows Sandbox
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -norestart}else{Write-Host 'Containers-DisposableClientVM (Windows Sandbox) is already enabled' -ForegroundColor Darkgreen}"

# Enable Hyper-V
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -norestart}else{Write-Host 'Microsoft-Hyper-V is already enabled' -ForegroundColor Darkgreen}"

# Enable Virtual Machine Platform
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -norestart}else{Write-Host 'VirtualMachinePlatform is already enabled' -ForegroundColor Darkgreen}"


}

else {

    # Disable PowerShell v2 (needs 2 commands) 
    if((get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart}else{Write-Host 'MicrosoftWindowsPowerShellV2 is already disabled' -ForegroundColor Darkgreen}
    if((get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart}else{Write-Host 'MicrosoftWindowsPowerShellV2Root is already disabled' -ForegroundColor Darkgreen}

    # Disable Work Folders client
    if((get-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -norestart}else{Write-Host 'WorkFolders-Client is already disabled' -ForegroundColor Darkgreen}

    # Disable Internet Printing Client
    if((get-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features -norestart}else{Write-Host 'Printing-Foundation-Features is already disabled' -ForegroundColor Darkgreen}

    # Disable Windows Media Player (legacy)
    if((get-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -norestart}else{Write-Host 'WindowsMediaPlayer is already disabled' -ForegroundColor Darkgreen}

    # Enable Windows Defender Application Guard
    if((get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -norestart}else{Write-Host 'Windows-Defender-ApplicationGuard is already enabled' -ForegroundColor Darkgreen}

    # Enable Windows Sandbox
    if((get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -norestart}else{Write-Host 'Containers-DisposableClientVM (Windows Sandbox) is already enabled' -ForegroundColor Darkgreen}

    # Enable Hyper-V
    if((get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -norestart}else{Write-Host 'Microsoft-Hyper-V is already enabled' -ForegroundColor Darkgreen}

    # Enable Virtual Machine Platform
    if((get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -norestart}else{Write-Host 'VirtualMachinePlatform is already enabled' -ForegroundColor Darkgreen}


        
}



} "N" {Break}   }}  until ($OptionalFeaturesQuestion -eq "y" -or $OptionalFeaturesQuestion -eq "N")
# =========================================================================================================================
# ==============================================End of Optional Windows Features===========================================
# =========================================================================================================================








# =========================================================================================================================
# ====================================================Windows Networking===================================================
# =========================================================================================================================
do { $WinNetworkingQuestion= $(write-host "Run Windows Networking section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($WinNetworkingQuestion) {   
    "y" { 



# disable NetBIOS over TCP/IP on all network interfaces, virtual and physical
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |ForEach-Object { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 }


# disable the LLMNR protocol on a Windows
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient  -Force
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value 0 -PropertyType DWORD  -Force


# disable LMHOSTS lookup protocol on all network adapters
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -RegName 'EnableLMHOSTS' -RegValue '0'


# Set the Network Location of all connections to Public (or Private)
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Public


# Disable Printing over HTTP
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -RegName 'DisableHTTPPrinting' -RegValue '1'

# Turn off downloading of print drivers over HTTP
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -RegName 'DisableWebPnPDownload' -RegValue '1'

# Disable IP Source Routing
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -RegName 'DisableIPSourceRouting' -RegValue '2'

# Allow the computer to ignore NetBIOS name release requests
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters' -RegName 'NoNameReleaseOnDemand' -RegValue '1'




} "N" {Break}   }}  until ($WinNetworkingQuestion -eq "y" -or $WinNetworkingQuestion -eq "N")
# =========================================================================================================================
# =================================================End of Windows Networking===============================================
# =========================================================================================================================







# =========================================================================================================================
# ==============================================Miscellaneous Configurations===============================================
# =========================================================================================================================
do { $MiscellaneousQuestion= $(write-host "Run Miscellaneous section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($MiscellaneousQuestion) {   
    "y" {




# Enable early launch antimalware driver for scan of boot-start drivers
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -RegName 'DriverLoadPolicy' -RegValue '8'

# Disable Location services from Windows - affects Windows settings privacy section
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -RegName 'DisableLocation' -RegValue '1'

# Enable Hibernate
powercfg /hibernate on

# Set Hibnernate mode to full
powercfg /h /type full

# Add Hibernate option to Start menu's power options
ModifyRegistry -RegPath 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' -RegName 'ShowHibernateOption' -RegValue '1'

# Disable sleep for when plugged in
ModifyRegistry -RegPath 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab' -RegName 'ACSettingIndex' -RegValue '0'

# Disable sleep for when on battery
ModifyRegistry -RegPath 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab' -RegName 'DCSettingIndex' -RegValue '0'

# Enable Mandatory ASLR
set-processmitigation -System -Enable ForceRelocateImages

# You can add Mandatory ASLR override for a Trusted App using the command below or in the Program Settings section of Exploit Protection in Windows Defender app. 
# Set-ProcessMitigation -Name "C:\TrustedApp.exe" -Disable ForceRelocateImages

# Enable svchost.exe mitigations
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SCMConfig' -RegName 'EnableSvchostMitigationPolicy' -RegValue '1'

# Turn on Enhanced mode search for Windows indexer
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows Search' -RegName 'EnableFindMyFiles' -RegValue '1'

# Enforce the Administrator role for adding printer drivers
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' -RegName 'AddPrinterDrivers' -RegValue '1'


# Enable SMB/LDAP Signing
ModifyRegistry -RegPath 'HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters' -RegName 'RequireSecuritySignature' -RegValue '1'
ModifyRegistry -RegPath 'HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters' -RegName 'EnableSecuritySignature' -RegValue '1'
ModifyRegistry -RegPath 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters' -RegName 'RequireSecuritySignature' -RegValue '1'
ModifyRegistry -RegPath 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters' -RegName 'EnableSecuritySignature' -RegValue '1'


# Enable SMB Encryption - using force to confirm the action
Set-SmbServerConfiguration -EncryptData $true -force


# Set Microsoft Edge to update over Metered connections
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientStateMedium\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' -RegName 'allowautoupdatesmetered' -RegValue '1'

# Download Windows Updates over metered connections
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -RegName 'AllowAutoWindowsUpdateDownloadOverMeteredNetwork' -RegValue '1'

# Enable notify me when a restart is required to finish updating
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -RegName 'RestartNotificationsAllowed2' -RegValue '1'

# Allow all Windows users to use Hyper-V and Windows Sandbox by adding all Windows users to the "Hyper-V Administrators" security group
$usernames = Get-LocalUser | Where-Object{$_.enabled -EQ "True"} | Select-Object "Name"
$usernames | ForEach-Object {

try { Add-LocalGroupMember -Group "Hyper-V Administrators" -Member $_.Name -ErrorAction Stop  }
 catch {  write-host "user account is already part of the Hyper-V Administrators group `n" -ForegroundColor Magenta } 
    }


# Change Windows time sync interval from every 7 days to every 4 days (= every 345600 seconds)
ModifyRegistry -RegPath 'HKLM:\SYSTEM\ControlSet001\Services\W32Time\TimeProviders\NtpClient' -RegName 'SpecialPollInterval' -RegValue '345600'


# Configure LSASS process to run as a protected process with UEFI Lock, the expected default value on new Windows 11 installations is "2" which is without UEFI lock, "1" is with UEFI lock
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -RegName 'RunAsPPL' -RegValue '1'






}
"N" {Break}   }}  until ($MiscellaneousQuestion -eq "y" -or $MiscellaneousQuestion -eq "N")



# =========================================================================================================================
# ============================================End of Miscellaneous Configurations==========================================
# =========================================================================================================================






# =========================================================================================================================
# ====================================================Certificate Checking Commands========================================
# =========================================================================================================================
do { $CertCheckQuestion= $(write-host "Run Certificate Checking section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($CertCheckQuestion) {   
    "y" { 



      # List valid certificates not rooted to the Microsoft Certificate Trust List in the User store
      do { $UserStoreQ= $(write-host "List valid certificates not rooted to the Microsoft Certificate Trust List in the User store ? Enter Y for Yes or N for No" -ForegroundColor Cyan; Read-Host)
      switch ($UserStoreQ) {   
      "y" { 
      
        \\live.sysinternals.com\tools\sigcheck64.exe -tuv -nobanner
      
      } "N" {Break}   }}  until ($UserStoreQ -eq "y" -or $UserStoreQ -eq "N")



      

      # List valid certificates not rooted to the Microsoft Certificate Trust List in the Machine store
    do { $MachineStoreQ= $(write-host "List valid certificates not rooted to the Microsoft Certificate Trust List in the Machine store ? Enter Y for Yes or N for No" -ForegroundColor Cyan; Read-Host)
    switch ($MachineStoreQ) {   
    "y" { 

      \\live.sysinternals.com\tools\sigcheck64.exe -tv -nobanner

    } "N" {Break}   }}  until ($MachineStoreQ -eq "y" -or $MachineStoreQ -eq "N")









    }  "N" {Break}   }}  until ($CertCheckQuestion -eq "y" -or $CertCheckQuestion -eq "N")
# =========================================================================================================================
# ====================================================End of Certificate Checking Commands=================================
# =========================================================================================================================






# =========================================================================================================================
# ====================================================Country IP Blocking==================================================
# =========================================================================================================================
do { $CountryIPBlockingQuestion = $(write-host "Run Country IP Blocking section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($CountryIPBlockingQuestion) {   
    "y" {  




# -RemoteAddress in New-NetFirewallRule accepts array according to Microsoft Docs, 
# so we use "[string[]]$IPList = $IPList -split '\r?\n' -ne ''" to convert the IP lists, which is a single multiline string, into an array

function BlockCountryIP {
    param ($IPList , $CountryName)

    # checks if the rule is present and if it is, deletes them to get new up-to-date IP ranges from the sources
    if (Get-NetFirewallRule -DisplayName "$CountryName IP range blocking" 2> $null) 
    {Remove-NetFirewallRule -DisplayName "$CountryName IP range blocking" }

    # converts the list which is in string into array
    [string[]]$IPList = $IPList -split '\r?\n' -ne ''

    # makes sure the list isn't empty
    if ($IPList.count -eq 0) { Write-Host "The IP list was empty, skipping $CountryName" -ForegroundColor Yellow ; break }

      
    New-NetFirewallRule -DisplayName "$CountryName IP range blocking" -Direction Inbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$CountryName IP range blocking" -Profile Any -InterfaceType Any -Group "Hardening-Script-CountryIP-Blocking" -EdgeTraversalPolicy Block
    New-NetFirewallRule -DisplayName "$CountryName IP range blocking" -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$CountryName IP range blocking" -Profile Any -InterfaceType Any -Group "Hardening-Script-CountryIP-Blocking" -EdgeTraversalPolicy Block
        
}




# Iran
do { $BlockIranIP = $(write-host "Block the entire range of IPv4 and IPv6 belonging to Iran? Enter Y for Yes or N for No" -ForegroundColor DarkCyan ; Read-Host)
    switch ($BlockIranIP) {   
    "y" {  
    
    $IranIPv4 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone"
    $IranIPv6 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ir.zone"
    $IranIPRange = $IranIPv4 + $IranIPv6
    BlockCountryIP -IPList $IranIPRange -CountryName "Iran"

}"N" {Break}   }}  until ($BlockIranIP -eq "y" -or $BlockIranIP -eq "N")




# Cuba
do { $BlockCubaIP = $(write-host "Block the entire range of IPv4 and IPv6 belonging to Cuba? Enter Y for Yes or N for No" -ForegroundColor DarkCyan ; Read-Host)
    switch ($BlockCubaIP) {   
    "y" {  

    $CubaIPv4 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipblocks/data/aggregated/cu-aggregated.zone"
    $CubaIPv6 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipv6/ipaddresses/blocks/cu.zone"
    $CubaIPRange = $CubaIPv4 + $CubaIPv6
    BlockCountryIP -IPList $CubaIPRange -CountryName "Cuba"

}"N" {Break}   }}  until ($BlockCubaIP -eq "y" -or $BlockCubaIP -eq "N")




# North Korea
do { $BlockNorthKoreaIP = $(write-host "Block the entire range of IPv4 and IPv6 belonging to North Korea? Enter Y for Yes or N for No" -ForegroundColor DarkCyan ; Read-Host)
    switch ($BlockNorthKoreaIP) {   
    "y" {  
    
    $NorthKoreaIPv4 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipblocks/data/aggregated/kp-aggregated.zone"
    $NorthKoreaIPv6 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipv6/ipaddresses/blocks/kn.zone"
    $NorthKoreaIPRange = $NorthKoreaIPv4 + $NorthKoreaIPv6
    BlockCountryIP -IPList $NorthKoreaIPRange -CountryName "North Korea"

}"N" {Break}   }}  until ($BlockNorthKoreaIP -eq "y" -or $BlockNorthKoreaIP -eq "N")



# Syria
do { $BlockSyriaIP = $(write-host "Block the entire range of IPv4 and IPv6 belonging to Syria? Enter Y for Yes or N for No" -ForegroundColor DarkCyan ; Read-Host)
    switch ($BlockSyriaIP) {   
    "y" {  
    
    $SyriaIPv4 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipblocks/data/aggregated/sy-aggregated.zone"
    $SyriaIPv6 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipv6/ipaddresses/blocks/sy.zone"
    $SyriaIPRange = $SyriaIPv4 + $SyriaIPv6
    BlockCountryIP -IPList $SyriaIPRange -CountryName "Syria"

}"N" {Break}   }}  until ($BlockSyriaIP -eq "y" -or $BlockSyriaIP -eq "N")



# how to query the number of IPs in each rule
# (Get-NetFirewallRule -DisplayName "Cuba IP range blocking" | Get-NetFirewallAddressFilter).RemoteAddress.count





        

    }"N" {Break}   }}  until ($CountryIPBlockingQuestion -eq "y" -or $CountryIPBlockingQuestion -eq "N")
# =========================================================================================================================
# ====================================================End of Country IP Blocking===========================================
# =========================================================================================================================






} # End of Admin test function



# =========================================================================================================================
# ====================================================Non-Admin Commands===================================================
# =========================================================================================================================
do { $NonAdminQuestion= $(write-host "Run Non-Admin section? Enter Y for Yes or N for No" -ForegroundColor Magenta; Read-Host)
    switch ($NonAdminQuestion) {   
    "y" { 


# Show known file extensions in File explorer
ModifyRegistry -RegPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -RegName 'HideFileExt' -RegValue '0'

# Show hidden files, folders and drives (toggles the control panel folder options item)
ModifyRegistry -RegPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -RegName 'Hidden' -RegValue '1'

# Disable websites accessing local language list
ModifyRegistry -RegPath 'HKCU:\Control Panel\International\User Profile' -RegName 'HttpAcceptLanguageOptOut' -RegValue '1'

# turn off safe search in Windows search. from Windows settings > privacy and security > search permissions > safe search
ModifyRegistry -RegPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings' -RegName 'SafeSearchMode' -RegValue '0'

# prevent showing notifications in Lock screen - this is the same as toggling the button in Windows settings > system > notifications > show notifications in the lock screen
ModifyRegistry -RegPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' -RegName 'NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK' -RegValue '0'

# prevent showing notifications in Lock screen, 2nd reg key - this is the same as toggling the button in Windows settings > system > notifications > show notifications in the lock screen
ModifyRegistry -RegPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -RegName 'LockScreenToastEnabled' -RegValue '0'

# Enable Clipboard History for the current user
ModifyRegistry -RegPath 'HKCU:\Software\Microsoft\Clipboard' -RegName 'EnableClipboardHistory' -RegValue '1'

# 2 commands to enable sync of Clipboard history in Windows between devices
ModifyRegistry -RegPath 'HKCU:\Software\Microsoft\Clipboard' -RegName 'CloudClipboardAutomaticUpload' -RegValue '1'

# last one, to enable Clipboard sync
ModifyRegistry -RegPath 'HKCU:\Software\Microsoft\Clipboard' -RegName 'EnableCloudClipboard' -RegValue '1'




# creates Custom Views for Event Viewer in "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\"
# Event Viewer custom views are saved in "C:\ProgramData\Microsoft\Event Viewer\Views". files in there can be backed up and restored on new Windows installations.

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
ModifyRegistry -RegPath 'HKCU:\Software\Microsoft\Input\Settings' -RegName 'EnableHwkbTextPrediction' -RegValue '1'

# turn on "Multilingual text suggestions" for the current user, toggles the option in Windows settings
ModifyRegistry -RegPath 'HKCU:\Software\Microsoft\Input\Settings' -RegName 'MultilingualEnabled' -RegValue '1'

# turn off sticky key shortcut of pressing shift key 5 time fast - value is type string, can't use ModifyRegistry Function
$RegistryPath = 'HKCU:\Control Panel\Accessibility\StickyKeys'  
$Name         = 'Flags'  
$Value        = '506' 
If (-NOT (Test-Path $RegistryPath)) {   New-Item -Path $RegistryPath -Force | Out-Null } 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType string -Force





}
"N" {Break}   }}  until ($NonAdminQuestion -eq "y" -or $NonAdminQuestion -eq "N")
# =========================================================================================================================
# ====================================================End of Non-Admin Commands============================================
# =========================================================================================================================

Write-Host "T" -ForegroundColor Green -NoNewline;
Write-Host "H" -ForegroundColor Yellow -NoNewline;
Write-Host "E " -ForegroundColor Blue -NoNewline;
Write-Host "E" -ForegroundColor Red -NoNewline;
Write-Host "N" -ForegroundColor Magenta -NoNewline;
Write-Host "D" -ForegroundColor Cyan ;
