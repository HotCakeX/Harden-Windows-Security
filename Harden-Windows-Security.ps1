 <#PSScriptInfo

.VERSION 2022.12.26.2

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
#>

<# 

.SYNOPSIS
    Harden Windows 11 safely, securely and without breaking anything

.DESCRIPTION

Features of this Hardening script:

 -Always up-to-date and works with latest build of Windows (Currently Windows 11 - compatible and fully tested a Lot on stable and Insider Dev builds)
 -Doesn't break anything
 -Doesn't remove or disable Windows functionlities against Microsoft's recommendation
 -Above each command there are comments that explain what it does, why it's there, provide extra important information about it and links to additional resources for better understanding
 -When a hardening command is no longer necessary because it's applied by default by Microsoft on new builds of Windows, it will also be removed from this script in order to prevent any problems and because it won't be necessary anymore.
 -The script can be run infinite number of times, it's made in a way that it won't make any duplicate changes at all.



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
 Commands that don't require Administrator Privileges
  -Non-Admin Commands that only affect the current user and do not make machine-wide changes.




🎯 if you have any questions, requests, suggestions etc. about this script, please open a new discussion in Github:

https://github.com/HotCakeX/Harden-Windows-Security/discussions

.EXAMPLE

  
   type: "Set-ExecutionPolicy Bypass -Scope Process" without quotes, in an Elevated PowerShell, to allow running this script for the current session.
   
.NOTES
    When the script is running as Admin, please keep an eye on the PowerShell console because you might need to provide input for Bitlocker activation if it's not already set up with Startup-key key protector.

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

# https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps 
  


# Indicates whether to scan for malicious and unwanted software in removable drives, such as flash drives, during a full scan.
Set-MpPreference -DisableRemovableDriveScanning 0


<# Specifies whether to enable file hash computation. When this feature is enabled, Windows Defender computes hashes for files it scans.
 In Windows 10 2004, Microsoft Defender Antivirus provides a new setting known as 'Enable file hash computation feature'
 designed to allow admins to force the anti-malware solution to "compute file hashes for every executable file that is scanned
 if it wasn't previously computed" to "improve blocking for custom indicators in Microsoft Defender Advanced Threat Protection (Microsoft Defender ATP). #>
Set-MpPreference -efhc 1 


# good source of info: https://answers.microsoft.com/en-us/protect/forum/all/windows-defender/e23367ac-e99c-48f5-8b11-68a3fa0abff7
# increases level of Cloud Protection - this sets it to 6 which is currently the highest possible
Set-MpPreference -CloudBlockLevel ZeroTolerance


# This increases the allotted analysis time to max:
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
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/network-protection?view=o365-worldwide#optimizing-network-protection-performance
Set-MpPreference -AllowSwitchToAsyncInspection $True



# =========================================================================================================================
# =========================================End of Windows Security aka Defender============================================
# =========================================================================================================================





<#  JUST AN IDEA:
add all drives to the Controlled Folder Access using Windows Defender GUI. (probably not do this because then have to allow so many default Microsoft programs too)
we can add multiple exlusions to the Controlled Folder Access allowed apps list using this command:
Set-MpPreference -ControlledFolderAccessAllowedApplications 'C:\Program Files\App\app.exe','C:\Program Files\App2\app2.exe'
we can get a list of all allowd apps using this command:
$(get-MpPreference).ControlledFolderAccessAllowedApplications
then we can use it in this powershell script so we add all the apps automatically to exlusion list of Controlled Folder Acess on new Windows installations.
#>






# =========================================================================================================================
# ==========================================Attack surface reduction rules=================================================
# =========================================================================================================================

# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide






# ASR Rules, All 16 available rules are set to Enabled which means Block, except for 1 tagged with #TopSecurity
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
# Block executable files from running unless they meet a prevalence, age, or trusted list criteria #TopSecurity set to AuditMode 
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-faq?view=o365-worldwide#i-enabled-the-asr-rule---block-executable-files-from-running-unless-they-meet-a-prevalence--age--or-trusted-list-criterion---after-some-time--i-updated-a-piece-of-software--and-the-rule-is-now-blocking-it--even-though-it-didn-t-before--did-something-go-wrong-
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




# =========================================================================================================================
# =========================================End of Attack surface reduction rules===========================================
# =========================================================================================================================







# =========================================================================================================================
# ==========================================Bitlocker Settings=============================================================
# =========================================================================================================================



<#
 BitLocker software will bring you a real security against the theft of your computer if you strictly abide by the following basic rule:
 As soon as you have finished working, completly shut Windows down and allow for every shadow of information to disappear
 (from RAM, disk caches) within 2 minutes.
#>

# Bitlocker Drive Encryption settings: setting the encryption algorithm and cipher options
# https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures


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


<#
Bitlocker Group policy settings:
https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings

System compatibility Warning
https://learn.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt#system-compatibility


"To see if a system supports Kernel DMA Protection, check the System Information desktop app (MSINFO32).
Systems released prior to Windows 10 version 1803 do not support Kernel DMA Protection,
but they can leverage other DMA attack mitigations as described in BitLocker countermeasures."


"Kernel DMA Protection is not compatible with other BitLocker DMA attacks countermeasures.
It is recommended to disable the BitLocker DMA attacks countermeasures if the system supports Kernel DMA Protection.
Kernel DMA Protection provides higher security bar for the system over the BitLocker DMA attack countermeasures,
while maintaining usability of external peripherals."


in short, if your hardware is old and System Information shows Kernel DMA protection is off, use Bitlocker DMA protection from the command below.
but if System Information shows Kernel DMA protection is on, do not run the command below and if already run, set it in group policy to Not Configured state.


https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-kernel-dma-protection
*these requirements such as VT-X and VT-D support can be found in Inte's CPU product page,
e.g. https://www.intel.com/content/www/us/en/products/sku/134594/intel-core-i712700k-processor-25m-cache-up-to-5-00-ghz/specifications.html

to have VBS and Kernel protection, in Intel CPUs, from UEFI,
turn on Intel Virtualization features and also turn on VT-d (Intel Virtualization Technology for Directed I/O)



Disable new DMA devices when this computer is locked
#> 
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -RegName 'DisableExternalDMAUnderLock' -RegValue '1'


# Disallow standard users from changing the Bitlocker Startup PIN or password
# this is complementary for the Bitlocker activation and verification script below to work properly
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




# =========================================================================================================================
# ==========================================End of Bitlocker Settings======================================================
# =========================================================================================================================





# =========================================================================================================================
# ==============================================TLS Security===============================================================
# =========================================================================================================================


<#

Resources used:

https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-
These registry settings only affect things that use schannel: that includes Edge, IIS, built-in inbox Windows apps, posh and vbscript(!), I'd expect but can't verify Outlook, the curl.exe supplied by Microsoft,
, but not Chrome, Firefox, other programs that use portable stacks like Java nodejs python php, and anything in wsl.
these portable stacks are:

Example of portable TLS stacks used in 3rd party programs: OpenSSL/SSLeay (plus forks LibreSSL and BoringSSL), NSS and GnuTLS are written in C,
and JSSE and BouncyCastle in Java, and are widely available and used on at least all Linux (usually other Unix also) and Windows.
MbedTLS/PolarSSL Wolf/CyaSSL and BearSSL

  https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations#Portability_concerns


  https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-schannel/ba-p/259233


  https://dirteam.com/sander/2019/07/30/howto-disable-weak-protocols-cipher-suites-and-hashing-algorithms-on-web-application-proxies-ad-fs-servers-and-windows-servers-running-azure-ad-connect/

  #>

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
# https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-11
Enable-TlsCipherSuite -Name "TLS_CHACHA20_POLY1305_SHA256" -Position 0





# disabling weak cipher suites
# https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices

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





# =========================================================================================================================
# ==========================================End of TLS Security============================================================
# =========================================================================================================================





# =========================================================================================================================
# ==============================================Lock Screen================================================================
# =========================================================================================================================




# Automatically lock computer after X seconds, set to 120 seconds in this command.
# https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'InactivityTimeoutSecs' -RegValue '120'


# https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-do-not-require-ctrl-alt-del
# forces CAD requirement, CTRL + ALT + DELETE at Windows Lock screen to be pressed to show sign in fields
# Interactive logon: Do not require CTRL+ALT+DEL - when set to '0', CAD is required
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'DisableCAD' -RegValue '0'


# https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-account-lockout-threshold
# The security setting allows you to set a threshold for the number of failed sign-in attempts that causes the device to be locked by using BitLocker.
# This threshold means, if the specified maximum number of failed sign-in attempts is exceeded,
# the device will invalidate the Trusted Platform Module (TPM) protector and any other protector
# except the 48-digit recovery password, and then reboot. During Device Lockout mode,
# the computer or device only boots into the touch-enabled Windows Recovery Environment (WinRE) until an authorized user enters the recovery password to restore full access.
# it can provide security against brute force methods
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'MaxDevicePasswordFailedAttempts' -RegValue '6'


# https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-display-user-information-when-the-session-is-locked
# https://www.itsecdb.com/oval/definition/oval/gov.nist.3/def/5002/Interactive-logon-Display-user-information-when-the-session.html
# hides email address of the Microsoft account on lock screen
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'DontDisplayLockedUserId' -RegValue '3'


# If the policy is enabled and a user signs in as Other user, the full name of the user is not displayed during sign-in.
# In the same context, if users type their email address and password at the sign in screen and press Enter,
# the displayed text "Other user" remains unchanged, and is no longer replaced by the user's first and last name
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'DontDisplayUserName' -RegValue '1'


# https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-do-not-display-last-user-name
# Don't display last signed-in: this will stop showing Any info about Windows accounts; users need to manually enter username and password/Pin to sign in #TopSecurity could causes annoyance - Disabled here - to enable it, change it to 1
# this can be useful to enable if you live in a risky place and you don't want people to get any information about your computer when it's locked and you're not around
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'dontdisplaylastusername' -RegValue '0'





# =========================================================================================================================
# ==============================================End of Lock Screen=========================================================
# =========================================================================================================================




# =========================================================================================================================
# ==============================================UAC (User Account Control)=================================================
# =========================================================================================================================






# https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#registry-key-settings
# The following 3 changes harden UAC and set its slider in control panel beyond what's available in there.
# setting it to 1 asks for Admin credentials, setting it to 2 asks for Accept/Deny for Admin tasks in Admin account.
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'ConsentPromptBehaviorAdmin' -RegValue '1'


# Next one - this automatically denies all UAC prompts on Standard accounts when set to "0". not enabled here #topSecurity
# good for forcing log out of Standard account and logging in Admin account to perform actions,
# or switching to Admin account to perform elevated task. 1 = Prompt for credentials on the secure desktop 
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'ConsentPromptBehaviorUser' -RegValue '1'


# Enforce cryptographic signatures on any interactive application that requests elevation of privilege.
# it can prevent certain programs from running, e.g. it prevents Cheat Engine from prompting for UAC
# here is set to 0, only set it to 1 for #TopSecurity
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'ValidateAdminCodeSignatures' -RegValue '0'


# Don't show network (like WiFi) icon on lock screen
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -RegName 'DontDisplayNetworkSelectionUI' -RegValue '1'




# =========================================================================================================================
# ============================================End of UAC (User Account Control)============================================
# =========================================================================================================================





# =========================================================================================================================
# ======================================================Device Guard=======================================================
# =========================================================================================================================




<# source: https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity  #>


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


<#
More Device Guard info:
https://www.bsi.bund.de/EN/Service-Navi/Publikationen/Studien/SiSyPHuS_Win10/AP7/SiSyPHuS_AP7_node.html
https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Cyber-Sicherheit/SiSyPHus/E20172000_BSI_Win10_DGABGL_Win10_v_1_0.pdf?__blob=publicationFile&v=3



there are more settings available in Group Policy Device Guard section that these modifications do Not enable,
because I don't know if your hardware is modern to support them, so provided resources below to check them out and enable them if you wish.


1. Secure Launch:
https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/how-hardware-based-root-of-trust-helps-protect-windows#secure-launchthe-dynamic-root-of-trust-for-measurement-drtm
https://www.microsoft.com/en-us/security/blog/2020/09/01/force-firmware-code-to-be-measured-and-attested-by-secure-launch-on-windows-10

2. Require UEFI Memory Attributes Table"
https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/unified-extensible-firmware-interface

3. Kernel Mode Hardware Enforced Stack Protection
https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-version-22h2-security-baseline/ba-p/3632520

#>


# =========================================================================================================================
# ====================================================End of Device Guard==================================================
# =========================================================================================================================






# =========================================================================================================================
# ====================================================Windows Firewall=====================================================
# =========================================================================================================================

<#
Block LOLBins from making Internet connections
 
LOLBins are Microsoft-signed files, meaning they are either native to the Operating System (OS) and come pre-installed,
or are available from Microsoft (i.e. a Microsoft program or add-on).
Despite being legitimate (and well-intentioned) files,
these binaries can be exploited by an attacker and used in an attack.

https://blog.teamascend.com/lolbins

this website also lists them as well: https://lolbas-project.github.io
THESE COMMANDS CHECK IF THE RULE ALREADY EXISTS BEFORE ADDING THEM TO WINDOWS FIREWALL
https://stackoverflow.com/questions/6597951/how-can-you-check-for-existing-firewall-rules-using-powershell
#>



# make sure Firewall for all 3 profiles is enabled
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True


# set inbound and outbound default actions for Domain Firewall Profile to Block
Set-NetFirewallProfile -Name Domain -DefaultInboundAction Block -DefaultOutboundAction Block



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





# Enable Windows Firewall logging for Private and Public profiles, set the log file size to max 32.767 MB, log only dropped packets.
Set-NetFirewallProfile -Name private, Public -LogBlocked True -LogMaxSizeKilobytes 32767 -LogFileName %systemroot%\system32\LogFiles\Firewall\pfirewall.log






<#

 Setting Edge Traversal policy for All Firewall rules to Block (only inbound rules have that) 

 https://learn.microsoft.com/en-us/windows/win32/teredo/receiving-unsolicited-traffic-over-teredo

 UDP is a stateless protocol; blocking all traffic would block, for instance, inbound replies to DNS requests made by your server.

 Windows Firewall is Stateful https://geekflare.com/stateful-vs-stateless-firewalls/

 https://serverfault.com/questions/342985/what-is-solicited-network-traffic-and-what-is-unsolicited-network-traffic?newreg=e2271f0f1a2448d4bd772d686ff98f48


How Windows Firewall Works

this link also has explanation about IPSec policy which is accessible through MSC (Microsoft Management Console)

https://learn.microsoft.com/en-us/previous-versions//bb727017(v=technet.10)?redirectedfrom=MSDN#how-windows-firewall-works


https://superuser.com/questions/923937/how-does-my-computers-firewall-work-like-inbound-rule-outbound-rule-reply


https://security.stackexchange.com/a/106585

#>

Get-NetFirewallRule | Where-Object {$_.EdgeTraversalPolicy -notmatch "Block"} | ForEach-Object { Set-NetFirewallRule -Name $_.Name -EdgeTraversalPolicy Block}

$badrules = Get-NetFirewallRule | Where-Object {$_.EdgeTraversalPolicy -notmatch "Block"}

Write-Host "There are currently" $badrules.count "Firewall rules that allow Edge Traversal" -ForegroundColor Magenta





# =========================================================================================================================
# =================================================End of Windows Firewall=================================================
# =========================================================================================================================






# =========================================================================================================================
# =================================================Optional Windows Features===============================================
# =========================================================================================================================





if ($PSVersionTable.PSVersion.Major,$PSVersionTable.PSVersion.Minor -join "." -gt 5.1)


# since PowerShell Core (only if installed from Microsoft Store) has problem with these commands, letting the built-in PowerShell handle them
# There are Github issues for it already: https://github.com/PowerShell/PowerShell/issues/13866


{ 

# Disable PowerShell v2 (needs 2 commands) - because it's old and doesn't support AMSI: https://devblogs.microsoft.com/powershell/powershell-the-blue-team/#antimalware-scan-interface-integration
# https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/ 
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart}else{Write-Host 'MicrosoftWindowsPowerShellV2 is already disabled' -ForegroundColor Magenta}"
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart}else{Write-Host 'MicrosoftWindowsPowerShellV2Root is already disabled' -ForegroundColor Magenta}"

# Disable Work Folders client, not used when your computer is not part of a domain or enterprise network
# https://learn.microsoft.com/en-us/windows-server/storage/work-folders/work-folders-overview
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -norestart}else{Write-Host 'WorkFolders-Client is already disabled' -ForegroundColor Magenta}"

# Disable Internet Printing Client, used in combination with IIS web server, old feature, can be disabled without causing problems further down the road
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/printing/manage-connect-printers-use-web-browser
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features -norestart}else{Write-Host 'Printing-Foundation-Features is already disabled' -ForegroundColor Magenta}"

# Disable Windows Media Player (legacy)
# isn't needed anymore, Windows 11 has modern media player app. everything, including connecting phone to computer and importing photos etc., works after disabling it
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -norestart}else{Write-Host 'WindowsMediaPlayer is already disabled' -ForegroundColor Magenta}"


# Enable Windows Defender Application Guard
# which is a safe environment to open untrusted websites safely
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -norestart}else{Write-Host 'Windows-Defender-ApplicationGuard is already enabled' -ForegroundColor Magenta}"

# Enable Windows Sandbox
# install, test and use programs in a disposable virtual operation system, completely separate from your main OS
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -norestart}else{Write-Host 'Containers-DisposableClientVM (Windows Sandbox) is already enabled' -ForegroundColor Magenta}"

# Enable Hyper-V
# the best hypervisor to run virtual machines on
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -norestart}else{Write-Host 'Microsoft-Hyper-V is already enabled' -ForegroundColor Magenta}"

# Enable Virtual Machine Platform
# required for Android subsystem or WSA (Windows subsystem for Android). if it's disabled, it will be automatically enabled either way when you try to install WSA from Store app
PowerShell.exe "if((get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -norestart}else{Write-Host 'VirtualMachinePlatform is already enabled' -ForegroundColor Magenta}"


}

else {

    # Disable PowerShell v2 (needs 2 commands) - because it's old and doesn't support AMSI: https://devblogs.microsoft.com/powershell/powershell-the-blue-team/#antimalware-scan-interface-integration
# https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/ 
 if((get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart}else{Write-Host 'MicrosoftWindowsPowerShellV2 is already disabled' -ForegroundColor Magenta}
 if((get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart}else{Write-Host 'MicrosoftWindowsPowerShellV2Root is already disabled' -ForegroundColor Magenta}

# Disable Work Folders client, not used when your computer is not part of a domain or enterprise network
# https://learn.microsoft.com/en-us/windows-server/storage/work-folders/work-folders-overview
 if((get-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -norestart}else{Write-Host 'WorkFolders-Client is already disabled' -ForegroundColor Magenta}

# Disable Internet Printing Client, used in combination with IIS web server, old feature, can be disabled without causing problems further down the road
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/printing/manage-connect-printers-use-web-browser
 if((get-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features -norestart}else{Write-Host 'Printing-Foundation-Features is already disabled' -ForegroundColor Magenta}

# Disable Windows Media Player (legacy)
# isn't needed anymore, Windows 11 has modern media player app. everything, including connecting phone to computer and importing photos etc., works after disabling it
 if((get-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -norestart}else{Write-Host 'WindowsMediaPlayer is already disabled' -ForegroundColor Magenta}


# Enable Windows Defender Application Guard
# which is a safe environment to open untrusted websites safely
 if((get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -norestart}else{Write-Host 'Windows-Defender-ApplicationGuard is already enabled' -ForegroundColor Magenta}

# Enable Windows Sandbox
# install, test and use programs in a disposable virtual operation system, completely separate from your main OS
 if((get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -norestart}else{Write-Host 'Containers-DisposableClientVM (Windows Sandbox) is already enabled' -ForegroundColor Magenta}

# Enable Hyper-V
# the best hypervisor to run virtual machines on
 if((get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -norestart}else{Write-Host 'Microsoft-Hyper-V is already enabled' -ForegroundColor Magenta}

# Enable Virtual Machine Platform
# required for Android subsystem or WSA (Windows subsystem for Android). if it's disabled, it will be automatically enabled either way when you try to install WSA from Store app
if((get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -norestart}else{Write-Host 'VirtualMachinePlatform is already enabled' -ForegroundColor Magenta}



        
}




# =========================================================================================================================
# ==============================================End of Optional Windows Features===========================================
# =========================================================================================================================








# =========================================================================================================================
# ====================================================Windows Networking===================================================
# =========================================================================================================================




# disable NetBIOS over TCP/IP on all network interfaces, virtual and physical. need to run it every time after installing a new VPN software or network adapater, virtual or physical.
# https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-netbt-interfaces-interface-netbiosoptions
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |ForEach-Object { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 }


# disable the LLMNR protocol on a Windows
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient  -Force
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value 0 -PropertyType DWORD  -Force


# disable LMHOSTS lookup protocol on all network adapters
# the reason why we do this: https://www.crowe.com/cybersecurity-watch/netbios-llmnr-giving-away-credentials
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -RegName 'EnableLMHOSTS' -RegValue '0'


# Set the Network Location of all connections to Public (or Private)
# Public network means less trust to the nearby devices
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Public


<# Disable Printing over HTTP
https://www.stigviewer.com/stig/microsoft_windows_server_2012_member_server/2013-07-25/finding/WN12-CC-000039
https://www.windows-security.org/6a6bdc56768622d3fd84f1719d330d12/turn-off-printing-over-http
#>
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -RegName 'DisableHTTPPrinting' -RegValue '1'

# Turn off downloading of print drivers over HTTP
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -RegName 'DisableWebPnPDownload' -RegValue '1'

# Disable Multicast DNS
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -RegName 'EnableMulticast' -RegValue '0'


<# Turn off smart multi-homed name resolution in Windows

While the feature makes sense from a performance point of view, it introduces an issue from a privacy one.
If you connect to a VPN network on a Windows machine for instance, smart multi-homed name resolution may lead to DNS leakage.
Since requests are sent out to all network adapters at the same time,
all configured DNS servers receive the requests and with them information on the sites that you visit. 
https://www.windows-security.org/2718dc40b3ecea129213e7eca29b7357/turn-off-smart-multi-homed-name-resolution
#>
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -RegName 'DisableSmartNameResolution' -RegValue '1'


<# The value is 1 to disable DNS A and AAAA queries from executing in parallel on all configured DNS servers,
with the fastest response being theoretically accepted first.
benefits of disabling this are the same as "DisableSmartNameResolution" #>
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -RegName 'DisableParallelAandAAAA' -RegValue '1'

<# Disable IP Source Routing
https://www.curvesandchaos.com/what-is-disableipsourcerouting/

After applying this and restarting computer, "Source Routing Behavior" in "netsh int IPv4 show global" shows "Drop"
which is what the value "2" does.
#>
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -RegName 'DisableIPSourceRouting' -RegValue '2'


<# https://support.microsoft.com/en-us/topic/security-configuration-guidance-support-ea9aef24-347f-15fa-b94f-36f967907f2f
Allow the computer to ignore NetBIOS name release requests.
This setting is a good preventive measure for denial of service attacks against name servers and other very important server roles.
#>
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters' -RegName 'NoNameReleaseOnDemand' -RegValue '1'

# Disable TCP timestamping
# https://www.kicksecure.com/wiki/Disable_TCP_and_ICMP_Timestamps
netsh int tcp set global timestamps=disabled




# =========================================================================================================================
# =================================================End of Windows Networking===============================================
# =========================================================================================================================







# =========================================================================================================================
# ==============================================Miscellaneous Configurations===============================================
# =========================================================================================================================





# Enable early launch antimalware driver for scan of boot-start drivers
# 3 is the default which allows good, unknown and 'bad but critical'.
# 1 is for 'good and unknown' , 8 is for 'good only', used in this command
# https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220813
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -RegName 'DriverLoadPolicy' -RegValue '8'

# Disable Location services from Windows - affects Windows settings privacy section
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -RegName 'DisableLocation' -RegValue '1'

# Enable Hibernate
powercfg /hibernate on

# Set Hibnernate mode to full, more info: https://learn.microsoft.com/en-us/windows/win32/power/system-power-states#hibernation-file-types
powercfg /h /type full

# Add Hibernate option to Start menu's power options
ModifyRegistry -RegPath 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' -RegName 'ShowHibernateOption' -RegValue '1'


<# Disable Sleep (Power states S1-S3) - doing this also removes the Sleep option from Start menu and even using commands to put the computer to sleep won't work.
 https://learn.microsoft.com/en-us/windows/win32/power/system-power-states#sleep-state-s1-s3
 also is suggested to disable it for Bitlocker protection at the bottom of this page: 
 https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures#attacker-with-skill-and-lengthy-physical-access
 2 registry keys are required for disabling Sleep.
 how the relevant registry keys were found: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.PowerManagement::AllowStandbyStatesDC_2
 computer restart is required for the changes to take effect
#>

# Disable sleep for when plugged in
ModifyRegistry -RegPath 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab' -RegName 'ACSettingIndex' -RegValue '0'

# Disable sleep for when on battery
ModifyRegistry -RegPath 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab' -RegName 'DCSettingIndex' -RegValue '0'


# Enable Mandatory ASLR, there are more options in this official chart:
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-exploit-protection?view=o365-worldwide
set-processmitigation -System -Enable ForceRelocateImages

# You can add Mandatory ASLR override for a trusted program using the command below or in the Program Settings section of Exploit Protection in Windows Defender app. 
# Set-ProcessMitigation -Name "D:\trustedProgram.exe" -Disable ForceRelocateImages


# Enable svchost.exe mitigation options - more info: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-servicecontrolmanager
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SCMConfig' -RegName 'EnableSvchostMitigationPolicy' -RegValue '1'


# Set Power Plan to "Ultimate Performance". replace it with "High Performance" if wanted.
$p = Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -Filter "ElementName = 'Ultimate Performance'"      
powercfg /setactive ([string]$p.InstanceID).Replace("Microsoft:PowerPlan\{","").Replace("}","")


# Turn on Enhanced mode search for Windows indexer. the default is classic mode.
# this causes some UI elements in the search settings in Windows settings to become unavailable for Standard users to view.
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows Search' -RegName 'EnableFindMyFiles' -RegValue '1'


# https://posts.specterops.io/remote-code-execution-via-path-traversal-in-the-device-metadata-authoring-wizard-a0d5839fc54f
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
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' -RegName 'AddPrinterDrivers' -RegValue '1'


# Forces Installer NOT to use elevated privileges during installs by default, which prevents escalation of privileges vulnerabilities and attacks
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -RegName 'AlwaysInstallElevated' -RegValue '0'


# Enable SMB/LDAP Signing
# Sources:  http://eddiejackson.net/wp/?p=15812  and https://en.hackndo.com/ntlm-relay/ 
ModifyRegistry -RegPath 'HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters' -RegName 'RequireSecuritySignature' -RegValue '1'
ModifyRegistry -RegPath 'HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters' -RegName 'EnableSecuritySignature' -RegValue '1'
ModifyRegistry -RegPath 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters' -RegName 'RequireSecuritySignature' -RegValue '1'
ModifyRegistry -RegPath 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters' -RegName 'EnableSecuritySignature' -RegValue '1'



# Disable "Use my sign in info to automatically finish setting up after an update".
# when this option is enabled (default value), and the everyday account is Standard, it causes the other admin account to be
# automatically signed into and in the lock screen when logging into Standard account, you have to double sign in, asks twice for the Windows Pin.
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -RegName 'DisableAutomaticRestartSignOn' -RegValue '1'


# Set Microsoft Edge to update over Metered connections - toggles the button in edge://settings/help
# These updates are very important, shouldn't let anything suppress them
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientStateMedium\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' -RegName 'allowautoupdatesmetered' -RegValue '1'


# Download Windows Updates over metered connections - responsible for the toggle in Windows settings => Windows Update => Advanced options
# These updates are very important, shouldn't let anything suppress them
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -RegName 'AllowAutoWindowsUpdateDownloadOverMeteredNetwork' -RegValue '1'


# Enable notify me when a restart is required to finish updating - responsible for the toggle in Windows settings => Windows Update => Advanced options
ModifyRegistry -RegPath 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -RegName 'RestartNotificationsAllowed2' -RegValue '1'


# Allow all Windows users to use Hyper-V and Windows Sandbox by adding all Windows users to the "Hyper-V Administrators" security group
$usernames = Get-LocalUser | Where-Object{$_.enabled -EQ "True"} | Select-Object "Name"
$usernames | ForEach-Object {

try { Add-LocalGroupMember -Group "Hyper-V Administrators" -Member $_.Name -ErrorAction Stop  }
 catch {  write-host "user account is already part of the Hyper-V Administrators group `n" -ForegroundColor Magenta } 
  }


# change Windows time sync interval from every 7 days to every 2 days (= every 172800 seconds)
ModifyRegistry -RegPath 'HKLM:\SYSTEM\ControlSet001\Services\W32Time\TimeProviders\NtpClient' -RegName 'SpecialPollInterval' -RegValue '172800'


# this was automatically turned on after clean installing Windows 11 insider Dev build 25267 but was set to "2" which is without UEFI lock, and that is expected according to this:
# https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#automatic-enablement
# Configure LSASS process to run as a protected process with UEFI Lock
# https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
# when this feature is on, a new option called "Local Security Authority Protection" appears in Windows Security GUI => Device Security => Core Isolation
ModifyRegistry -RegPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -RegName 'RunAsPPL' -RegValue '1'


# Add ECH (Encrypted Client Hello) to the Edge browser when it's launched by clicking on a link in an app
# https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-108/ba-p/3691250
$EdgeRegPath = "Registry::HKEY_CLASSES_ROOT\MSEdgeHTM\shell\open\command\"
$EdgeRegValue = Get-ItemPropertyValue -Path $EdgeRegPath -Name "(default)"


if ($EdgeRegValue -notlike "*--enable-features=EncryptedClientHello*")

{       # checks whether Edge Dev channel is the default browser
        if ($EdgeRegValue -like "*C:\Program Files (x86)\Microsoft\Edge Dev\Application\msedge.exe*")
        {
            Set-ItemProperty -Path $EdgeRegPath -Name "(default)" -Value '"C:\Program Files (x86)\Microsoft\Edge Dev\Application\msedge.exe" --enable-features=EncryptedClientHello --single-argument %1'
        }
        # checks whether Edge Beta channel is the default browser
        elseif ($EdgeRegValue -like "*C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe*")
        {
            Set-ItemProperty -Path $EdgeRegPath -Name "(default)" -Value '"C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe" --enable-features=EncryptedClientHello --single-argument %1'
        }
        # checks whether Edge Stable channel is the default browser
        elseif ($EdgeRegValue -like "*C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe*")
        {
            Set-ItemProperty -Path $EdgeRegPath -Name "(default)" -Value '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --enable-features=EncryptedClientHello --single-argument %1'
        }

}

else 
{
Write-Host "The ECH flag is Enabled for Edge" -ForegroundColor Magenta
}


# Add ECH flag to the target of Edge browser shortcuts (all channel) on desktop of all users
# https://stackoverflow.com/questions/484560/editing-shortcut-lnk-properties-with-powershell
$path = Get-ChildItem "C:\Users\Public\Desktop" | Where-Object {$_.Name -like "*Microsoft Edge*"} 
$shell = New-Object -COM WScript.Shell

$path | ForEach-Object {
$shortcut = $shell.CreateShortcut($_.FullName)  ## Open the lnk
$shortcut.Arguments = "--enable-features=EncryptedClientHello"
$shortcut.Save()  ## Save

}


# Add ECH flag to the target of Pinned Edge browser Start menu shortcuts (all channel) for all users
$path = Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs" | Where-Object {$_.Name -like "*Microsoft Edge*"} 
$shell = New-Object -COM WScript.Shell

$path | ForEach-Object {
$shortcut = $shell.CreateShortcut($_.FullName)  ## Open the lnk
$shortcut.Arguments = "--enable-features=EncryptedClientHello"
$shortcut.Save()  ## Save

}




} # End of Admin test function


# =========================================================================================================================
# ============================================End of Miscellaneous Configurations==========================================
# =========================================================================================================================






# =========================================================================================================================
# ====================================================Non-Admin Commands===================================================
# =========================================================================================================================



# Show known file extensions in File explorer
ModifyRegistry -RegPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -RegName 'HideFileExt' -RegValue '0'

# Show hidden files, folders and drives (toggles the control panel folder options item)
ModifyRegistry -RegPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -RegName 'Hidden' -RegValue '1'

# Disable websites accessing local language list - good for privacy
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
# these are important event logs that are tracked and organized into a folder called "Hardening Script", it can be checked when you open Event Viewer
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

# Set Windows Personalization, color settings, to enable Dark mode for System
ModifyRegistry -RegPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -RegName 'SystemUsesLightTheme' -RegValue '0'

# Set Windows Personalization, color settings, to enable Dark mode for Apps
ModifyRegistry -RegPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -RegName 'AppsUseLightTheme' -RegValue '0'


# Add ECH flag to the target of Pinned Taskbar Edge browser shortcuts (all channel) of the current user
# the rest of the ECH flag related commands are in the section where Admin privileges are required.
$path = Get-ChildItem "$home\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" | Where-Object {$_.Name -like "*Microsoft Edge*"} 
$shell = New-Object -COM WScript.Shell

$path | ForEach-Object {
$shortcut = $shell.CreateShortcut($_.FullName)  ## Open the lnk
$shortcut.Arguments = "--enable-features=EncryptedClientHello"
$shortcut.Save()  ## Save

}




# =========================================================================================================================
# ====================================================End of Non-Admin Commands============================================
# =========================================================================================================================

