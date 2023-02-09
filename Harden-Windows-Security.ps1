$infomsg = "`r`n" +
"#############################################################################################################`r`n" +
"###  Make Sure you've completely read what's written in the GitHub repository, before running this script ###`r`n" +
"#############################################################################################################`r`n"
Write-Host $infomsg -ForegroundColor Cyan

$infomsg = "`r`n" +
"###########################################################################################`r`n" +
"###  Link to the GitHub Repository: https://github.com/HotCakeX/Harden-Windows-Security ###`r`n" +
"###########################################################################################`r`n"
Write-Host $infomsg -ForegroundColor Green

# Set execution policy temporarily to bypass for the current PowerShell session only
Set-ExecutionPolicy Bypass -Scope Process

# check if user's OS is Windows Home edition
if (((Get-WmiObject Win32_OperatingSystem).OperatingSystemSKU) -eq "101") {
    Write-host "Windows Home edition detected, exiting..." -ForegroundColor Red
    break
}

#region Functions
# Questions function
function Select-Option {
    param(
        [parameter(Mandatory = $true, Position = 0)][string]$Message,
        [parameter(Mandatory = $true, Position = 1)][string[]]$Options
    )
    $Selected = $null
    while ($null -eq $Selected) {
        Write-Host $Message -ForegroundColor Magenta
        for ($i = 0; $i -lt $Options.Length; $i++) { Write-Host "$($i+1): $($Options[$i])" }
        $SelectedIndex = Read-Host "Select an option"
        if ($SelectedIndex -gt 0 -and $SelectedIndex -le $Options.Length) { $Selected = $Options[$SelectedIndex - 1] }
        else { Write-Host "Invalid Option." -ForegroundColor Yellow }
    }
    return $Selected
}

# Function to modify registry
function ModifyRegistry {
    param ($path, $key, $value, $type )
    If (-NOT (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    New-ItemProperty -Path $path -Name $key -Value $value -PropertyType $type -Force
}

# https://devblogs.microsoft.com/scripting/use-function-to-determine-elevation-of-powershell-console/
# Function to test if current session has administrator privileges
Function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Hiding invoke-webrequest progress because it creates lingering visual effect on PowerShell console for some reason
# https://github.com/PowerShell/PowerShell/issues/14348

# https://stackoverflow.com/questions/18770723/hide-progress-of-invoke-webrequest
# Create an in-memory module so $ScriptBlock doesn't run in new scope
$null = New-Module {
    function Invoke-WithoutProgress {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)] [scriptblock] $ScriptBlock
        )
        # Save current progress preference and hide the progress
        $prevProgressPreference = $global:ProgressPreference
        $global:ProgressPreference = 'SilentlyContinue'
        try {
            # Run the script block in the scope of the caller of this module function
            . $ScriptBlock
        }
        finally {
            # Restore the original behavior
            $global:ProgressPreference = $prevProgressPreference
        }
    }
}

#endregion functions

# create our working directory
New-Item -ItemType Directory -Path "$env:TEMP\HardeningXStuff\" -Force | Out-Null

# working directory assignment
$workingDir = "$env:TEMP\HardeningXStuff\"

# change location to the new directory
Set-Location $workingDir

# Clean up script block
$cleanUp = { Set-Location $HOME; remove-item -Recurse "$env:TEMP\HardeningXStuff\" -Force; exit }

if (-NOT (Test-IsAdmin))
{ write-host "Skipping commands that require Administrator privileges" -ForegroundColor Magenta }
else {    
    Write-Host "Downloading the required files, Please wait..." -ForegroundColor Yellow
    Invoke-WithoutProgress { 
        try {                
            # download Microsoft Security Baselines directly from their servers
            Invoke-WebRequest -Uri "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Windows%2011%20version%2022H2%20Security%20Baseline.zip" -OutFile ".\Windows1122H2SecurityBaseline.zip" -ErrorAction Stop
            # Download LGPO program from Microsoft servers
            Invoke-WebRequest -Uri "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip" -OutFile ".\LGPO.zip" -ErrorAction Stop
            # Download the Group Policies of Windows Hardening script from GitHub
            Invoke-WebRequest -Uri "https://github.com/HotCakeX/Harden-Windows-Security/raw/main/Payload/Security-Baselines-X.zip" -OutFile ".\Security-Baselines-X.zip" -ErrorAction Stop         
            # Download Registry CSV file
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Payload/Registry.csv" -OutFile ".\Registry.csv" -ErrorAction Stop
        }
        catch {
            Write-Host "The required files couldn't be downloaded, Make sure you have Internet connection." -ForegroundColor Red
            &$cleanUp   
        }
    }
    # unzip Microsoft Security Baselines file
    Expand-Archive -Path .\Windows1122H2SecurityBaseline.zip -DestinationPath .\ -Force
    # unzip the LGPO file
    Expand-Archive -Path .\LGPO.zip -DestinationPath .\ -Force
    # unzip the Security-Baselines-X file which contains Windows Hardening script Group Policy Objects
    expand-Archive -Path .\Security-Baselines-X.zip -DestinationPath .\Security-Baselines-X\ -Force

    #region Microsoft-Security-Baseline    
    # ================================================Microsoft Security Baseline==============================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nApply Microsoft Security Baseline ?") {
        "Yes" {       
            # Copy LGPO.exe from its folder to Microsoft Security Baseline folder in order to get it ready to be used by PowerShell script
            Copy-Item -Path ".\LGPO_30\LGPO.exe" -Destination ".\Windows-11-v22H2-Security-Baseline\Scripts\Tools"

            # Change directory to the Security Baselines folder
            Set-Location ".\Windows-11-v22H2-Security-Baseline\Scripts\"

            Write-Host "`nApplying Microsoft Security Baseline" -ForegroundColor Cyan
            # Run the official PowerShell script included in the Microsoft Security Baseline file we downloaded from Microsoft servers
            .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined            
        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # ============================================End of Microsoft Security Baselines==========================================   
    #endregion Microsoft-Security-Baseline
 
    #region Windows-Security-Defender    
    # ==========================================Windows Security aka Defender==================================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run Windows Security (Defender) category ?") {
        "Yes" { 
            # Change current working directory to the LGPO's folder
            Set-Location "$workingDir\LGPO_30"

            Write-Host "`nApplying Windows Security (Defender) policies" -ForegroundColor Cyan
            .\LGPO.exe /m "..\Security-Baselines-X\Windows Security (Defender) Policies\registry.pol"
        
            # Optimizing Network Protection Performance of Windows Defender - this was off by default on Windows 11 insider build 25247
            Set-MpPreference -AllowSwitchToAsyncInspection $True
            
            switch (Select-Option -Options "Yes", "No", "Exit" -Message "Turn on Smart App Control ?") {
                "Yes" {
                    # Turn on Smart App Control
                    ModifyRegistry -path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -key 'VerifiedAndReputablePolicyState' -value '1' -type 'DWORD'
                } "No" { break }
                "Exit" { exit }
            }
            # Enable Mandatory ASLR
            set-processmitigation -System -Enable ForceRelocateImages
        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # =========================================End of Windows Security aka Defender============================================    
    #endregion Windows-Security-Defender

    #region Attack-Surface-Reduction-Rules    
    # =========================================Attack Surface Reduction Rules==================================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run Attack Surface Reduction Rules category ?") {
        "Yes" {
            # Change current working directory to the LGPO's folder
            Set-Location "$workingDir\LGPO_30"

            Write-Host "`nApplying Attack Surface Reduction rules policies" -ForegroundColor Cyan
            .\LGPO.exe /m "..\Security-Baselines-X\Attack Surface Reduction Rules Policies\registry.pol"
        } "No" { break }
        "Exit" { &$cleanUp }
    }
    # =========================================End of Attack Surface Reduction Rules===========================================
    #endregion Attack-Surface-Reduction-Rules
    
    #region Bitlocker-Settings    
    # ==========================================Bitlocker Settings=============================================================    
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run Bitlocker category ?") {
        "Yes" {
            # doing this so Controlled Folder Access won't bitch about powercfg.exe
            Set-MpPreference -ControlledFolderAccessAllowedApplications "C:\Windows\System32\powercfg.exe"
            Start-Sleep 5
            # Set Hibnernate mode to full
            powercfg /h /type full
            Start-Sleep 2
            Remove-MpPreference -ControlledFolderAccessAllowedApplications "C:\Windows\System32\powercfg.exe"
            # Change current working directory to the LGPO's folder
            Set-Location "$workingDir\LGPO_30"

            Write-Host "`nApplying Bitlocker policies" -ForegroundColor Cyan
            .\LGPO.exe /m "..\Security-Baselines-X\Bitlocker Policies\registry.pol"

            # This PowerShell script can be used to find out if the DMA Protection is ON \ OFF.
            # The Script will show this by emitting True \ False for On \ Off respectively.

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

            # Change current working directory to the LGPO's folder
            Set-Location "$workingDir\LGPO_30"
            
            # Enables or disables DMA protection from Bitlocker Countermeasures based on the status of Kernel DMA protection.
            if ($bootDMAProtection) {                 
                Write-Host "Kernel DMA protection is enabled on the system, disabling Bitlocker DMA protection." -ForegroundColor Blue
                .\LGPO.exe /m "..\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure OFF\Registry.pol"                           
            }
            else {
                Write-Host "Kernel DMA protection is unavailable on the system, enabling Bitlocker DMA protection." -ForegroundColor Blue
                .\LGPO.exe /m "..\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure ON\Registry.pol"                                                          
            }
            # set-up Bitlocker encryption for OS Drive with TPMandPIN and recovery password keyprotectors and Verify its implementation
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
            # check, make sure there is no CD/DVD drives in the system, because Bitlocker throws an error when there is
            $CDDVDCheck = (Get-WMIObject -Class Win32_CDROMDrive -Property *).MediaLoaded
            if ($CDDVDCheck) {
                Write-Warning "Remove any CD/DVD drives from the system and run the Bitlocker category after that"
                break
            }
            # check make sure Bitlocker isn't in the middle of decryption/encryption operation (on System Drive)
            if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage -ne "100" -and (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage -ne "0") {
                $kawai = (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage
                Write-Host "Please wait for Bitlocker operation to finish encrypting or decrypting the disk" -ForegroundColor Magenta
                Write-Host "drive $env:SystemDrive encryption is currently at $kawai" -ForegroundColor Magenta
            }

            else {
                # check if Bitlocker is enabled for the system drive
                if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq "on") {                                 
                    $KeyProtectors = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector.keyprotectortype
                    # check if TPM+PIN and recovery password are being used with Bitlocker which are the safest settings
                    if ($KeyProtectors -contains 'Tpmpin' -and $KeyProtectors -contains 'recoveryPassword') {        
                        Write-Host "Bitlocker is fully and securely enabled for the OS drive" -ForegroundColor Green    
                    }
                    else {       
                        # if Bitlocker is using TPM+PIN but not recovery password (for key protectors)
                        if ($KeyProtectors -contains 'Tpmpin' -and $KeyProtectors -notcontains 'recoveryPassword') {
                            Write-Host "TPM and Startup Pin are available but the recovery password is missing, adding it now...`
the recovery password will be saved in a Text file in $env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -ForegroundColor yellow                          
                            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt"
                            Write-Host "Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." -ForegroundColor Blue                         
                        }                
                        # if Bitlocker is using recovery password but not TPM+PIN
                        if ($KeyProtectors -notcontains 'Tpmpin' -and $KeyProtectors -contains 'recoveryPassword') {            
                            Write-Host "TPM and Start up PIN are missing but recovery password is in place, `nadding TPM and Start up PIN now..." -ForegroundColor Magenta
                            do {
                                $pin1 = $(write-host "Enter a Pin for Bitlocker startup (at least 6 digits)" -ForegroundColor Magenta; Read-Host -AsSecureString)
                                $pin2 = $(write-host "Confirm your Bitlocker Startup Pin (at least 6 digits)" -ForegroundColor Magenta; Read-Host -AsSecureString)
                                      
                                $theyMatch = Compare-SecureString $pin1 $pin2

                                if ( $theyMatch -and $pin1.Length -ge 6 -and $pin2.Length -ge 6  ) {                  
                                    $pin = $pin1                  
                                }                  
                                else { Write-Host "the PINs you entered didn't match, try again" -ForegroundColor red }                  
                            }                  
                            until ($theyMatch -and $pin1.Length -ge 6 -and $pin2.Length -ge 6)
                 
                            try {
                                Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinProtector -Pin $pin -ErrorAction Stop
                                Write-Host "PINs matched, enabling TPM and startup PIN now" -ForegroundColor DarkMagenta
                            }    
                            catch {         
                                Write-Host "These errors occured, run Bitlocker category again after meeting the requirements" -ForegroundColor Red
                                $Error
                                break
                            }
                        }     
                    }     
                }   
                else {
                    Write-Host "Bitlocker is Not enabled for the System Drive Drive, activating now..." -ForegroundColor yellow    
                    do {
                        $pin1 = $(write-host "Enter a Pin for Bitlocker startup (at least 6 digits)" -ForegroundColor Magenta; Read-Host -AsSecureString)
                        $pin2 = $(write-host "Confirm your Bitlocker Startup Pin (at least 6 digits)" -ForegroundColor Magenta; Read-Host -AsSecureString)
      
                        $theyMatch = Compare-SecureString $pin1 $pin2
            
                        if ($theyMatch -and $pin1.Length -ge 6 -and $pin2.Length -ge 6) {      
                            $pin = $pin1      
                        }      
                        else { Write-Host "the Pins you entered didn't match, try again" -ForegroundColor red }      
                    }      
                    until ($theyMatch -and $pin1.Length -ge 6 -and $pin2.Length -ge 6)

                    try {
                        enable-bitlocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -pin $pin -TpmAndPinProtector -SkipHardwareTest -ErrorAction Stop             
                    }
                    catch {
                        Write-Host "These errors occured, run Bitlocker category again after meeting the requirements" -ForegroundColor Red
                        $Error
                        break
                    }     
                    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" 
                    Resume-BitLocker -MountPoint $env:SystemDrive
                    Write-Host "the recovery password will be saved in a Text file in $env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt`
Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." -ForegroundColor Blue
                    Write-Host "Bitlocker is now fully and securely enabled for OS drive" -ForegroundColor Green                     
                }
            }
            # Enable Bitlocker for all the other drives
            # check if there is any other drive besides OS drive
            $nonOSVolumes = Get-BitLockerVolume | Where-Object { $_.volumeType -ne "OperatingSystem" }
            if ($nonOSVolumes) {
                $nonOSVolumes |
                ForEach-Object {
                    $MountPoint = $_.MountPoint
                    if ((Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage -ne "100" -and (Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage -ne "0") {
                        $kawai = (Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage
                        Write-Host "Please wait for Bitlocker operation to finish encrypting or decrypting drive $MountPoint" -ForegroundColor Magenta
                        Write-Host "drive $MountPoint encryption is currently at $kawai" -ForegroundColor Magenta
                    }   
                    else {
                        if ((Get-BitLockerVolume -MountPoint $MountPoint).ProtectionStatus -eq "on") {    
                            $KeyProtectors = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector.keyprotectortype    
                            if ($KeyProtectors -contains 'RecoveryPassword' -and $KeyProtectors -contains 'ExternalKey') {
                                # if there is any External key key protector, delete all of them and add a new one
                                $ExternalKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                    Where-Object { $_.keyprotectortype -eq "ExternalKey" }).KeyProtectorId
                                if ($ExternalKeyProtectors) {
                                    $ExternalKeyProtectors | ForEach-Object {
                                        Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ -ErrorAction SilentlyContinue 
                                    }
                                }
                                Enable-BitLockerAutoUnlock -MountPoint $MountPoint
                                # if there is more than 1 Recovery Password, delete all of them and add a new one
                                $RecoveryPasswordKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                    Where-Object { $_.keyprotectortype -eq "RecoveryPassword" }).KeyProtectorId
                                if ($RecoveryPasswordKeyProtectors.Count -gt 1) {
                                    write-host "there are more than 1 recovery password key protector associated with the drive $mountpoint`
Removing all of them and adding a new one now. Bitlocker Recovery Password has been added for drive $MountPoint`
it will be saved in a Text file in $($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt . Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." -ForegroundColor Yellow   
                                    $RecoveryPasswordKeyProtectors | ForEach-Object {
                                        Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ 
                                    }
                                    Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt";
                                }
                                
                                Write-Host "Bitlocker is fully and securely enabled for drive $MountPoint" -ForegroundColor Green    
                            }
                            else {
                                if ($KeyProtectors -contains 'ExternalKey' -and $KeyProtectors -notcontains 'RecoveryPassword' ) {
                                    # if there is any External key key protector, delete all of them and add a new one
                                    $ExternalKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                        Where-Object { $_.keyprotectortype -eq "ExternalKey" }).KeyProtectorId
                                    if ($ExternalKeyProtectors) {
                                        $ExternalKeyProtectors | ForEach-Object {
                                            Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ -ErrorAction SilentlyContinue 
                                        }
                                    }
                                    Enable-BitLockerAutoUnlock -MountPoint $MountPoint                                             
                                    Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt";
                                    Write-Host "`nDrive $MountPoint is auto-unlocked but doesn't have Recovery Password, adding it now...`
Bitlocker Recovery Password has been added for drive $MountPoint . it will be saved in a Text file in $($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt`
Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." -ForegroundColor Blue
                                }
                                if ($KeyProtectors -contains 'RecoveryPassword' -and $KeyProtectors -notcontains 'ExternalKey') {
                                    Enable-BitLockerAutoUnlock -MountPoint $MountPoint
                                    # if there is more than 1 Recovery Password, delete all of them and add a new one
                                    $RecoveryPasswordKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                        Where-Object { $_.keyprotectortype -eq "RecoveryPassword" }).KeyProtectorId
                                    if ($RecoveryPasswordKeyProtectors.Count -gt 1) {
                                        write-host "there are more than 1 recovery password key protector associated with the drive $mountpoint`
Removing all of them and adding a new one now. Bitlocker Recovery Password has been added for drive $MountPoint`
it will be saved in a Text file in $($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt . Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." -ForegroundColor Yellow   
                                        $RecoveryPasswordKeyProtectors | ForEach-Object {
                                            Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ 
                                        }
                                        Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt";
                                    }                                    
                                }                      
                            }
                        }
                        else {
                            Enable-BitLocker -MountPoint $MountPoint -RecoveryPasswordProtector *> "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt";
                            Enable-BitLockerAutoUnlock -MountPoint $MountPoint
                            Write-Host "Bitlocker has started encrypting drive $MountPoint . recovery password will be saved in a Text file in $($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt`
Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." -ForegroundColor Blue
                        }
                    }
                }
            }
        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # ==========================================End of Bitlocker Settings======================================================    
    #endregion Bitlocker-Settings

    #region TLS-Security    
    # ==============================================TLS Security===============================================================    
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run TLS Security category ?") {
        "Yes" {
            @( # creating these registry keys that have forward slashes in them
                'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56', # DES 56-bit 
                'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128', # RC2 40-bit
                'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128', # RC2 56-bit
                'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128', # RC2 128-bit
                'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128', # RC4 40-bit
                'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128', # RC4 56-bit
                'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128', # RC4 64-bit
                'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128', # RC4 128-bit
                'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168' # 3DES 168-bit (Triple DES 168)
            ) | ForEach-Object {
([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey($_)
            }
            # TLS Registry section
            Set-Location $workingDir
            $items = Import-Csv '.\Registry.csv' -Delimiter ";"
            foreach ($item in $items) {
                if ($item.category -eq 'TLS') {
                    ModifyRegistry -path $item.path -key $item.key -value $item.value -type $item.type
                }
            }
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
                Write-Host "`nAll weak TLS Cipher Suites have been disabled`n" -ForegroundColor Magenta
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
        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # ==========================================End of TLS Security============================================================
    #endregion TLS-Security

    #region Lock-Screen    
    # ==========================================Lock Screen====================================================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run Lock Screen category ?") {
        "Yes" {
            # Change current working directory to the LGPO's folder
            Set-Location "$workingDir\LGPO_30"

            Write-Host "`nApplying Lock Screen policies" -ForegroundColor Cyan
            .\LGPO.exe /m "..\Security-Baselines-X\Lock Screen Policies\registry.pol"

            Write-Host "`nApplying Lock Screen Security policies" -ForegroundColor Cyan
            .\LGPO.exe /s "..\Security-Baselines-X\Lock Screen Policies\GptTmpl.inf"        
        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # ==========================================End of Lock Screen=============================================================
    #endregion Lock-Screen

    #region User-Account-Control    
    # ==========================================User Account Control===========================================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run User Account Control category ?") {
        "Yes" {
            # Change current working directory to the LGPO's folder
            Set-Location "$workingDir\LGPO_30"

            Write-Host "`nApplying User Account Control (UAC) Security policies" -ForegroundColor Cyan
            .\LGPO.exe /s "..\Security-Baselines-X\User Account Control UAC Policies\GptTmpl.inf"        
        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # ==========================================End of User Account Control====================================================
    #endregion User-Account-Control

    #region Device-Guard    
    # ==========================================Device Guard===================================================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run Device Guard category ?") {
        "Yes" {
            # Change current working directory to the LGPO's folder
            Set-Location "$workingDir\LGPO_30"

            Write-Host "`nApplying Device Guard policies" -ForegroundColor Cyan
            .\LGPO.exe /m "..\Security-Baselines-X\Device Guard Policies\registry.pol"

        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # ==========================================End of Device Guard============================================================
    #endregion Device-Guard

    #region Windows-Firewall    
    # ====================================================Windows Firewall=====================================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run Windows Firewall category ?") {
        "Yes" {
            # Change current working directory to the LGPO's folder
            Set-Location "$workingDir\LGPO_30"

            Write-Host "`nApplying Windows Firewall policies" -ForegroundColor Cyan
            .\LGPO.exe /m "..\Security-Baselines-X\Windows Firewall Policies\registry.pol"

            # Disables Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles - disables only 3 rules
            get-NetFirewallRule |
            Where-Object { $_.RuleGroup -eq "@%SystemRoot%\system32\firewallapi.dll,-37302" -and $_.Direction -eq "inbound" } |
            ForEach-Object { Disable-NetFirewallRule -DisplayName $_.DisplayName }
        } "No" { break }
        "Exit" { exit }
    }    
    # =================================================End of Windows Firewall=================================================
    #endregion Windows-Firewall

    #region Optional-Windows-Features    
    # =================================================Optional Windows Features===============================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run Optional Windows Features category ?") {
        "Yes" {
            # since PowerShell Core (only if installed from Microsoft Store) has problem with these commands, making sure the built-in PowerShell handles them
            # There are Github issues for it already: https://github.com/PowerShell/PowerShell/issues/13866

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
        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # ==============================================End of Optional Windows Features===========================================
    #endregion Optional-Windows-Features

    #region Windows-Networking    
    # ====================================================Windows Networking===================================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run Windows Networking category ?") {
        "Yes" {
            # Change current working directory to the LGPO's folder
            Set-Location "$workingDir\LGPO_30"

            Write-Host "`nApplying Windows Networking policies" -ForegroundColor Cyan
            .\LGPO.exe /m "..\Security-Baselines-X\Windows Networking Policies\registry.pol"

            # disable LMHOSTS lookup protocol on all network adapters
            ModifyRegistry -path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -key 'EnableLMHOSTS' -value '0' -type 'DWORD'

            # Set the Network Location of all connections to Public
            Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Public
        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # =================================================End of Windows Networking===============================================
    #endregion Windows-Networking

    #region Miscellaneous-Configurations    
    # ==============================================Miscellaneous Configurations===============================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run Miscellaneous Configurations category ?") {
        "Yes" {
            # Miscellaneous Registry section
            Set-Location $workingDir
            $items = Import-Csv '.\Registry.csv' -Delimiter ";"
            foreach ($item in $items) {
                if ($item.category -eq 'Miscellaneous') {              
                    ModifyRegistry -path $item.path -key $item.key -value $item.value -type $item.type
                }
            }
            # Change current working directory to the LGPO's folder
            Set-Location "$workingDir\LGPO_30"

            Write-Host "`nApplying Miscellaneous Configurations policies" -ForegroundColor Cyan
            .\LGPO.exe /m "..\Security-Baselines-X\Miscellaneous Policies\registry.pol"

            Write-Host "`nApplying Miscellaneous Configurations Security policies" -ForegroundColor Cyan
            .\LGPO.exe /s "..\Security-Baselines-X\Miscellaneous Policies\GptTmpl.inf"

            # Enable SMB Encryption - using force to confirm the action
            Set-SmbServerConfiguration -EncryptData $true -force
                    
            # Allow all Windows users to use Hyper-V and Windows Sandbox by adding all Windows users to the "Hyper-V Administrators" security group
            Get-LocalUser | Where-Object { $_.enabled -EQ "True" } | Select-Object "Name" |
            ForEach-Object { Add-LocalGroupMember -Group "Hyper-V Administrators" -Member $_.Name -ErrorAction SilentlyContinue }
            
            # Event Viewer custom views are saved in "C:\ProgramData\Microsoft\Event Viewer\Views". files in there can be backed up and restored on new Windows installations.
            new-item -ItemType Directory -Path "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\" -force | Out-Null                
            Invoke-WithoutProgress { 
                try {
                    Write-Host "Downloading the Custom views for Event Viewer, Please wait..." -ForegroundColor Yellow
                    invoke-webrequest -Uri "https://github.com/HotCakeX/Harden-Windows-Security/raw/main/Payload/EventViewerCustomViews.zip" -OutFile "$env:TEMP\EventViewerCustomViews.zip" -ErrorAction Stop
                    Expand-Archive -Path "$env:TEMP\EventViewerCustomViews.zip" -DestinationPath "C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script" -Force
                    remove-item -Path "$env:TEMP\EventViewerCustomViews.zip" -Force
                    Write-Host "`nSuccessfully added Custom Views for Event Viewer" -ForegroundColor Green               
                }
                catch {
                    Write-Host "The required files couldn't be downloaded, Make sure you have Internet connection. Skipping..." -ForegroundColor Red
                }
            }
        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # ============================================End of Miscellaneous Configurations==========================================
    #endregion Miscellaneous-Configurations

    #region Overrides-for-Microsoft-Security-Baseline    
    # ============================================Overrides for Microsoft Security Baseline====================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Apply Overrides for Microsoft Security Baseline ?") {
        "Yes" {
            # Change current working directory to the LGPO's folder
            Set-Location "$workingDir\LGPO_30"

            Write-Host "`nApplying policy Overrides for Microsoft Security Baseline" -ForegroundColor Cyan
            .\LGPO.exe /v /m "..\Security-Baselines-X\Overrides for Microsoft Security Baseline\registry.pol"
            Write-Host "`nApplying Security policy Overrides for Microsoft Security Baseline" -ForegroundColor Cyan
            .\LGPO.exe /v /s "..\Security-Baselines-X\Overrides for Microsoft Security Baseline\GptTmpl.inf"
        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # ============================================End of Overrides for Microsoft Security Baseline=============================
    #endregion Overrides-for-Microsoft-Security-Baseline

    #region Windows-Update-Configurations    
    # ====================================================Windows Update Configurations==============================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Apply Windows Update Policies ?") {
        "Yes" {
            # enable restart notification for Windows update
            ModifyRegistry -path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -key "RestartNotificationsAllowed2" -value "1" -type 'DWORD'

            # Change current working directory to the LGPO's folder
            Set-Location "$workingDir\LGPO_30"

            Write-Host "`nApplying Windows Update policies" -ForegroundColor Cyan
            .\LGPO.exe /m "..\Security-Baselines-X\Windows Update Policies\registry.pol"
        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # ====================================================End of Windows Update Configurations=======================================
    #endregion Windows-Update-Configurations

    #region Edge-Browser-Configurations
    # ====================================================Edge Browser Configurations====================================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Apply Edge Browser Configurations ?") {
        "Yes" {
            # Edge Browser Configurations registry
            Set-Location $workingDir
            $items = Import-Csv '.\Registry.csv' -Delimiter ";"
            foreach ($item in $items) {
                if ($item.category -eq 'Edge') {
                    ModifyRegistry -path $item.path -key $item.key -value $item.value -type $item.type
                }
            }
        } "No" { break }
        "Exit" { &$cleanUp }
    } 
    # ====================================================End of Edge Browser Configurations==============================================
    #endregion Edge-Browser-Configurations

    #region Top-Security-Measures    
    # ============================================Top Security Measures========================================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Apply Top Security Measures ? Make sure you've read the GitHub repository") {
        "Yes" {             
            # Change current working directory to the LGPO's folder
            Set-Location "$workingDir\LGPO_30"

            Write-Host "`nApplying Top Security Measures" -ForegroundColor Cyan
            .\LGPO.exe /s "..\Security-Baselines-X\Top Security Measures\GptTmpl.inf"

        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # ============================================End of Top Security Measures=================================================
    #endregion Top-Security-Measures

    #region Certificate-Checking-Commands    
    # ====================================================Certificate Checking Commands========================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run Certificate Checking category ?") {
        "Yes" {            
            # List valid certificates not rooted to the Microsoft Certificate Trust List in the User store
            switch (Select-Option -Options "Yes", "No" -Message "List valid certificates not rooted to the Microsoft Certificate Trust List in the User store ?") {
                "Yes" {
                    try {
                        Invoke-WithoutProgress {
                            Invoke-WebRequest -Uri "https://live.sysinternals.com/sigcheck64.exe" -OutFile "sigcheck64.exe" -ErrorAction Stop
                        }
                        .\sigcheck64.exe -tuv -accepteula -nobanner
                        Remove-Item .\sigcheck64.exe -Force
                    }
                    catch {                    
                        Write-Host "sigcheck64.exe couldn't be downloaded from https://live.sysinternals.com" -ForegroundColor Red
                    }
                } "No" { break }              
            }
            # List valid certificates not rooted to the Microsoft Certificate Trust List in the Machine store
            switch (Select-Option -Options "Yes", "No" -Message "List valid certificates not rooted to the Microsoft Certificate Trust List in the Machine store ?") {
                "Yes" {
                    try {
                        Invoke-WithoutProgress {
                            Invoke-WebRequest -Uri "https://live.sysinternals.com/sigcheck64.exe" -OutFile "sigcheck64.exe" -ErrorAction Stop
                        }
                        .\sigcheck64.exe -tv -accepteula -nobanner
                        Remove-Item .\sigcheck64.exe -Force
                    }
                    catch {
                        Write-Host "sigcheck64.exe couldn't be downloaded from https://live.sysinternals.com" -ForegroundColor Red
                    }
                } "No" { break }  
            }
        } "No" { break }
        "Exit" { &$cleanUp }
    }
    # ====================================================End of Certificate Checking Commands=================================
    #endregion Certificate-Checking-Commands

    #region Country-IP-Blocking    
    # ====================================================Country IP Blocking==================================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run Country IP Blocking category ?") {
        "Yes" {
            # -RemoteAddress in New-NetFirewallRule accepts array according to Microsoft Docs, 
            # so we use "[string[]]$IPList = $IPList -split '\r?\n' -ne ''" to convert the IP lists, which is a single multiline string, into an array

            function BlockCountryIP {
                param ($IPList , $CountryName)

                # checks if the rule is present and if it is, deletes them to get new up-to-date IP ranges from the sources
                if (Get-NetFirewallRule -DisplayName "$CountryName IP range blocking" -PolicyStore localhost -ErrorAction SilentlyContinue) 
                { Remove-NetFirewallRule -DisplayName "$CountryName IP range blocking" -PolicyStore localhost }

                # converts the list which is in string into array
                [string[]]$IPList = $IPList -split '\r?\n' -ne ''

                # makes sure the list isn't empty
                if ($IPList.count -eq 0) { Write-Host "The IP list was empty, skipping $CountryName" -ForegroundColor Yellow ; break }
      
                New-NetFirewallRule -DisplayName "$CountryName IP range blocking" -Direction Inbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$CountryName IP range blocking" -Profile Any -InterfaceType Any -Group "Hardening-Script-CountryIP-Blocking" -EdgeTraversalPolicy Block -PolicyStore localhost
                New-NetFirewallRule -DisplayName "$CountryName IP range blocking" -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$CountryName IP range blocking" -Profile Any -InterfaceType Any -Group "Hardening-Script-CountryIP-Blocking" -EdgeTraversalPolicy Block -PolicyStore localhost        
            }
            # Iran
            switch (Select-Option -Options "Yes", "No" -Message "Block the entire range of IPv4 and IPv6 belonging to Iran?") {
                "Yes" {    
                    $IranIPv4 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone"
                    $IranIPv6 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ir.zone"
                    $IranIPRange = $IranIPv4 + $IranIPv6
                    BlockCountryIP -IPList $IranIPRange -CountryName "Iran"
                } "No" { break }
            }
            # Cuba
            switch (Select-Option -Options "Yes", "No" -Message "Block the entire range of IPv4 and IPv6 belonging to Cuba?") {
                "Yes" {
                    $CubaIPv4 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipblocks/data/aggregated/cu-aggregated.zone"
                    $CubaIPv6 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipv6/ipaddresses/blocks/cu.zone"
                    $CubaIPRange = $CubaIPv4 + $CubaIPv6
                    BlockCountryIP -IPList $CubaIPRange -CountryName "Cuba"
                } "No" { break }
            }
            # North Korea
            switch (Select-Option -Options "Yes", "No" -Message "Block the entire range of IPv4 and IPv6 belonging to North Korea?") {
                "Yes" {    
                    $NorthKoreaIPv4 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipblocks/data/aggregated/kp-aggregated.zone"
                    $NorthKoreaIPv6 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipv6/ipaddresses/blocks/kn.zone"
                    $NorthKoreaIPRange = $NorthKoreaIPv4 + $NorthKoreaIPv6
                    BlockCountryIP -IPList $NorthKoreaIPRange -CountryName "North Korea"
                } "No" { break }
            }
            # Syria
            switch (Select-Option -Options "Yes", "No" -Message "Block the entire range of IPv4 and IPv6 belonging to Syria?") {
                "Yes" {    
                    $SyriaIPv4 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipblocks/data/aggregated/sy-aggregated.zone"
                    $SyriaIPv6 = Invoke-RestMethod -Uri "https://www.ipdeny.com/ipv6/ipaddresses/blocks/sy.zone"
                    $SyriaIPRange = $SyriaIPv4 + $SyriaIPv6
                    BlockCountryIP -IPList $SyriaIPRange -CountryName "Syria"
                } "No" { break }
            }
            # how to query the number of IPs in each rule
            # (Get-NetFirewallRule -DisplayName "Cuba IP range blocking" | Get-NetFirewallAddressFilter).RemoteAddress.count
        } "No" { break }
        "Exit" { &$cleanUp }
    }    
    # ====================================================End of Country IP Blocking===========================================
    #endregion Country-IP-Blocking
    
} # End of Admin test function

#region Non-Admin-Commands
# ====================================================Non-Admin Commands===================================================
switch (Select-Option -Options "Yes", "No", "Exit" -Message "Run Non-Admin category ?") {
    "Yes" {
        # Non-Admin Registry section              
        Set-Location $workingDir       
        Invoke-WithoutProgress { 
            # Download Registry CSV file               
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Payload/Registry.csv" -OutFile ".\Registry.csv"
        }
        $items = Import-Csv '.\Registry.csv' -Delimiter ";"
        foreach ($item in $items) {
            if ($item.category -eq 'NonAdmin') {              
                ModifyRegistry -path $item.path -key $item.key -value $item.value -type $item.type
            }
        }        
        $infomsg = "`r`n" +
        "################################################################################################`r`n" +
        "###  Please Restart your device to completely apply the security measures and Group Policies ###`r`n" +
        "################################################################################################`r`n"
        Write-Host $infomsg -ForegroundColor Cyan
        Start-Sleep 3; &$cleanUp
    } "No" { break }
    "Exit" { &$cleanUp }
}
# ====================================================End of Non-Admin Commands============================================
#endregion Non-Admin-Commands
