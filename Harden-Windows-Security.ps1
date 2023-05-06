<#PSScriptInfo

.VERSION 2023.5.6

.GUID d435a293-c9ee-4217-8dc1-4ad2318a5770

.AUTHOR HotCakeX

.COMPANYNAME SpyNetGirl

.COPYRIGHT 2023

.TAGS Windows Hardening Security Bitlocker Defender Firewall Edge Protection Baseline TLS UAC Encryption

.LICENSEURI https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE

.PROJECTURI https://github.com/HotCakeX/Harden-Windows-Security

.ICONURI https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PowerShellGalleryICONURI.png

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES

Full Change log always available in Excel online (Copy and Paste the link if not displaying correctly): 
https://1drv.ms/x/s!AtCaUNAJbbvIhuVQhdMu_Hts7YZ_lA?e=df6H6P

#>

<# 

.SYNOPSIS
    Harden Windows Safely, Securely, only with Official Microsoft methods

.DESCRIPTION


  ⭕ You need to read the GitHub's readme page before running this script: https://github.com/HotCakeX/Harden-Windows-Security

💠 Features of this Hardening script:

  ✅ Always stays up-to-date with the newest security measures.
  ✅ Everything is in plain text, nothing hidden, no 3rd party executable or pre-compiled binary is involved.
  ✅ Doesn't remove or disable Windows functionalities against Microsoft's recommendations.
  ✅ The script primarily uses Group policies, the Microsoft recommended way of configuring Windows. It also uses PowerShell cmdlets where Group Policies aren't available, and finally uses a few registry keys to configure security measures that can neither be configured using Group Policies nor PowerShell cmdlets. This is why the script doesn't break anything or cause unwanted behavior.
  ✅ When a hardening measure is no longer necessary because it's applied by default by Microsoft on new builds of Windows, it will also be removed from this script in order to prevent any problems and because it won't be necessary anymore.
  ✅ The script can be run infinite number of times, it's made in a way that it won't make any duplicate changes.
  ✅ The script prompts for confirmation before running each hardening category and some sub-categories, so you can selectively run (or don't run) each of them.
  ✅ Applying this script makes your PC compliant with Microsoft Security Baselines and Secured-core PC specifications (provided that you use modern hardware that supports the latest Windows security features)

🛑 Note: Windows by default is secure and safe, this script does not imply nor claim otherwise. just like anything, you have to use it wisely and don't compromise yourself with reckless behavior and bad user configuration; Nothing is foolproof. this script only uses the tools and features that have already been implemented by Microsoft in Windows OS to fine-tune it towards the highest security and locked-down state, using well-documented, supported, recommended and official methods. continue reading on GitHub for comprehensive info.

💠 Hardening Categories from top to bottom: (🔻Detailed info about each of them at my Github🔻)

⏹ Commands that require Administrator Privileges
  ✅ Microsoft Security Baselines
  ✅ Microsoft 365 Apps Security Baselines
  ✅ Microsoft Defender
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
  ✅ Windows Update Configurations
  ✅ Edge Browser Configurations
  ✅ Certificate Checking Commands
  ✅ Country IP Blocking
⏹ Commands that don't require Administrator Privileges
  ✅ Non-Admin Commands that only affect the current user and do not make machine-wide changes.


💎 Note: If there are multiple Windows user accounts in your computer, it's recommended to run this script in each of them, without administrator privileges, because Non-admin commands only apply to the current user and are not machine wide.

💎 Note: There are 4 items tagged with #TopSecurity that can cause difficulties. When you run this script, you will have an option to enable them if you want to. You can find all the information about them on GitHub.

🏴 If you have any questions, requests, suggestions etc. about this script, please open a new discussion in GitHub:

🟡 https://github.com/HotCakeX/Harden-Windows-Security/discussions

.EXAMPLE  

.NOTES  
    Check out GitHub page for security recommendations: https://github.com/HotCakeX/Harden-Windows-Security
#>

# Change the execution policy temporarily only for the current PowerShell session
Set-ExecutionPolicy Bypass -Scope Process

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
            [Parameter(Mandatory)][scriptblock]$ScriptBlock
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
#endregion functions

if (Test-IsAdmin) {
    # backup the current allowed apps list in Controlled folder access in order to restore them at the end of the script
    # doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
    # no user customization will be affected
    $CFAAllowedAppsBackup = (Get-MpPreference).ControlledFolderAccessAllowedApplications

    # Temporarily allow the currently running PowerShell executables to the Controlled Folder Access allowed apps
    # so that the script can run without interruption. This change is reverted at the end.
    Get-ChildItem -Path "$PSHOME\*.exe" | ForEach-Object {
        Add-MpPreference -ControlledFolderAccessAllowedApplications $_.FullName
    }
}

# doing a try-finally block on the entire script so that when CTRL + C is pressed to forcefully exit the script,
# or break is passed, clean up will still happen for secure exit
try {

    # Check the current hard-coded version against the latest version online
    $currentVersion = '2023.5.6'
    try {
        $latestVersion = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Version.txt"
    }
    catch {
        Write-Error "Couldn't verify if the latest version of the script is installed, please check your Internet connection."
        break
    }
    if ($currentVersion -lt $latestVersion) {
        Write-Host "The currently installed script's version is $currentVersion while the latest version is $latestVersion" -ForegroundColor Cyan
        Write-Host "Please update your script using:" -ForegroundColor Yellow
        Write-Host "Update-Script -Name 'Harden-Windows-Security' -Force" -ForegroundColor Green
        Write-Host "and run it again after that." -ForegroundColor Yellow        
        Write-host "You can view the change log in here: https://1drv.ms/x/s!AtCaUNAJbbvIhuVQhdMu_Hts7YZ_lA?e=df6H6P" -ForegroundColor Magenta
        break
    }

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

    #region RequirementsCheck
    # check if user's OS is Windows Home edition
    if ((Get-CimInstance -ClassName Win32_OperatingSystem).OperatingSystemSKU -eq "101") {
        Write-Error "Windows Home edition detected, exiting..."
        break
    }

    # check if user's OS is latest version
    if (-NOT ([System.Environment]::OSVersion.Version -ge '10.0.22621')) {
        Write-Error "You're not using the latest version of Windows, exitting..."
        break
    }

    if (Test-IsAdmin) {
        # check to make sure Secure Boot is enabled
        if (-NOT (Confirm-SecureBootUEFI)) {
            Write-Error "Secure Boot is not enabled, please go to your UEFI settings and enable it and then run the script again."
            break    
        }

        # check to make sure TPM is available and enabled
        $TPMFlag1 = (Get-Tpm).tpmpresent
        $TPMFlag2 = (Get-Tpm).tpmenabled
        if (!$TPMFlag1 -or !$TPMFlag2) {
            Write-Error "TPM is not available or enabled, please go to your UEFI settings and enable it and then run the script again."
            break    
        }
    }
    #endregion RequirementsCheck

    # create our working directory
    New-Item -ItemType Directory -Path "$env:TEMP\HardeningXStuff\" -Force | Out-Null
    # working directory assignment
    $WorkingDir = "$env:TEMP\HardeningXStuff\"
    # change location to the new directory
    Set-Location $WorkingDir

    # Clean up script block
    $CleanUp = { Set-Location $HOME; remove-item -Recurse "$env:TEMP\HardeningXStuff\" -Force; exit }

    if (-NOT (Test-IsAdmin))
    { write-host "Skipping commands that require Administrator privileges" -ForegroundColor Magenta }
    else {
        Write-Progress -Activity 'Initialization' -Status 'Downloading the required files for the script' -PercentComplete 0      
        
        Invoke-WithoutProgress { 
            try {                
                # download Microsoft Security Baselines directly from their servers
                Invoke-WebRequest -Uri "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Windows%2011%20version%2022H2%20Security%20Baseline.zip" -OutFile ".\Windows1122H2SecurityBaseline.zip" -ErrorAction Stop
                # download Microsoft 365 Apps Security Baselines directly from their servers
                Invoke-WebRequest -Uri "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Microsoft%20365%20Apps%20for%20Enterprise-2206-FINAL.zip" -OutFile ".\Microsoft365SecurityBaseline2206.zip" -ErrorAction Stop
                # Download LGPO program from Microsoft servers
                Invoke-WebRequest -Uri "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip" -OutFile ".\LGPO.zip" -ErrorAction Stop
                # Download the Group Policies of Windows Hardening script from GitHub
                Invoke-WebRequest -Uri "https://github.com/HotCakeX/Harden-Windows-Security/raw/main/Payload/Security-Baselines-X.zip" -OutFile ".\Security-Baselines-X.zip" -ErrorAction Stop         
                # Download Registry CSV file
                Invoke-WebRequest -Uri "https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Payload/Registry.csv" -OutFile ".\Registry.csv" -ErrorAction Stop                
            }
            catch {
                Write-Error "The required files couldn't be downloaded, Make sure you have Internet connection."
                &$CleanUp   
            }
        }
        # unzip Microsoft Security Baselines file
        Expand-Archive -Path .\Windows1122H2SecurityBaseline.zip -DestinationPath .\ -Force
        # unzip Microsoft 365 Apps Security Baselines file
        Expand-Archive -Path .\Microsoft365SecurityBaseline2206.zip -DestinationPath .\ -Force
        # unzip the LGPO file
        Expand-Archive -Path .\LGPO.zip -DestinationPath .\ -Force
        # unzip the Security-Baselines-X file which contains Windows Hardening script Group Policy Objects
        Expand-Archive -Path .\Security-Baselines-X.zip -DestinationPath .\Security-Baselines-X\ -Force

        #region Microsoft-Security-Baseline    
        # ================================================Microsoft Security Baseline==============================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nApply Microsoft Security Baseline ?") {
            "Yes" {
                Write-Progress -Activity 'Microsoft Security Baseline' -Status 'Running Microsoft Security Baseline section' -PercentComplete 5

                # Copy LGPO.exe from its folder to Microsoft Security Baseline folder in order to get it ready to be used by PowerShell script
                Copy-Item -Path ".\LGPO_30\LGPO.exe" -Destination ".\Windows-11-v22H2-Security-Baseline\Scripts\Tools"

                # Change directory to the Security Baselines folder
                Set-Location ".\Windows-11-v22H2-Security-Baseline\Scripts\"

                Write-Host "`nApplying Microsoft Security Baseline" -ForegroundColor Cyan
                # Run the official PowerShell script included in the Microsoft Security Baseline file we downloaded from Microsoft servers
                .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined            
            } "No" { break }
            "Exit" { &$CleanUp }
        }    
        # ============================================End of Microsoft Security Baselines==========================================   
        #endregion Microsoft-Security-Baseline

        #region Overrides-for-Microsoft-Security-Baseline    
        # ============================================Overrides for Microsoft Security Baseline====================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nApply Overrides for Microsoft Security Baseline ?") {
            "Yes" {
                Write-Progress -Activity 'Overrides for Microsoft Security Baseline' -Status 'Running Overrides for Microsoft Security Baseline section' -PercentComplete 10

                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /v /m "..\Security-Baselines-X\Overrides for Microsoft Security Baseline\registry.pol"
                .\LGPO.exe /v /s "..\Security-Baselines-X\Overrides for Microsoft Security Baseline\GptTmpl.inf"
            } "No" { break }
            "Exit" { &$CleanUp }
        }    
        # ============================================End of Overrides for Microsoft Security Baseline=============================
        #endregion Overrides-for-Microsoft-Security-Baseline

        #region Microsoft-365-Apps-Security-Baseline
        # ================================================Microsoft 365 Apps Security Baseline==============================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nApply Microsoft 365 Apps Security Baseline ?") {
            "Yes" {
                Write-Progress -Activity 'Microsoft 365 Apps Security Baseline' -Status 'Running Microsoft 365 Apps Security Baseline section' -PercentComplete 15
    
                Set-Location $WorkingDir
                # Copy LGPO.exe from its folder to Microsoft Office 365 Apps for Enterprise Security Baseline folder in order to get it ready to be used by PowerShell script
                Copy-Item -Path ".\LGPO_30\LGPO.exe" -Destination '.\Microsoft 365 Apps for Enterprise-2206-FINAL\Scripts\Tools'

                # Change directory to the Security Baselines folder
                Set-Location "$WorkingDir\Microsoft 365 Apps for Enterprise-2206-FINAL\Scripts\"

                Write-Host "`nApplying Microsoft 365 Apps Security Baseline" -ForegroundColor Cyan
                # Run the official PowerShell script included in the Microsoft Security Baseline file we downloaded from Microsoft servers
                .\Baseline-LocalInstall.ps1           
            } "No" { break }
            "Exit" { &$CleanUp }
        }
        # ================================================End of Microsoft 365 Apps Security Baseline==============================================
        #endregion Microsoft-365-Apps-Security-Baseline
    
        #region Microsoft-Defender
        # ================================================Microsoft Defender=======================================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun Microsoft Defender category ?") {
            "Yes" {
                Write-Progress -Activity 'Microsoft Defender' -Status 'Running Microsoft Defender section' -PercentComplete 20

                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /m "..\Security-Baselines-X\Microsoft Defender Policies\registry.pol"
        
                # Optimizing Network Protection Performance of Windows Defender - this was off by default on Windows 11 insider build 25247
                Set-MpPreference -AllowSwitchToAsyncInspection $True

                # Add OneDrive folders of all user accounts to the Controlled Folder Access for Ransomware Protection
                Get-ChildItem "C:\Users\*\OneDrive" | ForEach-Object { Add-MpPreference -ControlledFolderAccessProtectedFolders $_ }

                # Try turning on Smart App Control
                switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nTurn on Smart App Control ?") {
                    "Yes" {               
                        if ((Get-MpComputerStatus).SmartAppControlState -eq "Eval") {
                            ModifyRegistry -path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -key 'VerifiedAndReputablePolicyState' -value '1' -type 'DWORD'
                        }
                        elseif ((Get-MpComputerStatus).SmartAppControlState -eq "On") {
                            Write-Host "Smart App Control is already turned on, skipping...`n"
                        }
                        elseif ((Get-MpComputerStatus).SmartAppControlState -eq "Off") {
                            Write-Host "Smart App Control is turned off. Can't use registry to force enable it.`n"
                        }
                    } "No" { break }
                    "Exit" { &$CleanUp }
                }
                # Enable Mandatory ASLR
                set-processmitigation -System -Enable ForceRelocateImages

                # Create scheduled task for fast weekly Microsoft recommended driver block list update
                switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nCreate scheduled task for fast weekly Microsoft recommended driver block list update ?") {
                    "Yes" { 
                        # create a scheduled task that runs every 7 days
                        if (-NOT (Get-ScheduledTask -TaskName "MSFT Driver Block list update" -ErrorAction SilentlyContinue)) {        
                            $action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
                                -Argument '-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop}catch{exit};Expand-Archive .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-Item .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "C:\Windows\System32\CodeIntegrity";citool --refresh -json;Remove-Item .\VulnerableDriverBlockList -Recurse -Force;Remove-Item .\VulnerableDriverBlockList.zip -Force;}"'    
                            $TaskPrincipal = New-ScheduledTaskPrincipal -LogonType S4U -UserId $env:USERNAME -RunLevel Highest
                            # trigger
                            $Time = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Days 7) 
                            # register the task
                            Register-ScheduledTask -Action $action -Trigger $Time -Principal $TaskPrincipal -TaskPath "MSFT Driver Block list update" -TaskName "MSFT Driver Block list update" -Description "Microsoft Recommended Driver Block List update"
                            # define advanced settings for the task
                            $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility Win8 -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
                            # add advanced settings we defined to the task
                            Set-ScheduledTask -TaskPath "MSFT Driver Block list update" -TaskName "MSFT Driver Block list update" -Settings $TaskSettings 
                        }
                    } "No" { break }
                    "Exit" { &$CleanUp }
                }
                # Set Microsoft Defender engine and platform update channel to beta - Devices in the Windows Insider Program are subscribed to this channel by default.
                switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nSet Microsoft Defender engine and platform update channel to beta ?") {
                    "Yes" {             
                        Set-MpPreference -EngineUpdatesChannel beta
                        Set-MpPreference -PlatformUpdatesChannel beta
                    } "No" { break }
                    "Exit" { &$CleanUp }
                }            
            } "No" { break }
            "Exit" { &$CleanUp }
        }    
        # ============================================End of Microsoft Defender====================================================    
        #endregion Microsoft-Defender

        #region Attack-Surface-Reduction-Rules    
        # =========================================Attack Surface Reduction Rules==================================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun Attack Surface Reduction Rules category ?") {
            "Yes" {
                Write-Progress -Activity 'Attack Surface Reduction Rules' -Status 'Running Attack Surface Reduction Rules section' -PercentComplete 25
                                
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                
                .\LGPO.exe /m "..\Security-Baselines-X\Attack Surface Reduction Rules Policies\registry.pol"
            } "No" { break }
            "Exit" { &$CleanUp }
        }
        # =========================================End of Attack Surface Reduction Rules===========================================
        #endregion Attack-Surface-Reduction-Rules
    
        #region Bitlocker-Settings    
        # ==========================================Bitlocker Settings=============================================================    
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun Bitlocker category ?") {
            "Yes" {
                Write-Progress -Activity 'Bitlocker Settings' -Status 'Running Bitlocker Settings section' -PercentComplete 30                     

                # doing this so Controlled Folder Access won't bitch about powercfg.exe
                Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Windows\System32\powercfg.exe"
                Start-Sleep 5
                # Set Hibnernate mode to full
                powercfg /h /type full
                Start-Sleep 3
                Remove-MpPreference -ControlledFolderAccessAllowedApplications "C:\Windows\System32\powercfg.exe"
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"

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
                Set-Location "$WorkingDir\LGPO_30"
            
                # Enables or disables DMA protection from Bitlocker Countermeasures based on the status of Kernel DMA protection.
                if ($bootDMAProtection) {                 
                    Write-Host "Kernel DMA protection is enabled on the system, disabling Bitlocker DMA protection." -ForegroundColor Blue
                    .\LGPO.exe /m "..\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure OFF\Registry.pol"                           
                }
                else {
                    Write-Host "Kernel DMA protection is unavailable on the system, enabling Bitlocker DMA protection." -ForegroundColor Blue
                    .\LGPO.exe /m "..\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure ON\Registry.pol"                                                          
                }

                # Set-up Bitlocker encryption for OS Drive with TPMandPIN and recovery password keyprotectors and Verify its implementation            
                # check, make sure there is no CD/DVD drives in the system, because Bitlocker throws an error when there is
                $CdDvdCheck = (Get-CimInstance -ClassName Win32_CDROMDrive -Property *).MediaLoaded
                if ($CdDvdCheck) {
                    Write-Warning "Remove any CD/DVD drives or mounted images/ISO from the system and run the Bitlocker category again."
                    # break from the current loop and continue to the next hardening category
                    break
                }
        
                # check make sure Bitlocker isn't in the middle of decryption/encryption operation (on System Drive)
                if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage -ne "100" -and (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage -ne "0") {
                    $EncryptionPercentageVar = (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage
                    Write-Host "`nPlease wait for Bitlocker to finish encrypting or decrypting the Operation System Drive." -ForegroundColor Yellow
                    Write-Host "Drive $env:SystemDrive encryption is currently at $EncryptionPercentageVar percent." -ForegroundColor Yellow
                    break
                }
                
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

                            $BitLockerMsg = "`nTPM and Startup Pin are available but the recovery password is missing, adding it now... `n" +
                            "The recovery password will be saved in a Text file in $env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt"
                            Write-Host $BitLockerMsg -ForegroundColor Yellow

                            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt"
                            Write-Host "`nMake sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." -ForegroundColor Cyan                         
                        }                
                        # if Bitlocker is using recovery password but not TPM+PIN
                        if ($KeyProtectors -notcontains 'Tpmpin' -and $KeyProtectors -contains 'recoveryPassword') {            
                            Write-Host "`nTPM and Start up PIN are missing but recovery password is in place, `nAdding TPM and Start up PIN now..." -ForegroundColor Cyan
                            do {
                                $pin1 = $(write-host "`nEnter a Pin for Bitlocker startup (at least 10 characters)" -ForegroundColor Magenta; Read-Host -AsSecureString)
                                $pin2 = $(write-host "Confirm your Bitlocker Startup Pin (at least 10 characters)" -ForegroundColor Magenta; Read-Host -AsSecureString)
                        
                                # Compare the PINs and make sure they match
                                $TheyMatch = Compare-SecureString $pin1 $pin2
                                # If the PINs match and they are at least 10 characters long
                                if ( $TheyMatch -and $pin1.Length -ge 10 -and $pin2.Length -ge 10  ) {                  
                                    $pin = $pin1                  
                                }                  
                                else { Write-Host "The PINs you entered didn't match or they weren't at least 10 characters, try again" -ForegroundColor red }                  
                            }
                            # Repeat this process until the entered PINs match and they are at least 10 characters long            
                            until ($TheyMatch -and $pin1.Length -ge 10 -and $pin2.Length -ge 10)
                 
                            try {
                                Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinProtector -Pin $pin -ErrorAction Stop
                                Write-Host "`nPINs matched, enabling TPM and startup PIN now" -ForegroundColor Green
                            }    
                            catch {         
                                Write-Host "These errors occured, run Bitlocker category again after meeting the requirements" -ForegroundColor Red
                                $Error
                                break
                            }
                        }     
                    }     
                }
                # Do this if Bitlocker is not enabled for the OS drive
                else {
                    Write-Host "`nBitlocker is Not enabled for the System Drive, activating now..." -ForegroundColor Yellow    
                    do {
                        $pin1 = $(write-host "Enter a Pin for Bitlocker startup (at least 10 characters)" -ForegroundColor Magenta; Read-Host -AsSecureString)
                        $pin2 = $(write-host "Confirm your Bitlocker Startup Pin (at least 10 characters)" -ForegroundColor Magenta; Read-Host -AsSecureString)
      
                        $TheyMatch = Compare-SecureString $pin1 $pin2
            
                        if ($TheyMatch -and $pin1.Length -ge 10 -and $pin2.Length -ge 10) {      
                            $pin = $pin1      
                        }      
                        else { Write-Host "The PINs you entered didn't match or they weren't at least 10 characters, try again" -ForegroundColor red }      
                    }      
                    until ($TheyMatch -and $pin1.Length -ge 10 -and $pin2.Length -ge 10)

                    try {
                        Enable-bitlocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -pin $pin -TpmAndPinProtector -SkipHardwareTest -ErrorAction Stop             
                    }
                    catch {
                        Write-Host "These errors occured, run Bitlocker category again after meeting the requirements" -ForegroundColor Red
                        $Error
                        break
                    }     
                    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" 
                    Resume-BitLocker -MountPoint $env:SystemDrive

                    $BitLockerMsg = "`nThe recovery password will be saved in a Text file in $env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt `n" +
                    "Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access."
                    Write-Host $BitLockerMsg -ForegroundColor Cyan

                    Write-Host "`nBitlocker is now fully and securely enabled for OS drive" -ForegroundColor Green                
                }

                # Enable Bitlocker for all the other drives
                # check if there is any other drive besides OS drive
                $NonOSVolumes = Get-Volume | Where-Object { $_.DriveType -ne "Removable" } | Where-Object { $_.DriveLetter } -PipelineVariable NonRemovableDrives |
                foreach-object { Get-BitLockerVolume | Where-Object { $_.volumeType -ne "OperatingSystem" -and $_.MountPoint -eq $($($NonRemovableDrives.DriveLetter) + ":") } }

                if ($NonOSVolumes) {
                    
                    $NonOSVolumes | Sort-Object | ForEach-Object {
                        $MountPoint = $_.MountPoint

                        # Prompt for confirmation before encrypting each drive
                        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nEncrypt $MountPoint drive ?`n") {
                            "Yes" {  

                                # Make sure the non-OS drive that the user selected to be encrypted is not in the middle of any encryption/decryption operation
                                if ((Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage -ne "100" -and (Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage -ne "0") {
                                    $EncryptionPercentageVar = (Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage
                                    Write-Host "`nPlease wait for Bitlocker to finish encrypting or decrypting drive $MountPoint" -ForegroundColor Magenta
                                    Write-Host "Drive $MountPoint encryption is currently at $EncryptionPercentageVar percent." -ForegroundColor Magenta
                                    break
                                }   
                        
                                # Check to see if Bitlocker is already turned on for the user selected drive
                                # if it is, perform multiple checks on its key protectors                        
                                if ((Get-BitLockerVolume -MountPoint $MountPoint).ProtectionStatus -eq "on") {  

                                    # Check 1: if Recovery Password and Auto Unlock key protectors are available on the drive
                                    $KeyProtectors = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector.keyprotectortype 
                                    if ($KeyProtectors -contains 'RecoveryPassword' -and $KeyProtectors -contains 'ExternalKey') {

                                        # Additional Check 1: if there is any External key key protector, try delete all of them and add a new one
                                        # The external key protector that is being used to unlock the drive will not be deleted
                                        $ExternalKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                            Where-Object { $_.keyprotectortype -eq "ExternalKey" }).KeyProtectorId

                                        $ExternalKeyProtectors | ForEach-Object {
                                            # -ErrorAction SilentlyContinue makes sure no error is thrown if the drive only has 1 External key key protector
                                            # and it's being used to unlock the drive
                                            Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ -ErrorAction SilentlyContinue                                            
                                        }
                                        Enable-BitLockerAutoUnlock -MountPoint $MountPoint

                                        # Additional Check 2: if there are more than 1 Recovery Password, delete all of them and add a new one
                                        $RecoveryPasswordKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                            Where-Object { $_.keyprotectortype -eq "RecoveryPassword" }).KeyProtectorId
                                        if ($RecoveryPasswordKeyProtectors.Count -gt 1) {

                                            $BitLockerMsg = "`nThere are more than 1 recovery password key protector associated with the drive $mountpoint `n" +
                                            "Removing all of them and adding a new one now. `n" + 
                                            "Bitlocker Recovery Password has been added for drive $MountPoint `n" +
                                            "It will be saved in a Text file in $($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt `n" +
                                            "Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." 
                                            write-host $BitLockerMsg -ForegroundColor Yellow

                                            $RecoveryPasswordKeyProtectors | ForEach-Object {
                                                Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ 
                                            }
                                            # Add new Recovery Password key protector after removing the previous ones
                                            Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt";
                                        }                                
                                        Write-Host "`nBitlocker is fully and securely enabled for drive $MountPoint" -ForegroundColor Green    
                                    }
                                    
                                    # This happens if the drive has either Recovery Password or Auto Unlock key protector missing
                                    else {

                                        # Check 2: If the selected drive has Auto Unlock key protector but doesn't have Recovery Password
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
                                            # Add Recovery Password Key protector and save it to a file inside the drive                                            
                                            Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt";
                                    
                                            $BitLockerMsg = "`nDrive $MountPoint is auto-unlocked but doesn't have Recovery Password, adding it now... `n" +
                                            "Bitlocker Recovery Password has been added for drive $MountPoint `n" +
                                            "It will be saved in a Text file in $($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt `n" +
                                            "Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access."
                                            Write-Host $BitLockerMsg -ForegroundColor Cyan
                                        }

                                        # Check 3: If the selected drive has Recovery Password key protector but doesn't have Auto Unlock enabled
                                        if ($KeyProtectors -contains 'RecoveryPassword' -and $KeyProtectors -notcontains 'ExternalKey') {
                                            Enable-BitLockerAutoUnlock -MountPoint $MountPoint
                                    
                                            # if there are more than 1 Recovery Password, delete all of them and add a new one
                                            $RecoveryPasswordKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                                Where-Object { $_.keyprotectortype -eq "RecoveryPassword" }).KeyProtectorId

                                            if ($RecoveryPasswordKeyProtectors.Count -gt 1) {

                                                $BitLockerMsg = "`nThere are more than 1 recovery password key protector associated with the drive $mountpoint `n" +
                                                "Removing all of them and adding a new one now. Bitlocker Recovery Password has been added for drive $MountPoint `n" +
                                                "It will be saved in a Text file in $($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt `n" +
                                                "Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access." 
                                                write-host $BitLockerMsg -ForegroundColor Yellow   
                                        
                                                # Delete all Recovery Passwords because there were more than 1
                                                $RecoveryPasswordKeyProtectors | ForEach-Object {
                                                    Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ 
                                                }
                                                # Add a new Recovery Password
                                                Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt";
                                            }                                    
                                        }                      
                                    }
                                }

                                # Do this if Bitlocker isn't turned on at all on the user selected drive
                                else {
                                    Enable-BitLocker -MountPoint $MountPoint -RecoveryPasswordProtector *> "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt";
                                    Enable-BitLockerAutoUnlock -MountPoint $MountPoint

                                    $BitLockerMsg = "`nBitlocker has started encrypting drive $MountPoint `n" +
                                    "Recovery password will be saved in a Text file in $($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt `n" +
                                    "Make sure to keep it in a safe place, e.g. in OneDrive's Personal Vault which requires authentication to access."
                                    Write-Host $BitLockerMsg -ForegroundColor Cyan
                                }                                

                            } "No" { break }
                            "Exit" { &$CleanUp }
                        }                            
                    }
                }
            } "No" { break }
            "Exit" { &$CleanUp }
        }    
        # ==========================================End of Bitlocker Settings======================================================    
        #endregion Bitlocker-Settings

        #region TLS-Security    
        # ==============================================TLS Security===============================================================    
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun TLS Security category ?") {
            "Yes" {
                Write-Progress -Activity 'TLS Security' -Status 'Running TLS Security section' -PercentComplete 35
                                
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
                Set-Location $WorkingDir
                $items = Import-Csv '.\Registry.csv' -Delimiter ","
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
            "Exit" { &$CleanUp }
        }    
        # ==========================================End of TLS Security============================================================
        #endregion TLS-Security

        #region Lock-Screen    
        # ==========================================Lock Screen====================================================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun Lock Screen category ?") {
            "Yes" {
                Write-Progress -Activity 'Lock Screen' -Status 'Running Lock Screen section' -PercentComplete 40
                                
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /m "..\Security-Baselines-X\Lock Screen Policies\registry.pol"
                .\LGPO.exe /s "..\Security-Baselines-X\Lock Screen Policies\GptTmpl.inf"        
            } "No" { break }
            "Exit" { &$CleanUp }
        }    
        # ==========================================End of Lock Screen=============================================================
        #endregion Lock-Screen

        #region User-Account-Control
        # ==========================================User Account Control===========================================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun User Account Control category ?") {
            "Yes" {
                Write-Progress -Activity 'User Account Control' -Status 'User Account Control section' -PercentComplete 45

                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /s "..\Security-Baselines-X\User Account Control UAC Policies\GptTmpl.inf" 
            
                # built-in Administrator account enablement
                switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nEnable the built-in Administrator account and set password for it?") {
                    "Yes" {
                        # show password policy details
                        Write-Host "`nHere are the current password & logon restrictions`n"
                        net accounts
                        do {
                            $Password1 = Get-Credential -UserName Administrator -Message "Enter a password for the built-in Administrator account"
                            #$Password1 = $host.ui.ReadLineAsSecureString()                            
                            $Password2 = Get-Credential -UserName Administrator -Message "Confirm your password for the built-in Administrator account"
                            #$Password2 = $host.ui.ReadLineAsSecureString()

                            $TheyMatch = Compare-SecureString $Password1.Password $Password2.Password
            
                            if ($TheyMatch) {
                                Set-LocalUser -Name "Administrator" -Password $Password1.Password
                            }      
                            else { Write-Host "the passwords you entered didn't match, try again" -ForegroundColor red }
                        }      
                        until ($TheyMatch -and $?)

                        if (-NOT ((Get-LocalUser | Where-Object { $_.name -eq "Administrator" }).enabled)) {
                            Enable-LocalUser -Name "Administrator"
                            Write-Host "Enabling Built-in Administrator account.`n" -ForegroundColor Green
                        }
                        else {
                            Write-Host "Built-in Administrator account is already enabled.`n" -ForegroundColor Green
                        }
                    } "No" { break }
                    "Exit" { &$CleanUp }
                }    
            } "No" { break }
            "Exit" { &$CleanUp }
        }    
        # ==========================================End of User Account Control====================================================
        #endregion User-Account-Control

        #region Device-Guard    
        # ==========================================Device Guard===================================================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun Device Guard category ?") {
            "Yes" {
                Write-Progress -Activity 'Device Guard' -Status 'Running Device Guard section' -PercentComplete 50
                
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /m "..\Security-Baselines-X\Device Guard Policies\registry.pol"
            } "No" { break }
            "Exit" { &$CleanUp }
        }    
        # ==========================================End of Device Guard============================================================
        #endregion Device-Guard

        #region Windows-Firewall    
        # ====================================================Windows Firewall=====================================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun Windows Firewall category ?") {
            "Yes" {
                Write-Progress -Activity 'Windows Firewall' -Status 'Running Windows Firewall section' -PercentComplete 55
                                
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /m "..\Security-Baselines-X\Windows Firewall Policies\registry.pol"

                # Disables Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles - disables only 3 rules
                get-NetFirewallRule |
                Where-Object { $_.RuleGroup -eq "@%SystemRoot%\system32\firewallapi.dll,-37302" -and $_.Direction -eq "inbound" } |
                ForEach-Object { Disable-NetFirewallRule -DisplayName $_.DisplayName }
            } "No" { break }
            "Exit" { &$CleanUp }
        }    
        # =================================================End of Windows Firewall=================================================
        #endregion Windows-Firewall

        #region Optional-Windows-Features    
        # =================================================Optional Windows Features===============================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun Optional Windows Features category ?") {
            "Yes" {
                Write-Progress -Activity 'Optional Windows Features' -Status 'Running Optional Windows Features section' -PercentComplete 60
                                
                # since PowerShell Core (only if installed from Microsoft Store) has problem with these commands, making sure the built-in PowerShell handles them
                # There are Github issues for it already: https://github.com/PowerShell/PowerShell/issues/13866
            
                # Disable PowerShell v2 (needs 2 commands)
                PowerShell.exe "Write-Host 'Disabling PowerShellv2 1st command' -ForegroundColor Yellow;if((get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart}else{Write-Host 'MicrosoftWindowsPowerShellV2 is already disabled' -ForegroundColor Darkgreen}"
                PowerShell.exe "Write-Host 'Disabling PowerShellv2 2nd command' -ForegroundColor Yellow;if((get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart}else{Write-Host 'MicrosoftWindowsPowerShellV2Root is already disabled' -ForegroundColor Darkgreen}"
                # Disable Work Folders client
                PowerShell.exe "Write-Host 'Disabling Work Folders' -ForegroundColor Yellow;if((get-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -norestart}else{Write-Host 'WorkFolders-Client is already disabled' -ForegroundColor Darkgreen}"
                # Disable Internet Printing Client
                PowerShell.exe "Write-Host 'Disabling Internet Printing Client' -ForegroundColor Yellow;if((get-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features -norestart}else{Write-Host 'Printing-Foundation-Features is already disabled' -ForegroundColor Darkgreen}"
                # Disable Windows Media Player (legacy)
                PowerShell.exe "Write-Host 'Disabling Windows Media Player (Legacy)' -ForegroundColor Yellow;if((get-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer).state -eq 'enabled'){disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -norestart}else{Write-Host 'WindowsMediaPlayer is already disabled' -ForegroundColor Darkgreen}"            
                # Enable Microsoft Defender Application Guard
                PowerShell.exe "Write-Host 'Enabling Microsoft Defender Application Guard' -ForegroundColor Yellow;if((get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -norestart}else{Write-Host 'Microsoft-Defender-ApplicationGuard is already enabled' -ForegroundColor Darkgreen}"
                # Enable Windows Sandbox
                PowerShell.exe "Write-Host 'Enabling Windows Sandbox' -ForegroundColor Yellow;if((get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -norestart}else{Write-Host 'Containers-DisposableClientVM (Windows Sandbox) is already enabled' -ForegroundColor Darkgreen}"
                # Enable Hyper-V
                PowerShell.exe "Write-Host 'Enabling Hyper-V' -ForegroundColor Yellow;if((get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -norestart}else{Write-Host 'Microsoft-Hyper-V is already enabled' -ForegroundColor Darkgreen}"
                # Enable Virtual Machine Platform
                PowerShell.exe "Write-Host 'Enabling Virtual Machine Platform' -ForegroundColor Yellow;if((get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -norestart}else{Write-Host 'VirtualMachinePlatform is already enabled' -ForegroundColor Darkgreen}"
            
                # Uninstall VBScript that is now uninstallable as an optional features since Windows 11 insider Dev build 25309 - Won't do anything in other builds                      
                PowerShell.exe 'if (Get-WindowsCapability -Online | Where-Object { $_.Name -like ''*VBSCRIPT*'' }){`
            Get-WindowsCapability -Online | Where-Object { $_.Name -like ''*VBSCRIPT*'' } | remove-WindowsCapability -Online;`
            Write-Host "VBSCRIPT has been uninstalled" -ForegroundColor Green}'         
                # Uninstall Internet Explorer mode functionality for Edge
                PowerShell.exe 'Get-WindowsCapability -Online | Where-Object { $_.Name -like ''*Browser.InternetExplorer*'' } | remove-WindowsCapability -Online'
                Write-Host "Internet Explorer mode functionality for Edge has been uninstalled" -ForegroundColor Green
                # Uninstall WMIC
                PowerShell.exe 'Get-WindowsCapability -Online | Where-Object { $_.Name -like ''*wmic*'' } | remove-WindowsCapability -Online'
                Write-Host "WMIC has been uninstalled" -ForegroundColor Green
                # Uninstall Legacy Notepad
                PowerShell.exe 'Get-WindowsCapability -Online | Where-Object { $_.Name -like ''*Microsoft.Windows.Notepad.System*'' } | remove-WindowsCapability -Online'
                Write-Host "Legacy Notepad has been uninstalled. The modern multi-tabbed Notepad is unaffected." -ForegroundColor Green
            } "No" { break }
            "Exit" { &$CleanUp }
        }    
        # ==============================================End of Optional Windows Features===========================================
        #endregion Optional-Windows-Features

        #region Windows-Networking    
        # ====================================================Windows Networking===================================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun Windows Networking category ?") {
            "Yes" {
                Write-Progress -Activity 'Windows Networking' -Status 'Running Windows Networking section' -PercentComplete 65

                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /m "..\Security-Baselines-X\Windows Networking Policies\registry.pol"

                # disable LMHOSTS lookup protocol on all network adapters
                ModifyRegistry -path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -key 'EnableLMHOSTS' -value '0' -type 'DWORD'

                # Set the Network Location of all connections to Public
                Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Public
            } "No" { break }
            "Exit" { &$CleanUp }
        }    
        # =================================================End of Windows Networking===============================================
        #endregion Windows-Networking

        #region Miscellaneous-Configurations    
        # ==============================================Miscellaneous Configurations===============================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun Miscellaneous Configurations category ?") {
            "Yes" {
                Write-Progress -Activity 'Miscellaneous Configurations' -Status 'Running Miscellaneous Configurations section' -PercentComplete 70
                                
                # Miscellaneous Registry section
                Set-Location $WorkingDir
                $items = Import-Csv '.\Registry.csv' -Delimiter ","
                foreach ($item in $items) {
                    if ($item.category -eq 'Miscellaneous') {              
                        ModifyRegistry -path $item.path -key $item.key -value $item.value -type $item.type
                    }
                }
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /m "..\Security-Baselines-X\Miscellaneous Policies\registry.pol"
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
            "Exit" { &$CleanUp }
        }    
        # ============================================End of Miscellaneous Configurations==========================================
        #endregion Miscellaneous-Configurations
 
        #region Windows-Update-Configurations    
        # ====================================================Windows Update Configurations==============================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nApply Windows Update Policies ?") {
            "Yes" {
                Write-Progress -Activity 'Windows Update Configurations' -Status 'Running Windows Update Configurations section' -PercentComplete 75

                # enable restart notification for Windows update
                ModifyRegistry -path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -key "RestartNotificationsAllowed2" -value "1" -type 'DWORD'
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /m "..\Security-Baselines-X\Windows Update Policies\registry.pol"
            } "No" { break }
            "Exit" { &$CleanUp }
        }    
        # ====================================================End of Windows Update Configurations=======================================
        #endregion Windows-Update-Configurations

        #region Edge-Browser-Configurations
        # ====================================================Edge Browser Configurations====================================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nApply Edge Browser Configurations ?") {
            "Yes" {
                Write-Progress -Activity 'Edge Browser Configurations' -Status 'Running Edge Browser Configurations section' -PercentComplete 80

                # Edge Browser Configurations registry
                Set-Location $WorkingDir
                $items = Import-Csv '.\Registry.csv' -Delimiter ","
                foreach ($item in $items) {
                    if ($item.category -eq 'Edge') {
                        ModifyRegistry -path $item.path -key $item.key -value $item.value -type $item.type
                    }
                }
            } "No" { break }
            "Exit" { &$CleanUp }
        } 
        # ====================================================End of Edge Browser Configurations==============================================
        #endregion Edge-Browser-Configurations

        #region Top-Security-Measures    
        # ============================================Top Security Measures========================================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nApply Top Security Measures ? Make sure you've read the GitHub repository") {
            "Yes" {                
                Write-Progress -Activity 'Top Security Measures' -Status 'Running Top Security Measures section' -PercentComplete 85
                                
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /s "..\Security-Baselines-X\Top Security Measures\GptTmpl.inf"
                .\LGPO.exe /m "..\Security-Baselines-X\Top Security Measures\registry.pol"
            } "No" { break }
            "Exit" { &$CleanUp }
        }    
        # ============================================End of Top Security Measures=================================================
        #endregion Top-Security-Measures

        #region Certificate-Checking-Commands    
        # ====================================================Certificate Checking Commands========================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun Certificate Checking category ?") {
            "Yes" {
                Write-Progress -Activity 'Certificate Checking Commands' -Status 'Running Certificate Checking Commands section' -PercentComplete 90
               
                try {
                    Invoke-WithoutProgress {                    
                        Invoke-WebRequest -Uri "https://live.sysinternals.com/sigcheck64.exe" -OutFile "sigcheck64.exe" -ErrorAction Stop
                    }                
                }
                catch {                    
                    Write-Host "sigcheck64.exe couldn't be downloaded from https://live.sysinternals.com" -ForegroundColor Red
                    break
                }      
                Write-Host -nonewline "`nListing valid certificates not rooted to the Microsoft Certificate Trust List in the" -ForegroundColor Yellow; write-host " User store`n" -ForegroundColor cyan
                .\sigcheck64.exe -tuv -accepteula -nobanner     
    
                Write-Host -nonewline "`nListing valid certificates not rooted to the Microsoft Certificate Trust List in the" -ForegroundColor Yellow; write-host " Machine Store`n" -ForegroundColor Blue
                .\sigcheck64.exe -tv -accepteula -nobanner
                Remove-Item .\sigcheck64.exe -Force
            } "No" { break }
            "Exit" { &$CleanUp }
        }
        # ====================================================End of Certificate Checking Commands=================================
        #endregion Certificate-Checking-Commands

        #region Country-IP-Blocking    
        # ====================================================Country IP Blocking==================================================
        switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun Country IP Blocking category ?") {
            "Yes" {
                Write-Progress -Activity 'Country IP Blocking' -Status 'Running Country IP Blocking section' -PercentComplete 95

                # -RemoteAddress in New-NetFirewallRule accepts array according to Microsoft Docs, 
                # so we use "[string[]]$IPList = $IPList -split '\r?\n' -ne ''" to convert the IP lists, which is a single multiline string, into an array
                function BlockCountryIP {
                    param ($IPList , $ListName)
                    # deletes previous rules (if any) to get new up-to-date IP ranges from the sources and set new rules               
                    Remove-NetFirewallRule -DisplayName "$ListName IP range blocking" -PolicyStore localhost -ErrorAction SilentlyContinue
                    # converts the list which is in string into array
                    [string[]]$IPList = $IPList -split '\r?\n' -ne ''
                    # makes sure the list isn't empty
                    if ($IPList.count -eq 0) { Write-Host "The IP list was empty, skipping $ListName" -ForegroundColor Yellow ; break }      
                    New-NetFirewallRule -DisplayName "$ListName IP range blocking" -Direction Inbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$ListName IP range blocking" -EdgeTraversalPolicy Block -PolicyStore localhost
                    New-NetFirewallRule -DisplayName "$ListName IP range blocking" -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$ListName IP range blocking" -EdgeTraversalPolicy Block -PolicyStore localhost        
                }
                switch (Select-Option -Options "Yes", "No" -Message "Add countries in the State Sponsors of Terrorism list to the Firewall block list?") {
                    "Yes" {
                        $StateSponsorsofTerrorism = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/StateSponsorsOfTerrorism.txt"
                        BlockCountryIP -IPList $StateSponsorsofTerrorism -ListName "State Sponsors of Terrorism"
                    } "No" { break }
                }
                switch (Select-Option -Options "Yes", "No" -Message "Add OFAC Sanctioned Countries to the Firewall block list?") {
                    "Yes" {
                        $OFACSanctioned = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/OFACSanctioned.txt"            
                        BlockCountryIP -IPList $OFACSanctioned -ListName "OFAC Sanctioned Countries"
                    } "No" { break }
                }
                # how to query the number of IPs in each rule
                # (Get-NetFirewallRule -DisplayName "OFAC Sanctioned Countries IP range blocking" -PolicyStore localhost | Get-NetFirewallAddressFilter).RemoteAddress.count
            } "No" { break }
            "Exit" { &$CleanUp }
        }    
        # ====================================================End of Country IP Blocking===========================================
        #endregion Country-IP-Blocking
    
    } # End of Admin test function

    #region Non-Admin-Commands
    # ====================================================Non-Admin Commands===================================================
    switch (Select-Option -Options "Yes", "No", "Exit" -Message "`nRun Non-Admin category ?") {
        "Yes" {
            Write-Progress -Activity 'Non-Admin Commands' -Status 'Running Non-Admin Commands section' -PercentComplete 100
            
            # Non-Admin Registry section              
            Set-Location $WorkingDir       
            Invoke-WithoutProgress { 
                # Download Registry CSV file               
                Invoke-WebRequest -Uri "https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Payload/Registry.csv" -OutFile ".\Registry.csv"
            }
            $items = Import-Csv '.\Registry.csv' -Delimiter ","
            foreach ($item in $items) {
                if ($item.category -eq 'NonAdmin') {              
                    ModifyRegistry -path $item.path -key $item.key -value $item.value -type $item.type
                }
            }  

            # Only suggest restarting the device if Admin related categories were run
            if (Test-IsAdmin) {          
                $infomsg = "`r`n" +
                "################################################################################################`r`n" +
                "###  Please Restart your device to completely apply the security measures and Group Policies ###`r`n" +
                "################################################################################################`r`n"
                Write-Host $infomsg -ForegroundColor Cyan
            }

        } "No" { &$CleanUp }
        "Exit" { &$CleanUp }
    }
    # ====================================================End of Non-Admin Commands============================================
    #endregion Non-Admin-Commands
}
finally {
    if (Test-IsAdmin) {
        # Reverting the PowerShell executables allow listings in Controlled folder access
        Get-ChildItem -Path "$PSHOME\*.exe" | ForEach-Object {
            Remove-MpPreference -ControlledFolderAccessAllowedApplications $_.FullName
        }
        # restoring the original Controlled folder access allow list - if user already had added PowerShell executables to the list
        # they will be restored as well, so user customization will remain intact
        if ($null -ne $CFAAllowedAppsBackup) { 
            $CFAAllowedAppsBackup | ForEach-Object {
                Add-MpPreference -ControlledFolderAccessAllowedApplications $_
            }
        }
    }
    Set-Location $HOME; remove-item -Recurse "$env:TEMP\HardeningXStuff\" -Force -ErrorAction SilentlyContinue    
}