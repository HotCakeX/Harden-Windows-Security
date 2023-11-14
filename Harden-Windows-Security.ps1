<#PSScriptInfo

.VERSION 2023.11.8

.GUID d435a293-c9ee-4217-8dc1-4ad2318a5770

.AUTHOR HotCakeX

.COMPANYNAME SpyNetGirl

.COPYRIGHT 2023

.TAGS Windows Hardening Security BitLocker Defender Firewall Edge Protection Baseline TLS UAC Encryption

.LICENSEURI https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE

.PROJECTURI https://github.com/HotCakeX/Harden-Windows-Security

.ICONURI https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PowerShellGalleryICONURI.png

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES

#>

<# 

.SYNOPSIS
    Harden Windows Safely, Securely, only with Official Microsoft methods

.DESCRIPTION

  ⭕ You need to read the GitHub's readme page before running this: https://github.com/HotCakeX/Harden-Windows-Security

  ⭕ This script is only for users that use the old PowerShell 5.1. It's highly recommended to use new PowerShell versions and the new Harden Windows Security Module that offers hardening + Auditing + Undoing hardening: https://www.powershellgallery.com/packages/Harden-Windows-Security-Module/
  
💠 Features of this Hardening script:

  ✅ Everything always stays up-to-date with the newest proactive security measures that are industry standards and scalable.
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
  ✅ BitLocker Settings
  ✅ TLS Security
  ✅ Lock Screen
  ✅ UAC (User Account Control)
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


🏴 If you have any questions, requests, suggestions etc. about this script, please open a new Discussion or Issue on GitHub


.EXAMPLE  

.NOTES  

    Check out GitHub page for security recommendations: https://github.com/HotCakeX/Harden-Windows-Security

#>

# Change the execution policy temporarily only for the current PowerShell session
Set-ExecutionPolicy Bypass -Scope Process

# Defining global script variables
# Current script's version, the same as the version at the top in the script info section
[datetime]$CurrentVersion = '2023.11.8'
# Minimum OS build number required for the hardening measures used in this script
[decimal]$Requiredbuild = '22621.2428'
# Fetching Temp Directory
[System.String]$global:UserTempDirectoryPath = [System.IO.Path]::GetTempPath()
# The total number of the main categories for the parent/main progress bar to render
[System.Int64]$TotalMainSteps = 18
# Defining a global boolean variable to determine whether optional diagnostic data should be enabled for Smart App Control or not
[bool]$ShouldEnableOptionalDiagnosticData = $false

#region Functions
# Questions function
function Select-Option {
    param(
        [parameter(Mandatory = $True)][System.String]$Message, # Contains the main prompt message
        [parameter(Mandatory = $True)][string[]]$Options,
        [parameter(Mandatory = $false)][switch]$SubCategory,
        [parameter(Mandatory = $false)][System.String]$ExtraMessage # Contains any extra notes for sub-categories
    )

    $Selected = $null
    while ($null -eq $Selected) {

        # Use this style if showing main categories only
        if (!$SubCategory) {            
            Write-SmartText -C Fuchsia -G Magenta -I $Message
        }
        # Use this style if showing sub-categories only that need additional confirmation
        else {
            # Show sub-category's main prompt
            Write-SmartText -C Orange -G Cyan -I $Message
            # Show sub-category's notes/extra message if any
            if ($ExtraMessage) {
                Write-SmartText -C PinkBoldBlink -G Yellow -I $ExtraMessage
            }
        }

        for ($i = 0; $i -lt $Options.Length; $i++) {             
            Write-SmartText -C MintGreen -G White -I "$($i+1): $($Options[$i])"
        }

        # Make sure user only inputs a positive integer
        [System.Int64]$SelectedIndex = 0
        $isValid = [System.Int64]::TryParse((Read-Host 'Select an option'), [ref]$SelectedIndex)
        if ($isValid) {
            if ($SelectedIndex -gt 0 -and $SelectedIndex -le $Options.Length) { 
                $Selected = $Options[$SelectedIndex - 1] 
            }
            else {                 
                Write-Warning -Message 'Invalid Option.'
            }
        }
        else {
            Write-Warning -Message 'Invalid input. Please only enter a positive number.'
        }  
    }
    return $Selected
}

# Function to modify registry
function Edit-Registry {
    param ($Path, $Key, $Value, $Type, $Action)
    If (-NOT (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    if ($Action -eq 'AddOrModify') {
        New-ItemProperty -Path $Path -Name $Key -Value $Value -PropertyType $Type -Force
    }
    elseif ($Action -eq 'Delete') {
        Remove-ItemProperty -Path $Path -Name $Key -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

# https://devblogs.microsoft.com/scripting/use-function-to-determine-elevation-of-powershell-console/
# Function to test if current session has administrator privileges
Function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Hiding Invoke-WebRequest progress because it creates lingering visual effect on PowerShell console for some reason
# https://github.com/PowerShell/PowerShell/issues/14348

# https://stackoverflow.com/questions/18770723/hide-progress-of-Invoke-WebRequest
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

# Function to write colorful text based on PS edition
Function Write-SmartText {
    [CmdletBinding()]
    [Alias('WST')]

    param (
        [Parameter(Mandatory = $True)]
        [Alias('C')]
        [ValidateSet('Fuchsia', 'Orange', 'NeonGreen', 'MintGreen', 'PinkBoldBlink', 'PinkBold', 'Rainbow' , 'Gold')]
        [System.String]$CustomColor,

        [Parameter(Mandatory = $True)]
        [Alias('G')]
        [ValidateSet('Green', 'Red', 'Magenta', 'Blue', 'Black', 'Cyan', 'DarkBlue', 'DarkCyan', 'DarkRed', 'Gray', 'Yellow', 'White', 'DarkGray', 'DarkGreen', 'DarkMagenta', 'DarkYellow')]
        [System.String]$GenericColor,

        [parameter(Mandatory = $True)]
        [Alias('I')]
        [System.String]$InputText
    )

    begin {
        
        # Determining if PowerShell is core to use modern styling
        [bool]$IsCore = $false
        if ([version]$PSVersionTable.PSVersion -ge [version]7.3) {
            [bool]$IsCore = $True
        }

    }

    process {
     
        # Check if the current PowerShell is Core using the global variable
        if ($IsCore) {

            switch ($CustomColor) {
                'Fuchsia' { Write-Host "$($PSStyle.Foreground.FromRGB(236,68,155))$InputText$($PSStyle.Reset)"; break }
                'Orange' { Write-Host "$($PSStyle.Foreground.FromRGB(255,165,0))$InputText$($PSStyle.Reset)"; break }
                'NeonGreen' { Write-Host "$($PSStyle.Foreground.FromRGB(153,244,67))$InputText$($PSStyle.Reset)"; break }
                'MintGreen' { Write-Host "$($PSStyle.Foreground.FromRGB(152,255,152))$InputText$($PSStyle.Reset)"; break }
                'PinkBoldBlink' { Write-Host "$($PSStyle.Foreground.FromRgb(255,192,203))$($PSStyle.Bold)$($PSStyle.Blink)$InputText$($PSStyle.Reset)"; break }
                'PinkBold' { Write-Host "$($PSStyle.Foreground.FromRgb(255,192,203))$($PSStyle.Bold)$($PSStyle.Reverse)$InputText$($PSStyle.Reset)"; break }
                'Gold' { Write-Host "$($PSStyle.Foreground.FromRgb(255,215,0))$($PSStyle.Bold)$($PSStyle.Reverse)$InputText$($PSStyle.Reset)"; break }
                'Rainbow' {
                    $colors = @(
                        [System.Drawing.Color]::Pink,
                        [System.Drawing.Color]::HotPink,
                        [System.Drawing.Color]::SkyBlue,
                        [System.Drawing.Color]::HotPink,
                        [System.Drawing.Color]::SkyBlue,
                        [System.Drawing.Color]::LightSkyBlue,      
                        [System.Drawing.Color]::LightGreen,
                        [System.Drawing.Color]::Coral,
                        [System.Drawing.Color]::Plum,
                        [System.Drawing.Color]::Gold
                    )
  
                    $output = ''
                    for ($i = 0; $i -lt $InputText.Length; $i++) {
                        $color = $colors[$i % $colors.Length]
                        $output += "$($PSStyle.Foreground.FromRGB($color.R, $color.G, $color.B))$($PSStyle.Blink)$($InputText[$i])$($PSStyle.BlinkOff)$($PSStyle.Reset)"
                    }
                    Write-Output $output
                    break
                }

                Default { Throw 'Unspecified Color' }
            }
        }
        else {
            Write-Host $InputText -ForegroundColor $GenericColor
        }
    }
}
#endregion functions

if (Test-IsAdmin) {

    # Get the current configurations and preferences of the Microsoft Defender
    New-Variable -Name 'MDAVConfigCurrent' -Value (Get-MpComputerStatus) -Force
    New-Variable -Name 'MDAVPreferencesCurrent' -Value (Get-MpPreference) -Force
    
    # backup the current allowed apps list in Controlled folder access in order to restore them at the end of the script
    # doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
    # no user customization will be affected
    [string[]]$CFAAllowedAppsBackup = $MDAVPreferencesCurrent.ControlledFolderAccessAllowedApplications    

    # Temporarily allow the currently running PowerShell executables to the Controlled Folder Access allowed apps
    # so that the script can run without interruption. This change is reverted at the end.
    Get-ChildItem -Path "$PSHOME\*.exe" | ForEach-Object {
        Add-MpPreference -ControlledFolderAccessAllowedApplications $_.FullName
    }
}

# doing a try-finally block on the entire script so that when CTRL + C is pressed to forcefully exit the script,
# or break is passed, clean up will still happen for secure exit
try {
    try {
        Invoke-WithoutProgress {   
            [datetime]$global:LatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Version.txt'
        }
    }
    catch {
        Write-Error "Couldn't verify if the latest version of the script is installed, please check your Internet connection."
        break
    }
    # Check the current hard-coded version against the latest version online
    if ($CurrentVersion -lt $LatestVersion) {
        Write-Host "The currently installed script's version is $CurrentVersion while the latest version is $LatestVersion" -ForegroundColor Cyan
        Write-Host 'Please update your script using:' -ForegroundColor Yellow
        Write-Host "Update-Script -Name 'Harden-Windows-Security' -Force" -ForegroundColor Green
        Write-Host 'and run it again after that.' -ForegroundColor Yellow        
        Write-Host 'You can view the change log on GitHub: https://github.com/HotCakeX/Harden-Windows-Security/releases' -ForegroundColor Magenta
        break
    }
   
    Write-Host "`r`n"
    Write-SmartText -CustomColor Rainbow -GenericColor Cyan -InputText "############################################################################################################`r`n"
    Write-SmartText -CustomColor MintGreen -GenericColor Cyan -InputText "### Please read the Readme in the GitHub repository: https://github.com/HotCakeX/Harden-Windows-Security ###`r`n"
    Write-SmartText -CustomColor Rainbow -GenericColor Cyan -InputText "############################################################################################################`r`n"

    #region RequirementsCheck
    # check if user's OS is Windows Home edition
    if ((Get-CimInstance -ClassName Win32_OperatingSystem).OperatingSystemSKU -eq '101') {
        Write-Error 'Windows Home edition detected, exiting...'
        break
    }

    # check if user's OS is the latest build
    # Get OS build version
    [decimal]$OSBuild = [System.Environment]::OSVersion.Version.Build
    # Get Update Build Revision (UBR) number
    [decimal]$UBR = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR'
    # Create full OS build number as seen in Windows Settings
    [decimal]$FullOSBuild = "$OSBuild.$UBR"
    # Make sure the current OS build is equal or greater than the required build
    if (-NOT ($FullOSBuild -ge $Requiredbuild)) {
        Write-Error "You're not using the latest build of the Windows OS. A minimum build of $Requiredbuild is required but your OS build is $FullOSBuild`nPlease go to Windows Update to install the updates and then try again."
        break
    }

    if (Test-IsAdmin) {
        # check to make sure Secure Boot is enabled
        if (-NOT (Confirm-SecureBootUEFI)) {
            Write-Error 'Secure Boot is not enabled, please go to your UEFI settings to enable it and then try again.'
            break    
        }

        # check to make sure TPM is available and enabled
        [bool]$TPMFlag1 = (Get-Tpm).tpmpresent
        [bool]$TPMFlag2 = (Get-Tpm).tpmenabled
        if (!$TPMFlag1 -or !$TPMFlag2) {
            Write-Error 'TPM is not available or enabled, please go to your UEFI settings to enable it and then try again.'
            break    
        }
        
        if (-NOT ($MDAVConfigCurrent.AMServiceEnabled -eq $true)) {
            Write-Error 'Microsoft Defender Anti Malware service is not enabled, please enable it and then try again.'
            break            
        } 

        if (-NOT ($MDAVConfigCurrent.AntispywareEnabled -eq $true)) {
            Write-Error 'Microsoft Defender Anti Spyware is not enabled, please enable it and then try again.'
            break            
        } 

        if (-NOT ($MDAVConfigCurrent.AntivirusEnabled -eq $true)) {
            Write-Error 'Microsoft Defender Anti Virus is not enabled, please enable it and then try again.'
            break            
        } 
        
        if ($MDAVConfigCurrent.AMRunningMode -ne 'Normal') {
            Write-Error "Microsoft Defender is running in $($MDAVConfigCurrent.AMRunningMode) state, please remove any 3rd party AV and then try again."
            break
        }
        
    }
    #endregion RequirementsCheck

    # create our working directory
    New-Item -ItemType Directory -Path "$global:UserTempDirectoryPath\HardeningXStuff\" -Force | Out-Null
    # working directory assignment
    [System.String]$WorkingDir = "$global:UserTempDirectoryPath\HardeningXStuff\"
    # change location to the new directory
    Set-Location $WorkingDir

    # Clean up script block
    [scriptblock]$CleanUp = {
        Set-Location $HOME
        Remove-Item -Recurse -Path "$global:UserTempDirectoryPath\HardeningXStuff\" -Force
        # Disable progress bars
        0..5 | ForEach-Object { Write-Progress -Id $_ -Activity 'Done' -Completed }
        exit 
    }

    if (-NOT (Test-IsAdmin)) {
        Write-SmartText -CustomColor NeonGreen -GenericColor Magenta -InputText 'Skipping commands that require Administrator privileges'
    }
    else {   
        
        [System.Int64]$CurrentMainStep = 0
        Write-Progress -Id 0 -Activity 'Downloading the required files' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete 1
            
        try {
                                 
            # Create an array of files to download
            [System.Object[]]$Files = @(
                # System.Net.WebClient requires absolute path instead of relative one      
                @{url = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Windows%2011%20v23H2%20Security%20Baseline.zip'; path = "$WorkingDir\MicrosoftSecurityBaseline.zip"; tag = 'MicrosoftSecurityBaseline' }
                @{url = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Microsoft%20365%20Apps%20for%20Enterprise%202306.zip'; path = "$WorkingDir\Microsoft365SecurityBaseline.zip"; tag = 'Microsoft365SecurityBaseline' }
                @{url = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip'; path = "$WorkingDir\LGPO.zip"; tag = 'LGPO' }
                @{url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Payload/Security-Baselines-X.zip'; path = "$WorkingDir\Security-Baselines-X.zip"; tag = 'Security-Baselines-X' }
                @{url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Payload/Registry.csv'; path = "$WorkingDir\Registry.csv"; tag = 'Registry' }
                @{url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Payload/ProcessMitigations.csv'; path = "$WorkingDir\ProcessMitigations.csv"; tag = 'ProcessMitigations' }
                @{url = 'https://github.com/HotCakeX/Harden-Windows-Security/raw/main/Payload/EventViewerCustomViews.zip'; path = "$WorkingDir\EventViewerCustomViews.zip"; tag = 'EventViewerCustomViews' }
            )
                    
            # Get the total number of files to download
            [System.Int64]$TotalRequiredFiles = $Files.Count
                    
            # Initialize a counter for the progress bar
            [System.Int64]$RequiredFilesCounter = 0
                        
            # Start a job for each file download    
            [System.Object[]]$Jobs = foreach ($File in $Files) {              
                                
                Start-Job -ErrorAction Stop -ScriptBlock {
                        
                    param($Url, $Path, $Tag)
                    # Create a WebClient object
                    [System.Net.WebClient]$WC = New-Object System.Net.WebClient
                    try {
                        # Try to download the file from the original URL
                        $WC.DownloadFile($Url, $Path)
                    }
                    catch {
                        # a switch for when the original URLs are failing and to provide Alt URL
                        switch ($Tag) {                                                        
                            'Security-Baselines-X' {
                                Write-Host 'Using Azure DevOps for Security-Baselines-X.zip' -ForegroundColor Yellow
                                $AltURL = 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/Security-Baselines-X.zip'
                                $WC.DownloadFile($AltURL, $Path)
                                break
                            }        
                            'Registry' {
                                Write-Host 'Using Azure DevOps for Registry.csv' -ForegroundColor Yellow
                                $AltURL = 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/Registry.csv'
                                $WC.DownloadFile($AltURL, $Path)
                                break
                            }        
                            'ProcessMitigations' {                            
                                Write-Host 'Using Azure DevOps for ProcessMitigations.CSV' -ForegroundColor Yellow
                                $AltURL = 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/ProcessMitigations.csv'
                                $WC.DownloadFile($AltURL, $Path)
                                break
                            } 
                            'EventViewerCustomViews' {
                                Write-Host 'Using Azure DevOps for EventViewerCustomViews.zip' -ForegroundColor Yellow
                                $AltURL = 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/EventViewerCustomViews.zip'
                                $WC.DownloadFile($AltURL, $Path)
                                break
                            }       
                            default {
                                # Write an error if any other URL fails and stop the script
                                Write-Error $_
                            }
                        }                
                    }            
                } -ArgumentList $File.url, $File.path, $File.tag
                        
                # Increment the counter by one
                $RequiredFilesCounter++
                        
                # Write the progress of the download jobs
                Write-Progress -Id 1 -ParentId 0 -Activity "Downloading $($file.tag)" -Status "$RequiredFilesCounter of $TotalRequiredFiles" -PercentComplete ($RequiredFilesCounter / $TotalRequiredFiles * 100)
            } 
            # Wait until all jobs are completed
            while ($Jobs | Where-Object { $_.State -ne 'Completed' }) {
                Start-Sleep -Milliseconds 700
            }
                        
            # Receive the output or errors of each job and remove the job
            foreach ($Job in $Jobs) {
                Receive-Job -Job $Job -ErrorAction Stop
                Remove-Job -Job $Job -ErrorAction Stop
            }       
                         
            Write-Progress -Id 1 -ParentId 0 -Activity 'Downloading files completed.' -Completed
        }
        catch {            
            Write-Error "The required files couldn't be downloaded, Make sure you have Internet connection."
            foreach ($Job in $Jobs) { Remove-Job -Job $Job -ErrorAction Stop }   
            &$CleanUp
        }  

        # unzip Microsoft Security Baselines file
        Expand-Archive -Path .\MicrosoftSecurityBaseline.zip -DestinationPath .\MicrosoftSecurityBaseline -Force -ErrorAction Stop
        # unzip Microsoft 365 Apps Security Baselines file
        Expand-Archive -Path .\Microsoft365SecurityBaseline.zip -DestinationPath .\Microsoft365SecurityBaseline -Force -ErrorAction Stop
        # unzip the LGPO file
        Expand-Archive -Path .\LGPO.zip -DestinationPath .\ -Force -ErrorAction Stop
        # unzip the Security-Baselines-X file which contains Windows Hardening script Group Policy Objects
        Expand-Archive -Path .\Security-Baselines-X.zip -DestinationPath .\Security-Baselines-X\ -Force -ErrorAction Stop

        # capturing the Microsoft Security Baselines extracted path in a variable using wildcard and storing it in a variable so that we won't need to change anything in the code other than the download link when they are updated
        [System.String]$MicrosoftSecurityBaselinePath = (Get-ChildItem -Path '.\MicrosoftSecurityBaseline\*\').FullName
        # capturing the Microsoft 365 Security Baselines extracted path in a variable using wildcard and storing it in a variable so that we won't need to change anything in the code other than the download link when they are updated
        [System.String]$Microsoft365SecurityBaselinePath = (Get-ChildItem -Path '.\Microsoft365SecurityBaseline\*\').FullName

        #region Windows-Boot-Manager-revocations-for-Secure-Boot KB5025885  
        # ============================May 9 2023 Windows Boot Manager revocations for Secure Boot =================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply May 9 2023 Windows Boot Manager Security measures ? (If you've already run this category, don't need to do it again)") {
            'Yes' {                
                Write-Progress -Id 0 -Activity 'Windows Boot Manager revocations for Secure Boot' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x30 /f

                Write-Host 'The required security measures have been applied to the system' -ForegroundColor Green
                Write-Warning 'Make sure to restart your device once. After restart, wait for at least 5-10 minutes and perform a 2nd restart to finish applying security measures completely.'
            } 'No' { break }
            'Exit' { &$CleanUp }
        }    
        # ============================End of May 9 2023 Windows Boot Manager revocations for Secure Boot===========================
        #endregion Windows-Boot-Manager-revocations-for-Secure-Boot KB5025885

        #region Microsoft-Security-Baseline    
        # ================================================Microsoft Security Baseline==============================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'Yes, With the Optional Overrides (Recommended)' , 'No', 'Exit' -Message "`nApply Microsoft Security Baseline ?") {
            'Yes' {  
                Write-Progress -Id 0 -Activity 'Microsoft Security Baseline' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                         
                # Copy LGPO.exe from its folder to Microsoft Security Baseline folder in order to get it ready to be used by PowerShell script
                Copy-Item -Path '.\LGPO_30\LGPO.exe' -Destination "$MicrosoftSecurityBaselinePath\Scripts\Tools"

                # Change directory to the Security Baselines folder
                Set-Location "$MicrosoftSecurityBaselinePath\Scripts\"

                # Run the official PowerShell script included in the Microsoft Security Baseline file we downloaded from Microsoft servers
                .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined            
            } 
            'Yes, With the Optional Overrides (Recommended)' {            
                
                # Copy LGPO.exe from its folder to Microsoft Security Baseline folder in order to get it ready to be used by PowerShell script
                Copy-Item -Path '.\LGPO_30\LGPO.exe' -Destination "$MicrosoftSecurityBaselinePath\Scripts\Tools"

                # Change directory to the Security Baselines folder
                Set-Location "$MicrosoftSecurityBaselinePath\Scripts\"

                # Run the official PowerShell script included in the Microsoft Security Baseline file we downloaded from Microsoft servers
                .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined

                Start-Sleep -Seconds 1

                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /q /m '..\Security-Baselines-X\Overrides for Microsoft Security Baseline\registry.pol'
                .\LGPO.exe /q /s '..\Security-Baselines-X\Overrides for Microsoft Security Baseline\GptTmpl.inf'
            
                # Re-enables the XblGameSave Standby Task that gets disabled by Microsoft Security Baselines
                SCHTASKS.EXE /Change /TN \Microsoft\XblGameSave\XblGameSaveTask /Enable            
            }
            'No' { break }
            'Exit' { &$CleanUp }
        }    
        # ==============================================End of Microsoft Security Baselines============================================   
        #endregion Microsoft-Security-Baseline
       
        #region Microsoft-365-Apps-Security-Baseline
        # ================================================Microsoft 365 Apps Security Baseline==============================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Microsoft 365 Apps Security Baseline ?") {
            'Yes' {    
                Write-Progress -Id 0 -Activity 'Microsoft 365 Apps Security Baseline' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                
                Set-Location $WorkingDir
                # Copy LGPO.exe from its folder to Microsoft Office 365 Apps for Enterprise Security Baseline folder in order to get it ready to be used by PowerShell script
                Copy-Item -Path '.\LGPO_30\LGPO.exe' -Destination "$Microsoft365SecurityBaselinePath\Scripts\Tools"

                # Change directory to the M365 Security Baselines folder
                Set-Location "$Microsoft365SecurityBaselinePath\Scripts\"

                # Run the official PowerShell script included in the Microsoft Security Baseline file we downloaded from Microsoft servers
                .\Baseline-LocalInstall.ps1           
            } 'No' { break }
            'Exit' { &$CleanUp }
        }
        # ================================================End of Microsoft 365 Apps Security Baseline==============================================
        #endregion Microsoft-365-Apps-Security-Baseline
    
        #region Microsoft-Defender
        # ================================================Microsoft Defender=======================================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Microsoft Defender category ?") {
            'Yes' {  
                Write-Progress -Id 0 -Activity 'Microsoft Defender' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /q /m '..\Security-Baselines-X\Microsoft Defender Policies\registry.pol'
        
                # Optimizing Network Protection Performance of Windows Defender
                Set-MpPreference -AllowSwitchToAsyncInspection $True

                # Configure whether real-time protection and Security Intelligence Updates are enabled during OOBE
                Set-MpPreference -OobeEnableRtpAndSigUpdate $True

                # Enable Intel Threat Detection Technology
                Set-MpPreference -IntelTDTEnabled $True

                # Enable Restore point scan
                Set-MpPreference -DisableRestorePoint $False

                # Disable Performance mode of Defender that only applies to Dev drives by lowering security
                Set-MpPreference -PerformanceModeStatus Disabled

                # Network protection blocks network traffic instead of displaying a warning
                Set-MpPreference -EnableConvertWarnToBlock $True

                # Add OneDrive folders of all user accounts (personal and work accounts) to the Controlled Folder Access for Ransomware Protection
                Get-ChildItem 'C:\Users\*\OneDrive*\' -Directory | ForEach-Object { Add-MpPreference -ControlledFolderAccessProtectedFolders $_ }

                # Enable Mandatory ASLR Exploit Protection system-wide
                Set-ProcessMitigation -System -Enable ForceRelocateImages

                Set-Location $WorkingDir

                # Apply Process Mitigations
                [System.Object[]]$ProcessMitigations = Import-Csv 'ProcessMitigations.csv' -Delimiter ','

                # Group the data by ProgramName
                [System.Object[]]$GroupedMitigations = $ProcessMitigations | Group-Object ProgramName
                # Get the current process mitigations
                [System.Object[]]$AllAvailableMitigations = (Get-ItemProperty -Path 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*')

                # Loop through each group to remove the mitigations, this way we apply clean set of mitigations in the next step
                foreach ($Group in $GroupedMitigations) {    
                    # To separate the filename from full path of the item in the CSV and then check whether it exists in the system registry
                    if ($Group.Name -match '\\([^\\]+)$') {
                        if ($Matches[1] -in $AllAvailableMitigations.pschildname) {
                            Remove-Item -Path "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($Matches[1])" -Recurse -Force
                        }        
                    }
                    elseif ($Group.Name -in $AllAvailableMitigations.pschildname) {
                        Remove-Item -Path "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($Group.Name)" -Recurse -Force
                    }
                } 

                # Loop through each group to add the mitigations
                foreach ($Group in $GroupedMitigations) {
                    # Get the program name
                    $ProgramName = $Group.Name
                    
                    # Get the list of mitigations to enable
                    $EnableMitigations = $Group.Group | Where-Object { $_.Action -eq 'Enable' } | Select-Object -ExpandProperty Mitigation
                    
                    # Get the list of mitigations to disable
                    $DisableMitigations = $Group.Group | Where-Object { $_.Action -eq 'Disable' } | Select-Object -ExpandProperty Mitigation
                    
                    # Call the Set-ProcessMitigation cmdlet with the lists of mitigations
                    if ($null -ne $EnableMitigations) {
                        if ($null -ne $DisableMitigations) {
                            Set-ProcessMitigation -Name $ProgramName -Enable $EnableMitigations -Disable $DisableMitigations
                        }
                        else {
                            Set-ProcessMitigation -Name $ProgramName -Enable $EnableMitigations
                        }
                    }
                    elseif ($null -ne $DisableMitigations) {
                        Set-ProcessMitigation -Name $ProgramName -Disable $DisableMitigations
                    }
                } 

                # Turn on Data Execution Prevention (DEP) for all applications, including 32-bit programs
                bcdedit.exe /set '{current}' nx AlwaysOn

                # Suggest turning on Smart App Control only if it's in Eval mode
                if ((Get-MpComputerStatus).SmartAppControlState -eq 'Eval') {
                    switch (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nTurn on Smart App Control ?") {
                        'Yes' {
                            Edit-Registry -path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -key 'VerifiedAndReputablePolicyState' -value '1' -type 'DWORD' -Action 'AddOrModify' | Out-Null
                            # Let the optional diagnostic data be enabled automatically
                            $ShouldEnableOptionalDiagnosticData = $True
                        } 'No' { break }
                        'Exit' { &$CleanUp }
                    }
                }

                # If Smart App Control is on or user selected to turn it on then automatically enable optional diagnostic data
                if (($ShouldEnableOptionalDiagnosticData -eq $True) -or ((Get-MpComputerStatus).SmartAppControlState -eq 'On')) {
                    # Change current working directory to the LGPO's folder
                    Set-Location "$WorkingDir\LGPO_30"
                    .\LGPO.exe /q /m '..\Security-Baselines-X\Microsoft Defender Policies\Optional Diagnostic Data\registry.pol'
                }
                else {
                    # Ask user if they want to turn on optional diagnostic data only if Smart App Control is not already turned off
                    if (-NOT ((Get-MpComputerStatus).SmartAppControlState -eq 'Off')) {                
                        switch (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnable Optional Diagnostic Data ?" -ExtraMessage 'Required for Smart App Control usage and evaluation, read the GitHub Readme!') {
                            'Yes' {               
                                # Change current working directory to the LGPO's folder
                                Set-Location "$WorkingDir\LGPO_30"
                                .\LGPO.exe /q /m '..\Security-Baselines-X\Microsoft Defender Policies\Optional Diagnostic Data\registry.pol'
                            } 'No' { break }
                            'Exit' { &$CleanUp }
                        }
                    }
                }

                # Get the state of fast weekly Microsoft recommended driver block list update scheduled task
                [System.String]$BlockListScheduledTaskState = (Get-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath '\MSFT Driver Block list update\' -ErrorAction SilentlyContinue).State
                
                # Create scheduled task for fast weekly Microsoft recommended driver block list update if it doesn't exist or exists but is not Ready/Running
                if (-NOT (($BlockListScheduledTaskState -eq 'Ready' -or $BlockListScheduledTaskState -eq 'Running'))) {
                    switch (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nCreate scheduled task for fast weekly Microsoft recommended driver block list update ?") {
                        'Yes' {
                            # Get the SID of the SYSTEM account. It is a well-known SID, but still querying it, going to use it to create the scheduled task
                            $SYSTEMSID = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
                            # create a scheduled task that runs every 7 days     
                            $Action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
                                -Argument '-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop}catch{exit};Expand-Archive .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-Item .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "C:\Windows\System32\CodeIntegrity";citool --refresh -json;Remove-Item .\VulnerableDriverBlockList -Recurse -Force;Remove-Item .\VulnerableDriverBlockList.zip -Force;}"'    
                            $TaskPrincipal = New-ScheduledTaskPrincipal -LogonType S4U -UserId $($SYSTEMSID.Value) -RunLevel Highest
                            # trigger
                            $Time = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Days 7) 
                            # register the task
                            Register-ScheduledTask -Action $Action -Trigger $Time -Principal $TaskPrincipal -TaskPath 'MSFT Driver Block list update' -TaskName 'MSFT Driver Block list update' -Description 'Microsoft Recommended Driver Block List update'
                            # define advanced settings for the task
                            $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility Win8 -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
                            # add advanced settings we defined to the task
                            Set-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath 'MSFT Driver Block list update' -Settings $TaskSettings 
                        } 'No' { break }
                        'Exit' { &$CleanUp }
                    }
                }

                # Only show this prompt if Engine and Platform update channels are not already set to Beta
                if ( ($MDAVPreferencesCurrent.EngineUpdatesChannel -ne '2') -or ($MDAVPreferencesCurrent.PlatformUpdatesChannel -ne '2') ) {
                    # Set Microsoft Defender engine and platform update channel to beta - Devices in the Windows Insider Program are subscribed to this channel by default.
                    switch (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nSet Microsoft Defender engine and platform update channel to beta ?") {
                        'Yes' {             
                            Set-MpPreference -EngineUpdatesChannel beta
                            Set-MpPreference -PlatformUpdatesChannel beta
                        } 'No' { break }
                        'Exit' { &$CleanUp }
                    }    
                }

            } 'No' { break }
            'Exit' { &$CleanUp }
        }    
        # ============================================End of Microsoft Defender====================================================    
        #endregion Microsoft-Defender

        #region Attack-Surface-Reduction-Rules    
        # =========================================Attack Surface Reduction Rules==================================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Attack Surface Reduction Rules category ?") {
            'Yes' {  
                Write-Progress -Id 0 -Activity 'Attack Surface Reduction Rules' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                                 
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                
                .\LGPO.exe /q /m '..\Security-Baselines-X\Attack Surface Reduction Rules Policies\registry.pol'
            } 'No' { break }
            'Exit' { &$CleanUp }
        }
        # =========================================End of Attack Surface Reduction Rules===========================================
        #endregion Attack-Surface-Reduction-Rules
    
        #region Bitlocker-Settings    
        # ==========================================Bitlocker Settings=============================================================    
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Bitlocker category ?") {
            'Yes' {   
                Write-Progress -Id 0 -Activity 'Bitlocker Settings' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"

                .\LGPO.exe /q /m '..\Security-Baselines-X\Bitlocker Policies\registry.pol'

                # This PowerShell script can be used to find out if the DMA Protection is ON \ OFF.
                # The Script will show this by emitting True \ False for On \ Off respectively.

                # bootDMAProtection check - checks for Kernel DMA Protection status in System information or msinfo32
                [System.String]$BootDMAProtectionCheck =
                @'
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
'@
                Add-Type -TypeDefinition $BootDMAProtectionCheck
                # returns true or false depending on whether Kernel DMA Protection is on or off
                [bool]$BootDMAProtection = ([SystemInfo.NativeMethods]::BootDmaCheck()) -ne 0

                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
            
                # Enables or disables DMA protection from Bitlocker Countermeasures based on the status of Kernel DMA protection.
                if ($BootDMAProtection) {                 
                    Write-Host 'Kernel DMA protection is enabled on the system, disabling Bitlocker DMA protection.' -ForegroundColor Blue
                    .\LGPO.exe /q /m '..\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure OFF\Registry.pol'                           
                }
                else {
                    Write-Host 'Kernel DMA protection is unavailable on the system, enabling Bitlocker DMA protection.' -ForegroundColor Blue
                    .\LGPO.exe /q /m '..\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure ON\Registry.pol'                                                          
                }

                # Set-up Bitlocker encryption for OS Drive with TPMandPIN and recovery password keyprotectors and Verify its implementation            
                # check, make sure there is no CD/DVD drives in the system, because Bitlocker throws an error when there is
                $CdDvdCheck = (Get-CimInstance -ClassName Win32_CDROMDrive -Property *).MediaLoaded
                if ($CdDvdCheck) {
                    Write-Warning 'Remove any CD/DVD drives or mounted images/ISO from the system and run the Bitlocker category again.'
                    # break from the current loop and continue to the next hardening category
                    break
                }
        
                # check make sure Bitlocker isn't in the middle of decryption/encryption operation (on System Drive)
                if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage -ne '100' -and (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage -ne '0') {
                    $EncryptionPercentageVar = (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage
                    Write-Host "`nPlease wait for Bitlocker to finish encrypting or decrypting the Operation System Drive." -ForegroundColor Yellow
                    Write-Host "Drive $env:SystemDrive encryption is currently at $EncryptionPercentageVar percent." -ForegroundColor Yellow
                    break
                }
                
                # A script block that generates recovery code just like the Windows does
                [scriptblock]$RecoveryPasswordContentGenerator = { 
                    param ([System.Object[]]$KeyProtectorsInputFromScriptBlock)
                
                    return @"
BitLocker Drive Encryption recovery key

To verify that this is the correct recovery key, compare the start of the following identifier with the identifier value displayed on your PC.

Identifier:

        $(($KeyProtectorsInputFromScriptBlock | Where-Object { $_.keyprotectortype -eq 'RecoveryPassword' }).KeyProtectorId.Trim('{', '}'))              

If the above identifier matches the one displayed by your PC, then use the following key to unlock your drive.

Recovery Key:

        $(($KeyProtectorsInputFromScriptBlock | Where-Object { $_.keyprotectortype -eq 'RecoveryPassword' }).RecoveryPassword)                            

If the above identifier doesn't match the one displayed by your PC, then this isn't the right key to unlock your drive.
Try another recovery key, or refer to https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview for additional assistance.
                    
IMPORTANT: Make sure to keep it in a safe place, e.g., in OneDrive's Personal Vault which requires additional authentication to access.
                    
"@
                }
                
                # check if Bitlocker is enabled for the system drive
                if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq 'on') {  
                
                    # Get the key protectors of the OS Drive
                    [System.Object[]]$KeyProtectors = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector
                    # Get the key protector types of the OS Drive
                    [System.String[]]$KeyProtectorTypes = $KeyProtectors.keyprotectortype
                
                    # check if TPM + PIN + recovery password are being used as key protectors for the OS Drive
                    if ($KeyProtectorTypes -contains 'Tpmpin' -and $KeyProtectorTypes -contains 'recoveryPassword') {        
                        Write-Host 'Bitlocker is already fully and securely enabled for the OS drive' -ForegroundColor Green
                    
                        Write-SmartText -C Fuchsia -GenericColor Magenta -I 'Here is your 48-digits recovery password for the OS drive in case you were looking for it:'
                        Write-SmartText -C Rainbow -GenericColor Yellow -I "$(($KeyProtectors | Where-Object { $_.keyprotectortype -eq 'RecoveryPassword' }).RecoveryPassword)"
                                    
                    }
                    else {
                        # if Bitlocker is using TPM + PIN but not recovery password (for key protectors)
                        if ($KeyProtectorTypes -contains 'Tpmpin' -and $KeyProtectorTypes -notcontains 'recoveryPassword') {
                
                            [System.String]$BitLockerMsg = "`nTPM and Startup PIN are available but the recovery password is missing, adding it now... `n" +
                            "It will be saved in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'"
                            Write-Host $BitLockerMsg -ForegroundColor Yellow
                
                            # Add RecoveryPasswordProtector key protector to the OS drive
                            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> $null
                            
                            # Get the new key protectors of the OS Drive after adding RecoveryPasswordProtector to it
                            [System.Object[]]$KeyProtectors = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector
                    
                            # Backup the recovery code of the OS drive in a file
                            New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectors) -ItemType File -Force | Out-Null
                                                 
                        }                
                        # if Bitlocker is using recovery password but not TPM + PIN as key protectors for the OS Drive
                        elseif ($KeyProtectorTypes -notcontains 'Tpmpin' -and $KeyProtectorTypes -contains 'recoveryPassword') {
                                       
                            Write-Host "`nTPM and Start up PIN are missing but recovery password is in place`nAdding TPM and Start up PIN now..." -ForegroundColor Cyan

                            # Get the key protectors of the OS Drive
                            [System.Object[]]$KeyProtectors = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector
                           
                            # Backup the recovery code of the OS drive in a file just in case - This is for when the disk is automatically encrypted and using TPM + Recovery code by default
                            New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectors) -ItemType File -Force | Out-Null
                                     
                            Write-Host "The recovery password was backed up in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'" -ForegroundColor Cyan

                            do {                                       
                                [securestring]$Pin1 = $(Write-SmartText -C PinkBold -G Magenta -I "`nEnter a Pin for Bitlocker startup (between 10 to 20 characters)"; Read-Host -AsSecureString)
                                [securestring]$Pin2 = $(Write-SmartText -C PinkBold -G Magenta -I 'Confirm your Bitlocker Startup Pin (between 10 to 20 characters)'; Read-Host -AsSecureString)
                                
                                # Compare the PINs and make sure they match
                                [bool]$TheyMatch = Compare-SecureString $Pin1 $Pin2
                                # If the PINs match and they are at least 10 characters long, max 20 characters
                                if ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) ) {
                                    [securestring]$Pin = $Pin1                  
                                }
                                else { Write-Host 'Please ensure that the PINs you entered match, and that they are between 10 to 20 characters.' -ForegroundColor red }                  
                            }
                            # Repeat this process until the entered PINs match and they are at least 10 characters long, max 20 characters           
                            until ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) )
                                 
                            try {
                                Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinProtector -Pin $Pin -ErrorAction Stop
                                Write-Host "`nPINs matched, enabling TPM and startup PIN now" -ForegroundColor Green
                            }
                            catch {         
                                Write-Host 'These errors occured, run Bitlocker category again after meeting the requirements' -ForegroundColor Red
                                $_
                                break
                            }
                        }     
                    }     
                }
                # Do this if Bitlocker is not enabled for the OS drive
                else {
                    Write-Host "`nBitlocker is not enabled for the OS Drive, activating it now..." -ForegroundColor Yellow    
                    do {                        
                        [securestring]$Pin1 = $(Write-SmartText -C PinkBold -G Magenta -I 'Enter a Pin for Bitlocker startup (between 10 to 20 characters)'; Read-Host -AsSecureString)
                        [securestring]$Pin2 = $(Write-SmartText -C PinkBold -G Magenta -I 'Confirm your Bitlocker Startup Pin (between 10 to 20 characters)'; Read-Host -AsSecureString)
                        
                        [bool]$TheyMatch = Compare-SecureString $Pin1 $Pin2
                            
                        if ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) ) {      
                            [securestring]$Pin = $Pin1      
                        }
                        else { Write-Host 'Please ensure that the PINs you entered match, and that they are between 10 to 20 characters.' -ForegroundColor red }      
                    }      
                    until ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) )
                
                    try {
                        Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod 'XtsAes256' -Pin $Pin -TpmAndPinProtector -SkipHardwareTest -ErrorAction Stop *> $null
                    }
                    catch {
                        Write-Host 'These errors occured, run Bitlocker category again after meeting the requirements' -ForegroundColor Red
                        $_
                        break
                    }     
                    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> $null
                
                    # Get the new key protectors of the OS Drive after adding RecoveryPasswordProtector to it
                    [System.Object[]]$KeyProtectors = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector
                
                    # Backup the recovery code of the OS drive in a file
                    New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectors) -ItemType File -Force | Out-Null
                
                    Resume-BitLocker -MountPoint $env:SystemDrive | Out-Null
                
                    Write-Host "`nBitlocker is now fully and securely enabled for OS drive" -ForegroundColor Green
                    Write-Host "The recovery password will be saved in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'" -ForegroundColor Cyan
                }

                # Enabling Hibernate after making sure OS drive is property encrypted for holding hibernate data
                # Making sure the system is not a VM because Hibernate on VM doesn't work and VMs have other/better options than Hibernation
                if (-NOT ((Get-MpComputerStatus).IsVirtualMachine)) {

                    # Check to see if Hibernate is already set to full and HiberFileType is set to 2 which is Full, 1 is Reduced
                    try {
                        [System.Int64]$HiberFileType = Get-ItemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power' -Name 'HiberFileType' -ErrorAction SilentlyContinue
                    }
                    catch {
                        # Do nothing if the key doesn't exist
                    }
                    if ($HiberFileType -and $HiberFileType -ne 2) {            
                        # doing this so Controlled Folder Access won't bitch about powercfg.exe
                        Add-MpPreference -ControlledFolderAccessAllowedApplications 'C:\Windows\System32\powercfg.exe'
                        Start-Sleep 5
                        # Set Hibernate mode to full
                        powercfg /h /type full
                        Start-Sleep 3
                        Remove-MpPreference -ControlledFolderAccessAllowedApplications 'C:\Windows\System32\powercfg.exe'
                    }
                    else {
                        Write-Host 'Hibernate is already set to full.' -ForegroundColor Magenta
                    }
                }

                #region Non-OS-BitLocker-Drives-Detection
                
                # Get the list of non OS volumes
                [System.Object[]]$NonOSBitLockerVolumes = Get-BitLockerVolume | Where-Object {
    ($_.volumeType -ne 'OperatingSystem')
                }

                # Get all the volumes and filter out removable ones
                [System.Object[]]$RemovableVolumes = Get-Volume |
                Where-Object { $_.DriveType -eq 'Removable' } |
                Where-Object { $_.DriveLetter }

                # Check if there is any removable volumes
                if ($RemovableVolumes) {

                    # Get the letters of all the removable volumes
                    [System.String[]]$RemovableVolumesLetters = foreach ($RemovableVolume in $RemovableVolumes) {
                        $(($RemovableVolume).DriveLetter + ':' )
                    }

                    # Filter out removable drives from BitLocker volumes to process
                    $NonOSBitLockerVolumes = $NonOSBitLockerVolumes | Where-Object {
    ($_.MountPoint -notin $RemovableVolumesLetters)
                    }

                }
                #endregion Non-OS-BitLocker-Drives-Detection

                # Check if there is any non-OS volumes
                if ($NonOSBitLockerVolumes) {    

                    # Loop through each non-OS volume and prompt for encryption
                    foreach ($MountPoint in $($NonOSBitLockerVolumes | Sort-Object).MountPoint) {
                
                        # Prompt for confirmation before encrypting each drive
                        switch (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEncrypt $MountPoint drive ?") {
                            'Yes' {
                
                                # Check if the non-OS drive that the user selected to be encrypted is not in the middle of any encryption/decryption operation
                                if ((Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage -ne '100' -and (Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage -ne '0') {
                                    # Check if the drive isn't already encrypted and locked
                                    if ((Get-BitLockerVolume -MountPoint $MountPoint).lockstatus -eq 'Locked') {
                                        Write-Host "`nThe drive $MountPoint is already encrypted and locked." -ForegroundColor Magenta
                                        break
                                    }
                                    else {
                                        $EncryptionPercentageVar = (Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage
                                        Write-Host "`nPlease wait for Bitlocker to finish encrypting or decrypting drive $MountPoint" -ForegroundColor Magenta
                                        Write-Host "Drive $MountPoint encryption is currently at $EncryptionPercentageVar percent." -ForegroundColor Magenta
                                        break
                                    }
                                }   
                                        
                                # Check to see if Bitlocker is already turned on for the user selected drive
                                # if it is, perform multiple checks on its key protectors                        
                                if ((Get-BitLockerVolume -MountPoint $MountPoint).ProtectionStatus -eq 'on') {
                
                                    # Get the key protector types of the Non-OS Drive
                                    [System.String[]]$KeyProtectorTypesNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector.keyprotectortype
                                    
                                    # Check 1: if Recovery Password and Auto Unlock key protectors are available on the drive
                                    if ($KeyProtectorTypesNonOS -contains 'RecoveryPassword' -and $KeyProtectorTypesNonOS -contains 'ExternalKey') {
                
                                        # Additional Check 1: if there are more than 1 ExternalKey key protector, try delete all of them and add a new one
                                        # The external key protector that is being used to unlock the drive will not be deleted
                                        ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                        Where-Object { $_.keyprotectortype -eq 'ExternalKey' }).KeyProtectorId |
                                        ForEach-Object {
                                            # -ErrorAction SilentlyContinue makes sure no error is thrown if the drive only has 1 External key key protector
                                            # and it's being used to unlock the drive
                                            Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ -ErrorAction SilentlyContinue                                            
                                        }
                                        Enable-BitLockerAutoUnlock -MountPoint $MountPoint | Out-Null
                
                                        # Additional Check 2: if there are more than 1 Recovery Password, delete all of them and add a new one
                                        [System.String[]]$RecoveryPasswordKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                            Where-Object { $_.keyprotectortype -eq 'RecoveryPassword' }).KeyProtectorId
                
                                        if ($RecoveryPasswordKeyProtectors.Count -gt 1) {
                
                                            [System.String]$BitLockerMsg = "`nThere are more than 1 recovery password key protector associated with the drive $mountpoint `n" +
                                            "Removing all of them and adding a new one. `n" + 
                                            "It will be saved in a text file in '$($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt'"
                                            Write-Host $BitLockerMsg -ForegroundColor Yellow
                
                                            $RecoveryPasswordKeyProtectors | ForEach-Object {
                                                Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ 
                                            }
                
                                            # Add new Recovery Password key protector after removing the previous ones
                                            Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> $null
                                       
                                            # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                            [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector
                                    
                                            # Backup the recovery code of the Non-OS drive in a file
                                            New-Item -Path "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsNonOS) -ItemType File -Force | Out-Null
                                                              
                                        }                                
                                        Write-Host "`nBitlocker is already fully and securely enabled for drive $MountPoint" -ForegroundColor Green    
                            
                                        # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                        [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector

                                        Write-SmartText -C Fuchsia -GenericColor Magenta -I "Here is your 48-digits recovery password for drive $MountPoint in case you were looking for it:"
                                        Write-SmartText -C Rainbow -GenericColor Yellow -I "$(($KeyProtectorsNonOS | Where-Object { $_.keyprotectortype -eq 'RecoveryPassword' }).RecoveryPassword)"
                                    
                                    }                                    
                                   
                                    # If the selected drive has Auto Unlock key protector but doesn't have Recovery Password
                                    elseif ($KeyProtectorTypesNonOS -contains 'ExternalKey' -and $KeyProtectorTypesNonOS -notcontains 'RecoveryPassword' ) {
                                      
                                        # if there are more than 1 ExternalKey key protector, try delete all of them and add a new one
                                        # The external key protector that is being used to unlock the drive will not be deleted
                                            ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                        Where-Object { $_.keyprotectortype -eq 'ExternalKey' }).KeyProtectorId |
                                        ForEach-Object {
                                            # -ErrorAction SilentlyContinue makes sure no error is thrown if the drive only has 1 External key key protector
                                            # and it's being used to unlock the drive
                                            Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ -ErrorAction SilentlyContinue                                            
                                        }
                                        Enable-BitLockerAutoUnlock -MountPoint $MountPoint | Out-Null
                
                                        # Add Recovery Password Key protector and save it to a file inside the drive                                            
                                        Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> $null
                
                                        # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                        [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector
                                    
                                        # Backup the recovery code of the Non-OS drive in a file
                                        New-Item -Path "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsNonOS) -ItemType File -Force | Out-Null
                                                                                
                                        [System.String]$BitLockerMsg = "`nDrive $MountPoint is auto-unlocked but doesn't have Recovery Password, adding it now... `n" +
                                        "It will be saved in a text file in '$($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt'"
                                        Write-Host $BitLockerMsg -ForegroundColor Cyan
                                    }
                
                                    # Check 3: If the selected drive has Recovery Password key protector but doesn't have Auto Unlock enabled
                                    elseif ($KeyProtectorTypesNonOS -contains 'RecoveryPassword' -and $KeyProtectorTypesNonOS -notcontains 'ExternalKey') {
                                        
                                        # Add Auto-unlock (a.k.a ExternalKey key protector to the drive)
                                        Enable-BitLockerAutoUnlock -MountPoint $MountPoint | Out-Null
                                                    
                                        # if there are more than 1 Recovery Password, delete all of them and add a new one
                                        [System.String[]]$RecoveryPasswordKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                            Where-Object { $_.keyprotectortype -eq 'RecoveryPassword' }).KeyProtectorId
                
                                        if ($RecoveryPasswordKeyProtectors.Count -gt 1) {
                
                                            [System.String]$BitLockerMsg = "`nThere are more than 1 recovery password key protector associated with the drive $mountpoint `n" +
                                            'Removing all of them and adding a new one.' +
                                            "It will be saved in a text file in '$($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt'"
                                            Write-Host $BitLockerMsg -ForegroundColor Yellow   
                                                        
                                            # Delete all Recovery Passwords because there were more than 1
                                            $RecoveryPasswordKeyProtectors | ForEach-Object {
                                                Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ 
                                            }
                
                                            # Add a new Recovery Password
                                            Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> $null
                
                                            # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                            [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector
                                    
                                            # Backup the recovery code of the Non-OS drive in a file
                                            New-Item -Path "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsNonOS) -ItemType File -Force | Out-Null
                                        }                
                                    }
                                }
                
                                # Do this if Bitlocker isn't turned on at all on the user selected drive
                                else {
                                    # Enable BitLocker with RecoveryPassword key protector for the selected Non-OS drive
                                    Enable-BitLocker -MountPoint $MountPoint -RecoveryPasswordProtector *> $null
                                    
                                    # Add Auto-unlock (a.k.a ExternalKey key protector to the drive)
                                    Enable-BitLockerAutoUnlock -MountPoint $MountPoint | Out-Null
                
                                    # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                    [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector
                                    
                                    # Backup the recovery code of the Non-OS drive in a file
                                    New-Item -Path "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsNonOS) -ItemType File -Force | Out-Null
                                    
                                    Write-Host "`nBitLocker has started encrypting drive $MountPoint" -ForegroundColor Green
                                    Write-Host "Recovery password will be saved in a text file in '$($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt'" -ForegroundColor Cyan
                                }
                
                            } 'No' { break }
                            'Exit' { &$CleanUp }
                        }                            
                    }
                }
            } 'No' { break }
            'Exit' { &$CleanUp }
        }    
        # ==========================================End of Bitlocker Settings======================================================    
        #endregion Bitlocker-Settings

        #region TLS-Security    
        # ==============================================TLS Security=============================================================== 
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun TLS Security category ?") {
            'Yes' {  
                Write-Progress -Id 0 -Activity 'TLS Security' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                
                # creating these registry keys that have forward slashes in them                                
                @( 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56', # DES 56-bit 
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
                } | Out-Null

                # TLS Registry section
                Set-Location $WorkingDir

                [System.Object[]]$Items = Import-Csv '.\Registry.csv' -Delimiter ','
                foreach ($Item in $Items) {
                    if ($Item.category -eq 'TLS') {
                        Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action | Out-Null
                    }
                }
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /q /m '..\Security-Baselines-X\TLS Security\registry.pol'               
            } 'No' { break }
            'Exit' { &$CleanUp }
        }    
        # ==========================================End of TLS Security============================================================
        #endregion TLS-Security

        #region Lock-Screen    
        # ==========================================Lock Screen====================================================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Lock Screen category ?") {
            'Yes' {  
                Write-Progress -Id 0 -Activity 'Lock Screen' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                                         
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /q /m '..\Security-Baselines-X\Lock Screen Policies\registry.pol'
                .\LGPO.exe /q /s '..\Security-Baselines-X\Lock Screen Policies\GptTmpl.inf'

                # Apply the Don't display last signed-in policy
                switch (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nDon't display last signed-in on logon screen ?" -ExtraMessage 'Read the GitHub Readme!') {
                    'Yes' {
                        Write-Progress -Id 2 -ParentId 0 -Activity 'Lock Screen' -Status "Applying the Don't display last signed-in policy" -PercentComplete 50
               
                        .\LGPO.exe /q /s "..\Security-Baselines-X\Lock Screen Policies\Don't display last signed-in\GptTmpl.inf"                      
                   
                        Write-Progress -Id 2 -Activity "Applying the Don't display last signed-in policy" -Completed
                    } 'No' { break }
                    'Exit' { &$CleanUp }
                }              

            } 'No' { break }
            'Exit' { &$CleanUp }
        }    
        # ==========================================End of Lock Screen=============================================================
        #endregion Lock-Screen

        #region User-Account-Control
        # ==========================================User Account Control===========================================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun User Account Control category ?") {
            'Yes' {  
                Write-Progress -Id 0 -Activity 'User Account Control' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                        
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /q /s '..\Security-Baselines-X\User Account Control UAC Policies\GptTmpl.inf'
                
                # Apply the Automatically deny all UAC prompts on Standard accounts policy
                switch (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nAutomatically deny all UAC prompts on Standard accounts ?") {
                    'Yes' {
                        Write-Progress -Id 3 -ParentId 0 -Activity 'User Account Control' -Status 'Automatically deny all UAC prompts on Standard accounts policy' -PercentComplete 50
               
                        .\LGPO.exe /q /s '..\Security-Baselines-X\User Account Control UAC Policies\Automatically deny all UAC prompts on Standard accounts\GptTmpl.inf'                      
                        
                        Write-Progress -Id 3 -Activity 'Automatically deny all UAC prompts on Standard accounts policy' -Completed
                    } 'No' { break }
                    'Exit' { &$CleanUp }
                }

                # Apply the Hide the entry points for Fast User Switching policy
                switch (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nHide the entry points for Fast User Switching ?" -ExtraMessage 'Read the GitHub Readme!') {
                    'Yes' {
                        Write-Progress -Id 4 -ParentId 0 -Activity 'User Account Control' -Status 'Hide the entry points for Fast User Switching policy' -PercentComplete 50

                        .\LGPO.exe /q /m '..\Security-Baselines-X\User Account Control UAC Policies\Hides the entry points for Fast User Switching\registry.pol'                      
                    
                        Write-Progress -Id 4 -Activity 'Hide the entry points for Fast User Switching policy' -Completed
                    } 'No' { break }
                    'Exit' { &$CleanUp }
                }               

                # Apply the Only elevate executables that are signed and validated policy
                switch (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nOnly elevate executables that are signed and validated ?" -ExtraMessage 'Read the GitHub Readme!') {
                    'Yes' {
                        Write-Progress -Id 5 -ParentId 0 -Activity 'User Account Control' -Status 'Only elevate executables that are signed and validated' -PercentComplete 50

                        .\LGPO.exe /q /s '..\Security-Baselines-X\User Account Control UAC Policies\Only elevate executables that are signed and validated\GptTmpl.inf'
                  
                        Write-Progress -Id 5 -Activity 'Only elevate executables that are signed and validated' -Completed
                    } 'No' { break }
                    'Exit' { &$CleanUp }
                }  

            } 'No' { break }
            'Exit' { &$CleanUp }
        }    
        # ==========================================End of User Account Control====================================================
        #endregion User-Account-Control

        #region Windows-Firewall    
        # ====================================================Windows Firewall=====================================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Windows Firewall category ?") {
            'Yes' {    
                Write-Progress -Id 0 -Activity 'Windows Firewall' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                                        
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /q /m '..\Security-Baselines-X\Windows Firewall Policies\registry.pol'

                # Disables Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles - disables only 3 rules
                Get-NetFirewallRule |
                Where-Object { $_.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302' -and $_.Direction -eq 'inbound' } |
                ForEach-Object { Disable-NetFirewallRule -DisplayName $_.DisplayName }
            } 'No' { break }
            'Exit' { &$CleanUp }
        }    
        # =================================================End of Windows Firewall=================================================
        #endregion Windows-Firewall

        #region Optional-Windows-Features    
        # =================================================Optional Windows Features===============================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Optional Windows Features category ?") {
            'Yes' {    
                Write-Progress -Id 0 -Activity 'Optional Windows Features' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                                        
                # since PowerShell Core (only if installed from Microsoft Store) has problem with these commands, making sure the built-in PowerShell handles them
                # There are Github issues for it already: https://github.com/PowerShell/PowerShell/issues/13866

                powershell.exe {

                    # Disable PowerShell v2 (part 1)       
                    Write-Host "`nDisabling PowerShellv2 1st part" -ForegroundColor Yellow
                    if ((Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).state -eq 'enabled') {
                        try {
                            Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction Stop
                        }
                        catch {
                            # show error
                            $_                           
                        }
                    }
                    else {
                        Write-Host 'PowerShellv2 1st part is already disabled' -ForegroundColor Green 
                    }

                    # Disable PowerShell v2 (part 2)
                    Write-Host "`nDisabling PowerShellv2 2nd part" -ForegroundColor Yellow
                    if ((Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).state -eq 'enabled') {
                        try {
                            Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop
                            # Shows the successful message only if removal process was successful
                            Write-Host 'PowerShellv2 2nd part was successfully disabled' -ForegroundColor Green
                        }
                        catch {
                            # show error
                            $_                           
                        }
                    }
                    else {
                        Write-Host 'PowerShellv2 2nd part is already disabled' -ForegroundColor Green
                    }
            
                    # Disable Work Folders client
                    Write-Host "`nDisabling Work Folders" -ForegroundColor Yellow
                    if ((Get-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client).state -eq 'enabled') { 
                        try {
                            Disable-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -NoRestart -ErrorAction Stop
                            # Shows the successful message only if removal process was successful
                            Write-Host 'Work Folders was successfully disabled' -ForegroundColor Green
                        }
                        catch {
                            #show error
                            $_
                        }
                    }
                    else { 
                        Write-Host 'Work Folders is already disabled' -ForegroundColor Green 
                    }
                
                    # Disable Internet Printing Client
                    Write-Host "`nDisabling Internet Printing Client" -ForegroundColor Yellow
                    if ((Get-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features).state -eq 'enabled') {
                        try {
                            Disable-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features -NoRestart -ErrorAction Stop
                            # Shows the successful message only if removal process was successful
                            Write-Host 'Internet Printing Client was successfully disabled' -ForegroundColor Green
                        }
                        catch {
                            # show errors
                            $_
                        }
                    }
                    else {
                        Write-Host 'Internet Printing Client is already disabled' -ForegroundColor Green 
                    }                

                    # Uninstall Windows Media Player (legacy)
                    Write-Host "`nUninstalling Windows Media Player (legacy)" -ForegroundColor Yellow
                    if ((Get-WindowsCapability -Online | Where-Object { $_.Name -like '*Media.WindowsMediaPlayer*' }).state -ne 'NotPresent') {
                        try {                            
                            Get-WindowsCapability -Online | Where-Object { $_.Name -like '*Media.WindowsMediaPlayer*' } | Remove-WindowsCapability -Online -ErrorAction Stop
                            # Shows the successful message only if removal process was successful
                            Write-Host 'Windows Media Player (legacy) has been uninstalled.' -ForegroundColor Green
                        }
                        catch {
                            # show error
                            $_
                        }
                    }
                    else {
                        Write-Host 'Windows Media Player (legacy) is already uninstalled.' -ForegroundColor Green
                    }
                
                    # Enable Microsoft Defender Application Guard
                    Write-Host "`nEnabling Microsoft Defender Application Guard" -ForegroundColor Yellow
                    if ((Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard).state -eq 'disabled') {
                        try {
                            Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -NoRestart -ErrorAction Stop
                            # Shows the successful message only if enablement process was successful
                            Write-Host 'Microsoft Defender Application Guard was successfully enabled' -ForegroundColor Green
                        }
                        catch {
                            # show errors
                            $_
                        }
                    }
                    else {
                        Write-Host 'Microsoft Defender Application Guard is already enabled' -ForegroundColor Green 
                    }

                }

                # Need to split the commands in 2 scriptblocks so we don't get "program PowerShell.exe failed to run: The filename or extension is too long" error
                powershell.exe {
                
                    # Enable Windows Sandbox
                    Write-Host "`nEnabling Windows Sandbox" -ForegroundColor Yellow
                    if ((Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).state -eq 'disabled') { 
                        try {
                            Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart -ErrorAction Stop
                            # Shows the successful message only if enablement process was successful
                            Write-Host 'Windows Sandbox was successfully enabled' -ForegroundColor Green
                        }
                        catch {
                            # show errors
                            $_
                        }
                    }
                    else { 
                        Write-Host 'Windows Sandbox is already enabled' -ForegroundColor Green 
                    }
                
                    # Enable Hyper-V
                    Write-Host "`nEnabling Hyper-V" -ForegroundColor Yellow
                    if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq 'disabled') {
                        try {
                            Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart -ErrorAction Stop
                            # Shows the successful message only if enablement process was successful
                            Write-Host 'Hyper-V was successfully enabled' -ForegroundColor Green
                        }
                        catch {
                            # show errors
                            $_
                        }
                    }
                    else {
                        Write-Host 'Hyper-V is already enabled' -ForegroundColor Green
                    }
                
                    # Enable Virtual Machine Platform
                    Write-Host "`nEnabling Virtual Machine Platform" -ForegroundColor Yellow
                    if ((Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).state -eq 'disabled') {
                        try {
                            Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart -ErrorAction Stop
                            # Shows the successful message only if enablement process was successful
                            Write-Host 'Virtual Machine Platform was successfully enabled' -ForegroundColor Green
                        }
                        catch {
                            # show errors
                            $_
                        }
                    }
                    else {
                        Write-Host 'Virtual Machine Platform is already enabled' -ForegroundColor Green
                    }
            
                    # Uninstall VBScript that is now uninstallable as an optional features since Windows 11 insider Dev build 25309 - Won't do anything in other builds                      
                    if (Get-WindowsCapability -Online | Where-Object { $_.Name -like '*VBSCRIPT*' }) {                        
                        try {  
                            Write-Host "`nUninstalling VBSCRIPT" -ForegroundColor Yellow                          
                            Get-WindowsCapability -Online | Where-Object { $_.Name -like '*VBSCRIPT*' } | Remove-WindowsCapability -Online -ErrorAction Stop
                            # Shows the successful message only if removal process was successful                                                      
                            Write-Host 'VBSCRIPT has been uninstalled' -ForegroundColor Green
                        }
                        catch {
                            # show errors
                            $_
                        }
                    }     
                
                    # Uninstall Internet Explorer mode functionality for Edge
                    Write-Host "`nUninstalling Internet Explorer mode functionality for Edge" -ForegroundColor Yellow
                    if ((Get-WindowsCapability -Online | Where-Object { $_.Name -like '*Browser.InternetExplorer*' }).state -ne 'NotPresent') {
                        try {                            
                            Get-WindowsCapability -Online | Where-Object { $_.Name -like '*Browser.InternetExplorer*' } | Remove-WindowsCapability -Online -ErrorAction Stop
                            # Shows the successful message only if removal process was successful
                            Write-Host 'Internet Explorer mode functionality for Edge has been uninstalled' -ForegroundColor Green
                        }
                        catch {
                            # show errors
                            $_
                        }
                    }
                    else {
                        Write-Host 'Internet Explorer mode functionality for Edge is already uninstalled.' -ForegroundColor Green
                    }

                    # Uninstall WMIC 
                    Write-Host "`nUninstalling WMIC" -ForegroundColor Yellow
                    if ((Get-WindowsCapability -Online | Where-Object { $_.Name -like '*wmic*' }).state -ne 'NotPresent') {                   
                        try {                            
                            Get-WindowsCapability -Online | Where-Object { $_.Name -like '*wmic*' } | Remove-WindowsCapability -Online -ErrorAction Stop
                            # Shows the successful message only if removal process was successful
                            Write-Host 'WMIC has been uninstalled' -ForegroundColor Green
                        }
                        catch {
                            # show error
                            $_
                        }
                    }
                    else {
                        Write-Host 'WMIC is already uninstalled.' -ForegroundColor Green
                    }

                    # Uninstall Legacy Notepad
                    Write-Host "`nUninstalling Legacy Notepad" -ForegroundColor Yellow
                    if ((Get-WindowsCapability -Online | Where-Object { $_.Name -like '*Microsoft.Windows.Notepad.System*' }).state -ne 'NotPresent') {
                        try {                            
                            Get-WindowsCapability -Online | Where-Object { $_.Name -like '*Microsoft.Windows.Notepad.System*' } | Remove-WindowsCapability -Online -ErrorAction Stop
                            # Shows the successful message only if removal process was successful
                            Write-Host 'Legacy Notepad has been uninstalled. The modern multi-tabbed Notepad is unaffected.' -ForegroundColor Green
                        }
                        catch {
                            # show error
                            $_
                        }
                    }
                    else {
                        Write-Host 'Legacy Notepad is already uninstalled.' -ForegroundColor Green
                    }

                    # Uninstall WordPad
                    Write-Host "`nUninstalling WordPad" -ForegroundColor Yellow
                    if ((Get-WindowsCapability -Online | Where-Object { $_.Name -like '*Microsoft.Windows.WordPad*' }).state -ne 'NotPresent') {
                        try {                            
                            Get-WindowsCapability -Online | Where-Object { $_.Name -like '*Microsoft.Windows.WordPad*' } | Remove-WindowsCapability -Online -ErrorAction Stop
                            # Shows the successful message only if removal process was successful
                            Write-Host 'WordPad has been uninstalled.' -ForegroundColor Green
                        }
                        catch {
                            # show error
                            $_
                        }
                    }
                    else {
                        Write-Host 'WordPad is already uninstalled.' -ForegroundColor Green
                    }   

                    # Uninstall PowerShell ISE
                    Write-Host "`nUninstalling PowerShell ISE" -ForegroundColor Yellow
                    if ((Get-WindowsCapability -Online | Where-Object { $_.Name -like '*Microsoft.Windows.PowerShell.ISE*' }).state -ne 'NotPresent') {
                        try {                            
                            Get-WindowsCapability -Online | Where-Object { $_.Name -like '*Microsoft.Windows.PowerShell.ISE*' } | Remove-WindowsCapability -Online -ErrorAction Stop
                            # Shows the successful message only if removal process was successful
                            Write-Host 'PowerShell ISE has been uninstalled.' -ForegroundColor Green
                        }
                        catch {
                            # show error
                            $_
                        }
                    }
                    else {
                        Write-Host 'PowerShell ISE is already uninstalled.' -ForegroundColor Green
                    }                    
                }

            } 'No' { break }
            'Exit' { &$CleanUp }
        }    
        # ==============================================End of Optional Windows Features===========================================
        #endregion Optional-Windows-Features

        #region Windows-Networking   
        # ====================================================Windows Networking===================================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Windows Networking category ?") {
            'Yes' { 
                Write-Progress -Id 0 -Activity 'Windows Networking' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
              
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /q /m '..\Security-Baselines-X\Windows Networking Policies\registry.pol'
                .\LGPO.exe /q /s '..\Security-Baselines-X\Windows Networking Policies\GptTmpl.inf'

                # Disable LMHOSTS lookup protocol on all network adapters
                Edit-Registry -path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -key 'EnableLMHOSTS' -value '0' -type 'DWORD' -Action 'AddOrModify' | Out-Null

                # Set the Network Location of all connections to Public
                Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Public
            } 'No' { break }
            'Exit' { &$CleanUp }
        }
        # =================================================End of Windows Networking===============================================
        #endregion Windows-Networking

        #region Miscellaneous-Configurations    
        # ==============================================Miscellaneous Configurations===============================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Miscellaneous Configurations category ?") {
            'Yes' {   
                Write-Progress -Id 0 -Activity 'Miscellaneous Configurations' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                                      
                # Miscellaneous Registry section
                Set-Location $WorkingDir
                [System.Object[]]$Items = Import-Csv '.\Registry.csv' -Delimiter ','
                foreach ($Item in $Items) {
                    if ($Item.category -eq 'Miscellaneous') {              
                        Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action | Out-Null
                    }
                }
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /q /m '..\Security-Baselines-X\Miscellaneous Policies\registry.pol'
                .\LGPO.exe /q /s '..\Security-Baselines-X\Miscellaneous Policies\GptTmpl.inf'

                # Apply the Blocking Untrusted Fonts policy
                switch (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nBlock Untrusted Fonts ?") {
                    'Yes' {
                        .\LGPO.exe /q /m '..\Security-Baselines-X\Miscellaneous Policies\Blocking Untrusted Fonts\registry.pol'                      
                    } 'No' { break }
                    'Exit' { &$CleanUp }
                }
                   
                # Allow all Windows users to use Hyper-V and Windows Sandbox by adding all Windows users to the "Hyper-V Administrators" security group using its SID
                Get-LocalUser | Where-Object { $_.enabled -eq 'True' } | ForEach-Object { Add-LocalGroupMember -SID 'S-1-5-32-578' -Member $_.Name -ErrorAction SilentlyContinue }
                
                # Makes sure auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category is enabled, doesn't touch affect any other sub-category
                # For tracking Lock screen unlocks and locks
                # auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
                # Using GUID
                auditpol /set /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
                
                # Query all Audits status
                # auditpol /get /category:*
                # Get the list of subcategories and their associated GUIDs
                # auditpol /list /subcategory:* /r

                # Event Viewer custom views are saved in "C:\ProgramData\Microsoft\Event Viewer\Views". files in there can be backed up and restored on new Windows installations.
                New-Item -ItemType Directory -Path 'C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\' -Force | Out-Null                

                # Due to change in event viewer custom log files, making sure no old file names exist
                if (Test-Path -Path 'C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script') {
                    Remove-Item -Path 'C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script' -Recurse -Force
                }
                # Creating new sub-folder to store the custom views
                New-Item -Path 'C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script' -ItemType Directory -Force | Out-Null

                Expand-Archive -Path "$WorkingDir\EventViewerCustomViews.zip" -DestinationPath 'C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script' -Force -ErrorAction Stop
                
            } 'No' { break }
            'Exit' { &$CleanUp }
        }    
        # ============================================End of Miscellaneous Configurations==========================================
        #endregion Miscellaneous-Configurations
 
        #region Windows-Update-Configurations    
        # ====================================================Windows Update Configurations==============================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Windows Update Policies ?") {
            'Yes' {
                Write-Progress -Id 0 -Activity 'Windows Update Configurations' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                      
                # Enable restart notification for Windows update
                Edit-Registry -path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -key 'RestartNotificationsAllowed2' -value '1' -type 'DWORD' -Action 'AddOrModify' | Out-Null
                # Change current working directory to the LGPO's folder
                Set-Location "$WorkingDir\LGPO_30"
                .\LGPO.exe /q /m '..\Security-Baselines-X\Windows Update Policies\registry.pol'
            } 'No' { break }
            'Exit' { &$CleanUp }
        }    
        # ====================================================End of Windows Update Configurations=======================================
        #endregion Windows-Update-Configurations

        #region Edge-Browser-Configurations
        # ====================================================Edge Browser Configurations====================================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Edge Browser Configurations ?") {
            'Yes' {   
                Write-Progress -Id 0 -Activity 'Edge Browser Configurations' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                     
                # Edge Browser Configurations registry
                Set-Location $WorkingDir
                [System.Object[]]$Items = Import-Csv '.\Registry.csv' -Delimiter ','
                foreach ($Item in $Items) {
                    if ($Item.category -eq 'Edge') {
                        Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action | Out-Null
                    }
                }
            } 'No' { break }
            'Exit' { &$CleanUp }
        } 
        # ====================================================End of Edge Browser Configurations==============================================
        #endregion Edge-Browser-Configurations
        
        #region Certificate-Checking-Commands    
        # ====================================================Certificate Checking Commands========================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Certificate Checking category ?") {
            'Yes' {    
                Write-Progress -Id 0 -Activity 'Certificate Checking Commands' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                      
                try {
                    Invoke-WithoutProgress {                    
                        Invoke-WebRequest -Uri 'https://live.sysinternals.com/sigcheck64.exe' -OutFile 'sigcheck64.exe' -ErrorAction Stop
                    }                
                }
                catch {                    
                    Write-Host "sigcheck64.exe couldn't be downloaded from https://live.sysinternals.com" -ForegroundColor Red
                    break
                }      
                Write-Host -NoNewline "`nListing valid certificates not rooted to the Microsoft Certificate Trust List in the" -ForegroundColor Yellow; Write-Host " User store`n" -ForegroundColor cyan
                .\sigcheck64.exe -tuv -accepteula -nobanner     
    
                Write-Host -NoNewline "`nListing valid certificates not rooted to the Microsoft Certificate Trust List in the" -ForegroundColor Yellow; Write-Host " Machine Store`n" -ForegroundColor Blue
                .\sigcheck64.exe -tv -accepteula -nobanner
                Remove-Item -Path .\sigcheck64.exe -Force
            } 'No' { break }
            'Exit' { &$CleanUp }
        }
        # ====================================================End of Certificate Checking Commands=================================
        #endregion Certificate-Checking-Commands

        #region Country-IP-Blocking    
        # ====================================================Country IP Blocking==================================================
        $CurrentMainStep++
        switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Country IP Blocking category ?") {
            'Yes' {    
                Write-Progress -Id 0 -Activity 'Country IP Blocking' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
              
                # -RemoteAddress in New-NetFirewallRule accepts array according to Microsoft Docs, 
                # so we use "[string[]]$IPList = $IPList -split '\r?\n' -ne ''" to convert the IP lists, which is a single multiline string, into an array
                function Block-CountryIP {
                    param ([string[]]$IPList , [System.String]$ListName)
                    
                    # deletes previous rules (if any) to get new up-to-date IP ranges from the sources and set new rules               
                    Remove-NetFirewallRule -DisplayName "$ListName IP range blocking" -PolicyStore localhost -ErrorAction SilentlyContinue
                    
                    # converts the list which is in string into array
                    [string[]]$IPList = $IPList -split '\r?\n' -ne ''

                    # makes sure the list isn't empty
                    if ($IPList.count -eq 0) {
                        Write-Host "The IP list was empty, skipping $ListName" -ForegroundColor Yellow
                        break 
                    }      

                    New-NetFirewallRule -DisplayName "$ListName IP range blocking" -Direction Inbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$ListName IP range blocking" -EdgeTraversalPolicy Block -PolicyStore localhost
                    New-NetFirewallRule -DisplayName "$ListName IP range blocking" -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$ListName IP range blocking" -EdgeTraversalPolicy Block -PolicyStore localhost        
                }
                switch (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Add countries in the State Sponsors of Terrorism list to the Firewall block list?') {
                    'Yes' {
                        Invoke-WithoutProgress {   
                            $global:StateSponsorsofTerrorism = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/StateSponsorsOfTerrorism.txt'
                        }
                        Block-CountryIP -IPList $StateSponsorsofTerrorism -ListName 'State Sponsors of Terrorism'
                    } 'No' { break }
                }
                switch (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Add OFAC Sanctioned Countries to the Firewall block list?') {
                    'Yes' {
                        Invoke-WithoutProgress {   
                            $global:OFACSanctioned = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/OFACSanctioned.txt'            
                        }
                        Block-CountryIP -IPList $OFACSanctioned -ListName 'OFAC Sanctioned Countries'
                    } 'No' { break }
                }

                # how to query the number of IPs in each rule
                # (Get-NetFirewallRule -DisplayName "OFAC Sanctioned Countries IP range blocking" -PolicyStore localhost | Get-NetFirewallAddressFilter).RemoteAddress.count
            
            } 'No' { break }
            'Exit' { &$CleanUp }
        }    
        # ====================================================End of Country IP Blocking===========================================
        #endregion Country-IP-Blocking
    
    } # End of Admin test function

    #region Non-Admin-Commands
    # ====================================================Non-Admin Commands===================================================
    switch (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Non-Admin category ?") {
        'Yes' {
            $CurrentMainStep = $TotalMainSteps
            Write-Progress -Id 0 -Activity 'Non-Admin category' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
    
            # Non-Admin Registry section              
            Set-Location $WorkingDir       
            Invoke-WithoutProgress { 
                # Download Registry CSV file from GitHub or Azure DevOps
                try {
                    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Payload/Registry.csv' -OutFile '.\Registry.csv' -ErrorAction Stop                
                }
                catch {
                    Write-Host 'Using Azure DevOps...' -ForegroundColor Yellow
                    Invoke-WebRequest -Uri 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/Registry.csv' -OutFile '.\Registry.csv' -ErrorAction Stop
                } 
            }
            [System.Object[]]$Items = Import-Csv '.\Registry.csv' -Delimiter ','
            foreach ($Item in $Items) {
                if ($Item.category -eq 'NonAdmin') {              
                    Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action | Out-Null
                }
            }  

            # Only suggest restarting the device if Admin related categories were run
            if (Test-IsAdmin) {          
                Write-Host "`r`n"
                Write-SmartText -C Rainbow -G Cyan -I "################################################################################################`r`n"
                Write-SmartText -C MintGreen -G Cyan -I "###  Please Restart your device to completely apply the security measures and Group Policies ###`r`n"
                Write-SmartText -C Rainbow -G Cyan -I "################################################################################################`r`n"
            }

        } 'No' { &$CleanUp }
        'Exit' { &$CleanUp }
    }
    # ====================================================End of Non-Admin Commands============================================
    #endregion Non-Admin-Commands
}
finally {
    # Disable progress bars
    0..5 | ForEach-Object { Write-Progress -Id $_ -Activity 'Done' -Completed }

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
    Set-Location $HOME; Remove-Item -Recurse -Path "$global:UserTempDirectoryPath\HardeningXStuff\" -Force -ErrorAction SilentlyContinue    
}
