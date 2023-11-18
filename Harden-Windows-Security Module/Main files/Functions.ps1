# Stop the execution when there is an error
$global:ErrorActionPreference = 'Stop'

# Function to test if current session has administrator privileges
Function Test-IsAdmin {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal $Identity
    $Principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Make sure the latest version of the module is installed and if not, automatically update it, clean up any old versions
function Update-self {   

    [System.Version]$CurrentVersion = (Test-ModuleManifest -Path "$psscriptroot\Harden-Windows-Security-Module.psd1").Version
        
    try {
        [System.Version]$global:LatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/version.txt' -ProgressAction SilentlyContinue     
    }
    catch {   
        Write-Error -Message "Couldn't verify if the latest version of the module is installed, please check your Internet connection."
    }
        
    if ($CurrentVersion -lt $LatestVersion) {
        Write-Output "$($PSStyle.Foreground.FromRGB(255,105,180))The currently installed module's version is $CurrentVersion while the latest version is $LatestVersion - Auto Updating the module... 💓$($PSStyle.Reset)"
        
        # Only attempt to auto update the module if running as Admin, because Controlled Folder Access exclusion modification requires Admin privs
        if (Test-IsAdmin) {               
        
            Remove-Module -Name 'Harden-Windows-Security-Module' -Force
            
            try {
                # backup the current allowed apps list in Controlled folder access in order to restore them at the end of the script
                # doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
                # no user customization will be affected
                [string[]]$CFAAllowedAppsBackup = (Get-MpPreference).ControlledFolderAccessAllowedApplications
        
                # Temporarily allow the currently running PowerShell executables to the Controlled Folder Access allowed apps
                # so that the script can run without interruption. This change is reverted at the end.
                Get-ChildItem -Path "$PSHOME\*.exe" | ForEach-Object {
                    Add-MpPreference -ControlledFolderAccessAllowedApplications $_.FullName
                }

                # Do this if the module was installed properly using Install-moodule cmdlet
                Uninstall-Module -Name 'Harden-Windows-Security-Module' -AllVersions -Force
                Install-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force              
                Import-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force -Global
            }
            # Do this if module files/folder was just copied to Documents folder and not properly installed - Should rarely happen
            catch {
                Install-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force
                Import-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force -Global
            }
            finally {
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
            # Make sure the old version isn't run after update
            Write-Output "$($PSStyle.Foreground.FromRGB(152,255,152))Update successful, please run the cmdlet again.$($PSStyle.Reset)"          
            break
            return 
        }            
        else {            
            Write-Error -Message 'Please run the cmdlet as Admin to update the module.'
            break
        }
    }
}

# Self update the module
Update-self

#Region Requirements-Check

# check if user's OS is Windows Home edition
if ((Get-CimInstance -ClassName Win32_OperatingSystem).OperatingSystemSKU -eq '101') {
    Write-Error 'Windows Home edition detected, exiting...'
    break
}

# Check if user's OS is the latest build
# Minimum OS build number required for the hardening measures used in this script
[System.Decimal]$Requiredbuild = '22621.2428'

# Get OS build version
[System.Decimal]$OSBuild = [System.Environment]::OSVersion.Version.Build

# Get Update Build Revision (UBR) number
[System.Decimal]$UBR = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR'

# Create full OS build number as seen in Windows Settings
[System.Decimal]$FullOSBuild = "$OSBuild.$UBR"

# Make sure the current OS build is equal or greater than the required build
if (-NOT ($FullOSBuild -ge $Requiredbuild)) {
    Write-Error -Message "You're not using the latest build of the Windows OS. A minimum build of $Requiredbuild is required but your OS build is $FullOSBuild`nPlease go to Windows Update to install the updates and then try again."
    break
}

if (Test-IsAdmin) {
    # check to make sure TPM is available and enabled
    $TPM = Get-Tpm
    if (-not ($TPM.tpmpresent -and $TPM.tpmenabled)) {
        Write-Error -Message 'TPM is not available or enabled, please enable it in UEFI settings and try again.'
        break
    }
}

#Endregion Requirements-Check
