Function Protect-WindowsSecurity { 
    
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

    # Function to test if current session has administrator privileges
    Function Test-IsAdmin {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal $identity
        $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    }

    # Make sure the latest version of the module is installed and if not, automatically update it, clean up any old versions
    function Update-self {   

        [version]$CurrentVersion = (Test-ModuleManifest "$psscriptroot\Harden-Windows-Security-Module.psd1" -ErrorAction Stop).Version
            
        try {
            Invoke-WithoutProgress {             
                [version]$global:LatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/version.txt'             
            }
        }
        catch {   
            Write-Error -Message "Couldn't verify if the latest version of the module is installed, please check your Internet connection." -ErrorAction Stop
        }
            
        if ($CurrentVersion -lt $LatestVersion) {
            Write-Output "$($PSStyle.Foreground.FromRGB(255,105,180))The currently installed module's version is $CurrentVersion while the latest version is $LatestVersion - Auto Updating the module... 💓$($PSStyle.Reset)"
            
            # Only attempt to auto update the module if running as Admin, because Controlled Folder Access exclusion modification requires Admin privs
            if (Test-IsAdmin) {               
            
                Remove-Module -Name 'Harden-Windows-Security-Module' -Force -ErrorAction Stop
                
                try {
                    # backup the current allowed apps list in Controlled folder access in order to restore them at the end of the script
                    # doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
                    # no user customization will be affected
                    [string[]]$CFAAllowedAppsBackup = (Get-MpPreference).ControlledFolderAccessAllowedApplications
            
                    # Temporarily allow the currently running PowerShell executables to the Controlled Folder Access allowed apps
                    # so that the script can run without interruption. This change is reverted at the end.
                    Get-ChildItem -Path "$PSHOME\*.exe" -ErrorAction Stop | ForEach-Object {
                        Add-MpPreference -ControlledFolderAccessAllowedApplications $_.FullName -ErrorAction Stop
                    }

                    # Do this if the module was installed properly using Install-moodule cmdlet
                    Uninstall-Module -Name 'Harden-Windows-Security-Module' -AllVersions -Force -ErrorAction Stop
                    Install-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force -ErrorAction Stop              
                    Import-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force -Global -ErrorAction Stop
                }
                # Do this if module files/folder was just copied to Documents folder and not properly installed - Should rarely happen
                catch {
                    Install-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force -ErrorAction Stop
                    Import-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force -Global -ErrorAction Stop
                }
                finally {
                    # Reverting the PowerShell executables allow listings in Controlled folder access
                    Get-ChildItem -Path "$PSHOME\*.exe" -ErrorAction Stop | ForEach-Object {
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
                Write-Output "$($PSStyle.Foreground.FromRGB(152,255,152))Update successful, please run the Protect-WindowsSecurity cmdlet again.$($PSStyle.Reset)"          
                break
                return 
            }            
            else {            
                Write-Error -Message 'Run the protect-WindowsSecurity cmdlet as Admin to update the module.'
                break
            }
        }
    }
       
    # Self update the module
    Update-self
        
    & "$psscriptroot\Harden-Windows-Security.ps1"

    <#
.SYNOPSIS
Applies the hardening measures

.LINK
https://github.com/HotCakeX/Harden-Windows-Security

.DESCRIPTION
Applies the hardening measures

.COMPONENT
PowerShell

.FUNCTIONALITY
Applies the hardening measures

#> 
}
