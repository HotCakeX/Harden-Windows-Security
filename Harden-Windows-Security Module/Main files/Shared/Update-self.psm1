function Update-self {
    <#
    .SYNOPSIS
        Make sure the latest version of the module is installed and if not, automatically update it, clean up any old versions
    .PARAMETER InvocationStatement
        The command that was used to invoke the main function/cmdlet that invoked the Update-self function, this is used to re-run the command after the module has been updated.
        It checks to make sure the Update-self function was called by an authorized command, that is one of the main cmdlets of the Harden-Windows-Security module, otherwise it will throw an error.
        The parameter also shouldn't contain any backtick or semicolon characters used to chain commands together.
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidatePattern('^(Protect-WindowsSecurity|Unprotect-WindowsSecurity|Confirm-SystemCompliance)(?!.*[;`]).*$', ErrorMessage = 'Either Update-self function was called with an unauthorized command or it contains semicolon and/or backtick')]
        [System.String]$InvocationStatement
    )

    # Importing the required sub-modules
    Write-Verbose -Message 'Importing the required sub-modules'
    Import-Module -FullyQualifiedName "$HardeningModulePath\Shared\Test-IsAdmin.psm1" -Force -Verbose:$false

    # Get the current module's version
    [System.Version]$CurrentVersion = (Test-ModuleManifest -Path "$HardeningModulePath\Harden-Windows-Security-Module.psd1").Version

    # Get the latest version from GitHub
    [System.Version]$LatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/version.txt' -ProgressAction SilentlyContinue

    if ($CurrentVersion -lt $LatestVersion) {
        Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,105,180))The currently installed module's version is $CurrentVersion while the latest version is $LatestVersion - Auto Updating the module... 💓$($PSStyle.Reset)"

        # Only attempt to auto update the module if running as Admin, because Controlled Folder Access exclusion modification requires Admin privs
        if (-NOT (Test-IsAdmin)) { Throw 'There is a new update available, please run the cmdlet as Admin to update the module.' }

        Remove-Module -Name 'Harden-Windows-Security-Module' -Force

        try {
            # backup the current allowed apps list in Controlled folder access in order to restore them at the end of the script
            # doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
            # no user customization will be affected
            [System.String[]]$CFAAllowedAppsBackup = (Get-MpPreference).ControlledFolderAccessAllowedApplications

            # Temporarily allow the currently running PowerShell executables to the Controlled Folder Access allowed apps
            # so that the script can run without interruption. This change is reverted at the end.
            foreach ($FilePath in (Get-ChildItem -Path "$PSHOME\*.exe" -File).FullName) {
                Add-MpPreference -ControlledFolderAccessAllowedApplications $FilePath
            }

            # Do this if the module was installed properly using Install-module cmdlet
            Uninstall-Module -Name 'Harden-Windows-Security-Module' -AllVersions -Force
            Install-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force
            # Will not import the new module version in the current session because of the constant variables. New version is automatically imported when the main cmdlet is run in a new session.
        }
        # Do this if module files/folder was just copied to Documents folder and not properly installed - Should rarely happen
        catch {
            Install-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force
            # Will not import the new module version in the current session because of the constant variables. New version is automatically imported when the main cmdlet is run in a new session.
        }
        finally {
            # Reverting the PowerShell executables allow listings in Controlled folder access
            foreach ($FilePath in (Get-ChildItem -Path "$PSHOME\*.exe" -File).FullName) {
                Remove-MpPreference -ControlledFolderAccessAllowedApplications $FilePath
            }

            # restoring the original Controlled folder access allow list - if user already had added PowerShell executables to the list
            # they will be restored as well, so user customization will remain intact
            if ($null -ne $CFAAllowedAppsBackup) {
                Set-MpPreference -ControlledFolderAccessAllowedApplications $CFAAllowedAppsBackup
            }
        }

        Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(152,255,152))Update has been successful, running your command now$($PSStyle.Reset)"

        # Make sure the old version isn't run after update
        try {
            # Try to re-run the command that invoked the Update-self function in a new session after the module is updated.
            pwsh.exe -NoLogo -NoExit -command $InvocationStatement
        }
        catch {
            Throw 'Could not relaunch PowerShell after update. Please close and reopen PowerShell to run your command again.'
        }

    }
}
# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Update-self' -Verbose:$false
