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
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidatePattern('^(Protect-WindowsSecurity|Unprotect-WindowsSecurity|Confirm-SystemCompliance)(?!.*[;`]).*$', ErrorMessage = 'Either Update-self function was called with an unauthorized command or it contains semicolon and/or backtick')]
        [System.String]$InvocationStatement
    )
    $script:ErrorActionPreference = 'Stop'

    # Get the current module's version
    [System.Version]$CurrentVersion = (Test-ModuleManifest -Path "$([HardenWindowsSecurity.GlobalVars]::Path)\Harden-Windows-Security-Module.psd1").Version

    # Get the latest version from GitHub
    [System.Version]$LatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/version.txt' -ProgressAction SilentlyContinue

    if ($CurrentVersion -lt $LatestVersion) {
        Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,105,180))The currently installed module's version is $CurrentVersion while the latest version is $LatestVersion - Auto Updating the module... 💓$($PSStyle.Reset)"

        # Only attempt to auto update the module if running as Admin, because Controlled Folder Access exclusion modification requires Admin privs
        if (-NOT ([HardenWindowsSecurity.UserPrivCheck]::IsAdmin())) {
            Throw 'There is a new update available, please run the cmdlet as Admin to update the module.'
        }

        Remove-Module -Name 'Harden-Windows-Security-Module' -Force -WarningAction SilentlyContinue

        try {
            [HardenWindowsSecurity.ControlledFolderAccessHandler]::Start()
            # Suppressing errors and warnings on this one because it can't uninstall the module currently in use even after Remove attempt earlier so it removes any leftover versions except for the one currently in use.
            Uninstall-Module -Name 'Harden-Windows-Security-Module' -AllVersions -Force -WarningAction SilentlyContinue -ErrorAction Ignore
            Install-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force
            # Will not import the new module version in the current session. New version is automatically imported and used when the main cmdlet is run in a new session.
        }
        catch {}
        finally {
            [HardenWindowsSecurity.ControlledFolderAccessHandler]::reset()
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
