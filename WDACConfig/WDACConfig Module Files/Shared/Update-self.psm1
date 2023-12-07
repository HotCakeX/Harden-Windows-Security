Function Update-self {
    <#
    .SYNOPSIS
        Make sure the latest version of the module is installed and if not, automatically update it, clean up any old versions
    .INPUTS
        System.Void
    .OUTPUTS
        System.Void
    #>

    try {
        # Get the last update check time
        [System.DateTime]$UserConfigDate = Get-CommonWDACConfig -LastUpdateCheck
    }
    catch {
        # If the User Config file doesn't exist then set this flag to perform online update check
        [System.Boolean]$PerformOnlineUpdateCheck = $true
    }

    # Ensure these are run only if the User Config file exists and contains a date for last update check
    if (!$PerformOnlineUpdateCheck) {
        # Get the current time
        [System.DateTime]$CurrentDateTime = Get-Date
        # Calculate the minutes elapsed since the last online update check
        [System.Int64]$TimeDiff = ($CurrentDateTime - $UserConfigDate).TotalMinutes
    }

    # Only check for updates if the last attempt occured more than 10 minutes ago or the User Config file for last update check doesn't exist
    # This prevents the module from constantly doing an update check by fetching the version file from GitHub
    if (($TimeDiff -gt 10) -or $PerformOnlineUpdateCheck) {

        [System.Version]$CurrentVersion = (Test-ModuleManifest -Path "$ModuleRootPath\WDACConfig.psd1").Version.ToString()
        try {
            # First try the GitHub source
            [System.Version]$LatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/version.txt' -ProgressAction SilentlyContinue
        }
        catch {
            try {
                # If GitHub source is unavailable, use the Azure DevOps source
                [System.Version]$LatestVersion = Invoke-RestMethod -Uri 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/WDACConfig/version.txt' -ProgressAction SilentlyContinue
            }
            catch {
                Throw [System.Security.VerificationException] 'Could not verify if the latest version of the module is installed, please check your Internet connection. You can optionally bypass the online check by using -SkipVersionCheck parameter.'
            }
        }
        if ($CurrentVersion -lt $LatestVersion) {
            Write-ColorfulText -Color Pink -InputText "The currently installed module's version is $CurrentVersion while the latest version is $LatestVersion - Auto Updating the module... 💓"
            Remove-Module -Name 'WDACConfig' -Force
            # Do this if the module was installed properly using Install-module cmdlet
            try {
                Uninstall-Module -Name 'WDACConfig' -AllVersions -Force -ErrorAction Stop
                Install-Module -Name 'WDACConfig' -RequiredVersion $LatestVersion -Force
                Import-Module -Name 'WDACConfig' -RequiredVersion $LatestVersion -Force -Global
            }
            # Do this if module files/folder was just copied to Documents folder and not properly installed - Should rarely happen
            catch {
                Install-Module -Name 'WDACConfig' -RequiredVersion $LatestVersion -Force
                Import-Module -Name 'WDACConfig' -RequiredVersion $LatestVersion -Force -Global
            }
            # Make sure the old version isn't run after update
            Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(152,255,152))Update successful, please run the cmdlet again.$($PSStyle.Reset)"
            break
            return
        }

        # Reset the last update timer to the current time
        Set-CommonWDACConfig -LastUpdateCheck $(Get-Date ) | Out-Null
    }
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Update-self' -Verbose:$false
