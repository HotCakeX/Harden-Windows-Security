$global:ErrorActionPreference = 'Stop'

if (!$IsWindows) {
    Throw [System.PlatformNotSupportedException] 'The WDACConfig module only runs on Windows operation systems. Download it from here: https://www.microsoft.com/software-download/windows11'
}

#Requires -RunAsAdministrator

Function Update-WDACConfigPSModule {
    <#
    .SYNOPSIS
        Make sure the latest version of the module is installed and if not, automatically update it, clean up any old versions
    .PARAMETER InvocationStatement
        The command that was used to invoke the main function/cmdlet that invoked the Update-WDACConfigPSModule function, this is used to re-run the command after the module has been updated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [System.String]$InvocationStatement
    )
    try {
        [WDACConfig.Logger]::Write('Getting the last update check time')
        [System.DateTime]$UserConfigDate = [WDACConfig.UserConfiguration]::Get().LastUpdateCheck
    }
    catch {
        # If the User Config file doesn't exist then set this flag to perform online update check
        [WDACConfig.Logger]::Write('No LastUpdateCheck was found in the user configurations, will perform online update check')
        [System.Boolean]$PerformOnlineUpdateCheck = $true
        # If it's the first time the module is running on a system, keep the auto-update enabled, unless user disables it. This maintains the same experience as before.
        $null = [WDACConfig.UserConfiguration]::Set($null, $null, $null, $null, $null, $null, $null, $null , $null, $true)
    }

    # If the AutoUpdateCheck is not set, set it to true. This only occurs when the user auto updates from a previous version that doesn't have AutoUpdateCheck context to a new one that utilizes it.
    # This ensures that the auto update check experience remains familiar and the same unless user disables it explicitly. This step can be removed in the future once all users are moved to the new versions.
    if ($null -eq [WDACConfig.UserConfiguration]::Get().AutoUpdateCheck) {
        $null = [WDACConfig.UserConfiguration]::Set($null, $null, $null, $null, $null, $null, $null, $null , $null, $true)
    }

    # Ensure these are run only if the User Config file exists and contains a date for last update check
    if (!$PerformOnlineUpdateCheck) {
        # Get the current time
        [System.DateTime]$CurrentDateTime = Get-Date
        # Calculate the minutes elapsed since the last online update check
        [System.Int64]$TimeDiff = ($CurrentDateTime - $UserConfigDate).TotalMinutes
    }

    # Only check for updates if the last attempt occurred more than 60 minutes ago And the AutoUpdateCheck is true, Or the User Config file for last update check doesn't exist
    # This prevents the module from constantly doing an update check by fetching the version file from GitHub
    if ((($TimeDiff -gt 60) -and ([WDACConfig.UserConfiguration]::Get().AutoUpdateCheck -eq $true)) -or $PerformOnlineUpdateCheck) {

        [WDACConfig.Logger]::Write("Performing online update check because the last update check was performed $($TimeDiff ?? [System.Char]::ConvertFromUtf32(8734)) minutes ago")

        [System.Version]$CurrentVersion = (Test-ModuleManifest -Path "$([WDACConfig.GlobalVars]::ModuleRootPath)\WDACConfig.psd1").Version.ToString()
        try {
            # First try the GitHub source
            [System.Version]$LatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/version.txt' -ProgressAction SilentlyContinue
        }
        catch {
            try {
                # If GitHub source is unavailable, use the Azure DevOps source which is the mirror of the GitHub repository
                [System.Version]$LatestVersion = Invoke-RestMethod -Uri 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/WDACConfig/version.txt' -ProgressAction SilentlyContinue
            }
            catch {
                Throw [System.Security.VerificationException] 'Could not verify if the latest version of the module is installed, please check your Internet connection.'
            }
        }

        # Reset the last update timer to the current time
        [WDACConfig.Logger]::Write('Resetting the last update timer to the current time')
        $null = [WDACConfig.UserConfiguration]::Set($null, $null, $null, $null, $null, $null, $null, $(Get-Date) , $null, $null)

        if ($CurrentVersion -lt $LatestVersion) {

            Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,0,230))The currently installed module's version is $CurrentVersion while the latest version is $LatestVersion - Auto Updating the module...$($PSStyle.Reset)"

            # Remove the old module version from the current session
            Remove-Module -Name 'WDACConfig' -Force -WarningAction SilentlyContinue

            try {
                Uninstall-Module -Name 'WDACConfig' -AllVersions -Force -ErrorAction Ignore -WarningAction SilentlyContinue
            }
            catch {}

            Install-Module -Name 'WDACConfig' -RequiredVersion $LatestVersion -Scope AllUsers -Force
            # Will not import the new module version in the current session because of the constant variables. New version is automatically imported when the main cmdlet is run in a new session.

            # Make sure the old version isn't run after update
            Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(152,255,152))Update has been successful, running your command now$($PSStyle.Reset)"

            try {
                # Try to re-run the command that invoked the Update-WDACConfigPSModule function in a new session after the module is updated.
                pwsh.exe -NoProfile -NoLogo -NoExit -command $InvocationStatement
            }
            catch {
                Throw 'Could not relaunch PowerShell after update. Please close and reopen PowerShell to run your command again.'
            }
        }
    }
    else {
        [WDACConfig.Logger]::Write('Skipping online update check.')
    }
}

# Unimportant actions that don't need to be terminating if they fail
try {
    # Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
    Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'
    # Enables additional progress indicators for Windows Terminal and Windows
    $PSStyle.Progress.UseOSCIndicator = $true
}
catch {}

<#
# This is required for the EKUs to work.
# Load all the DLLs in the PowerShell folder, providing .NET types for the module
# These types are required for the folder picker with multiple select options. Also the module manifest no longer handles assembly as it's not necessary anymore.
foreach ($Dll in (Convert-Path -Path ("$([psobject].Assembly.Location)\..\*.dll"))) {
    try {
        Add-Type -Path $Dll
    }
    catch {}
}
# Clear the Get-Error from Add-Type errors that are unnecessary
$Error.Clear()

#>
# Because we need it to construct Microsoft.Powershell.Commands.EnhancedKeyUsageProperty object for EKUs
Add-Type -AssemblyName 'Microsoft.PowerShell.Security'

# Import all C# codes at once so they will get compiled together, have resolved dependencies and recognize each others' classes/types
Add-Type -Path ([System.IO.Directory]::GetFiles("$PSScriptRoot\C#", '*.*', [System.IO.SearchOption]::AllDirectories)) -ReferencedAssemblies @(Get-Content -Path "$PSScriptRoot\.NETAssembliesToLoad.txt")

# Assign the value of the automatic variable $PSScriptRoot to the [WDACConfig.GlobalVars]::ModuleRootPath
[WDACConfig.GlobalVars]::ModuleRootPath = $PSScriptRoot

# Import the public global module
Import-Module -FullyQualifiedName ([System.IO.Directory]::GetFiles("$PSScriptRoot\Public", '*.*', [System.IO.SearchOption]::AllDirectories)) -Force -Global

[WDACConfig.Initializer]::Initialize()

[System.Management.Automation.ScriptBlock]$AppxNamesScriptBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)
    foreach ($AppName in (Get-AppxPackage -Name *$WordToComplete*)) {
        "`"$($AppName.Name)`""
    }
}
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'PackageName' -ScriptBlock $AppxNamesScriptBlock
Register-ArgumentCompleter -CommandName 'New-DenyWDACConfig' -ParameterName 'PackageName' -ScriptBlock $AppxNamesScriptBlock