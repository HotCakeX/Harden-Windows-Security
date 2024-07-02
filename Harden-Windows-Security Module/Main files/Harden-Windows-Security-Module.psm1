$global:ErrorActionPreference = 'Stop'

if (!$IsWindows) {
    Throw [System.PlatformNotSupportedException] 'The Harden Windows Security module only runs on Windows operation systems.'
}

# Load all of the C# codes
Add-Type -Path (Get-ChildItem -Filter '*.cs' -Path "$PSScriptRoot\Shared")

[HardeningModule.GlobalVars]::Path = $PSScriptRoot

# Make sure the current OS build is equal or greater than the required build number
if (-NOT ([System.Decimal]([HardeningModule.GlobalVars]::FullOSBuild) -ge [System.Decimal]([HardeningModule.GlobalVars]::Requiredbuild))) {
    Throw [System.PlatformNotSupportedException] "You are not using the latest build of the Windows OS. A minimum build of $([HardeningModule.GlobalVars]::Requiredbuild) is required but your OS build is $([HardeningModule.GlobalVars]::FullOSBuild)`nPlease go to Windows Update to install the updates and then try again."
}

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'
