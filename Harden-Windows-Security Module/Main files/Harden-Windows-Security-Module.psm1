$global:ErrorActionPreference = 'Stop'

if (!$IsWindows) {
    Throw [System.PlatformNotSupportedException] 'The Harden Windows Security module only runs on Windows operation systems.'
}

# Create tamper resistant global variables (if they don't already exist)
try {
    if ((Test-Path -Path 'Variable:\RequiredbuildHardeningModule') -eq $false) { New-Variable -Name 'RequiredbuildHardeningModule' -Value '22621.3155' -Option 'Constant' -Scope 'Script' -Description 'Minimum required OS build number' -Force }
    if ((Test-Path -Path 'Variable:\OSBuild') -eq $false) { New-Variable -Name 'OSBuild' -Value ([System.Environment]::OSVersion.Version.Build) -Option 'Constant' -Scope 'Script' -Description 'Current OS build version' -Force }
    if ((Test-Path -Path 'Variable:\UBR') -eq $false) { New-Variable -Name 'UBR' -Value (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR') -Option 'Constant' -Scope 'Script' -Description 'Update Build Revision (UBR) number' -Force }
    if ((Test-Path -Path 'Variable:\FullOSBuild') -eq $false) { New-Variable -Name 'FullOSBuild' -Value "$OSBuild.$UBR" -Option 'Constant' -Scope 'Script' -Description 'Create full OS build number as seen in Windows Settings' -Force }
}
catch {
    Throw [System.InvalidOperationException] 'Could not set the required global variables.'
}

# Make sure the current OS build is equal or greater than the required build number
if (-NOT ([System.Decimal]$FullOSBuild -ge [System.Decimal]$RequiredbuildHardeningModule)) {
    Throw [System.PlatformNotSupportedException] "You are not using the latest build of the Windows OS. A minimum build of $RequiredbuildHardeningModule is required but your OS build is $FullOSBuild`nPlease go to Windows Update to install the updates and then try again."
}

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'

Add-Type -Path ("$PSScriptRoot\Shared\UserPrivCheck.cs",
    "$PSScriptRoot\Shared\SystemInfoNativeMethods.cs",
    "$PSScriptRoot\Shared\IndividualResultClass.cs",
    "$PSScriptRoot\Shared\GlobalVars.cs")

[HardeningModule.GlobalVars]::Path = $PSScriptRoot
