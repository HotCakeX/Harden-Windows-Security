# Specifies that the WDACConfig module requires Administrator privileges
#Requires -RunAsAdministrator

# Create tamper resistant global variables (if they don't already exist)
try {
    if ((Test-Path -Path 'Variable:\MSFTRecommendeBlockRulesURL') -eq $false) { New-Variable -Name 'MSFTRecommendeBlockRulesURL' -Value 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac.md' -Option 'Constant' -Scope 'Global' -Description 'User Mode block rules' }
    if ((Test-Path -Path 'Variable:\MSFTRecommendeDriverBlockRulesURL') -eq $false) { New-Variable -Name 'MSFTRecommendeDriverBlockRulesURL' -Value 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md' -Option 'Constant' -Scope 'Global' -Description 'Kernel Mode block rules' }
    if ((Test-Path -Path 'Variable:\UserTempDirectoryPath') -eq $false) { New-Variable -Name 'UserTempDirectoryPath' -Value ([System.IO.Path]::GetTempPath()) -Option 'Constant' -Scope 'Global' -Description 'Fetching Temp Directory' }
}
catch {
    Throw 'Could not set the required global variables.'
}

# A constant variable that is automatically imported in the caller's environment and used to detect the main module's root directory
# Create it only if it's not already present, helps when user tries to import the module over and over again without closing the PowerShell session
try {
    Get-Variable -Name 'ModuleRootPath' -ErrorAction Stop | Out-Null
}
catch {
    New-Variable -Name 'ModuleRootPath' -Value ($PSScriptRoot) -Option 'Constant' -Scope 'Global'
}

# Minimum required OS build number
[System.Decimal]$Requiredbuild = '22621.2428'
# Get OS build version
[System.Decimal]$OSBuild = [System.Environment]::OSVersion.Version.Build
# Get Update Build Revision (UBR) number
[System.Decimal]$UBR = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR'
# Create full OS build number as seen in Windows Settings
[System.Decimal]$FullOSBuild = "$OSBuild.$UBR"
# Make sure the current OS build is equal or greater than the required build number
if (-NOT ($FullOSBuild -ge $Requiredbuild)) {
    Throw [System.PlatformNotSupportedException] "You are not using the latest build of the Windows OS. A minimum build of $Requiredbuild is required but your OS build is $FullOSBuild`nPlease go to Windows Update to install the updates and then try again."
}
