<#
Load order of the WDACConfig module

1. The Preloader.ps1 file (aka ScriptsToProcess defined in the manifest)
2. All Individual sub-modules (All psm1 files defined in the NestedModules array in the manifest)
3. The WDACConfig.psm1 (aka RootModule defined in the manifest)
4. The cmdlet that the user invoked on the command line, if any.
#>

# Stopping the module process if any error occurs
$global:ErrorActionPreference = 'Stop'

if (!$IsWindows) {
    Throw [System.PlatformNotSupportedException] 'The WDACConfig module only runs on Windows operation systems.'
}

# Specifies that the WDACConfig module requires Administrator privileges
#Requires -RunAsAdministrator

function Set-ConstantVariable {
    <#
    .SYNOPSIS
        Performs precise check to ensure that a global variable is not already pre-defined with a potentially malicious value.
        Even a single space change in the value of the variable will be detected.
    #>
    param (
        [System.String]$Name,
        $Value,
        [System.String]$Description,
        [System.String]$Option,
        [System.String]$Scope
    )
    if ((Test-Path -Path "Variable:\$Name") -eq $true) {
        $ExistingValue = [System.String]$(Get-Variable -Name $Name -Scope Global -ValueOnly)
        if ($ExistingValue -ne $Value) {
            throw "Variable '$Name' already exists with a different value: ($ExistingValue). For security reasons, cannot continue the operation. Please close and reopen the PowerShell session and try again."
        }
    }
    else {
        try {
            New-Variable -Name $Name -Value $Value -Option $Option -Scope $Scope -Description $Description -Force
        }
        catch {
            Throw [System.InvalidOperationException] "Could not set the required global variable: $Name"
        }
    }
}

# Create tamper resistant global/script variables (if they don't already exist) - They are automatically imported in the caller's environment
Set-ConstantVariable -Name 'MSFTRecommendedBlockRulesURL' -Value 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac.md' -Option 'Constant' -Scope 'Global' -Description 'User Mode block rules'
Set-ConstantVariable -Name 'MSFTRecommendedDriverBlockRulesURL' -Value 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md' -Option 'Constant' -Scope 'Global' -Description 'Kernel Mode block rules'
# Set-ConstantVariable -Name 'UserAccountDirectoryPath' -Value ((Get-CimInstance Win32_UserProfile -Filter "SID = '$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)'").LocalPath) -Option 'Constant' -Scope 'Script' -Description 'Securely retrieved User profile directory'
Set-ConstantVariable -Name 'Requiredbuild' -Value '22621.3447' -Option 'Constant' -Scope 'Script' -Description 'Minimum required OS build number'
Set-ConstantVariable -Name 'OSBuild' -Value ([System.Environment]::OSVersion.Version.Build) -Option 'Constant' -Scope 'Script' -Description 'Current OS build version'
Set-ConstantVariable -Name 'UBR' -Value (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR') -Option 'Constant' -Scope 'Script' -Description 'Update Build Revision (UBR) number'
Set-ConstantVariable -Name 'FullOSBuild' -Value "$OSBuild.$UBR" -Option 'Constant' -Scope 'Script' -Description 'Create full OS build number as seen in Windows Settings'
Set-ConstantVariable -Name 'ModuleRootPath' -Value ($PSScriptRoot) -Option 'Constant' -Scope 'Global' -Description 'Storing the value of $PSScriptRoot in a global constant variable to allow the internal functions to use it when navigating the module structure'
Set-ConstantVariable -Name 'CISchemaPath' -Value "$Env:SystemDrive\Windows\schemas\CodeIntegrity\cipolicy.xsd" -Option 'Constant' -Scope 'Global' -Description 'Storing the path to the WDAC Code Integrity Schema XSD file'
Set-ConstantVariable -Name 'UserConfigDir' -Value "$Env:ProgramFiles\WDACConfig" -Option 'Constant' -Scope 'Global' -Description 'Storing the path to the WDACConfig folder in the Program Files'
Set-ConstantVariable -Name 'UserConfigJson' -Value "$UserConfigDir\UserConfigurations\UserConfigurations.json" -Option 'Constant' -Scope 'Global' -Description 'Storing the path to User Config JSON file in the WDACConfig folder in the Program Files'

# Make sure the current OS build is equal or greater than the required build number
if (-NOT ([System.Decimal]$FullOSBuild -ge [System.Decimal]$Requiredbuild)) {
    Throw [System.PlatformNotSupportedException] "You are not using the latest build of the Windows OS. A minimum build of $Requiredbuild is required but your OS build is $FullOSBuild`nPlease go to Windows Update to install the updates and then try again."
}

# Import the ArgumentCompleters class which will introduce App-Domain-Wide variables to the session
if (-NOT ('WDACConfig.ArgumentCompleters' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\ArgumentCompleters.cs"
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\CoreExt\ArgumentCompleters.ps1"
