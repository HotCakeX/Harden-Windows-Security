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

# Set-ConstantVariable -Name 'UserAccountDirectoryPath' -Value ((Get-CimInstance Win32_UserProfile -Filter "SID = '$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)'").LocalPath) -Option 'Constant' -Scope 'Script' -Description 'Securely retrieved User profile directory'

# This is required for the EKUs to work.
# Load all the DLLs in the PowerShell folder, providing .NET types for the module
# These types are required for the folder picker with multiple select options. Also the module manifest no longer handles assembly as it's not necessary anymore.
foreach ($Dll in (Convert-Path -Path ("$([psobject].Assembly.Location)\..\*.dll"))) {
    try {
        Add-Type -Path $Dll
    }
    catch {}
}

# Import all C# codes at once so they will get compiled together, have resolved dependencies and recognize each others' classes/types
Add-Type -Path (Get-ChildItem -File -Recurse -Path "$PSScriptRoot\C#").FullName -ReferencedAssemblies ('System',
    'System.Security.Cryptography.Pkcs',
    'System.Security.Cryptography.X509Certificates',
    'System.Security.Cryptography',
    'System.Xml',
    'System.Formats.Asn1',
    'System.IO',
    'System.Runtime.InteropServices',
    'System.Collections',
    'System.Xml.ReaderWriter',
    'System.Collections.NonGeneric',
    'System.Management',
    'System.Globalization',
    'Microsoft.Win32.registry')

# Assign the value of the automatic variable $PSScriptRoot to the [WDACConfig.GlobalVars]::ModuleRootPath
[WDACConfig.GlobalVars]::ModuleRootPath = $PSScriptRoot

# Importing argument completer ScriptBlocks
. "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\ArgumentCompleters.ps1"

# Make sure the current OS build is equal or greater than the required build number
if (-NOT ([System.Decimal]([WDACConfig.GlobalVars]::FullOSBuild) -ge [System.Decimal]([WDACConfig.GlobalVars]::Requiredbuild))) {
    Throw [System.PlatformNotSupportedException] "You are not using the latest build of the Windows OS. A minimum build of $([WDACConfig.GlobalVars]::Requiredbuild) is required but your OS build is $([WDACConfig.GlobalVars]::FullOSBuild)`nPlease go to Windows Update to install the updates and then try again."
}
