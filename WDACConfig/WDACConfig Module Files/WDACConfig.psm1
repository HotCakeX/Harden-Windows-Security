<# -------- Guidance for code readers --------
The module uses tight import/export control, no internal function is exposed on the console/to the user.
The $PSDefaultParameterValues located in "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1" is imported via dot-sourcing to the current session of each main cmdlet/internal function that calls any (other) internal function or uses any of the cmdlets defined in that file, prior to everything else.
At the beginning of each main cmdlet, 2 custom $Verbose and/or $Debug variables are defined which help to take actions based on Verbose/Debug preferences and also pass the $VerbosePreference and $DebugPreference to the subsequent sub-functions/modules being called from the main cmdlets.

E.g.,

this captures the $Debug preference from the command line:
[System.Boolean]$Debug = $PSBoundParameters.Debug.IsPresent ? $true : $false

Then in the PSDefaultParameterValues.ps1 file, there is 'Do-Something:Debug' = $Debug

So that essentially means any instance of 'Do-Something' cmdlet in the code is actually 'Do-Something -Debug:$Debug'
#>


<#
Load order of the WDACConfig module

1. ScriptsToProcess defined in the manifest
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
    'Microsoft.Win32.registry',
    'System.Management.Automation',
    'System.Text.Json',
    'System.Diagnostics.Process',
    'System.ComponentModel.Primitives',
    'System.Memory',
    'System.Linq')

# Assign the value of the automatic variable $PSScriptRoot to the [WDACConfig.GlobalVars]::ModuleRootPath
[WDACConfig.GlobalVars]::ModuleRootPath = $PSScriptRoot

# Importing argument completer ScriptBlocks
. "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\ArgumentCompleters.ps1"

# Make sure the current OS build is equal or greater than the required build number
if (-NOT ([System.Decimal]([WDACConfig.GlobalVars]::FullOSBuild) -ge [System.Decimal]([WDACConfig.GlobalVars]::Requiredbuild))) {
    Throw [System.PlatformNotSupportedException] "You are not using the latest build of the Windows OS. A minimum build of $([WDACConfig.GlobalVars]::Requiredbuild) is required but your OS build is $([WDACConfig.GlobalVars]::FullOSBuild)`nPlease go to Windows Update to install the updates and then try again."
}

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'

# Enables additional progress indicators for Windows Terminal and Windows
$PSStyle.Progress.UseOSCIndicator = $true

# Import the public global module
Import-Module -FullyQualifiedName ("$([WDACConfig.GlobalVars]::ModuleRootPath)\Public\Write-FinalOutput.psm1", "$([WDACConfig.GlobalVars]::ModuleRootPath)\Public\MockConfigCIBootstrap.psm1") -Force -Global

#Region Argument Completer Registrations

Register-ArgumentCompleter -CommandName 'ConvertTo-WDACPolicy' -ParameterName 'PolicyToAddLogsTo' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'ConvertTo-WDACPolicy' -ParameterName 'BasePolicyFile' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)

Register-ArgumentCompleter -CommandName 'Deploy-SignedWDACConfig' -ParameterName 'PolicyPaths' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterMultipleXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Deploy-SignedWDACConfig' -ParameterName 'CertPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterCerFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Deploy-SignedWDACConfig' -ParameterName 'SignToolPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterExeFilePathsPicker)

Register-ArgumentCompleter -CommandName 'Edit-SignedWDACConfig' -ParameterName 'CertPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterCerFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Edit-SignedWDACConfig' -ParameterName 'SignToolPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterExeFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Edit-SignedWDACConfig' -ParameterName 'PolicyPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Edit-SignedWDACConfig' -ParameterName 'SuppPolicyPaths' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterMultipleXmlFilePathsPicker)

Register-ArgumentCompleter -CommandName 'Edit-WDACConfig' -ParameterName 'PolicyPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Edit-WDACConfig' -ParameterName 'SuppPolicyPaths' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterMultipleXmlFilePathsPicker)

Register-ArgumentCompleter -CommandName 'Get-CiFileHashes' -ParameterName 'FilePath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterAnyFilePathsPicker)

Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'FolderPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterFolderPathsPicker)
Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'CatRootPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterFolderPathsPicker)
Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'XmlFilePath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'FilePath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterMultipleAnyFilePathsPicker)

Register-ArgumentCompleter -CommandName 'Test-CiPolicy' -ParameterName 'XmlFile' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Test-CiPolicy' -ParameterName 'CipFile' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterAnyFilePathsPicker)

Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'CertPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterCerFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'SignToolPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterExeFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'SignedPolicyPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'UnsignedPolicyPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)

Register-ArgumentCompleter -CommandName 'Remove-WDACConfig' -ParameterName 'PolicyPaths' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterMultipleXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Remove-WDACConfig' -ParameterName 'SignToolPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterExeFilePathsPicker)

Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'PolicyPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'PackageName' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterAppxPackageNames)
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'ScanLocation' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterFolderPathsPicker)
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'FolderPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterFolderPathsPickerWildCards)
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'CertificatePaths' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterCerFilesPathsPicker)

Register-ArgumentCompleter -CommandName 'New-DenyWDACConfig' -ParameterName 'ScanLocations' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterFolderPathsPicker)
Register-ArgumentCompleter -CommandName 'New-DenyWDACConfig' -ParameterName 'PackageName' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterAppxPackageNames)
Register-ArgumentCompleter -CommandName 'New-DenyWDACConfig' -ParameterName 'FolderPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterFolderPathsPickerWildCards)

Register-ArgumentCompleter -CommandName 'Set-CiRuleOptions' -ParameterName 'FilePath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Set-CiRuleOptions' -ParameterName 'RulesToAdd' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterPolicyRuleOptions)
Register-ArgumentCompleter -CommandName 'Set-CiRuleOptions' -ParameterName 'RulesToRemove' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterPolicyRuleOptions)

#Endregion Argument Completer Registrations
