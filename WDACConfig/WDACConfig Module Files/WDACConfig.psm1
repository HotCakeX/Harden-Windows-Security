<# -------- Guidance for code readers --------
The module uses tight import/export control, no internal function is exposed on the console/to the user.
The $PSDefaultParameterValues located in "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1" is imported via dot-sourcing to the current session of each main cmdlet/internal function that calls any (other) internal function or uses any of the cmdlets defined in that file, prior to everything else.
At the beginning of each main cmdlet, 2 custom $Verbose and/or $Debug variables are defined which help to take actions based on Verbose/Debug preferences and also pass the $VerbosePreference and $DebugPreference to the subsequent sub-functions/modules being called from the main cmdlets.

E.g.,

this captures the $Debug preference from the command line:
[System.Boolean]$Debug = $PSBoundParameters.Debug.IsPresent ? $true : $false

Then in the PSDefaultParameterValues.ps1 file, there is 'Do-Something:Debug' = $Debug
So that essentially means any instance of 'Do-Something' cmdlet in the code is actually 'Do-Something -Debug:$Debug'

Load order of the WDACConfig module:

1. ScriptsToProcess defined in the manifest
2. All Individual sub-modules (All psm1 files defined in the NestedModules array in the manifest)
3. The WDACConfig.psm1 (aka RootModule defined in the manifest)
4. The cmdlet that the user invoked on the command line, if any.
#>

# Stopping the module process if any error occurs
$global:ErrorActionPreference = 'Stop'

if (!$IsWindows) {
    Throw [System.PlatformNotSupportedException] 'The WDACConfig module only runs on Windows operation systems. Download it from here: https://www.microsoft.com/software-download/windows11'
}

# Specifies that the WDACConfig module requires Administrator privileges
#Requires -RunAsAdministrator

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

# Import all C# codes at once so they will get compiled together, have resolved dependencies and recognize each others' classes/types
Add-Type -Path ([System.IO.Directory]::GetFiles("$PSScriptRoot\C#", '*.*', [System.IO.SearchOption]::AllDirectories)) -ReferencedAssemblies @(Get-Content -Path "$PSScriptRoot\.NETAssembliesToLoad.txt")

# Assign the value of the automatic variable $PSScriptRoot to the [WDACConfig.GlobalVars]::ModuleRootPath
[WDACConfig.GlobalVars]::ModuleRootPath = $PSScriptRoot

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'

# Enables additional progress indicators for Windows Terminal and Windows
$PSStyle.Progress.UseOSCIndicator = $true

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
