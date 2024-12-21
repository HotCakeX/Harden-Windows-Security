$global:ErrorActionPreference = 'Stop'

#Requires -RunAsAdministrator

# Unimportant actions that don't need to be terminating if they fail
try {
    # Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
    Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'
    # Enables additional progress indicators for Windows Terminal and Windows
    $PSStyle.Progress.UseOSCIndicator = $true
}
catch {}

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