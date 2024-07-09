$global:ErrorActionPreference = 'Stop'
$PSStyle.Progress.UseOSCIndicator = $true
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'

if (!$IsWindows) {
    Throw [System.PlatformNotSupportedException] 'The Harden Windows Security module only runs on Windows operation systems.'
}

# Load all of the C# codes
# for some reason it tries to use another version of the dll unless i define its path explicitly like this
Add-Type -Path ([System.IO.Directory]::GetFiles("$PSScriptRoot\C#")) -ReferencedAssemblies @((Get-Content -Path "$PSScriptRoot\.NETAssembliesToLoad.txt") + "$($PSHOME)\WindowsBase.dll")

[HardeningModule.GlobalVars]::Path = $PSScriptRoot
[HardeningModule.Initializer]::Initialize()
