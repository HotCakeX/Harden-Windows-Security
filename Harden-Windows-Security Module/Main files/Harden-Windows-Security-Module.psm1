$global:ErrorActionPreference = 'Stop'
$PSStyle.Progress.UseOSCIndicator = $true
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'

if (!$IsWindows) {
    Throw [System.PlatformNotSupportedException] 'The Harden Windows Security module only runs on Windows operation systems.'
}

# Load all of the C# codes
# for some reason it tries to use another version of the dll unless i define its path explicitly like this
Add-Type -Path ([System.IO.Directory]::GetFiles("$PSScriptRoot\C#", '*.*', [System.IO.SearchOption]::AllDirectories)) -ReferencedAssemblies @((Get-Content -Path "$PSScriptRoot\.NETAssembliesToLoad.txt") + "$($PSHOME)\WindowsBase.dll")

[HardenWindowsSecurity.GlobalVars]::Host = $HOST
[HardenWindowsSecurity.GlobalVars]::PSHOME = $PSHOME
[HardenWindowsSecurity.GlobalVars]::path = $PSScriptRoot
# Save the valid values of the Protect-WindowsSecurity categories to a variable since the process can be time consuming and shouldn't happen every time the categories are fetched
[HardenWindowsSecurity.GlobalVars]::HardeningCategorieX = [HardenWindowsSecurity.ProtectionCategoriex]::GetValidValues()
