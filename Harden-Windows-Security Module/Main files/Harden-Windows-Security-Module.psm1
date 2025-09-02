$script:ErrorActionPreference = 'Stop'
if (!$IsWindows) { Throw [System.PlatformNotSupportedException] 'The Harden Windows Security module only runs on Windows operation systems.' }
try {
    $PSStyle.Progress.UseOSCIndicator = $true
    # Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
    Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'
}
catch {}

[System.String[]]$DLLsToLoad = [System.IO.Directory]::GetFiles("$PSScriptRoot\DLLs", '*.dll', [System.IO.SearchOption]::TopDirectoryOnly)

# Let the compilation begin - For some reason PowerShell tries to use another version of the WindowsBase.dll unless i define its path explicitly like this
# https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/
Add-Type -Path ([System.IO.Directory]::GetFiles("$PSScriptRoot\C#", '*.*', [System.IO.SearchOption]::AllDirectories)) -ReferencedAssemblies @((Get-Content -Path "$PSScriptRoot\.NETAssembliesToLoad.txt") + "$($PSHOME)\WindowsBase.dll" + $DLLsToLoad) -CompilerOptions '/langversion:preview', '/nowarn:1701,WPF0001', '/nullable:enable', '/checked'

Function LoadHardenWindowsSecurityNecessaryDLLsInternal {
    # Do not reload the required DLLs if they have been already loaded
    if ([HardenWindowsSecurity.GlobalVars]::RequiredDLLsLoaded) { return }
    # when we use the -ReferencedAssemblies parameter of Add-Type, The DLLs are only added and made available to the C# compilation, not the PowerShell host itself
    # In order to display the toast notifications and other codes that rely on them, they needed to be added to the PowerShell itself as well
    foreach ($DLLPath in $DLLsToLoad) { Add-Type -Path $DLLPath }
    [HardenWindowsSecurity.GlobalVars]::RequiredDLLsLoaded = $true # Set that DLLs have been loaded
}
try { [HardenWindowsSecurity.GlobalVars]::Host = $HOST } catch { [HardenWindowsSecurity.GlobalVars]::Host = $null }
[HardenWindowsSecurity.GlobalVars]::path = $PSScriptRoot
Function ReRunTheModuleAgain($C) { pwsh.exe -NoProfile -NoLogo -NoExit -command $C }