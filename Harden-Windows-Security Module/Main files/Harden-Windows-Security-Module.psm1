$script:ErrorActionPreference = 'Stop'

try {
    $PSStyle.Progress.UseOSCIndicator = $true
    # Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
    Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'
}
catch {}

if (!$IsWindows) {
    Throw [System.PlatformNotSupportedException] 'The Harden Windows Security module only runs on Windows operation systems.'
}

$ToastNotificationDLLs = [System.Collections.Generic.List[System.String]]::new()
$ToastNotificationDLLs.Add([System.IO.Path]::Combine($PSScriptRoot, 'DLLs', 'Toast Notifications', 'Microsoft.Toolkit.Uwp.Notifications.dll'))
$ToastNotificationDLLs.Add([System.IO.Path]::Combine($PSScriptRoot, 'DLLs', 'Toast Notifications', 'Microsoft.Win32.SystemEvents.dll'))
$ToastNotificationDLLs.Add([System.IO.Path]::Combine($PSScriptRoot, 'DLLs', 'Toast Notifications', 'Microsoft.Windows.SDK.NET.dll'))
$ToastNotificationDLLs.Add([System.IO.Path]::Combine($PSScriptRoot, 'DLLs', 'Toast Notifications', 'System.Drawing.Common.dll'))
$ToastNotificationDLLs.Add([System.IO.Path]::Combine($PSScriptRoot, 'DLLs', 'Toast Notifications', 'WinRT.Runtime.dll'))

# Load all of the C# codes
# for some reason it tries to use another version of the dll unless i define its path explicitly like this
Add-Type -Path ([System.IO.Directory]::GetFiles("$PSScriptRoot\C#", '*.*', [System.IO.SearchOption]::AllDirectories)) -ReferencedAssemblies @((Get-Content -Path "$PSScriptRoot\.NETAssembliesToLoad.txt") + "$($PSHOME)\WindowsBase.dll" + $ToastNotificationDLLs) -CompilerOptions '/nowarn:1701'

try {
    # when we use the -ReferencedAssemblies parameter of Add-Type, The DLLs are only added and made available to the C# compilation, not the PowerShell host itself
    # In order to display the toast notifications, they needed to be added to the PowerShell itself as well
    foreach ($DLLPath in $ToastNotificationDLLs) {
        Add-Type -Path $DLLPath
    }
}
catch {
    [HardenWindowsSecurity.GlobalVars]::UseNewNotificationsExp = $false
}
[HardenWindowsSecurity.GlobalVars]::Host = $HOST
[HardenWindowsSecurity.GlobalVars]::path = $PSScriptRoot
