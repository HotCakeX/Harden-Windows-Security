$global:ErrorActionPreference = 'Stop'
$PSStyle.Progress.UseOSCIndicator = $true
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'

if (!$IsWindows) {
    Throw [System.PlatformNotSupportedException] 'The Harden Windows Security module only runs on Windows operation systems.'
}

# Load all of the C# codes
Add-Type -Path ([System.IO.Directory]::GetFiles("$PSScriptRoot\C#")) -ReferencedAssemblies @(
    'System',
    'System.IO',
    'System.Collections',
    'System.Management',
    'System.Management.Automation',
    'System.Security',
    'System.Security.Principal',
    'System.ComponentModel.Primitives',
    'System.Linq',
    'System.Runtime.InteropServices',
    'System.Text.RegularExpressions',
    'System.Security.Principal.Windows',
    'System.Security.Claims',
    'Microsoft.Win32.Registry',
    'System.Net.Http',
    'System.Threading.Tasks',
    'System.Net.Primitives',
    'System.Net',
    'System.Windows',
    'PresentationFramework',
    "$($PSHOME)\WindowsBase.dll", # for some reason it tries to use another version of the dll unless i define its path explicitly like this
    'PresentationCore',
    'System.Threading',
    'System.Threading.Thread',
    'System.IO.Compression',
    'System.IO.Compression.zipfile',
    'System.Runtime',
    'System.Linq.Expressions'
)

[HardeningModule.GlobalVars]::Path = $PSScriptRoot
[HardeningModule.Initializer]::Initialize()
