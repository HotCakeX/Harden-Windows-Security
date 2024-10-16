$script:ErrorActionPreference = 'Stop'
if (!$IsWindows) {
    Throw [System.PlatformNotSupportedException] 'The Harden Windows Security module only runs on Windows operation systems.'
}

function Update-HardenWindowsSecurity {
    <#
    .SYNOPSIS
        Make sure the latest version of the module is installed and if not, automatically update it, clean up any old versions
    .PARAMETER InvocationStatement
        The command that was used to invoke the main function/cmdlet that invoked the Update-HardenWindowsSecurity function, this is used to re-run the command after the module has been updated.
        It checks to make sure the Update-HardenWindowsSecurity function was called by an authorized command, that is one of the main cmdlets of the Harden-Windows-Security module, otherwise it will throw an error.
        The parameter also shouldn't contain any backtick or semicolon characters used to chain commands together.
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [AllowNull()]
        [ValidatePattern('^(Protect-WindowsSecurity|Unprotect-WindowsSecurity|Confirm-SystemCompliance)(?!.*[;`]).*$', ErrorMessage = 'Either Update-HardenWindowsSecurity function was called with an unauthorized command or it contains semicolon and/or backtick')]
        [System.String]$InvocationStatement
    )
    $script:ErrorActionPreference = 'Stop'

    # Get the current module's version
    [System.Version]$CurrentVersion = (Test-ModuleManifest -Path "$([HardenWindowsSecurity.GlobalVars]::Path)\Harden-Windows-Security-Module.psd1").Version

    # Get the latest version from GitHub
    [System.Version]$LatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/version.txt' -ProgressAction SilentlyContinue

    if ($CurrentVersion -lt $LatestVersion) {
        Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,105,180))The currently installed module's version is $CurrentVersion while the latest version is $LatestVersion - Auto Updating the module... 💓$($PSStyle.Reset)"

        # Only attempt to auto update the module if running as Admin, because Controlled Folder Access exclusion modification requires Admin privs
        if (-NOT ([HardenWindowsSecurity.UserPrivCheck]::IsAdmin())) {
            Throw 'There is a new update available, please run the cmdlet as Admin to update the module.'
        }

        Remove-Module -Name 'Harden-Windows-Security-Module' -Force -WarningAction SilentlyContinue

        try {
            [HardenWindowsSecurity.ControlledFolderAccessHandler]::Start()

            try {
                # Suppressing errors and warnings on this one because it can't uninstall the module currently in use even after Remove attempt earlier so it removes any leftover versions except for the one currently in use.
                Uninstall-Module -Name 'Harden-Windows-Security-Module' -AllVersions -Force -WarningAction SilentlyContinue -ErrorAction Ignore
            }
            catch {}

            Install-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force -ErrorAction Stop
            # Will not import the new module version in the current session. New version is automatically imported and used when the main cmdlet is run in a new session.
        }
        catch {
            throw
        }
        finally {
            [HardenWindowsSecurity.ControlledFolderAccessHandler]::reset()
        }

        Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(152,255,152))Update has been successful, running your command now$($PSStyle.Reset)"

        # Make sure the old version isn't run after update
        try {
            # Try to re-run the command that invoked the Update-HardenWindowsSecurity function in a new session after the module is updated.
            if ($null -ne $InvocationStatement) {
                pwsh.exe -NoProfile -NoLogo -NoExit -command $InvocationStatement
            }
            # This is for when user might invoke the function standalone
            else {
                pwsh.exe -NoProfile -NoLogo -NoExit
            }
        }
        catch {
            Throw 'Could not relaunch PowerShell after update. Please close and reopen PowerShell to run your command again.'
        }
    }
}

try {
    $PSStyle.Progress.UseOSCIndicator = $true
    # Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
    Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'
}
catch {}

$ToastNotificationDLLs = [System.Collections.Generic.List[System.String]]::new()
$ToastNotificationDLLs.Add([System.IO.Path]::Combine($PSScriptRoot, 'DLLs', 'Toast Notifications', 'Microsoft.Toolkit.Uwp.Notifications.dll'))
$ToastNotificationDLLs.Add([System.IO.Path]::Combine($PSScriptRoot, 'DLLs', 'Toast Notifications', 'Microsoft.Win32.SystemEvents.dll'))
$ToastNotificationDLLs.Add([System.IO.Path]::Combine($PSScriptRoot, 'DLLs', 'Toast Notifications', 'Microsoft.Windows.SDK.NET.dll'))
$ToastNotificationDLLs.Add([System.IO.Path]::Combine($PSScriptRoot, 'DLLs', 'Toast Notifications', 'System.Drawing.Common.dll'))
$ToastNotificationDLLs.Add([System.IO.Path]::Combine($PSScriptRoot, 'DLLs', 'Toast Notifications', 'WinRT.Runtime.dll'))

# Load all of the C# codes
# for some reason it tries to use another version of the WindowsBase.dll unless i define its path explicitly like this
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
try {
    [HardenWindowsSecurity.GlobalVars]::Host = $HOST
}
catch {
    [HardenWindowsSecurity.GlobalVars]::Host = $null
}
[HardenWindowsSecurity.GlobalVars]::path = $PSScriptRoot
