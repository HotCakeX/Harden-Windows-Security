Function P {
    <#
    .SYNOPSIS
        Effortlessly starts the hardening script on any system
        if necessary, installs PowerShell core using Winget from Microsoft Store
        If Winget is not present, Installs it along with its dependencies on the system
        Can start from Windows PowerShell too
    #>
    Param (
        [System.Management.Automation.SwitchParameter]$G
    )
    [System.Boolean]$CommandRan = $false
    if ($G) {
        [System.Management.Automation.ScriptBlock]$Command = {
            (Invoke-RestMethod 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Core/Protect-WindowsSecurity.psm1') + 'P -G' | Invoke-Expression
        }
    }
    else {
        [System.Management.Automation.ScriptBlock]$Command = {
            (Invoke-RestMethod 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Core/Protect-WindowsSecurity.psm1') + 'P' | Invoke-Expression
        }
    }
    Try {
        Write-Verbose -Verbose -Message 'Trying to run the command in PowerShell Core'
        pwsh.exe -NoLogo -NoExit -command $Command
        $CommandRan = $true
    }
    Catch {
        Write-Verbose -Verbose -Message 'Failed to run the command in PowerShell Core'
    }
    if (-NOT $CommandRan) {
        try {
            Write-Verbose -Verbose -Message 'Trying to Install PowerShell Core using Winget'
            Winget install 9MZ1SNWT0N5D --accept-package-agreements --accept-source-agreements | Out-Null
        }
        catch {
            Write-Verbose -Verbose -Message 'Failed to Install PowerShell Core using Winget'
            $progressPreference = 'silentlyContinue'
            Write-Verbose -Verbose -Message 'Downloading WinGet and its dependencies...'
            # https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget-on-windows-sandbox
            Invoke-WebRequest -Uri 'https://aka.ms/getwinget' -OutFile 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
            Invoke-WebRequest -Uri 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx' -OutFile 'Microsoft.VCLibs.x64.14.00.Desktop.appx'
            Invoke-WebRequest -Uri 'https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx' -OutFile 'Microsoft.UI.Xaml.2.8.x64.appx'

            Add-AppxPackage -Path 'Microsoft.VCLibs.x64.14.00.Desktop.appx'
            Add-AppxPackage -Path 'Microsoft.UI.Xaml.2.8.x64.appx'
            Add-AppxPackage -Path 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'

            Remove-Item -Path 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle' -Force
            Remove-Item -Path 'Microsoft.VCLibs.x64.14.00.Desktop.appx' -Force
            Remove-Item -Path 'Microsoft.UI.Xaml.2.8.x64.appx' -Force
        }
    }
    Write-Verbose -Verbose -Message 'Trying to Install PowerShell Core using Winget'
    # https://apps.microsoft.com/detail/9mz1snwt0n5d
    Winget install 9MZ1SNWT0N5D --accept-package-agreements --accept-source-agreements | Out-Null

    Write-Verbose -Verbose -Message 'Trying to run the command in PowerShell Core'
    pwsh.exe -NoLogo -NoExit -command $Command
}
