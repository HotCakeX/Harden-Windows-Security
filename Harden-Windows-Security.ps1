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

    if ($PSVersionTable.PSEdition -eq 'Desktop') {

        if (!(Get-Command -Name 'pwsh.exe')) {
            try {
                Write-Verbose -Verbose -Message 'Trying to Install PowerShell Core using Winget because it could not be found' -Verbose
                $null = Winget install 9MZ1SNWT0N5D --accept-package-agreements --accept-source-agreements
            }
            catch {
                Write-Verbose -Verbose -Message 'Failed to Install PowerShell Core using Winget' -Verbose
                $progressPreference = 'silentlyContinue'
                Write-Verbose -Verbose -Message 'Downloading WinGet and its dependencies...' -Verbose
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

            Write-Verbose -Verbose -Message 'Trying to Install PowerShell Core using Winget again' -Verbose
            # https://apps.microsoft.com/detail/9mz1snwt0n5d
            $null = Winget install 9MZ1SNWT0N5D --accept-package-agreements --accept-source-agreements
        }
        else {
            Write-Verbose -Verbose -Message 'Trying to run the command in PowerShell Core'
            pwsh.exe -NoLogo -NoExit -Command {
                Install-Module -Name 'Harden-Windows-Security-Module' -Force
                Protect-WindowsSecurity
            }
        }
    }
    else {
        if (($PSVersionTable.PSVersion) -lt '7.4.2') {
            if ($PSHome -like '*\Program Files\WindowsApps\*') {
                throw 'Update PowerShell from Microsoft Store because you are using an older version'
            }
            else {
                throw "Install newer version of PowerShell and try again`nhttps://github.com/PowerShell/PowerShell/releases/latest"
            }
        }
        else {
            Write-Verbose -Verbose -Message 'Trying to run the command in PowerShell Core'
            pwsh.exe -NoLogo -NoExit -Command {
                Install-Module -Name 'Harden-Windows-Security-Module' -Force
                Protect-WindowsSecurity
            }
        }
    }
}

P