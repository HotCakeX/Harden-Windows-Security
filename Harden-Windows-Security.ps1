Function P {
    <#
    .SYNOPSIS
        Effortlessly starts the Harden Windows Security module on any system
        if necessary, installs PowerShell core using Winget from Microsoft Store
        If Winget is not present, Installs it along with its dependencies on the system
        Can start from Windows PowerShell too
    #>
    Param (
        [System.Management.Automation.SwitchParameter]$G
    )

    Set-ExecutionPolicy -ExecutionPolicy 'Unrestricted' -Scope 'Process' -Force

    if ($PSVersionTable.PSEdition -eq 'Desktop') {

        if (!(Get-Command -Name 'pwsh.exe' -ErrorAction Ignore)) {
            try {
                Write-Verbose -Message 'Trying to Install PowerShell Core using Winget because it could not be found' -Verbose
                $null = Winget install 9MZ1SNWT0N5D --accept-package-agreements --accept-source-agreements
            }
            catch {

                # Change location to temp because Windows PowerShell's default dir is System32 and if running as non-admin cannot be used for download location
                Push-Location -Path ([System.IO.Path]::GetTempPath())

                Write-Verbose -Message 'Failed to Install PowerShell Core using Winget' -Verbose
                $progressPreference = 'silentlyContinue'
                Write-Verbose -Message 'Downloading WinGet and its dependencies...' -Verbose
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

                Pop-Location

                Write-Verbose -Message 'Trying to Install PowerShell Core using Winget again' -Verbose
                # https://apps.microsoft.com/detail/9mz1snwt0n5d
                $null = Winget install 9MZ1SNWT0N5D --accept-package-agreements --accept-source-agreements
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
    }

    Write-Verbose -Message 'Trying to run the command in PowerShell Core'
    if ($G) {
        pwsh.exe -NoLogo -NoExit -Command {
            Set-ExecutionPolicy -ExecutionPolicy 'Unrestricted' -Scope 'Process' -Force
            if (!(Get-Module -ListAvailable -Name 'Harden-Windows-Security-Module' -ErrorAction Ignore)) {
                Write-Verbose -Message 'Installing the Harden Windows Security Module because it could not be found'
                Install-Module -Name 'Harden-Windows-Security-Module' -Force
            }
            Protect-WindowsSecurity -GUI
        }
    }
    else {
        pwsh.exe -NoLogo -NoExit -Command {
            Set-ExecutionPolicy -ExecutionPolicy 'Unrestricted' -Scope 'Process' -Force
            if (!(Get-Module -ListAvailable -Name 'Harden-Windows-Security-Module' -ErrorAction Ignore)) {
                Write-Verbose -Message 'Installing the Harden Windows Security Module because it could not be found'
                Install-Module -Name 'Harden-Windows-Security-Module' -Force
            }
            Protect-WindowsSecurity
        }
    }
}
