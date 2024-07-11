Function P {
    [CmdletBinding()]
    param([switch]$G)
    begin {
        $ErrorActionPreference = 'Stop'
        Set-ExecutionPolicy -ExecutionPolicy 'Unrestricted' -Scope 'Process' -Force
        [System.Boolean]$WingetSourceUpdated = $false
        [System.Boolean]$PSInstalled = $false
        [System.Version]$RequiredPSVer = '7.4.2.0'
        [System.String]$PSDownloadURLMSIX = 'https://github.com/PowerShell/PowerShell/releases/download/v7.4.3/PowerShell-7.4.3-Win.msixbundle'
        $UserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $User = Get-LocalUser | Where-Object -FilterScript { $_.SID -eq $UserSID }

        Function Install-StoreSource {
            # https://apps.microsoft.com/detail/9mz1snwt0n5d
            Write-Verbose -Message 'Microsoft account detected, using Microsoft Store source for PowerShell installation through Winget'
            $null = Winget install --id 9MZ1SNWT0N5D --accept-package-agreements --accept-source-agreements --source msstore
        }
    }
    process {
        if ($PSVersionTable.PSEdition -eq 'Desktop') {
            if (!(Get-Command -Name 'pwsh.exe' -ErrorAction Ignore)) {
                try {
                    Write-Verbose -Message 'Trying to Install PowerShell Core using Winget because it could not be found on the system' -Verbose
                    Write-Verbose -Message 'Updating Winget source...'
                    $null = winget source update
                    $WingetSourceUpdated = $true

                    if ($User.PrincipalSource -eq 'MicrosoftAccount') {
                        Install-StoreSource
                    }
                    else {
                        Write-Verbose -Message 'Local account detected, cannot install PowerShell Core from Microsoft Store using Winget and msstore as the source'
                        Throw
                    }

                    if ($LASTEXITCODE -ne 0) {
                        Write-Verbose -Message "Failed to Install PowerShell Core using Winget: $LASTEXITCODE"
                        throw
                    }
                    $PSInstalled = $true
                }
                catch {
                    try {
                        try {
                            # Change location to temp because Windows PowerShell's default dir is System32 and if running as non-admin cannot be used for download location
                            Push-Location -Path ([System.IO.Path]::GetTempPath())

                            Write-Verbose -Message 'Failed to Install PowerShell Core using Winget' -Verbose

                            $ProgressPreference = 'silentlyContinue'
                            Write-Verbose -Message 'Downloading WinGet and its dependencies...'
                            # https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget-on-windows-sandbox
                            Invoke-WebRequest -Uri 'https://aka.ms/getwinget' -OutFile 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
                            Invoke-WebRequest -Uri 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx' -OutFile 'Microsoft.VCLibs.x64.14.00.Desktop.appx'
                            Invoke-WebRequest -Uri 'https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx' -OutFile 'Microsoft.UI.Xaml.2.8.x64.appx'

                            Add-AppxPackage -Path 'Microsoft.VCLibs.x64.14.00.Desktop.appx'
                            Add-AppxPackage -Path 'Microsoft.UI.Xaml.2.8.x64.appx'
                            Add-AppxPackage -Path 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
                        }
                        finally {
                            try {
                                Pop-Location
                                Remove-Item -Path 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle' -Force
                                Remove-Item -Path 'Microsoft.VCLibs.x64.14.00.Desktop.appx' -Force
                                Remove-Item -Path 'Microsoft.UI.Xaml.2.8.x64.appx' -Force
                            }
                            catch {}
                        }

                        Write-Verbose -Message 'Trying to Install PowerShell Core using Winget again after installing Winget' -Verbose

                        if (!$WingetSourceUpdated) {
                            Write-Verbose -Message 'Updating Winget source...'
                            $null = winget source update
                        }

                        if ($User.PrincipalSource -eq 'MicrosoftAccount') {
                            Install-StoreSource
                        }
                        else {
                            Write-Verbose -Message 'Local account detected, cannot install PowerShell Core from Microsoft Store using Winget and msstore as the source'
                            Throw
                        }
                        if ($LASTEXITCODE -ne 0) {
                            Write-Verbose -Message "Failed to Install PowerShell Core using Winget: $LASTEXITCODE"
                            throw
                        }
                        $PSInstalled = $true
                    }
                    catch {
                        try {
                            Push-Location -Path ([System.IO.Path]::GetTempPath())
                            Write-Verbose -Message 'Downloading and Installing PowerShell directly from GitHub using MSIX file'
                            Invoke-WebRequest -Uri $PSDownloadURLMSIX -OutFile 'PowerShell.msixbundle'
                            Add-AppxPackage -Path 'PowerShell.msixbundle'
                            $PSInstalled = $true
                        }
                        catch {
                            throw 'Failed to automatically Install PowerShell Core after exhausting all options'
                        }
                        finally {
                            try {
                                Remove-Item -Path 'PowerShell.msixbundle' -Force
                            }
                            catch {}
                            Pop-Location
                        }
                    }
                }
            }
            else {
                $PSInstalled = $true
            }
        }
        else {
            if (($PSVersionTable.PSVersion) -lt $RequiredPSVer) {
                Throw "Current PowerShell version is $($PSVersionTable.PSVersion), which is less than $RequiredPSVer. Please update it and try again."
            }
            else {
                $PSInstalled = $true
            }
        }
    }
    end {
        if ($PSInstalled) {
            Write-Verbose -Message 'Trying to run the command in PowerShell Core'
            pwsh.exe -NoLogo -NoExit -Command {
                Set-ExecutionPolicy -ExecutionPolicy 'Unrestricted' -Scope 'Process' -Force
                if (!(Get-Module -ListAvailable -Name 'Harden-Windows-Security-Module' -ErrorAction Ignore)) {
                    Write-Verbose -Message 'Installing the Harden Windows Security Module because it could not be found' -Verbose
                    Install-Module -Name 'Harden-Windows-Security-Module' -Force
                }
                Protect-WindowsSecurity -GUI
            }
        }
        else {
            throw 'Failed to automatically Install PowerShell Core after exhausting all options'
        }
    }
}
