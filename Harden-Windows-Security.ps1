#Requires -Version 5.1
Function P {
    [CmdletBinding()]
    param([switch]$G)
    begin {
        $ErrorActionPreference = 'Stop'
        Set-ExecutionPolicy -ExecutionPolicy 'Unrestricted' -Scope 'Process' -Force
        [System.Boolean]$WingetSourceUpdated = $false
        [System.Boolean]$PSInstalled = $false
        [System.Version]$RequiredPSVer = '7.4.2.0'
        [System.String]$PSDownloadURLMSIX = 'https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/PowerShell-7.4.6-win.msixbundle'
        [System.String]$MicrosoftUIXamlDownloadedFileName = 'Microsoft.UI.Xaml.2.8.appx'

        if ($Env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
            Write-Verbose -Message 'ARM64 architecture detected, using ARM64 version of Microsoft.UI.Xaml.2.8.appx'
            [System.String]$MicrosoftUIXamlDownloadLink = 'https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.arm64.appx'
        }
        else {
            Write-Verbose -Message 'x64 architecture detected, using x64 version of Microsoft.UI.Xaml.2.8.appx'
            [System.String]$MicrosoftUIXamlDownloadLink = 'https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx'
        }

        [System.String]$UserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
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
                            Invoke-WebRequest -Uri $MicrosoftUIXamlDownloadLink -OutFile $MicrosoftUIXamlDownloadedFileName

                            Add-AppxPackage -Path 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle' -DependencyPath 'Microsoft.VCLibs.x64.14.00.Desktop.appx', $MicrosoftUIXamlDownloadedFileName
                        }
                        finally {
                            try {
                                Remove-Item -Path 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle', 'Microsoft.VCLibs.x64.14.00.Desktop.appx', $MicrosoftUIXamlDownloadedFileName -Force
                                Pop-Location
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
            pwsh.exe -NoProfile -NoLogo -NoExit -Command {
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
Function AppControl {
    <#
    .DESCRIPTION
        Please refer to the provided link for all of the information about this function and detailed overview of the entire process.
    .PARAMETER MSIXPath
        The path to the AppControlManager MSIX file. If not provided, the latest MSIX file will be downloaded from the GitHub. It must have the version number and architecture in its file name as provided on GitHub or produced by Visual Studio.
    .PARAMETER SignTool
        Optional. The path to the Microsoft's Signtool.exe
        If not provided, the function automatically downloads the latest SignTool.exe from the Microsoft website in Nuget and will use it for the signing operations.
    .LINK
        https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)][System.String]$MSIXPath,
        [Parameter(Mandatory = $False)][System.String]$SignTool
    )
    $ErrorActionPreference = 'Stop'
    if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning -Message 'Please run this function as an Administrator'; return
    }
    Write-Verbose -Message 'Detecting the CPU Arch'
    switch ($Env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { [System.String]$CPUArch = 'x64'; break }
        'ARM64' { [System.String]$CPUArch = 'arm64'; break }
        default { Throw [System.PlatformNotSupportedException] 'Only AMD64 and ARM64 architectures are supported.' }
    }

    # Used to generate a SecureString, adding the class only if it hasn't already been added to the session - Better version of the random number generator would require PowerShell core/.NET
    if (!([System.Management.Automation.PSTypeName]'SecureStringGenerator').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Security;
public static class SecureStringGenerator
{
    private static readonly char[] allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray();
    private static readonly Random random = new Random();
    public static SecureString GenerateSecureString(int length)
    {
        SecureString secureString = new SecureString();
        for (int i = 0; i < length; i++)
        {
            char randomChar = allowedChars[random.Next(allowedChars.Length)];
            secureString.AppendChar(randomChar);
        }
        secureString.MakeReadOnly();
        return secureString;
    }
}
'@ -Language CSharp
    }
    [System.String]$CommonName = 'SelfSignedCertForAppControlManager'
    [System.String]$WorkingDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $CommonName)
    [System.String]$CertificateOutputPath = [System.IO.Path]::Combine($WorkingDir, "$CommonName.cer")
    [System.String]$PFXCertificateOutputPath = [System.IO.Path]::Combine($WorkingDir, "$CommonName.pfx")
    [System.Security.SecureString]$PassWord = [SecureStringGenerator]::GenerateSecureString(100) # Generate a random 100 characters password that will be used to encrypt the temporary PFX file.
    [System.String]$HashingAlgorithm = 'Sha512'

    # Pattern for AppControl Manager version and architecture extraction from file path and download link URL
    [regex]$RegexPattern = '_(?<Version>\d+\.\d+\.\d+\.\d+)_(?<Architecture>x64|arm64)\.msix$'

    # Download link for the latest version of AppControl manger is retrieved from this text file
    [System.String]$MSIXPackageDownloadURL = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/AppControl%20Manager/DownloadURL.txt'

    Write-Verbose -Message 'Creating the working directory in the TEMP directory'
    if ([System.IO.Directory]::Exists($WorkingDir)) {
        [System.IO.Directory]::Delete($WorkingDir, $true)
    }
    $null = [System.IO.Directory]::CreateDirectory($WorkingDir)

    try {
        Write-Verbose -Message "Checking if a certificate with the common name '$CommonName' already exists."
        [System.String[]]$CertStoresToCheck = @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\CA', 'Cert:\LocalMachine\TrustedPublisher', 'Cert:\CurrentUser\My', 'Cert:\CurrentUser\Root', 'Cert:\CurrentUser\CA', 'Cert:\CurrentUser\TrustedPublisher')
        foreach ($Store in $CertStoresToCheck) {
            foreach ($Item in (Get-ChildItem -Path $Store)) {
                if ($Item.Subject -ieq "CN=$CommonName") {
                    Write-Verbose -Message "A certificate with the common name '$CommonName' in the store '$Store' already exists. Removing it."
                    $Item | Remove-Item -Force
                }
            }
        }

        Write-Verbose -Message 'Building the certificate'
        [System.Collections.Hashtable]$Params = @{
            Subject           = "CN=$CommonName"
            FriendlyName      = $CommonName
            CertStoreLocation = 'Cert:\CurrentUser\My'
            KeyExportPolicy   = 'ExportableEncrypted'
            KeyLength         = '4096'
            KeyAlgorithm      = 'RSA'
            HashAlgorithm     = $HashingAlgorithm
            KeySpec           = 'Signature'
            KeyUsage          = 'DigitalSignature'
            KeyUsageProperty  = 'Sign'
            Type              = 'CodeSigningCert'
            NotAfter          = [System.DateTime](Get-Date).AddYears(100)
            TextExtension     = @('2.5.29.19={text}CA:FALSE', '2.5.29.37={text}1.3.6.1.5.5.7.3.3', '1.3.6.1.4.1.311.21.10={text}oid=1.3.6.1.5.5.7.3.3')
        }
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$NewCertificate = New-SelfSignedCertificate @params

        # Save the thumbprint of the certificate to a variable
        [System.String]$NewCertificateThumbprint = $NewCertificate.Thumbprint

        Write-Verbose -Message 'Finding the certificate that was just created by its thumbprint'
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$TheCert = foreach ($Cert in (Get-ChildItem -Path 'Cert:\CurrentUser\My' -CodeSigningCert)) {
            if ($Cert.Thumbprint -eq $NewCertificateThumbprint) { $Cert }
        }

        Write-Verbose -Message 'Exporting the certificate (public key only)'
        $null = Export-Certificate -Cert $TheCert -FilePath $CertificateOutputPath -Type 'CERT' -Force

        Write-Verbose -Message 'Exporting the certificate (public and private keys)'
        $null = Export-PfxCertificate -Cert $TheCert -CryptoAlgorithmOption 'AES256_SHA256' -Password $PassWord -ChainOption 'BuildChain' -FilePath $PFXCertificateOutputPath -Force

        Write-Verbose -Message "Removing the certificate from the 'Current User/Personal' store"
        $TheCert | Remove-Item -Force

        try {
            Write-Verbose -Message "Importing the certificate to the 'Local Machine/Trusted Root Certification Authorities' store with the private key protected by VSM (Virtual Secure Mode - Virtualization Based Security)"
            $null = Import-PfxCertificate -ProtectPrivateKey 'VSM' -FilePath $PFXCertificateOutputPath -CertStoreLocation 'Cert:\LocalMachine\Root' -Password $PassWord
        }
        catch {
            Write-Verbose -Message "Importing the certificate to the 'Local Machine/Trusted Root Certification Authorities' store with the private key without VSM protection since it's most likely not available on the system. Happens usually in VMs with not nested-virtualization feature enabled."
            $null = Import-PfxCertificate -FilePath $PFXCertificateOutputPath -CertStoreLocation 'Cert:\LocalMachine\Root' -Password $PassWord
        }

        if ([System.String]::IsNullOrWhiteSpace($SignTool)) {
            Write-Verbose -Message 'Finding the latest version of the Microsoft.Windows.SDK.BuildTools package from NuGet and Downloading it'
            [System.String]$LatestSignToolVersion = (Invoke-RestMethod -Uri 'https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.buildtools/index.json').versions | Select-Object -Last 1
            Invoke-WebRequest -Uri "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.buildtools/${LatestSignToolVersion}/microsoft.windows.sdk.buildtools.${LatestSignToolVersion}.nupkg" -OutFile (Join-Path -Path $WorkingDir -ChildPath 'Microsoft.Windows.SDK.BuildTools.zip')
            Write-Verbose -Message 'Extracting the nupkg'
            Expand-Archive -Path "$WorkingDir\Microsoft.Windows.SDK.BuildTools.zip" -DestinationPath $WorkingDir -Force # Saving .nupkg as .zip to satisfy Windows PowerShell
            Write-Verbose -Message 'Finding the Signtool.exe path in the extracted directory'
            [System.String]$SignTool = (Get-Item -Path "$WorkingDir\bin\*\$CPUArch\signtool.exe").FullName
        }

        # Download the MSIX package if user did not provide the path to it
        if ([System.String]::IsNullOrWhiteSpace($MSIXPath)) {
            [System.String]$MSIXPath = [System.IO.Path]::Combine($WorkingDir, 'AppControl.Manager.msix')

            Write-Verbose -Message 'Downloading the MSIX package from the GitHub releases' -Verbose
            $null = Invoke-WebRequest -Uri $MSIXPackageDownloadURL -OutFile $MSIXPath

            # Get the version and architecture of the installing MSIX package app from the download URL
            $RegexMatch = $RegexPattern.Match($MSIXPackageDownloadURL)
            if ($RegexMatch.Success) {
                $InstallingAppVersion = $RegexMatch.Groups['Version'].Value
                $InstallingAppArchitecture = $RegexMatch.Groups['Architecture'].Value
            }
            else {
                throw 'Could not get the version of the installing app from the MSIX download URL.'
            }
        }
        else {
            # Get the version and architecture of the installing MSIX package app from the User provided file path
            $RegexMatch = $RegexPattern.Match($MSIXPath)
            if ($RegexMatch.Success) {
                $InstallingAppVersion = $RegexMatch.Groups['Version'].Value
                $InstallingAppArchitecture = $RegexMatch.Groups['Architecture'].Value
            }
            else {
                throw 'Could not get the version of the installing app from the -MSIX parameter value that you provided.'
            }
        }
        Write-Verbose -Message 'Signing the App Control Manager MSIX package'

        # In this step the SignTool detects the cert to use based on Common name + ThumbPrint + Hash Algo + Store Type + Store Name
        if ($VerbosePreference -eq 'Continue') {
            # Displays full debug logs if -Verbose is used or Verbose preference of the session is set to Continue
            . $SignTool sign /debug /n $CommonName /fd $HashingAlgorithm /sm /s 'Root' /sha1 $NewCertificateThumbprint $MSIXPath
        }
        else {
            # Displays no output if the command runs successfully, and displays minimal output if the command fails.
            $null = . $SignTool sign /q /n $CommonName /fd $HashingAlgorithm /sm /s 'Root' /sha1 $NewCertificateThumbprint $MSIXPath
        }
        if ($LASTEXITCODE -ne 0) {
            throw "SignTool Failed. Exit Code: $LASTEXITCODE"
        }

        Write-Verbose -Message 'Checking for existence of the application in unpacked format'
        $PossibleExistingApp = Get-AppxPackage -Name 'AppControlManager'
        if ($null -ne $PossibleExistingApp) {
            if ($PossibleExistingApp.IsDevelopmentMode -eq $true) {
                if ($PossibleExistingApp.SignatureKind -eq 'None') {
                    # Without this step, the installing would fail
                    Write-Verbose -Message 'The MSIX package is already installed in an unpacked format. Removing it and installing it again from the MSIX file.'
                    $PossibleExistingApp | Remove-AppxPackage -AllUsers
                }
            }
            # Get the details of the currently installed app before attempting to install the new one
            [System.String]$InstalledAppVersionBefore = $PossibleExistingApp.Version
            [System.String]$InstalledAppArchitectureBefore = $PossibleExistingApp.Architecture
            Write-Verbose -Message "The AppControl Manager app is already installed with version '$InstalledAppVersionBefore' and architecture '$InstalledAppArchitectureBefore'"
        }

        Write-Verbose -Message "Installing AppControl Manager MSIX Package version '$InstallingAppVersion' with architecture '$InstallingAppArchitecture'"
        Add-AppPackage -Path $MSIXPath -ForceUpdateFromAnyVersion -DeferRegistrationWhenPackagesAreInUse # -ForceTargetApplicationShutdown will shutdown the application if its open.

        Write-Verbose -Message "Finding the certificate that was just created by its thumbprint again from the 'Local Machine/Trusted Root Certification Authorities' store and removing it"
        foreach ($Cert2 in (Get-ChildItem -Path 'Cert:\LocalMachine\Root' -CodeSigningCert)) {
            if ($Cert.Thumbprint -eq $NewCertificateThumbprint) { $Cert2 | Remove-Item -Force }
        }

        Write-Verbose -Message "Adding the certificate to the 'Local Machine/Trusted Root Certification Authorities' store with public key only. This safely stores the certificate on your device, ensuring its private key does not exist so cannot be used to sign anything else."
        $null = Import-Certificate -FilePath $CertificateOutputPath -CertStoreLocation 'Cert:\LocalMachine\Root'

        [System.String]$InstallingAppLocationToAdd = 'C:\Program Files\WindowsApps\AppControlManager_' + $InstallingAppVersion + '_' + $InstallingAppArchitecture + '__sadt7br7jpt02\'
        Write-Verbose -Message "Adding the new app install's files To the ASR Rules exclusions."
        # The cmdlet won't add duplicates
        Add-MpPreference -AttackSurfaceReductionOnlyExclusions (($InstallingAppLocationToAdd + 'AppControlManager.exe'), ($InstallingAppLocationToAdd + 'AppControlManager.dll'))

        # If the app version being installed is not the same as the app version currently installed
        if ($InstallingAppVersion -ne $InstalledAppVersionBefore) {
            if (![string]::IsNullOrWhiteSpace($InstalledAppVersionBefore) -and ![string]::IsNullOrWhiteSpace($InstalledAppArchitectureBefore)) {
                Write-Verbose -Message 'Removing ASR Rules exclusions that belong to the previous app version.'
                # No check is needed since the Remove-MpPreference accepts any string and only removes them if they exist
                [System.String]$InstalledAppLocationToRemove = 'C:\Program Files\WindowsApps\AppControlManager_' + $InstalledAppVersionBefore + '_' + $InstalledAppArchitectureBefore + '__sadt7br7jpt02\'
                Remove-MpPreference -AttackSurfaceReductionOnlyExclusions (($InstalledAppLocationToRemove + 'AppControlManager.exe'), ($InstalledAppLocationToRemove + 'AppControlManager.dll'))
            }
        }
        else {
            Write-Verbose -Message 'Current and new AppControl Manager versions are the same, skipping removing previous ASR rules exclusions.'
        }

        try {
            $ValidateAdminCodeSignaturesRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            $ValidateAdminCodeSignaturesRegName = 'ValidateAdminCodeSignatures'
            $ValidateAdminCodeSignaturesRegValue = Get-ItemProperty -Path $ValidateAdminCodeSignaturesRegPath -Name $ValidateAdminCodeSignaturesRegName -ErrorAction SilentlyContinue
            # This will cause the "A referral was returned from the server." error to show up when AppControl Manager tries to start.
            if ($ValidateAdminCodeSignaturesRegValue.$ValidateAdminCodeSignaturesRegName -eq 1) {
                Write-Warning -Message "A policy named 'Only elevate executables that are signed and validated' is conflicting with the AppControl Manager app and won't let it start because it's self-signed with your on-device keys. Please disable the policy. It can be found in Group Policy Editor -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> 'User Account Control: Only elevate executable files that are signed and validated'"
            }
        }
        catch {}
    }
    finally {
        Write-Verbose -Message 'Cleaning up the working directory in the TEMP directory'
        [System.IO.Directory]::Delete($WorkingDir, $true)
    }
}
