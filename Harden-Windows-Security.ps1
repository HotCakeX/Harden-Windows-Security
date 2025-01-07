Function P {
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'Stop'
    Set-ExecutionPolicy -ExecutionPolicy 'Unrestricted' -Scope 'Process' -Force
    [string]$PSDownloadURLMSIX = 'https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/PowerShell-7.4.6-win.msixbundle'
    [string]$PSMSIXDownloadPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'PowerShell.msixbundle')
    try {
        if ($PSVersionTable.PSEdition -eq 'Desktop' -and !(Get-Command -Name 'pwsh.exe' -ErrorAction Ignore)) {
            $User = Get-LocalUser | Where-Object -FilterScript { $_.SID -eq ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value) }
            Write-Verbose -Message 'Trying to Install PowerShell Core because it could not be found on the system' -Verbose
            if ($User.PrincipalSource -eq 'MicrosoftAccount' -and (Get-Command -Name 'winget.exe' -ErrorAction Ignore)) {
                # https://apps.microsoft.com/detail/9mz1snwt0n5d
                Write-Verbose -Message 'Microsoft account detected, using Microsoft Store source for PowerShell installation through Winget'
                $null = Winget install --id 9MZ1SNWT0N5D --accept-package-agreements --accept-source-agreements --source msstore
                if ($LASTEXITCODE -ne 0) { throw "Failed to Install PowerShell Core using Winget: $LASTEXITCODE" }
            }
            else {
                if ([System.IO.File]::Exists($PSMSIXDownloadPath)) { [System.IO.File]::Delete($PSMSIXDownloadPath) }
                Write-Verbose -Message 'Local account detected or winget is not installed, cannot install PowerShell Core from Microsoft Store using Winget and msstore as the source. Downloading and Installing PowerShell directly from the official Microsoft GitHub repository using MSIX file'
                Invoke-WebRequest -Uri $PSDownloadURLMSIX -OutFile $PSMSIXDownloadPath
                Add-AppxPackage -Path $PSMSIXDownloadPath
            }
        }
    }
    finally { if ([System.IO.File]::Exists($PSMSIXDownloadPath)) { [System.IO.File]::Delete($PSMSIXDownloadPath) } }
    pwsh.exe -NoProfile -NoLogo -NoExit -Command {
        Set-ExecutionPolicy -ExecutionPolicy 'Unrestricted' -Scope 'Process' -Force
        if (!(Get-Module -ListAvailable -Name 'Harden-Windows-Security-Module' -ErrorAction Ignore)) {
            Write-Verbose -Message 'Installing the Harden Windows Security Module because it could not be found' -Verbose
            Install-Module -Name 'Harden-Windows-Security-Module' -Force
        }
        Protect-WindowsSecurity -GUI
    }
}
Function AppControl {
    <#
    .DESCRIPTION
        Please refer to the provided link for all of the information about this function and detailed overview of the entire process.
        https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager
    .PARAMETER MSIXPath
        The path to the AppControlManager MSIX file. If not provided, the latest MSIX file will be downloaded from the GitHub. It must have the version number and architecture in its file name as provided on GitHub or produced by Visual Studio.
    .PARAMETER SignTool
       The path to the Microsoft's Signtool.exe If not provided, the function automatically downloads the latest SignTool.exe from the Microsoft website in Nuget and will use it for the signing operations.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)][string]$MSIXPath, [Parameter(Mandatory = $False)][string]$SignTool
    )
    $ErrorActionPreference = 'Stop'
    if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning -Message 'Please run this function as an Administrator'; return
    }
    Write-Verbose -Message 'Detecting the CPU Arch'
    switch ($Env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { [string]$CPUArch = 'x64'; break }
        'ARM64' { [string]$CPUArch = 'arm64'; break }
        default { Throw [System.PlatformNotSupportedException] 'Only AMD64 and ARM64 architectures are supported.' }
    }
    [string]$CommonName = 'SelfSignedCertForAppControlManager'
    [string]$WorkingDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $CommonName)
    [string]$CertificateOutputPath = [System.IO.Path]::Combine($WorkingDir, "$CommonName.cer")
    [string]$HashingAlgorithm = 'Sha512'

    # Pattern for AppControl Manager version and architecture extraction from file path and download link URL
    [regex]$RegexPattern = '_(?<Version>\d+\.\d+\.\d+\.\d+)_(?<Architecture>x64|arm64)\.msix$'

    Write-Verbose -Message 'Creating the working directory in the TEMP directory'
    if ([System.IO.Directory]::Exists($WorkingDir)) { [System.IO.Directory]::Delete($WorkingDir, $true) }
    $null = [System.IO.Directory]::CreateDirectory($WorkingDir)

    try {
        Write-Verbose -Message "Checking if a certificate with the common name '$CommonName' already exists."
        [string[]]$CertStoresToCheck = @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\CA', 'Cert:\LocalMachine\TrustedPublisher', 'Cert:\CurrentUser\My', 'Cert:\CurrentUser\Root', 'Cert:\CurrentUser\CA', 'Cert:\CurrentUser\TrustedPublisher')
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
            KeyExportPolicy   = 'NonExportable' # Private key is non-exportable for security
            KeyLength         = '4096' # A good balance between generation time and security
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

        Write-Verbose -Message 'Exporting the certificate (public key only)'
        $null = Export-Certificate -Cert $NewCertificate -FilePath $CertificateOutputPath -Type 'CERT' -Force

        if ([string]::IsNullOrWhiteSpace($SignTool)) {
            Write-Verbose -Message 'Finding the latest version of the Microsoft.Windows.SDK.BuildTools package from NuGet and Downloading it'
            [string]$LatestSignToolVersion = (Invoke-RestMethod -Uri 'https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.buildtools/index.json').versions | Select-Object -Last 1
            Invoke-WebRequest -Uri "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.buildtools/${LatestSignToolVersion}/microsoft.windows.sdk.buildtools.${LatestSignToolVersion}.nupkg" -OutFile (Join-Path -Path $WorkingDir -ChildPath 'Microsoft.Windows.SDK.BuildTools.zip')
            Write-Verbose -Message 'Extracting the nupkg'
            Expand-Archive -Path "$WorkingDir\Microsoft.Windows.SDK.BuildTools.zip" -DestinationPath $WorkingDir -Force # Saving .nupkg as .zip to satisfy Windows PowerShell
            Write-Verbose -Message 'Finding the Signtool.exe path in the extracted directory'
            [string]$SignTool = (Get-Item -Path "$WorkingDir\bin\*\$CPUArch\signtool.exe").FullName
        }

        # Download the MSIX package if user did not provide the path to it
        if ([string]::IsNullOrWhiteSpace($MSIXPath)) {
            [string]$MSIXPath = [System.IO.Path]::Combine($WorkingDir, 'AppControl.Manager.msix')

            # Download link for the latest version of AppControl manger is retrieved from this text file
            [string]$MSIXPackageDownloadURL = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/AppControl%20Manager/DownloadURL.txt'

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
            . $SignTool sign /debug /n $CommonName /fd $HashingAlgorithm /s 'My' /sha1 $NewCertificate.Thumbprint $MSIXPath
        }
        else {
            # Displays no output if the command runs successfully, and displays minimal output if the command fails.
            $null = . $SignTool sign /q /n $CommonName /fd $HashingAlgorithm /s 'My' /sha1 $NewCertificate.Thumbprint $MSIXPath
        }
        if ($LASTEXITCODE -ne 0) { throw "SignTool Failed. Exit Code: $LASTEXITCODE" }

        $NewCertificate | Remove-Item -Force # Remove the certificate from Current User's personal certificate store because we don't need its private key anymore

        Write-Verbose -Message "Adding the certificate to the 'Local Machine/Trusted Root Certification Authorities' store with public key only. This safely stores the certificate on your device, ensuring its private key does not exist so cannot be used to sign anything else."
        $null = Import-Certificate -FilePath $CertificateOutputPath -CertStoreLocation 'Cert:\LocalMachine\Root'

        try {
            Write-Verbose -Message 'Removing any possible ASR Rules exclusions that belong to the previous app version.'
            [string[]]$PossiblePreviousASRExclusions = (Get-MpPreference).AttackSurfaceReductionOnlyExclusions | Where-Object -FilterScript { $_ -like '*__sadt7br7jpt02\AppControlManager*' }
            if ($null -ne $PossiblePreviousASRExclusions -and $PossiblePreviousASRExclusions.Length -gt 0) { Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $PossiblePreviousASRExclusions }

            [string]$InstallingAppLocationToAdd = 'C:\Program Files\WindowsApps\AppControlManager_' + $InstallingAppVersion + '_' + $InstallingAppArchitecture + '__sadt7br7jpt02\'
            Write-Verbose -Message "Adding the new app install's files To the ASR Rules exclusions."
            # The cmdlet won't add duplicates
            Add-MpPreference -AttackSurfaceReductionOnlyExclusions (($InstallingAppLocationToAdd + 'AppControlManager.exe'), ($InstallingAppLocationToAdd + 'AppControlManager.dll')) -ErrorAction Stop

            $ValidateAdminCodeSignaturesRegName = 'ValidateAdminCodeSignatures'
            $ValidateAdminCodeSignaturesRegValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name $ValidateAdminCodeSignaturesRegName -ErrorAction SilentlyContinue
            # This will cause the "A referral was returned from the server." error to show up when AppControl Manager tries to start.
            if ($ValidateAdminCodeSignaturesRegValue.$ValidateAdminCodeSignaturesRegName -eq 1) {
                Write-Warning -Message "A policy named 'Only elevate executables that are signed and validated' is conflicting with the AppControl Manager app and won't let it start because it's self-signed with your on-device keys. Please disable the policy. It can be found in Group Policy Editor -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> 'User Account Control: Only elevate executable files that are signed and validated'"
            }
        }
        catch { Write-Verbose -Message "You can safely ignore this error: $_" } # If this section fails for some reason such as running the script in Windows Sandbox, no error should be thrown

        Write-Verbose -Message "Installing AppControl Manager MSIX Package version '$InstallingAppVersion' with architecture '$InstallingAppArchitecture'"
        Add-AppPackage -Path $MSIXPath -ForceUpdateFromAnyVersion -DeferRegistrationWhenPackagesAreInUse
    }
    finally { [System.IO.Directory]::Delete($WorkingDir, $true) } # Cleaning up the working directory in the TEMP directory
}