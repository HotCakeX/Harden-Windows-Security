Function P {
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'Stop'
    Set-ExecutionPolicy -ExecutionPolicy 'Unrestricted' -Scope 'Process' -Force
    [string]$PSDownloadURLMSIX = 'https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/PowerShell-7.4.6-win.msixbundle'
    [string]$PSMSIXDownloadPath = Join-Path -Path $env:TEMP -ChildPath 'PowerShell.msixbundle'
    try {
        if ($PSVersionTable.PSEdition -eq 'Desktop' -and !(Get-Command -Name 'pwsh.exe' -ErrorAction Ignore)) {
            Write-Verbose -Message 'Trying to Install PowerShell (Core) because it could not be found on the system' -Verbose
            if (Get-Command -Name 'winget.exe' -ErrorAction Ignore) {
                # https://apps.microsoft.com/detail/9mz1snwt0n5d
                Write-Verbose -Message 'Installing PowerShell through Winget'
                $null = Winget install --id 9MZ1SNWT0N5D --accept-package-agreements --accept-source-agreements --source msstore
                if ($LASTEXITCODE -ne 0) { throw "Failed to Install PowerShell using Winget: $LASTEXITCODE" }
            }
            else {
                if (Test-Path -Path $PSMSIXDownloadPath -PathType Leaf) { Remove-Item -Path $PSMSIXDownloadPath -Force }
                Write-Verbose -Message 'Winget is not installed. Downloading and Installing PowerShell directly from the official Microsoft GitHub repository using MSIX file'
                Invoke-WebRequest -Uri $PSDownloadURLMSIX -OutFile $PSMSIXDownloadPath
                Add-AppxPackage -Path $PSMSIXDownloadPath
            }
        }
    }
    finally { if (Test-Path -Path $PSMSIXDownloadPath -PathType Leaf) { Remove-Item -Path $PSMSIXDownloadPath -Force } }
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
    .PARAMETER MSIXBundlePath
        The path to the AppControlManager MSIXBundle file. If not provided, the latest MSIXBundle file will be downloaded from the GitHub.
    .PARAMETER MSIXPath
        The path to the AppControlManager MSIX file. If not provided, the latest MSIX file will be downloaded from the GitHub. It must have the version number and architecture in its file name as provided on GitHub or produced by Visual Studio.
    .PARAMETER SignTool
       The path to the Microsoft's Signtool.exe; If not provided, the function automatically downloads the latest SignTool.exe from the Microsoft website in Nuget and will use it for the signing operations.
    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory = $false)][string]$MSIXBundlePath, [Parameter(Mandatory = $false)][string]$MSIXPath, [Parameter(Mandatory = $False)][string]$SignTool)
    $ErrorActionPreference = 'Stop'
    if ($ExecutionContext.SessionState.LanguageMode -ne 'ConstrainedLanguage') {
        # We cannot use .NET methods in ConstrainedLanguage mode
        if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Warning -Message 'Please run this function as an Administrator'; return
        }
    }
    [string]$CommonName = 'SelfSignedCertForAppControlManager'
    [string]$WorkingDir = Join-Path -Path $env:TEMP -ChildPath $CommonName
    [string]$CertificateOutputPath = Join-Path -Path $WorkingDir -ChildPath "$CommonName.cer"
    [string]$HashingAlgorithm = 'Sha512'
    [string]$_Package # Where the final package path will be stored, whether it's MSIX or MSIXBundle
    [string]$CPUArch = @{AMD64 = 'x64'; ARM64 = 'arm64' }[$Env:PROCESSOR_ARCHITECTURE]
    if ([System.String]::IsNullOrWhiteSpace($CPUArch)) { throw [System.PlatformNotSupportedException] 'Only AMD64 and ARM64 architectures are supported.' }
    Write-Verbose -Message 'Creating the working directory in the TEMP directory'
    if (Test-Path -Path $WorkingDir -PathType Container) { Remove-Item -Path $WorkingDir -Recurse -Force }
    $null = New-Item -Path $WorkingDir -ItemType Directory -Force

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
            Write-Verbose -Message 'Extracting the nupkg and finding the Signtool.exe path in the extracted directory'
            Expand-Archive -Path (Join-Path -Path $WorkingDir -ChildPath 'Microsoft.Windows.SDK.BuildTools.zip') -DestinationPath $WorkingDir -Force # Saving .nupkg as .zip to satisfy Windows PowerShell
            [string]$SignTool = (Get-Item -Path "$WorkingDir\bin\*\$CPUArch\signtool.exe").FullName
        }

        # If user provided a valid path to the MSIXBundle file
        if (![string]::IsNullOrWhiteSpace($MSIXBundlePath) -and (Test-Path -Path $MSIXBundlePath -PathType Leaf)) {
            $_Package = $MSIXBundlePath
        }
        # If user provided a valid path to the MSIX file
        elseif (![string]::IsNullOrWhiteSpace($MSIXPath) -and (Test-Path -Path $MSIXPath -PathType Leaf)) {
            $_Package = $MSIXPath
        }
        # Download the MSIXBundle if user didn't provide any paths
        else {
            Write-Verbose -Message 'Downloading the latest AppControl Manager MSIXBundle file from GitHub'
            $_Package = Join-Path -Path $WorkingDir -ChildPath 'AppControlManager.msixbundle'

            # Download link for the latest version of AppControl manger is retrieved from this text file
            [string]$MSIXBundleDownloadURL = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/AppControl%20Manager/MSIXBundleDownloadURL.txt'

            Write-Verbose -Message 'Downloading the MSIXBundle from the GitHub releases' -Verbose
            $null = Invoke-WebRequest -Uri $MSIXBundleDownloadURL -OutFile $MSIXPath
        }
        Write-Verbose -Message 'Signing the App Control Manager package'

        # In this step the SignTool detects the cert to use based on Common name + ThumbPrint + Hash Algo + Store Type + Store Name
        if ($VerbosePreference -eq 'Continue') {
            # Displays full debug logs if -Verbose is used or Verbose preference of the session is set to Continue
            . $SignTool sign /debug /n $CommonName /fd $HashingAlgorithm /s 'My' /sha1 $NewCertificate.Thumbprint $_Package
        }
        else {
            # Displays no output if the command runs successfully, and displays minimal output if the command fails.
            $null = . $SignTool sign /q /n $CommonName /fd $HashingAlgorithm /s 'My' /sha1 $NewCertificate.Thumbprint $_Package
        }
        if ($LASTEXITCODE -ne 0) { throw "SignTool Failed. Exit Code: $LASTEXITCODE" }

        $NewCertificate | Remove-Item -Force # Remove the certificate from Current User's personal certificate store because we don't need its private key anymore

        Write-Verbose -Message "Adding the certificate to the 'Local Machine/Trusted Root Certification Authorities' store with public key only. This safely stores the certificate on your device, ensuring its private key does not exist so cannot be used to sign anything else."
        $null = Import-Certificate -FilePath $CertificateOutputPath -CertStoreLocation 'Cert:\LocalMachine\Root'

        try {
            Write-Verbose -Message 'Removing any possible ASR Rules exclusions that belong to the previous app version.'
            [string[]]$PossiblePreviousASRExclusions = (Get-MpPreference).AttackSurfaceReductionOnlyExclusions | Where-Object -FilterScript { $_ -like '*__sadt7br7jpt02\AppControlManager*' }
            if ($null -ne $PossiblePreviousASRExclusions -and $PossiblePreviousASRExclusions.Length -gt 0) { Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $PossiblePreviousASRExclusions }

            [string]$ValidateAdminCodeSignaturesRegName = 'ValidateAdminCodeSignatures'
            $ValidateAdminCodeSignaturesRegValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name $ValidateAdminCodeSignaturesRegName -ErrorAction SilentlyContinue
            # This will cause the "A referral was returned from the server." error to show up when AppControl Manager tries to start.
            if ($ValidateAdminCodeSignaturesRegValue.$ValidateAdminCodeSignaturesRegName -eq 1) {
                Write-Warning -Message "A policy named 'Only elevate executables that are signed and validated' is conflicting with the AppControl Manager app and won't let it start because it's self-signed with your on-device keys. Please disable the policy. It can be found in Group Policy Editor -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> 'User Account Control: Only elevate executable files that are signed and validated'"
            }
        }
        catch { Write-Verbose -Message "You can safely ignore this error: $_" } # If this section fails for some reason such as running the script in Windows Sandbox, no error should be thrown

        Write-Verbose -Message 'Installing the AppControl Manager'
        Add-AppPackage -Path $_Package -ForceUpdateFromAnyVersion -DeferRegistrationWhenPackagesAreInUse

        try {
            [string]$InstallingAppLocationToAdd = (Get-AppxPackage -Name AppControlManager).InstallLocation
            Write-Verbose -Message "Adding the new app's dll and exe (2 files) To the ASR Rules exclusions."
            # The cmdlet won't add duplicates
            Add-MpPreference -AttackSurfaceReductionOnlyExclusions (Join-Path -Path $InstallingAppLocationToAdd -ChildPath 'AppControlManager.exe'), (Join-Path -Path $InstallingAppLocationToAdd -ChildPath 'AppControlManager.dll') -ErrorAction Stop
        }
        catch { Write-Verbose -Message "You can safely ignore this error: $_" }
    }
    finally { Remove-Item -Path $WorkingDir -Recurse -Force } # Cleaning up the working directory in the TEMP directory
}