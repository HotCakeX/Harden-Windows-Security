using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

#pragma warning disable IDE0063 // Do not simplify using statements, keep them scoped for proper disposal otherwise files will be in use until the method is exited

namespace WDACConfig.Pages
{

    public sealed partial class Update : Page
    {

        public Update()
        {
            this.InitializeComponent();

            // Cache the page in the memory so that when the user navigates back to this page, it does not go through the entire initialization process again, which improves performance.
            this.NavigationCacheMode = NavigationCacheMode.Enabled;
        }


        private async void CheckForUpdateButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {

            try
            {

                UpdateStatusInfoBar.IsClosable = false;
                CheckForUpdateButton.IsEnabled = false;
                UpdateStatusInfoBar.IsOpen = true;
                UpdateStatusInfoBar.Message = "Checking for update";
                UpdateStatusInfoBar.Severity = InfoBarSeverity.Informational;

                // Check for update asynchronously
                UpdateCheckResponse updateCheckResult = await Task.Run(() => AppUpdate.Check());

                if (updateCheckResult.IsNewVersionAvailable)
                {

                    string msg1 = $"The current version is {App.currentAppVersion} while the online version is {updateCheckResult.OnlineVersion}, updating the application...";
                    Logger.Write(msg1);
                    UpdateStatusInfoBar.Message = msg1;

                    string onlineDownloadURL;

                    using (HttpClient client = new())
                    {
                        // Store the download link to the latest available version
                        onlineDownloadURL = await client.GetStringAsync(GlobalVars.AppUpdateDownloadLinkURL);
                    }

                    string stagingArea = StagingArea.NewStagingArea("AppUpdate").ToString();

                    string AppControlManagerSavePath = Path.Combine(stagingArea, "AppControlManager.msix");

                    UpdateStatusInfoBar.Message = "Downloading the AppControl Manager MSIX package...";

                    DownloadProgressRingForMSIXFile.Visibility = Microsoft.UI.Xaml.Visibility.Visible;

                    using (HttpClient client = new())
                    {
                        // Send an Async get request to the url and specify to stop reading after headers are received for better efficiently
                        using (HttpResponseMessage response = await client.GetAsync(onlineDownloadURL, HttpCompletionOption.ResponseHeadersRead))
                        {
                            // Ensure that the response is successful (status code 2xx); otherwise, throw an exception
                            _ = response.EnsureSuccessStatusCode();

                            // Retrieve the total file size from the Content-Length header (if available)
                            long? totalBytes = response.Content.Headers.ContentLength;

                            // Open a stream to read the response content asynchronously
                            await using (Stream contentStream = await response.Content.ReadAsStreamAsync())
                            {
                                // Open a file stream to save the downloaded data locally
                                await using (FileStream fileStream = new(
                                    AppControlManagerSavePath,       // Path to save the file
                                    FileMode.Create,                 // Create a new file or overwrite if it exists
                                    FileAccess.Write,                // Write-only access
                                    FileShare.None,                  // Do not allow other processes to access the file
                                    bufferSize: 8192,                // Set buffer size to 8 KB
                                    useAsync: true))                 // Enable asynchronous operations for the file stream
                                {
                                    // Define a buffer to hold data chunks as they are read
                                    byte[] buffer = new byte[8192];
                                    long totalReadBytes = 0;         // Track the total number of bytes read
                                    int readBytes;                   // Holds the count of bytes read in each iteration
                                    double lastReportedProgress = 0; // Tracks the last reported download progress

                                    // Loop to read from the content stream in chunks until no more data is available
                                    while ((readBytes = await contentStream.ReadAsync(buffer)) > 0)
                                    {
                                        // Write the buffer to the file stream
                                        await fileStream.WriteAsync(buffer.AsMemory(0, readBytes));
                                        totalReadBytes += readBytes;  // Update the total bytes read so far

                                        // If the total file size is known, calculate and report progress
                                        if (totalBytes.HasValue)
                                        {
                                            // Calculate the current download progress as a percentage
                                            double progressPercentage = (double)totalReadBytes / totalBytes.Value * 100;

                                            // Only update the ProgressBar if progress has increased by at least 1% to avoid constantly interacting with the UI thread
                                            if (progressPercentage - lastReportedProgress >= 1)
                                            {
                                                // Update the last reported progress
                                                lastReportedProgress = progressPercentage;

                                                // Update the UI ProgressBar value on the dispatcher thread
                                                _ = DownloadProgressRingForMSIXFile.DispatcherQueue.TryEnqueue(() =>
                                                {
                                                    DownloadProgressRingForMSIXFile.Value = progressPercentage;
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }


                    Logger.Write($"The AppControl Manager MSIX package has been successfully downloaded to {AppControlManagerSavePath}");

                    DownloadProgressRingForMSIXFile.IsIndeterminate = true;

                    UpdateStatusInfoBar.Message = "Detecting and downloading the SignTool.exe from the Microsoft servers";

                    string signToolPath = string.Empty;

                    await Task.Run(() =>
                    {
                        signToolPath = SignToolHelper.GetSignToolPath();
                    });

                    UpdateStatusInfoBar.Message = "All Downloads finished, installing the new AppControl Manager version";

                    // Run the update check in a separate thread and asynchronously wait for its completion
                    await Task.Run(() =>
                    {

                        string script = """
[System.String]$MSIXPath = '{MSIXPath}'
[System.String]$SignTool = '{SignTool}'
[System.String]$MSIXDownloadURL = '{MSIXDownloadURL}'
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'
Write-Verbose -Message 'Detecting the CPU Arch'
switch ($Env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { [System.String]$CPUArch = 'x64'; break }
    'ARM64' { [System.String]$CPUArch = 'arm64'; break }
    default { Throw [System.PlatformNotSupportedException] 'Only AMD64 and ARM64 architectures are supported.' }
}

Add-Type -TypeDefinition @'
using System;
using System.Security;
using System.Security.Cryptography;

public static class SecureStringGenerator
{
    private static readonly char[] allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray();
    public static SecureString GenerateSecureString(int length)
    {
        SecureString secureString = new();
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        byte[] randomNumber = new byte[4]; // Buffer for generating secure random numbers
        for (int i = 0; i < length; i++)
        {
            rng.GetBytes(randomNumber);
            int randomIndex = BitConverter.ToInt32(randomNumber, 0) & int.MaxValue; // Ensure non-negative index
            randomIndex %= allowedChars.Length; // Fit within allowedChars length

            char randomChar = allowedChars[randomIndex];
            secureString.AppendChar(randomChar);
        }
        secureString.MakeReadOnly();
        return secureString;
    }
}
'@ -Language CSharp

Write-Verbose -Message 'Creating the working directory in the TEMP directory'
[System.String]$CommonName = 'SelfSignedCertForAppControlManager'
[System.String]$WorkingDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $CommonName)
[System.String]$CertificateOutputPath = [System.IO.Path]::Combine($WorkingDir, "$CommonName.cer")
[System.String]$PFXCertificateOutputPath = [System.IO.Path]::Combine($WorkingDir, "$CommonName.pfx")
[System.Security.SecureString]$PassWord = [SecureStringGenerator]::GenerateSecureString(100)
[System.String]$HashingAlgorithm = 'Sha512'

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
        if ($Cert.Thumbprint -eq $NewCertificateThumbprint) {
            $Cert
        }
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

    # Pattern for AppControl Manager version and architecture extraction from file path and download link URL
    [regex]$RegexPattern = '_(?<Version>\d+\.\d+\.\d+\.\d+)_(?<Architecture>x64|arm64)\.msix$'

    # Get the version and architecture of the installing MSIX package app from the provided file path
    $RegexMatch = $RegexPattern.Match($MSIXDownloadURL)

    if ($RegexMatch.Success) {
        $InstallingAppVersion = $RegexMatch.Groups['Version'].Value
        $InstallingAppArchitecture = $RegexMatch.Groups['Architecture'].Value
    }
    else {
        throw 'Could not get the version of the installing app'
    }

    Write-Verbose -Message 'Signing the App Control Manager MSIX package'

    # In this step the SignTool detects the cert to use based on Common name + ThumbPrint + Hash Algo + Store Type + Store Name
    . $SignTool sign /debug /n $CommonName /fd $HashingAlgorithm /sm /s 'Root' /sha1 $NewCertificateThumbprint $MSIXPath

    if ($LASTEXITCODE -ne 0) {
        throw "SignTool Failed. Exit Code: $LASTEXITCODE"
    }

    $PossibleExistingApp = Get-AppxPackage -Name 'AppControlManager'
    if ($null -ne $PossibleExistingApp) {
        # Get the details of the currently installed app before attempting to install the new one
        [System.String]$InstalledAppVersionBefore = $PossibleExistingApp.Version
        [System.String]$InstalledAppArchitectureBefore = $PossibleExistingApp.Architecture
    }

    Write-Verbose -Message "Installing AppControl Manager MSIX package version '$InstallingAppVersion' with architecture '$InstallingAppArchitecture'"
    Add-AppPackage -Path $MSIXPath -ForceUpdateFromAnyVersion -DeferRegistrationWhenPackagesAreInUse # -ForceTargetApplicationShutdown will shutdown the application if its open.

    Write-Verbose -Message "Finding the certificate that was just created by its thumbprint again from the 'Local Machine/Trusted Root Certification Authorities' store"
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$TheCert2 = foreach ($Cert2 in (Get-ChildItem -Path 'Cert:\LocalMachine\Root' -CodeSigningCert)) {
        if ($Cert.Thumbprint -eq $NewCertificateThumbprint) {
            $Cert2
        }
    }

    Write-Verbose -Message 'Removing the certificate that has private + public keys'
    $TheCert2 | Remove-Item -Force

    Write-Verbose -Message "Adding the certificate to the 'Local Machine/Trusted Root Certification Authorities' store with public key only. This safely stores the certificate on your device, ensuring its private key does not exist so cannot be used to sign anything else."
    $null = Import-Certificate -FilePath $CertificateOutputPath -CertStoreLocation 'Cert:\LocalMachine\Root'

    [System.String]$InstallingAppLocationToAdd = 'C:\Program Files\WindowsApps\AppControlManager_' + $InstallingAppVersion + '_' + $InstallingAppArchitecture + '__sadt7br7jpt02\'
    Write-Verbose -Message "Adding the new app install's files To the ASR Rules exclusions."
    Add-MpPreference -AttackSurfaceReductionOnlyExclusions (($InstallingAppLocationToAdd + 'AppControlManager.exe'), ($InstallingAppLocationToAdd + 'AppControlManager.dll'))

    # Remove ASR rule exclusions that belong to the previous app version if it existed
    if (![string]::IsNullOrWhiteSpace($InstalledAppVersionBefore) -and ![string]::IsNullOrWhiteSpace($InstalledAppArchitectureBefore)) {
        Write-Verbose -Message 'Removing ASR Rules exclusions that belong to the previous app version.'
        [System.String]$InstalledAppLocationToRemove = 'C:\Program Files\WindowsApps\AppControlManager_' + $InstalledAppVersionBefore + '_' + $InstalledAppArchitectureBefore + '__sadt7br7jpt02\'
        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions (($InstalledAppLocationToRemove + 'AppControlManager.exe'), ($InstalledAppLocationToRemove + 'AppControlManager.dll'))
    }
}
finally {
    Write-Verbose -Message 'Cleaning up the working directory in the TEMP directory'
    [System.IO.Directory]::Delete($WorkingDir, $true)
}

""";

                        // Replace placeholders in the script with actual values
                        script = script.Replace("{MSIXPath}", AppControlManagerSavePath, StringComparison.OrdinalIgnoreCase)
                                       .Replace("{SignTool}", signToolPath, StringComparison.OrdinalIgnoreCase)
                                       .Replace("{MSIXDownloadURL}", onlineDownloadURL, StringComparison.OrdinalIgnoreCase);


                        // Run the PowerShell script to check for updates and save the output code
                        _ = PowerShellExecutor.ExecuteScript(script);

                    });

                    UpdateStatusInfoBar.Message = "Update has been successful. When you close and reopen the AppControl Manager, you will be automatically using the new version.";
                    UpdateStatusInfoBar.Severity = InfoBarSeverity.Success;
                }

                else
                {
                    UpdateStatusInfoBar.Message = "The current version is already up to date.";
                    UpdateStatusInfoBar.Severity = InfoBarSeverity.Success;
                }
            }

            catch
            {
                UpdateStatusInfoBar.Severity = InfoBarSeverity.Error;
                UpdateStatusInfoBar.Message = "An error occurred while checking for update.";

                DownloadProgressRingForMSIXFile.Value = 0;

                throw;
            }

            finally
            {
                UpdateStatusInfoBar.IsClosable = true;

                CheckForUpdateButton.IsEnabled = true;

                DownloadProgressRingForMSIXFile.Visibility = Microsoft.UI.Xaml.Visibility.Collapsed;
            }
        }


        // Event handler for the Auto Update Check Toggle Button to modify the User Configurations file
        private void AutoUpdateCheckToggle_Toggled(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {
            _ = UserConfiguration.Set(AutoUpdateCheck: AutoUpdateCheckToggle.IsOn);
        }


        /// <summary>
        /// Override OnNavigatedTo to update the toggle button when the page is navigated to.
        /// The method is called whenever the page becomes the active page in the navigation stack but the Update() constructor is not called again.
        /// Changes the in-memory (cached) instance of the page
        /// </summary>
        /// <param name="e"></param>
        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            // Call the base class implementation first
            base.OnNavigatedTo(e);

            // Set the toggle for Auto Update Check based on the User Configurations
            AutoUpdateCheckToggle.IsOn = (UserConfiguration.Get().AutoUpdateCheck == true);

            // Grab the latest text for the CheckForUpdateButton button
            CheckForUpdateButton.Content = GlobalVars.updateButtonTextOnTheUpdatePage;
        }
    }
}
