using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AppControlManager.Logging;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel;
using Windows.Management.Deployment;

#pragma warning disable IDE0063 // Do not simplify using statements, keep them scoped for proper disposal otherwise files will be in use until the method is exited

namespace AppControlManager.Pages;


public sealed partial class Update : Page
{
	// Pattern for AppControl Manager version and architecture extraction from file path and download link URL
	[GeneratedRegex(@"_(?<Version>\d+\.\d+\.\d+\.\d+)_(?<Architecture>x64|arm64)\.msix$", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
	private static partial Regex MyRegex();

	// Create a Regex object
	internal readonly Regex regex = MyRegex();

	// Track whether hardened update procedure must be used
	private bool useHardenedUpdateProcedure;

	// To determine whether to use the user-supplied MSIX path or continue with downloading the MSIX from GitHub
	// It's changed by the UI toggle
	internal bool useCustomMSIXPath;

	// The custom MSIX path that the user supplied
	internal string? customMSIXPath;

	// Could be a URL or file path, will be used by Regex to detect version and architecture
	private string? sourceForRegex;

	// A static instance of the Update class which will hold the single, shared instance of it
	private static Update? _instance;

	public Update()
	{
		this.InitializeComponent();

		// Assign this instance to the static field
		_instance = this;

		// Cache the page in the memory so that when the user navigates back to this page, it does not go through the entire initialization process again, which improves performance.
		this.NavigationCacheMode = NavigationCacheMode.Enabled;
	}


	// Public property to access the singleton instance from other classes
	public static Update Instance => _instance ?? throw new InvalidOperationException("Update is not initialized.");



	// Event handler for check for update button
	private async void CheckForUpdateButton_Click(object sender, RoutedEventArgs e)
	{

		try
		{

			UpdateStatusInfoBar.IsClosable = false;
			CheckForUpdateButton.IsEnabled = false;
			UpdateStatusInfoBar.IsOpen = true;
			UpdateStatusInfoBar.Severity = InfoBarSeverity.Informational;

			// variable to store the update results
			UpdateCheckResponse? updateCheckResult = null;

			// If user did not provide custom MSIX path, start checking for update
			if (!useCustomMSIXPath)
			{
				UpdateStatusInfoBar.Message = "Checking for update";
				// Check for update asynchronously using the AppUpdate class's singleton instance
				updateCheckResult = await Task.Run(AppUpdate.Instance.Check);
			}

			// If a new version is available or user supplied a custom MSIX path to be installed
			if ((updateCheckResult is not null && updateCheckResult.IsNewVersionAvailable) || useCustomMSIXPath)
			{
				string msg1;

				if (useCustomMSIXPath)
				{
					msg1 = $"Installing the MSIX path that you selected: {customMSIXPath}";
				}
				else
				{
					msg1 = $"The current version is {App.currentAppVersion} while the online version is {updateCheckResult?.OnlineVersion}, updating the application...";
				}

				Logger.Write(msg1);
				UpdateStatusInfoBar.Message = msg1;

				WhatsNewInfoBar.IsOpen = true;

				string stagingArea = StagingArea.NewStagingArea("AppUpdate").ToString();

				// To store the latest MSIX version download link after retrieving it from GitHub text file
				Uri onlineDownloadURL;

				// Location of the MSIX package where it will be saved after download it from GitHub
				// Or in case user supplied a custom path, it will be assigned to this
				string AppControlManagerSavePath;

				DownloadProgressRingForMSIXFile.Visibility = Visibility.Visible;

				// If user did not supply a custom MSIX file path
				if (!useCustomMSIXPath)
				{

					using (HttpClient client = new())
					{
						// Store the download link to the latest available version
						onlineDownloadURL = new Uri(await client.GetStringAsync(GlobalVars.AppUpdateDownloadLinkURL));
					}

					// The Uri will be used to detect the version and architecture of the MSIX package being installed
					sourceForRegex = onlineDownloadURL.ToString();

					AppControlManagerSavePath = Path.Combine(stagingArea, "AppControlManager.msix");

					UpdateStatusInfoBar.Message = "Downloading the AppControl Manager MSIX package...";


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

				}

				else
				{
					// Use the user-supplied MSIX file path to detect the version and architecture
					sourceForRegex = customMSIXPath ?? throw new InvalidOperationException("No MSIX path was selected");

					// Use the user-supplied MSIX file path for installation source
					AppControlManagerSavePath = customMSIXPath;
				}

				DownloadProgressRingForMSIXFile.IsIndeterminate = true;

				UpdateStatusInfoBar.Message = "Detecting/Downloading the SignTool.exe from the Microsoft servers";

				// First check if SignTool path is registered in the user configurations, else attempt to detect or download it
				string signToolPath = UserConfiguration.Get().SignToolCustomPath ?? await Task.Run(() => SignToolHelper.GetSignToolPath());

				UpdateStatusInfoBar.Message = "All Downloads finished, installing the new AppControl Manager version";

				// Run the update check in a separate thread and asynchronously wait for its completion
				await Task.Run(() =>
				{
					// Random password to temporarily encrypt the private key of the newly generated certificate
					string PassWord = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUID();

					// Common name of the certificate
					string commonName = "SelfSignedCertForAppControlManager";

					// Path where the .cer file will be saved
					string CertificateOutputPath = Path.Combine(stagingArea, $"{commonName}.cer");

					// Remove any certificates with the specified common name that may already exist on the system form previos attempts
					CertificateGenerator.DeleteCertificateByCN(commonName);

					// Generate a new certificate
					X509Certificate2 generatedCert = CertificateGenerator.GenerateSelfSignedCertificate(
					subjectName: commonName,
					validityInYears: 100,
					keySize: 4096,
					hashAlgorithm: HashAlgorithmName.SHA512,
					storeLocation: CertificateGenerator.CertificateStoreLocation.Machine,
					cerExportFilePath: CertificateOutputPath,
					friendlyName: commonName,
					UserProtectedPrivateKey: useHardenedUpdateProcedure,
					ExportablePrivateKey: false);

					// Get the version and architecture of the installing MSIX package app
					Match RegexMatch = regex.Match(sourceForRegex);

					string InstallingAppVersion;
					string InstallingAppArchitecture;

					if (RegexMatch.Success)
					{
						InstallingAppVersion = RegexMatch.Groups["Version"].Value;
						InstallingAppArchitecture = RegexMatch.Groups["Architecture"].Value;
					}
					else
					{
						throw new InvalidOperationException("Could not get the version of the installing app");
					}


					// Signing the App Control Manager MSIX package
					// In this step the SignTool detects the cert to use based on Common name + ThumbPrint + Hash Algo + Store Type + Store Name
					ProcessStarter.RunCommand(signToolPath, $"sign /debug /n \"{commonName}\" /fd Sha512 /sm /s Root /sha1 {generatedCert.Thumbprint} \"{AppControlManagerSavePath}\"");

					PackageManager packageManager = new();
					IEnumerable<Package> PossibleExistingApp = packageManager.FindPackages("AppControlManager", "CN=SelfSignedCertForAppControlManager");

					Package? PossibleExistingPackage = PossibleExistingApp.FirstOrDefault();

					// Get the version of the first matching package
					string? InstalledAppVersionBefore = $"{PossibleExistingPackage?.Id.Version.Major}.{PossibleExistingPackage?.Id.Version.Minor}.{PossibleExistingPackage?.Id.Version.Build}.{PossibleExistingPackage?.Id.Version.Revision}";

					// Get the architecture of the first matching package
					string? InstalledAppArchitectureBefore = PossibleExistingPackage?.Id.Architecture.ToString();

					Logger.Write($"Installing AppControl Manager MSIX package version '{InstallingAppVersion}' with architecture '{InstallingAppArchitecture}'");

					// https://learn.microsoft.com/en-us/uwp/api/windows.management.deployment.addpackageoptions
					AddPackageOptions options = new()
					{
						DeferRegistrationWhenPackagesAreInUse = true,
						ForceUpdateFromAnyVersion = true
					};

					_ = packageManager.AddPackageByUriAsync(new Uri(AppControlManagerSavePath), options);


					// Remove any certificates with the specified common name again
					// Because the existing one contains private keys and don't want that
					CertificateGenerator.DeleteCertificateByCN(commonName);

					// Adding the certificate to the 'Local Machine/Trusted Root Certification Authorities' store with public key only. This safely stores the certificate on your device, ensuring its private key does not exist so cannot be used to sign anything else
					CertificateGenerator.StoreCertificateInStore(generatedCert, CertificateGenerator.CertificateStoreLocation.Machine, true);

					try
					{

						// Connect to the WMI namespace
						ManagementScope scope = new(@"\\.\ROOT\Microsoft\Windows\Defender");
						scope.Connect();

						// Create an instance of the MSFT_MpPreference class for Add method
						using ManagementClass mpPreferenceClass = new(scope, new ManagementPath("MSFT_MpPreference"), null);


						StringBuilder InstallingAppLocationToAdd = new();
						_ = InstallingAppLocationToAdd.Append("C:\\Program Files\\WindowsApps\\AppControlManager_");
						_ = InstallingAppLocationToAdd.Append(InstallingAppVersion);
						_ = InstallingAppLocationToAdd.Append('_');
						_ = InstallingAppLocationToAdd.Append(InstallingAppArchitecture);
						_ = InstallingAppLocationToAdd.Append("__sadt7br7jpt02\\");

						string path1 = Path.Combine(InstallingAppLocationToAdd.ToString(), "AppControlManager.exe");
						string path2 = Path.Combine(InstallingAppLocationToAdd.ToString(), "AppControlManager.dll");


						// Get the available methods for the class
						ManagementBaseObject methodParams = mpPreferenceClass.GetMethodParameters("Add");

						methodParams["AttackSurfaceReductionOnlyExclusions"] = new string[] { path1, path2 };

						// Invoke the method to apply the settings
						_ = mpPreferenceClass.InvokeMethod("Add", methodParams, null);


						// Remove ASR rule exclusions that belong to the previous app version if it existed
						if (!string.IsNullOrWhiteSpace(InstalledAppVersionBefore) && !string.IsNullOrWhiteSpace(InstalledAppArchitectureBefore))
						{

							// Removing ASR Rules exclusions that belong to the previous app version.

							StringBuilder InstalledAppLocationToRemove = new();
							_ = InstalledAppLocationToRemove.Append("C:\\Program Files\\WindowsApps\\AppControlManager_");
							_ = InstalledAppLocationToRemove.Append(InstalledAppVersionBefore);
							_ = InstalledAppLocationToRemove.Append('_');
							_ = InstalledAppLocationToRemove.Append(InstalledAppArchitectureBefore);
							_ = InstalledAppLocationToRemove.Append("__sadt7br7jpt02\\");

							// Create an instance of the MSFT_MpPreference class for Remove Method
							using ManagementClass mpPreferenceClass2 = new(scope, new ManagementPath("MSFT_MpPreference"), null);


							path1 = Path.Combine(InstalledAppLocationToRemove.ToString(), "AppControlManager.exe");
							path2 = Path.Combine(InstalledAppLocationToRemove.ToString(), "AppControlManager.dll");


							// Get the available methods for the class
							ManagementBaseObject methodParams2 = mpPreferenceClass2.GetMethodParameters("Remove");

							methodParams2["AttackSurfaceReductionOnlyExclusions"] = new string[] { path1, path2 };

							// Invoke the method to apply the settings
							_ = mpPreferenceClass2.InvokeMethod("Remove", methodParams2, null);

						}

					}

					catch (Exception ex)
					{
						Logger.Write($"An error occurred while trying to add the ASR rule exclusions which you can ignore: {ex.Message}");
					}

				});

				UpdateStatusInfoBar.Message = "Update has been successful. When you close and reopen the AppControl Manager, you will be automatically using the new version.";
				UpdateStatusInfoBar.Severity = InfoBarSeverity.Success;

				GlobalVars.updateButtonTextOnTheUpdatePage = "Updates installed";

				// Keep the CheckForUpdate button disabled since the update has been installed at this point
				// And all that's required is for the app to be restarted by the user
			}

			else
			{
				UpdateStatusInfoBar.Message = "The current version is already up to date.";
				UpdateStatusInfoBar.Severity = InfoBarSeverity.Success;
				CheckForUpdateButton.IsEnabled = true;
			}
		}

		catch
		{
			UpdateStatusInfoBar.Severity = InfoBarSeverity.Error;
			UpdateStatusInfoBar.Message = "An error occurred while checking for update.";

			DownloadProgressRingForMSIXFile.Value = 0;

			CheckForUpdateButton.IsEnabled = true;

			WhatsNewInfoBar.IsOpen = false;

			throw;
		}

		finally
		{
			UpdateStatusInfoBar.IsClosable = true;

			DownloadProgressRingForMSIXFile.Visibility = Visibility.Collapsed;
		}
	}


	// Event handler for the Auto Update Check Toggle Button to modify the User Configurations file
	private void AutoUpdateCheckToggle_Toggled(object sender, RoutedEventArgs e)
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


	/// <summary>
	/// Event handler for the Hardened Update Procedure Toggle Button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void HardenedUpdateProcedureToggle_Toggled(object sender, RoutedEventArgs e)
	{
		useHardenedUpdateProcedure = ((ToggleSwitch)sender).IsOn;
	}


	/// <summary>
	/// Event handler for the Settings card click that will act as click/tap on the toggle switch itself
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void AutoUpdateCheckToggleSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		_ = UserConfiguration.Set(AutoUpdateCheck: AutoUpdateCheckToggle.IsOn);

		AutoUpdateCheckToggle.IsOn = !AutoUpdateCheckToggle.IsOn;
	}


	/// <summary>
	/// Event handler for the Settings card click that will act as click/tap on the toggle switch itself
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void HardenedUpdateProcedureToggleSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		useHardenedUpdateProcedure = HardenedUpdateProcedureToggle.IsOn;

		HardenedUpdateProcedureToggle.IsOn = !HardenedUpdateProcedureToggle.IsOn;
	}


	/// <summary>
	/// Navigate to the extra sub-page
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void CheckForUpdate_Click(object sender, RoutedEventArgs e)
	{
		MainWindow.Instance.NavView_Navigate(typeof(UpdatePageCustomMSIXPath), null);
	}

}
