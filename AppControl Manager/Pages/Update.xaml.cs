using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.AppSettings;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel;
using Windows.Foundation;
using Windows.Management.Deployment;

#pragma warning disable IDE0063 // Do not simplify using statements, keep them scoped for proper disposal otherwise files will be in use until the method is exited

namespace AppControlManager.Pages;

public sealed partial class Update : Page
{
	// Pattern for finding ASR rules that belong to the AppControl Manager
	[GeneratedRegex("__sadt7br7jpt02", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
	private static partial Regex MyRegex1();

	// Common name of the on-device generated certificate used to sign the AppControl Manager MSIXBundle package
	private const string commonName = "SelfSignedCertForAppControlManager";

	// Track whether hardened update procedure must be used
	private bool useHardenedUpdateProcedure;

	// To determine whether to use the user-supplied MSIXBundle path or continue with downloading the MSIXBundle from GitHub
	// It's changed by the UI toggle
	internal bool useCustomMSIXBundlePath;

	// The custom MSIXBundle path that the user supplied
	internal string? customMSIXBundlePath;

	// A static instance of the Update class which will hold the single, shared instance of it
	private static Update? _instance;

	public Update()
	{
		this.InitializeComponent();

		// Assign this instance to the static field
		_instance = this;

		// Cache the page in the memory so that when the user navigates back to this page, it does not go through the entire initialization process again, which improves performance.
		this.NavigationCacheMode = NavigationCacheMode.Required;
	}

	// Public property to access the singleton instance from other classes
	public static Update Instance => _instance ?? throw new InvalidOperationException(GlobalVars.Rizz.GetString("UpdateNotInitialized"));

	// Event handler for check for update button
	private async void CheckForUpdateButton_Click(object sender, RoutedEventArgs e)
	{

		try
		{
			UpdateStatusInfoBar.IsClosable = false;
			CheckForUpdateButton.IsEnabled = false;
			CheckForUpdate.IsClickEnabled = false;
			UpdateStatusInfoBar.IsOpen = true;
			UpdateStatusInfoBar.Severity = InfoBarSeverity.Informational;

			// variable to store the update results
			UpdateCheckResponse? updateCheckResult = null;

			// If user did not provide custom MSIXBundle path, start checking for update
			if (!useCustomMSIXBundlePath)
			{
				UpdateStatusInfoBar.Message = GlobalVars.Rizz.GetString("CheckingForUpdate");
				// Check for update asynchronously using the AppUpdate class's singleton instance
				updateCheckResult = await Task.Run(AppUpdate.Instance.Check);
			}

			// If a new version is available or user supplied a custom MSIXBundle path to be installed
			if ((updateCheckResult is { IsNewVersionAvailable: true }) || useCustomMSIXBundlePath)
			{
				string msg1;

				if (useCustomMSIXBundlePath)
				{
					msg1 = GlobalVars.Rizz.GetString("InstallingCustomPath") + customMSIXBundlePath;
				}
				else
				{
					msg1 = GlobalVars.Rizz.GetString("VersionComparison") + App.currentAppVersion + GlobalVars.Rizz.GetString("WhileOnlineVersion") + updateCheckResult?.OnlineVersion + GlobalVars.Rizz.GetString("UpdatingApplication");
				}

				Logger.Write(msg1);
				UpdateStatusInfoBar.Message = msg1;

				WhatsNewInfoBar.IsOpen = true;

				string stagingArea = StagingArea.NewStagingArea("AppUpdate").ToString();

				// To store the latest MSIXBundle version download link after retrieving it from GitHub text file
				Uri onlineDownloadURL;

				// Location of the MSIXBundle package where it will be saved after downloading it from GitHub
				// Or in case user supplied a custom path, it will be assigned to this
				string AppControlManagerSavePath;

				DownloadProgressRingForMSIXFile.Visibility = Visibility.Visible;

				// If user did not supply a custom MSIXBundle file path
				if (!useCustomMSIXBundlePath)
				{

					using (HttpClient client = new SecHttpClient())
					{
						// Store the download link to the latest available version
						onlineDownloadURL = new Uri(await client.GetStringAsync(GlobalVars.AppUpdateDownloadLinkURL));
					}

					AppControlManagerSavePath = Path.Combine(stagingArea, "AppControlManager.msixbundle");

					UpdateStatusInfoBar.Message = GlobalVars.Rizz.GetString("DownloadingPackage");


					using (HttpClient client = new SecHttpClient())
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

					Logger.Write(GlobalVars.Rizz.GetString("DownloadSuccess") + AppControlManagerSavePath);
				}

				else
				{
					// Use the user-supplied MSIXBundle file path for installation source
					AppControlManagerSavePath = customMSIXBundlePath ?? throw new InvalidOperationException(GlobalVars.Rizz.GetString("NoMSIXBundlePath"));
				}

				DownloadProgressRingForMSIXFile.IsIndeterminate = true;

				UpdateStatusInfoBar.Message = GlobalVars.Rizz.GetString("DetectingSignTool");

				// First check if SignTool path is registered in the user configurations, else attempt to detect or download it
				string signToolPath = UserConfiguration.Get().SignToolCustomPath ?? await Task.Run(() => SignToolHelper.GetSignToolPath());

				UpdateStatusInfoBar.Message = GlobalVars.Rizz.GetString("DownloadsFinished");

				await Task.Run(() =>
				{
					// Random password to temporarily encrypt the private key of the newly generated certificate
					string PassWord = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUID();

					// Path where the .cer file will be saved
					string CertificateOutputPath = Path.Combine(stagingArea, $"{commonName}.cer");

					// Remove any certificates with the specified common name that may already exist on the system form previous attempts
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

					// Signing the App Control Manager package
					// In this step the SignTool detects the cert to use based on Common name + ThumbPrint + Hash Algo + Store Type + Store Name
					ProcessStarter.RunCommand(signToolPath, $"sign /debug /n \"{commonName}\" /fd Sha512 /sm /s Root /sha1 {generatedCert.Thumbprint} \"{AppControlManagerSavePath}\"");

					// Remove any certificates with the specified common name again
					// Because the existing one contains private keys and we don't want that
					CertificateGenerator.DeleteCertificateByCN(commonName);

					// Adding the certificate to the 'Local Machine/Trusted Root Certification Authorities' store with public key only.
					// This safely stores the certificate on your device, ensuring its private key does not exist so cannot be used to sign anything else.
					CertificateGenerator.StoreCertificateInStore(generatedCert, CertificateGenerator.CertificateStoreLocation.Machine, true);

					try
					{
						/*

						// Execute the query to get the MpPreferences
						using ManagementObjectSearcher searcher = new("ROOT\\Microsoft\\Windows\\Defender", $"SELECT AttackSurfaceReductionOnlyExclusions FROM MSFT_MpPreference");
						ManagementObjectCollection results = searcher.Get();

						// Retrieve the property value for AttackSurfaceReductionOnlyExclusions
						ManagementBaseObject? result = results.Cast<ManagementBaseObject>().FirstOrDefault();
						string[]? currentAttackSurfaceReductionExclusions = result?["AttackSurfaceReductionOnlyExclusions"] as string[];

						*/

						// TODO: Create a Native AOT compatible source generated COM code that won't rely on System.Management or PowerShell

						string ASRscript = "(Get-CimInstance -Namespace 'ROOT\\Microsoft\\Windows\\Defender' -Query 'SELECT AttackSurfaceReductionOnlyExclusions FROM MSFT_MpPreference').AttackSurfaceReductionOnlyExclusions -join ','";
						string ASRoutput = ProcessStarter.RunCommandWithOutput("powershell.exe", $"-NoProfile -Command \"{ASRscript}\"");

						// If there are ASR rule exclusions, find ones that belong to AppControl Manager and remove them
						// Before adding new ones for the new version
						if (!string.IsNullOrWhiteSpace(ASRoutput))
						{

							string[] ASRoutputArray = ASRoutput.Split(separator, StringSplitOptions.RemoveEmptyEntries);

							List<string> ASRoutputArrayCleaned = [];

							foreach (string item in ASRoutputArray)
							{
								ASRoutputArrayCleaned.Add(item.TrimStart().TrimEnd().TrimEnd('\r', '\n'));
							}

							List<string> asrRulesToRemove = [];

							// Find all the rules that belong to the AppControl Manager
							foreach (string item in ASRoutputArrayCleaned)
							{
								if (MyRegex1().Match(item).Success)
								{
									asrRulesToRemove.Add(item);
								}
							}

							// If any of the rules belong to the AppControl Manager
							if (asrRulesToRemove.Count > 0)
							{

								// Remove ASR rule exclusions that belong to all previous app versions

								/*

								using ManagementClass managementClass = new(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null);
								ManagementBaseObject inParams = managementClass.GetMethodParameters("Remove");
								inParams["AttackSurfaceReductionOnlyExclusions"] = stringArrayRepo;
								_ = managementClass.InvokeMethod("Remove", inParams, null);

								*/

								foreach (string item in asrRulesToRemove)
								{

									string script = $"Remove-MpPreference -AttackSurfaceReductionOnlyExclusions '{item}'";
									ProcessStarter.RunCommand("powershell.exe", $"-NoProfile -Command \"{script}\"");
								}
							}
						}
					}
					catch (Exception ex)
					{
						Logger.Write(GlobalVars.Rizz.GetString("ASRError") + ex.Message);
					}


					PackageManager packageManager = new();

					Logger.Write(GlobalVars.Rizz.GetString("InstallingPackage"));

					// https://learn.microsoft.com/en-us/uwp/api/windows.management.deployment.addpackageoptions
					AddPackageOptions options = new()
					{
						DeferRegistrationWhenPackagesAreInUse = true,
						ForceUpdateFromAnyVersion = true
					};

					IAsyncOperationWithProgress<DeploymentResult, DeploymentProgress> deploymentOperation = packageManager.AddPackageByUriAsync(new Uri(AppControlManagerSavePath), options);

					// This event is signaled when the operation completes
					ManualResetEvent opCompletedEvent = new(false);

					// Define the delegate using a statement lambda
					deploymentOperation.Completed = (depProgress, status) => { _ = opCompletedEvent.Set(); };

					// Wait until the operation completes
					_ = opCompletedEvent.WaitOne();

					// Check the status of the operation
					if (deploymentOperation.Status == AsyncStatus.Error)
					{
						DeploymentResult deploymentResult = deploymentOperation.GetResults();
						throw new InvalidOperationException(GlobalVars.Rizz.GetString("InstallationError") + deploymentOperation.ErrorCode + GlobalVars.Rizz.GetString("InstallationErrorText") + deploymentResult.ErrorText);
					}
					else if (deploymentOperation.Status == AsyncStatus.Canceled)
					{
						Logger.Write(GlobalVars.Rizz.GetString("InstallationCanceled"));
					}
					else if (deploymentOperation.Status == AsyncStatus.Completed)
					{
						Logger.Write(GlobalVars.Rizz.GetString("InstallationSucceeded"));
					}
					else
					{
						throw new InvalidOperationException(GlobalVars.Rizz.GetString("UnknownInstallationIssue"));
					}

					try
					{

						Package AppControlManagerPackage = packageManager.FindPackages("AppControlManager_sadt7br7jpt02").First();

						string AppControlInstallFolder = AppControlManagerPackage.EffectivePath;

						// Construct the paths to the .exe and .dll files of the AppControl Manager
						string path1 = Path.Combine(AppControlInstallFolder, "AppControlManager.exe");
						string path2 = Path.Combine(AppControlInstallFolder, "AppControlManager.dll");

						/*

						// Connect to the WMI namespace again
						ManagementScope scope = new(@"\\.\ROOT\Microsoft\Windows\Defender");
						scope.Connect();

						// Create an instance of the MSFT_MpPreference class for Add method
						using ManagementClass mpPreferenceClass = new(scope, new ManagementPath("MSFT_MpPreference"), null);


						// Get the available methods for the class
						ManagementBaseObject methodParams = mpPreferenceClass.GetMethodParameters("Add");

						// Create a string array containing the paths which is what AttackSurfaceReductionOnlyExclusions accepts
						methodParams["AttackSurfaceReductionOnlyExclusions"] = new string[] { path1, path2 };

						// Invoke the Add method to add the paths to the ASR rules exclusions
						_ = mpPreferenceClass.InvokeMethod("Add", methodParams, null);

						*/

						string script1 = $"Add-MpPreference -AttackSurfaceReductionOnlyExclusions '{path1}'";
						ProcessStarter.RunCommand("powershell.exe", $"-NoProfile -Command \"{script1}\"");

						string script2 = $"Add-MpPreference -AttackSurfaceReductionOnlyExclusions '{path2}'";
						ProcessStarter.RunCommand("powershell.exe", $"-NoProfile -Command \"{script2}\"");

					}
					catch (Exception ex)
					{
						Logger.Write(GlobalVars.Rizz.GetString("ASRAddError") + ex.Message);

					}
				});

				UpdateStatusInfoBar.Message = GlobalVars.Rizz.GetString("UpdateSuccess");
				UpdateStatusInfoBar.Severity = InfoBarSeverity.Success;

				GlobalVars.updateButtonTextOnTheUpdatePage = GlobalVars.Rizz.GetString("UpdatesInstalled");

				// Keep the CheckForUpdate button disabled since the update has been installed at this point
				// And all that's required is for the app to be restarted by the user
			}

			else
			{
				UpdateStatusInfoBar.Message = GlobalVars.Rizz.GetString("AlreadyUpdated");
				UpdateStatusInfoBar.Severity = InfoBarSeverity.Success;
				CheckForUpdateButton.IsEnabled = true;
			}
		}
		catch
		{
			UpdateStatusInfoBar.Severity = InfoBarSeverity.Error;
			UpdateStatusInfoBar.Message = GlobalVars.Rizz.GetString("UpdateCheckError");

			DownloadProgressRingForMSIXFile.Value = 0;

			CheckForUpdateButton.IsEnabled = true;

			WhatsNewInfoBar.IsOpen = false;

			throw;
		}
		finally
		{
			UpdateStatusInfoBar.IsClosable = true;

			DownloadProgressRingForMSIXFile.Visibility = Visibility.Collapsed;

			CheckForUpdate.IsClickEnabled = true;
		}
	}

	private static readonly char[] separator = [','];

	/// <summary>
	/// Event handler for the Auto Update Check Toggle Button to modify the app settings
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void AutoUpdateCheckToggle_Toggled(object sender, RoutedEventArgs e)
	{
		AppSettingsCls.SaveSetting(AppSettingsCls.SettingKeys.AutoCheckForUpdateAtStartup, AutoUpdateCheckToggle.IsOn);
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

		// Set the toggle for Auto Update Check based on app settings
		AutoUpdateCheckToggle.IsOn = AppSettingsCls.TryGetSetting<bool?>(AppSettingsCls.SettingKeys.AutoCheckForUpdateAtStartup) ?? true;

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
		AutoUpdateCheckToggle.IsOn = !AutoUpdateCheckToggle.IsOn;

		AppSettingsCls.SaveSetting(AppSettingsCls.SettingKeys.AutoCheckForUpdateAtStartup, AutoUpdateCheckToggle.IsOn);
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
