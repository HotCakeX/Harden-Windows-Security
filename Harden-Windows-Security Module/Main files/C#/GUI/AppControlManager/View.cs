using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media.Imaging;
using Windows.ApplicationModel;
using Windows.Management.Deployment;

#pragma warning disable IDE0063

namespace HardenWindowsSecurity;

public partial class GUIMain
{

	// Partial class definition for handling navigation and view models
	public partial class NavigationVM : ViewModelBase
	{

		// Method to handle the AppControlManager view, including loading
		private void AppControlManagerView(object obj)
		{

			// Check if the view is already cached
			if (_viewCache.TryGetValue("AppControlManagerView", out var cachedView))
			{
				CurrentView = cachedView;
				return;
			}

			// if Admin privileges are not available, return and do not proceed any further
			// Will prevent the page from being loaded since the CurrentView won't be set/changed
			if (!UserPrivCheck.IsAdmin())
			{
				Logger.LogMessage("AppControl Manager section can only be used when running the Harden Windows Security Application with Administrator privileges", LogTypeIntel.ErrorInteractionRequired);
				return;
			}

			// Construct the file path for the AppControlManager view XAML
			string xamlPath = Path.Combine(GlobalVars.path, "Resources", "XAML", "AppControlManager.xaml");

			// Read the XAML content from the file
			string xamlContent = File.ReadAllText(xamlPath);

			// Parse the XAML content to create a UserControl
			GUIAppControlManager.View = (UserControl)XamlReader.Parse(xamlContent);

			// Find the Parent Grid
			GUIAppControlManager.ParentGrid = (Grid)GUIAppControlManager.View.FindName("ParentGrid");

			// Finding other elements
			Button InstallAppControlManagerButton = GUIAppControlManager.ParentGrid.FindName("InstallAppControlManagerButton") as Button ?? throw new InvalidOperationException("InstallAppControlManagerButton could not be found in the AppControlManager view");
			Button ViewDemoOnYouTubeButton = GUIAppControlManager.ParentGrid.FindName("ViewDemoOnYouTubeButton") as Button ?? throw new InvalidOperationException("ViewDemoOnYouTubeButton could not be found in the AppControlManager view");
			Button AccessTheGuideOnGitHubButton = GUIAppControlManager.ParentGrid.FindName("AccessTheGuideOnGitHubButton") as Button ?? throw new InvalidOperationException("AccessTheGuideOnGitHubButton could not be found in the AppControlManager view");
			Image ViewDemoOnYouTubeButtonIcon = GUIAppControlManager.ParentGrid.FindName("ViewDemoOnYouTubeButtonIcon") as Image ?? throw new InvalidOperationException("ViewDemoOnYouTubeButtonIcon could not be found in the AppControlManager view");
			Image AccessTheGuideOnGitHubButtonIcon = GUIAppControlManager.ParentGrid.FindName("AccessTheGuideOnGitHubButtonIcon") as Image ?? throw new InvalidOperationException("AccessTheGuideOnGitHubButtonIcon could not be found in the AppControlManager view");
			Image InstallAppControlManagerButtonIcon = GUIAppControlManager.ParentGrid.FindName("InstallAppControlManagerButtonIcon") as Image ?? throw new InvalidOperationException("InstallAppControlManagerButtonIcon could not be found in the AppControlManager view");
			ProgressBar MainProgressBar = GUIAppControlManager.ParentGrid.FindName("MainProgressBar") as ProgressBar ?? throw new InvalidOperationException("MainProgressBar could not be found in the AppControlManager view");

			#region Assigning icon images for the buttons

			BitmapImage BitmapImage1 = new();
			BitmapImage1.BeginInit();
			BitmapImage1.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "YouTubeIcon.png"));
			BitmapImage1.CacheOption = BitmapCacheOption.OnLoad;
			BitmapImage1.EndInit();
			ViewDemoOnYouTubeButtonIcon.Source = BitmapImage1;

			BitmapImage BitmapImage2 = new();
			BitmapImage2.BeginInit();
			BitmapImage2.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "GitHubIcon.png"));
			BitmapImage2.CacheOption = BitmapCacheOption.OnLoad;
			BitmapImage2.EndInit();
			AccessTheGuideOnGitHubButtonIcon.Source = BitmapImage2;

			BitmapImage BitmapImage3 = new();
			BitmapImage3.BeginInit();
			BitmapImage3.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "InstallAppControlManagerIcon.png"));
			BitmapImage3.CacheOption = BitmapCacheOption.OnLoad;
			BitmapImage3.EndInit();
			InstallAppControlManagerButtonIcon.Source = BitmapImage3;

			#endregion

			// Register the elements that will be enabled/disabled based on current activity
			ActivityTracker.RegisterUIElement(InstallAppControlManagerButton);

			// Event handler for the Install button
			InstallAppControlManagerButton.Click += async (sender, e) =>
			{
				// Only continue if there is no activity other places
				if (ActivityTracker.IsActive)
				{
					return;
				}

				// mark as activity started
				ActivityTracker.IsActive = true;

				try
				{

					#region Ensure the app is not already installed

					bool alreadyInstalled = false;
					Package? PossibleExistingPackage = null;

					await Task.Run(() =>
					{
						IEnumerable<Package> PossibleExistingApp = GUIAppControlManager.packageMgr.FindPackages("AppControlManager", "CN=SelfSignedCertForAppControlManager");

						PossibleExistingPackage = PossibleExistingApp.FirstOrDefault();

						alreadyInstalled = PossibleExistingPackage is not null;
					});

					if (alreadyInstalled)
					{
						Logger.LogMessage($"AppControl Manager version {PossibleExistingPackage?.Id.Version.Major}.{PossibleExistingPackage?.Id.Version.Minor}.{PossibleExistingPackage?.Id.Version.Build}.{PossibleExistingPackage?.Id.Version.Revision} is already installed. If you want to update it, please start the AppControl Manager then navigate to the Update page to update it. If you want to reinstall it, please uninstall it first.", LogTypeIntel.InformationInteractionRequired);
						return;
					}

					#endregion



					using HttpClient client1 = new();

					Logger.LogMessage("Getting the download link from GitHub", LogTypeIntel.Information);

					// Store the download link to the latest available version
					Uri onlineDownloadURL = new(await client1.GetStringAsync(GUIAppControlManager.AppUpdateDownloadLinkURL));

					// The Uri will be used to detect the version and architecture of the MSIX package being installed
					string sourceForRegex = onlineDownloadURL.ToString();

					Logger.LogMessage("Downloading the AppControl Manager MSIX package...", LogTypeIntel.Information);

					string AppControlManagerSavePath = Path.Combine(GlobalVars.WorkingDir, "AppControlManager.msix");

					MainProgressBar.Visibility = Visibility.Visible;

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

												Application.Current.Dispatcher.Invoke(() =>
											   {
												   MainProgressBar.Value = progressPercentage;
											   });
											}
										}
									}
								}
							}
						}
					}

					Logger.LogMessage($"The AppControl Manager MSIX package has been successfully downloaded to {AppControlManagerSavePath}", LogTypeIntel.Information);

					MainProgressBar.Visibility = Visibility.Collapsed;

					Logger.LogMessage("Detecting/Downloading the SignTool.exe from the Microsoft servers", LogTypeIntel.Information);

					string signToolPath = await Task.Run(() => SignToolHelper.GetSignToolPath());

					Logger.LogMessage("All Downloads finished, installing the new AppControl Manager version", LogTypeIntel.Information);

					await Task.Run(() =>
					{

						string randomPassword = Guid.NewGuid().ToString("N");

						// Common name of the certificate
						string commonName = "SelfSignedCertForAppControlManager";

						// Path where the .cer file will be saved
						string CertificateOutputPath = Path.Combine(GlobalVars.WorkingDir, $"{commonName}.cer");

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
						UserProtectedPrivateKey: false,
						ExportablePrivateKey: false);

						// Get the version and architecture of the installing MSIX package app
						Match RegexMatch = GUIAppControlManager.regex.Match(sourceForRegex);

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

						// Remove any certificates with the specified common name again
						// Because the existing one contains private keys and don't want that
						CertificateGenerator.DeleteCertificateByCN(commonName);

						// Adding the certificate to the 'Local Machine/Trusted Root Certification Authorities' store with public key only. This safely stores the certificate on your device, ensuring its private key does not exist so cannot be used to sign anything else
						CertificateGenerator.StoreCertificateInStore(generatedCert, CertificateGenerator.CertificateStoreLocation.Machine, true);

						try
						{

							// Get the current Defender configurations
							GlobalVars.MDAVPreferencesCurrent = MpPreferenceHelper.GetMpPreference();

							// Get the current ASR Rules Exclusions lists
							string[]? currentAttackSurfaceReductionExclusions = PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "AttackSurfaceReductionOnlyExclusions");

							// If there are ASR rule exclusions, find ones that belong to AppControl Manager and remove them
							// Before adding new ones for the new version
							if (currentAttackSurfaceReductionExclusions is not null)
							{

								List<string> asrRulesToRemove = [];

								// Find all the rules that belong to the AppControl Manager
								foreach (string item in currentAttackSurfaceReductionExclusions)
								{
									if (Regex.Match(item, "__sadt7br7jpt02").Success)
									{
										asrRulesToRemove.Add(item);
									}
								}

								// If any of the rules belong to the AppControl Manager
								if (asrRulesToRemove.Count > 0)
								{
									string[] stringArrayRepo = [.. asrRulesToRemove];

									// Remove ASR rule exclusions that belong to the previous app version
									using ManagementClass managementClass = new(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null);
									ManagementBaseObject inParams = managementClass.GetMethodParameters("Remove");
									inParams["AttackSurfaceReductionOnlyExclusions"] = stringArrayRepo;
									_ = managementClass.InvokeMethod("Remove", inParams, null);
								}
							}


							#region Add new exclusions

							StringBuilder InstallingAppLocationToAdd = new();
							_ = InstallingAppLocationToAdd.Append("C:\\Program Files\\WindowsApps\\AppControlManager_");
							_ = InstallingAppLocationToAdd.Append(InstallingAppVersion);
							_ = InstallingAppLocationToAdd.Append('_');
							_ = InstallingAppLocationToAdd.Append(InstallingAppArchitecture);
							_ = InstallingAppLocationToAdd.Append("__sadt7br7jpt02\\");

							string path1 = Path.Combine(InstallingAppLocationToAdd.ToString(), "AppControlManager.exe");
							string path2 = Path.Combine(InstallingAppLocationToAdd.ToString(), "AppControlManager.dll");

							ConfigDefenderHelper.ManageMpPreference("AttackSurfaceReductionOnlyExclusions", new string[] { path1, path2 }, false);

							#endregion

						}

						catch (Exception ex)
						{
							Logger.LogMessage($"An error occurred while trying to add the ASR rule exclusions which you can ignore: {ex.Message}", LogTypeIntel.Information);
						}


						Logger.LogMessage($"Installing AppControl Manager MSIX package version '{InstallingAppVersion}' with architecture '{InstallingAppArchitecture}'", LogTypeIntel.Information);

						// https://learn.microsoft.com/en-us/uwp/api/windows.management.deployment.addpackageoptions
						AddPackageOptions options = new()
						{
							DeferRegistrationWhenPackagesAreInUse = false,
							ForceUpdateFromAnyVersion = true
						};

						_ = GUIAppControlManager.packageMgr.AddPackageByUriAsync(new Uri(AppControlManagerSavePath), options);

						Logger.LogMessage($"AppControl Manager installation has been successful.", LogTypeIntel.InformationInteractionRequired);

					});
				}

				finally
				{
					// mark as activity completed
					ActivityTracker.IsActive = false;
				}
			};


			ViewDemoOnYouTubeButton.Click += (sender, e) =>
			{
				_ = Process.Start(new ProcessStartInfo
				{
					FileName = "https://youtu.be/SzMs13n7elE?si=S70QiB5ZlYdhMk9r",
					UseShellExecute = true // Ensure the link opens in the default browser
				});
			};


			AccessTheGuideOnGitHubButton.Click += (sender, e) =>
			{
				_ = Process.Start(new ProcessStartInfo
				{
					FileName = "https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager",
					UseShellExecute = true // Ensure the link opens in the default browser
				});
			};


			// Cache the view before setting it as the CurrentView
			_viewCache["AppControlManagerView"] = GUIAppControlManager.View;

			// Set the CurrentView to the Protect view
			CurrentView = GUIAppControlManager.View;
		}
	}
}
