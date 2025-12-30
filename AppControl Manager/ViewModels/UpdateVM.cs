// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel;
using Windows.Foundation;
using Windows.Management.Deployment;
using Windows.System;

#if HARDEN_SYSTEM_SECURITY
using HardenSystemSecurity.Others;
using AppControlManager.ViewModels;
namespace HardenSystemSecurity.ViewModels;
#endif

#if APP_CONTROL_MANAGER
namespace AppControlManager.ViewModels;
#endif

#pragma warning disable IDE0063
// Do not simplify using statements, keep them scoped for proper disposal otherwise files will be in use until the method is exited

internal sealed partial class UpdateVM : ViewModelBase
{
	internal UpdateVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		AppPackageInstallerInfoBar = new InfoBarSettings(
			() => AppPackageInstallerInfoBarIsOpen, value => AppPackageInstallerInfoBarIsOpen = value,
			() => AppPackageInstallerInfoBarMessage, value => AppPackageInstallerInfoBarMessage = value,
			() => AppPackageInstallerInfoBarSeverity, value => AppPackageInstallerInfoBarSeverity = value,
			() => AppPackageInstallerInfoBarIsClosable, value => AppPackageInstallerInfoBarIsClosable = value,
			Dispatcher, null, null);
	}

	internal readonly InfoBarSettings MainInfoBar;

	#region UI-Bound Properties

	/// <summary>
	/// Whether the UI elements are enabled or disabled.
	/// </summary>
	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				MainInfoBarIsClosable = field;
				AppPackageInstallerInfoBarIsClosable = field;
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	/// <summary>
	/// Content of the main update button
	/// </summary>
	internal string UpdateButtonContent { get; set => SP(ref field, value); } = GlobalVars.GetStr("UpdateNavItem/ToolTipService/ToolTip");

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal double ProgressBarValue { get; set => SP(ref field, value); }

	internal bool ProgressBarIsIndeterminate { get; set => SP(ref field, value); }

	internal bool WhatsNewInfoBarIsOpen { get; set => SP(ref field, value); }

	internal Visibility RatingsSectionVisibility { get; set => SP(ref field, value); } = App.PackageSource is 1 ? Visibility.Visible : Visibility.Collapsed;

	#endregion

	/// <summary>
	/// Event handler for check for update button
	/// </summary>
	internal async void CheckForUpdateButton_Click()
	{
		try
		{
			ElementsAreEnabled = false;

			if (App.PackageSource is 1)
			{
				MainInfoBar.WriteInfo(GlobalVars.GetStr("CheckingForUpdateStore"));

				UpdateCheckResponse UpCheckResult = await AppUpdate.CheckStore();

				if (UpCheckResult.IsNewVersionAvailable)
				{
					MainInfoBar.WriteInfo(GlobalVars.GetStr("NewUpdateIsAvailableStore"));

					// https://learn.microsoft.com/windows/apps/develop/launch/launch-store-app#opening-to-a-specific-product
					Uri uri = new($"ms-windows-store://pdp/?ProductId={GlobalVars.StoreProductID}&mode=mini");

					bool launched = await Launcher.LaunchUriAsync(uri);

					if (!launched)
					{
						MainInfoBar.WriteWarning(GlobalVars.GetStr("ProblemOpeningMSStore"));
					}
				}
				else
				{
					MainInfoBar.WriteSuccess(GlobalVars.GetStr("TheAppIsUpToDate"));
				}
			}
			else
			{
#if APP_CONTROL_MANAGER
				try
				{
					MainInfoBar.WriteInfo(GlobalVars.GetStr("CheckingForUpdate"));

					// Check for update asynchronously
					UpdateCheckResponse updateCheckResult = await Task.Run(AppUpdate.CheckGitHub);

					// If a new version is available
					if (updateCheckResult.IsNewVersionAvailable)
					{
						MainInfoBar.WriteInfo(GlobalVars.GetStr("VersionComparison") + App.currentAppVersion + GlobalVars.GetStr("WhileOnlineVersion") + updateCheckResult.OnlineVersion + GlobalVars.GetStr("UpdatingApplication"));

						WhatsNewInfoBarIsOpen = true;

						string stagingArea = StagingArea.NewStagingArea("AppUpdate").ToString();

						// store the latest MSIXBundle version download link after retrieving it from GitHub text file
						Uri onlineDownloadURL = new(await SecHttpClient.Instance.GetStringAsync(GlobalVars.AppUpdateDownloadLinkURL));

						// Location of the MSIXBundle package where it will be saved after downloading it from GitHub
						string AppControlManagerSavePath = Path.Combine(stagingArea, "AppControlManager.msixbundle");

						MainInfoBar.WriteInfo(GlobalVars.GetStr("DownloadingPackage"));

						ProgressBarIsIndeterminate = false;

						// Send an Async get request to the url and specify to stop reading after headers are received for better efficiently
						using (HttpResponseMessage response = await SecHttpClient.Instance.GetAsync(onlineDownloadURL, HttpCompletionOption.ResponseHeadersRead))
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
												_ = Dispatcher.TryEnqueue(() =>
												{
													ProgressBarValue = progressPercentage;
												});
											}
										}
									}
								}
							}
						}

						MainInfoBar.WriteInfo(GlobalVars.GetStr("DownloadSuccess") + AppControlManagerSavePath);

						ProgressBarIsIndeterminate = true;

						MainInfoBar.WriteInfo(GlobalVars.GetStr("DownloadsFinished"));

						await InstallAppPackage(AppControlManagerSavePath, UseHardenedInstallationProcess, MainInfoBar);

						MainInfoBar.WriteSuccess(GlobalVars.GetStr("UpdateSuccess"));

						UpdateButtonContent = GlobalVars.GetStr("UpdatesInstalled");
					}
					else
					{
						MainInfoBar.WriteSuccess(GlobalVars.GetStr("AlreadyUpdated"));
					}
				}
				catch
				{
					WhatsNewInfoBarIsOpen = false;
					throw;
				}
#endif
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("UpdateCheckError"));
		}
		finally
		{
			ProgressBarValue = 0;
			ElementsAreEnabled = true;
			ProgressBarIsIndeterminate = true;
		}
	}

	/// <summary>
	/// Launches the Microsoft Store mini page of the app where user can review and rate.
	/// </summary>
	internal async void LaunchRating()
	{
		try
		{
			// https://learn.microsoft.com/windows/apps/develop/launch/launch-store-app#opening-to-a-specific-product
			Uri uri = new($"ms-windows-store://review/?ProductId={GlobalVars.StoreProductID}");

			bool launched = await Launcher.LaunchUriAsync(uri);

			if (!launched)
			{
				Logger.Write(GlobalVars.GetStr("FailedToOpenRating"));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	#region App Package Installer's Page

	[JsonSourceGenerationOptions(WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
	[JsonSerializable(typeof(string[]))] // Used to deserialize MS Defender results
	private sealed partial class MSDefenderJsonContext : JsonSerializerContext
	{
	}

	/// <summary>
	/// Removes any existing ASR rule exclusions that belong to the AppControl Manager, non-store version.
	/// </summary>
	private static void RemoveExistingAppControlManagerASRExclusions()
	{
		string? ASROutput = null;

		const string comCommand = "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference AttackSurfaceReductionOnlyExclusions";

		try
		{
			ASROutput = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, comCommand);

			// If there are ASR rule exclusions, find ones that belong to AppControl Manager and remove them
			if (!string.IsNullOrWhiteSpace(ASROutput))
			{
				// Deserialize the JSON string
				string[]? ASROutputArrayCleaned = JsonSerializer.Deserialize(ASROutput, MSDefenderJsonContext.Default.StringArray) as string[];

				// If there were ASR rules exceptions
				if (ASROutputArrayCleaned is not null && ASROutputArrayCleaned.Length > 0)
				{
					List<string> asrRulesToRemove = [];

					// Find all the rules that belong to the AppControl Manager
					foreach (string item in ASROutputArrayCleaned)
					{
						if (item.Contains("__sadt7br7jpt02", StringComparison.OrdinalIgnoreCase))
						{
							asrRulesToRemove.Add(item);
						}
					}

					// If any of the rules belong to the AppControl Manager
					if (asrRulesToRemove.Count > 0)
					{
						// Wrap them with double quotes and separate them with a space
						string asrRulesToRemoveFinal = string.Join(" ", asrRulesToRemove.Select(item => $"\"{item}\""));

						_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $@"wmi stringarray ROOT\Microsoft\Windows\Defender MSFT_MpPreference remove AttackSurfaceReductionOnlyExclusions {asrRulesToRemoveFinal}");
					}
				}
			}
		}
		catch (JsonException Jex)
		{
			Logger.Write(string.Format(GlobalVars.GetStr("ASRRulesDeserializationFailedMessage"), ASROutput, Jex.Message));
		}
		catch (Exception ex)
		{
			Logger.Write(GlobalVars.GetStr("ASRError") + ex.Message);
		}
	}

	private static void AddASRExclusionsForAppControlManager(PackageManager packageManager)
	{
		try
		{
			// This correctly lists all packages for all users and gets the latest version package which we just installed which will be in staged state.
			Package? AppControlManagerPackage = packageManager.FindPackages("AppControlManager_sadt7br7jpt02")
				.OrderByDescending(p => new Version(p.Id.Version.Major, p.Id.Version.Minor, p.Id.Version.Build, p.Id.Version.Revision))
				.FirstOrDefault();

			if (AppControlManagerPackage is null)
				return;

			string AppControlInstallFolder = AppControlManagerPackage.EffectivePath;

			// Construct the paths to the .exe and .dll files of the AppControl Manager
			string path1 = Path.Combine(AppControlInstallFolder, "AppControlManager.exe");
			string path2 = Path.Combine(AppControlInstallFolder, "AppControlManager.dll");
			string path3 = Path.Combine(AppControlInstallFolder, "CppInterop", "ComManager.exe");

			// Adding the extra executables included in the package so they will be allowed to run as well
			_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"wmi stringarray ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference add AttackSurfaceReductionOnlyExclusions \"{path1}\" \"{path2}\" \"{path3}\" ");
		}
		catch (Exception ex)
		{
			Logger.Write(GlobalVars.GetStr("ASRAddError") + ex.Message);
		}
	}

	/// <summary>
	/// Navigate to the Package Installer sub-page.
	/// </summary>
	internal void NavigateToAppPackageInstallerPage_Click() =>
		ViewModelProvider.NavigationService.Navigate(typeof(Pages.UpdatePageCustomMSIXPath), null);

	/// <summary>
	/// Whether the installation process must use hardened procedures.
	/// </summary>
	internal bool UseHardenedInstallationProcess { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Common name of the on-device generated certificate used to sign the AppControl Manager MSIXBundle package.
	/// </summary>
	private const string CertCommonName = "SelfSignedCertForAppControlManager";

	internal readonly InfoBarSettings AppPackageInstallerInfoBar;
	internal bool AppPackageInstallerInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? AppPackageInstallerInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity AppPackageInstallerInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool AppPackageInstallerInfoBarIsClosable { get; set => SP(ref field, value); }

	/// <summary>
	/// The package path that the user supplied.
	/// </summary>
	internal string? LocalPackageFilePath { get; set => SP(ref field, value); }

	/// <summary>
	/// Opens a file picker to select a MSIX/MSIXBundle package file.
	/// </summary>
	internal void BrowseForCustomMSIXPathButton_Click() =>
		LocalPackageFilePath = FileDialogHelper.ShowFilePickerDialog("MSIX/MSIXBundle files|*.msixbundle;*.msix");

	/// <summary>
	/// Event handler to clear the selected file path.
	/// </summary>
	internal void ClearSelectedFilePath() => LocalPackageFilePath = null;

	/// <summary>
	/// Event handler for the UI button.
	/// </summary>
	internal async void InstallButton_Click()
	{
		try
		{
			ElementsAreEnabled = false;
			await InstallAppPackage(LocalPackageFilePath, UseHardenedInstallationProcess, AppPackageInstallerInfoBar);
		}
		catch (Exception ex)
		{
			AppPackageInstallerInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Installs an app package from a user-supplied path.
	/// It can automatically detect if the package is signed or unsigned and perform signing if needed.
	/// </summary>
	/// <param name="packagePath"></param>
	/// <exception cref="InvalidOperationException"></exception>
	private static async Task InstallAppPackage(
		string? packagePath,
		bool UseHardenedInstallationProcess,
		InfoBarSettings infoBar)
	{
		if (packagePath is null)
		{
			throw new InvalidOperationException("You must provide a valid package path.");
		}

		await Task.Run(() =>
		{
			bool isNonStoreACM = false;

			infoBar.WriteInfo($"Getting the package details for: '{packagePath}'");

			List<AllFileSigners> possibleExistingSigners = AllCertificatesGrabber.GetAllFileSigners(packagePath);

			// Only attempt signing if the package doesn't already have signatures
			if (possibleExistingSigners.Count == 0)
			{
				LLPackageReader.PackageDetails packageDits = LLPackageReader.GetPackageDetails(packagePath);

				// Determine whether this is the AppControl Manager app package provided in GitHub releases that the user is trying to install
				isNonStoreACM = string.Equals(packageDits.CertCN, CertCommonName, StringComparison.Ordinal);

				infoBar.WriteInfo($"Package details retrieved. Package Publisher: '{packageDits.CertCN}', Package Hashing Algorithm: '{packageDits.HashAlgorithm}'.");

				// Remove any certificates with the specified common name that may already exist on the system form previous attempts
				CertificateGenerator.DeleteCertificateByCN(packageDits.CertCN);

				// Generate a new certificate
				using X509Certificate2 generatedCert = CertificateGenerator.GenerateSelfSignedCertificate(
				subjectName: packageDits.CertCN,
				validityInYears: 100,
				keySize: 4096,
				hashAlgorithm: packageDits.HashAlgorithm,
				storeLocation: CertificateGenerator.CertificateStoreLocation.Machine,
				cerExportFilePath: null,
				friendlyName: packageDits.CertCN,
				UserProtectedPrivateKey: UseHardenedInstallationProcess,
				ExportablePrivateKey: false);

				// Sign the package
				CommonCore.Signing.Main.SignAppPackage(packagePath, generatedCert);

				// Remove any certificates with the specified common name again
				// Because the existing one contains private keys and we don't want that
				CertificateGenerator.DeleteCertificateByCN(packageDits.CertCN);

				// Adding the certificate to the 'Local Machine/Trusted Root Certification Authorities' store with public key only.
				// This safely stores the certificate on your device, ensuring its private key does not exist so cannot be used to sign anything else.
				CertificateGenerator.StoreCertificateInStore(generatedCert, CertificateGenerator.CertificateStoreLocation.Machine, true);
			}
			else
			{
				infoBar.WriteInfo("The package is already signed. Proceeding with installation.");
			}

			PackageManager packageManager = new();

			infoBar.WriteInfo($"Installing '{packagePath}'");

			// https://learn.microsoft.com/uwp/api/windows.management.deployment.addpackageoptions
			AddPackageOptions options = new()
			{
				DeferRegistrationWhenPackagesAreInUse = true,
				ForceUpdateFromAnyVersion = true
			};

			IAsyncOperationWithProgress<DeploymentResult, DeploymentProgress> deploymentOperation = packageManager.AddPackageByUriAsync(new Uri(packagePath), options);

			// This event is signaled when the operation completes
			using ManualResetEvent opCompletedEvent = new(false);

			// The delegate
			deploymentOperation.Completed = (depProgress, status) => { _ = opCompletedEvent.Set(); };

			// Wait until the operation completes
			_ = opCompletedEvent.WaitOne();

			// Check the status of the operation
			if (deploymentOperation.Status == AsyncStatus.Error)
			{
				DeploymentResult deploymentResult = deploymentOperation.GetResults();
				throw new InvalidOperationException($"There was a problem installing '{packagePath}': {deploymentOperation.ErrorCode} - {deploymentResult.ErrorText}");
			}
			else if (deploymentOperation.Status == AsyncStatus.Canceled)
			{
				infoBar.WriteWarning("App installation was cancelled.");
			}
			else if (deploymentOperation.Status == AsyncStatus.Completed)
			{
				infoBar.WriteSuccess($"Successfully installed '{packagePath}'");
			}
			else
			{
				throw new InvalidOperationException($"There was an unknown problem installing '{packagePath}'");
			}

			if (isNonStoreACM)
			{
				RemoveExistingAppControlManagerASRExclusions();
				AddASRExclusionsForAppControlManager(packageManager);
			}
		});
	}

	#endregion

}
