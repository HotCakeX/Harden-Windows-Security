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
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
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
namespace HardenSystemSecurity.ViewModels;
#endif

#if APP_CONTROL_MANAGER
namespace AppControlManager.ViewModels;
#endif

#pragma warning disable IDE0063
// Do not simplify using statements, keep them scoped for proper disposal otherwise files will be in use until the method is exited

internal sealed partial class UpdateVM : ViewModelBase
{
	internal readonly InfoBarSettings MainInfoBar = new();

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
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	/// <summary>
	/// Content of the main update button
	/// </summary>
	internal string UpdateButtonContent { get; set => SP(ref field, value); } = Atlas.GetStr("UpdateNavItem/ToolTipService/ToolTip");

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal double ProgressBarValue { get; set => SP(ref field, value); }

	internal bool ProgressBarIsIndeterminate { get; set => SP(ref field, value); }

	internal bool WhatsNewInfoBarIsOpen { get; set => SP(ref field, value); }

	internal Visibility RatingsSectionVisibility { get; set => SP(ref field, value); } = Atlas.PackageSource is 1 ? Visibility.Visible : Visibility.Collapsed;

	#endregion

	/// <summary>
	/// Event handler for check for update button
	/// </summary>
	internal async void CheckForUpdateButton_Click()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBar.IsClosable = false;

			if (Atlas.PackageSource is 1)
			{
				MainInfoBar.WriteInfo(Atlas.GetStr("CheckingForUpdateStore"));

				UpdateCheckResponse UpCheckResult = await AppUpdate.CheckStore();

				if (UpCheckResult.IsNewVersionAvailable)
				{
					MainInfoBar.WriteInfo(Atlas.GetStr("NewUpdateIsAvailableStore"));

					// https://learn.microsoft.com/windows/apps/develop/launch/launch-store-app#opening-to-a-specific-product
					Uri uri = new($"ms-windows-store://pdp/?ProductId={Atlas.StoreProductID}&mode=mini");

					bool launched = await Launcher.LaunchUriAsync(uri);

					if (!launched)
					{
						MainInfoBar.WriteWarning(Atlas.GetStr("ProblemOpeningMSStore"));
					}
				}
				else
				{
					MainInfoBar.WriteSuccess(Atlas.GetStr("TheAppIsUpToDate"));
				}
			}
			else
			{
#if APP_CONTROL_MANAGER

				string stagingArea = Directory.CreateDirectory(Path.Join(Microsoft.Windows.Storage.ApplicationData.GetDefault().MachinePath, "AppUpdate")).FullName;

				try
				{
					MainInfoBar.WriteInfo(Atlas.GetStr("CheckingForUpdate"));

					// Check for update asynchronously
					UpdateCheckResponse updateCheckResult = await Task.Run(AppUpdate.CheckGitHub);

					// If a new version is available
					if (updateCheckResult.IsNewVersionAvailable)
					{
						MainInfoBar.WriteInfo(Atlas.GetStr("VersionComparison") + Atlas.currentAppVersion + Atlas.GetStr("WhileOnlineVersion") + updateCheckResult.OnlineVersion + Atlas.GetStr("UpdatingApplication"));

						WhatsNewInfoBarIsOpen = true;

						// store the latest MSIXBundle version download link after retrieving it from GitHub text file
						Uri onlineDownloadURL = new(await SecHttpClient.Instance.GetStringAsync(Atlas.AppUpdateDownloadLinkURL));

						// Location of the MSIXBundle package where it will be saved after downloading it from GitHub
						string AppControlManagerSavePath = Path.Join(stagingArea, "AppControlManager.msixbundle");

						MainInfoBar.WriteInfo(Atlas.GetStr("DownloadingPackage"));

						ProgressBarIsIndeterminate = false;

						// Send an Async get request to the url and specify to stop reading after headers are received for better efficiency
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

												// Update the UI ProgressBar value
												ProgressBarValue = progressPercentage;
											}
										}
									}
								}
							}
						}

						MainInfoBar.WriteInfo(Atlas.GetStr("DownloadSuccess") + AppControlManagerSavePath);

						ProgressBarIsIndeterminate = true;

						MainInfoBar.WriteInfo(Atlas.GetStr("DownloadsFinished"));

						await InstallAppPackage(AppControlManagerSavePath, UseHardenedInstallationProcess, MainInfoBar);

						MainInfoBar.WriteSuccess(Atlas.GetStr("UpdateSuccess"));

						UpdateButtonContent = Atlas.GetStr("UpdatesInstalled");
					}
					else
					{
						MainInfoBar.WriteSuccess(Atlas.GetStr("AlreadyUpdated"));
					}
				}
				catch
				{
					WhatsNewInfoBarIsOpen = false;
					throw;
				}
				finally
				{
					Directory.Delete(stagingArea, true);
				}
#endif
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, Atlas.GetStr("UpdateCheckError"));
		}
		finally
		{
			ProgressBarValue = 0;
			ElementsAreEnabled = true;
			ProgressBarIsIndeterminate = true;
			MainInfoBar.IsClosable = true;
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
			Uri uri = new($"ms-windows-store://review/?ProductId={Atlas.StoreProductID}");

			bool launched = await Launcher.LaunchUriAsync(uri);

			if (!launched)
			{
				Logger.Write(Atlas.GetStr("FailedToOpenRating"));
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
			ASROutput = ProcessStarter.RunCommand(Atlas.ComManagerProcessPath, comCommand);

			// If there are ASR rule exclusions, find ones that belong to AppControl Manager and remove them
			if (!string.IsNullOrWhiteSpace(ASROutput))
			{
				// Deserialize the JSON string
				string[]? ASROutputArrayCleaned = JsonSerializer.Deserialize(ASROutput, MSDefenderJsonContext.Default.StringArray);

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
						string asrRulesToRemoveFinal = string.Join(" ", asrRulesToRemove.Select(static item => $"\"{item}\""));

						_ = ProcessStarter.RunCommand(Atlas.ComManagerProcessPath, $@"wmi stringarray ROOT\Microsoft\Windows\Defender MSFT_MpPreference remove AttackSurfaceReductionOnlyExclusions {asrRulesToRemoveFinal}");
					}
				}
			}
		}
		catch (JsonException Jex)
		{
			Logger.Write(string.Format(Atlas.GetStr("ASRRulesDeserializationFailedMessage"), ASROutput, Jex.Message));
		}
		catch (Exception ex)
		{
			Logger.Write(Atlas.GetStr("ASRError") + ex.Message);
		}
	}

	private static void AddASRExclusionsForAppControlManager(PackageManager packageManager)
	{
		try
		{
			// This correctly lists all packages for all users and gets the latest version package which we just installed which will be in staged state.
			Package? AppControlManagerPackage = packageManager.FindPackages("AppControlManager_sadt7br7jpt02")
				.OrderByDescending(static p => new Version(p.Id.Version.Major, p.Id.Version.Minor, p.Id.Version.Build, p.Id.Version.Revision))
				.FirstOrDefault();

			if (AppControlManagerPackage is null)
				return;

			string AppControlInstallFolder = AppControlManagerPackage.EffectivePath;

			// Construct the paths to the .exe and .dll files of the AppControl Manager
			string path1 = Path.Join(AppControlInstallFolder, "AppControlManager.exe");
			string path2 = Path.Join(AppControlInstallFolder, "AppControlManager.dll");
			string path3 = Path.Join(AppControlInstallFolder, "CppInterop", "ComManager.exe");

			// Adding the extra executables included in the package so they will be allowed to run as well
			_ = ProcessStarter.RunCommand(Atlas.ComManagerProcessPath, $"wmi stringarray ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference add AttackSurfaceReductionOnlyExclusions \"{path1}\" \"{path2}\" \"{path3}\" ");
		}
		catch (Exception ex)
		{
			Logger.Write(Atlas.GetStr("ASRAddError") + ex.Message);
		}
	}

	/// <summary>
	/// Navigate to the Package Installer sub-page.
	/// </summary>
	internal async void NavigateToAppPackageInstallerPage_Click() =>
		await ViewModelProvider.NavigationService.Navigate(typeof(Pages.UpdatePageCustomMSIXPath), null);

	/// <summary>
	/// Whether the installation process must use hardened procedures.
	/// </summary>
	internal bool UseHardenedInstallationProcess { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Common name of the on-device generated certificate used to sign the AppControl Manager MSIXBundle package.
	/// </summary>
	private const string CertCommonName = "SelfSignedCertForAppControlManager";

	internal readonly InfoBarSettings AppPackageInstallerInfoBar = new();

	/// <summary>
	/// The package path that the user supplied.
	/// </summary>
	internal string? LocalPackageFilePath { get; set => SP(ref field, value); }

	/// <summary>
	/// Opens a file picker to select a MSIX/MSIXBundle package file.
	/// </summary>
	internal void BrowseForCustomMSIXPathButton_Click() =>
		LocalPackageFilePath = FileDialogHelper.ShowFilePickerDialog(Atlas.AppPackagesPickerFilter);

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
			AppPackageInstallerInfoBar.IsClosable = false;
			await InstallAppPackage(LocalPackageFilePath, UseHardenedInstallationProcess, AppPackageInstallerInfoBar);
		}
		catch (Exception ex)
		{
			AppPackageInstallerInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			AppPackageInstallerInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Installs an app package from a user-supplied path.
	/// It can automatically detect if the package is signed or unsigned and perform signing if needed.
	/// </summary>
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

			int signerCount = possibleExistingSigners.Count;

			foreach (AllFileSigners signer in CollectionsMarshal.AsSpan(possibleExistingSigners))
			{
				signer.Dispose();
			}

			// Only attempt signing if the package doesn't already have signatures
			if (signerCount == 0)
			{
				LLPackageReader.PackageDetails packageDits = LLPackageReader.GetPackageDetails(packagePath);

				// Determine whether this is the AppControl Manager app package provided in GitHub releases that the user is trying to install
				isNonStoreACM = string.Equals(packageDits.CertCN, CertCommonName, StringComparison.Ordinal);

				infoBar.WriteInfo($"Package details retrieved. Package Publisher: '{packageDits.CertCN}', Package Family Name: '{packageDits.PackageFamilyName}', Package Version: '{packageDits.Version}', Package Hashing Algorithm: '{packageDits.HashAlgorithm}'.");

				// Remove any certificates with the specified common name that may already exist on the system from previous attempts
				CertificateGenerator.DeleteCertificateByCN(packageDits.CertCN);

				// Generate a certificate whose complete subject matches the manifest Publisher.
				using X509Certificate2 generatedCert = CertificateGenerator.GenerateSelfSignedCertificate(
				distinguishedName: packageDits.PublisherDistinguishedName,
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

			IAsyncOperationWithProgress<DeploymentResult, DeploymentProgress> deploymentOperation = packageManager.AddPackageByUriAsync(new(packagePath), options);

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

	#region Package Signature Removal

	internal readonly InfoBarSettings PackageSignatureRemovalInfoBar = new();

	internal string? PackageSignatureRemovalPath
	{
		get; set
		{
			if (SP(ref field, value))
			{
				SignatureSelectionIsBundle = string.Equals(Path.GetExtension(value), ".msixbundle", StringComparison.OrdinalIgnoreCase);
			}
		}
	}

	internal bool SignatureSelectionIsBundle { get; set => SP(ref field, value); }
	internal bool RemoveInnerPackageSignatures { get; set => SP(ref field, value); }

	internal void BrowseForSignatureRemoval_Click()
	{
		if (!ElementsAreEnabled)
		{
			return;
		}
		string? selected = FileDialogHelper.ShowFilePickerDialog(Atlas.AppPackagesPickerFilter);
		if (!string.IsNullOrWhiteSpace(selected))
		{
			PackageSignatureRemovalPath = selected;
		}
	}

	internal void Clear_PackageSignatureRemovalPath() => PackageSignatureRemovalPath = null;

	/// <summary>
	/// UI-bound handler for removing signatures from app packages.
	/// </summary>
	internal async void RemovePackageSignature_Click()
	{
		if (!ElementsAreEnabled)
		{
			return;
		}
		try
		{
			ElementsAreEnabled = false;
			PackageSignatureRemovalInfoBar.IsClosable = false;

			if (!File.Exists(PackageSignatureRemovalPath))
			{
				PackageSignatureRemovalInfoBar.WriteWarning("Browse for a package first.");
				return;
			}

			bool removeInner = SignatureSelectionIsBundle && RemoveInnerPackageSignatures;
			string extension = Path.GetExtension(PackageSignatureRemovalPath);

			string? destination = FileDialogHelper.ShowSaveFileDialog(
				$"Unsigned package (*{extension})|*{extension}",
				$"{Path.GetFileNameWithoutExtension(PackageSignatureRemovalPath)}-unsigned{extension}");

			if (string.IsNullOrWhiteSpace(destination))
			{
				return;
			}

			PackageSignatureRemovalInfoBar.WriteInfo(removeInner
				? "Removing inner signatures and rebuilding the bundle. The original will not be modified."
				: "Creating and validating an unsigned copy. The original and inner packages will not be modified.");

			bool removed = await Task.Run(() => CommonCore.Signing.PackageSignatureRemover.CreateUnsignedCopy(PackageSignatureRemovalPath, destination, removeInner));

			if (removed)
			{
				PackageSignatureRemovalInfoBar.WriteSuccess($"Unsigned copy saved to '{destination}'.");
			}
			else
			{
				PackageSignatureRemovalInfoBar.WriteWarning("No signature was found in the selected scope. No output was created.");
			}
		}
		catch (Exception ex)
		{
			PackageSignatureRemovalInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	#endregion

	#region Package Explorer

	/// <summary>
	/// Hide the empty explorer tree without a XAML converter or duplicated state.
	/// </summary>
	internal Visibility PackageContentVisibility(int count) => count > 0 ? Visibility.Visible : Visibility.Collapsed;

	internal string? PackageExplorerPath { get; set => SP(ref field, value); }

	/// <summary>
	/// Collection for the hierarchical XAML template.
	/// </summary>
	internal readonly ObservableCollection<CommonCore.Signing.PackageExplorerItem> PackageExplorerItems = new();

	internal readonly InfoBarSettings PackageExplorerInfoBar = new();

	/// <summary>
	/// Select a package and read its contents into a hierarchical collection for XAML display.
	/// </summary>
	internal async void BrowseForPackageExplorer_Click()
	{
		if (!ElementsAreEnabled)
		{
			return;
		}

		string? selected = FileDialogHelper.ShowFilePickerDialog(Atlas.AppPackagesPickerFilter);

		if (string.IsNullOrWhiteSpace(selected))
		{
			return;
		}
		try
		{
			ElementsAreEnabled = false;
			PackageExplorerInfoBar.IsClosable = false;

			PackageExplorerPath = selected;
			PackageExplorerItems.Clear();
			PackageExplorerInfoBar.WriteInfo("Reading the package contents.");
			CommonCore.Signing.PackageSignatureRemover.PackageTreeEntry contents = await Task.Run(
				() => CommonCore.Signing.PackageSignatureRemover.ReadPackageTree(selected));

			CommonCore.Signing.PackageExplorerItem root = CreatePackageExplorerItem(contents);

			root.IsExpanded = true;
			PackageExplorerItems.Add(root);
			PackageExplorerInfoBar.WriteSuccess("Expand folders and package nodes to inspect their contents.");
		}
		catch (Exception ex)
		{
			PackageExplorerItems.Clear();
			PackageExplorerInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Convert native-reader results to data-only items. Each XAML template creates
	/// its own icons and text controls. Nothing in this hierarchy has a visual parent.
	/// </summary>
	private static CommonCore.Signing.PackageExplorerItem CreatePackageExplorerItem(CommonCore.Signing.PackageSignatureRemover.PackageTreeEntry entry)
	{
		string sizeText = entry.Size.HasValue ? AppControlManager.ViewModels.HomeVM.FormatDataSize(entry.Size.Value) : string.Empty;
		string toolTip = entry.Size.HasValue ? $"{entry.Name} ({entry.Size.Value:N0} bytes)" : entry.Name;

		CommonCore.Signing.PackageExplorerItem item = new(entry.Name, sizeText, toolTip, entry.IsDirectory, entry.Children.Count);

		foreach (CommonCore.Signing.PackageSignatureRemover.PackageTreeEntry child in entry.Children)
		{
			item.Children.Add(CreatePackageExplorerItem(child));
		}
		return item;
	}

	internal void ClearPackageExplorer_Click()
	{
		PackageExplorerItems.Clear();
		PackageExplorerPath = null;
	}

	#endregion

	#region Package Version Editor

	/// <summary>
	/// Show selection guidance only when no content is loaded and the UI is idle.
	/// </summary>
	internal Visibility PackageEmptyStateVisibility(int count, bool enabled) => count is 0 && enabled ? Visibility.Visible : Visibility.Collapsed;

	internal readonly InfoBarSettings PackageVersionInfoBar = new();

	internal string? PackageVersionPath { get; set => SP(ref field, value); }

	internal readonly ObservableCollection<CommonCore.Signing.PackageVersionItem> PackageVersionItems = new();

	internal async void BrowseForPackageVersions_Click()
	{
		if (!ElementsAreEnabled)
		{
			return;
		}
		try
		{
			string? selected = FileDialogHelper.ShowFilePickerDialog(Atlas.AppPackagesPickerFilter);
			if (string.IsNullOrWhiteSpace(selected))
			{
				return;
			}
			ElementsAreEnabled = false;
			PackageVersionInfoBar.IsClosable = false;
			PackageVersionItems.Clear();
			PackageVersionPath = selected;
			PackageVersionInfoBar.WriteInfo("Reading package versions.");

			List<CommonCore.Signing.PackageVersionRecord> versions = await Task.Run(() => CommonCore.Signing.PackageSignatureRemover.ReadPackageVersions(selected));

			foreach (CommonCore.Signing.PackageVersionRecord version in versions)
			{
				PackageVersionItems.Add(new(version, SavePackageVersionAsync));
			}

			PackageVersionInfoBar.WriteSuccess("Each Save updates only that row in the selected file after validation. The modified package is unsigned.");
		}
		catch (Exception ex)
		{
			PackageVersionItems.Clear();
			PackageVersionInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	internal void ClearPackageVersions_Click()
	{
		PackageVersionItems.Clear();
		PackageVersionPath = null;
	}

	/// <summary>
	/// Awaited row callback; snapshots exactly one draft and never applies other rows.
	/// </summary>
	internal async Task SavePackageVersionAsync(CommonCore.Signing.PackageVersionItem row)
	{
		if (!ElementsAreEnabled)
		{
			return;
		}
		try
		{
			ElementsAreEnabled = false;
			PackageVersionInfoBar.IsClosable = false;

			string? source = PackageVersionPath;

			if (!File.Exists(source))
			{
				throw new FileNotFoundException("Browse for a package first.");
			}

			ulong version = CommonCore.Signing.PackageSignatureRemover.ParsePackageVersion(row.VersionText);
			ulong expectedVersion = row.OriginalVersion;
			if (version == expectedVersion)
			{
				PackageVersionInfoBar.WriteInfo("This row's version has not changed.");
				return;
			}
			string? innerName = row.InnerName;
			PackageVersionInfoBar.WriteInfo("Rebuilding and validating only the selected version change before replacing this package.");
			await Task.Run(() => CommonCore.Signing.PackageSignatureRemover.WritePackageVersionInPlace(source, innerName, expectedVersion, version));

			// Continue at the same path so later saves preserve earlier committed edits.
			// Other rows retain their unsaved text and are never submitted implicitly.
			row.AcceptVersion(version);
			PackageVersionInfoBar.WriteSuccess($"Saved '{row.DisplayName}' as {row.VersionText} in '{source}'. The package is now unsigned.");
		}
		catch (Exception ex)
		{
			PackageVersionInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	#endregion

}
