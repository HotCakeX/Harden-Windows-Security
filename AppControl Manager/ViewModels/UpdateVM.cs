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

using System.IO;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.System;
using System.Text.Json.Serialization;

#if HARDEN_SYSTEM_SECURITY
using HardenSystemSecurity.Others;
using AppControlManager.ViewModels;
namespace HardenSystemSecurity.ViewModels;
#endif

#if APP_CONTROL_MANAGER
using Windows.ApplicationModel;
using Windows.Foundation;
using Windows.Management.Deployment;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
namespace AppControlManager.ViewModels;
#endif

#pragma warning disable IDE0063
// Do not simplify using statements, keep them scoped for proper disposal otherwise files will be in use until the method is exited

internal sealed partial class UpdateVM : ViewModelBase
{

	[JsonSourceGenerationOptions(WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
	[JsonSerializable(typeof(string[]))] // Used to deserialize MS Defender results
	private sealed partial class MSDefenderJsonContext : JsonSerializerContext
	{
	}

	internal UpdateVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);
	}

	internal readonly InfoBarSettings MainInfoBar;

#if APP_CONTROL_MANAGER
	/// <summary>
	/// Pattern for finding ASR rules that belong to the AppControl Manager
	/// </summary>
	/// <returns></returns>
	[GeneratedRegex("__sadt7br7jpt02", RegexOptions.IgnoreCase)]
	internal partial Regex AppPFNRegex();

	/// <summary>
	/// Navigate to the extra sub-page
	/// </summary>
	internal void CheckForUpdate_Click()
	{
		ViewModelProvider.NavigationService.Navigate(typeof(Pages.UpdatePageCustomMSIXPath), null);
	}
#endif

	/// <summary>
	/// Common name of the on-device generated certificate used to sign the AppControl Manager MSIXBundle package
	/// </summary>
	internal const string CertCommonName = "SelfSignedCertForAppControlManager";

	#region UI-Bound Properties

	/// <summary>
	/// To determine whether to use the user-supplied package or continue with downloading the package from GitHub.
	/// </summary>
	internal bool CheckForUpdateButtonIsEnabled
	{
		get; set => SP(ref field, value);
	} = true;

	internal bool CheckForUpdateSettingsCardIsClickable
	{
		get; set => SP(ref field, value);
	} = App.PackageSource is 0;

	/// <summary>
	/// Content of the main update button
	/// </summary>
	internal string UpdateButtonContent { get; set => SP(ref field, value); } = GlobalVars.GetStr("UpdateNavItem/ToolTipService/ToolTip");

	/// <summary>
	/// To determine whether to use the user-supplied package or continue with downloading the package from GitHub.
	/// </summary>
	internal bool InstallLocalPackageConfirmation
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				// Change the update button's text based on the file path
				UpdateButtonContent = field ? $"Install {Path.GetFileName(LocalPackageFilePath)}" : GlobalVars.GetStr("UpdateNavItem/ToolTipService/ToolTip");
			}
		}
	}

	/// <summary>
	/// The custom package path that the user supplied.
	/// </summary>
	internal string? LocalPackageFilePath
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				bool ok = !string.IsNullOrEmpty(field);

				// Set the enabled/disabled state of the confirmation section based on file path availability.
				InstallLocalPackageConfirmationIsEnabled = ok;

				// If the file path is emptied, the confirmation toggle must be off.
				if (!ok)
				{
					InstallLocalPackageConfirmation = false;
				}
			}
		}
	}

	/// <summary>
	/// Whether the section that provides confirmation ability is enabled or disabled
	/// </summary>
	internal bool InstallLocalPackageConfirmationIsEnabled { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the installation process must use hardened procedures.
	/// </summary>
	internal bool UseHardenedInstallationProcess { get; set => SP(ref field, value); }

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal double ProgressBarValue { get; set => SP(ref field, value); }

	internal bool ProgressBarIsIndeterminate { get; set => SP(ref field, value); }

	internal bool WhatsNewInfoBarIsOpen { get; set => SP(ref field, value); }

	internal Visibility HardenedProcedureSectionVisibility { get; set => SP(ref field, value); } = App.PackageSource is 0 ? Visibility.Visible : Visibility.Collapsed;

	internal Visibility RatingsSectionVisibility { get; set => SP(ref field, value); } = App.PackageSource is 1 ? Visibility.Visible : Visibility.Collapsed;

	#endregion

	/// <summary>
	/// Event handler for check for update button
	/// </summary>
	internal async void CheckForUpdateButton_Click()
	{
		if (App.PackageSource is 1)
		{
			try
			{
				CheckForUpdateButtonIsEnabled = false;
				MainInfoBarIsClosable = false;

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
			catch (Exception ex)
			{
				MainInfoBar.WriteError(ex, GlobalVars.GetStr("UpdateCheckError"));
			}
			finally
			{
				CheckForUpdateButtonIsEnabled = true;
				MainInfoBarIsClosable = true;
			}
		}
		else
		{
#if APP_CONTROL_MANAGER
			try
			{
				CheckForUpdateButtonIsEnabled = false;
				CheckForUpdateSettingsCardIsClickable = false;
				MainInfoBarIsClosable = false;

				// variable to store the update results
				UpdateCheckResponse? updateCheckResult = null;

				// If user did not provide custom MSIXBundle path, start checking for update
				if (!InstallLocalPackageConfirmation)
				{
					MainInfoBar.WriteInfo(GlobalVars.GetStr("CheckingForUpdate"));

					// Check for update asynchronously
					updateCheckResult = await Task.Run(AppUpdate.CheckGitHub);
				}

				// If a new version is available or user supplied a custom MSIXBundle path to be installed
				if ((updateCheckResult is { IsNewVersionAvailable: true }) || InstallLocalPackageConfirmation)
				{
					if (InstallLocalPackageConfirmation)
					{
						MainInfoBar.WriteInfo(GlobalVars.GetStr("InstallingCustomPath") + LocalPackageFilePath);
					}
					else
					{
						MainInfoBar.WriteInfo(GlobalVars.GetStr("VersionComparison") + App.currentAppVersion + GlobalVars.GetStr("WhileOnlineVersion") + updateCheckResult?.OnlineVersion + GlobalVars.GetStr("UpdatingApplication"));
					}

					WhatsNewInfoBarIsOpen = true;

					string stagingArea = StagingArea.NewStagingArea("AppUpdate").ToString();

					// To store the latest MSIXBundle version download link after retrieving it from GitHub text file
					Uri onlineDownloadURL;

					// Location of the MSIXBundle package where it will be saved after downloading it from GitHub
					// Or in case user supplied a custom path, it will be assigned to this
					string AppControlManagerSavePath;

					ProgressBarVisibility = Visibility.Visible;

					// If user did not supply a custom MSIXBundle file path
					if (!InstallLocalPackageConfirmation)
					{

						using (HttpClient client = new SecHttpClient())
						{
							// Store the download link to the latest available version
							onlineDownloadURL = new Uri(await client.GetStringAsync(GlobalVars.AppUpdateDownloadLinkURL));
						}

						AppControlManagerSavePath = Path.Combine(stagingArea, "AppControlManager.msixbundle");

						MainInfoBar.WriteInfo(GlobalVars.GetStr("DownloadingPackage"));

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
						}

						Logger.Write(GlobalVars.GetStr("DownloadSuccess") + AppControlManagerSavePath);
					}

					else
					{
						// Use the user-supplied MSIXBundle file path for installation source
						AppControlManagerSavePath = LocalPackageFilePath ?? throw new InvalidOperationException(GlobalVars.GetStr("NoMSIXBundlePath"));
					}

					ProgressBarIsIndeterminate = true;

					MainInfoBar.WriteInfo(GlobalVars.GetStr("DownloadsFinished"));

					await Task.Run(() =>
					{
						// Random password to temporarily encrypt the private key of the newly generated certificate
						string PassWord = Guid.CreateVersion7().ToString("N");

						// Path where the .cer file will be saved
						string CertificateOutputPath = Path.Combine(stagingArea, $"{CertCommonName}.cer");

						// Remove any certificates with the specified common name that may already exist on the system form previous attempts
						CertificateGenerator.DeleteCertificateByCN(CertCommonName);

						// Generate a new certificate
						X509Certificate2 generatedCert = CertificateGenerator.GenerateSelfSignedCertificate(
						subjectName: CertCommonName,
						validityInYears: 100,
						keySize: 4096,
						hashAlgorithm: HashAlgorithmName.SHA512,
						storeLocation: CertificateGenerator.CertificateStoreLocation.Machine,
						cerExportFilePath: CertificateOutputPath,
						friendlyName: CertCommonName,
						UserProtectedPrivateKey: UseHardenedInstallationProcess,
						ExportablePrivateKey: false);

						// Sign the package
						Signing.Main.SignAppPackage(AppControlManagerSavePath, generatedCert);

						// Remove any certificates with the specified common name again
						// Because the existing one contains private keys and we don't want that
						CertificateGenerator.DeleteCertificateByCN(CertCommonName);

						// Adding the certificate to the 'Local Machine/Trusted Root Certification Authorities' store with public key only.
						// This safely stores the certificate on your device, ensuring its private key does not exist so cannot be used to sign anything else.
						CertificateGenerator.StoreCertificateInStore(generatedCert, CertificateGenerator.CertificateStoreLocation.Machine, true);


						string? ASROutput = null;

						const string comCommand = "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference AttackSurfaceReductionOnlyExclusions";

						try
						{
							ASROutput = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, comCommand);

							// If there are ASR rule exclusions, find ones that belong to AppControl Manager and remove them
							// Before adding new ones for the new version
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
										if (AppPFNRegex().IsMatch(item))
										{
											asrRulesToRemove.Add(item);
										}
									}

									// If any of the rules belong to the AppControl Manager
									if (asrRulesToRemove.Count > 0)
									{
										// Remove ASR rule exclusions that belong to all previous app versions
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


						PackageManager packageManager = new();

						Logger.Write(GlobalVars.GetStr("InstallingPackage"));

						// https://learn.microsoft.com/uwp/api/windows.management.deployment.addpackageoptions
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
							throw new InvalidOperationException(GlobalVars.GetStr("InstallationError") + deploymentOperation.ErrorCode + GlobalVars.GetStr("InstallationErrorText") + deploymentResult.ErrorText);
						}
						else if (deploymentOperation.Status == AsyncStatus.Canceled)
						{
							Logger.Write(GlobalVars.GetStr("InstallationCanceled"));
						}
						else if (deploymentOperation.Status == AsyncStatus.Completed)
						{
							Logger.Write(GlobalVars.GetStr("InstallationSucceeded"));
						}
						else
						{
							throw new InvalidOperationException(GlobalVars.GetStr("UnknownInstallationIssue"));
						}

						try
						{
							// Problem: This won't get the latest version of the app as long as the current app version is still open, preventing the new app version from being fully installed.
							// Solution: Going through the installation process for the 2nd time, after the first one has completed and app is restarted, resolves it.
							// Note: This obviously only applies to the Non-Store versions of the app.
							// Possible remedy: replace the version manually via string manipulation.
							Package AppControlManagerPackage = packageManager.FindPackages("AppControlManager_sadt7br7jpt02").First();

							string AppControlInstallFolder = AppControlManagerPackage.EffectivePath;

							// Construct the paths to the .exe and .dll files of the AppControl Manager
							string path1 = Path.Combine(AppControlInstallFolder, "AppControlManager.exe");
							string path2 = Path.Combine(AppControlInstallFolder, "AppControlManager.dll");

							// Adding the extra executables included in the package so they will be allowed to run as well
							_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"wmi stringarray ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference add AttackSurfaceReductionOnlyExclusions \"{path1}\" \"{path2}\" \"{GlobalVars.ComManagerProcessPath}\" ");
						}
						catch (Exception ex)
						{
							Logger.Write(GlobalVars.GetStr("ASRAddError") + ex.Message);
						}
					});

					MainInfoBar.WriteSuccess(GlobalVars.GetStr("UpdateSuccess"));

					UpdateButtonContent = GlobalVars.GetStr("UpdatesInstalled");

					// Keep the CheckForUpdate button disabled since the update has been installed at this point
					// And all that's required is for the app to be restarted by the user
				}

				else
				{
					MainInfoBar.WriteSuccess(GlobalVars.GetStr("AlreadyUpdated"));

					CheckForUpdateButtonIsEnabled = true;
				}
			}
			catch (Exception ex)
			{
				ProgressBarValue = 0;

				CheckForUpdateButtonIsEnabled = true;

				WhatsNewInfoBarIsOpen = false;

				MainInfoBar.WriteError(ex, GlobalVars.GetStr("UpdateCheckError"));
			}
			finally
			{
				MainInfoBarIsClosable = true;

				CheckForUpdateSettingsCardIsClickable = true;

				ProgressBarVisibility = Visibility.Collapsed;
			}
#endif
		}
	}


	/// <summary>
	/// Opens a file picker to select a MSIX/MSIXBundle package file.
	/// </summary>
	internal void BrowseForCustomMSIXPathButton_Click()
	{
		LocalPackageFilePath = FileDialogHelper.ShowFilePickerDialog("MSIX/MSIXBundle files|*.msixbundle;*.msix");
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

}
