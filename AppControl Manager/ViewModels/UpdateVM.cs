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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel;
using Windows.Foundation;
using Windows.Management.Deployment;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812, CA1822, IDE0063
// an internal class that is apparently never instantiated, It's handled by Dependency Injection so this warning is a false-positive.
// Do not simplify using statements, keep them scoped for proper disposal otherwise files will be in use until the method is exited

internal sealed partial class UpdateVM : ViewModelBase
{

	/// <summary>
	/// Pattern for finding ASR rules that belong to the AppControl Manager
	/// </summary>
	/// <returns></returns>
	[GeneratedRegex("__sadt7br7jpt02", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
	internal partial Regex AppPFNRegex();

	/// <summary>
	/// Common name of the on-device generated certificate used to sign the AppControl Manager MSIXBundle package
	/// </summary>
	internal readonly string CertCommonName = "SelfSignedCertForAppControlManager";

	#region UI-Bound Properties

	/// <summary>
	/// To determine whether to use the user-supplied package or continue with downloading the package from GitHub.
	/// </summary>
	internal bool CheckForUpdateButtonIsEnabled
	{
		get; set => SetProperty(ref field, value);
	} = true;

	internal bool CheckForUpdateSettingsCardIsClickable
	{
		get; set => SetProperty(ref field, value);
	} = true;

	/// <summary>
	/// Content of the main update button
	/// </summary>
	internal string UpdateButtonContent
	{
		get; set => SetProperty(ref field, value);
	} = GlobalVars.Rizz.GetString("UpdateNavItem/ToolTipService/ToolTip");

	/// <summary>
	/// To determine whether to use the user-supplied package or continue with downloading the package from GitHub.
	/// </summary>
	internal bool InstallLocalPackageConfirmation
	{
		get;
		set
		{
			if (SetProperty(ref field, value))
			{
				// Change the update button's text based on the file path
				UpdateButtonContent = field ? $"Install {Path.GetFileName(LocalPackageFilePath)}" : GlobalVars.Rizz.GetString("UpdateNavItem/ToolTipService/ToolTip");
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
			if (SetProperty(ref field, value))
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
	internal bool InstallLocalPackageConfirmationIsEnabled
	{
		get; set => SetProperty(ref field, value);
	}

	/// <summary>
	/// Whether the installation process must use hardened procedures.
	/// </summary>
	internal bool UseHardenedInstallationProcess
	{
		get; set => SetProperty(ref field, value);
	}

	internal Visibility MainInfoBarVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	internal bool MainInfoBarIsOpen
	{
		get; set => SetProperty(ref field, value);
	}

	internal string? MainInfoBarMessage
	{
		get; set => SetProperty(ref field, value);
	}

	internal InfoBarSeverity MainInfoBarSeverity
	{
		get; set => SetProperty(ref field, value);
	} = InfoBarSeverity.Informational;

	internal bool MainInfoBarIsClosable
	{
		get; set => SetProperty(ref field, value);
	}

	internal Visibility ProgressBarVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	internal double ProgressBarValue
	{
		get; set => SetProperty(ref field, value);
	}

	internal bool ProgressBarIsIndeterminate
	{
		get; set => SetProperty(ref field, value);
	}

	internal bool WhatsNewInfoBarIsOpen
	{
		get; set => SetProperty(ref field, value);
	}

	#endregion

	/// <summary>
	/// Navigate to the extra sub-page
	/// </summary>
	internal void CheckForUpdate_Click()
	{
		MainWindow.Instance.NavView_Navigate(typeof(Pages.UpdatePageCustomMSIXPath), null);
	}


	/// <summary>
	/// Event handler for check for update button
	/// </summary>
	internal async void CheckForUpdateButton_Click()
	{

		try
		{
			CheckForUpdateButtonIsEnabled = false;
			CheckForUpdateSettingsCardIsClickable = false;
			MainInfoBarIsClosable = false;
			MainInfoBarVisibility = Visibility.Visible;
			MainInfoBarIsOpen = true;
			MainInfoBarSeverity = InfoBarSeverity.Informational;

			// variable to store the update results
			UpdateCheckResponse? updateCheckResult = null;

			// If user did not provide custom MSIXBundle path, start checking for update
			if (!InstallLocalPackageConfirmation)
			{
				MainInfoBarMessage = GlobalVars.Rizz.GetString("CheckingForUpdate");
				// Check for update asynchronously
				updateCheckResult = await Task.Run(AppUpdate.Check);
			}

			// If a new version is available or user supplied a custom MSIXBundle path to be installed
			if ((updateCheckResult is { IsNewVersionAvailable: true }) || InstallLocalPackageConfirmation)
			{
				string msg1;

				if (InstallLocalPackageConfirmation)
				{
					msg1 = GlobalVars.Rizz.GetString("InstallingCustomPath") + LocalPackageFilePath;
				}
				else
				{
					msg1 = GlobalVars.Rizz.GetString("VersionComparison") + App.currentAppVersion + GlobalVars.Rizz.GetString("WhileOnlineVersion") + updateCheckResult?.OnlineVersion + GlobalVars.Rizz.GetString("UpdatingApplication");
				}

				Logger.Write(msg1);
				MainInfoBarMessage = msg1;

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

					MainInfoBarMessage = GlobalVars.Rizz.GetString("DownloadingPackage");


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

					Logger.Write(GlobalVars.Rizz.GetString("DownloadSuccess") + AppControlManagerSavePath);
				}

				else
				{
					// Use the user-supplied MSIXBundle file path for installation source
					AppControlManagerSavePath = LocalPackageFilePath ?? throw new InvalidOperationException(GlobalVars.Rizz.GetString("NoMSIXBundlePath"));
				}

				ProgressBarIsIndeterminate = true;

				MainInfoBarMessage = GlobalVars.Rizz.GetString("DetectingSignTool");

				// First check if SignTool path is registered in the user configurations, else attempt to detect or download it
				string signToolPath = UserConfiguration.Get().SignToolCustomPath ?? await Task.Run(() => SignToolHelper.GetSignToolPath());

				MainInfoBarMessage = GlobalVars.Rizz.GetString("DownloadsFinished");

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

					// Signing the App Control Manager package
					// In this step the SignTool detects the cert to use based on Common name + ThumbPrint + Hash Algo + Store Type + Store Name
					_ = ProcessStarter.RunCommand(signToolPath, $"sign /debug /n \"{CertCommonName}\" /fd Sha512 /sm /s Root /sha1 {generatedCert.Thumbprint} \"{AppControlManagerSavePath}\"");

					// Remove any certificates with the specified common name again
					// Because the existing one contains private keys and we don't want that
					CertificateGenerator.DeleteCertificateByCN(CertCommonName);

					// Adding the certificate to the 'Local Machine/Trusted Root Certification Authorities' store with public key only.
					// This safely stores the certificate on your device, ensuring its private key does not exist so cannot be used to sign anything else.
					CertificateGenerator.StoreCertificateInStore(generatedCert, CertificateGenerator.CertificateStoreLocation.Machine, true);


					string? ASROutput = null;

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


						ASROutput = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get AttackSurfaceReductionOnlyExclusions");

						// If there are ASR rule exclusions, find ones that belong to AppControl Manager and remove them
						// Before adding new ones for the new version
						if (!string.IsNullOrWhiteSpace(ASROutput))
						{

							// Deserialize the JSON string
							string[]? ASROutputArrayCleaned = JsonSerializer.Deserialize(ASROutput, MicrosoftGraph.MSGraphJsonContext.Default.StringArray) as string[];

							// If there were ASR rules exceptions
							if (ASROutputArrayCleaned is not null && ASROutputArrayCleaned.Length > 0)
							{

								List<string> asrRulesToRemove = [];

								// Find all the rules that belong to the AppControl Manager
								foreach (string item in ASROutputArrayCleaned)
								{
									if (AppPFNRegex().Match(item).Success)
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

									// Wrap them with double quotes and separate them with a space
									string asrRulesToRemoveFinal = string.Join(" ", asrRulesToRemove.Select(item => $"\"{item}\""));

									_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, $"stringarray remove AttackSurfaceReductionOnlyExclusions {asrRulesToRemoveFinal}");
								}
							}
						}
					}
					catch (JsonException Jex)
					{
						Logger.Write($"Couldn't deserialize ASR rules exceptions list JSON which was this: {ASROutput}\nError: {Jex.Message}");
					}
					catch (Exception ex)
					{
						Logger.Write(GlobalVars.Rizz.GetString("ASRError") + ex.Message);
					}


					PackageManager packageManager = new();

					Logger.Write(GlobalVars.Rizz.GetString("InstallingPackage"));

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

						// Adding the 2 extra executables included in the package so they will be allowed to run as well
						_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, $"stringarray add AttackSurfaceReductionOnlyExclusions \"{path1}\" \"{path2}\" \"{GlobalVars.ManageDefenderProcessPath}\" \"{GlobalVars.DeviceGuardWMIRetrieverProcessPath}\" ");

					}
					catch (Exception ex)
					{
						Logger.Write(GlobalVars.Rizz.GetString("ASRAddError") + ex.Message);
					}
				});

				MainInfoBarMessage = GlobalVars.Rizz.GetString("UpdateSuccess");
				MainInfoBarSeverity = InfoBarSeverity.Success;

				UpdateButtonContent = GlobalVars.Rizz.GetString("UpdatesInstalled");

				// Keep the CheckForUpdate button disabled since the update has been installed at this point
				// And all that's required is for the app to be restarted by the user
			}

			else
			{
				MainInfoBarMessage = GlobalVars.Rizz.GetString("AlreadyUpdated");
				MainInfoBarSeverity = InfoBarSeverity.Success;
				CheckForUpdateButtonIsEnabled = true;
			}
		}
		catch
		{
			MainInfoBarSeverity = InfoBarSeverity.Error;
			MainInfoBarMessage = GlobalVars.Rizz.GetString("UpdateCheckError");

			ProgressBarValue = 0;

			CheckForUpdateButtonIsEnabled = true;

			WhatsNewInfoBarIsOpen = false;

			throw;
		}
		finally
		{
			MainInfoBarIsClosable = true;

			CheckForUpdateSettingsCardIsClickable = true;

			ProgressBarVisibility = Visibility.Collapsed;
		}
	}


	/// <summary>
	/// Opens a file picker to select a MSIX/MSIXBundle package file.
	/// </summary>
	internal void BrowseForCustomMSIXPathButton_Click()
	{
		LocalPackageFilePath = FileDialogHelper.ShowFilePickerDialog("MSIX/MSIXBundle files|*.msixbundle;*.msix");
	}

}
