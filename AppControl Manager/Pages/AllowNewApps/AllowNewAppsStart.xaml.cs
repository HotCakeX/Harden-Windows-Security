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
using System.Numerics;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.SiPolicyIntel;
using AppControlManager.ViewModels;
using AppControlManager.XMLOps;
using CommunityToolkit.WinUI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// AllowNewAppsStart is a page that manages the process of allowing new applications through policy management. It
/// handles user interactions for selecting policies, scanning directories, and creating supplemental policies.
/// </summary>
internal sealed partial class AllowNewAppsStart : Page, Sidebar.IAnimatedIconsManager
{

#pragma warning disable CA1822
	private AllowNewAppsVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<AllowNewAppsVM>();
	private PolicyEditorVM PolicyEditorViewModel { get; } = App.AppHost.Services.GetRequiredService<PolicyEditorVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
#pragma warning restore CA1822


	// The user selected XML base policy path
	internal string? selectedXMLFilePath;

	// The user selected Supplemental policy name
	private static string? selectedSupplementalPolicyName;

	// The user selected directories to scan
	private static readonly HashSet<string> selectedDirectoriesToScan = [];

	// The user selected scan level
	private ScanLevels scanLevel = ScanLevels.FilePublisher;

	// Only the logs generated after this time will be shown
	// It will be set when user moves from Step1 to Step2
	private DateTime? LogsScanStartTime;

	// Paths for the entire operation of this page
	private static DirectoryInfo? stagingArea;
	private string? tempBasePolicyPath;
	private string? AuditModeCIP;
	private string? EnforcedModeCIP;

	// Save the current log size that is user input from the number box UI element
	private ulong LogSize;

	// Custom HashSet to store the output of both local files and event logs scans
	// If the same file is detected in event logs And local file scans, the one with IsECCSigned property set to true will be kept
	// So that the respective methods will make Hash based rule for that file since AppControl doesn't support ECC Signed files yet
	private static readonly FileIdentityECCBasedHashSet fileIdentities = new();

	// A static instance of the AllowNewAppsStart class which will hold the single, shared instance of the page
	private static AllowNewAppsStart? _instance;

	// The ThemeShadow defined in Grid XAML
	private readonly ThemeShadow sharedShadow;

	// Will determine whether the user selected XML policy file is signed or unsigned
	private bool _IsSignedPolicy;

	// The base policy XML objectified
	private SiPolicy.SiPolicy? _BasePolicyObject;

	// To hold the necessary details for policy signing if the selected base policy is signed
	// They will be retrieved from the content dialog
	private string? _CertCN;
	private string? _CertPath;
	private string? _SignToolPath;

	/// <summary>
	/// Initializes the AllowNewAppsStart instance, setting up the navigation cache mode, data context, and UI elements. It
	/// also retrieves the shared shadow resource and configures initial states for UI components.
	/// </summary>
	/// <exception cref="InvalidOperationException">Thrown if the sharedShadow resource cannot be found in the XAML.</exception>
	internal AllowNewAppsStart()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Required;

		this.DataContext = ViewModel;

		// Assign this instance to the static field
		_instance = this;

		// Get the ThemeShadow defined in the XAML
		sharedShadow = RootGrid.Resources["SharedShadow"] as ThemeShadow ?? throw new InvalidOperationException("sharedShadow could not be found");

		// Initially disable Steps 2 and 3
		SetBorderStyles(Step1Border);
		DisableStep2();
		DisableStep3();

		// Initially set the log size in the number box to the current size of the Code Integrity Operational log
		double currentLogSize = EventLogUtility.GetCurrentLogSize();
		LogSizeNumberBox.Value = currentLogSize;
		LogSize = Convert.ToUInt64(currentLogSize);
	}

	/// <summary>
	/// Public property to access the singleton instance from other classes
	/// </summary>
	public static AllowNewAppsStart Instance => _instance ?? throw new InvalidOperationException("AllowNewAppsStart is not initialized.");


	#region Augmentation Interface


	// Exposing the AnimatedIcon via class instance since this is an internal page managed by AllowNewApps page's own NavigationView
	internal AnimatedIcon BrowseForXMLPolicyButtonLightAnimatedIconPub => BrowseForXMLPolicyButtonLightAnimatedIcon;

	// Exposing more elements to the main page of AllowNewApps since this is a sub-page managed by a 2nd NavigationView
	internal Flyout BrowseForXMLPolicyButton_FlyOutPub => BrowseForXMLPolicyButton_FlyOut;
	internal Button BrowseForXMLPolicyButtonPub => BrowseForXMLPolicyButton;
	internal TextBox BrowseForXMLPolicyButton_SelectedBasePolicyTextBoxPub => BrowseForXMLPolicyButton_SelectedBasePolicyTextBox;


	private string? unsignedBasePolicyPathFromSidebar;


	/// <summary>
	/// Sets the visibility of various UI elements and updates button content and event handlers based on the provided
	/// visibility state.
	/// </summary>
	/// <param name="visibility">Controls the visibility state of the UI elements.</param>
	/// <param name="unsignedBasePolicyPath">Stores the path for the unsigned policy from the sidebar.</param>
	/// <param name="button1">Represents the first button whose visibility and content are updated.</param>
	/// <param name="button2">Represents the second button, though it is not modified in this context.</param>
	/// <param name="button3">Represents the third button, though it is not modified in this context.</param>
	/// <param name="button4">Represents the fourth button, though it is not modified in this context.</param>
	/// <param name="button5">Represents the fifth button, though it is not modified in this context.</param>
	public void SetVisibility(Visibility visibility, string? unsignedBasePolicyPath, Button? button1, Button? button2, Button? button3, Button? button4, Button? button5)
	{

		ArgumentNullException.ThrowIfNull(button1);

		// Light up the local page's button icons
		BrowseForXMLPolicyButtonLightAnimatedIcon.Visibility = visibility;

		// Light up the sidebar buttons' icons
		button1.Visibility = visibility;

		// Set the incoming text which is from sidebar for unsigned policy path to a local private variable
		unsignedBasePolicyPathFromSidebar = unsignedBasePolicyPath;


		if (visibility is Visibility.Visible)
		{
			// Assign sidebar buttons' content texts
			button1.Content = "Allow New Apps Base Policy";

			// Assign a local event handler to the sidebar button
			button1.Click += LightUp1;
			// Save a reference to the event handler we just set for tracking
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect1EventHandler = LightUp1;

		}

	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void LightUp1(object sender, RoutedEventArgs e)
	{
		BrowseForXMLPolicyButton_FlyOut.ShowAt(BrowseForXMLPolicyButton);
		BrowseForXMLPolicyButton_SelectedBasePolicyTextBox.Text = unsignedBasePolicyPathFromSidebar;
		selectedXMLFilePath = unsignedBasePolicyPathFromSidebar;
	}


	#endregion


	#region Steps management

	private void DisableStep1()
	{
		BrowseForXMLPolicyButton.IsEnabled = false;
		GoToStep2Button.IsEnabled = false;
		SupplementalPolicyNameTextBox.IsEnabled = false;
		Step1Grid.Opacity = 0.5;
		ResetBorderStyles(Step1Border);
		Step1InfoBar.IsOpen = false;
		Step1InfoBar.Message = null;
		LogSizeNumberBox.IsEnabled = false;
	}

	private void EnableStep1()
	{
		BrowseForXMLPolicyButton.IsEnabled = true;
		GoToStep2Button.IsEnabled = true;
		SupplementalPolicyNameTextBox.IsEnabled = true;
		Step1Grid.Opacity = 1;
		SetBorderStyles(Step1Border);
		LogSizeNumberBox.IsEnabled = true;
	}

	private void DisableStep2()
	{
		BrowseForFoldersButton.IsEnabled = false;
		GoToStep3Button.IsEnabled = false;
		Step2Grid.Opacity = 0.5;
		ResetBorderStyles(Step2Border);
		Step2InfoBar.IsOpen = false;
		Step2InfoBar.Message = null;
	}

	private void EnableStep2()
	{
		BrowseForFoldersButton.IsEnabled = true;
		Step2Grid.Opacity = 1;
		GoToStep3Button.IsEnabled = true;
		SetBorderStyles(Step2Border);
	}

	private void DisableStep3()
	{
		ViewModel.DeployPolicyState = false;
		ScanLevelComboBox.IsEnabled = false;
		CreatePolicyButton.IsEnabled = false;
		Step3Grid.Opacity = 0.5;
		ResetBorderStyles(Step3Border);
		Step3InfoBar.IsOpen = false;
		Step3InfoBar.Message = null;
	}

	private void EnableStep3()
	{
		ViewModel.DeployPolicyState = true;
		ScanLevelComboBox.IsEnabled = true;
		CreatePolicyButton.IsEnabled = true;
		Step3Grid.Opacity = 1;
		SetBorderStyles(Step3Border);
	}

	#endregion


	/// <summary>
	/// Step 1 validation
	/// </summary>
	/// <exception cref="InvalidOperationException"></exception>
	private async void GoToStep2Button_Click()
	{
		bool errorOccurred = false;

		try
		{
			Step1ProgressRing.IsActive = true;
			GoToStep2Button.IsEnabled = false;
			ResetStepsButton.IsEnabled = false;


			// Ensure the text box for policy file name is filled
			if (string.IsNullOrWhiteSpace(SupplementalPolicyNameTextBox.Text))
			{
				throw new InvalidOperationException("You need to select a name for the Supplemental Policy");
			}
			else
			{
				selectedSupplementalPolicyName = SupplementalPolicyNameTextBox.Text;
			}

			// Ensure user selected a XML policy file path
			if (string.IsNullOrWhiteSpace(selectedXMLFilePath))
			{
				throw new InvalidOperationException("You need to select a XML policy file path");
			}

			// Ensure the selected XML file path exists on the disk
			if (!File.Exists(selectedXMLFilePath))
			{
				throw new InvalidOperationException($"The selected XML file path doesn't exist {selectedXMLFilePath}");
			}

			await Task.Run(() =>
			{
				// Instantiate the selected policy file
				_BasePolicyObject = Management.Initialize(selectedXMLFilePath, null);

				if (_BasePolicyObject.PolicyType is not PolicyType.BasePolicy)
				{
					throw new InvalidOperationException($"The selected XML policy file must be Base policy type, but its type is '{_BasePolicyObject.PolicyType}'");
				}

				// Get all deployed base policies
				List<CiPolicyInfo> allDeployedBasePolicies = CiToolHelper.GetPolicies(false, true, false);

				// Get all the deployed base policyIDs
				List<string?> CurrentlyDeployedBasePolicyIDs = [.. allDeployedBasePolicies.Select(p => p.BasePolicyID)];

				// Trim the curly braces from the policyID
				string trimmedPolicyID = _BasePolicyObject.PolicyID.TrimStart('{').TrimEnd('}');

				// Make sure the selected policy is deployed on the system
				if (!CurrentlyDeployedBasePolicyIDs.Any(id => string.Equals(id, trimmedPolicyID, StringComparison.OrdinalIgnoreCase)))
				{
					throw new InvalidOperationException($"The selected policy file {selectedXMLFilePath} is not deployed on the system.");
				}


				// If the policy doesn't have any rule options or it doesn't have the EnabledUnsignedSystemIntegrityPolicy rule option then it is signed
				_IsSignedPolicy = (!_BasePolicyObject.Rules.Any(rule => rule.Item is OptionType.EnabledUnsignedSystemIntegrityPolicy));
			});

			if (_IsSignedPolicy)
			{

				Logger.Write("Signed policy detected");

				#region Signing Details acquisition

				// Instantiate the Content Dialog
				SigningDetailsDialog customDialog = new(_BasePolicyObject);

				App.CurrentlyOpenContentDialog = customDialog;

				// Show the dialog and await its result
				ContentDialogResult result = await customDialog.ShowAsync();

				// Ensure primary button was selected
				if (result is ContentDialogResult.Primary)
				{
					_SignToolPath = customDialog.SignToolPath!;
					_CertPath = customDialog.CertificatePath!;
					_CertCN = customDialog.CertificateCommonName!;
				}
				else
				{
					GoToStep2Button.IsEnabled = true;

					return;
				}

				#endregion
			}

			// Execute the main tasks of step 1
			await Task.Run(() =>
			{

				// Create the required directory and file paths in step 1
				stagingArea = StagingArea.NewStagingArea("AllowNewApps");
				tempBasePolicyPath = Path.Combine(stagingArea.FullName, "BasePolicy.XML");
				AuditModeCIP = Path.Combine(stagingArea.FullName, "BaseAudit.cip");

				// Make sure it stays unique because it's being put outside of the StagingArea and we don't want any other command to remove or overwrite it
				EnforcedModeCIP = Path.Combine(GlobalVars.UserConfigDir, $"BaseEnforced-{GUIDGenerator.GenerateUniqueGUID()}.cip");

				_ = DispatcherQueue.TryEnqueue(() =>
				{
					Step1InfoBar.IsOpen = true;
					Step1InfoBar.Message = "Deploying the selected policy in Audit mode, please wait";
				});

				// Creating a copy of the original policy in the Staging Area so that the original one will be unaffected
				File.Copy(selectedXMLFilePath, tempBasePolicyPath, true);

				// If the policy is Unsigned
				if (!_IsSignedPolicy)
				{
					// Create audit mode CIP
					CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToAdd: [OptionType.EnabledAuditMode]);
					PolicyToCIPConverter.Convert(tempBasePolicyPath, AuditModeCIP);

					// Create Enforced mode CIP
					CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToRemove: [OptionType.EnabledAuditMode]);
					PolicyToCIPConverter.Convert(tempBasePolicyPath, EnforcedModeCIP);
				}
				// If the policy is Signed
				else
				{
					// Create audit mode CIP
					CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToAdd: [OptionType.EnabledAuditMode], rulesToRemove: [OptionType.EnabledUnsignedSystemIntegrityPolicy]);

					string CIPp7SignedFilePathAudit = Path.Combine(stagingArea.FullName, "BaseAudit.cip.p7");

					// Convert the XML file to CIP
					PolicyToCIPConverter.Convert(tempBasePolicyPath, AuditModeCIP);

					// Sign the CIP
					SignToolHelper.Sign(new FileInfo(AuditModeCIP), new FileInfo(_SignToolPath!), _CertCN!);

					// Rename the .p7 signed file to .cip
					File.Move(CIPp7SignedFilePathAudit, AuditModeCIP, true);

					// Create Enforced mode CIP
					CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToRemove: [OptionType.EnabledAuditMode, OptionType.EnabledUnsignedSystemIntegrityPolicy]);

					string CIPp7SignedFilePathEnforced = Path.Combine(stagingArea.FullName, "BaseAuditTemp.cip.p7");

					string tempEnforcedModeCIPPath = Path.Combine(stagingArea.FullName, "BaseAuditTemp.cip");

					// Convert the XML file to CIP
					PolicyToCIPConverter.Convert(tempBasePolicyPath, tempEnforcedModeCIPPath);

					// Sign the CIP
					SignToolHelper.Sign(new FileInfo(tempEnforcedModeCIPPath), new FileInfo(_SignToolPath!), _CertCN!);

					// Rename the .p7 signed file to .cip
					File.Move(CIPp7SignedFilePathEnforced, EnforcedModeCIP, true);
				}

				Logger.Write("Creating Enforced Mode SnapBack guarantee");
				SnapBackGuarantee.Create(EnforcedModeCIP);

#if !DEBUG
				Logger.Write("Deploying the Audit mode policy");
				CiToolHelper.UpdatePolicy(AuditModeCIP);
#endif

				Logger.Write("The Base policy has been Re-Deployed in Audit Mode");

				EventLogUtility.SetLogSize(LogSize);

			});

			DisableStep1();
			EnableStep2();
			DisableStep3();

			// Capture the current time so that the audit logs that will be displayed will be newer than that
			LogsScanStartTime = DateTime.Now;
		}
		catch
		{
			errorOccurred = true;

			throw;  // Re-throw the same exception, preserving the stack trace
		}
		finally
		{
			Step1ProgressRing.IsActive = false;
			ResetStepsButton.IsEnabled = true;

			// Only re-enable the button if errors occurred, otherwise we don't want to override the work that DisableStep1() method does
			if (errorOccurred)
			{
				GoToStep2Button.IsEnabled = true;
				Step1InfoBar.Message = null;
				Step1InfoBar.IsOpen = false;

				// Clear the variables if errors occurred in step 1
				_BasePolicyObject = null;
				_CertCN = null;
				_CertPath = null;
			}
		}
	}

	/// <summary>
	/// Step 2 validation
	/// </summary>
	private async void GoToStep3Button_Click()
	{

		bool errorsOccurred = false;

		try
		{
			Step2ProgressRing.IsActive = true;
			GoToStep3Button.IsEnabled = false;
			ResetStepsButton.IsEnabled = false;

			// While the base policy is being deployed is audit mode, set the progress ring as indeterminate
			Step2ProgressRing.IsIndeterminate = true;

			// Enable the ListView pages so user can select the logs
			ViewModel.EventLogsMenuItemState = true;
			ViewModel.LocalFilesMenuItemState = true;

			Step2InfoBar.IsOpen = true;

			await Task.Run(async () =>
			{

				// Deploy the base policy in enforced mode before proceeding with scans
				if (EnforcedModeCIP is null)
				{
					throw new InvalidOperationException("Enforced mode CIP file could not be found");
				}

				_ = DispatcherQueue.TryEnqueue(() =>
				{
					Step2InfoBar.Message = "Deploying the Enforced mode policy.";
				});

#if !DEBUG
				Logger.Write("Deploying the Enforced mode policy.");
				CiToolHelper.UpdatePolicy(EnforcedModeCIP);
#endif

				// Delete the enforced mode CIP file after deployment
				File.Delete(EnforcedModeCIP);

				// Remove the snap back guarantee task and related .bat file after successfully re-deploying the Enforced mode policy
				SnapBackGuarantee.Remove();

				// Check if user selected directories to be scanned
				if (selectedDirectoriesToScan.Count > 0)
				{

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						Step2InfoBar.Message = "Scanning the selected directories";

						// Set the progress ring to no longer be indeterminate since file scan will take control of its value
						Step2ProgressRing.IsIndeterminate = false;
					});

					DirectoryInfo[] selectedDirectories = [];

					// Convert user selected folder paths that are strings to DirectoryInfo objects
					selectedDirectories = [.. selectedDirectoriesToScan.Select(dir => new DirectoryInfo(dir))];

					// Get all of the AppControl compatible files from user selected directories
					(IEnumerable<FileInfo>, int) DetectedFilesInSelectedDirectories = FileUtility.GetFilesFast(selectedDirectories, null, null);

					// If any App Control compatible files were found in the user selected directories
					if (DetectedFilesInSelectedDirectories.Item2 > 0)
					{

						_ = DispatcherQueue.TryEnqueue(() =>
						{
							Step2InfoBar.Message = $"Scanning {DetectedFilesInSelectedDirectories.Item2} files found in the selected directories";

							// Set the progress ring to no longer be indeterminate since file scan will take control of its value
							Step2ProgressRing.IsIndeterminate = false;
						});

						// Scan all of the detected files from the user selected directories
						// Add a reference to the ViewModel class to each item so we can navigate using it in the XAML ItemTemplate
						IEnumerable<FileIdentity> LocalFilesResults = LocalFilesScan.Scan(
							DetectedFilesInSelectedDirectories,
							2,
							Step2ProgressRing,
							ViewModel,
							(fi, vm) => fi.ParentViewModelAllowNewApps = vm);

						// Add the results to the backing list
						ViewModel.LocalFilesAllFileIdentities.Clear();
						ViewModel.LocalFilesAllFileIdentities.AddRange(LocalFilesResults);

						await DispatcherQueue.EnqueueAsync(() =>
						{
							// Add the results of the Files/Directories scans to the ObservableCollection
							ViewModel.LocalFilesFileIdentities = new(LocalFilesResults);

							ViewModel.CalculateColumnWidthLocalFiles();
						});
					}
				}
			});

			// Update the InfoBadge for the top menu
			ViewModel.LocalFilesCountInfoBadgeValue = ViewModel.LocalFilesFileIdentities.Count;
			ViewModel.LocalFilesCountInfoBadgeOpacity = 1;

			Step2InfoBar.Message = "Scanning the event logs";

			// Log scanning doesn't produce determinate real time progress so setting it as indeterminate
			Step2ProgressRing.IsIndeterminate = true;

			// Check for available logs

			// Grab the App Control Logs
			HashSet<FileIdentity> Output = await GetEventLogsData.GetAppControlEvents();

#if !DEBUG

			// Filter the logs and keep only ones generated after audit mode policy was deployed
			await Task.Run(() =>
			{
				Output = [.. Output.Where(fileIdentity => fileIdentity.TimeCreated >= LogsScanStartTime)];
			});

#endif

			Step2InfoBar.Message = $"{Output.Count} log(s) were generated during the Audit phase";

			// If any logs were generated since audit mode policy was deployed
			if (Output.Count > 0)
			{
				// Add the results to the backing list
				ViewModel.EventLogsAllFileIdentities.Clear();
				ViewModel.EventLogsAllFileIdentities.AddRange(Output);

				await DispatcherQueue.EnqueueAsync(() =>
				{
					ViewModel.EventLogsFileIdentities.Clear();

					// Add the event logs to the ObservableCollection
					foreach (FileIdentity item in Output)
					{
						// Add a reference to the ViewModel class to each item so we can navigate using it in the XAML ItemTemplate
						item.ParentViewModelAllowNewApps = ViewModel;
						ViewModel.EventLogsFileIdentities.Add(item);
					}

					ViewModel.CalculateColumnWidthEventLogs();
				});
			}

			// Update the InfoBadge for the top menu
			ViewModel.EventLogsCountInfoBadgeValue = ViewModel.EventLogsFileIdentities.Count;
			ViewModel.EventLogsCountInfoBadgeOpacity = 1;

			DisableStep1();
			DisableStep2();
			EnableStep3();
		}
		catch
		{
			errorsOccurred = true;

			throw;
		}
		finally
		{
			Step2ProgressRing.IsActive = false;
			ResetStepsButton.IsEnabled = true;

			// Only perform these actions if an error occurred
			if (errorsOccurred)
			{
				GoToStep3Button.IsEnabled = true;

				// When an error occurs before the disable methods run, we need to clear them manually here
				Step2InfoBar.IsOpen = false;
				Step2InfoBar.Message = null;
			}
		}
	}


	/// <summary>
	/// Steps Reset
	/// </summary>
	private async void ResetStepsButton_Click()
	{
		try
		{
			ResetStepsButton.IsEnabled = false;

			ResetProgressRing.IsActive = true;

			// Disable all steps
			DisableStep1();
			DisableStep2();
			DisableStep3();

			// Hide the action button for InfoBar in Step 3 that offers to open the supplemental policy in the Policy Editor
			ViewModel.OpenInPolicyEditorInfoBarActionButtonVisibility = Visibility.Collapsed;

			// Clear the path to the supplemental policy
			finalSupplementalPolicyPath = null;

			// Clear the ListViews and their respective search/filter-related lists
			ViewModel.LocalFilesFileIdentities.Clear();
			ViewModel.LocalFilesAllFileIdentities.Clear();
			ViewModel.EventLogsFileIdentities.Clear();
			ViewModel.EventLogsAllFileIdentities.Clear();

			// reset the class variables back to their default states
			fileIdentities.FileIdentitiesInternal.Clear();
			selectedDirectoriesToScan.Clear();
			ViewModel.DeployPolicy = true;
			selectedSupplementalPolicyName = null;
			LogsScanStartTime = null;
			tempBasePolicyPath = null;
			_BasePolicyObject = null;
			_CertCN = null;
			_CertPath = null;
			_SignToolPath = null;
			_IsSignedPolicy = false;

			LogSizeNumberBox.Value = EventLogUtility.GetCurrentLogSize();

			// Disable the data grids access
			ViewModel.EventLogsMenuItemState = false;
			ViewModel.LocalFilesMenuItemState = false;


			// Update the InfoBadges for the top menu
			ViewModel.LocalFilesCountInfoBadgeValue = 0;
			ViewModel.LocalFilesCountInfoBadgeOpacity = 0;
			ViewModel.EventLogsCountInfoBadgeOpacity = 0;
			ViewModel.EventLogsCountInfoBadgeValue = 0;

			// Reset the UI inputs back to their default states
			ViewModel.DeployPolicy = true;
			SelectedDirectoriesTextBox.Text = null;
			SupplementalPolicyNameTextBox.Text = null;
			ScanLevelComboBox.SelectedIndex = 0;

			// Run the main reset tasks on a different thread
			await Task.Run(() =>
			{

				// Deploy the base policy in enforced mode if user advanced to that step
				if (Path.Exists(EnforcedModeCIP))
				{

#if !DEBUG
					Logger.Write("Deploying the Enforced mode policy because user decided to reset the operation");
					CiToolHelper.UpdatePolicy(EnforcedModeCIP);
#endif

					// Delete the enforced mode CIP file from the user config directory after deploying it
					File.Delete(EnforcedModeCIP);
				}

				// Remove the snap back guarantee task and .bat file if it exists
				SnapBackGuarantee.Remove();
			});

		}
		finally
		{
			// Enable the step1 for new operation
			EnableStep1();
			ResetProgressRing.IsActive = false;
			ResetStepsButton.IsEnabled = true;
		}
	}


	/// <summary>
	/// Clears the text box and the list of selected directories when the button is clicked.
	/// </summary>
	private void ClearSelectedDirectoriesButton_Click()
	{
		// Clear the text box on the UI
		SelectedDirectoriesTextBox.Text = string.Empty;

		// Clear the list of selected directories
		selectedDirectoriesToScan.Clear();
	}


	/// <summary>
	/// Handles the selection change event for a ComboBox, updating the scan level based on the selected item.
	/// </summary>
	/// <param name="sender">Represents the source of the event, allowing access to the ComboBox that triggered the selection change.</param>
	/// <param name="e">Contains event data related to the selection change, providing information about the new selection.</param>
	private void ScanLevelComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Get the ComboBox that triggered the event
		ComboBox comboBox = (ComboBox)sender;

		// Get the selected item from the ComboBox
		string selectedText = (string)comboBox.SelectedItem;

		scanLevel = Enum.Parse<ScanLevels>(selectedText);
	}


	/// <summary>
	/// Handles the click event for a button to browse and select multiple folders. Selected folders are added to a
	/// collection and displayed in the UI.
	/// </summary>
	private void BrowseForFoldersButton_Click()
	{
		List<string>? selectedFolders = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		if (selectedFolders is { Count: > 0 })
		{
			// Add each folder to the HashSet of the selected directories
			foreach (string folder in selectedFolders)
			{
				// If the add was successful then display it on the UI too
				if (selectedDirectoriesToScan.Add(folder))
				{
					// Append the new folder to the TextBox, followed by a newline
					SelectedDirectoriesTextBox.Text += folder + Environment.NewLine;
				}
			}
		}
	}


	/// <summary>
	/// Handles the click event for a button to browse and select an XML policy file.
	/// </summary>
	/// <exception cref="InvalidOperationException">Thrown when the selected file path is not a valid XML file.</exception>
	private void BrowseForXMLPolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrWhiteSpace(selectedFile))
		{
			// The extra validations are required since user can provide path in the text box directly
			if (File.Exists(selectedFile) && (Path.GetExtension(selectedFile).Equals(".xml", StringComparison.OrdinalIgnoreCase)))
			{
				// Store the selected XML file path
				selectedXMLFilePath = selectedFile;

				// Update the TextBox with the selected XML file path
				BrowseForXMLPolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
			}
			else
			{
				throw new InvalidOperationException($"Selected item '{selectedFile}' is not a valid XML file path");
			}
		}
	}


	#region Manage active step border

	private void SetBorderStyles(Border border)
	{

		// Create a LinearGradientBrush
		LinearGradientBrush linearGradientBrush = new()
		{
			StartPoint = new Windows.Foundation.Point(0, 0),
			EndPoint = new Windows.Foundation.Point(1, 1)
		};

		// Add Gradient Stops
		linearGradientBrush.GradientStops.Add(new GradientStop
		{
			Color = Colors.HotPink,
			Offset = 0
		});

		linearGradientBrush.GradientStops.Add(new GradientStop
		{
			Color = Colors.Wheat,
			Offset = 1
		});

		// apply the styles to the border
		border.BorderBrush = linearGradientBrush;
		border.BorderThickness = new Thickness(1);

		// Adjust the elevation of the border to achieve the shadow effect
		border.Translation += new Vector3(0, 0, 40);

		// Use the SharedShadow defined in XAML
		border.Shadow = sharedShadow;
	}

	private static void ResetBorderStyles(Border border)
	{
		// Reset the BorderBrush and BorderThickness to their default values
		border.BorderBrush = null;
		border.BorderThickness = new Thickness(0);

		// Reset the border depth
		border.Translation = new Vector3(0, 0, 0);

		border.Shadow = null;
	}

	#endregion


	/// <summary>
	/// Event handler for the Create Policy button
	/// </summary>
	private async void CreatePolicyButton_Click()
	{
		try
		{
			// Disable the CreatePolicy button for the duration of the operation
			CreatePolicyButton.IsEnabled = false;

			ResetStepsButton.IsEnabled = false;

			ViewModel.OpenInPolicyEditorInfoBarActionButtonVisibility = Visibility.Collapsed;

			Step3InfoBar.IsOpen = true;
			Step3InfoBar.Severity = InfoBarSeverity.Informational;
			Step3InfoBar.Message = "Creating the policy using any available event logs or file scan results in other tabs.";


			// Check if there are items for the local file scans ListView
			if (ViewModel.LocalFilesAllFileIdentities.Count > 0)
			{
				// convert every selected item to FileIdentity and store it in the list
				foreach (FileIdentity item in ViewModel.LocalFilesAllFileIdentities)
				{
					_ = fileIdentities.Add(item);
				}
			}

			// Check if there are selected items for the Event Logs scan ListView
			if (ViewModel.EventLogsAllFileIdentities.Count > 0)
			{
				// convert every selected item to FileIdentity and store it in the list
				foreach (FileIdentity item in ViewModel.EventLogsAllFileIdentities)
				{
					_ = fileIdentities.Add(item);
				}
			}

			// If there are no logs to create a Supplemental policy with
			if (fileIdentities.Count is 0)
			{
				Step3InfoBar.Severity = InfoBarSeverity.Warning;
				Step3InfoBar.Message = "There are no logs or files in any data grids to create a Supplemental policy for.";
				return;
			}

			await Task.Run(() =>
			{

				if (stagingArea is null)
				{
					throw new InvalidOperationException("Staging Area wasn't found");
				}

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. fileIdentities.FileIdentitiesInternal], level: scanLevel);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, Authorization.Allow);

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{selectedSupplementalPolicyName}.xml");

				// Set the BasePolicyID of our new policy to the one from user selected policy
				_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, selectedSupplementalPolicyName, _BasePolicyObject!.BasePolicyID, null);

				// Configure policy rule options
				if (!_IsSignedPolicy)
				{
					CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);
				}
				else
				{
					CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental, rulesToRemove: [OptionType.EnabledUnsignedSystemIntegrityPolicy]);
				}

				// Set policy version
				SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

				if (_IsSignedPolicy)
				{
					// Add certificate's details to the supplemental policy
					_ = AddSigningDetails.Add(EmptyPolicyPath, _CertPath!);
				}

				// Copying the policy file to the User Config directory - outside of the temporary staging area
				File.Copy(EmptyPolicyPath, OutputPath, true);

				string CIPPath = Path.Combine(stagingArea.FullName, $"{selectedSupplementalPolicyName}.cip");

				// This path is only used if the policy is signed
				string CIPp7SignedFilePath = Path.Combine(stagingArea.FullName, $"{selectedSupplementalPolicyName}.cip.p7");

				// Convert the XML file to CIP
				PolicyToCIPConverter.Convert(OutputPath, CIPPath);

				// Add the supplemental policy path to the class variable
				finalSupplementalPolicyPath = OutputPath;

				if (_IsSignedPolicy)
				{
					// Sign the CIP
					SignToolHelper.Sign(new FileInfo(CIPPath), new FileInfo(_SignToolPath!), _CertCN!);

					// Rename the .p7 signed file to .cip
					File.Move(CIPp7SignedFilePath, CIPPath, true);
				}
				else
				{
					PolicyToCIPConverter.Convert(OutputPath, CIPPath);
				}

				// If user selected to deploy the policy
				if (ViewModel.DeployPolicy)
				{
#if !DEBUG
					CiToolHelper.UpdatePolicy(CIPPath);
#endif
				}

				// If not deploying it, copy the CIP file to the user config directory, just like the XML policy file
				else
				{
					string finalCIPPath = Path.Combine(GlobalVars.UserConfigDir, Path.GetFileName(CIPPath));
					File.Copy(CIPPath, finalCIPPath, true);
				}

			});

			Step3InfoBar.Severity = InfoBarSeverity.Success;
			Step3InfoBar.IsClosable = true;
			Step3InfoBar.Message = ViewModel.DeployPolicy ? "Successfully created and deployed the policy." : "Successfully created the policy.";

		}
		finally
		{
			CreatePolicyButton.IsEnabled = true;
			ResetStepsButton.IsEnabled = true;

			ViewModel.OpenInPolicyEditorInfoBarActionButtonVisibility = Visibility.Visible;

			// Clear the private variable after the policy is created. This allows the user to remove some items from the logs and recreate the policy with less data if needed.
			fileIdentities.FileIdentitiesInternal.Clear();
		}
	}

	/// <summary>
	/// Event handler for the LogSize number box
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	/// <exception cref="InvalidOperationException"></exception>
	private void LogSizeNumberBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
	{
		// Check if the value changed successfully.
		if (!double.IsNaN(args.NewValue))
		{
			// Handle the new value.
			double newValue = args.NewValue;

			// Convert the value from megabytes to bytes
			double bytesValue = newValue * 1024 * 1024;

			// Convert the value to ulong
			LogSize = Convert.ToUInt64(bytesValue);
		}
		else
		{
			throw new InvalidOperationException("Invalid input detected.");
		}
	}


	/// <summary>
	/// Event handler for the clear button in the base policy path selection button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForXMLPolicyButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		BrowseForXMLPolicyButton_SelectedBasePolicyTextBox.Text = null;
		selectedXMLFilePath = null;
		tempBasePolicyPath = null;
	}


	/// <summary>
	/// Handles the right-tap event on a button to display a flyout menu if it is not already open.
	/// </summary>
	/// <param name="sender">Represents the source of the right-tap event.</param>
	/// <param name="e">Contains data related to the right-tap event.</param>
	private void BrowseForXMLPolicyButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!BrowseForXMLPolicyButton_FlyOut.IsOpen)
			BrowseForXMLPolicyButton_FlyOut.ShowAt(BrowseForXMLPolicyButton);
	}

	/// <summary>
	/// Handles the holding event for a button to display a flyout if the holding state has started and the flyout is not
	/// already open.
	/// </summary>
	/// <param name="sender">Represents the source of the event, typically the UI element that was interacted with.</param>
	/// <param name="e">Contains data related to the holding event, including the current state of the hold action.</param>
	private void BrowseForXMLPolicyButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!BrowseForXMLPolicyButton_FlyOut.IsOpen)
				BrowseForXMLPolicyButton_FlyOut.ShowAt(BrowseForXMLPolicyButton);
	}

	/// <summary>
	/// Handles the right-tap event on a button to display a flyout menu if it is not already open.
	/// </summary>
	/// <param name="sender">Represents the source of the right-tap event.</param>
	/// <param name="e">Contains data related to the right-tap event.</param>
	private void BrowseForFoldersButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!BrowseForFoldersButton_FlyOut.IsOpen)
			BrowseForFoldersButton_FlyOut.ShowAt(BrowseForFoldersButton);
	}

	/// <summary>
	/// Handles the holding gesture on a button to display a flyout menu if it is not already open.
	/// </summary>
	/// <param name="sender">Represents the source of the event, typically the button being held.</param>
	/// <param name="e">Contains data related to the holding gesture, including its current state.</param>
	private void BrowseForFoldersButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!BrowseForFoldersButton_FlyOut.IsOpen)
				BrowseForFoldersButton_FlyOut.ShowAt(BrowseForFoldersButton);
	}


	/// <summary>
	/// Path of the Supplemental policy that is created
	/// </summary>
	private string? finalSupplementalPolicyPath;


	/// <summary>
	/// Event handler to open the supplemental policy in the Policy Editor
	/// </summary>
	private async void OpenInPolicyEditor()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(finalSupplementalPolicyPath);
	}

}
