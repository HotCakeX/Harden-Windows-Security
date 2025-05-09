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
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
using AppControlManager.XMLOps;
using CommunityToolkit.WinUI;
using CommunityToolkit.WinUI.Controls;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Represents a page for creating supplemental policies, managing data display and user interactions.
/// </summary>
internal sealed partial class CreateSupplementalPolicy : Page, IAnimatedIconsManager
{

	private CreateSupplementalPolicyVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<CreateSupplementalPolicyVM>();
	private PolicyEditorVM PolicyEditorViewModel { get; } = App.AppHost.Services.GetRequiredService<PolicyEditorVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
	private SidebarVM sideBarVM { get; } = App.AppHost.Services.GetRequiredService<SidebarVM>();

	/// <summary>
	/// Constructor for the CreateSupplementalPolicy class. Initializes components, sets navigation cache mode, and assigns
	/// the data context.
	/// </summary>
	internal CreateSupplementalPolicy()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;

		this.DataContext = ViewModel;
	}

	#region Merge With Existing Policy Section

	private void PolicyFileToMergeWithButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			ViewModel.PolicyFileToMergeWith = selectedFile;
		}
	}

	#endregion

	#region Augmentation Interface

	public void SetVisibility(Visibility visibility)
	{
		// Light up the local page's button icons
		ViewModel.FilesAndFoldersBasePolicyLightAnimatedIconVisibility = visibility;
		ViewModel.CertificatesBasePolicyPathLightAnimatedIconVisibility = visibility;
		ViewModel.ISGBasePolicyPathLightAnimatedIconVisibility = visibility;
		ViewModel.StrictKernelModeBasePolicyLightAnimatedIconVisibility = visibility;
		ViewModel.PFNBasePolicyPathLightAnimatedIconVisibility = visibility;

		sideBarVM.AssignActionPacks(
			(param => LightUp1(), GlobalVars.Rizz.GetString("FilesAndFoldersSupplementalPolicyLabel")),
			(param => LightUp2(), GlobalVars.Rizz.GetString("CertificatesSupplementalPolicyLabel")),
			(param => LightUp3(), GlobalVars.Rizz.GetString("ISGSupplementalPolicyLabel")),
			(param => LightUp4(), GlobalVars.Rizz.GetString("StrictKernelModeSupplementalPolicyLabel")),
			(param => LightUp5(), GlobalVars.Rizz.GetString("PFNSupplementalPolicyLabel"))
		);
	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	private void LightUp1()
	{
		// Make sure the element has XamlRoot. When it's in a settings card that is not expanded yet, it won't have it
		if (FilesAndFoldersBrowseForBasePolicyButton.XamlRoot is not null)
		{
			FilesAndFoldersBrowseForBasePolicyButton_FlyOut.ShowAt(FilesAndFoldersBrowseForBasePolicyButton);
		}

		FilesAndFoldersBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
		filesAndFoldersBasePolicyPath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
	}
	private void LightUp2()
	{
		// Make sure the element has XamlRoot. When it's in a settings card that is not expanded yet, it won't have it
		if (CertificatesBrowseForBasePolicyButton.XamlRoot is not null)
		{
			CertificatesBrowseForBasePolicyButton_FlyOut.ShowAt(CertificatesBrowseForBasePolicyButton);
		}

		CertificatesBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
		CertificatesBasedBasePolicyPath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
	}
	private void LightUp3()
	{
		if (ISGBrowseForBasePolicyButton.XamlRoot is not null)
		{
			ISGBrowseForBasePolicyButton_FlyOut.ShowAt(ISGBrowseForBasePolicyButton);
		}

		ISGBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
		ISGBasedBasePolicyPath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
	}

	private void LightUp4()
	{
		if (StrictKernelModeBrowseForBasePolicyButton.XamlRoot is not null)
		{
			StrictKernelModeBrowseForBasePolicyButton_FlyOut.ShowAt(StrictKernelModeBrowseForBasePolicyButton);
		}

		StrictKernelModeBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
		StrictKernelModeBasePolicyPath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
	}

	private void LightUp5()
	{
		if (PFNBrowseForBasePolicyButton.XamlRoot is not null)
		{
			PFNBrowseForBasePolicyButton_FlyOut.ShowAt(PFNBrowseForBasePolicyButton);
		}

		PFNBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
		PFNBasePolicyPath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
	}

	#endregion


	#region Files and Folders scan

	// Selected File Paths
	private readonly HashSet<string> filesAndFoldersFilePaths = [];

	// Selected Folder Paths
	private readonly HashSet<string> filesAndFoldersFolderPaths = [];

	// Selected Base policy path
	private string? filesAndFoldersBasePolicyPath;

	// Selected Supplemental policy name
	private string? filesAndFoldersSupplementalPolicyName;

	// The default selected scan level
	private ScanLevels filesAndFoldersScanLevel = ScanLevels.FilePublisher;

	private bool filesAndFoldersDeployButton;

	private bool usingWildCardFilePathRules;

	/// <summary>
	/// Browse for Files - Button Click
	/// </summary>
	private void FilesAndFoldersBrowseForFilesButton_Click()
	{
		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.AnyFilePickerFilter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				_ = filesAndFoldersFilePaths.Add(file);

				// Append the new file to the TextBox, followed by a newline
				FilesAndFoldersBrowseForFilesButton_SelectedFilesTextBox.Text += file + Environment.NewLine;
			}
		}
	}


	/// <summary>
	/// Browse for Folders - Button Click
	/// </summary>
	private void FilesAndFoldersBrowseForFoldersButton_Click()
	{
		List<string>? selectedDirectories = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		if (selectedDirectories is { Count: > 0 })
		{
			foreach (string dir in selectedDirectories)
			{
				_ = filesAndFoldersFolderPaths.Add(dir);

				// Append the new directory to the TextBox, followed by a newline
				FilesAndFoldersBrowseForFoldersButton_SelectedFoldersTextBox.Text += dir + Environment.NewLine;
			}
		}
	}


	/// <summary>
	/// Browse for Base Policy - Button Click
	/// </summary>
	private void FilesAndFoldersBrowseForBasePolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			filesAndFoldersBasePolicyPath = selectedFile;

			// Add the file path to the GUI's text box
			FilesAndFoldersBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}
	}


	/// <summary>
	/// Link to the page that shows scanned file details
	/// </summary>
	private void FilesAndFoldersViewFileDetailsSettingsCard_Click()
	{
		App._nav.Navigate(typeof(CreateSupplementalPolicyFilesAndFoldersScanResults), null);
	}


	/// <summary>
	/// Deploy policy Toggle Button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersPolicyDeployToggleButton_Click(object sender, RoutedEventArgs e)
	{
		filesAndFoldersDeployButton = ((ToggleButton)sender).IsChecked ?? false;
	}


	/// <summary>
	/// To detect when File Scan Level ComboBox level changes
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	/// <exception cref="InvalidOperationException"></exception>
	private void ScanLevelComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Get the ComboBox that triggered the event
		ComboBox comboBox = (ComboBox)sender;

		// Get the selected item from the ComboBox
		string selectedText = (string)comboBox.SelectedItem;

		// Since the texts in the ComboBox have spaces in them for user friendliness, we remove the spaces here before parsing them as enum
		filesAndFoldersScanLevel = Enum.Parse<ScanLevels>(selectedText.Replace(" ", ""));

		// For Wildcard file path rules, only folder paths should be used
		if (filesAndFoldersScanLevel is ScanLevels.WildCardFolderPath)
		{
			FilesAndFoldersBrowseForFilesButton.IsEnabled = false;
			FilesAndFoldersBrowseForFilesSettingsCard.IsEnabled = false;
			usingWildCardFilePathRules = true;
		}
		else
		{
			FilesAndFoldersBrowseForFilesButton.IsEnabled = true;
			FilesAndFoldersBrowseForFilesSettingsCard.IsEnabled = true;
			usingWildCardFilePathRules = false;
		}
	}


	/// <summary>
	/// When the Supplemental Policy Name Textbox text changes
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersPolicyNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		filesAndFoldersSupplementalPolicyName = ((TextBox)sender).Text;
	}


	/// <summary>
	/// Button to clear the list of selected file paths
	/// </summary>
	private void FilesAndFoldersBrowseForFilesButton_Flyout_Clear_Click()
	{
		filesAndFoldersFilePaths.Clear();
		FilesAndFoldersBrowseForFilesButton_SelectedFilesTextBox.Text = null;
	}


	/// <summary>
	/// Button to clear the list of selected folder paths
	/// </summary>
	private void FilesAndFoldersBrowseForFoldersButton_Flyout_Clear_Click()
	{
		filesAndFoldersFolderPaths.Clear();
		FilesAndFoldersBrowseForFoldersButton_SelectedFoldersTextBox.Text = null;
	}


	/// <summary>
	/// Main button's event handler for files and folder Supplemental policy creation
	/// </summary>
	private async void CreateFilesAndFoldersSupplementalPolicyButton_Click()
	{

		// Close the teaching tip if it's open when user presses the button
		// it will be opened again if necessary
		CreateSupplementalPolicyTeachingTip.IsOpen = false;

		_FilesAndFoldersSupplementalPolicyPath = null;

		ViewModel.FilesAndFoldersInfoBarActionButtonVisibility = Visibility.Collapsed;

		// Make sure the InfoBar is closed initially. if there will be an error, we don't want it stay open from previous runs.
		FilesAndFoldersInfoBar.IsOpen = false;

		// Reset the progress ring from previous runs or in case an error occurred
		ViewModel.FilesAndFoldersProgressRingValue = 0;

		if (filesAndFoldersFilePaths.Count is 0 && filesAndFoldersFolderPaths.Count is 0)
		{
			CreateSupplementalPolicyTeachingTip.IsOpen = true;
			CreateSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("SelectFilesOrFoldersTitle");
			CreateSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("NoFilesOrFoldersSelected");
			return;
		}

		// use the policy to merge with file if that option is enabled by the user
		if (ViewModel.OperationModeComboBoxSelectedIndex is 1)
		{
			if (ViewModel.PolicyFileToMergeWith is null)
			{
				CreateSupplementalPolicyTeachingTip.IsOpen = true;
				CreateSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("SelectPolicyToAddRulesToTitle");
				CreateSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectPolicyToAddRulesToSubtitle");
				return;
			}
		}
		else if (filesAndFoldersBasePolicyPath is null)
		{
			CreateSupplementalPolicyTeachingTip.IsOpen = true;
			CreateSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("SelectBasePolicyTitle");
			CreateSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectBasePolicySubtitle");
			return;
		}

		// Only check for policy name if user hasn't provided a policy to add the rules to
		if (ViewModel.OperationModeComboBoxSelectedIndex is 0 && string.IsNullOrWhiteSpace(filesAndFoldersSupplementalPolicyName))
		{
			CreateSupplementalPolicyTeachingTip.IsOpen = true;
			CreateSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("ChoosePolicyNameTitle");
			CreateSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("ChoosePolicyNameSubtitle");
			return;
		}

		bool errorsOccurred = false;

		try
		{
			FilesAndFoldersPolicyDeployToggleButton.IsEnabled = false;
			CreateFilesAndFoldersSupplementalPolicyButton.IsEnabled = false;
			FilesAndFoldersBrowseForFilesSettingsCard.IsEnabled = false;
			FilesAndFoldersBrowseForFilesButton.IsEnabled = false;
			FilesAndFoldersBrowseForFoldersSettingsCard.IsEnabled = false;
			FilesAndFoldersBrowseForFoldersButton.IsEnabled = false;
			FilesAndFoldersPolicyNameTextBox.IsEnabled = false;
			ViewModel.FilesAndFoldersBrowseForBasePolicyIsEnabled = false;
			ScanLevelComboBoxSettingsCard.IsEnabled = false;
			ScanLevelComboBox.IsEnabled = false;
			FilesAndFoldersViewFileDetailsSettingsCard.IsEnabled = true;

			FilesAndFoldersInfoBar.IsClosable = false;

			FilesAndFoldersInfoBar.IsOpen = true;
			FilesAndFoldersInfoBar.Severity = InfoBarSeverity.Informational;
			string msg1 = string.Format(
				GlobalVars.Rizz.GetString("FindingAllAppControlFilesMessage"),
				filesAndFoldersFilePaths.Count,
				filesAndFoldersFolderPaths.Count
			);
			FilesAndFoldersInfoBar.Message = msg1;
			Logger.Write(msg1);


			double radialGaugeValue = ScalabilityRadialGauge.Value; // Value from radial gauge

			ScalabilityRadialGauge.IsEnabled = false;

			await Task.Run(async () =>
			{

				DirectoryInfo[] selectedDirectories = [];

				// Convert user selected folder paths that are strings to DirectoryInfo objects
				selectedDirectories = [.. filesAndFoldersFolderPaths.Select(dir => new DirectoryInfo(dir))];

				FileInfo[] selectedFiles = [];

				IEnumerable<FileIdentity> LocalFilesResults = [];

				// Convert user selected file paths that are strings to FileInfo objects
				selectedFiles = [.. filesAndFoldersFilePaths.Select(file => new FileInfo(file))];

				// Do the following steps only if Wildcard paths aren't going to be used because then only the selected folder paths are needed
				if (!usingWildCardFilePathRules)
				{

					// Collect all of the AppControl compatible files from user selected directories and files
					(IEnumerable<FileInfo>, int) DetectedFilesInSelectedDirectories = FileUtility.GetFilesFast(selectedDirectories, selectedFiles, null);

					// Make sure there are AppControl compatible files
					if (DetectedFilesInSelectedDirectories.Item2 is 0)
					{
						_ = DispatcherQueue.TryEnqueue(() =>
						{
							CreateSupplementalPolicyTeachingTip.IsOpen = true;
							CreateSupplementalPolicyTeachingTip.Title = "No compatible files detected";
							CreateSupplementalPolicyTeachingTip.Subtitle = "No AppControl compatible files have been detected in any of the files and folder paths you selected";
							errorsOccurred = true;
							FilesAndFoldersInfoBar.IsOpen = false;
							FilesAndFoldersInfoBar.Severity = InfoBarSeverity.Informational;
							FilesAndFoldersInfoBar.Message = null;
						});

						return;
					}

					string msg2 = string.Format(
						GlobalVars.Rizz.GetString("ScanningTotalAppControlFilesMessage"),
						DetectedFilesInSelectedDirectories.Item2
					);
					Logger.Write(msg2);

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						FilesAndFoldersInfoBar.Message = msg2;
					});


					// Scan all of the detected files from the user selected directories
					// Add a reference to the ViewModel class to each item so we can use it for navigation in the XAML
					LocalFilesResults = LocalFilesScan.Scan(
						DetectedFilesInSelectedDirectories,
						(ushort)radialGaugeValue,
						ViewModel.FilesAndFoldersProgressRingValueProgress,
						ViewModel,
						(fi, vm) => fi.ParentViewModelCreateSupplementalPolicyVM = vm);

					// Clear variables responsible for the ListView
					ViewModel.filesAndFoldersScanResultsList.Clear();

					ViewModel.filesAndFoldersScanResultsList.AddRange(LocalFilesResults);

					await DispatcherQueue.EnqueueAsync(() =>
					{
						// Add the results of the directories scans to the ListView
						ViewModel.FilesAndFoldersScanResults = new(LocalFilesResults);

						ViewModel.CalculateColumnWidths();

						ViewModel.UpdateTotalFilesFilesAndFolders();
					});

					string msg3 = "Scan completed, creating the Supplemental policy";

					Logger.Write(msg3);

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						FilesAndFoldersInfoBar.Message = msg3;
					});

				}


				DirectoryInfo stagingArea = StagingArea.NewStagingArea("FilesAndFoldersSupplementalPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. LocalFilesResults], level: filesAndFoldersScanLevel, folderPaths: filesAndFoldersFolderPaths);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Allow);

				string OutputPath = ViewModel.OperationModeComboBoxSelectedIndex is 1 ? ViewModel.PolicyFileToMergeWith! : Path.Combine(GlobalVars.UserConfigDir, $"{filesAndFoldersSupplementalPolicyName}.xml");

				if (ViewModel.OperationModeComboBoxSelectedIndex is 1)
				{
					// Merge the new supplemental policy with the user selected policy - user selected policy is the main one in the merge operation
					Merger.Merge(OutputPath, [EmptyPolicyPath]);
				}
				else
				{
					// Instantiate the user selected Base policy
					SiPolicy.SiPolicy policyObj = Management.Initialize(filesAndFoldersBasePolicyPath, null);

					// Set the BasePolicyID of our new policy to the one from user selected policy
					_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, filesAndFoldersSupplementalPolicyName, policyObj.BasePolicyID, null);

					// Configure policy rule options
					if (filesAndFoldersScanLevel is ScanLevels.FilePath || filesAndFoldersScanLevel is ScanLevels.WildCardFolderPath)
					{
						Logger.Write(string.Format(
							GlobalVars.Rizz.GetString("SelectedScanLevelMessage"),
							filesAndFoldersScanLevel
						));

						CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental, rulesToAdd: [OptionType.DisabledRuntimeFilePathRuleProtection]);
					}
					else
					{
						CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);
					}

					// Set policy version
					SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

					// Copying the policy file to the User Config directory - outside of the temporary staging area
					File.Copy(EmptyPolicyPath, OutputPath, true);

				}

				// Assign the supplemental policy file path to the local variable
				_FilesAndFoldersSupplementalPolicyPath = OutputPath;

				// Use the name of the user selected file for CIP file name, otherwise use the name of the supplemental policy provided by the user
				string CIPName = ViewModel.OperationModeComboBoxSelectedIndex is 1 ? $"{Path.GetFileNameWithoutExtension(ViewModel.PolicyFileToMergeWith!)}.cip" : $"{filesAndFoldersSupplementalPolicyName}.cip";
				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// If user selected to deploy the policy
				if (filesAndFoldersDeployButton)
				{
					string msg4 = GlobalVars.Rizz.GetString("DeployingThePolicy");

					Logger.Write(msg4);

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						FilesAndFoldersInfoBar.Message = msg4;
					});

					CiToolHelper.UpdatePolicy(CIPPath);
				}
				// If not deploying it, copy the CIP file to the user config directory, just like the XML policy file
				else
				{
					string finalCIPPath = Path.Combine(GlobalVars.UserConfigDir, Path.GetFileName(CIPPath));
					File.Copy(CIPPath, finalCIPPath, true);
				}
			});

		}
		catch (Exception ex)
		{
			FilesAndFoldersInfoBar.Severity = InfoBarSeverity.Error;
			FilesAndFoldersInfoBar.Message = GlobalVars.Rizz.GetString("ErrorOccurredCreatingPolicy") + ex.Message;

			Logger.Write(ErrorWriter.FormatException(ex));

			errorsOccurred = true;
		}
		finally
		{
			if (!errorsOccurred)
			{
				FilesAndFoldersInfoBar.Severity = InfoBarSeverity.Success;
				FilesAndFoldersInfoBar.Message = string.Format(
					GlobalVars.Rizz.GetString("SuccessfullyCreatedSupplementalPolicyMessage"),
					filesAndFoldersSupplementalPolicyName
				);

				ViewModel.FilesAndFoldersInfoBarActionButtonVisibility = Visibility.Visible;
			}

			FilesAndFoldersInfoBar.IsClosable = true;

			FilesAndFoldersPolicyDeployToggleButton.IsEnabled = true;
			CreateFilesAndFoldersSupplementalPolicyButton.IsEnabled = true;

			// Only re-enable these buttons if wildcard file path is not used
			// Because only folder paths are required for wildcard FileRule paths
			if (!usingWildCardFilePathRules)
			{
				FilesAndFoldersBrowseForFilesSettingsCard.IsEnabled = true;
				FilesAndFoldersBrowseForFilesButton.IsEnabled = true;
			}

			FilesAndFoldersBrowseForFoldersSettingsCard.IsEnabled = true;
			FilesAndFoldersBrowseForFoldersButton.IsEnabled = true;
			FilesAndFoldersPolicyNameTextBox.IsEnabled = true;
			ViewModel.FilesAndFoldersBrowseForBasePolicyIsEnabled = true;
			ScanLevelComboBoxSettingsCard.IsEnabled = true;
			ScanLevelComboBox.IsEnabled = true;

			ScalabilityRadialGauge.IsEnabled = true;
		}
	}

	// Event handler for RadialGauge ValueChanged
	private void ScalabilityRadialGauge_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
	{
		// Update the button content with the current value of the gauge
		ScalabilityButton.Content = $"Scalability: {((RadialGauge)sender).Value:N0}";
	}

	/// <summary>
	/// Event handler for the clear button for the text box of selected Base policy path
	/// </summary>
	private void FilesAndFoldersBrowseForBasePolicyButton_Flyout_Clear_Click()
	{
		filesAndFoldersBasePolicyPath = null;
		FilesAndFoldersBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
	}

	/// <summary>
	/// Path to the Files and Folders Supplemental policy XML file
	/// </summary>
	private string? _FilesAndFoldersSupplementalPolicyPath;

	/// <summary>
	/// Opens a policy editor for files and folders using a specified supplemental policy path.
	/// </summary>
	private async void OpenInPolicyEditor_FilesAndFolders()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_FilesAndFoldersSupplementalPolicyPath);
	}

	#endregion


	#region Certificates scan


	// Selected Certificate File Paths
	private readonly HashSet<string> CertificatesBasedCertFilePaths = [];

	// Selected Base policy path
	private string? CertificatesBasedBasePolicyPath;

	// Selected Supplemental policy name
	private string? CertificatesBasedSupplementalPolicyName;

	private bool CertificatesBasedDeployButton;

	// Signing Scenario
	// True = User Mode
	// False = Kernel Mode
	private bool signingScenario = true;

	/// <summary>
	/// Deploy button event handler for Certificates-based Supplemental policy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void CertificatesPolicyDeployToggleButton_Click(object sender, RoutedEventArgs e)
	{
		CertificatesBasedDeployButton = ((ToggleButton)sender).IsChecked ?? false;
	}

	private void CertificatesBrowseForCertsButton_Click()
	{
		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.CertificatePickerFilter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				_ = CertificatesBasedCertFilePaths.Add(file);
			}
		}
	}

	private void CertificatesBrowseForCertsSettingsCard_Click()
	{
		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.CertificatePickerFilter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				_ = CertificatesBasedCertFilePaths.Add(file);
			}
		}
	}

	private void CertificatesPolicyNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		CertificatesBasedSupplementalPolicyName = ((TextBox)sender).Text;
	}


	private void CertificatesBrowseForBasePolicyButton_Click()
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			CertificatesBasedBasePolicyPath = selectedFile;

			CertificatesBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}
	}


	private void UserModeRadioButton_Checked()
	{
		signingScenario = true;
	}

	private void KernelModeRadioButton_Checked()
	{
		signingScenario = false;
	}


	/// <summary>
	/// Main Button - Creates the Certificates-based Supplemental policy
	/// </summary>
	private async void CreateCertificatesSupplementalPolicyButton_Click()
	{
		bool errorsOccurred = false;

		ViewModel.CertificatesInfoBarActionButtonVisibility = Visibility.Collapsed;

		// Make sure the InfoBar is closed initially. if there will be an error, we don't want it stay open from previous runs.
		CertificatesInfoBar.IsOpen = false;

		if (CertificatesBasedCertFilePaths.Count is 0)
		{
			CreateCertificateBasedSupplementalPolicyTeachingTip.IsOpen = true;
			CreateCertificateBasedSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("SelectCertificatesTitle");
			CreateCertificateBasedSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectCertificatesSubtitle");
			return;
		}

		// use the policy to merge with file if that option is enabled by the user
		if (ViewModel.OperationModeComboBoxSelectedIndex is 1)
		{
			if (ViewModel.PolicyFileToMergeWith is null)
			{
				CreateCertificateBasedSupplementalPolicyTeachingTip.IsOpen = true;
				CreateCertificateBasedSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("SelectPolicyToAddRulesToTitle");
				CreateCertificateBasedSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectPolicyToAddRulesToSubtitle");
				return;
			}
		}
		else if (CertificatesBasedBasePolicyPath is null)
		{
			CreateCertificateBasedSupplementalPolicyTeachingTip.IsOpen = true;
			CreateCertificateBasedSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("SelectBasePolicyTitle");
			CreateCertificateBasedSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectBasePolicySubtitle");
			return;
		}

		// Only check for policy name if user hasn't provided a policy to add the rules to
		if (ViewModel.OperationModeComboBoxSelectedIndex is 0 && string.IsNullOrWhiteSpace(CertificatesBasedSupplementalPolicyName))
		{
			CreateCertificateBasedSupplementalPolicyTeachingTip.IsOpen = true;
			CreateCertificateBasedSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("ChoosePolicyNameTitle");
			CreateCertificateBasedSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("ChoosePolicyNameSubtitle");
			return;
		}

		_CertificatesSupplementalPolicyPath = null;

		try
		{
			CreateCertificatesSupplementalPolicyButton.IsEnabled = false;
			CertificatesPolicyDeployToggleButton.IsEnabled = false;
			CertificatesBrowseForCertsButton.IsEnabled = false;
			CertificatesBrowseForCertsSettingsCard.IsEnabled = false;
			CertificatesPolicyNameTextBox.IsEnabled = false;
			ViewModel.CertificatesBrowseForBasePolicyIsEnabled = false;
			CertificatesSigningScenarioSettingsCard.IsEnabled = false;
			SigningScenariosRadioButtons.IsEnabled = false;

			CertificatesInfoBar.IsOpen = true;
			CertificatesInfoBar.IsClosable = false;
			CertificatesInfoBar.Message = string.Format(
				GlobalVars.Rizz.GetString("CreatingCertificatesPolicyMessage"),
				CertificatesBasedCertFilePaths.Count
			);
			CertificatesInfoBar.Severity = InfoBarSeverity.Informational;


			await Task.Run(() =>
			{
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("CertificatesSupplementalPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				List<CertificateSignerCreator> certificateResults = [];

				foreach (string certificate in CertificatesBasedCertFilePaths)
				{
					// Create a certificate object from the .cer file
					X509Certificate2 CertObject = X509CertificateLoader.LoadCertificateFromFile(certificate);

					// Create rule for the certificate based on the first element in its chain
					certificateResults.Add(new CertificateSignerCreator(
					   CertificateHelper.GetTBSCertificate(CertObject),
						(CryptoAPI.GetNameString(CertObject.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false)),
						signingScenario ? 1 : 0 // By default it's set to User-Mode in XAML/UI
					));
				}


				if (certificateResults.Count > 0)
				{
					// Generating signer rules
					NewCertificateSignerRules.CreateAllow(EmptyPolicyPath, certificateResults);
				}
				else
				{
					_ = DispatcherQueue.TryEnqueue(() =>
					{
						CertificatesInfoBar.IsOpen = true;
						CertificatesInfoBar.Message = GlobalVars.Rizz.GetString("NoCertificateDetailsFoundCreatingPolicy");
						CertificatesInfoBar.Severity = InfoBarSeverity.Warning;
					});

					errorsOccurred = true;
					return;
				}

				Merger.Merge(EmptyPolicyPath, [EmptyPolicyPath]);

				string OutputPath = ViewModel.OperationModeComboBoxSelectedIndex is 1
					? ViewModel.PolicyFileToMergeWith!
					: Path.Combine(GlobalVars.UserConfigDir, $"{CertificatesBasedSupplementalPolicyName}.xml");

				if (ViewModel.OperationModeComboBoxSelectedIndex is 1)
				{
					// Merge the new supplemental policy with the user selected policy - user selected policy is the main one in the merge operation
					Merger.Merge(OutputPath, [EmptyPolicyPath]);
				}
				else
				{
					// Instantiate the user selected Base policy
					SiPolicy.SiPolicy policyObj = Management.Initialize(CertificatesBasedBasePolicyPath, null);

					// Set the BasePolicyID of our new policy to the one from user selected policy
					_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, CertificatesBasedSupplementalPolicyName, policyObj.BasePolicyID, null);

					// Configure policy rule options
					CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);

					// Set policy version
					SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

					// Copying the policy file to the User Config directory - outside of the temporary staging area
					File.Copy(EmptyPolicyPath, OutputPath, true);
				}

				_CertificatesSupplementalPolicyPath = OutputPath;

				// Use the name of the user selected file for CIP file name, otherwise use the name of the supplemental policy provided by the user
				string CIPName = ViewModel.OperationModeComboBoxSelectedIndex is 1
					? $"{Path.GetFileNameWithoutExtension(ViewModel.PolicyFileToMergeWith!)}.cip"
					: $"{CertificatesBasedSupplementalPolicyName}.cip";
				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// If user selected to deploy the policy
				if (CertificatesBasedDeployButton)
				{
					string msg4 = GlobalVars.Rizz.GetString("DeployingThePolicy");

					Logger.Write(msg4);

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						CertificatesInfoBar.Message = msg4;
					});

					CiToolHelper.UpdatePolicy(CIPPath);
				}
				// If not deploying it, copy the CIP file to the user config directory, just like the XML policy file
				else
				{
					string finalCIPPath = Path.Combine(GlobalVars.UserConfigDir, Path.GetFileName(CIPPath));
					File.Copy(CIPPath, finalCIPPath, true);
				}
			});
		}
		catch (Exception ex)
		{
			CertificatesInfoBar.Severity = InfoBarSeverity.Error;
			CertificatesInfoBar.Message = GlobalVars.Rizz.GetString("ErrorOccurredCreatingPolicy") + ex.Message;

			Logger.Write(ErrorWriter.FormatException(ex));

			errorsOccurred = true;
		}
		finally
		{
			if (!errorsOccurred)
			{
				CertificatesInfoBar.Severity = InfoBarSeverity.Success;
				CertificatesInfoBar.Message = string.Format(
					GlobalVars.Rizz.GetString("SuccessfullyCreatedCertificatePolicyMessage"),
					CertificatesBasedSupplementalPolicyName
				);

				ViewModel.CertificatesInfoBarActionButtonVisibility = Visibility.Visible;
			}

			CreateCertificatesSupplementalPolicyButton.IsEnabled = true;
			CertificatesPolicyDeployToggleButton.IsEnabled = true;
			CertificatesBrowseForCertsButton.IsEnabled = true;
			CertificatesBrowseForCertsSettingsCard.IsEnabled = true;
			CertificatesPolicyNameTextBox.IsEnabled = true;
			ViewModel.CertificatesBrowseForBasePolicyIsEnabled = true;
			CertificatesSigningScenarioSettingsCard.IsEnabled = true;
			SigningScenariosRadioButtons.IsEnabled = true;

			CertificatesInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for the clear button for the text box of selected Base policy path
	/// </summary>
	private void CertificatesBrowseForBasePolicyButton_Flyout_Clear_Click()
	{
		CertificatesBasedBasePolicyPath = null;
		CertificatesBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
	}


	/// <summary>
	/// Path to the Certificates Supplemental policy XML file
	/// </summary>
	private string? _CertificatesSupplementalPolicyPath;


	/// <summary>
	/// Opens a policy editor for Certificates using a specified supplemental policy path.
	/// </summary>
	private async void OpenInPolicyEditor_Certificates()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_CertificatesSupplementalPolicyPath);
	}

	#endregion


	#region ISG

	// Path to the base policy for the ISG based supplemental policy
	private string? ISGBasedBasePolicyPath;

	private bool ISGBasedDeployButton;

	// Selected Supplemental policy name
	private string? ISGBasedSupplementalPolicyName;

	/// <summary>
	/// Event handler for the main button - to create Supplemental ISG based policy
	/// </summary>
	private async void CreateISGSupplementalPolicyButton_Click()
	{

		ViewModel.ISGInfoBarActionButtonVisibility = Visibility.Collapsed;

		// Make sure the InfoBar is closed initially. if there will be an error, we don't want it stay open from previous runs.
		ISGInfoBar.IsOpen = false;

		bool errorsOccurred = false;

		// use the policy to merge with file if that option is enabled by the user
		if (ViewModel.OperationModeComboBoxSelectedIndex is 1)
		{
			if (ViewModel.PolicyFileToMergeWith is null)
			{
				CreateISGSupplementalPolicyTeachingTip.IsOpen = true;
				CreateISGSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("SelectPolicyToAddRulesToTitle");
				CreateISGSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectPolicyToAddRulesToSubtitle");
				return;
			}
		}
		else if (ISGBasedBasePolicyPath is null)
		{
			CreateISGSupplementalPolicyTeachingTip.IsOpen = true;
			CreateISGSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("SelectBasePolicyTitle");
			CreateISGSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectBasePolicySubtitle");
			return;
		}

		_ISGSupplementalPolicyPath = null;

		try
		{
			CreateISGSupplementalPolicyButton.IsEnabled = false;
			ISGPolicyDeployToggleButton.IsEnabled = false;
			ISGPolicyNameTextBox.IsEnabled = false;
			ViewModel.ISGBrowseForBasePolicyIsEnabled = false;

			ISGInfoBar.IsOpen = true;
			ISGInfoBar.IsClosable = false;
			ISGInfoBar.Message = GlobalVars.Rizz.GetString("CreatingISGBasedSupplementalPolicyMessage");
			ISGInfoBar.Severity = InfoBarSeverity.Informational;

			await Task.Run(() =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("ISGBasedSupplementalPolicy");

				// Defining the paths
				string savePathTemp = Path.Combine(stagingArea.FullName, "ISGBasedSupplementalPolicy.xml");
				string OutputPath = ViewModel.OperationModeComboBoxSelectedIndex is 1 ? ViewModel.PolicyFileToMergeWith! : Path.Combine(GlobalVars.UserConfigDir, "ISGBasedSupplementalPolicy.xml");

				if (ViewModel.OperationModeComboBoxSelectedIndex is 1)
				{
					// Configure policy rule options only
					CiRuleOptions.Set(filePath: OutputPath, rulesToAdd: [OptionType.EnabledIntelligentSecurityGraphAuthorization, OptionType.EnabledInvalidateEAsonReboot]);
				}
				else
				{
					// Instantiate the user-selected base policy
					SiPolicy.SiPolicy basePolicyObj = Management.Initialize(ISGBasedBasePolicyPath, null);

					// Instantiate the supplemental policy
					SiPolicy.SiPolicy supplementalPolicyObj = Management.Initialize(GlobalVars.ISGOnlySupplementalPolicyPath, null);

					// If policy name was provided by user
					if (!string.IsNullOrWhiteSpace(ISGBasedSupplementalPolicyName))
					{
						// Finding the policy name in the settings
						List<Setting> nameSettings = [.. supplementalPolicyObj.Settings.Where(x =>
					string.Equals(x.Provider, "PolicyInfo", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(x.Key, "Information", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(x.ValueName, "Name", StringComparison.OrdinalIgnoreCase))];

						SettingValueType settingVal = new()
						{
							Item = ISGBasedSupplementalPolicyName
						};

						foreach (Setting setting in nameSettings)
						{
							setting.Value = settingVal;
						}
					}

					// Replace the BasePolicyID in the Supplemental policy
					supplementalPolicyObj.BasePolicyID = basePolicyObj.BasePolicyID;

					// Save the policy object to XML file in the staging Area
					Management.SavePolicyToFile(supplementalPolicyObj, savePathTemp);

					// Copying the policy file to the User Config directory - outside of the temporary staging area
					File.Copy(savePathTemp, OutputPath, true);

				}

				_ISGSupplementalPolicyPath = OutputPath;

				// Use the name of the user selected file for CIP file name, otherwise use the name of the supplemental policy provided by the user
				string CIPName = ViewModel.OperationModeComboBoxSelectedIndex is 1 ? $"{Path.GetFileNameWithoutExtension(ViewModel.PolicyFileToMergeWith!)}.cip" : "ISGBasedSupplementalPolicy.cip";
				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// If the policy is to be deployed
				if (ISGBasedDeployButton)
				{
					string msg4 = GlobalVars.Rizz.GetString("DeployingThePolicy");

					Logger.Write(msg4);

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						ISGInfoBar.Message = msg4;
					});

					// Prepare the ISG services
					ConfigureISGServices.Configure();

					// Deploy the signed CIP file
					CiToolHelper.UpdatePolicy(CIPPath);
				}
				// If not deploying it, copy the CIP file to the user config directory, just like the XML policy file
				else
				{
					string finalCIPPath = Path.Combine(GlobalVars.UserConfigDir, Path.GetFileName(CIPPath));
					File.Copy(CIPPath, finalCIPPath, true);
				}

			});

		}
		catch (Exception ex)
		{
			errorsOccurred = true;

			ISGInfoBar.Severity = InfoBarSeverity.Error;
			ISGInfoBar.Message = GlobalVars.Rizz.GetString("ErrorOccurredCreatingPolicy") + ex.Message;

			Logger.Write(ErrorWriter.FormatException(ex));
		}
		finally
		{
			if (!errorsOccurred)
			{
				ISGInfoBar.Severity = InfoBarSeverity.Success;

				ISGInfoBar.Message = GlobalVars.Rizz.GetString("SuccessfullyCreatedISGBasedSupplementalPolicyMessage");

				ViewModel.ISGInfoBarActionButtonVisibility = Visibility.Visible;
			}

			CreateISGSupplementalPolicyButton.IsEnabled = true;
			ISGPolicyDeployToggleButton.IsEnabled = true;
			ISGPolicyNameTextBox.IsEnabled = true;
			ViewModel.ISGBrowseForBasePolicyIsEnabled = true;

			ISGInfoBar.IsClosable = true;
		}
	}


	private void ISGPolicyDeployToggleButton_Click(object sender, RoutedEventArgs e)
	{
		ISGBasedDeployButton = ((ToggleButton)sender).IsChecked ?? false;
	}


	private void ISGPolicyNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		ISGBasedSupplementalPolicyName = ((TextBox)sender).Text;
	}

	private void ISGBrowseForBasePolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			ISGBasedBasePolicyPath = selectedFile;

			ISGBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}
	}


	private void ISGBrowseForBasePolicyButton_Flyout_Clear_Click()
	{
		ISGBasedBasePolicyPath = null;
		ISGBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
	}


	/// <summary>
	/// Path to the ISG Supplemental policy XML file
	/// </summary>
	private string? _ISGSupplementalPolicyPath;


	/// <summary>
	/// Opens a policy editor for ISG using a specified supplemental policy path.
	/// </summary>
	private async void OpenInPolicyEditor_ISG()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_ISGSupplementalPolicyPath);
	}

	#endregion


	#region Strict Kernel-Mode Supplemental Policy

	// Path to the base policy for the Strict kernel-mode supplemental policy
	private string? StrictKernelModeBasePolicyPath;

	private void StrictKernelModeScanButton_Click()
	{
		StrictKernelModePerformScans(false);
	}

	private void DetectedKernelModeFilesDetailsSettingsCard_Click()
	{
		App._nav.Navigate(typeof(StrictKernelPolicyScanResults), null);
	}


	/// <summary>
	/// Browse for Base Policy - Button Click
	/// </summary>
	private void StrictKernelModeBrowseForBasePolicyButton_Click()
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			StrictKernelModeBasePolicyPath = selectedFile;

			// Add the file path to the GUI's text box
			StrictKernelModeBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}
	}


	/// <summary>
	/// Event handler for the clear button for the text box of selected Base policy path
	/// </summary>
	private void StrictKernelModeBrowseForBasePolicyButton_Flyout_Clear_Click()
	{
		StrictKernelModeBasePolicyPath = null;
		StrictKernelModeBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
	}


	private void StrictKernelModeScanSinceLastRebootButton_Click()
	{
		StrictKernelModePerformScans(true);
	}


	private async void StrictKernelModePerformScans(bool OnlyAfterReboot)
	{
		bool ErrorsOccurred = false;

		try
		{
			StrictKernelModeScanButton.IsEnabled = false;
			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = false;

			StrictKernelModeInfoBar.IsClosable = false;
			StrictKernelModeInfoBar.IsOpen = true;
			StrictKernelModeInfoBar.Severity = InfoBarSeverity.Informational;
			StrictKernelModeInfoBar.Message = GlobalVars.Rizz.GetString("ScanningSystemForEvents");
			StrictKernelModeSection.IsExpanded = true;

			// Clear variables responsible for the ListView
			ViewModel.StrictKernelModeScanResults.Clear();
			ViewModel.StrictKernelModeScanResultsList.Clear();


			// Grab the App Control Logs
			HashSet<FileIdentity> Output = await GetEventLogsData.GetAppControlEvents();

			// Filter the logs
			// Only DLL and SYS files must be included
			await Task.Run(() =>
			{
				if (OnlyAfterReboot)
				{
					DateTime lastRebootTime = DateTime.Now - TimeSpan.FromMilliseconds(Environment.TickCount64);

					// Signed kernel-mode files that were run after last reboot
					Output = [.. Output.Where(fileIdentity => fileIdentity.TimeCreated >= lastRebootTime && fileIdentity.SISigningScenario is 0 && fileIdentity.SignatureStatus is SignatureStatus.IsSigned)];
				}
				else
				{
					// Signed kernel-mode files
					Output = [.. Output.Where(fileIdentity => fileIdentity.SISigningScenario is 0 && fileIdentity.SignatureStatus is SignatureStatus.IsSigned)];
				}
			});

			// If any logs were generated since audit mode policy was deployed
			if (Output.Count is 0)
			{
				StrictKernelModeInfoBar.Message = GlobalVars.Rizz.GetString("NoLogsGeneratedDuringAuditPhase");
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Warning;
				ErrorsOccurred = true;
				return;
			}

			StrictKernelModeInfoBar.Message = string.Format(GlobalVars.Rizz.GetString("GeneratedLogsDuringAuditPhase"), Output.Count);

			// Add the event logs to the List
			ViewModel.StrictKernelModeScanResultsList.AddRange(Output);

			// Add the event logs to the ObservableCollection
			foreach (FileIdentity item in Output)
			{
				// Add a reference to the ViewModel class to each item for navigation in the XAML
				item.ParentViewModelCreateSupplementalPolicyVM = ViewModel;
				ViewModel.StrictKernelModeScanResults.Add(item);
			}

			ViewModel.CalculateColumnWidthsStrictKernelMode();

			ViewModel.UpdateTotalFilesStrictKernelMode();

			DetectedKernelModeFilesDetailsSettingsCard.IsEnabled = true;
		}
		catch (Exception ex)
		{
			ErrorsOccurred = true;

			StrictKernelModeInfoBar.Severity = InfoBarSeverity.Error;
			StrictKernelModeInfoBar.Message = string.Format(GlobalVars.Rizz.GetString("ErrorOccurredWhileScanningSystem"), ex.Message);

			Logger.Write(ErrorWriter.FormatException(ex));
		}
		finally
		{
			StrictKernelModeScanButton.IsEnabled = true;
			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = true;

			if (!ErrorsOccurred)
			{
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Success;
				StrictKernelModeInfoBar.Message = GlobalVars.Rizz.GetString("SuccessfullyScannedSystemForEvents");
			}

			StrictKernelModeInfoBar.IsClosable = true;
		}
	}


	/// <summary>
	/// Event handler for the create button
	/// </summary>
	private async void StrictKernelModeCreateButton_Click()
	{
		// Close the teaching tip if it's open when user presses the button
		// it will be opened again if necessary
		StrictKernelModeCreateButtonTeachingTip.IsOpen = false;

		ViewModel.StrictKernelModeInfoBarActionButtonVisibility = Visibility.Collapsed;

		// Make sure the InfoBar is closed initially. if there will be an error, we don't want it stay open from previous runs.
		StrictKernelModeInfoBar.IsOpen = false;

		if (ViewModel.StrictKernelModeScanResults.Count is 0)
		{
			StrictKernelModeCreateButtonTeachingTip.IsOpen = true;
			StrictKernelModeCreateButtonTeachingTip.Title = GlobalVars.Rizz.GetString("StrictKernelModeTeachingTipTitle");
			StrictKernelModeCreateButtonTeachingTip.Subtitle = GlobalVars.Rizz.GetString("StrictKernelModeTeachingTipSubtitleNoItems");
			return;
		}

		// Only check for policy name if user hasn't provided a policy to add the rules to
		if (ViewModel.OperationModeComboBoxSelectedIndex is 0 && string.IsNullOrWhiteSpace(StrictKernelModePolicyNameTextBox.Text))
		{
			StrictKernelModeCreateButtonTeachingTip.IsOpen = true;
			StrictKernelModeCreateButtonTeachingTip.Title = GlobalVars.Rizz.GetString("ChoosePolicyNameTitle");
			StrictKernelModeCreateButtonTeachingTip.Subtitle = GlobalVars.Rizz.GetString("ChoosePolicyNameSubtitle");
			return;
		}


		// use the policy to merge with file if that option is enabled by the user
		if (ViewModel.OperationModeComboBoxSelectedIndex is 1)
		{
			if (ViewModel.PolicyFileToMergeWith is null)
			{
				StrictKernelModeCreateButtonTeachingTip.IsOpen = true;
				StrictKernelModeCreateButtonTeachingTip.Title = GlobalVars.Rizz.GetString("SelectPolicyToAddRulesToTitle");
				StrictKernelModeCreateButtonTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectPolicyToAddRulesToSubtitle");
				return;
			}
		}
		else if (string.IsNullOrWhiteSpace(StrictKernelModeBasePolicyPath))
		{
			StrictKernelModeCreateButtonTeachingTip.IsOpen = true;
			StrictKernelModeCreateButtonTeachingTip.Title = GlobalVars.Rizz.GetString("SelectBasePolicyTitle");
			StrictKernelModeCreateButtonTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectBasePolicySubtitle");
			return;
		}

		_StrictKernelModeSupplementalPolicyPath = null;

		bool ErrorsOccurred = false;

		try
		{
			StrictKernelModeCreateButton.IsEnabled = false;
			StrictKernelModeDeployToggleButton.IsEnabled = false;
			StrictKernelModeAutoDetectAllDriversSettingsCard.IsClickEnabled = false;
			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = false;
			StrictKernelModeScanButton.IsEnabled = false;
			StrictKernelModeScanSinceLastRebootButton.IsEnabled = false;
			ViewModel.StrictKernelModeBrowseForBasePolicyIsEnabled = false;

			StrictKernelModeInfoBar.IsClosable = false;
			StrictKernelModeInfoBar.IsOpen = true;
			StrictKernelModeInfoBar.Severity = InfoBarSeverity.Informational;
			StrictKernelModeInfoBar.Message = string.Format(
				GlobalVars.Rizz.GetString("CreatingStrictKernelModePolicyMessage"),
				ViewModel.StrictKernelModeScanResults.Count
			);
			StrictKernelModeSection.IsExpanded = true;

			bool shouldDeploy = StrictKernelModeDeployToggleButton.IsChecked ?? false;

			string policyNameChosenByUser = string.Empty;

			// Enqueue the work to the UI thread
			await DispatcherQueue.EnqueueAsync(() =>
			{
				policyNameChosenByUser = StrictKernelModePolicyNameTextBox.Text;
			});

			await Task.Run(() =>
			{
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("StrictKernelModeSupplementalPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. ViewModel.StrictKernelModeScanResults], level: ScanLevels.FilePublisher);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Allow);


				string OutputPath = ViewModel.OperationModeComboBoxSelectedIndex is 1 ? ViewModel.PolicyFileToMergeWith! : Path.Combine(GlobalVars.UserConfigDir, $"{policyNameChosenByUser}.xml");

				if (ViewModel.OperationModeComboBoxSelectedIndex is 1)
				{
					// Merge the new supplemental policy with the user selected policy - user selected policy is the main one in the merge operation
					Merger.Merge(OutputPath, [EmptyPolicyPath]);
				}
				else
				{

					// Instantiate the user selected Base policy - To get its BasePolicyID
					SiPolicy.SiPolicy policyObj = Management.Initialize(StrictKernelModeBasePolicyPath, null);

					// Set the BasePolicyID of our new policy to the one from user selected policy
					_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, policyNameChosenByUser, policyObj.BasePolicyID, null);

					// Configure policy rule options
					CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);

					// Set policy version
					SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

					RemoveUserModeSS.Remove(EmptyPolicyPath);

					// Copying the policy file to the User Config directory - outside of the temporary staging area
					File.Copy(EmptyPolicyPath, OutputPath, true);

				}

				_StrictKernelModeSupplementalPolicyPath = OutputPath;

				// Use the name of the user selected file for CIP file name, otherwise use the name of the supplemental policy provided by the user
				string CIPName = ViewModel.OperationModeComboBoxSelectedIndex is 1 ? $"{Path.GetFileNameWithoutExtension(ViewModel.PolicyFileToMergeWith!)}.cip" : Path.Combine(stagingArea.FullName, $"{policyNameChosenByUser}.cip");
				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// If user selected to deploy the policy
				if (shouldDeploy)
				{
					string msg4 = GlobalVars.Rizz.GetString("DeployingThePolicy");

					Logger.Write(msg4);

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						StrictKernelModeInfoBar.Message = msg4;
					});

					CiToolHelper.UpdatePolicy(CIPPath);
				}
				// If not deploying it, copy the CIP file to the user config directory, just like the XML policy file
				else
				{
					string finalCIPPath = Path.Combine(GlobalVars.UserConfigDir, Path.GetFileName(CIPPath));
					File.Copy(CIPPath, finalCIPPath, true);
				}

			});
		}
		catch (Exception ex)
		{
			ErrorsOccurred = true;

			StrictKernelModeInfoBar.Severity = InfoBarSeverity.Error;
			StrictKernelModeInfoBar.Message = GlobalVars.Rizz.GetString("ErrorOccurredCreatingPolicy") + ex.Message;

			Logger.Write(ErrorWriter.FormatException(ex));
		}
		finally
		{
			if (!ErrorsOccurred)
			{
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Success;
				StrictKernelModeInfoBar.Message = GlobalVars.Rizz.GetString("SuccessfullyCreatedStrictKernelModePolicyMessage");

				ViewModel.StrictKernelModeInfoBarActionButtonVisibility = Visibility.Visible;
			}

			StrictKernelModeCreateButton.IsEnabled = true;
			StrictKernelModeDeployToggleButton.IsEnabled = true;
			StrictKernelModeAutoDetectAllDriversSettingsCard.IsClickEnabled = true;
			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = true;
			StrictKernelModeScanButton.IsEnabled = true;
			StrictKernelModeScanSinceLastRebootButton.IsEnabled = true;
			ViewModel.StrictKernelModeBrowseForBasePolicyIsEnabled = true;
			StrictKernelModeInfoBar.IsClosable = true;
		}
	}


	/// <summary>
	/// Detects the kernel-mode drivers from the system and scans them
	/// </summary>
	private async void DriverAutoDetector()
	{
		bool ErrorsOccurred = false;

		try
		{

			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = false;
			StrictKernelModeScanButton.IsEnabled = false;
			StrictKernelModeScanSinceLastRebootButton.IsEnabled = false;
			StrictKernelModeAutoDetectAllDriversSettingsCard.IsClickEnabled = false;
			StrictKernelModeCreateButton.IsEnabled = false;

			StrictKernelModeInfoBar.IsClosable = false;
			StrictKernelModeInfoBar.IsOpen = true;
			StrictKernelModeInfoBar.Severity = InfoBarSeverity.Informational;
			StrictKernelModeInfoBar.Message = GlobalVars.Rizz.GetString("ScanningSystemForDrivers");
			StrictKernelModeSection.IsExpanded = true;

			ViewModel.DriverAutoDetectionProgressRingValue = 0;

			List<FileInfo> kernelModeDriversList = [];

			await Task.Run(() =>
			{

				// Since there can be more than one folder due to localizations such as en-US then from each of the folders, the bootres.dll.mui file is added

				// Get the system drive
				string systemDrive = Environment.GetEnvironmentVariable("SystemDrive")!;

				// Define the directory path
				string directoryPath = Path.Combine(systemDrive, "Windows", "Boot", "Resources");

				// Iterate through each directory in the specified path
				foreach (string directory in Directory.GetDirectories(directoryPath))
				{
					// Add the desired file path to the list
					kernelModeDriversList.Add(new FileInfo(Path.Combine(directory, "bootres.dll.mui")));
				}

				DirectoryInfo sys32Dir = new(Path.Combine(systemDrive, "Windows", "System32"));

				(IEnumerable<FileInfo>, int) filesOutput = FileUtility.GetFilesFast([sys32Dir], null, [".dll", ".sys"]);

				kernelModeDriversList.AddRange(filesOutput.Item1);

			});

			if (kernelModeDriversList.Count is 0)
			{
				StrictKernelModeInfoBar.Message = GlobalVars.Rizz.GetString("NoKernelModeDriversDetected");
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Warning;
				DetectedKernelModeFilesDetailsSettingsCard.IsEnabled = false;
				ErrorsOccurred = true;
				return;
			}

			StrictKernelModeInfoBar.Message = string.Format(GlobalVars.Rizz.GetString("ScanningKernelModeFilesCount"), kernelModeDriversList.Count);

			IEnumerable<FileIdentity> LocalFilesResults = [];

			await Task.Run(() =>
			{
				// Scan all of the detected files from the user selected directories
				// Add a reference to the ViewModel class to each item so we can use it for navigation in the XAML
				LocalFilesResults = LocalFilesScan.Scan(
					(kernelModeDriversList, kernelModeDriversList.Count),
					3,
					ViewModel.DriverAutoDetectionProgressRingValueProgress,
					ViewModel,
					(fi, vm) => fi.ParentViewModelCreateSupplementalPolicyVM = vm);

				// Only keep the signed kernel-mode files
				LocalFilesResults = LocalFilesResults.Where(fileIdentity => fileIdentity.SISigningScenario is 0 && fileIdentity.SignatureStatus is SignatureStatus.IsSigned);

				ViewModel.StrictKernelModeScanResultsList.Clear();

				// Add the results to the List
				ViewModel.StrictKernelModeScanResultsList.AddRange(LocalFilesResults);
			});

			// Add the results to the ObservableCollection
			ViewModel.StrictKernelModeScanResults = new(LocalFilesResults);

			ViewModel.CalculateColumnWidthsStrictKernelMode();

			ViewModel.UpdateTotalFilesStrictKernelMode();

			DetectedKernelModeFilesDetailsSettingsCard.IsEnabled = true;
		}

		catch (Exception ex)
		{
			ErrorsOccurred = true;

			StrictKernelModeInfoBar.Severity = InfoBarSeverity.Error;
			StrictKernelModeInfoBar.Message = string.Format(GlobalVars.Rizz.GetString("ErrorOccurredScanningDrivers"), ex.Message);

			throw;
		}
		finally
		{
			if (!ErrorsOccurred)
			{
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Success;
				StrictKernelModeInfoBar.Message = GlobalVars.Rizz.GetString("SuccessfullyScannedSystemForDrivers");
			}

			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = true;
			StrictKernelModeScanButton.IsEnabled = true;
			StrictKernelModeScanSinceLastRebootButton.IsEnabled = true;
			StrictKernelModeAutoDetectAllDriversSettingsCard.IsClickEnabled = true;
			StrictKernelModeCreateButton.IsEnabled = true;

			StrictKernelModeInfoBar.IsClosable = true;
		}
	}


	/// <summary>
	/// Path to the StrictKernelMode Supplemental policy XML file
	/// </summary>
	private string? _StrictKernelModeSupplementalPolicyPath;


	/// <summary>
	/// Opens a policy editor for StrictKernelMode using a specified supplemental policy path.
	/// </summary>
	private async void OpenInPolicyEditor_StrictKernelMode()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_StrictKernelModeSupplementalPolicyPath);
	}

	#endregion


	#region Package Family Names

	// To track whether the expandable settings section for the PFN supplemental policy has expanded so the apps list can be pre-loaded
	private bool packagesLoadedOnExpand;

	// Path to the base policy for the PFN based supplemental policy
	private string? PFNBasePolicyPath;

	/// <summary>
	/// Event handler for the Refresh button to get the apps list
	/// </summary>
	private async void PFNRefreshAppsListButton_Click()
	{
		try
		{
			PFNRefreshAppsListButton.IsEnabled = false;

			PackagedAppsCollectionViewSource.Source = await GetAppsList.GetContactsGroupedAsync();
		}
		finally
		{
			PFNRefreshAppsListButton.IsEnabled = true;
		}
	}


	/// <summary>
	/// Event handler for the touch-initiated refresh action
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private async void PFNRefreshContainer_RefreshRequested(RefreshContainer sender, RefreshRequestedEventArgs args)
	{
		try
		{
			PFNRefreshAppsListButton.IsEnabled = false;

			PackagedAppsCollectionViewSource.Source = await GetAppsList.GetContactsGroupedAsync();
		}
		finally
		{
			PFNRefreshAppsListButton.IsEnabled = true;
		}
	}


	// Since we have a ScrollView around the page, it captures the mouse Scroll Wheel events.
	// We have to disable its scrolling ability while pointer is inside of the ListView.
	// Scrolling via touch or dragging the ListView's scrollbar via mouse doesn't require this and they work either way.
	private void PFNPackagedAppsListView_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (e.Pointer.PointerDeviceType is PointerDeviceType.Mouse)
		{
			// Disable vertical scrolling for the outer ScrollView only for mouse input
			MainScrollView.VerticalScrollMode = ScrollingScrollMode.Disabled;
		}
	}

	private void PFNPackagedAppsListView_PointerExited()
	{
		// Re-enable vertical scrolling for the outer ScrollView
		MainScrollView.VerticalScrollMode = ScrollingScrollMode.Enabled;

	}

	private void MainScrollView_PointerPressed(object sender, PointerRoutedEventArgs e)
	{
		if (e.Pointer.PointerDeviceType is not PointerDeviceType.Mouse)
		{
			// Always enable vertical scrolling for input that's not mouse
			MainScrollView.VerticalScrollMode = ScrollingScrollMode.Enabled;
		}
	}

	/// <summary>
	/// Event handler to select all apps in the ListView
	/// </summary>
	private void PFNSelectAllAppsListButton_Click()
	{
		// Ensure the ListView has items
		if (PFNPackagedAppsListView.ItemsSource is IEnumerable<object> items)
		{
			PFNPackagedAppsListView.SelectedItems.Clear(); // Clear any existing selection

			foreach (object item in items)
			{
				PFNPackagedAppsListView.SelectedItems.Add(item); // Add each item to SelectedItems
			}
		}
	}

	/// <summary>
	/// Event handler to remove all selections of apps in the ListView
	/// </summary>
	private void PFNRemoveSelectionAppsListButton_Click()
	{
		PFNPackagedAppsListView.SelectedItems.Clear();
	}


	/// <summary>
	/// Event handler to display the selected apps count on the UI TextBlock
	/// </summary>
	private void PFNPackagedAppsListView_SelectionChanged()
	{
		int selectedCount = PFNPackagedAppsListView.SelectedItems.Count;
		PFNSelectedItemsCount.Text = string.Format(GlobalVars.Rizz.GetString("SelectedAppsCount"), selectedCount);
	}


	// Used to store the original Apps collection so when we filter the results and then remove the filters,
	// We can still have access to the original collection of apps
	private ObservableCollection<GroupInfoListForPackagedAppView>? _originalContacts;


	/// <summary>
	/// Event handler for when the search box of apps list changes
	/// </summary>
	private void PFNAppFilteringTextBox_TextChanged()
	{
		// Store the original collection if it hasn't been saved yet
		_originalContacts ??= (ObservableCollection<GroupInfoListForPackagedAppView>)PackagedAppsCollectionViewSource.Source;

		// Get the text from text box
		string filterText = PFNAppFilteringTextBox.Text;

		if (string.IsNullOrWhiteSpace(filterText))
		{
			// If the filter is cleared, restore the original collection
			PackagedAppsCollectionViewSource.Source = _originalContacts;
			return;
		}

		// Filter the original collection
		List<GroupInfoListForPackagedAppView> filtered = [.. _originalContacts
			.Select(group => new GroupInfoListForPackagedAppView(group.Where(app =>
				app.DisplayName.Contains(filterText, StringComparison.OrdinalIgnoreCase)))
			{
				Key = group.Key // Preserve the group key
			})
			.Where(group => group.Any())];

		// Update the ListView source with the filtered data
		PackagedAppsCollectionViewSource.Source = new ObservableCollection<GroupInfoListForPackagedAppView>(filtered);
	}


	/// <summary>
	/// Event handler to happen only once when the section is expanded and apps list is loaded
	/// </summary>
	private async void PFNSettingsCard_Expanded()
	{
		if (!packagesLoadedOnExpand)
		{
			try
			{
				PFNRefreshAppsListButton.IsEnabled = false;

				PackagedAppsCollectionViewSource.Source = await GetAppsList.GetContactsGroupedAsync();

				packagesLoadedOnExpand = true;
			}
			finally
			{
				PFNRefreshAppsListButton.IsEnabled = true;
			}
		}
	}

	private void PFNBrowseForBasePolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			PFNBasePolicyPath = selectedFile;

			// Add the file path to the GUI's text box
			PFNBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}
	}

	private void PFNBasePolicyClearButton_Click()
	{

		PFNBasePolicyPath = null;
		PFNBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;

	}

	/// <summary>
	/// Main button's event handler - Create Supplemental policy based on PFNs
	/// </summary>
	private async void CreatePFNSupplementalPolicyButton_Click()
	{

		ViewModel.PFNInfoBarActionButtonVisibility = Visibility.Collapsed;

		// Make sure the InfoBar is closed initially. if there will be an error, we don't want it stay open from previous runs.
		PFNInfoBar.IsOpen = false;

		string? PFNBasedSupplementalPolicyName = PFNPolicyNameTextBox.Text;

		bool shouldDeploy = PFNPolicyDeployToggleButton.IsChecked ?? false;

		// Close the teaching tip if it's open when user presses the button
		// it will be opened again if necessary
		CreatePFNSupplementalPolicyTeachingTip.IsOpen = false;

		if (PFNPackagedAppsListView.SelectedItems.Count is 0)
		{
			CreatePFNSupplementalPolicyTeachingTip.IsOpen = true;
			CreatePFNSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("PFNBasedSupplementalPolicyTitle");
			CreatePFNSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("PFNBasedSupplementalPolicySubtitle");
			return;
		}

		// Only check for policy name if user hasn't provided a policy to add the rules to
		if (ViewModel.OperationModeComboBoxSelectedIndex is 0 && string.IsNullOrWhiteSpace(PFNBasedSupplementalPolicyName))
		{
			CreatePFNSupplementalPolicyTeachingTip.IsOpen = true;
			CreatePFNSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("ChoosePolicyNameTitle");
			CreatePFNSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("ChoosePolicyNameSubtitle");
			return;
		}


		// use the policy to merge with file if that option is enabled by the user
		if (ViewModel.OperationModeComboBoxSelectedIndex is 1)
		{
			if (ViewModel.PolicyFileToMergeWith is null)
			{
				CreatePFNSupplementalPolicyTeachingTip.IsOpen = true;
				CreatePFNSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("SelectPolicyToAddRulesToTitle");
				CreatePFNSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectPolicyToAddRulesToSubtitle");
				return;
			}
		}
		else if (string.IsNullOrWhiteSpace(PFNBasePolicyPath))
		{
			CreatePFNSupplementalPolicyTeachingTip.IsOpen = true;
			CreatePFNSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("SelectBasePolicyTitle");
			CreatePFNSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectBasePolicySubtitle");
			return;
		}

		_PFNSupplementalPolicyPath = null;

		bool ErrorsOccurred = false;

		try
		{

			CreatePFNSupplementalPolicyButton.IsEnabled = false;
			ViewModel.PFNBrowseForBasePolicyIsEnabled = false;
			PFNSelectPackagedAppsSettingsCard.IsEnabled = false;
			PFNPolicyNameTextBox.IsEnabled = false;

			PFNInfoBar.IsClosable = false;
			PFNInfoBar.IsOpen = true;
			PFNInfoBar.Severity = InfoBarSeverity.Informational;
			PFNInfoBar.Message = GlobalVars.Rizz.GetString("CreatingPFNSupplementalPolicyMessage");
			PFNSettingsCard.IsExpanded = true;

			// A list to store the selected PackagedAppView items
			List<string> selectedAppsPFNs = [];

			// Loop through the selected items
			foreach (var selectedItem in PFNPackagedAppsListView.SelectedItems)
			{
				if (selectedItem is PackagedAppView appView)
				{
					// Add the selected item's PFN to the list
					selectedAppsPFNs.Add(appView.PackageFamilyNameActual);
				}
			}

			await Task.Run(() =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("PFNSupplementalPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(level: ScanLevels.PFN, packageFamilyNames: selectedAppsPFNs);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Allow);


				string OutputPath = ViewModel.OperationModeComboBoxSelectedIndex is 1 ? ViewModel.PolicyFileToMergeWith! : Path.Combine(GlobalVars.UserConfigDir, $"{PFNBasedSupplementalPolicyName}.xml");

				if (ViewModel.OperationModeComboBoxSelectedIndex is 1)
				{
					// Merge the new supplemental policy with the user selected policy - user selected policy is the main one in the merge operation
					Merger.Merge(OutputPath, [EmptyPolicyPath]);
				}
				else
				{

					// Instantiate the user selected Base policy
					SiPolicy.SiPolicy policyObj = Management.Initialize(PFNBasePolicyPath, null);

					// Set the BasePolicyID of our new policy to the one from user selected policy
					_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, PFNBasedSupplementalPolicyName, policyObj.BasePolicyID, null);

					// Configure policy rule options
					CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);

					// Set policy version
					SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

					// Copying the policy file to the User Config directory - outside of the temporary staging area
					File.Copy(EmptyPolicyPath, OutputPath, true);

				}

				_PFNSupplementalPolicyPath = OutputPath;

				// Use the name of the user selected file for CIP file name, otherwise use the name of the supplemental policy provided by the user
				string CIPName = ViewModel.OperationModeComboBoxSelectedIndex is 1 ? $"{Path.GetFileNameWithoutExtension(ViewModel.PolicyFileToMergeWith!)}.cip" : Path.Combine(stagingArea.FullName, $"{PFNBasedSupplementalPolicyName}.cip");
				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// If user selected to deploy the policy
				if (shouldDeploy)
				{
					string msg4 = GlobalVars.Rizz.GetString("DeployingThePolicy");

					Logger.Write(msg4);

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						PFNInfoBar.Message = msg4;
					});

					CiToolHelper.UpdatePolicy(CIPPath);
				}
				// If not deploying it, copy the CIP file to the user config directory, just like the XML policy file
				else
				{
					string finalCIPPath = Path.Combine(GlobalVars.UserConfigDir, Path.GetFileName(CIPPath));
					File.Copy(CIPPath, finalCIPPath, true);
				}

			});

		}

		catch (Exception ex)
		{
			ErrorsOccurred = true;

			PFNInfoBar.Severity = InfoBarSeverity.Error;
			PFNInfoBar.Message = GlobalVars.Rizz.GetString("ErrorOccurredCreatingPolicy") + ex.Message;

			Logger.Write(ErrorWriter.FormatException(ex));
		}
		finally
		{
			if (!ErrorsOccurred)
			{
				PFNInfoBar.Severity = InfoBarSeverity.Success;
				PFNInfoBar.Message = GlobalVars.Rizz.GetString("SuccessfullyCreatedPFNSupplementalPolicyMessage");

				ViewModel.PFNInfoBarActionButtonVisibility = Visibility.Visible;
			}

			CreatePFNSupplementalPolicyButton.IsEnabled = true;
			ViewModel.PFNBrowseForBasePolicyIsEnabled = true;
			PFNSelectPackagedAppsSettingsCard.IsEnabled = true;
			PFNPolicyNameTextBox.IsEnabled = true;

			PFNInfoBar.IsClosable = true;
		}

	}


	/// <summary>
	/// Path to the PFN Supplemental policy XML file
	/// </summary>
	private string? _PFNSupplementalPolicyPath;


	/// <summary>
	/// Opens a policy editor for PFN using a specified supplemental policy path.
	/// </summary>
	private async void OpenInPolicyEditor_PFN()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_PFNSupplementalPolicyPath);
	}

	#endregion


	#region Custom Pattern-based File Rule

	// Path to the base policy for the Custom Pattern-based File Rule supplemental policy
	private string? CustomPatternBasedFileRuleBasedBasePolicyPath;

	private bool CustomPatternBasedFileRuleBasedDeployButton;

	// Selected Supplemental policy name
	private string? CustomPatternBasedFileRuleBasedSupplementalPolicyName;

	private void CustomPatternBasedFileRulePolicyDeployToggleButton_Click(object sender, RoutedEventArgs e)
	{
		CustomPatternBasedFileRuleBasedDeployButton = ((ToggleButton)sender).IsChecked ?? false;
	}

	private void CustomPatternBasedFileRulePolicyNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		CustomPatternBasedFileRuleBasedSupplementalPolicyName = ((TextBox)sender).Text;
	}

	private void CustomPatternBasedFileRuleBrowseForBasePolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			CustomPatternBasedFileRuleBasedBasePolicyPath = selectedFile;

			CustomPatternBasedFileRuleBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}
	}

	private void CustomPatternBasedFileRuleBrowseForBasePolicyButton_Flyout_Clear_Click()
	{
		CustomPatternBasedFileRuleBasedBasePolicyPath = null;
		CustomPatternBasedFileRuleBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
	}


	/// <summary>
	/// Event handler for the main button - to create Supplemental pattern based File path policy
	/// </summary>
	private async void CreateCustomPatternBasedFileRuleSupplementalPolicyButton_Click()
	{

		ViewModel.CustomFilePathRulesInfoBarActionButtonVisibility = Visibility.Collapsed;

		// Make sure the InfoBar is closed initially. if there will be an error, we don't want it stay open from previous runs.
		CustomPatternBasedFileRuleInfoBar.IsOpen = false;

		bool errorsOccurred = false;


		// use the policy to merge with file if that option is enabled by the user
		if (ViewModel.OperationModeComboBoxSelectedIndex is 1)
		{
			if (ViewModel.PolicyFileToMergeWith is null)
			{
				CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.IsOpen = true;
				CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("SelectPolicyToAddRulesToTitle");
				CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectPolicyToAddRulesToSubtitle");
				return;
			}
		}
		else if (CustomPatternBasedFileRuleBasedBasePolicyPath is null)
		{
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.IsOpen = true;
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("SelectBasePolicyTitle");
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectBasePolicySubtitle");
			return;
		}

		if (string.IsNullOrWhiteSpace(SupplementalPolicyCustomPatternBasedCustomPatternTextBox.Text))
		{
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.IsOpen = true;
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("EnterCustomPatternTitle");
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("EnterCustomPatternSubtitle");
			return;
		}

		// Only check for policy name if user hasn't provided a policy to add the rules to
		if (ViewModel.OperationModeComboBoxSelectedIndex is 0 && string.IsNullOrWhiteSpace(CustomPatternBasedFileRuleBasedSupplementalPolicyName))
		{
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.IsOpen = true;
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Title = GlobalVars.Rizz.GetString("ChoosePolicyNameTitle");
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Subtitle = GlobalVars.Rizz.GetString("ChoosePolicyNameSubtitle");
			return;
		}

		_CustomPatternBasedFileRuleSupplementalPolicyPath = null;

		try
		{
			CreateCustomPatternBasedFileRuleSupplementalPolicyButton.IsEnabled = false;
			CustomPatternBasedFileRulePolicyDeployToggleButton.IsEnabled = false;
			CustomPatternBasedFileRulePolicyNameTextBox.IsEnabled = false;
			ViewModel.CustomPatternBasedFileRuleBrowseForBasePolicyIsEnabled = false;
			SupplementalPolicyCustomPatternBasedCustomPatternTextBox.IsEnabled = false;

			CustomPatternBasedFileRuleInfoBar.IsOpen = true;
			CustomPatternBasedFileRuleInfoBar.Message = GlobalVars.Rizz.GetString("CreatingPatternBasedFileRuleMessage");
			CustomPatternBasedFileRuleInfoBar.Severity = InfoBarSeverity.Informational;
			CustomPatternBasedFileRuleInfoBar.IsClosable = false;

			string pattern = SupplementalPolicyCustomPatternBasedCustomPatternTextBox.Text;

			await Task.Run(() =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("PatternBasedFilePathRulePolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: null, level: ScanLevels.CustomFileRulePattern, folderPaths: null, customFileRulePatterns: [pattern]);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Allow);

				string OutputPath = ViewModel.OperationModeComboBoxSelectedIndex is 1 ? ViewModel.PolicyFileToMergeWith! : Path.Combine(GlobalVars.UserConfigDir, $"{CustomPatternBasedFileRuleBasedSupplementalPolicyName}.xml");

				if (ViewModel.OperationModeComboBoxSelectedIndex is 1)
				{
					// Merge the new supplemental policy with the user selected policy - user selected policy is the main one in the merge operation
					Merger.Merge(OutputPath, [EmptyPolicyPath]);
				}
				else
				{

					// Instantiate the user selected Base policy
					SiPolicy.SiPolicy policyObj = Management.Initialize(CustomPatternBasedFileRuleBasedBasePolicyPath, null);

					// Set the BasePolicyID of our new policy to the one from user selected policy
					_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, CustomPatternBasedFileRuleBasedSupplementalPolicyName, policyObj.BasePolicyID, null);

					// Configure policy rule options
					CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental, rulesToAdd: [OptionType.DisabledRuntimeFilePathRuleProtection]);

					// Set policy version
					SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

					// Copying the policy file to the User Config directory - outside of the temporary staging area
					File.Copy(EmptyPolicyPath, OutputPath, true);

				}

				_CustomPatternBasedFileRuleSupplementalPolicyPath = OutputPath;

				// Use the name of the user selected file for CIP file name, otherwise use the name of the supplemental policy provided by the user
				string CIPName = ViewModel.OperationModeComboBoxSelectedIndex is 1 ? $"{Path.GetFileNameWithoutExtension(ViewModel.PolicyFileToMergeWith!)}.cip" : Path.Combine(stagingArea.FullName, $"{CustomPatternBasedFileRuleBasedSupplementalPolicyName}.cip");
				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// If user selected to deploy the policy
				if (CustomPatternBasedFileRuleBasedDeployButton)
				{
					string msg4 = GlobalVars.Rizz.GetString("DeployingThePolicy");

					Logger.Write(msg4);

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						CustomPatternBasedFileRuleInfoBar.Message = msg4;
					});

					CiToolHelper.UpdatePolicy(CIPPath);
				}
				// If not deploying it, copy the CIP file to the user config directory, just like the XML policy file
				else
				{
					string finalCIPPath = Path.Combine(GlobalVars.UserConfigDir, Path.GetFileName(CIPPath));
					File.Copy(CIPPath, finalCIPPath, true);
				}

			});
		}
		catch (Exception ex)
		{
			errorsOccurred = true;

			CustomPatternBasedFileRuleInfoBar.Severity = InfoBarSeverity.Error;
			CustomPatternBasedFileRuleInfoBar.Message = GlobalVars.Rizz.GetString("ErrorOccurredCreatingPolicy") + ex.Message;

			Logger.Write(ErrorWriter.FormatException(ex));
		}
		finally
		{
			if (!errorsOccurred)
			{
				CustomPatternBasedFileRuleInfoBar.Severity = InfoBarSeverity.Success;

				CustomPatternBasedFileRuleInfoBar.Message = GlobalVars.Rizz.GetString("SuccessfullyCreatedPatternBasedFileRuleMessage");

				ViewModel.CustomFilePathRulesInfoBarActionButtonVisibility = Visibility.Visible;
			}

			CreateCustomPatternBasedFileRuleSupplementalPolicyButton.IsEnabled = true;
			CustomPatternBasedFileRulePolicyDeployToggleButton.IsEnabled = true;
			CustomPatternBasedFileRulePolicyNameTextBox.IsEnabled = true;
			ViewModel.CustomPatternBasedFileRuleBrowseForBasePolicyIsEnabled = true;
			SupplementalPolicyCustomPatternBasedCustomPatternTextBox.IsEnabled = true;
			CustomPatternBasedFileRuleInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Event handler to display the content dialog for more info about patterns
	/// </summary>
	private async void SupplementalPolicyCustomPatternBasedFileRuleSettingsCard_Click()
	{
		// Instantiate the Content Dialog
		CustomUIElements.CustomPatternBasedFilePath customDialog = new();

		App.CurrentlyOpenContentDialog = customDialog;

		// Show the dialog
		_ = await customDialog.ShowAsync();
	}


	/// <summary>
	/// Path to the CustomPatternBasedFileRule Supplemental policy XML file
	/// </summary>
	private string? _CustomPatternBasedFileRuleSupplementalPolicyPath;


	/// <summary>
	/// Opens a policy editor for CustomPatternBasedFileRule using a specified supplemental policy path.
	/// </summary>
	private async void OpenInPolicyEditor_CustomPatternBasedFileRule()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_CustomPatternBasedFileRuleSupplementalPolicyPath);
	}


	#endregion

}
