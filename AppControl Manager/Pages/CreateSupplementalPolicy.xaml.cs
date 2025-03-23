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
public sealed partial class CreateSupplementalPolicy : Page, Sidebar.IAnimatedIconsManager
{

#pragma warning disable CA1822
	private CreateSupplementalPolicyVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<CreateSupplementalPolicyVM>();
#pragma warning restore CA1822

	/// <summary>
	/// Constructor for the CreateSupplementalPolicy class. Initializes components, sets navigation cache mode, and assigns
	/// the data context.
	/// </summary>
	public CreateSupplementalPolicy()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;

		this.DataContext = ViewModel;
	}


	#region Augmentation Interface

	private string? unsignedBasePolicyPathFromSidebar;

	/// <summary>
	/// Implement the SetVisibility method required by IAnimatedIconsManager
	/// </summary>
	/// <param name="visibility"></param>
	/// <param name="unsignedBasePolicyPath"></param>
	/// <param name="button1"></param>
	/// <param name="button2"></param>
	/// <param name="button3"></param>
	/// <param name="button4"></param>
	/// <param name="button5"></param>
	public void SetVisibility(Visibility visibility, string? unsignedBasePolicyPath, Button? button1, Button? button2, Button? button3, Button? button4, Button? button5)
	{
		ArgumentNullException.ThrowIfNull(button1);
		ArgumentNullException.ThrowIfNull(button2);
		ArgumentNullException.ThrowIfNull(button3);
		ArgumentNullException.ThrowIfNull(button4);
		ArgumentNullException.ThrowIfNull(button5);

		// Light up the local page's button icons
		FilesAndFoldersBasePolicyLightAnimatedIcon.Visibility = visibility;
		CertificatesBasePolicyPathLightAnimatedIcon.Visibility = visibility;
		ISGBasePolicyPathLightAnimatedIcon.Visibility = visibility;
		StrictKernelModeBasePolicyLightAnimatedIcon.Visibility = visibility;
		PFNBasePolicyPathLightAnimatedIcon.Visibility = visibility;

		// Light up the sidebar buttons' icons
		button1.Visibility = visibility;
		button2.Visibility = visibility;
		button3.Visibility = visibility;
		button4.Visibility = visibility;
		button5.Visibility = visibility;

		// Set the incoming text which is from sidebar for unsigned policy path to a local private variable
		unsignedBasePolicyPathFromSidebar = unsignedBasePolicyPath;

		if (visibility is Visibility.Visible)
		{
			// Assign sidebar buttons' content texts
			button1.Content = "Files And Folders Supplemental Policy";
			button2.Content = "Certificates Based Supplemental Policy";
			button3.Content = "ISG Supplemental Policy";
			button4.Content = "Strict Kernel-Mode Supplemental Policy";
			button5.Content = "PFN-Based Supplemental Policy";

			// Assign a local event handler to the sidebar button
			button1.Click += LightUp1;
			// Save a reference to the event handler we just set for tracking
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect1EventHandler = LightUp1;

			// Assign a local event handler to the sidebar button
			button2.Click += LightUp2;
			// Save a reference to the event handler we just set for tracking
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect2EventHandler = LightUp2;

			button3.Click += LightUp3;
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect3EventHandler = LightUp3;

			button4.Click += LightUp4;
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect4EventHandler = LightUp4;

			button5.Click += LightUp5;
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect5EventHandler = LightUp5;
		}
	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void LightUp1(object sender, RoutedEventArgs e)
	{
		// Make sure the element has XamlRoot. When it's in a settings card that is not expanded yet, it won't have it
		if (FilesAndFoldersBrowseForBasePolicyButton.XamlRoot is not null)
		{
			FilesAndFoldersBrowseForBasePolicyButton_FlyOut.ShowAt(FilesAndFoldersBrowseForBasePolicyButton);
		}

		FilesAndFoldersBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = unsignedBasePolicyPathFromSidebar;
		filesAndFoldersBasePolicyPath = unsignedBasePolicyPathFromSidebar;
	}
	private void LightUp2(object sender, RoutedEventArgs e)
	{
		// Make sure the element has XamlRoot. When it's in a settings card that is not expanded yet, it won't have it
		if (CertificatesBrowseForBasePolicyButton.XamlRoot is not null)
		{
			CertificatesBrowseForBasePolicyButton_FlyOut.ShowAt(CertificatesBrowseForBasePolicyButton);
		}

		CertificatesBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = unsignedBasePolicyPathFromSidebar;
		CertificatesBasedBasePolicyPath = unsignedBasePolicyPathFromSidebar;
	}
	private void LightUp3(object sender, RoutedEventArgs e)
	{
		if (ISGBrowseForBasePolicyButton.XamlRoot is not null)
		{
			ISGBrowseForBasePolicyButton_FlyOut.ShowAt(ISGBrowseForBasePolicyButton);
		}

		ISGBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = unsignedBasePolicyPathFromSidebar;
		ISGBasedBasePolicyPath = unsignedBasePolicyPathFromSidebar;
	}

	private void LightUp4(object sender, RoutedEventArgs e)
	{
		if (StrictKernelModeBrowseForBasePolicyButton.XamlRoot is not null)
		{
			StrictKernelModeBrowseForBasePolicyButton_FlyOut.ShowAt(StrictKernelModeBrowseForBasePolicyButton);
		}

		StrictKernelModeBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = unsignedBasePolicyPathFromSidebar;
		StrictKernelModeBasePolicyPath = unsignedBasePolicyPathFromSidebar;
	}

	private void LightUp5(object sender, RoutedEventArgs e)
	{
		if (PFNBrowseForBasePolicyButton.XamlRoot is not null)
		{
			PFNBrowseForBasePolicyButton_FlyOut.ShowAt(PFNBrowseForBasePolicyButton);
		}

		PFNBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = unsignedBasePolicyPathFromSidebar;
		PFNBasePolicyPath = unsignedBasePolicyPathFromSidebar;
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


	private void FilesAndFoldersBrowseForFilesButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!FilesAndFoldersBrowseForFilesButton_Flyout.IsOpen)
			FilesAndFoldersBrowseForFilesButton_Flyout.ShowAt(FilesAndFoldersBrowseForFilesButton);
	}

	private void FilesAndFoldersBrowseForFilesSettingsCard_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!FilesAndFoldersBrowseForFilesButton_Flyout.IsOpen)
			FilesAndFoldersBrowseForFilesButton_Flyout.ShowAt(FilesAndFoldersBrowseForFilesSettingsCard);
	}

	private void FilesAndFoldersBrowseForFilesSettingsCard_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!FilesAndFoldersBrowseForFilesButton_Flyout.IsOpen)
				FilesAndFoldersBrowseForFilesButton_Flyout.ShowAt(FilesAndFoldersBrowseForFilesSettingsCard);
	}

	private void FilesAndFoldersBrowseForFoldersSettingsCard_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!FilesAndFoldersBrowseForFoldersButton_FlyOut.IsOpen)
				FilesAndFoldersBrowseForFoldersButton_FlyOut.ShowAt(FilesAndFoldersBrowseForFoldersSettingsCard);
	}

	private void FilesAndFoldersBrowseForFoldersSettingsCard_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!FilesAndFoldersBrowseForFoldersButton_FlyOut.IsOpen)
			FilesAndFoldersBrowseForFoldersButton_FlyOut.ShowAt(FilesAndFoldersBrowseForFoldersSettingsCard);
	}

	private void FilesAndFoldersBrowseForFoldersButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!FilesAndFoldersBrowseForFoldersButton_FlyOut.IsOpen)
			FilesAndFoldersBrowseForFoldersButton_FlyOut.ShowAt(FilesAndFoldersBrowseForFoldersButton);
	}


	private void FilesAndFoldersBrowseForBasePolicySettingsCard_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!FilesAndFoldersBrowseForBasePolicyButton_FlyOut.IsOpen)
				FilesAndFoldersBrowseForBasePolicyButton_FlyOut.ShowAt(FilesAndFoldersBrowseForBasePolicySettingsCard);
	}

	private void FilesAndFoldersBrowseForBasePolicySettingsCard_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!FilesAndFoldersBrowseForBasePolicyButton_FlyOut.IsOpen)
			FilesAndFoldersBrowseForBasePolicyButton_FlyOut.ShowAt(FilesAndFoldersBrowseForBasePolicySettingsCard);
	}

	private void FilesAndFoldersBrowseForBasePolicyButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!FilesAndFoldersBrowseForBasePolicyButton_FlyOut.IsOpen)
			FilesAndFoldersBrowseForBasePolicyButton_FlyOut.ShowAt(FilesAndFoldersBrowseForBasePolicyButton);
	}

	/// <summary>
	/// Browse for Files - Settings Card Click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersBrowseForFilesSettingsCard_Click(object sender, RoutedEventArgs e)
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

			// Display the Flyout manually at SettingsCard element since the click event happened on the Settings card
			FilesAndFoldersBrowseForFilesButton_Flyout.ShowAt(FilesAndFoldersBrowseForFilesSettingsCard);
		}
	}


	/// <summary>
	/// Browse for Files - Button Click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersBrowseForFilesButton_Click(object sender, RoutedEventArgs e)
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
	/// Browse for Folders - Settings Card Click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersBrowseForFoldersSettingsCard_Click(object sender, RoutedEventArgs e)
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

			// Display the Flyout manually at SettingsCard element since the click event happened on the Settings card
			FilesAndFoldersBrowseForFoldersButton_FlyOut.ShowAt(FilesAndFoldersBrowseForFoldersSettingsCard);
		}
	}


	/// <summary>
	/// Browse for Folders - Button Click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersBrowseForFoldersButton_Click(object sender, RoutedEventArgs e)
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
	/// Browse for Base Policy - Settings Card Click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersBrowseForBasePolicySettingsCard_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			filesAndFoldersBasePolicyPath = selectedFile;

			// Add the file path to the GUI's text box
			FilesAndFoldersBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;

			// Display the Flyout manually at SettingsCard element since the click event happened on the Settings card
			FilesAndFoldersBrowseForBasePolicyButton_FlyOut.ShowAt(FilesAndFoldersBrowseForBasePolicySettingsCard);
		}
	}


	/// <summary>
	/// Browse for Base Policy - Button Click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersBrowseForBasePolicyButton_Click(object sender, RoutedEventArgs e)
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
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersViewFileDetailsSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		MainWindow.Instance.NavView_Navigate(typeof(CreateSupplementalPolicyFilesAndFoldersScanResults), null);
	}


	/// <summary>
	/// File Scan Level ComboBox - Settings Card Click to simulate ComboBox click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void ScanLevelComboBoxSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		ScanLevelComboBox.IsDropDownOpen = !ScanLevelComboBox.IsDropDownOpen;
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
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersBrowseForFilesButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		filesAndFoldersFilePaths.Clear();
		FilesAndFoldersBrowseForFilesButton_SelectedFilesTextBox.Text = null;
	}


	/// <summary>
	/// Button to clear the list of selected folder paths
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersBrowseForFoldersButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		filesAndFoldersFolderPaths.Clear();
		FilesAndFoldersBrowseForFoldersButton_SelectedFoldersTextBox.Text = null;
	}


	/// <summary>
	/// Main button's event handler for files and folder Supplemental policy creation
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void CreateFilesAndFoldersSupplementalPolicyButton_Click(object sender, RoutedEventArgs e)
	{

		// Close the teaching tip if it's open when user presses the button
		// it will be opened again if necessary
		CreateSupplementalPolicyTeachingTip.IsOpen = false;

		// Reset the progress ring from previous runs or in case an error occurred
		FilesAndFoldersProgressRing.Value = 0;

		FilesAndFoldersInfoBar.IsClosable = false;

		if (filesAndFoldersFilePaths.Count is 0 && filesAndFoldersFolderPaths.Count is 0)
		{
			CreateSupplementalPolicyTeachingTip.IsOpen = true;
			CreateSupplementalPolicyTeachingTip.Title = "Select files or folders";
			CreateSupplementalPolicyTeachingTip.Subtitle = "No files or folders were selected for Supplemental policy creation";
			return;
		}

		if (filesAndFoldersBasePolicyPath is null)
		{
			CreateSupplementalPolicyTeachingTip.IsOpen = true;
			CreateSupplementalPolicyTeachingTip.Title = "Select base policy";
			CreateSupplementalPolicyTeachingTip.Subtitle = "You need to select a base policy before you can create a Supplemental policy.";
			return;
		}

		if (string.IsNullOrWhiteSpace(filesAndFoldersSupplementalPolicyName))
		{
			CreateSupplementalPolicyTeachingTip.IsOpen = true;
			CreateSupplementalPolicyTeachingTip.Title = "Choose Supplemental Policy Name";
			CreateSupplementalPolicyTeachingTip.Subtitle = "You need to provide a name for the Supplemental policy.";
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
			FilesAndFoldersBrowseForBasePolicySettingsCard.IsEnabled = false;
			FilesAndFoldersBrowseForBasePolicyButton.IsEnabled = false;
			ScanLevelComboBoxSettingsCard.IsEnabled = false;
			ScanLevelComboBox.IsEnabled = false;
			FilesAndFoldersViewFileDetailsSettingsCard.IsEnabled = true;

			FilesAndFoldersInfoBar.IsOpen = true;
			FilesAndFoldersInfoBar.Severity = InfoBarSeverity.Informational;
			string msg1 = $"Finding all App Control compatible files among {filesAndFoldersFilePaths.Count} files and {filesAndFoldersFolderPaths.Count} folders you selected...";
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

					string msg2 = $"Scanning a total of {DetectedFilesInSelectedDirectories.Item2} AppControl compatible files...";
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
						FilesAndFoldersProgressRing,
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

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{filesAndFoldersSupplementalPolicyName}.xml");

				// Instantiate the user selected Base policy
				SiPolicy.SiPolicy policyObj = Management.Initialize(filesAndFoldersBasePolicyPath, null);

				// Set the BasePolicyID of our new policy to the one from user selected policy
				_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, filesAndFoldersSupplementalPolicyName, policyObj.BasePolicyID, null);

				// Configure policy rule options
				if (filesAndFoldersScanLevel is ScanLevels.FilePath || filesAndFoldersScanLevel is ScanLevels.WildCardFolderPath)
				{
					Logger.Write($"The selected scan level is {filesAndFoldersScanLevel}, adding 'Disabled: Runtime FilePath Rule Protection' rule option to the Supplemental policy so non-admin protected file paths will work.'");

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

				string CIPPath = Path.Combine(stagingArea.FullName, $"{filesAndFoldersSupplementalPolicyName}.cip");

				// Convert the XML file to CIP and save it in the defined path
				PolicyToCIPConverter.Convert(OutputPath, CIPPath);

				// If user selected to deploy the policy
				if (filesAndFoldersDeployButton)
				{

					string msg4 = "Deploying the Supplemental policy on the system";

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
		catch
		{
			FilesAndFoldersInfoBar.Severity = InfoBarSeverity.Error;
			FilesAndFoldersInfoBar.Message = "An error occurred while creating the Supplemental policy";

			errorsOccurred = true;

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				FilesAndFoldersInfoBar.Severity = InfoBarSeverity.Success;
				FilesAndFoldersInfoBar.Message = $"Successfully created a Supplemental policy named '{filesAndFoldersSupplementalPolicyName}'";
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
			FilesAndFoldersBrowseForBasePolicySettingsCard.IsEnabled = true;
			FilesAndFoldersBrowseForBasePolicyButton.IsEnabled = true;
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
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FilesAndFoldersBrowseForBasePolicyButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		filesAndFoldersBasePolicyPath = null;
		FilesAndFoldersBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
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

	private void CertificatesBrowseForBasePolicyButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!CertificatesBrowseForBasePolicyButton_FlyOut.IsOpen)
			CertificatesBrowseForBasePolicyButton_FlyOut.ShowAt(CertificatesBrowseForBasePolicyButton);
	}

	private void CertificatesBrowseForBasePolicySettingsCard_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!CertificatesBrowseForBasePolicyButton_FlyOut.IsOpen)
			CertificatesBrowseForBasePolicyButton_FlyOut.ShowAt(CertificatesBrowseForBasePolicySettingsCard);
	}

	private void CertificatesBrowseForBasePolicySettingsCard_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!CertificatesBrowseForBasePolicyButton_FlyOut.IsOpen)
				CertificatesBrowseForBasePolicyButton_FlyOut.ShowAt(CertificatesBrowseForBasePolicySettingsCard);
	}

	/// <summary>
	/// Deploy button event handler for Certificates-based Supplemental policy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void CertificatesPolicyDeployToggleButton_Click(object sender, RoutedEventArgs e)
	{
		CertificatesBasedDeployButton = ((ToggleButton)sender).IsChecked ?? false;
	}

	private void CertificatesBrowseForCertsButton_Click(object sender, RoutedEventArgs e)
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

	private void CertificatesBrowseForCertsSettingsCard_Click(object sender, RoutedEventArgs e)
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


	private void CertificatesBrowseForBasePolicySettingsCard_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			CertificatesBasedBasePolicyPath = selectedFile;

			CertificatesBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;

			CertificatesBrowseForBasePolicyButton_FlyOut.ShowAt(CertificatesBrowseForBasePolicySettingsCard);
		}
	}

	private void CertificatesBrowseForBasePolicyButton_Click(object sender, RoutedEventArgs e)
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			CertificatesBasedBasePolicyPath = selectedFile;

			CertificatesBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}
	}


	private void UserModeRadioButton_Checked(object sender, RoutedEventArgs e)
	{
		signingScenario = true;
	}

	private void KernelModeRadioButton_Checked(object sender, RoutedEventArgs e)
	{
		signingScenario = false;
	}


	/// <summary>
	/// Main Button - Creates the Certificates-based Supplemental policy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void CreateCertificatesSupplementalPolicyButton_Click(object sender, RoutedEventArgs e)
	{
		bool errorsOccurred = false;

		if (CertificatesBasedCertFilePaths.Count is 0)
		{
			CreateCertificateBasedSupplementalPolicyTeachingTip.IsOpen = true;
			CreateCertificateBasedSupplementalPolicyTeachingTip.Title = "Select certificates";
			CreateCertificateBasedSupplementalPolicyTeachingTip.Subtitle = "You need to select some certificates first to create Supplemental policy";
			return;
		}

		if (CertificatesBasedBasePolicyPath is null)
		{
			CreateCertificateBasedSupplementalPolicyTeachingTip.IsOpen = true;
			CreateCertificateBasedSupplementalPolicyTeachingTip.Title = "Select base policy";
			CreateCertificateBasedSupplementalPolicyTeachingTip.Subtitle = "You need to select a base policy before you can create a Supplemental policy.";
			return;
		}

		if (string.IsNullOrWhiteSpace(CertificatesBasedSupplementalPolicyName))
		{
			CreateCertificateBasedSupplementalPolicyTeachingTip.IsOpen = true;
			CreateCertificateBasedSupplementalPolicyTeachingTip.Title = "Choose Supplemental Policy Name";
			CreateCertificateBasedSupplementalPolicyTeachingTip.Subtitle = "You need to provide a name for the Supplemental policy.";
			return;
		}

		try
		{
			CreateCertificatesSupplementalPolicyButton.IsEnabled = false;
			CertificatesPolicyDeployToggleButton.IsEnabled = false;
			CertificatesBrowseForCertsButton.IsEnabled = false;
			CertificatesBrowseForCertsSettingsCard.IsEnabled = false;
			CertificatesPolicyNameTextBox.IsEnabled = false;
			CertificatesBrowseForBasePolicySettingsCard.IsEnabled = false;
			CertificatesBrowseForBasePolicyButton.IsEnabled = false;
			CertificatesSigningScenarioSettingsCard.IsEnabled = false;
			SigningScenariosRadioButtons.IsEnabled = false;

			CertificatesInfoBar.IsOpen = true;
			CertificatesInfoBar.IsClosable = false;
			CertificatesInfoBar.Message = $"Creating the Certificates-based Supplemental policy for {CertificatesBasedCertFilePaths.Count} certificates";
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
						 CertificatesInfoBar.Message = "No certificate details could be found for creating the policy";
						 CertificatesInfoBar.Severity = InfoBarSeverity.Warning;
					 });

					errorsOccurred = true;
					return;
				}

				Merger.Merge(EmptyPolicyPath, [EmptyPolicyPath]);

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{CertificatesBasedSupplementalPolicyName}.xml");

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

				string CIPPath = Path.Combine(stagingArea.FullName, $"{CertificatesBasedSupplementalPolicyName}.cip");

				// Convert the XML file to CIP and save it in the defined path
				PolicyToCIPConverter.Convert(OutputPath, CIPPath);

				// If user selected to deploy the policy
				if (CertificatesBasedDeployButton)
				{
					string msg4 = "Deploying the Supplemental policy on the system";

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

		catch
		{
			CertificatesInfoBar.Severity = InfoBarSeverity.Error;
			CertificatesInfoBar.Message = "An error occurred while creating certificate based Supplemental policy";

			errorsOccurred = true;

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				CertificatesInfoBar.Severity = InfoBarSeverity.Success;

				CertificatesInfoBar.Message = $"Successfully created a certificate-based Supplemental policy named {CertificatesBasedSupplementalPolicyName}.";
			}

			CreateCertificatesSupplementalPolicyButton.IsEnabled = true;
			CertificatesPolicyDeployToggleButton.IsEnabled = true;
			CertificatesBrowseForCertsButton.IsEnabled = true;
			CertificatesBrowseForCertsSettingsCard.IsEnabled = true;
			CertificatesPolicyNameTextBox.IsEnabled = true;
			CertificatesBrowseForBasePolicySettingsCard.IsEnabled = true;
			CertificatesBrowseForBasePolicyButton.IsEnabled = true;
			CertificatesSigningScenarioSettingsCard.IsEnabled = true;
			SigningScenariosRadioButtons.IsEnabled = true;

			CertificatesInfoBar.IsClosable = true;
		}

	}


	/// <summary>
	/// Event handler for the clear button for the text box of selected Base policy path
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void CertificatesBrowseForBasePolicyButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		CertificatesBasedBasePolicyPath = null;
		CertificatesBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
	}


	#endregion


	#region ISG

	// Path to the base policy for the ISG based supplemental policy
	private string? ISGBasedBasePolicyPath;

	private bool ISGBasedDeployButton;

	// Selected Supplemental policy name
	private string? ISGBasedSupplementalPolicyName;

	private void ISGBrowseForBasePolicySettingsCard_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!ISGBrowseForBasePolicyButton_FlyOut.IsOpen)
				ISGBrowseForBasePolicyButton_FlyOut.ShowAt(ISGBrowseForBasePolicySettingsCard);
	}

	private void ISGBrowseForBasePolicySettingsCard_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!ISGBrowseForBasePolicyButton_FlyOut.IsOpen)
			ISGBrowseForBasePolicyButton_FlyOut.ShowAt(ISGBrowseForBasePolicySettingsCard);
	}

	private void ISGBrowseForBasePolicyButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!ISGBrowseForBasePolicyButton_FlyOut.IsOpen)
			ISGBrowseForBasePolicyButton_FlyOut.ShowAt(ISGBrowseForBasePolicyButton);
	}

	/// <summary>
	/// Event handler for the main button - to create Supplemental ISG based policy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void CreateISGSupplementalPolicyButton_Click(object sender, RoutedEventArgs e)
	{

		bool errorsOccurred = false;

		if (ISGBasedBasePolicyPath is null)
		{
			CreateISGSupplementalPolicyTeachingTip.IsOpen = true;
			CreateISGSupplementalPolicyTeachingTip.Title = "Select base policy";
			CreateISGSupplementalPolicyTeachingTip.Subtitle = "You need to select a base policy before you can create a Supplemental policy.";
			return;
		}

		try
		{
			CreateISGSupplementalPolicyButton.IsEnabled = false;
			ISGPolicyDeployToggleButton.IsEnabled = false;
			ISGPolicyNameTextBox.IsEnabled = false;
			ISGBrowseForBasePolicyButton.IsEnabled = false;

			ISGInfoBar.IsOpen = true;
			ISGInfoBar.IsClosable = false;
			ISGInfoBar.Message = "Creating the ISG-based Supplemental policy.";
			ISGInfoBar.Severity = InfoBarSeverity.Informational;

			await Task.Run(() =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("ISGBasedSupplementalPolicy");

				// Defining the paths
				string savePathTemp = Path.Combine(stagingArea.FullName, "ISGBasedSupplementalPolicy.xml");
				string savePathFinal = Path.Combine(GlobalVars.UserConfigDir, "ISGBasedSupplementalPolicy.xml");
				string CIPPath = Path.Combine(stagingArea.FullName, "ISGBasedSupplementalPolicy.cip");

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
				File.Copy(savePathTemp, savePathFinal, true);

				// Convert the XML file to CIP
				PolicyToCIPConverter.Convert(savePathTemp, CIPPath);

				// If the policy is to be deployed
				if (ISGBasedDeployButton)
				{
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
			ISGInfoBar.Message = $"An error occurred while creating ISG based Supplemental policy: {ex.Message}";

			Logger.Write($"An error occurred while creating ISG based Supplemental policy: {ex.Message}");

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				ISGInfoBar.Severity = InfoBarSeverity.Success;

				ISGInfoBar.Message = "Successfully created an ISG-based Supplemental policy.";
			}

			CreateISGSupplementalPolicyButton.IsEnabled = true;
			ISGPolicyDeployToggleButton.IsEnabled = true;
			ISGPolicyNameTextBox.IsEnabled = true;
			ISGBrowseForBasePolicyButton.IsEnabled = true;

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


	private void ISGBrowseForBasePolicySettingsCard_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			ISGBasedBasePolicyPath = selectedFile;

			ISGBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;

			ISGBrowseForBasePolicyButton_FlyOut.ShowAt(ISGBrowseForBasePolicySettingsCard);
		}
	}


	private void ISGBrowseForBasePolicyButton_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			ISGBasedBasePolicyPath = selectedFile;

			ISGBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}
	}


	private void ISGBrowseForBasePolicyButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		ISGBasedBasePolicyPath = null;
		ISGBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
	}


	#endregion


	#region Strict Kernel-Mode Supplemental Policy

	// Path to the base policy for the Strict kernel-mode supplemental policy
	private string? StrictKernelModeBasePolicyPath;

	private void StrictKernelModeBrowseForBasePolicySettingsCard_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!StrictKernelModeBrowseForBasePolicyButton_FlyOut.IsOpen)
			StrictKernelModeBrowseForBasePolicyButton_FlyOut.ShowAt(StrictKernelModeBrowseForBasePolicySettingsCard);
	}

	private void StrictKernelModeBrowseForBasePolicySettingsCard_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!StrictKernelModeBrowseForBasePolicyButton_FlyOut.IsOpen)
				StrictKernelModeBrowseForBasePolicyButton_FlyOut.ShowAt(StrictKernelModeBrowseForBasePolicySettingsCard);
	}

	private void StrictKernelModeBrowseForBasePolicyButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!StrictKernelModeBrowseForBasePolicyButton_FlyOut.IsOpen)
			StrictKernelModeBrowseForBasePolicyButton_FlyOut.ShowAt(StrictKernelModeBrowseForBasePolicyButton);
	}

	private void StrictKernelModeScanButton_Click(object sender, RoutedEventArgs e)
	{
		StrictKernelModePerformScans(false);
	}

	private void DetectedKernelModeFilesDetailsSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		MainWindow.Instance.NavView_Navigate(typeof(StrictKernelPolicyScanResults), null);
	}


	/// <summary>
	/// Browse for Base Policy - Settings Card Click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void StrictKernelModeBrowseForBasePolicySettingsCard_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			StrictKernelModeBasePolicyPath = selectedFile;

			// Add the file path to the GUI's text box
			StrictKernelModeBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;

			// Display the Flyout manually at SettingsCard element since the click event happened on the Settings card
			StrictKernelModeBrowseForBasePolicyButton_FlyOut.ShowAt(StrictKernelModeBrowseForBasePolicySettingsCard);
		}
	}


	/// <summary>
	/// Browse for Base Policy - Button Click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void StrictKernelModeBrowseForBasePolicyButton_Click(object sender, RoutedEventArgs e)
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
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void StrictKernelModeBrowseForBasePolicyButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		StrictKernelModeBasePolicyPath = null;
		StrictKernelModeBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
	}


	private void StrictKernelModeScanSinceLastRebootButton_Click(object sender, RoutedEventArgs e)
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
			StrictKernelModeInfoBar.Message = "Scanning the system for events";
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
				StrictKernelModeInfoBar.Message = "No logs were generated during the Audit phase";
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Warning;
				ErrorsOccurred = true;
				return;
			}

			StrictKernelModeInfoBar.Message = $"{Output.Count} log(s) were generated during the Audit phase";

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
			StrictKernelModeInfoBar.Message = $"An error occurred while scanning the system for events: {ex.Message}";
		}
		finally
		{
			StrictKernelModeScanButton.IsEnabled = true;
			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = true;

			if (!ErrorsOccurred)
			{
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Success;
				StrictKernelModeInfoBar.Message = "Successfully scanned the system for events";
			}

			StrictKernelModeInfoBar.IsClosable = true;
		}
	}


	/// <summary>
	/// Event handler for the create button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void StrictKernelModeCreateButton_Click(object sender, RoutedEventArgs e)
	{
		// Close the teaching tip if it's open when user presses the button
		// it will be opened again if necessary
		StrictKernelModeCreateButtonTeachingTip.IsOpen = false;

		if (ViewModel.StrictKernelModeScanResults.Count is 0)
		{
			StrictKernelModeCreateButtonTeachingTip.IsOpen = true;
			StrictKernelModeCreateButtonTeachingTip.Title = "Strict Kernel-mode Supplemental policy";
			StrictKernelModeCreateButtonTeachingTip.Subtitle = "No item exists in the detected Kernel-mode files data grid";
			return;
		}

		if (string.IsNullOrWhiteSpace(StrictKernelModePolicyNameTextBox.Text))
		{
			StrictKernelModeCreateButtonTeachingTip.IsOpen = true;
			StrictKernelModeCreateButtonTeachingTip.Title = "Strict Kernel-mode Supplemental policy";
			StrictKernelModeCreateButtonTeachingTip.Subtitle = "No policy name was selected for the supplemental policy";
			return;
		}

		if (string.IsNullOrWhiteSpace(StrictKernelModeBasePolicyPath))
		{
			StrictKernelModeCreateButtonTeachingTip.IsOpen = true;
			StrictKernelModeCreateButtonTeachingTip.Title = "Strict Kernel-mode Supplemental policy";
			StrictKernelModeCreateButtonTeachingTip.Subtitle = "No Base policy file was selected for the supplemental policy";
			return;
		}

		bool ErrorsOccurred = false;

		try
		{
			StrictKernelModeCreateButton.IsEnabled = false;
			StrictKernelModeDeployToggleButton.IsEnabled = false;
			StrictKernelModeAutoDetectAllDriversSettingsCard.IsClickEnabled = false;
			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = false;
			StrictKernelModeScanButton.IsEnabled = false;
			StrictKernelModeScanSinceLastRebootButton.IsEnabled = false;
			StrictKernelModeBrowseForBasePolicyButton.IsEnabled = false;

			StrictKernelModeInfoBar.IsClosable = false;
			StrictKernelModeInfoBar.IsOpen = true;
			StrictKernelModeInfoBar.Severity = InfoBarSeverity.Informational;
			StrictKernelModeInfoBar.Message = $"Creating Strict Kernel-mode supplemental policy for {ViewModel.StrictKernelModeScanResults.Count} files";
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

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyNameChosenByUser}.xml");

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

				string CIPPath = Path.Combine(stagingArea.FullName, $"{policyNameChosenByUser}.cip");

				// Convert the XML file to CIP and save it in the defined path
				PolicyToCIPConverter.Convert(OutputPath, CIPPath);

				// If user selected to deploy the policy
				if (shouldDeploy)
				{
					string msg4 = "Deploying the Supplemental policy on the system";

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
			StrictKernelModeInfoBar.Message = $"There was an error: {ex.Message}";

			throw;
		}
		finally
		{
			if (!ErrorsOccurred)
			{
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Success;
				StrictKernelModeInfoBar.Message = "Successfully created strict Kernel-mode supplemental policy";
			}

			StrictKernelModeCreateButton.IsEnabled = true;
			StrictKernelModeDeployToggleButton.IsEnabled = true;
			StrictKernelModeAutoDetectAllDriversSettingsCard.IsClickEnabled = true;
			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = true;
			StrictKernelModeScanButton.IsEnabled = true;
			StrictKernelModeScanSinceLastRebootButton.IsEnabled = true;
			StrictKernelModeBrowseForBasePolicyButton.IsEnabled = true;
			StrictKernelModeInfoBar.IsClosable = true;
		}
	}


	/// <summary>
	/// Event handler for the button that auto detects system drivers
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void StrictKernelModeAutoDetectAllDriversButton_Click(object sender, RoutedEventArgs e)
	{
		DriverAutoDetector();
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
			StrictKernelModeInfoBar.Message = "Scanning the system for drivers";
			StrictKernelModeSection.IsExpanded = true;

			DriverAutoDetectionProgressRing.Value = 0;

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
				StrictKernelModeInfoBar.Message = "No kernel-mode drivers could be detected";
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Warning;
				DetectedKernelModeFilesDetailsSettingsCard.IsEnabled = false;
				ErrorsOccurred = true;
				return;
			}

			StrictKernelModeInfoBar.Message = $"Scanning {kernelModeDriversList.Count} files";

			IEnumerable<FileIdentity> LocalFilesResults = [];

			await Task.Run(() =>
			{
				// Scan all of the detected files from the user selected directories
				// Add a reference to the ViewModel class to each item so we can use it for navigation in the XAML
				LocalFilesResults = LocalFilesScan.Scan(
					(kernelModeDriversList, kernelModeDriversList.Count),
					3,
					DriverAutoDetectionProgressRing,
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
			StrictKernelModeInfoBar.Message = $"There was an error: {ex.Message}";

			throw;
		}
		finally
		{
			if (!ErrorsOccurred)
			{
				StrictKernelModeInfoBar.Severity = InfoBarSeverity.Success;
				StrictKernelModeInfoBar.Message = "Successfully scanned the system for drivers";
			}

			StrictKernelModeAutoDetectAllDriversButton.IsEnabled = true;
			StrictKernelModeScanButton.IsEnabled = true;
			StrictKernelModeScanSinceLastRebootButton.IsEnabled = true;
			StrictKernelModeAutoDetectAllDriversSettingsCard.IsClickEnabled = true;
			StrictKernelModeCreateButton.IsEnabled = true;

			StrictKernelModeInfoBar.IsClosable = true;
		}
	}


	private void StrictKernelModeAutoDetectAllDriversSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		DriverAutoDetector();
	}

	#endregion


	#region Package Family Names

	// To track whether the expandable settings section for the PFN supplemental policy has expanded so the apps list can be pre-loaded
	private bool packagesLoadedOnExpand;

	// Path to the base policy for the PFN based supplemental policy
	private string? PFNBasePolicyPath;

	private void PFNBrowseForBasePolicySettingsCard_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!PFNBrowseForBasePolicyButton_FlyOut.IsOpen)
			PFNBrowseForBasePolicyButton_FlyOut.ShowAt(PFNBrowseForBasePolicySettingsCard);
	}

	private void PFNBrowseForBasePolicySettingsCard_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!PFNBrowseForBasePolicyButton_FlyOut.IsOpen)
				PFNBrowseForBasePolicyButton_FlyOut.ShowAt(PFNBrowseForBasePolicySettingsCard);
	}

	private void PFNBrowseForBasePolicyButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!PFNBrowseForBasePolicyButton_FlyOut.IsOpen)
			PFNBrowseForBasePolicyButton_FlyOut.ShowAt(PFNBrowseForBasePolicyButton);
	}


	/// <summary>
	/// Event handler for the Refresh button to get the apps list
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void PFNRefreshAppsListButton_Click(object sender, RoutedEventArgs e)
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

	private void PFNPackagedAppsListView_PointerExited(object sender, PointerRoutedEventArgs e)
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
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void PFNSelectAllAppsListButton_Click(object sender, RoutedEventArgs e)
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
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void PFNRemoveSelectionAppsListButton_Click(object sender, RoutedEventArgs e)
	{
		PFNPackagedAppsListView.SelectedItems.Clear(); // Clear all selected items
	}


	/// <summary>
	/// Event handler to display the selected apps count on the UI TextBlock
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void PFNPackagedAppsListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		int selectedCount = PFNPackagedAppsListView.SelectedItems.Count;
		PFNSelectedItemsCount.Text = $"Selected Apps: {selectedCount}";
	}


	// Used to store the original Apps collection so when we filter the results and then remove the filters,
	// We can still have access to the original collection of apps
	private ObservableCollection<GroupInfoListForPackagedAppView>? _originalContacts;


	/// <summary>
	/// Event handler for when the search box of apps list changes
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void PFNAppFilteringTextBox_TextChanged(object sender, TextChangedEventArgs e)
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
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void PFNSettingsCard_Expanded(object sender, EventArgs e)
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


	private void PFNBrowseForBasePolicySettingsCard_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			PFNBasePolicyPath = selectedFile;

			// Add the file path to the GUI's text box
			PFNBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;

			// Display the Flyout manually at SettingsCard element since the click event happened on the Settings card
			PFNBrowseForBasePolicyButton_FlyOut.ShowAt(PFNBrowseForBasePolicySettingsCard);
		}
	}


	private void PFNBrowseForBasePolicyButton_Click(object sender, RoutedEventArgs e)
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

	private void PFNBasePolicyClearButton_Click(object sender, RoutedEventArgs e)
	{

		PFNBasePolicyPath = null;
		PFNBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;

	}

	/// <summary>
	/// Main button's event handler - Create Supplemental policy based on PFNs
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void CreatePFNSupplementalPolicyButton_Click(object sender, RoutedEventArgs e)
	{

		string? PFNBasedSupplementalPolicyName = PFNPolicyNameTextBox.Text;

		bool shouldDeploy = PFNPolicyDeployToggleButton.IsChecked ?? false;

		// Close the teaching tip if it's open when user presses the button
		// it will be opened again if necessary
		CreatePFNSupplementalPolicyTeachingTip.IsOpen = false;

		if (PFNPackagedAppsListView.SelectedItems.Count is 0)
		{
			CreatePFNSupplementalPolicyTeachingTip.IsOpen = true;
			CreatePFNSupplementalPolicyTeachingTip.Title = "PFN based Supplemental policy";
			CreatePFNSupplementalPolicyTeachingTip.Subtitle = "No app was selected to create a supplemental policy for";
			return;
		}

		if (string.IsNullOrWhiteSpace(PFNBasedSupplementalPolicyName))
		{
			CreatePFNSupplementalPolicyTeachingTip.IsOpen = true;
			CreatePFNSupplementalPolicyTeachingTip.Title = "PFN based Supplemental policy";
			CreatePFNSupplementalPolicyTeachingTip.Subtitle = "No policy name was selected for the supplemental policy";
			return;
		}

		if (string.IsNullOrWhiteSpace(PFNBasePolicyPath))
		{
			CreatePFNSupplementalPolicyTeachingTip.IsOpen = true;
			CreatePFNSupplementalPolicyTeachingTip.Title = "PFN based Supplemental policy";
			CreatePFNSupplementalPolicyTeachingTip.Subtitle = "No Base policy file was selected for the supplemental policy";
			return;
		}

		bool ErrorsOccurred = false;

		try
		{

			CreatePFNSupplementalPolicyButton.IsEnabled = false;
			PFNBrowseForBasePolicySettingsCard.IsEnabled = false;
			PFNBrowseForBasePolicyButton.IsEnabled = false;
			PFNSelectPackagedAppsSettingsCard.IsEnabled = false;
			PFNPolicyNameTextBox.IsEnabled = false;

			PFNInfoBar.IsClosable = false;
			PFNInfoBar.IsOpen = true;
			PFNInfoBar.Severity = InfoBarSeverity.Informational;
			PFNInfoBar.Message = "Creating the Supplemental policy based on Package Family Names";
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

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{PFNBasedSupplementalPolicyName}.xml");

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

				string CIPPath = Path.Combine(stagingArea.FullName, $"{PFNBasedSupplementalPolicyName}.cip");

				// Convert the XML file to CIP and save it in the defined path
				PolicyToCIPConverter.Convert(OutputPath, CIPPath);

				// If user selected to deploy the policy
				if (shouldDeploy)
				{
					string msg4 = "Deploying the Supplemental policy on the system";

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
			PFNInfoBar.Message = $"There was an error: {ex.Message}";

			throw;
		}
		finally
		{
			if (!ErrorsOccurred)
			{
				PFNInfoBar.Severity = InfoBarSeverity.Success;
				PFNInfoBar.Message = "Successfully created the supplemental policy";
			}

			CreatePFNSupplementalPolicyButton.IsEnabled = true;
			PFNBrowseForBasePolicySettingsCard.IsEnabled = true;
			PFNBrowseForBasePolicyButton.IsEnabled = true;
			PFNSelectPackagedAppsSettingsCard.IsEnabled = true;
			PFNPolicyNameTextBox.IsEnabled = true;

			PFNInfoBar.IsClosable = true;
		}

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

	private void CustomPatternBasedFileRuleBrowseForBasePolicySettingsCard_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!CustomPatternBasedFileRuleBrowseForBasePolicyButton_FlyOut.IsOpen)
				CustomPatternBasedFileRuleBrowseForBasePolicyButton_FlyOut.ShowAt(CustomPatternBasedFileRuleBrowseForBasePolicySettingsCard);
	}

	private void CustomPatternBasedFileRuleBrowseForBasePolicySettingsCard_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!CustomPatternBasedFileRuleBrowseForBasePolicyButton_FlyOut.IsOpen)
			CustomPatternBasedFileRuleBrowseForBasePolicyButton_FlyOut.ShowAt(CustomPatternBasedFileRuleBrowseForBasePolicySettingsCard);
	}

	private void CustomPatternBasedFileRuleBrowseForBasePolicyButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!CustomPatternBasedFileRuleBrowseForBasePolicyButton_FlyOut.IsOpen)
			CustomPatternBasedFileRuleBrowseForBasePolicyButton_FlyOut.ShowAt(CustomPatternBasedFileRuleBrowseForBasePolicyButton);
	}

	private void CustomPatternBasedFileRuleBrowseForBasePolicySettingsCard_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			CustomPatternBasedFileRuleBasedBasePolicyPath = selectedFile;

			CustomPatternBasedFileRuleBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;

			CustomPatternBasedFileRuleBrowseForBasePolicyButton_FlyOut.ShowAt(CustomPatternBasedFileRuleBrowseForBasePolicySettingsCard);
		}
	}

	private void CustomPatternBasedFileRuleBrowseForBasePolicyButton_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			CustomPatternBasedFileRuleBasedBasePolicyPath = selectedFile;

			CustomPatternBasedFileRuleBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = selectedFile;
		}
	}

	private void CustomPatternBasedFileRuleBrowseForBasePolicyButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		CustomPatternBasedFileRuleBasedBasePolicyPath = null;
		CustomPatternBasedFileRuleBrowseForBasePolicyButton_SelectedBasePolicyTextBox.Text = null;
	}


	/// <summary>
	/// Event handler for the main button - to create Supplemental pattern based File path policy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void CreateCustomPatternBasedFileRuleSupplementalPolicyButton_Click(object sender, RoutedEventArgs e)
	{

		bool errorsOccurred = false;

		if (CustomPatternBasedFileRuleBasedBasePolicyPath is null)
		{
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.IsOpen = true;
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Title = "Select base policy";
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Subtitle = "You need to select a base policy before you can create a Supplemental policy.";
			return;
		}

		if (string.IsNullOrWhiteSpace(SupplementalPolicyCustomPatternBasedCustomPatternTextBox.Text))
		{
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.IsOpen = true;
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Title = "Enter a custom pattern";
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Subtitle = "You need to enter a custom pattern for the file rule.";
			return;
		}

		if (string.IsNullOrWhiteSpace(CustomPatternBasedFileRuleBasedSupplementalPolicyName))
		{
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.IsOpen = true;
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Title = "Enter a policy name";
			CreateCustomPatternBasedFileRuleSupplementalPolicyTeachingTip.Subtitle = "You need to enter a name for the supplemental policy.";
			return;
		}

		try
		{
			CreateCustomPatternBasedFileRuleSupplementalPolicyButton.IsEnabled = false;
			CustomPatternBasedFileRulePolicyDeployToggleButton.IsEnabled = false;
			CustomPatternBasedFileRulePolicyNameTextBox.IsEnabled = false;
			CustomPatternBasedFileRuleBrowseForBasePolicyButton.IsEnabled = false;
			SupplementalPolicyCustomPatternBasedCustomPatternTextBox.IsEnabled = false;

			CustomPatternBasedFileRuleInfoBar.IsOpen = true;
			CustomPatternBasedFileRuleInfoBar.Message = "Creating the Pattern-based File Path rule Supplemental policy.";
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

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{CustomPatternBasedFileRuleBasedSupplementalPolicyName}.xml");

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

				string CIPPath = Path.Combine(stagingArea.FullName, $"{CustomPatternBasedFileRuleBasedSupplementalPolicyName}.cip");

				// Convert the XML file to CIP and save it in the defined path
				PolicyToCIPConverter.Convert(OutputPath, CIPPath);

				// If user selected to deploy the policy
				if (CustomPatternBasedFileRuleBasedDeployButton)
				{
					string msg4 = "Deploying the Supplemental policy on the system";

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
			CustomPatternBasedFileRuleInfoBar.Message = $"An error occurred while creating Pattern-based File Path rule Supplemental policy: {ex.Message}";

			Logger.Write($"An error occurred while creating Pattern-based File Path rule Supplemental policy: {ex.Message}");

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				CustomPatternBasedFileRuleInfoBar.Severity = InfoBarSeverity.Success;

				CustomPatternBasedFileRuleInfoBar.Message = "Successfully created Pattern-based File Path rule Supplemental policy.";
			}

			CreateCustomPatternBasedFileRuleSupplementalPolicyButton.IsEnabled = true;
			CustomPatternBasedFileRulePolicyDeployToggleButton.IsEnabled = true;
			CustomPatternBasedFileRulePolicyNameTextBox.IsEnabled = true;
			CustomPatternBasedFileRuleBrowseForBasePolicyButton.IsEnabled = true;
			SupplementalPolicyCustomPatternBasedCustomPatternTextBox.IsEnabled = true;
			CustomPatternBasedFileRuleInfoBar.IsClosable = true;
		}
	}


	/// <summary>
	/// Event handler to display the content dialog for more info about patterns
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void SupplementalPolicyCustomPatternBasedFileRuleSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		// Instantiate the Content Dialog
		CustomUIElements.CustomPatternBasedFilePath customDialog = new();

		App.CurrentlyOpenContentDialog = customDialog;

		// Show the dialog
		_ = await customDialog.ShowAsync();
	}

	#endregion

}
