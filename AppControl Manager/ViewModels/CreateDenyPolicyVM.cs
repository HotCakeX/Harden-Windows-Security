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
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.Pages;
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;
using CommunityToolkit.WinUI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class CreateDenyPolicyVM : ViewModelBase
{
	private PolicyEditorVM PolicyEditorViewModel { get; } = App.AppHost.Services.GetRequiredService<PolicyEditorVM>();

	internal CreateDenyPolicyVM()
	{
		FilesAndFoldersProgressRingValueProgress = new Progress<double>(p => FilesAndFoldersProgressRingValue = p);

		// InfoBar manager for the FilesAndFolders section
		FilesAndFoldersInfoBar = new InfoBarSettings(
			() => FilesAndFoldersInfoBarIsOpen, value => FilesAndFoldersInfoBarIsOpen = value,
			() => FilesAndFoldersInfoBarMessage, value => FilesAndFoldersInfoBarMessage = value,
			() => FilesAndFoldersInfoBarSeverity, value => FilesAndFoldersInfoBarSeverity = value,
			() => FilesAndFoldersInfoBarIsClosable, value => FilesAndFoldersInfoBarIsClosable = value,
			() => FilesAndFoldersInfoBarTitle, value => FilesAndFoldersInfoBarTitle = value);

		// InfoBar manager for the PFN section
		PFNInfoBar = new InfoBarSettings(
			() => PFNInfoBarIsOpen, value => PFNInfoBarIsOpen = value,
			() => PFNInfoBarMessage, value => PFNInfoBarMessage = value,
			() => PFNInfoBarSeverity, value => PFNInfoBarSeverity = value,
			() => PFNInfoBarIsClosable, value => PFNInfoBarIsClosable = value,
			() => PFNInfoBarTitle, value => PFNInfoBarTitle = value);

		// InfoBar manager for the CustomFilePathRules section
		CustomFilePathRulesInfoBar = new InfoBarSettings(
			() => CustomFilePathRulesInfoBarIsOpen, value => CustomFilePathRulesInfoBarIsOpen = value,
			() => CustomFilePathRulesInfoBarMessage, value => CustomFilePathRulesInfoBarMessage = value,
			() => CustomFilePathRulesInfoBarSeverity, value => CustomFilePathRulesInfoBarSeverity = value,
			() => CustomFilePathRulesInfoBarIsClosable, value => CustomFilePathRulesInfoBarIsClosable = value,
			() => CustomFilePathRulesInfoBarTitle, value => CustomFilePathRulesInfoBarTitle = value);
	}

	#region Files and Folders scan

	/// <summary>
	/// Whether the UI elements for Files and Folders section are enabled or disabled.
	/// </summary>
	internal bool FilesAndFoldersElementsAreEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the Settings Expander for the Files and Folders section is expanded.
	/// </summary>
	internal bool FilesAndFoldersSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	internal readonly InfoBarSettings FilesAndFoldersInfoBar;

	internal double FilesAndFoldersProgressRingValue { get; set => SP(ref field, value); }

	// A Progress<double> so Report() callbacks run on the UI thread
	internal IProgress<double> FilesAndFoldersProgressRingValueProgress;

	// Used to store the scan results and as the source for the results ListViews
	internal ObservableCollection<FileIdentity> FilesAndFoldersScanResults { get; set => SP(ref field, value); } = [];

	internal readonly List<FileIdentity> filesAndFoldersScanResultsList = [];

	internal Visibility FilesAndFoldersBrowseForFilesSettingsCardVisibility { get; set => SP(ref field, value); } = Visibility.Visible;

	internal ListViewHelper.SortState SortStateFilesAndFolders { get; set; } = new();

	internal Visibility FilesAndFoldersInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal string TotalCountOfTheFilesTextBox { get; set => SP(ref field, value); } = GlobalVars.Rizz.GetString("TotalFiles") + ": 0";

	/// <summary>
	/// Selected File Paths
	/// </summary>
	internal readonly UniqueStringObservableCollection filesAndFoldersFilePaths = [];

	/// <summary>
	/// Selected Folder Paths
	/// </summary>
	internal readonly UniqueStringObservableCollection filesAndFoldersFolderPaths = [];

	/// <summary>
	/// Selected Deny policy name
	/// </summary>
	internal string? filesAndFoldersDenyPolicyName { get; set => SP(ref field, value); }

	internal bool filesAndFoldersDeployButton { get; set => SP(ref field, value); }

	private bool UsingWildCardFilePathRules { get; set; }

	// The default selected scan level
	internal ScanLevels filesAndFoldersScanLevel = ScanLevels.FilePublisher;
	internal string FilesAndFoldersScanLevelComboBoxSelectedItem
	{
		get; set
		{
			if (SP(ref field, value))
			{
				filesAndFoldersScanLevel = StringToScanLevel[field];

				// For Wildcard file path rules, only folder paths should be used
				UsingWildCardFilePathRules = filesAndFoldersScanLevel is ScanLevels.WildCardFolderPath;
				FilesAndFoldersBrowseForFilesSettingsCardVisibility = filesAndFoldersScanLevel is ScanLevels.WildCardFolderPath ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = ScanLevelToString[ScanLevels.FilePublisher];

	internal double FilesAndFoldersScalabilityRadialGaugeValue
	{
		get; set
		{
			if (SP(ref field, value))
			{
				FilesAndFoldersScalabilityButtonContent = GlobalVars.Rizz.GetString("Scalability") + field;
			}
		}
	} = 2;

	/// <summary>
	/// The content of the button that has the RadialGauge inside it.
	/// </summary>
	internal string FilesAndFoldersScalabilityButtonContent { get; set => SP(ref field, value); } = GlobalVars.Rizz.GetString("Scalability") + "2";

	internal bool FilesAndFoldersInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool FilesAndFoldersInfoBarIsClosable { get; set => SP(ref field, value); }
	internal string? FilesAndFoldersInfoBarMessage { get; set => SP(ref field, value); }
	internal string? FilesAndFoldersInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity FilesAndFoldersInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	#region LISTVIEW IMPLEMENTATIONS

	// Properties to hold each columns' width.
	internal GridLength ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth6 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth7 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth8 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth9 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth10 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth11 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth12 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth13 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth14 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth15 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth16 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth17 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth18 { get; set => SP(ref field, value); }

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidths()
	{

		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SignatureStatusHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("OriginalFileNameHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("InternalNameHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileDescriptionHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("ProductNameHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileVersionHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("PackageFamilyNameHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA256HashHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA1HashHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SigningScenarioHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FilePathHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA1PageHashHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA256PageHashHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("HasWHQLSignerHeader/Text"));
		double maxWidth16 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FilePublishersHeader/Text"));
		double maxWidth17 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("IsECCSignedHeader/Text"));
		double maxWidth18 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("OpusDataHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileIdentity item in FilesAndFoldersScanResults)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.FileName, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.SignatureStatus.ToString(), maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.OriginalFileName, maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.InternalName, maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.FileDescription, maxWidth5);
			maxWidth6 = ListViewHelper.MeasureText(item.ProductName, maxWidth6);
			maxWidth7 = ListViewHelper.MeasureText(item.FileVersion?.ToString(), maxWidth7);
			maxWidth8 = ListViewHelper.MeasureText(item.PackageFamilyName, maxWidth8);
			maxWidth9 = ListViewHelper.MeasureText(item.SHA256Hash, maxWidth9);
			maxWidth10 = ListViewHelper.MeasureText(item.SHA1Hash, maxWidth10);
			maxWidth11 = ListViewHelper.MeasureText(item.SISigningScenario.ToString(), maxWidth11);
			maxWidth12 = ListViewHelper.MeasureText(item.FilePath, maxWidth12);
			maxWidth13 = ListViewHelper.MeasureText(item.SHA1PageHash, maxWidth13);
			maxWidth14 = ListViewHelper.MeasureText(item.SHA256PageHash, maxWidth14);
			maxWidth15 = ListViewHelper.MeasureText(item.HasWHQLSigner.ToString(), maxWidth15);
			maxWidth16 = ListViewHelper.MeasureText(item.FilePublishersToDisplay, maxWidth16);
			maxWidth17 = ListViewHelper.MeasureText(item.IsECCSigned.ToString(), maxWidth17);
			maxWidth18 = ListViewHelper.MeasureText(item.Opus, maxWidth18);
		}

		// Set the column width properties.
		ColumnWidth1 = new GridLength(maxWidth1);
		ColumnWidth2 = new GridLength(maxWidth2);
		ColumnWidth3 = new GridLength(maxWidth3);
		ColumnWidth4 = new GridLength(maxWidth4);
		ColumnWidth5 = new GridLength(maxWidth5);
		ColumnWidth6 = new GridLength(maxWidth6);
		ColumnWidth7 = new GridLength(maxWidth7);
		ColumnWidth8 = new GridLength(maxWidth8);
		ColumnWidth9 = new GridLength(maxWidth9);
		ColumnWidth10 = new GridLength(maxWidth10);
		ColumnWidth11 = new GridLength(maxWidth11);
		ColumnWidth12 = new GridLength(maxWidth12);
		ColumnWidth13 = new GridLength(maxWidth13);
		ColumnWidth14 = new GridLength(maxWidth14);
		ColumnWidth15 = new GridLength(maxWidth15);
		ColumnWidth16 = new GridLength(maxWidth16);
		ColumnWidth17 = new GridLength(maxWidth17);
		ColumnWidth18 = new GridLength(maxWidth18);
	}

	#endregion

	/// <summary>
	/// Updates the total logs count displayed on the UI
	/// </summary>
	internal void UpdateTotalFiles(bool? Zero = null)
	{
		if (Zero == true)
		{
			TotalCountOfTheFilesTextBox = GlobalVars.Rizz.GetString("TotalFiles") + ": 0";
		}
		else
		{
			TotalCountOfTheFilesTextBox = GlobalVars.Rizz.GetString("TotalFiles") + ": " + FilesAndFoldersScanResults.Count;
		}
	}

	/// <summary>
	/// Main button's event handler for files and folder Deny policy creation
	/// </summary>
	internal async void CreateFilesAndFoldersDenyPolicyButton_Click()
	{
		FilesAndFoldersSettingsExpanderIsExpanded = true;

		FilesAndFoldersInfoBarActionButtonVisibility = Visibility.Collapsed;

		// Reset the progress ring from previous runs or in case an error occurred
		FilesAndFoldersProgressRingValue = 0;

		if (filesAndFoldersFilePaths.Count == 0 && filesAndFoldersFolderPaths.Count == 0)
		{
			FilesAndFoldersInfoBar.WriteWarning(GlobalVars.Rizz.GetString("NoFilesOrFoldersSelected"),
				GlobalVars.Rizz.GetString("SelectFilesOrFoldersTitle"));
			return;
		}

		if (string.IsNullOrWhiteSpace(filesAndFoldersDenyPolicyName))
		{
			FilesAndFoldersInfoBar.WriteWarning(GlobalVars.Rizz.GetString("ChoosePolicyNameSubtitle"),
				GlobalVars.Rizz.GetString("ChoosePolicyNameTitle"));
			return;
		}

		_FilesAndFoldersDenyPolicyPath = null;

		bool errorsOccurred = false;

		try
		{

			FilesAndFoldersElementsAreEnabled = false;

			FilesAndFoldersInfoBar.IsClosable = false;

			FilesAndFoldersInfoBar.WriteInfo(GlobalVars.Rizz.GetString("SelectedFilesAndFolders") + filesAndFoldersFilePaths.Count + GlobalVars.Rizz.GetString("FilesAnd") + filesAndFoldersFolderPaths.Count + GlobalVars.Rizz.GetString("Folders"));

			await Task.Run(async () =>
			{

				DirectoryInfo[] selectedDirectories = [];

				// Convert user selected folder paths that are strings to DirectoryInfo objects
				selectedDirectories = [.. filesAndFoldersFolderPaths.Select(dir => new DirectoryInfo(dir))];

				FileInfo[] selectedFiles = [];

				// Convert user selected file paths that are strings to FileInfo objects
				selectedFiles = [.. filesAndFoldersFilePaths.Select(file => new FileInfo(file))];

				IEnumerable<FileIdentity> LocalFilesResults = [];

				// Do the following steps only if Wildcard paths aren't going to be used because then only the selected folder paths are needed
				if (!UsingWildCardFilePathRules)
				{

					// Collect all of the AppControl compatible files from user selected directories and files
					(IEnumerable<FileInfo>, int) DetectedFilesInSelectedDirectories = FileUtility.GetFilesFast(selectedDirectories, selectedFiles, null);


					// Make sure there are AppControl compatible files
					if (DetectedFilesInSelectedDirectories.Item2 is 0)
					{
						_ = Dispatcher.TryEnqueue(() =>
						{
							errorsOccurred = true;
							FilesAndFoldersInfoBar.WriteWarning(GlobalVars.Rizz.GetString("NoCompatibleFilesDetected"),
								GlobalVars.Rizz.GetString("NoCompatibleFilesTitle"));
						});
						return;
					}

					_ = Dispatcher.TryEnqueue(() =>
					{
						FilesAndFoldersInfoBar.WriteInfo(GlobalVars.Rizz.GetString("ScanningFiles") + DetectedFilesInSelectedDirectories.Item2 + GlobalVars.Rizz.GetString("AppControlCompatibleFiles"));
					});

					// Scan all of the detected files from the user selected directories
					// Add the reference to the ViewModel class to the item so we can use it for navigation from the XAML
					LocalFilesResults = LocalFilesScan.Scan(
						DetectedFilesInSelectedDirectories,
						(ushort)FilesAndFoldersProgressRingValue,
						FilesAndFoldersProgressRingValueProgress,
						this,
						(fi, vm) => fi.ParentViewModelCreateDenyPolicyVM = vm);


					filesAndFoldersScanResultsList.Clear();

					filesAndFoldersScanResultsList.AddRange(LocalFilesResults);

					await Dispatcher.EnqueueAsync(() =>
					{
						// Add the results of the directories scans to the ListView
						FilesAndFoldersScanResults = new(LocalFilesResults);

						CalculateColumnWidths();

						UpdateTotalFiles();
					});

					_ = Dispatcher.TryEnqueue(() =>
					{
						FilesAndFoldersInfoBar.WriteInfo(GlobalVars.Rizz.GetString("ScanCompleted"));
					});
				}

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("FilesAndFoldersDenyPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. LocalFilesResults], level: filesAndFoldersScanLevel, folderPaths: filesAndFoldersFolderPaths);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Deny, stagingArea.FullName);

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{filesAndFoldersDenyPolicyName}.xml");

				// Set policy name and reset the policy ID
				_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, filesAndFoldersDenyPolicyName, null, null);

				// Configure policy rule options
				CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Base);

				// Set policy version
				SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

				// Copying the policy file to the User Config directory - outside of the temporary staging area
				File.Copy(EmptyPolicyPath, OutputPath, true);

				_FilesAndFoldersDenyPolicyPath = OutputPath;

				string CIPPath = Path.Combine(stagingArea.FullName, $"{filesAndFoldersDenyPolicyName}.cip");

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// If user selected to deploy the policy
				if (filesAndFoldersDeployButton)
				{
					_ = Dispatcher.TryEnqueue(() =>
					{
						FilesAndFoldersInfoBar.WriteInfo(GlobalVars.Rizz.GetString("DeployingThePolicy"));
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
			FilesAndFoldersInfoBar.WriteError(ex, GlobalVars.Rizz.GetString("ErrorOccurredCreatingPolicy"));
		}
		finally
		{
			if (!errorsOccurred)
			{
				FilesAndFoldersInfoBar.WriteSuccess(GlobalVars.Rizz.GetString("DenyPolicyCreatedSuccessfully") + filesAndFoldersDenyPolicyName + "'");

				FilesAndFoldersInfoBarActionButtonVisibility = Visibility.Visible;
			}

			FilesAndFoldersInfoBar.IsClosable = true;

			FilesAndFoldersElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Browse for Files - Button Click
	/// </summary>
	internal void FilesAndFoldersBrowseForFilesButton_Click()
	{
		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.AnyFilePickerFilter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				filesAndFoldersFilePaths.Add(file);
			}
		}
	}

	/// <summary>
	/// Browse for Folders - Button Click
	/// </summary>
	internal void FilesAndFoldersBrowseForFoldersButton_Click()
	{
		List<string>? selectedDirectories = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		if (selectedDirectories is { Count: > 0 })
		{
			foreach (string dir in selectedDirectories)
			{
				filesAndFoldersFolderPaths.Add(dir);
			}
		}
	}

	internal void FilesAndFoldersViewFileDetailsSettingsCard_Click()
	{
		App._nav.Navigate(typeof(CreateDenyPolicyFilesAndFoldersScanResults), null);
	}

	/// <summary>
	/// Button to clear the list of selected folder paths
	/// </summary>
	internal void FilesAndFoldersBrowseForFoldersButton_Flyout_Clear_Click()
	{
		filesAndFoldersFolderPaths.Clear();
	}

	/// <summary>
	/// Button to clear the list of selected file paths
	/// </summary>
	internal void FilesAndFoldersBrowseForFilesButton_Flyout_Clear_Click()
	{
		filesAndFoldersFilePaths.Clear();
	}

	/// <summary>
	/// Path to the Files and Folders Deny policy XML file
	/// </summary>
	private string? _FilesAndFoldersDenyPolicyPath;

	/// <summary>
	/// Opens a policy editor for files and folders using a specified Deny policy path.
	/// </summary>
	internal async void OpenInPolicyEditor_FilesAndFolders()
	{
		try
		{
			await PolicyEditorViewModel.OpenInPolicyEditor(_FilesAndFoldersDenyPolicyPath);
		}
		catch (Exception ex)
		{
			FilesAndFoldersInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// De-selects all of the displayed rows on the ListView
	/// </summary>
	internal void DeSelectAll_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.DenyPolicy_FilesAndFolders_ScanResults);
		if (lv is null) return;
		lv.SelectedItems.Clear(); // Deselect all rows by clearing SelectedItems
	}

	/// <summary>
	/// Selects all of the displayed rows on the ListView
	/// </summary>
	internal void SelectAll_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.DenyPolicy_FilesAndFolders_ScanResults);
		if (lv is null) return;

		ListViewHelper.SelectAll(lv, FilesAndFoldersScanResults);
	}

	/// <summary>
	/// Event handler for the Clear Data button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void ClearDataButton_Click(object sender, RoutedEventArgs e)
	{
		FilesAndFoldersScanResults.Clear();
		filesAndFoldersScanResultsList.Clear();
		UpdateTotalFiles(true);
	}

	/// <summary>
	/// Search box for the Files and Folders scan results.
	/// </summary>
	internal string? FilesAndFoldersScanResultsSearchTextBox
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ApplyFilters();
			}
		}
	}

	/// <summary>
	/// Applies the date and search filters to the data grid
	/// </summary>
	private void ApplyFilters()
	{
		ListViewHelper.ApplyFilters(
			allFileIdentities: filesAndFoldersScanResultsList.AsEnumerable(),
			filteredCollection: FilesAndFoldersScanResults,
			searchText: FilesAndFoldersScanResultsSearchTextBox,
			datePicker: null,
			regKey: ListViewHelper.ListViewsRegistry.DenyPolicy_FilesAndFolders_ScanResults
		);
		UpdateTotalFiles();
	}

	#endregion

	#region Package Family Names

	internal readonly InfoBarSettings PFNInfoBar;

	internal Visibility PFNInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool PFNInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool PFNInfoBarIsClosable { get; set => SP(ref field, value); }
	internal string? PFNInfoBarMessage { get; set => SP(ref field, value); }
	internal string? PFNInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity PFNInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	/// <summary>
	/// Whether the UI elements for the PFN section are enabled or disabled.
	/// </summary>
	internal bool PFNElementsAreEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// To track whether the expandable settings section for the PFN Deny policy has expanded so the apps list can be pre-loaded
	/// </summary>
	internal bool packagesLoadedOnExpand;

	/// <summary>
	/// Whether the Settings Expander for the PFN based section is expanded or not.
	/// </summary>
	internal bool PFNBasedSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	/// <summary>
	/// Items Source of the ListView that displays the list of the installed packaged apps.
	/// </summary>
	internal ObservableCollection<GroupInfoListForPackagedAppView> PFNBasedAppsListItemsSource { get; set => SP(ref field, value); } = [];

	private List<object> PFNBasedAppsListItemsSourceSelectedItems = [];

	/// <summary>
	/// Whether the Deny policy should be deployed at the end.
	/// </summary>
	internal bool PFNBasedShouldDeploy { get; set => SP(ref field, value); }

	/// <summary>
	/// Displays the count of the selected apps from the ListView.
	/// </summary>
	internal string? PFNBasedSelectedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// The search keyword for filtering the apps list.
	/// </summary>
	internal string? PFNBasedSearchKeywordForAppsList
	{
		get; set
		{
			if (SP(ref field, value))
			{
				PFNAppFilteringTextBox_TextChanged();
			}
		}
	}

	/// <summary>
	/// The name of the Deny policy that will be created.
	/// </summary>
	internal string? PFNBasedDenyPolicyName { get; set => SP(ref field, value); }

	/// <summary>
	/// Event handler for the Refresh button to get the apps list
	/// </summary>
	internal async void PFNRefreshAppsListButton_Click()
	{
		try
		{
			PFNElementsAreEnabled = false;
			PFNBasedAppsListItemsSource = await GetAppsList.GetContactsGroupedAsync();
		}
		finally
		{
			PFNElementsAreEnabled = true;
			PFNBasedAppsListItemsSourceSelectedItems.Clear();
		}
	}

	/// <summary>
	/// Event handler to select all apps in the ListView
	/// </summary>
	internal void PFNSelectAllAppsListButton_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.DenyPolicy_PFNBasedRules);
		if (lv is null) return;

		// Ensure the ListView has items
		if (lv.ItemsSource is IEnumerable<object> items)
		{
			lv.SelectedItems.Clear(); // Clear any existing selection

			foreach (object item in items)
			{
				lv.SelectedItems.Add(item); // Add each item to SelectedItems
			}
		}

		PFNBasedAppsListItemsSourceSelectedItems = new(lv.SelectedItems);
	}

	/// <summary>
	/// Event handler to remove all selections of apps in the ListView
	/// </summary>
	internal void PFNRemoveSelectionAppsListButton_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.DenyPolicy_PFNBasedRules);
		if (lv is null) return;

		lv.SelectedItems.Clear();

		PFNBasedAppsListItemsSourceSelectedItems.Clear();
	}


	/// <summary>
	/// Event handler to display the selected apps count on the UI TextBlock
	/// </summary>
	internal void PFNPackagedAppsListView_SelectionChanged()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.DenyPolicy_PFNBasedRules);
		if (lv is null) return;

		int selectedCount = lv.SelectedItems.Count;
		PFNBasedSelectedItemsCount = string.Format(GlobalVars.Rizz.GetString("SelectedAppsCount"), selectedCount);

		PFNBasedAppsListItemsSourceSelectedItems = new(lv.SelectedItems);
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
		_originalContacts ??= (ObservableCollection<GroupInfoListForPackagedAppView>)PFNBasedAppsListItemsSource;

		if (string.IsNullOrWhiteSpace(PFNBasedSearchKeywordForAppsList))
		{
			// If the filter is cleared, restore the original collection
			PFNBasedAppsListItemsSource = _originalContacts;
			return;
		}

		// Filter the original collection
		List<GroupInfoListForPackagedAppView> filtered = [.. _originalContacts
			.Select(group => new GroupInfoListForPackagedAppView(group.Where(app =>
				app.DisplayName.Contains(PFNBasedSearchKeywordForAppsList, StringComparison.OrdinalIgnoreCase)))
			{
				Key = group.Key // Preserve the group key
			})
			.Where(group => group.Any())];

		// Update the ListView source with the filtered data
		PFNBasedAppsListItemsSource = new ObservableCollection<GroupInfoListForPackagedAppView>(filtered);
	}


	/// <summary>
	/// Event handler to happen only once when the section is expanded and apps list is loaded
	/// </summary>
	internal async void PFNSettingsCard_Expanded()
	{
		if (!packagesLoadedOnExpand)
		{
			try
			{
				PFNElementsAreEnabled = false;
				PFNBasedAppsListItemsSource = await GetAppsList.GetContactsGroupedAsync();
			}
			finally
			{
				PFNElementsAreEnabled = true;
				PFNBasedAppsListItemsSourceSelectedItems.Clear();
			}
			packagesLoadedOnExpand = true;
		}
	}


	/// <summary>
	/// Main button's event handler - Create Deny policy based on PFNs
	/// </summary>
	internal async void CreatePFNDenyPolicyButton_Click()
	{
		PFNBasedSettingsExpanderIsExpanded = true;

		PFNInfoBarActionButtonVisibility = Visibility.Collapsed;

		if (PFNBasedAppsListItemsSourceSelectedItems.Count is 0)
		{
			PFNInfoBar.WriteWarning(GlobalVars.Rizz.GetString("NoAppSelectedForDenyPolicy"),
				"PFN based policy");
			return;
		}

		if (string.IsNullOrWhiteSpace(PFNBasedDenyPolicyName))
		{
			PFNInfoBar.WriteWarning(GlobalVars.Rizz.GetString("ChoosePolicyNameSubtitle"),
				GlobalVars.Rizz.GetString("ChoosePolicyNameTitle"));
			return;
		}

		bool ErrorsOccurred = false;

		_PFNDenyPolicyPath = null;

		try
		{

			PFNElementsAreEnabled = false;

			PFNInfoBar.IsClosable = false;

			PFNInfoBar.WriteInfo(GlobalVars.Rizz.GetString("CreatingPFNBasedDenyPolicy"));

			// A list to store the selected PackagedAppView items
			List<string> selectedAppsPFNs = [];

			// Loop through the selected items
			foreach (var selectedItem in PFNBasedAppsListItemsSourceSelectedItems)
			{
				if (selectedItem is PackagedAppView appView)
				{
					// Add the selected item's PFN to the list
					selectedAppsPFNs.Add(appView.PackageFamilyNameActual);
				}
			}

			await Task.Run(() =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("PFNDenyPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(level: ScanLevels.PFN, packageFamilyNames: selectedAppsPFNs);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Deny, stagingArea.FullName);

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{PFNBasedDenyPolicyName}.xml");

				// Set policy name and reset the policy ID
				_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, PFNBasedDenyPolicyName, null, null);

				// Configure policy rule options
				CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Base);

				// Set policy version
				SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

				// Copying the policy file to the User Config directory - outside of the temporary staging area
				File.Copy(EmptyPolicyPath, OutputPath, true);

				_PFNDenyPolicyPath = OutputPath;

				string CIPPath = Path.Combine(stagingArea.FullName, $"{PFNBasedDenyPolicyName}.cip");

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// If user selected to deploy the policy
				if (PFNBasedShouldDeploy)
				{
					_ = Dispatcher.TryEnqueue(() =>
					{
						PFNInfoBar.WriteInfo(GlobalVars.Rizz.GetString("DeployingThePolicy"));
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
			PFNInfoBar.WriteError(ex, GlobalVars.Rizz.GetString("ErrorOccurredScanningDrivers"));
		}
		finally
		{
			if (!ErrorsOccurred)
			{
				PFNInfoBar.WriteSuccess(GlobalVars.Rizz.GetString("DenyPolicyCreated"));

				PFNInfoBarActionButtonVisibility = Visibility.Visible;
			}

			PFNElementsAreEnabled = true;

			PFNInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Path to the PFN Deny policy XML file
	/// </summary>
	private string? _PFNDenyPolicyPath;

	/// <summary>
	/// Opens a policy editor for PFN using a specified Deny policy path.
	/// </summary>
	internal async void OpenInPolicyEditor_PFN()
	{
		try
		{
			await PolicyEditorViewModel.OpenInPolicyEditor(_PFNDenyPolicyPath);
		}
		catch (Exception ex)
		{
			PFNInfoBar.WriteError(ex);
		}
	}

	#endregion

	#region Custom Pattern-based File Rule

	/// <summary>
	/// Whether the UI elements for the Custom File Path Rules section are enabled or disabled.
	/// </summary>
	internal bool CustomFilePathRulesElementsAreEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the Settings Expander for the Custom File Path Rules section is expanded.
	/// </summary>
	internal bool CustomFilePathRulesSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	internal readonly InfoBarSettings CustomFilePathRulesInfoBar;

	internal Visibility CustomFilePathRulesInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool CustomFilePathRulesInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool CustomFilePathRulesInfoBarIsClosable { get; set => SP(ref field, value); }
	internal string? CustomFilePathRulesInfoBarMessage { get; set => SP(ref field, value); }
	internal string? CustomFilePathRulesInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity CustomFilePathRulesInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	internal bool CustomPatternBasedFileRuleBasedDeployButton { get; set => SP(ref field, value); }

	/// <summary>
	/// The custom pattern used for file rule.
	/// </summary>
	internal string? DenyPolicyCustomPatternBasedCustomPatternTextBox { get; set => SP(ref field, value); }

	/// <summary>
	/// Selected Deny policy name
	/// </summary>
	internal string? CustomPatternBasedFileRuleBasedDenyPolicyName { get; set => SP(ref field, value); }

	/// <summary>
	/// Event handler for the main button - to create Deny pattern based File path policy
	/// </summary>
	internal async void CreateCustomPatternBasedFileRuleDenyPolicyButton_Click()
	{
		bool errorsOccurred = false;

		CustomFilePathRulesSettingsExpanderIsExpanded = true;

		CustomFilePathRulesInfoBarActionButtonVisibility = Visibility.Collapsed;

		if (string.IsNullOrWhiteSpace(DenyPolicyCustomPatternBasedCustomPatternTextBox))
		{
			CustomFilePathRulesInfoBar.WriteWarning(GlobalVars.Rizz.GetString("EnterCustomPatternSubtitle"),
				GlobalVars.Rizz.GetString("EnterCustomPatternTitle"));
			return;
		}

		if (string.IsNullOrWhiteSpace(CustomPatternBasedFileRuleBasedDenyPolicyName))
		{
			CustomFilePathRulesInfoBar.WriteWarning(GlobalVars.Rizz.GetString("ChoosePolicyNameSubtitle"),
				GlobalVars.Rizz.GetString("ChoosePolicyNameTitle"));
			return;
		}

		_CustomPatternBasedFileRuleDenyPolicyPath = null;

		try
		{
			CustomFilePathRulesElementsAreEnabled = false;

			CustomFilePathRulesInfoBarIsClosable = false;

			CustomFilePathRulesInfoBar.WriteInfo(GlobalVars.Rizz.GetString("CreatingPatternBasedFilePathRuleDenyPolicyMessage"));

			await Task.Run(() =>
			{
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("PatternBasedFilePathRuleDenyPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: null, level: ScanLevels.CustomFileRulePattern, folderPaths: null, customFileRulePatterns: [DenyPolicyCustomPatternBasedCustomPatternTextBox]);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Deny, stagingArea.FullName);

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{CustomPatternBasedFileRuleBasedDenyPolicyName}.xml");

				// Set policy name and reset the policy ID
				_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, CustomPatternBasedFileRuleBasedDenyPolicyName, null, null);

				// Configure policy rule options
				CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Base);

				// Set policy version
				SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

				// Copying the policy file to the User Config directory - outside of the temporary staging area
				File.Copy(EmptyPolicyPath, OutputPath, true);

				_CustomPatternBasedFileRuleDenyPolicyPath = OutputPath;

				string CIPPath = Path.Combine(stagingArea.FullName, $"{CustomPatternBasedFileRuleBasedDenyPolicyName}.cip");

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// If user selected to deploy the policy
				if (CustomPatternBasedFileRuleBasedDeployButton)
				{
					_ = Dispatcher.TryEnqueue(() =>
					{
						CustomFilePathRulesInfoBar.WriteInfo(GlobalVars.Rizz.GetString("DeployingThePolicy"));
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
			CustomFilePathRulesInfoBar.WriteError(ex, GlobalVars.Rizz.GetString("ErrorOccurredCreatingPolicy"));
		}
		finally
		{
			if (!errorsOccurred)
			{
				CustomFilePathRulesInfoBar.WriteSuccess(GlobalVars.Rizz.GetString("SuccessfullyCreatedPatternBasedFilePathRuleDenyPolicyMessage"));

				CustomFilePathRulesInfoBarActionButtonVisibility = Visibility.Visible;
			}

			CustomFilePathRulesElementsAreEnabled = true;

			CustomFilePathRulesInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Event handler to display the content dialog for more info about patterns
	/// </summary>
	internal async void DenyPolicyCustomPatternBasedFileRuleSettingsCard_Click()
	{
		try
		{
			// Instantiate the Content Dialog
			CustomUIElements.CustomPatternBasedFilePath customDialog = new();

			App.CurrentlyOpenContentDialog = customDialog;

			// Show the dialog
			_ = await customDialog.ShowAsync();
		}
		catch (Exception ex)
		{
			CustomFilePathRulesInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Path to the CustomPatternBasedFileRule Deny policy XML file
	/// </summary>
	private string? _CustomPatternBasedFileRuleDenyPolicyPath;

	/// <summary>
	/// Opens a policy editor for CustomPatternBasedFileRule using a specified Deny policy path.
	/// </summary>
	internal async void OpenInPolicyEditor_CustomPatternBasedFileRule()
	{
		try
		{
			await PolicyEditorViewModel.OpenInPolicyEditor(_CustomPatternBasedFileRuleDenyPolicyPath);
		}
		catch (Exception ex)
		{
			CustomFilePathRulesInfoBar.WriteError(ex);
		}
	}

	#endregion

}
