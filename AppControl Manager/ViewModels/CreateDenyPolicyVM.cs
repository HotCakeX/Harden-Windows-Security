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
using System.Threading.Tasks;
using AppControlManager.IncrementalCollection;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.Pages;
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;
using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.ViewModels;

internal sealed partial class CreateDenyPolicyVM : ViewModelBase, IDisposable
{
	// Dispose the controller
	public void Dispose() => LVController.Dispose();

	private PolicyEditorVM PolicyEditorViewModel { get; } = ViewModelProvider.PolicyEditorVM;

	internal CreateDenyPolicyVM()
	{
		FilesAndFoldersProgressRingValueProgress = new Progress<double>(p => FilesAndFoldersProgressRingValue = p);

		// InfoBar manager for the FilesAndFolders section
		FilesAndFoldersInfoBar = new InfoBarSettings(
			() => FilesAndFoldersInfoBarIsOpen, value => FilesAndFoldersInfoBarIsOpen = value,
			() => FilesAndFoldersInfoBarMessage, value => FilesAndFoldersInfoBarMessage = value,
			() => FilesAndFoldersInfoBarSeverity, value => FilesAndFoldersInfoBarSeverity = value,
			() => FilesAndFoldersInfoBarIsClosable, value => FilesAndFoldersInfoBarIsClosable = value,
			Dispatcher,
			() => FilesAndFoldersInfoBarTitle, value => FilesAndFoldersInfoBarTitle = value);

		FilesAndFoldersCancellableButton = new(GlobalVars.GetStr("CreateDenyPolicyButton/Content"));

		// InfoBar manager for the PFN section
		PFNInfoBar = new InfoBarSettings(
			() => PFNInfoBarIsOpen, value => PFNInfoBarIsOpen = value,
			() => PFNInfoBarMessage, value => PFNInfoBarMessage = value,
			() => PFNInfoBarSeverity, value => PFNInfoBarSeverity = value,
			() => PFNInfoBarIsClosable, value => PFNInfoBarIsClosable = value,
			Dispatcher,
			() => PFNInfoBarTitle, value => PFNInfoBarTitle = value);

		PFNBasedCancellableButton = new(GlobalVars.GetStr("CreateDenyPolicyButton/Content"));

		// InfoBar manager for the CustomFilePathRules section
		CustomFilePathRulesInfoBar = new InfoBarSettings(
			() => CustomFilePathRulesInfoBarIsOpen, value => CustomFilePathRulesInfoBarIsOpen = value,
			() => CustomFilePathRulesInfoBarMessage, value => CustomFilePathRulesInfoBarMessage = value,
			() => CustomFilePathRulesInfoBarSeverity, value => CustomFilePathRulesInfoBarSeverity = value,
			() => CustomFilePathRulesInfoBarIsClosable, value => CustomFilePathRulesInfoBarIsClosable = value,
			Dispatcher,
			() => CustomFilePathRulesInfoBarTitle, value => CustomFilePathRulesInfoBarTitle = value);

		PatternBasedFileRuleCancellableButton = new(GlobalVars.GetStr("CreateDenyPolicyButton/Content"));

		LVController = new(
			registryKey: ListViewHelper.ListViewsRegistry.DenyPolicy_FilesAndFolders_ScanResults,
			applyWidthCallback: (index, width) =>
			{
				switch (index)
				{
					case 0: ColumnWidth1 = new GridLength(width); break;
					case 1: ColumnWidth2 = new GridLength(width); break;
					case 2: ColumnWidth3 = new GridLength(width); break;
					case 3: ColumnWidth4 = new GridLength(width); break;
					case 4: ColumnWidth5 = new GridLength(width); break;
					case 5: ColumnWidth6 = new GridLength(width); break;
					case 6: ColumnWidth7 = new GridLength(width); break;
					case 7: ColumnWidth8 = new GridLength(width); break;
					case 8: ColumnWidth9 = new GridLength(width); break;
					case 9: ColumnWidth10 = new GridLength(width); break;
					case 10: ColumnWidth11 = new GridLength(width); break;
					case 11: ColumnWidth12 = new GridLength(width); break;
					case 12: ColumnWidth13 = new GridLength(width); break;
					case 13: ColumnWidth14 = new GridLength(width); break;
					case 14: ColumnWidth15 = new GridLength(width); break;
					case 15: ColumnWidth16 = new GridLength(width); break;
					case 16: ColumnWidth17 = new GridLength(width); break;
					case 17: ColumnWidth18 = new GridLength(width); break;
					default: break;
				}
			},
			// Current widths provider handed to controller for delta comparison & anchoring.
			getCurrentWidthsCallback: () => new double[]
			{
				ColumnWidth1.Value,  ColumnWidth2.Value,  ColumnWidth3.Value,  ColumnWidth4.Value,  ColumnWidth5.Value,
				ColumnWidth6.Value,  ColumnWidth7.Value,  ColumnWidth8.Value,  ColumnWidth9.Value,  ColumnWidth10.Value,
				ColumnWidth11.Value, ColumnWidth12.Value, ColumnWidth13.Value, ColumnWidth14.Value, ColumnWidth15.Value,
				ColumnWidth16.Value, ColumnWidth17.Value, ColumnWidth18.Value
			},
			headerResourceKeys: ListViewHelper.SupplementalAndDenyPolicyCreationHeaderResourceKeys,
			columnPropertyKeys: ListViewHelper.SupplementalAndDenyPolicyCreationPropertyKeys
		);

		// Run header-only pass once during VM construction so headers are sized before any data loads.
		LVController.InitializeHeaderOnlyColumnWidths();
	}

	#region Files and Folders scan

	internal readonly ListViewIncrementalController LVController;

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

	internal Visibility FilesAndFoldersBrowseForFilesSettingsCardVisibility { get; set => SP(ref field, value); } = Visibility.Visible;

	internal ListViewHelper.SortState SortStateFilesAndFolders { get; set; } = new();

	internal Visibility FilesAndFoldersInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

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
	internal string? filesAndFoldersDenyPolicyName { get; set => SPT(ref field, value); }

	internal bool filesAndFoldersDeployButton { get; set => SP(ref field, value); }

	internal ScanLevelsComboBoxType FilesAndFoldersScanLevelComboBoxSelectedItem
	{
		get; set
		{
			if (SP(ref field, value))
			{
				// For Wildcard file path rules, only folder paths should be used
				FilesAndFoldersBrowseForFilesSettingsCardVisibility = field.Level is ScanLevels.WildCardFolderPath ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = DefaultScanLevel;

	internal double FilesAndFoldersScalabilityRadialGaugeValue
	{
		get; set
		{
			if (SP(ref field, value))
			{
				FilesAndFoldersScalabilityButtonContent = GlobalVars.GetStr("Scalability") + field;
			}
		}
	} = 2;

	/// <summary>
	/// The content of the button that has the RadialGauge inside it.
	/// </summary>
	internal string FilesAndFoldersScalabilityButtonContent { get; set => SP(ref field, value); } = GlobalVars.GetStr("Scalability") + "2";

	internal bool FilesAndFoldersInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool FilesAndFoldersInfoBarIsClosable { get; set => SP(ref field, value); }
	internal string? FilesAndFoldersInfoBarMessage { get; set => SP(ref field, value); }
	internal string? FilesAndFoldersInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity FilesAndFoldersInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	// Column width dependency properties
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

	internal void FileAndFoldersHeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		string key = (string)((Button)sender).Tag;
		LVController.SortByHeader(key, FilesAndFoldersScanResultsSearchTextBox);
	}

	/// <summary>
	/// Search box for the Files and Folders scan results.
	/// </summary>
	internal string? FilesAndFoldersScanResultsSearchTextBox
	{
		get; set
		{
			if (SPT(ref field, value))
			{
				LVController.ApplySearch(value);
			}
		}
	}

	/// <summary>
	/// Initialization details for the main Create button for the Files and Folders section
	/// </summary>
	internal readonly AnimatedCancellableButtonInitializer FilesAndFoldersCancellableButton;

	/// <summary>
	/// Main button's event handler for files and folders Deny policy creation
	/// </summary>
	internal async void CreateFilesAndFoldersDenyPolicyButton_Click()
	{
		FilesAndFoldersSettingsExpanderIsExpanded = true;

		FilesAndFoldersInfoBarActionButtonVisibility = Visibility.Collapsed;

		// Reset the progress ring from previous runs or in case an error occurred
		FilesAndFoldersProgressRingValue = 0;

		// Check validation conditions but do NOT set button state until all checks pass
		if (filesAndFoldersFilePaths.Count == 0 && filesAndFoldersFolderPaths.Count == 0)
		{
			FilesAndFoldersInfoBar.WriteWarning(GlobalVars.GetStr("NoFilesOrFoldersSelected"),
				GlobalVars.GetStr("SelectFilesOrFoldersTitle"));

			return;
		}

		if (OperationModeComboBoxSelectedIndex is 0 && string.IsNullOrWhiteSpace(filesAndFoldersDenyPolicyName))
		{
			FilesAndFoldersInfoBar.WriteWarning(GlobalVars.GetStr("ChoosePolicyNameSubtitle"),
				GlobalVars.GetStr("ChoosePolicyNameTitle"));

			return;
		}

		// use the policy to merge with file if that option is enabled by the user
		if (OperationModeComboBoxSelectedIndex is 1)
		{
			if (PolicyFileToMergeWith is null)
			{
				FilesAndFoldersInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyToAddRulesToSubtitle"), GlobalVars.GetStr("SelectPolicyToAddRulesToTitle"));
				return;
			}
		}

		// All validation passed - NOW we set button state to indicate operation starting
		_FilesAndFoldersDenyPolicyPath = null;

		bool errorsOccurred = false;

		FilesAndFoldersCancellableButton.Begin();

		try
		{
			FilesAndFoldersElementsAreEnabled = false;

			FilesAndFoldersInfoBar.IsClosable = false;

			FilesAndFoldersInfoBar.WriteInfo(GlobalVars.GetStr("SelectedFilesAndFolders") + filesAndFoldersFilePaths.Count + GlobalVars.GetStr("FilesAnd") + filesAndFoldersFolderPaths.Count + GlobalVars.GetStr("Folders"));

			await Task.Run(async () =>
			{
				IEnumerable<FileIdentity> LocalFilesResults = [];

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Do the following steps only if Wildcard paths aren't going to be used because then only the selected folder paths are needed
				if (FilesAndFoldersScanLevelComboBoxSelectedItem.Level is not ScanLevels.WildCardFolderPath)
				{
					// Collect all of the AppControl compatible files from user selected directories and files
					(IEnumerable<string>, int) DetectedFilesInSelectedDirectories = FileUtility.GetFilesFast(filesAndFoldersFolderPaths,
						filesAndFoldersFilePaths,
						null,
						FilesAndFoldersCancellableButton.Cts?.Token);

					// Make sure there are AppControl compatible files
					if (DetectedFilesInSelectedDirectories.Item2 is 0)
					{
						errorsOccurred = true;
						FilesAndFoldersInfoBar.WriteWarning(GlobalVars.GetStr("NoCompatibleFilesDetected"),
							GlobalVars.GetStr("NoCompatibleFilesTitle"));
						return;
					}

					FilesAndFoldersInfoBar.WriteInfo(GlobalVars.GetStr("ScanningFiles") + DetectedFilesInSelectedDirectories.Item2 + GlobalVars.GetStr("AppControlCompatibleFiles"));

					FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					// Scan all of the detected files from the user selected directories
					LocalFilesResults = LocalFilesScan.Scan(
						DetectedFilesInSelectedDirectories,
						(ushort)FilesAndFoldersProgressRingValue,
						FilesAndFoldersProgressRingValueProgress,
						FilesAndFoldersCancellableButton.Cts?.Token);

					LVController.FullSource.Clear();

					LVController.FullSource.AddRange(LocalFilesResults);

					FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					await Dispatcher.EnqueueAsync(() =>
					{
						GenericIncrementalCollection<FileIdentityIncrementalSource, FileIdentity> incrementalCollection =
							new(new FileIdentityIncrementalSource(LVController.FullSource));

						// Replaces the ItemsSource for the results ListView with the incremental collection.
						LVController.UpdateCollection(incrementalCollection);

						// Kicks off the initial page load for the incremental collection. Intentionally discard the returned Task because:
						// - The first page begins populating asynchronously.
						// - Width recalculation below is safe: the controller will size to headers immediately,
						//   and will re-debounce/recompute widths again as items realize (via ContainerContentChanging/scroll hooks).
						_ = incrementalCollection.RefreshDataAsync();

						// Recompute visible column widths right away (headers + any realized rows).
						// This ensures the header grid columns get an immediate, sane size before/while the first page appears.
						// Subsequent realization/scroll events will trigger debounced recalcs for smooth adjustments.
						LVController.RecalculateVisibleColumnWidths();

						LVController.NotifyFullSourceChanged();
					});

					FilesAndFoldersInfoBar.WriteInfo(GlobalVars.GetStr("ScanCompleted"));
				}

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("FilesAndFoldersDenyPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. LocalFilesResults], level: FilesAndFoldersScanLevelComboBoxSelectedItem.Level, folderPaths: filesAndFoldersFolderPaths);

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Deny, stagingArea.FullName, OperationModeComboBoxSelectedIndex is 1);

				string OutputPath = OperationModeComboBoxSelectedIndex is 1 ? PolicyFileToMergeWith! : Path.Combine(GlobalVars.UserConfigDir, $"{filesAndFoldersDenyPolicyName}.xml");

				if (OperationModeComboBoxSelectedIndex is 1)
				{
					// Merge the new Deny policy with the user selected policy - user selected policy is the main one in the merge operation
					Merger.Merge(OutputPath, [EmptyPolicyPath]);
				}
				else
				{
					// Set policy name and reset the policy ID
					_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, filesAndFoldersDenyPolicyName, null, null);

					FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					// Configure policy rule options
					CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Base);

					// Set policy version
					SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

					// Copying the policy file to the User Config directory - outside of the temporary staging area
					File.Copy(EmptyPolicyPath, OutputPath, true);
				}

				_FilesAndFoldersDenyPolicyPath = OutputPath;

				// Use the name of the user selected file for CIP file name, otherwise use the name of the Deny policy provided by the user
				string CIPName = OperationModeComboBoxSelectedIndex is 1
					? $"{Path.GetFileNameWithoutExtension(PolicyFileToMergeWith!)}.cip"
					: $"{filesAndFoldersDenyPolicyName}.cip";

				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// If user selected to deploy the policy
				if (filesAndFoldersDeployButton)
				{
					_ = Dispatcher.TryEnqueue(() =>
					{
						FilesAndFoldersInfoBar.WriteInfo(GlobalVars.GetStr("DeployingThePolicy"));
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

			// Final check for cancellation after Task.Run completes
			FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

		}
		catch (Exception ex)
		{
			HandleExceptions(ex, ref errorsOccurred, ref FilesAndFoldersCancellableButton.wasCancelled, FilesAndFoldersInfoBar, GlobalVars.GetStr("ErrorOccurredCreatingPolicy"));
		}
		finally
		{
			if (FilesAndFoldersCancellableButton.wasCancelled)
			{
				FilesAndFoldersInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledByUser"));
			}
			else if (!errorsOccurred)
			{
				FilesAndFoldersInfoBar.WriteSuccess(GlobalVars.GetStr("DenyPolicyCreatedSuccessfully") + filesAndFoldersDenyPolicyName + "'");

				FilesAndFoldersInfoBarActionButtonVisibility = Visibility.Visible;
			}

			FilesAndFoldersCancellableButton.End();

			FilesAndFoldersInfoBar.IsClosable = true;

			FilesAndFoldersElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Browse for Files - Button Click
	/// </summary>
	internal void FilesAndFoldersBrowseForFilesButton_Click()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.AnyFilePickerFilter);

		if (selectedFiles.Count > 0)
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
		List<string> selectedDirectories = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		if (selectedDirectories.Count > 0)
		{
			foreach (string dir in selectedDirectories)
			{
				filesAndFoldersFolderPaths.Add(dir);
			}
		}
	}

	internal void FilesAndFoldersViewFileDetailsSettingsCard_Click()
	{
		ViewModelProvider.NavigationService.Navigate(typeof(CreateDenyPolicyFilesAndFoldersScanResults), null);
	}

	/// <summary>
	/// Button to clear the list of selected folder paths
	/// </summary>
	internal void FilesAndFoldersBrowseForFoldersButton_Flyout_Clear_Click() => filesAndFoldersFolderPaths.Clear();

	/// <summary>
	/// Button to clear the list of selected file paths
	/// </summary>
	internal void FilesAndFoldersBrowseForFilesButton_Flyout_Clear_Click() => filesAndFoldersFilePaths.Clear();

	/// <summary>
	/// Path to the Files and Folders Deny policy XML file
	/// </summary>
	private string? _FilesAndFoldersDenyPolicyPath;

	/// <summary>
	/// Opens a policy editor for files and folders using a specified Deny policy path.
	/// </summary>
	internal async void OpenInPolicyEditor_FilesAndFolders() => await PolicyEditorViewModel.OpenInPolicyEditor(_FilesAndFoldersDenyPolicyPath);

	internal async void OpenInDefaultFileHandler_FilesAndFolders() => await OpenInDefaultFileHandler(_FilesAndFoldersDenyPolicyPath);

	/// <summary>
	/// Exports data to JSON.
	/// </summary>
	internal async void ExportFilesAndFoldersToJsonButton_Click()
	{
		try
		{
			await FileIdentity.ExportToJson(LVController.FullSource, FilesAndFoldersInfoBar);
		}
		catch (Exception ex)
		{
			FilesAndFoldersInfoBar.WriteError(ex);
		}
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

	// Used to store the original Apps collection so when we filter the results and then remove the filters,
	// We can still have access to the original collection of apps
	private List<GroupInfoListForPackagedAppView> PFNBasedAppsFullList = [];

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
	/// Initialization details for the main Create button for the PFN-Based section
	/// </summary>
	internal readonly AnimatedCancellableButtonInitializer PFNBasedCancellableButton;

	/// <summary>
	/// The search keyword for filtering the apps list.
	/// </summary>
	internal string? PFNBasedSearchKeywordForAppsList
	{
		get; set
		{
			if (SPT(ref field, value))
			{
				PFNAppFilteringTextBox_TextChanged();
			}
		}
	}

	/// <summary>
	/// The name of the Deny policy that will be created.
	/// </summary>
	internal string? PFNBasedDenyPolicyName { get; set => SPT(ref field, value); }

	/// <summary>
	/// Event handler for the Refresh button to get the apps list
	/// </summary>
	internal async void PFNRefreshAppsListButton_Click()
	{
		try
		{
			PFNElementsAreEnabled = false;
			PFNBasedAppsListItemsSource = await GetAppsList.GetContactsGroupedAsync(this);
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
		PFNBasedSelectedItemsCount = string.Format(GlobalVars.GetStr("SelectedAppsCount"), selectedCount);

		PFNBasedAppsListItemsSourceSelectedItems = new(lv.SelectedItems);
	}

	/// <summary>
	/// Event handler for when the search box of apps list changes
	/// </summary>
	private void PFNAppFilteringTextBox_TextChanged()
	{
		if (string.IsNullOrWhiteSpace(PFNBasedSearchKeywordForAppsList))
		{
			// If the filter is cleared, restore the original collection
			PFNBasedAppsListItemsSource = new(PFNBasedAppsFullList);
			return;
		}

		// Filter the original collection
		List<GroupInfoListForPackagedAppView> filtered = PFNBasedAppsFullList
			.Select(group => new GroupInfoListForPackagedAppView(
				items: group.Where(app => app.DisplayName.Contains(PFNBasedSearchKeywordForAppsList, StringComparison.OrdinalIgnoreCase)),
				key: group.Key)).Where(group => group.Any()).ToList();

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

				// Get the data first and store in ObservableCollection
				PFNBasedAppsListItemsSource = await GetAppsList.GetContactsGroupedAsync(this);

				// Store the same data on the FullList used for searching
				PFNBasedAppsFullList = new(PFNBasedAppsListItemsSource);
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
			PFNInfoBar.WriteWarning(GlobalVars.GetStr("NoAppSelectedForDenyPolicy"),
				"PFN based policy");
			return;
		}

		if (OperationModeComboBoxSelectedIndex is 0 && string.IsNullOrWhiteSpace(PFNBasedDenyPolicyName))
		{
			PFNInfoBar.WriteWarning(GlobalVars.GetStr("ChoosePolicyNameSubtitle"),
				GlobalVars.GetStr("ChoosePolicyNameTitle"));
			return;
		}

		// use the policy to merge with file if that option is enabled by the user
		if (OperationModeComboBoxSelectedIndex is 1)
		{
			if (PolicyFileToMergeWith is null)
			{
				PFNInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyToAddRulesToSubtitle"), GlobalVars.GetStr("SelectPolicyToAddRulesToTitle"));
				return;
			}
		}

		// All validation passed - NOW we set button state to indicate operation starting
		_PFNDenyPolicyPath = null;

		bool errorsOccurred = false;

		PFNBasedCancellableButton.Begin();

		try
		{
			PFNElementsAreEnabled = false;

			PFNInfoBar.IsClosable = false;

			PFNInfoBar.WriteInfo(GlobalVars.GetStr("CreatingPFNBasedDenyPolicy"));

			PFNBasedCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

			// A list to store the selected PackagedAppView items
			List<string> selectedAppsPFNs = [];

			// Loop through the selected items
			foreach (var selectedItem in PFNBasedAppsListItemsSourceSelectedItems)
			{
				PFNBasedCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				if (selectedItem is PackagedAppView appView)
				{
					// Add the selected item's PFN to the list
					selectedAppsPFNs.Add(appView.PackageFamilyName);
				}
			}

			await Task.Run(() =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("PFNDenyPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				PFNBasedCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(level: ScanLevels.PFN, packageFamilyNames: selectedAppsPFNs);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Deny, stagingArea.FullName, OperationModeComboBoxSelectedIndex is 1);

				string OutputPath = OperationModeComboBoxSelectedIndex is 1 ? PolicyFileToMergeWith! : Path.Combine(GlobalVars.UserConfigDir, $"{PFNBasedDenyPolicyName}.xml");

				PFNBasedCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				if (OperationModeComboBoxSelectedIndex is 1)
				{
					// Merge the new Deny policy with the user selected policy - user selected policy is the main one in the merge operation
					Merger.Merge(OutputPath, [EmptyPolicyPath]);
				}
				else
				{
					// Set policy name and reset the policy ID
					_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, PFNBasedDenyPolicyName, null, null);

					// Configure policy rule options
					CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Base);

					// Set policy version
					SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

					PFNBasedCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					// Copying the policy file to the User Config directory - outside of the temporary staging area
					File.Copy(EmptyPolicyPath, OutputPath, true);
				}

				_PFNDenyPolicyPath = OutputPath;

				// Use the name of the user selected file for CIP file name, otherwise use the name of the Deny policy provided by the user
				string CIPName = OperationModeComboBoxSelectedIndex is 1
					? $"{Path.GetFileNameWithoutExtension(PolicyFileToMergeWith!)}.cip"
					: $"{PFNBasedDenyPolicyName}.cip";

				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				PFNBasedCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// If user selected to deploy the policy
				if (PFNBasedShouldDeploy)
				{
					_ = Dispatcher.TryEnqueue(() =>
					{
						PFNInfoBar.WriteInfo(GlobalVars.GetStr("DeployingThePolicy"));
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
			HandleExceptions(ex, ref errorsOccurred, ref PFNBasedCancellableButton.wasCancelled, PFNInfoBar, GlobalVars.GetStr("ErrorOccurredScanningDrivers"));
		}
		finally
		{

			if (PFNBasedCancellableButton.wasCancelled)
			{
				PFNInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledByUser"));
			}
			else if (!errorsOccurred)
			{
				PFNInfoBar.WriteSuccess(GlobalVars.GetStr("DenyPolicyCreated"));

				PFNInfoBarActionButtonVisibility = Visibility.Visible;
			}

			PFNBasedCancellableButton.End();

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
	internal async void OpenInPolicyEditor_PFN() => await PolicyEditorViewModel.OpenInPolicyEditor(_PFNDenyPolicyPath);

	internal async void OpenInDefaultFileHandler_PFN() => await OpenInDefaultFileHandler(_PFNDenyPolicyPath);

	/// <summary>
	/// Event handler for copying app details to clipboard from the context menu.
	/// </summary>
	/// <param name="sender">The MenuFlyoutItem that was clicked</param>
	/// <param name="e">Event arguments</param>
	internal void CopyAppDetails_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			PFNInfoBar.IsClosable = false;

			if (sender is not MenuFlyoutItem menuItem)
			{
				return;
			}

			// Navigate up the visual tree to find the PackagedAppView data context
			DependencyObject? current = menuItem;
			PackagedAppView? targetApp = null;

			while (current is not null)
			{
				if (current is FrameworkElement element && element.DataContext is PackagedAppView app)
				{
					targetApp = app;
					break;
				}
				current = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(current);
			}

			if (targetApp is null)
			{
				PFNInfoBar.WriteWarning("Could not determine which app's details to copy.");
				return;
			}

			ListViewHelper.ConvertRowToText([targetApp], ListViewHelper.PackagedAppPropertyMappings);
		}
		catch (Exception ex)
		{
			PFNInfoBar.WriteError(ex);
		}
		finally
		{
			PFNInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for opening the installation location of a single app from the context menu.
	/// </summary>
	/// <param name="sender">The MenuFlyoutItem that was clicked</param>
	/// <param name="e">Event arguments</param>
	internal async void OpenAppLocation_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			PFNInfoBar.IsClosable = false;

			if (sender is not MenuFlyoutItem menuItem)
			{
				return;
			}

			// Navigate up the visual tree to find the PackagedAppView data context
			DependencyObject? current = menuItem;
			PackagedAppView? targetApp = null;

			while (current is not null)
			{
				if (current is FrameworkElement element && element.DataContext is PackagedAppView app)
				{
					targetApp = app;
					break;
				}
				current = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(current);
			}

			if (targetApp is null)
			{
				PFNInfoBar.WriteWarning("Could not determine which app's location to open.");
				return;
			}

			if (string.IsNullOrWhiteSpace(targetApp.InstallLocation))
			{
				PFNInfoBar.WriteWarning($"No installation location available for {targetApp.DisplayName}.");
				return;
			}

			// Check if the directory exists
			if (!Directory.Exists(targetApp.InstallLocation))
			{
				PFNInfoBar.WriteWarning($"Installation location does not exist: {targetApp.InstallLocation}");
				return;
			}

			// Open the folder in File Explorer
			await OpenInDefaultFileHandler(targetApp.InstallLocation);

			PFNInfoBar.WriteInfo($"Opened installation location for {targetApp.DisplayName}");
		}
		catch (Exception ex)
		{
			PFNInfoBar.WriteError(ex);
		}
		finally
		{
			PFNInfoBar.IsClosable = true;
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
	internal string? DenyPolicyCustomPatternBasedCustomPatternTextBox { get; set => SPT(ref field, value); }

	/// <summary>
	/// Selected Deny policy name
	/// </summary>
	internal string? CustomPatternBasedFileRuleBasedDenyPolicyName { get; set => SPT(ref field, value); }

	/// <summary>
	/// Initialization details for the main Create button for the Pattern Based FileRule section
	/// </summary>
	internal readonly AnimatedCancellableButtonInitializer PatternBasedFileRuleCancellableButton;

	/// <summary>
	/// Event handler for the main button - to create Deny pattern based File path policy
	/// </summary>
	internal async void CreateCustomPatternBasedFileRuleDenyPolicyButton_Click()
	{

		CustomFilePathRulesSettingsExpanderIsExpanded = true;

		CustomFilePathRulesInfoBarActionButtonVisibility = Visibility.Collapsed;

		if (string.IsNullOrWhiteSpace(DenyPolicyCustomPatternBasedCustomPatternTextBox))
		{
			CustomFilePathRulesInfoBar.WriteWarning(GlobalVars.GetStr("EnterCustomPatternSubtitle"),
				GlobalVars.GetStr("EnterCustomPatternTitle"));
			return;
		}

		if (OperationModeComboBoxSelectedIndex is 0 && string.IsNullOrWhiteSpace(CustomPatternBasedFileRuleBasedDenyPolicyName))
		{
			CustomFilePathRulesInfoBar.WriteWarning(GlobalVars.GetStr("ChoosePolicyNameSubtitle"),
				GlobalVars.GetStr("ChoosePolicyNameTitle"));
			return;
		}

		// use the policy to merge with file if that option is enabled by the user
		if (OperationModeComboBoxSelectedIndex is 1)
		{
			if (PolicyFileToMergeWith is null)
			{
				CustomFilePathRulesInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyToAddRulesToSubtitle"), GlobalVars.GetStr("SelectPolicyToAddRulesToTitle"));
				return;
			}
		}

		// All validation passed - NOW we set button state to indicate operation starting
		_CustomPatternBasedFileRuleDenyPolicyPath = null;

		bool errorsOccurred = false;

		PatternBasedFileRuleCancellableButton.Begin();

		try
		{
			CustomFilePathRulesElementsAreEnabled = false;

			CustomFilePathRulesInfoBarIsClosable = false;

			CustomFilePathRulesInfoBar.WriteInfo(GlobalVars.GetStr("CreatingPatternBasedFilePathRuleDenyPolicyMessage"));

			PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

			await Task.Run(() =>
			{
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("PatternBasedFilePathRuleDenyPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: null, level: ScanLevels.CustomFileRulePattern, folderPaths: null, customFileRulePatterns: [DenyPolicyCustomPatternBasedCustomPatternTextBox]);

				PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Deny, stagingArea.FullName, OperationModeComboBoxSelectedIndex is 1);

				string OutputPath = OperationModeComboBoxSelectedIndex is 1 ? PolicyFileToMergeWith! : Path.Combine(GlobalVars.UserConfigDir, $"{CustomPatternBasedFileRuleBasedDenyPolicyName}.xml");

				PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				if (OperationModeComboBoxSelectedIndex is 1)
				{
					// Merge the new Deny policy with the user selected policy - user selected policy is the main one in the merge operation
					Merger.Merge(OutputPath, [EmptyPolicyPath]);
				}
				else
				{
					// Set policy name and reset the policy ID
					_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, CustomPatternBasedFileRuleBasedDenyPolicyName, null, null);

					// Configure policy rule options
					CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Base);

					// Set policy version
					SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

					PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					// Copying the policy file to the User Config directory - outside of the temporary staging area
					File.Copy(EmptyPolicyPath, OutputPath, true);
				}

				_CustomPatternBasedFileRuleDenyPolicyPath = OutputPath;

				// Use the name of the user selected file for CIP file name, otherwise use the name of the Deny policy provided by the user
				string CIPName = OperationModeComboBoxSelectedIndex is 1
					? $"{Path.GetFileNameWithoutExtension(PolicyFileToMergeWith!)}.cip"
					: $"{CustomPatternBasedFileRuleBasedDenyPolicyName}.cip";

				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// If user selected to deploy the policy
				if (CustomPatternBasedFileRuleBasedDeployButton)
				{
					_ = Dispatcher.TryEnqueue(() =>
					{
						CustomFilePathRulesInfoBar.WriteInfo(GlobalVars.GetStr("DeployingThePolicy"));
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
			HandleExceptions(ex, ref errorsOccurred, ref PatternBasedFileRuleCancellableButton.wasCancelled, CustomFilePathRulesInfoBar, GlobalVars.GetStr("ErrorOccurredCreatingPolicy"));
		}
		finally
		{
			if (PatternBasedFileRuleCancellableButton.wasCancelled)
			{
				CustomFilePathRulesInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledByUser"));
			}
			else if (!errorsOccurred)
			{
				CustomFilePathRulesInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyCreatedPatternBasedFilePathRuleDenyPolicyMessage"));

				CustomFilePathRulesInfoBarActionButtonVisibility = Visibility.Visible;
			}

			PatternBasedFileRuleCancellableButton.End();

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
	internal async void OpenInPolicyEditor_CustomPatternBasedFileRule() => await PolicyEditorViewModel.OpenInPolicyEditor(_CustomPatternBasedFileRuleDenyPolicyPath);

	internal async void OpenInDefaultFileHandler_CustomPatternBasedFileRule() => await OpenInDefaultFileHandler(_CustomPatternBasedFileRuleDenyPolicyPath);

	#endregion

	#region Policy Creation Mode

	/// <summary>
	/// The path to the policy file that user selected to add the new rules to.
	/// </summary>
	internal string? PolicyFileToMergeWith { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the button that allows for picking a policy file to add the rules to is enabled or disabled.
	/// </summary>
	internal bool PolicyFileToMergeWithPickerButtonIsEnabled { get; set => SP(ref field, value); }

	/// <summary>
	/// Controls the visibility of all of the elements related to browsing for base policy file.
	/// </summary>
	internal Visibility BasePolicyElementsVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Visible;


	/// <summary>
	/// The mode of operation for the Deny creation page.
	/// Set to 0 (Creating New Policies) by default.
	/// </summary>
	internal int OperationModeComboBoxSelectedIndex
	{
		get;
		set
		{
			// Update the operation mode property
			_ = SP(ref field, value);

			// Automate the update of elements responsible for accepting base policy path.
			// If this is set to 0, they should be visible, otherwise they should be collapsed.
			BasePolicyElementsVisibility = field == 0 ? Visibility.Visible : Visibility.Collapsed;

			PolicyFileToMergeWithPickerButtonIsEnabled = field == 1;
		}
	}

	/// <summary>
	/// Clears the PolicyFileToMergeWith
	/// </summary>
	internal void ClearPolicyFileToMergeWith()
	{
		PolicyFileToMergeWith = null;
	}

	internal void PolicyFileToMergeWithButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			PolicyFileToMergeWith = selectedFile;
		}
	}

	#endregion

	internal void _OpenInFileExplorer() => OpenInFileExplorer(ListViewHelper.ListViewsRegistry.DenyPolicy_FilesAndFolders_ScanResults);
	internal void _OpenInFileExplorerShortCut(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		_OpenInFileExplorer();
		args.Handled = true;
	}
}
