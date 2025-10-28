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
using System.Security.Cryptography.X509Certificates;
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

internal sealed partial class CreateSupplementalPolicyVM : ViewModelBase, IDisposable
{
	// Dispose the controller
	public void Dispose() => LVController.Dispose();

	internal PolicyEditorVM PolicyEditorViewModel { get; } = ViewModelProvider.PolicyEditorVM;

	internal CreateSupplementalPolicyVM()
	{
		FilesAndFoldersProgressRingValueProgress = new Progress<double>(p => FilesAndFoldersProgressRingValue = p);
		DriverAutoDetectionProgressRingValueProgress = new Progress<double>(p => DriverAutoDetectionProgressRingValue = p);

		// InfoBar manager for the FilesAndFolders section
		FilesAndFoldersInfoBar = new InfoBarSettings(
			() => FilesAndFoldersInfoBarIsOpen, value => FilesAndFoldersInfoBarIsOpen = value,
			() => FilesAndFoldersInfoBarMessage, value => FilesAndFoldersInfoBarMessage = value,
			() => FilesAndFoldersInfoBarSeverity, value => FilesAndFoldersInfoBarSeverity = value,
			() => FilesAndFoldersInfoBarIsClosable, value => FilesAndFoldersInfoBarIsClosable = value,
			Dispatcher,
			() => FilesAndFoldersInfoBarTitle, value => FilesAndFoldersInfoBarTitle = value);

		LVController = new(
			registryKey: ListViewHelper.ListViewsRegistry.SupplementalPolicy_FilesAndFolders_ScanResults,
			applyWidthCallback: (index, width) =>
			{
				switch (index)
				{
					case 0: ColumnWidthFilesAndFolders1 = new GridLength(width); break;
					case 1: ColumnWidthFilesAndFolders2 = new GridLength(width); break;
					case 2: ColumnWidthFilesAndFolders3 = new GridLength(width); break;
					case 3: ColumnWidthFilesAndFolders4 = new GridLength(width); break;
					case 4: ColumnWidthFilesAndFolders5 = new GridLength(width); break;
					case 5: ColumnWidthFilesAndFolders6 = new GridLength(width); break;
					case 6: ColumnWidthFilesAndFolders7 = new GridLength(width); break;
					case 7: ColumnWidthFilesAndFolders8 = new GridLength(width); break;
					case 8: ColumnWidthFilesAndFolders9 = new GridLength(width); break;
					case 9: ColumnWidthFilesAndFolders10 = new GridLength(width); break;
					case 10: ColumnWidthFilesAndFolders11 = new GridLength(width); break;
					case 11: ColumnWidthFilesAndFolders12 = new GridLength(width); break;
					case 12: ColumnWidthFilesAndFolders13 = new GridLength(width); break;
					case 13: ColumnWidthFilesAndFolders14 = new GridLength(width); break;
					case 14: ColumnWidthFilesAndFolders15 = new GridLength(width); break;
					case 15: ColumnWidthFilesAndFolders16 = new GridLength(width); break;
					case 16: ColumnWidthFilesAndFolders17 = new GridLength(width); break;
					case 17: ColumnWidthFilesAndFolders18 = new GridLength(width); break;
					default: break;
				}
			},
			// Current widths provider handed to controller for delta comparison & anchoring.
			getCurrentWidthsCallback: () => new double[]
			{
						ColumnWidthFilesAndFolders1.Value,  ColumnWidthFilesAndFolders2.Value,  ColumnWidthFilesAndFolders3.Value,  ColumnWidthFilesAndFolders4.Value,  ColumnWidthFilesAndFolders5.Value,
						ColumnWidthFilesAndFolders6.Value,  ColumnWidthFilesAndFolders7.Value,  ColumnWidthFilesAndFolders8.Value,  ColumnWidthFilesAndFolders9.Value,  ColumnWidthFilesAndFolders10.Value,
						ColumnWidthFilesAndFolders11.Value, ColumnWidthFilesAndFolders12.Value, ColumnWidthFilesAndFolders13.Value, ColumnWidthFilesAndFolders14.Value, ColumnWidthFilesAndFolders15.Value,
						ColumnWidthFilesAndFolders16.Value, ColumnWidthFilesAndFolders17.Value, ColumnWidthFilesAndFolders18.Value
			},
			headerResourceKeys: ListViewHelper.SupplementalAndDenyPolicyCreationHeaderResourceKeys,
			columnPropertyKeys: ListViewHelper.SupplementalAndDenyPolicyCreationPropertyKeys
		);

		// Run header-only pass once during VM construction so headers are sized before any data loads.
		LVController.InitializeHeaderOnlyColumnWidths();

		FilesAndFoldersCancellableButton = new(GlobalVars.GetStr("CreateSupplementalPolicyButton/Content"));

		// InfoBar manager for the CertificatesBased section
		CertificatesBasedInfoBar = new InfoBarSettings(
			() => CertificatesBasedInfoBarIsOpen, value => CertificatesBasedInfoBarIsOpen = value,
			() => CertificatesBasedInfoBarMessage, value => CertificatesBasedInfoBarMessage = value,
			() => CertificatesBasedInfoBarSeverity, value => CertificatesBasedInfoBarSeverity = value,
			() => CertificatesBasedInfoBarIsClosable, value => CertificatesBasedInfoBarIsClosable = value,
			Dispatcher,
			() => CertificatesBasedInfoBarTitle, value => CertificatesBasedInfoBarTitle = value);

		// InfoBar manager for the ISGInfoBar section
		ISGInfoBar = new InfoBarSettings(
			() => ISGInfoBarIsOpen, value => ISGInfoBarIsOpen = value,
			() => ISGInfoBarMessage, value => ISGInfoBarMessage = value,
			() => ISGInfoBarSeverity, value => ISGInfoBarSeverity = value,
			() => ISGInfoBarIsClosable, value => ISGInfoBarIsClosable = value,
			Dispatcher,
			() => ISGInfoBarTitle, value => ISGInfoBarTitle = value);

		// InfoBar manager for the StrictKernelMode section
		StrictKernelModeInfoBar = new InfoBarSettings(
			() => StrictKernelModeInfoBarIsOpen, value => StrictKernelModeInfoBarIsOpen = value,
			() => StrictKernelModeInfoBarMessage, value => StrictKernelModeInfoBarMessage = value,
			() => StrictKernelModeInfoBarSeverity, value => StrictKernelModeInfoBarSeverity = value,
			() => StrictKernelModeInfoBarIsClosable, value => StrictKernelModeInfoBarIsClosable = value,
			Dispatcher,
			() => StrictKernelModeInfoBarTitle, value => StrictKernelModeInfoBarTitle = value);

		// InfoBar manager for the PFN section
		PFNInfoBar = new InfoBarSettings(
			() => PFNInfoBarIsOpen, value => PFNInfoBarIsOpen = value,
			() => PFNInfoBarMessage, value => PFNInfoBarMessage = value,
			() => PFNInfoBarSeverity, value => PFNInfoBarSeverity = value,
			() => PFNInfoBarIsClosable, value => PFNInfoBarIsClosable = value,
			Dispatcher,
			() => PFNInfoBarTitle, value => PFNInfoBarTitle = value);

		PFNBasedCancellableButton = new(GlobalVars.GetStr("CreateSupplementalPolicyButton/Content"));

		// InfoBar manager for the CustomFilePathRules section
		CustomFilePathRulesInfoBar = new InfoBarSettings(
			() => CustomFilePathRulesInfoBarIsOpen, value => CustomFilePathRulesInfoBarIsOpen = value,
			() => CustomFilePathRulesInfoBarMessage, value => CustomFilePathRulesInfoBarMessage = value,
			() => CustomFilePathRulesInfoBarSeverity, value => CustomFilePathRulesInfoBarSeverity = value,
			() => CustomFilePathRulesInfoBarIsClosable, value => CustomFilePathRulesInfoBarIsClosable = value,
			Dispatcher,
			() => CustomFilePathRulesInfoBarTitle, value => CustomFilePathRulesInfoBarTitle = value);

		PatternBasedFileRuleCancellableButton = new(GlobalVars.GetStr("CreateSupplementalPolicyButton/Content"));

		// To adjust the initial width of the columns, giving them nice paddings.
		CalculateColumnWidthsStrictKernelMode();
	}

	internal Visibility FilesAndFoldersBasePolicyLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility CertificatesBasePolicyPathLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility ISGBasePolicyPathLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility StrictKernelModeBasePolicyLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility PFNBasePolicyPathLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility CustomPatternBasedFileRuleBasePolicyPathLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	#region Files and Folders scan

	// LVController for the FilesAndFolders Section.
	internal readonly ListViewIncrementalController LVController;

	// A Progress<double> so Report() callbacks run on the UI thread
	internal IProgress<double> FilesAndFoldersProgressRingValueProgress;
	internal double FilesAndFoldersProgressRingValue { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the Settings Expander for the Files and Folders section is expanded.
	/// </summary>
	internal bool FilesAndFoldersSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	/// <summary>
	/// Selected File Paths
	/// </summary>
	internal readonly UniqueStringObservableCollection filesAndFoldersFilePaths = [];

	/// <summary>
	/// Selected Folder Paths
	/// </summary>
	internal readonly UniqueStringObservableCollection filesAndFoldersFolderPaths = [];

	#region LISTVIEW IMPLEMENTATIONS Files And Folders

	// Properties to hold each columns' width.
	internal GridLength ColumnWidthFilesAndFolders1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders6 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders7 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders8 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders9 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders10 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders11 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders12 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders13 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders14 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders15 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders16 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders17 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders18 { get; set => SP(ref field, value); }

	#endregion

	/// <summary>
	/// Selected Base policy path
	/// </summary>
	internal string? FilesAndFoldersBasePolicyPath { get; set => SP(ref field, value); }

	/// <summary>
	/// Selected Supplemental policy name
	/// </summary>
	internal string? FilesAndFoldersSupplementalPolicyName { get; set => SPT(ref field, value); }

	/// <summary>
	/// Whether the UI elements for Files and Folders section are enabled or disabled.
	/// </summary>
	internal bool FilesAndFoldersElementsAreEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the policy should be deployed.
	/// </summary>
	internal bool FilesAndFoldersDeployButton { get; set => SP(ref field, value); }

	internal Visibility FilesAndFoldersBrowseForFilesSettingsCardVisibility { get; set => SP(ref field, value); } = Visibility.Visible;

	internal bool FilesAndFoldersInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool FilesAndFoldersInfoBarIsClosable { get; set => SP(ref field, value); }
	internal string? FilesAndFoldersInfoBarMessage { get; set => SP(ref field, value); }
	internal string? FilesAndFoldersInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity FilesAndFoldersInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	private readonly InfoBarSettings FilesAndFoldersInfoBar;

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

	internal Visibility FilesAndFoldersInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Initialization details for the main Create button for the Files and Folders section
	/// </summary>
	internal readonly AnimatedCancellableButtonInitializer FilesAndFoldersCancellableButton;

	/// <summary>
	/// Path to the Files and Folders Supplemental policy XML file.
	/// </summary>
	internal string? _FilesAndFoldersSupplementalPolicyPath;


	/// <summary>
	/// Button to clear the list of selected file paths
	/// </summary>
	internal void FilesAndFoldersBrowseForFilesButton_Flyout_Clear_Click() => filesAndFoldersFilePaths.Clear();

	/// <summary>
	/// Button to clear the list of selected folder paths
	/// </summary>
	internal void FilesAndFoldersBrowseForFoldersButton_Flyout_Clear_Click() => filesAndFoldersFolderPaths.Clear();

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

	/// <summary>
	/// Browse for Base Policy - Button Click
	/// </summary>
	internal void FilesAndFoldersBrowseForBasePolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			FilesAndFoldersBasePolicyPath = selectedFile;
		}
	}

	/// <summary>
	/// Link to the page that shows scanned file details
	/// </summary>
	internal void FilesAndFoldersViewFileDetailsSettingsCard_Click()
	{
		ViewModelProvider.NavigationService.Navigate(typeof(CreateSupplementalPolicyFilesAndFoldersScanResults), null);
	}

	/// <summary>
	/// Event handler for the clear button for the text box of selected Base policy path
	/// </summary>
	internal void FilesAndFoldersBrowseForBasePolicyButton_Flyout_Clear_Click() => FilesAndFoldersBasePolicyPath = null;

	/// <summary>
	/// Opens a policy editor for files and folders using a specified supplemental policy path.
	/// </summary>
	internal async void OpenInPolicyEditor_FilesAndFolders() => await PolicyEditorViewModel.OpenInPolicyEditor(_FilesAndFoldersSupplementalPolicyPath);

	internal async void OpenInDefaultFileHandler_FilesAndFolders() => await OpenInDefaultFileHandler(_FilesAndFoldersSupplementalPolicyPath);

	/// <summary>
	/// Main button's event handler for files and folders Supplemental policy creation
	/// </summary>
	internal async void CreateFilesAndFoldersSupplementalPolicyButton_Click()
	{
		_FilesAndFoldersSupplementalPolicyPath = null;

		FilesAndFoldersInfoBarActionButtonVisibility = Visibility.Collapsed;

		FilesAndFoldersSettingsExpanderIsExpanded = true;

		// Reset the progress ring from previous runs or in case an error occurred
		FilesAndFoldersProgressRingValue = 0;

		if (filesAndFoldersFilePaths.Count is 0 && filesAndFoldersFolderPaths.Count is 0)
		{
			FilesAndFoldersInfoBar.WriteWarning(GlobalVars.GetStr("NoFilesOrFoldersSelected"), GlobalVars.GetStr("SelectFilesOrFoldersTitle"));
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
		else if (FilesAndFoldersBasePolicyPath is null)
		{
			FilesAndFoldersInfoBar.WriteWarning(GlobalVars.GetStr("SelectBasePolicySubtitle"), GlobalVars.GetStr("SelectBasePolicyTitle"));
			return;
		}

		// Only check for policy name if user hasn't provided a policy to add the rules to
		if (OperationModeComboBoxSelectedIndex is 0 && string.IsNullOrWhiteSpace(FilesAndFoldersSupplementalPolicyName))
		{
			FilesAndFoldersInfoBar.WriteWarning(GlobalVars.GetStr("ChoosePolicyNameSubtitle"), GlobalVars.GetStr("ChoosePolicyNameTitle"));
			return;
		}

		// All validation passed - NOW we set button state to indicate operation starting

		bool errorsOccurred = false;

		FilesAndFoldersCancellableButton.Begin();

		try
		{
			FilesAndFoldersElementsAreEnabled = false;

			FilesAndFoldersInfoBar.WriteInfo(string.Format(
				GlobalVars.GetStr("FindingAllAppControlFilesMessage"),
				filesAndFoldersFilePaths.Count,
				filesAndFoldersFolderPaths.Count
			));

			FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

			await Task.Run(async () =>
			{
				IEnumerable<FileIdentity> LocalFilesResults = [];

				// Do the following steps only if Wildcard paths aren't going to be used because then only the selected folder paths are needed
				if (FilesAndFoldersScanLevelComboBoxSelectedItem.Level is not ScanLevels.WildCardFolderPath)
				{

					// Collect all of the AppControl compatible files from user selected directories and files
					(IEnumerable<string>, int) DetectedFilesInSelectedDirectories = FileUtility.GetFilesFast(filesAndFoldersFolderPaths, filesAndFoldersFilePaths, null, FilesAndFoldersCancellableButton.Cts?.Token);

					// Make sure there are AppControl compatible files
					if (DetectedFilesInSelectedDirectories.Item2 is 0)
					{
						FilesAndFoldersInfoBar.WriteInfo(
							GlobalVars.GetStr("NoCompatibleFilesDetectedSubtitle"),
							GlobalVars.GetStr("NoCompatibleFilesTitle"));

						errorsOccurred = true;
						return;
					}

					FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					FilesAndFoldersInfoBar.WriteInfo(string.Format(
					GlobalVars.GetStr("ScanningTotalAppControlFilesMessage"),
					DetectedFilesInSelectedDirectories.Item2));

					// Scan all of the detected files from the user selected directories
					LocalFilesResults = LocalFilesScan.Scan(
						DetectedFilesInSelectedDirectories,
						(ushort)FilesAndFoldersScalabilityRadialGaugeValue,
						FilesAndFoldersProgressRingValueProgress,
						FilesAndFoldersCancellableButton.Cts?.Token);

					// Clear variables responsible for the ListView
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

					_ = Dispatcher.TryEnqueue(() =>
					{
						FilesAndFoldersInfoBar.WriteInfo(GlobalVars.GetStr("ScanCompletedCreatingSupplementalPolicyMessage"));
					});

				}

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("FilesAndFoldersSupplementalPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. LocalFilesResults], level: FilesAndFoldersScanLevelComboBoxSelectedItem.Level, folderPaths: filesAndFoldersFolderPaths.UniqueItems);

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Allow);

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				string OutputPath = OperationModeComboBoxSelectedIndex is 1 ? PolicyFileToMergeWith! : Path.Combine(GlobalVars.UserConfigDir, $"{FilesAndFoldersSupplementalPolicyName}.xml");

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				if (OperationModeComboBoxSelectedIndex is 1)
				{
					// Merge the new supplemental policy with the user selected policy - user selected policy is the main one in the merge operation
					Merger.Merge(OutputPath, [EmptyPolicyPath]);
				}
				else
				{
					// Instantiate the user selected Base policy
					SiPolicy.SiPolicy policyObj = Management.Initialize(FilesAndFoldersBasePolicyPath, null);

					// Set the BasePolicyID of our new policy to the one from user selected policy
					_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, FilesAndFoldersSupplementalPolicyName, policyObj.BasePolicyID, null);

					FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					// Configure policy rule options
					if (FilesAndFoldersScanLevelComboBoxSelectedItem.Level is ScanLevels.FilePath || FilesAndFoldersScanLevelComboBoxSelectedItem.Level is ScanLevels.WildCardFolderPath)
					{
						Logger.Write(string.Format(
							GlobalVars.GetStr("SelectedScanLevelMessage"),
							FilesAndFoldersScanLevelComboBoxSelectedItem.FriendlyName
						));

						CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental, rulesToAdd: [OptionType.DisabledRuntimeFilePathRuleProtection]);
					}
					else
					{
						CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);
					}

					FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					// Set policy version
					SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

					// Copying the policy file to the User Config directory - outside of the temporary staging area
					File.Copy(EmptyPolicyPath, OutputPath, true);

				}

				// Assign the supplemental policy file path to the local variable
				_FilesAndFoldersSupplementalPolicyPath = OutputPath;

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Use the name of the user selected file for CIP file name, otherwise use the name of the supplemental policy provided by the user
				string CIPName = OperationModeComboBoxSelectedIndex is 1 ? $"{Path.GetFileNameWithoutExtension(PolicyFileToMergeWith!)}.cip" : $"{FilesAndFoldersSupplementalPolicyName}.cip";
				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// If user selected to deploy the policy
				if (FilesAndFoldersDeployButton)
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
				FilesAndFoldersInfoBar.WriteSuccess(string.Format(
					GlobalVars.GetStr("SuccessfullyCreatedSupplementalPolicyMessage"),
					FilesAndFoldersSupplementalPolicyName
				));
				FilesAndFoldersInfoBarActionButtonVisibility = Visibility.Visible;
			}

			FilesAndFoldersCancellableButton.End();

			FilesAndFoldersInfoBarIsClosable = true;

			FilesAndFoldersElementsAreEnabled = true;
		}
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

	internal void _OpenInFileExplorerFilesAndFolders() => OpenInFileExplorer(ListViewHelper.ListViewsRegistry.SupplementalPolicy_FilesAndFolders_ScanResults);
	internal void _OpenInFileExplorerShortCutFilesAndFolders(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		_OpenInFileExplorerFilesAndFolders();
		args.Handled = true;
	}

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

	internal void FileAndFoldersHeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		string key = (string)((Button)sender).Tag;
		LVController.SortByHeader(key, FilesAndFoldersScanResultsSearchTextBox);
	}

	#endregion

	#region Certificates scan

	internal Visibility CertificatesInfoBarActionButtonVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal bool CertificatesBasedInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool CertificatesBasedInfoBarIsClosable { get; set => SP(ref field, value); }
	internal string? CertificatesBasedInfoBarMessage { get; set => SP(ref field, value); }
	internal string? CertificatesBasedInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity CertificatesBasedInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	private readonly InfoBarSettings CertificatesBasedInfoBar;

	/// <summary>
	/// Whether the Settings Expander for the Certificates Based section is expanded.
	/// </summary>
	internal bool CertificatesBasedSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	/// <summary>
	/// Path to the Certificates Supplemental policy XML file
	/// </summary>
	internal string? _CertificatesSupplementalPolicyPath;

	/// <summary>
	/// Selected Certificate File Paths
	/// </summary>
	internal readonly HashSet<string> CertificatesBasedCertFilePaths = [];

	/// <summary>
	/// Selected Base policy path
	/// </summary>
	internal string? CertificatesBasedBasePolicyPath { get; set => SP(ref field, value); }

	/// <summary>
	/// Selected Supplemental policy name,
	/// </summary>
	internal string? CertificatesBasedSupplementalPolicyName { get; set => SPT(ref field, value); }

	/// <summary>
	/// Whether the policy should be deployed or not.
	/// </summary>
	internal bool CertificatesBasedDeployButton { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the UI elements for Certificates Based section are enabled or disabled.
	/// </summary>
	internal bool CertificatesBasedElementsAreEnabled { get; set => SP(ref field, value); } = true;

	// Signing Scenario
	// True = User Mode
	// False = Kernel Mode
	internal bool signingScenario = true;

	internal bool CertificatesBasedUserModeOption
	{
		get; set
		{
			if (SP(ref field, value))
			{
				signingScenario = field;
			}
		}
	} = true;

	internal bool CertificatesBasedKernelModeOption
	{
		get; set
		{
			if (SP(ref field, value))
			{
				signingScenario = !field;
			}
		}
	}

	internal void CertificatesBrowseForCertsButton_Click()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.CertificatePickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string file in selectedFiles)
			{
				_ = CertificatesBasedCertFilePaths.Add(file);
			}
		}
	}

	internal void CertificatesBrowseForBasePolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			CertificatesBasedBasePolicyPath = selectedFile;
		}
	}

	/// <summary>
	/// Main Button - Creates the Certificates-based Supplemental policy
	/// </summary>
	internal async void CreateCertificatesSupplementalPolicyButton_Click()
	{
		bool errorsOccurred = false;

		CertificatesBasedSettingsExpanderIsExpanded = true;

		CertificatesInfoBarActionButtonVisibility = Visibility.Collapsed;

		if (CertificatesBasedCertFilePaths.Count is 0)
		{
			CertificatesBasedInfoBar.WriteWarning(GlobalVars.GetStr("SelectCertificatesSubtitle"),
				GlobalVars.GetStr("SelectCertificatesTitle"));
			return;
		}

		// use the policy to merge with file if that option is enabled by the user
		if (OperationModeComboBoxSelectedIndex is 1)
		{
			if (PolicyFileToMergeWith is null)
			{
				CertificatesBasedInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyToAddRulesToSubtitle"),
				GlobalVars.GetStr("SelectPolicyToAddRulesToTitle"));
				return;
			}
		}
		else if (CertificatesBasedBasePolicyPath is null)
		{
			CertificatesBasedInfoBar.WriteWarning(GlobalVars.GetStr("SelectBasePolicySubtitle"),
				GlobalVars.GetStr("SelectBasePolicyTitle"));
			return;
		}

		// Only check for policy name if user hasn't provided a policy to add the rules to
		if (OperationModeComboBoxSelectedIndex is 0 && string.IsNullOrWhiteSpace(CertificatesBasedSupplementalPolicyName))
		{
			CertificatesBasedInfoBar.WriteWarning(GlobalVars.GetStr("ChoosePolicyNameSubtitle"),
				GlobalVars.GetStr("ChoosePolicyNameTitle"));
			return;
		}

		_CertificatesSupplementalPolicyPath = null;

		try
		{
			CertificatesBasedElementsAreEnabled = false;

			CertificatesBasedInfoBar.WriteInfo(string.Format(
				GlobalVars.GetStr("CreatingCertificatesPolicyMessage"),
				CertificatesBasedCertFilePaths.Count
			));

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
						CryptoAPI.GetNameString(CertObject.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false),
						signingScenario ? SiPolicyIntel.SSType.UserMode : SiPolicyIntel.SSType.KernelMode // By default it's set to User-Mode in XAML/UI
					));
				}

				if (certificateResults.Count > 0)
				{
					// Generating signer rules
					NewCertificateSignerRules.CreateAllow(EmptyPolicyPath, certificateResults);
				}
				else
				{
					CertificatesBasedInfoBar.WriteWarning(GlobalVars.GetStr("NoCertificateDetailsFoundCreatingPolicy"));
					errorsOccurred = true;
					return;
				}

				Merger.Merge(EmptyPolicyPath, [EmptyPolicyPath]);

				string OutputPath = OperationModeComboBoxSelectedIndex is 1
					? PolicyFileToMergeWith!
					: Path.Combine(GlobalVars.UserConfigDir, $"{CertificatesBasedSupplementalPolicyName}.xml");

				if (OperationModeComboBoxSelectedIndex is 1)
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
				string CIPName = OperationModeComboBoxSelectedIndex is 1
					? $"{Path.GetFileNameWithoutExtension(PolicyFileToMergeWith!)}.cip"
					: $"{CertificatesBasedSupplementalPolicyName}.cip";
				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// If user selected to deploy the policy
				if (CertificatesBasedDeployButton)
				{
					_ = Dispatcher.TryEnqueue(() =>
					{
						CertificatesBasedInfoBar.WriteInfo(GlobalVars.GetStr("DeployingThePolicy"));
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
			CertificatesBasedInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorOccurredCreatingPolicy"));
			errorsOccurred = true;
		}
		finally
		{
			if (!errorsOccurred)
			{
				CertificatesBasedInfoBar.WriteSuccess(string.Format(
					GlobalVars.GetStr("SuccessfullyCreatedCertificatePolicyMessage"),
					CertificatesBasedSupplementalPolicyName
				));

				CertificatesInfoBarActionButtonVisibility = Visibility.Visible;
			}

			CertificatesBasedElementsAreEnabled = true;

			CertificatesBasedInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for the clear button for the text box of selected Base policy path
	/// </summary>
	internal void CertificatesBrowseForBasePolicyButton_Flyout_Clear_Click()
	{
		CertificatesBasedBasePolicyPath = null;
	}

	/// <summary>
	/// Opens a policy editor for Certificates using a specified supplemental policy path.
	/// </summary>
	internal async void OpenInPolicyEditor_Certificates() => await PolicyEditorViewModel.OpenInPolicyEditor(_CertificatesSupplementalPolicyPath);

	internal async void OpenInDefaultFileHandler_Certificates() => await OpenInDefaultFileHandler(_CertificatesSupplementalPolicyPath);

	#endregion

	#region ISG

	/// <summary>
	/// Whether the UI elements for the ISG section are enabled or disabled.
	/// </summary>
	internal bool ISGElementsAreEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the Settings Expander for the ISG section is expanded.
	/// </summary>
	internal bool ISGSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	internal Visibility ISGInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool ISGInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool ISGInfoBarIsClosable { get; set => SP(ref field, value); }
	internal string? ISGInfoBarMessage { get; set => SP(ref field, value); }
	internal string? ISGInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity ISGInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	private readonly InfoBarSettings ISGInfoBar;

	/// <summary>
	/// Path to the base policy for the ISG based supplemental policy
	/// </summary>
	internal string? ISGBasedBasePolicyPath { get; set => SP(ref field, value); }

	internal bool ISGBasedDeployButton { get; set => SP(ref field, value); }

	/// <summary>
	/// Selected Supplemental policy name
	/// </summary>
	internal string? ISGBasedSupplementalPolicyName { get; set => SPT(ref field, value); }

	/// <summary>
	/// Path to the ISG Supplemental policy XML file
	/// </summary>
	private string? _ISGSupplementalPolicyPath;

	/// <summary>
	/// Event handler for the main button - to create Supplemental ISG based policy
	/// </summary>
	internal async void CreateISGSupplementalPolicyButton_Click()
	{

		ISGInfoBarActionButtonVisibility = Visibility.Collapsed;

		ISGSettingsExpanderIsExpanded = true;

		bool errorsOccurred = false;

		// use the policy to merge with file if that option is enabled by the user
		if (OperationModeComboBoxSelectedIndex is 1)
		{
			if (PolicyFileToMergeWith is null)
			{
				ISGInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyToAddRulesToSubtitle"),
					GlobalVars.GetStr("SelectPolicyToAddRulesToTitle"));
				return;
			}
		}
		else if (ISGBasedBasePolicyPath is null)
		{
			ISGInfoBar.WriteWarning(GlobalVars.GetStr("SelectBasePolicySubtitle"),
				GlobalVars.GetStr("SelectBasePolicyTitle"));
			return;
		}

		_ISGSupplementalPolicyPath = null;

		try
		{
			ISGElementsAreEnabled = false;

			ISGInfoBar.WriteInfo(GlobalVars.GetStr("CreatingISGBasedSupplementalPolicyMessage"));

			await Task.Run(() =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("ISGBasedSupplementalPolicy");

				// Defining the paths
				string savePathTemp = Path.Combine(stagingArea.FullName, "ISGBasedSupplementalPolicy.xml");
				string OutputPath = OperationModeComboBoxSelectedIndex is 1 ? PolicyFileToMergeWith! : Path.Combine(GlobalVars.UserConfigDir, "ISGBasedSupplementalPolicy.xml");

				if (OperationModeComboBoxSelectedIndex is 1)
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

					PolicySettingsManager.SetPolicyName(supplementalPolicyObj, ISGBasedSupplementalPolicyName);

					// Replace the BasePolicyID in the Supplemental policy
					supplementalPolicyObj.BasePolicyID = basePolicyObj.BasePolicyID;

					// Save the policy object to XML file in the staging Area
					Management.SavePolicyToFile(supplementalPolicyObj, savePathTemp);

					// Copying the policy file to the User Config directory - outside of the temporary staging area
					File.Copy(savePathTemp, OutputPath, true);

				}

				_ISGSupplementalPolicyPath = OutputPath;

				// Use the name of the user selected file for CIP file name, otherwise use the name of the supplemental policy provided by the user
				string CIPName = OperationModeComboBoxSelectedIndex is 1 ? $"{Path.GetFileNameWithoutExtension(PolicyFileToMergeWith!)}.cip" : "ISGBasedSupplementalPolicy.cip";
				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// If the policy is to be deployed
				if (ISGBasedDeployButton)
				{
					ISGInfoBar.WriteInfo(GlobalVars.GetStr("DeployingThePolicy"));

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
			ISGInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorOccurredCreatingPolicy"));
			errorsOccurred = true;
		}
		finally
		{
			if (!errorsOccurred)
			{
				ISGInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyCreatedISGBasedSupplementalPolicyMessage"));

				ISGInfoBarActionButtonVisibility = Visibility.Visible;
			}

			ISGElementsAreEnabled = true;

			ISGInfoBarIsClosable = true;
		}
	}

	internal void ISGBrowseForBasePolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			ISGBasedBasePolicyPath = selectedFile;
		}
	}

	internal void ISGBrowseForBasePolicyButton_Flyout_Clear_Click()
	{
		ISGBasedBasePolicyPath = null;
	}

	/// <summary>
	/// Opens a policy editor for ISG using a specified supplemental policy path.
	/// </summary>
	internal async void OpenInPolicyEditor_ISG() => await PolicyEditorViewModel.OpenInPolicyEditor(_ISGSupplementalPolicyPath);

	internal async void OpenInDefaultFileHandler_ISG() => await OpenInDefaultFileHandler(_ISGSupplementalPolicyPath);

	#endregion

	#region Strict Kernel-Mode Supplemental Policy

	// A Progress<double> so Report() callbacks run on the UI thread
	internal IProgress<double> DriverAutoDetectionProgressRingValueProgress;
	internal double DriverAutoDetectionProgressRingValue { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the UI elements for Strict Kernel Mode section are enabled or disabled.
	/// </summary>
	internal bool StrictKernelModeElementsAreEnabled { get; set => SP(ref field, value); } = true;

	#region LISTVIEW IMPLEMENTATIONS Strict Kernel Mode

	// Properties to hold each columns' width.
	internal GridLength ColumnWidthStrictKernelMode1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode6 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode7 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode8 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode9 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode10 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode11 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode12 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode13 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode14 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode15 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode16 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode17 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode18 { get; set => SP(ref field, value); }

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidthsStrictKernelMode()
	{

		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("FileNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("SignatureStatusHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("OriginalFileNameHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("InternalNameHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("FileDescriptionHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.GetStr("ProductNameHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.GetStr("FileVersionHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.GetStr("PackageFamilyNameHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA256HashHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA1HashHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureText(GlobalVars.GetStr("SigningScenarioHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureText(GlobalVars.GetStr("FilePathHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA1PageHashHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA256PageHashHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureText(GlobalVars.GetStr("HasWHQLSignerHeader/Text"));
		double maxWidth16 = ListViewHelper.MeasureText(GlobalVars.GetStr("FilePublishersHeader/Text"));
		double maxWidth17 = ListViewHelper.MeasureText(GlobalVars.GetStr("IsECCSignedHeader/Text"));
		double maxWidth18 = ListViewHelper.MeasureText(GlobalVars.GetStr("OpusDataHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileIdentity item in StrictKernelModeScanResults)
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
		ColumnWidthStrictKernelMode1 = new GridLength(maxWidth1);
		ColumnWidthStrictKernelMode2 = new GridLength(maxWidth2);
		ColumnWidthStrictKernelMode3 = new GridLength(maxWidth3);
		ColumnWidthStrictKernelMode4 = new GridLength(maxWidth4);
		ColumnWidthStrictKernelMode5 = new GridLength(maxWidth5);
		ColumnWidthStrictKernelMode6 = new GridLength(maxWidth6);
		ColumnWidthStrictKernelMode7 = new GridLength(maxWidth7);
		ColumnWidthStrictKernelMode8 = new GridLength(maxWidth8);
		ColumnWidthStrictKernelMode9 = new GridLength(maxWidth9);
		ColumnWidthStrictKernelMode10 = new GridLength(maxWidth10);
		ColumnWidthStrictKernelMode11 = new GridLength(maxWidth11);
		ColumnWidthStrictKernelMode12 = new GridLength(maxWidth12);
		ColumnWidthStrictKernelMode13 = new GridLength(maxWidth13);
		ColumnWidthStrictKernelMode14 = new GridLength(maxWidth14);
		ColumnWidthStrictKernelMode15 = new GridLength(maxWidth15);
		ColumnWidthStrictKernelMode16 = new GridLength(maxWidth16);
		ColumnWidthStrictKernelMode17 = new GridLength(maxWidth17);
		ColumnWidthStrictKernelMode18 = new GridLength(maxWidth18);
	}

	#endregion

	internal ObservableCollection<FileIdentity> StrictKernelModeScanResults { get; set => SP(ref field, value); } = [];

	internal readonly List<FileIdentity> StrictKernelModeScanResultsList = [];

	internal ListViewHelper.SortState SortStateStrictKernelMode { get; set; } = new();

	internal Visibility StrictKernelModeInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool StrictKernelModeInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool StrictKernelModeInfoBarIsClosable { get; set => SP(ref field, value); }
	internal string? StrictKernelModeInfoBarMessage { get; set => SP(ref field, value); }
	internal string? StrictKernelModeInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity StrictKernelModeInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	private readonly InfoBarSettings StrictKernelModeInfoBar;

	/// <summary>
	/// Path to the base policy for the Strict kernel-mode supplemental policy
	/// </summary>
	internal string? StrictKernelModeBasePolicyPath { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the supplemental policy should be deployed at the end.
	/// </summary>
	internal bool StrictKernelModeShouldDeploy { get; set => SP(ref field, value); }

	/// <summary>
	/// The name of the supplemental policy for Strict Kernel Mode.
	/// </summary>
	internal string? StrictKernelModePolicyName { get; set => SPT(ref field, value); }

	internal bool StrictKernelModeSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	/// <summary>
	/// Path to the StrictKernelMode Supplemental policy XML file
	/// </summary>
	private string? _StrictKernelModeSupplementalPolicyPath;

	internal void StrictKernelModeScanButton_Click()
	{
		StrictKernelModePerformScans(false);
	}

	internal void DetectedKernelModeFilesDetailsSettingsCard_Click()
	{
		ViewModelProvider.NavigationService.Navigate(typeof(StrictKernelPolicyScanResults), null);
	}

	/// <summary>
	/// Browse for Base Policy - Button Click
	/// </summary>
	internal void StrictKernelModeBrowseForBasePolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			StrictKernelModeBasePolicyPath = selectedFile;
		}
	}

	/// <summary>
	/// Event handler for the clear button for the text box of selected Base policy path
	/// </summary>
	internal void StrictKernelModeBrowseForBasePolicyButton_Flyout_Clear_Click() => StrictKernelModeBasePolicyPath = null;

	internal void StrictKernelModeScanSinceLastRebootButton_Click() => StrictKernelModePerformScans(true);

	internal async void StrictKernelModePerformScans(bool OnlyAfterReboot)
	{
		bool ErrorsOccurred = false;

		StrictKernelModeInfoBarActionButtonVisibility = Visibility.Collapsed;

		try
		{
			StrictKernelModeElementsAreEnabled = false;

			StrictKernelModeInfoBarIsClosable = false;
			StrictKernelModeInfoBar.WriteInfo(GlobalVars.GetStr("ScanningSystemForEvents"));
			StrictKernelModeSettingsExpanderIsExpanded = true;

			// Clear variables responsible for the ListView
			StrictKernelModeScanResults.Clear();
			StrictKernelModeScanResultsList.Clear();

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
					Output = [.. Output.Where(fileIdentity => fileIdentity.TimeCreated >= lastRebootTime && fileIdentity.SISigningScenario is SiPolicyIntel.SSType.KernelMode && fileIdentity.SignatureStatus is SignatureStatus.IsSigned)];
				}
				else
				{
					// Signed kernel-mode files
					Output = [.. Output.Where(fileIdentity => fileIdentity.SISigningScenario is SiPolicyIntel.SSType.KernelMode && fileIdentity.SignatureStatus is SignatureStatus.IsSigned)];
				}
			});

			// If any logs were generated since audit mode policy was deployed
			if (Output.Count is 0)
			{
				StrictKernelModeInfoBar.WriteWarning(GlobalVars.GetStr("NoLogsGeneratedDuringAuditPhase"));
				ErrorsOccurred = true;
				return;
			}

			StrictKernelModeInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("GeneratedLogsDuringAuditPhase"), Output.Count));

			// Add the event logs to the List
			StrictKernelModeScanResultsList.AddRange(Output);

			// Add the event logs to the ObservableCollection
			foreach (FileIdentity item in Output)
			{
				StrictKernelModeScanResults.Add(item);
			}

			CalculateColumnWidthsStrictKernelMode();
		}
		catch (Exception ex)
		{
			ErrorsOccurred = true;
			StrictKernelModeInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorOccurredWhileScanningSystem"));
		}
		finally
		{
			StrictKernelModeElementsAreEnabled = true;

			if (!ErrorsOccurred)
			{
				StrictKernelModeInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyScannedSystemForEvents"));
			}

			StrictKernelModeInfoBarIsClosable = true;
		}
	}


	/// <summary>
	/// Event handler for the create button
	/// </summary>
	internal async void StrictKernelModeCreateButton_Click()
	{
		StrictKernelModeInfoBarActionButtonVisibility = Visibility.Collapsed;

		StrictKernelModeSettingsExpanderIsExpanded = true;

		if (StrictKernelModeScanResults.Count is 0)
		{
			StrictKernelModeInfoBar.WriteWarning(GlobalVars.GetStr("StrictKernelModeTeachingTipSubtitleNoItems"),
				GlobalVars.GetStr("StrictKernelModeTeachingTipTitle"));
			return;
		}

		// Only check for policy name if user hasn't provided a policy to add the rules to
		if (OperationModeComboBoxSelectedIndex is 0 && string.IsNullOrWhiteSpace(StrictKernelModePolicyName))
		{
			StrictKernelModeInfoBar.WriteWarning(GlobalVars.GetStr("ChoosePolicyNameSubtitle"),
				GlobalVars.GetStr("ChoosePolicyNameTitle"));
			return;
		}

		// use the policy to merge with file if that option is enabled by the user
		if (OperationModeComboBoxSelectedIndex is 1)
		{
			if (PolicyFileToMergeWith is null)
			{
				StrictKernelModeInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyToAddRulesToSubtitle"),
					GlobalVars.GetStr("SelectPolicyToAddRulesToTitle"));
				return;
			}
		}
		else if (string.IsNullOrWhiteSpace(StrictKernelModeBasePolicyPath))
		{
			StrictKernelModeInfoBar.WriteWarning(GlobalVars.GetStr("SelectBasePolicySubtitle"),
				GlobalVars.GetStr("SelectBasePolicyTitle"));
			return;
		}

		_StrictKernelModeSupplementalPolicyPath = null;

		bool ErrorsOccurred = false;

		try
		{
			StrictKernelModeElementsAreEnabled = false;

			StrictKernelModeInfoBarIsClosable = false;

			StrictKernelModeInfoBar.WriteInfo(string.Format(
				GlobalVars.GetStr("CreatingStrictKernelModePolicyMessage"),
				StrictKernelModeScanResults.Count
			));

			string policyNameChosenByUser = StrictKernelModePolicyName ?? string.Empty;

			await Task.Run(() =>
			{
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("StrictKernelModeSupplementalPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. StrictKernelModeScanResults], level: ScanLevels.WHQLFilePublisher);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Allow);

				string OutputPath = OperationModeComboBoxSelectedIndex is 1 ? PolicyFileToMergeWith! : Path.Combine(GlobalVars.UserConfigDir, $"{policyNameChosenByUser}.xml");

				if (OperationModeComboBoxSelectedIndex is 1)
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
				string CIPName = OperationModeComboBoxSelectedIndex is 1 ? $"{Path.GetFileNameWithoutExtension(PolicyFileToMergeWith!)}.cip" : Path.Combine(stagingArea.FullName, $"{policyNameChosenByUser}.cip");
				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// If user selected to deploy the policy
				if (StrictKernelModeShouldDeploy)
				{
					StrictKernelModeInfoBar.WriteInfo(GlobalVars.GetStr("DeployingThePolicy"));

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
			StrictKernelModeInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorOccurredCreatingPolicy"));
		}
		finally
		{
			if (!ErrorsOccurred)
			{
				StrictKernelModeInfoBarActionButtonVisibility = Visibility.Visible;
				StrictKernelModeInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyCreatedStrictKernelModePolicyMessage"));
			}

			StrictKernelModeElementsAreEnabled = true;
			StrictKernelModeInfoBarIsClosable = true;
		}
	}


	/// <summary>
	/// Detects the kernel-mode drivers from the system and scans them
	/// </summary>
	internal async void DriverAutoDetector()
	{
		bool ErrorsOccurred = false;

		StrictKernelModeInfoBarActionButtonVisibility = Visibility.Collapsed;

		try
		{
			StrictKernelModeElementsAreEnabled = false;

			StrictKernelModeInfoBarIsClosable = false;

			StrictKernelModeInfoBar.WriteInfo(GlobalVars.GetStr("ScanningSystemForDrivers"));

			StrictKernelModeSettingsExpanderIsExpanded = true;

			DriverAutoDetectionProgressRingValue = 0;

			List<string> kernelModeDriversList = [];

			await Task.Run(() =>
			{

				// Since there can be more than one folder due to localizations such as en-US then from each of the folders, the bootres.dll.mui file is added

				// Define the directory path
				string directoryPath = Path.Combine(GlobalVars.SystemDrive, "Windows", "Boot", "Resources");

				// Iterate through each directory in the specified path
				foreach (string directory in Directory.GetDirectories(directoryPath))
				{
					// Add the desired file path to the list
					kernelModeDriversList.Add(Path.Combine(directory, "bootres.dll.mui"));
				}

				string sys32Dir = new(Path.Combine(GlobalVars.SystemDrive, "Windows", "System32"));

				(IEnumerable<string>, int) filesOutput = FileUtility.GetFilesFast(new[] { sys32Dir }, null, [".dll", ".sys"]);

				kernelModeDriversList.AddRange(filesOutput.Item1);

			});

			if (kernelModeDriversList.Count is 0)
			{
				StrictKernelModeInfoBar.WriteWarning(GlobalVars.GetStr("NoKernelModeDriversDetected"));
				ErrorsOccurred = true;
				return;
			}

			StrictKernelModeInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("ScanningKernelModeFilesCount"), kernelModeDriversList.Count));

			IEnumerable<FileIdentity> LocalFilesResults = [];

			await Task.Run(() =>
			{
				// Scan all of the detected files from the user selected directories
				LocalFilesResults = LocalFilesScan.Scan(
					(kernelModeDriversList, kernelModeDriversList.Count),
					3,
					DriverAutoDetectionProgressRingValueProgress);

				// Only keep the signed kernel-mode files
				LocalFilesResults = LocalFilesResults.Where(fileIdentity => fileIdentity.SISigningScenario is SiPolicyIntel.SSType.KernelMode && fileIdentity.SignatureStatus is SignatureStatus.IsSigned);

				StrictKernelModeScanResultsList.Clear();

				// Add the results to the List
				StrictKernelModeScanResultsList.AddRange(LocalFilesResults);
			});

			// Add the results to the ObservableCollection
			StrictKernelModeScanResults = new(LocalFilesResults);

			CalculateColumnWidthsStrictKernelMode();
		}

		catch (Exception ex)
		{
			ErrorsOccurred = true;
			StrictKernelModeInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorOccurredScanningDrivers"));
		}
		finally
		{
			if (!ErrorsOccurred)
			{
				StrictKernelModeInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyScannedSystemForDrivers"));
			}

			StrictKernelModeElementsAreEnabled = true;

			StrictKernelModeInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Opens a policy editor for StrictKernelMode using a specified supplemental policy path.
	/// </summary>
	internal async void OpenInPolicyEditor_StrictKernelMode() => await PolicyEditorViewModel.OpenInPolicyEditor(_StrictKernelModeSupplementalPolicyPath);

	internal async void OpenInDefaultFileHandler_StrictKernelMode() => await OpenInDefaultFileHandler(_StrictKernelModeSupplementalPolicyPath);

	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	internal void StrictKernel_ListViewFlyoutMenuCopy_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.SupplementalPolicy_StrictKernelMode_ScanResults);
		if (lv is null) return;

		// Check if there are selected items in the ListView
		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText(lv.SelectedItems, ListViewHelper.FileIdentityPropertyMappings);
		}
	}

	/// <summary>
	/// Event handler for the Clear Data button
	/// </summary>
	internal void StrictKernel_ClearDataButton_Click()
	{
		StrictKernelModeScanResults.Clear();
		StrictKernelModeScanResultsList.Clear();
		CalculateColumnWidthsStrictKernelMode();
	}

	/// <summary>
	/// Selects all of the displayed rows on the ListView
	/// </summary>
	internal void StrictKernel_SelectAll_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.SupplementalPolicy_StrictKernelMode_ScanResults);
		if (lv is null) return;

		ListViewHelper.SelectAll(lv, StrictKernelModeScanResults);
	}

	/// <summary>
	/// De-selects all of the displayed rows on the ListView
	/// </summary>
	internal void StrictKernel_DeSelectAll_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.SupplementalPolicy_StrictKernelMode_ScanResults);
		if (lv is null) return;

		lv.SelectedItems.Clear(); // Deselect all rows by clearing SelectedItems
	}

	internal string? StrictKernelModeResultsSearchTextBox
	{
		get; set
		{
			if (SPT(ref field, value))
			{
				StrictKernel_ApplyFilters();
			}
		}
	}

	/// <summary>
	/// Applies the date and search filters to the data grid
	/// </summary>
	private void StrictKernel_ApplyFilters()
	{
		ListViewHelper.ApplyFilters(
		allFileIdentities: StrictKernelModeScanResultsList.AsEnumerable(),
		filteredCollection: StrictKernelModeScanResults,
		searchText: StrictKernelModeResultsSearchTextBox,
		selectedDate: null,
		regKey: ListViewHelper.ListViewsRegistry.SupplementalPolicy_StrictKernelMode_ScanResults
		);
	}

	/// <summary>
	/// Deletes the selected row from the results
	/// </summary>
	internal void StrictKernel_ListViewFlyoutMenuDelete_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.SupplementalPolicy_StrictKernelMode_ScanResults);
		if (lv is null) return;

		// Collect the selected items to delete
		List<FileIdentity> itemsToDelete = [.. lv.SelectedItems.Cast<FileIdentity>()];

		// Remove each selected item from the FileIdentities collection
		foreach (FileIdentity item in itemsToDelete)
		{
			_ = StrictKernelModeScanResults.Remove(item);
			_ = StrictKernelModeScanResultsList.Remove(item);
		}
	}

	internal void _OpenInFileExplorerStrictKernelMode() => OpenInFileExplorer(ListViewHelper.ListViewsRegistry.SupplementalPolicy_StrictKernelMode_ScanResults);
	internal void _OpenInFileExplorerShortCutStrictKernelMode(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		_OpenInFileExplorerStrictKernelMode();
		args.Handled = true;
	}

	/// <summary>
	/// Exports data to JSON.
	/// </summary>
	internal async void ExportStrictKernelModeToJsonButton_Click()
	{
		try
		{
			await FileIdentity.ExportToJson(StrictKernelModeScanResults, StrictKernelModeInfoBar);
		}
		catch (Exception ex)
		{
			StrictKernelModeInfoBar.WriteError(ex);
		}
	}

	#endregion

	#region Package Family Names

	/// <summary>
	/// Whether the UI elements for the PFN section are enabled or disabled.
	/// </summary>
	internal bool PFNElementsAreEnabled { get; set => SP(ref field, value); } = true;

	internal Visibility PFNInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool PFNInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool PFNInfoBarIsClosable { get; set => SP(ref field, value); }
	internal string? PFNInfoBarMessage { get; set => SP(ref field, value); }
	internal string? PFNInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity PFNInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	private readonly InfoBarSettings PFNInfoBar;

	/// <summary>
	/// To track whether the expandable settings section for the PFN supplemental policy has expanded so the apps list can be pre-loaded
	/// </summary>
	internal bool packagesLoadedOnExpand;

	/// <summary>
	/// Path to the base policy for the PFN based supplemental policy
	/// </summary>
	internal string? PFNBasePolicyPath { get; set => SP(ref field, value); }

	/// <summary>
	/// The name of the supplemental policy that will be created.
	/// </summary>
	internal string? PFNBasedSupplementalPolicyName { get; set => SPT(ref field, value); }

	/// <summary>
	/// Whether the Supplemental policy should be deployed at the end.
	/// </summary>
	internal bool PFNBasedShouldDeploy { get; set => SP(ref field, value); }

	/// <summary>
	/// Path to the PFN Supplemental policy XML file
	/// </summary>
	private string? _PFNSupplementalPolicyPath;

	/// <summary>
	/// Items Source of the ListView that displays the list of the installed packaged apps.
	/// </summary>
	internal ObservableCollection<GroupInfoListForPackagedAppView> PFNBasedAppsListItemsSource { get; set => SP(ref field, value); } = [];

	private List<object> PFNBasedAppsListItemsSourceSelectedItems = [];

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
			if (SPT(ref field, value))
			{
				PFNAppFilteringTextBox_TextChanged();
			}
		}
	}

	/// <summary>
	/// Whether the Settings Expander for the PFN based section is expanded or not.
	/// </summary>
	internal bool PFNBasedSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	/// <summary>
	/// Initialization details for the main Create button for the PFN-Based section
	/// </summary>
	internal readonly AnimatedCancellableButtonInitializer PFNBasedCancellableButton;

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
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.SupplementalPolicy_PFNBasedRules);
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
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.SupplementalPolicy_PFNBasedRules);
		if (lv is null) return;

		lv.SelectedItems.Clear();

		PFNBasedAppsListItemsSourceSelectedItems.Clear();
	}

	/// <summary>
	/// Event handler to display the selected apps count on the UI TextBlock
	/// </summary>
	internal void PFNPackagedAppsListView_SelectionChanged()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.SupplementalPolicy_PFNBasedRules);
		if (lv is null) return;

		int selectedCount = lv.SelectedItems.Count;
		PFNBasedSelectedItemsCount = string.Format(GlobalVars.GetStr("SelectedAppsCount"), selectedCount);

		PFNBasedAppsListItemsSourceSelectedItems = new(lv.SelectedItems);
	}

	// Used to store the original Apps collection so when we filter the results and then remove the filters,
	// We can still have access to the original collection of apps
	private ObservableCollection<GroupInfoListForPackagedAppView>? _AppsListBackingList;

	/// <summary>
	/// Event handler for when the search box of apps list changes
	/// </summary>
	private void PFNAppFilteringTextBox_TextChanged()
	{
		// Store the original collection if it hasn't been saved yet
		_AppsListBackingList ??= PFNBasedAppsListItemsSource;

		if (string.IsNullOrWhiteSpace(PFNBasedSearchKeywordForAppsList))
		{
			// If the filter is cleared, restore the original collection
			PFNBasedAppsListItemsSource = _AppsListBackingList;
			return;
		}

		// Filter the original collection
		List<GroupInfoListForPackagedAppView> filtered = _AppsListBackingList
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
				PFNBasedAppsListItemsSource = await GetAppsList.GetContactsGroupedAsync(this);
			}
			finally
			{
				PFNElementsAreEnabled = true;
				PFNBasedAppsListItemsSourceSelectedItems.Clear();
			}
			packagesLoadedOnExpand = true;
		}
	}

	internal void PFNBrowseForBasePolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			PFNBasePolicyPath = selectedFile;
		}
	}

	internal void PFNBasePolicyClearButton_Click() => PFNBasePolicyPath = null;

	/// <summary>
	/// Main button's event handler - Create Supplemental policy based on PFNs
	/// </summary>
	internal async void CreatePFNSupplementalPolicyButton_Click()
	{
		PFNInfoBarActionButtonVisibility = Visibility.Collapsed;

		PFNBasedSettingsExpanderIsExpanded = true;

		if (PFNBasedAppsListItemsSourceSelectedItems.Count is 0)
		{
			PFNInfoBar.WriteWarning(GlobalVars.GetStr("PFNBasedSupplementalPolicySubtitle"),
				GlobalVars.GetStr("PFNBasedSupplementalPolicyTitle"));
			return;
		}

		// Only check for policy name if user hasn't provided a policy to add the rules to
		if (OperationModeComboBoxSelectedIndex is 0 && string.IsNullOrWhiteSpace(PFNBasedSupplementalPolicyName))
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
				PFNInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyToAddRulesToSubtitle"),
					GlobalVars.GetStr("SelectPolicyToAddRulesToTitle"));
				return;
			}
		}
		else if (string.IsNullOrWhiteSpace(PFNBasePolicyPath))
		{
			PFNInfoBar.WriteWarning(GlobalVars.GetStr("SelectBasePolicySubtitle"),
				GlobalVars.GetStr("SelectBasePolicyTitle"));
			return;
		}

		// All validation passed - NOW we set button state to indicate operation starting
		_PFNSupplementalPolicyPath = null;

		bool errorsOccurred = false;

		PFNBasedCancellableButton.Begin();

		try
		{
			PFNElementsAreEnabled = false;

			PFNInfoBarIsClosable = false;

			PFNInfoBar.WriteInfo(GlobalVars.GetStr("CreatingPFNSupplementalPolicyMessage"));

			PFNBasedCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

			// A list to store the selected PackagedAppView items
			List<string> selectedAppsPFNs = [];

			// Loop through the selected items
			foreach (var selectedItem in PFNBasedAppsListItemsSourceSelectedItems)
			{
				if (selectedItem is PackagedAppView appView)
				{
					// Add the selected item's PFN to the list
					selectedAppsPFNs.Add(appView.PackageFamilyName);
				}
			}

			PFNBasedCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

			await Task.Run(() =>
			{
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("PFNSupplementalPolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				PFNBasedCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(level: ScanLevels.PFN, packageFamilyNames: selectedAppsPFNs);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Allow);

				PFNBasedCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				string OutputPath = OperationModeComboBoxSelectedIndex is 1 ? PolicyFileToMergeWith! : Path.Combine(GlobalVars.UserConfigDir, $"{PFNBasedSupplementalPolicyName}.xml");

				if (OperationModeComboBoxSelectedIndex is 1)
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

					PFNBasedCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					// Set policy version
					SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

					// Copying the policy file to the User Config directory - outside of the temporary staging area
					File.Copy(EmptyPolicyPath, OutputPath, true);
				}

				_PFNSupplementalPolicyPath = OutputPath;

				// Use the name of the user selected file for CIP file name, otherwise use the name of the supplemental policy provided by the user
				string CIPName = OperationModeComboBoxSelectedIndex is 1 ? $"{Path.GetFileNameWithoutExtension(PolicyFileToMergeWith!)}.cip" : Path.Combine(stagingArea.FullName, $"{PFNBasedSupplementalPolicyName}.cip");
				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

				PFNBasedCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Convert the XML file to CIP and save it in the defined path
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// If user selected to deploy the policy
				if (PFNBasedShouldDeploy)
				{
					_ = Dispatcher.TryEnqueue(() =>
					{
						PFNInfoBar.WriteInfo(GlobalVars.GetStr("DeployingThePolicy"));
					});

					PFNBasedCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

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
				PFNInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyCreatedPFNSupplementalPolicyMessage"));

				PFNInfoBarActionButtonVisibility = Visibility.Visible;
			}

			PFNBasedCancellableButton.End();

			PFNElementsAreEnabled = true;

			PFNInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Opens a policy editor for PFN using a specified supplemental policy path.
	/// </summary>
	internal async void OpenInPolicyEditor_PFN() => await PolicyEditorViewModel.OpenInPolicyEditor(_PFNSupplementalPolicyPath);

	internal async void OpenInDefaultFileHandler_PFN() => await OpenInDefaultFileHandler(_PFNSupplementalPolicyPath);

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

	internal Visibility CustomFilePathRulesInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool CustomFilePathRulesInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool CustomFilePathRulesInfoBarIsClosable { get; set => SP(ref field, value); }
	internal string? CustomFilePathRulesInfoBarMessage { get; set => SP(ref field, value); }
	internal string? CustomFilePathRulesInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity CustomFilePathRulesInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	private readonly InfoBarSettings CustomFilePathRulesInfoBar;

	/// <summary>
	/// Path to the base policy for the Custom Pattern-based File Rule supplemental policy
	/// </summary>
	internal string? CustomPatternBasedFileRuleBasedBasePolicyPath { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the supplemental policy should be deployed at the end.
	/// </summary>
	internal bool CustomPatternBasedFileRuleBasedDeployButton { get; set => SP(ref field, value); }

	/// <summary>
	/// Path to the CustomPatternBasedFileRule Supplemental policy XML file
	/// </summary>
	private string? _CustomPatternBasedFileRuleSupplementalPolicyPath { get; set => SP(ref field, value); }

	/// <summary>
	/// The custom pattern used for file rule.
	/// </summary>
	internal string? SupplementalPolicyCustomPatternBasedCustomPatternTextBox { get; set => SPT(ref field, value); }

	/// <summary>
	/// Initialization details for the main Create button for the Pattern Based FileRule section
	/// </summary>
	internal readonly AnimatedCancellableButtonInitializer PatternBasedFileRuleCancellableButton;

	/// <summary>
	/// Selected Supplemental policy name
	/// </summary>
	internal string? CustomPatternBasedFileRuleBasedSupplementalPolicyName { get; set => SPT(ref field, value); }

	internal void CustomPatternBasedFileRuleBrowseForBasePolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			CustomPatternBasedFileRuleBasedBasePolicyPath = selectedFile;
		}
	}

	internal void CustomPatternBasedFileRuleBrowseForBasePolicyButton_Flyout_Clear_Click()
	{
		CustomPatternBasedFileRuleBasedBasePolicyPath = null;
	}

	/// <summary>
	/// Event handler for the main button - to create Supplemental pattern based File path policy
	/// </summary>
	internal async void CreateCustomPatternBasedFileRuleSupplementalPolicyButton_Click()
	{

		CustomFilePathRulesSettingsExpanderIsExpanded = true;

		CustomFilePathRulesInfoBarActionButtonVisibility = Visibility.Collapsed;

		// use the policy to merge with file if that option is enabled by the user
		if (OperationModeComboBoxSelectedIndex is 1)
		{
			if (PolicyFileToMergeWith is null)
			{
				CustomFilePathRulesInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyToAddRulesToSubtitle"),
					GlobalVars.GetStr("SelectPolicyToAddRulesToTitle"));
				return;
			}
		}
		else if (CustomPatternBasedFileRuleBasedBasePolicyPath is null)
		{
			CustomFilePathRulesInfoBar.WriteWarning(GlobalVars.GetStr("SelectBasePolicySubtitle"),
				GlobalVars.GetStr("SelectBasePolicyTitle"));
			return;
		}

		if (string.IsNullOrWhiteSpace(SupplementalPolicyCustomPatternBasedCustomPatternTextBox))
		{
			CustomFilePathRulesInfoBar.WriteWarning(GlobalVars.GetStr("EnterCustomPatternSubtitle"),
				GlobalVars.GetStr("EnterCustomPatternTitle"));
			return;
		}

		// Only check for policy name if user hasn't provided a policy to add the rules to
		if (OperationModeComboBoxSelectedIndex is 0 && string.IsNullOrWhiteSpace(CustomPatternBasedFileRuleBasedSupplementalPolicyName))
		{
			CustomFilePathRulesInfoBar.WriteWarning(GlobalVars.GetStr("ChoosePolicyNameSubtitle"),
				GlobalVars.GetStr("ChoosePolicyNameTitle"));
			return;
		}

		// All validation passed - NOW we set button state to indicate operation starting
		_CustomPatternBasedFileRuleSupplementalPolicyPath = null;

		bool errorsOccurred = false;

		PatternBasedFileRuleCancellableButton.Begin();

		try
		{
			CustomFilePathRulesElementsAreEnabled = false;

			CustomFilePathRulesInfoBar.WriteInfo(GlobalVars.GetStr("CreatingPatternBasedFileRuleMessage"));

			CustomFilePathRulesInfoBarIsClosable = false;

			PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

			await Task.Run(() =>
			{
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("PatternBasedFilePathRulePolicy");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: null, level: ScanLevels.CustomFileRulePattern, folderPaths: null, customFileRulePatterns: [SupplementalPolicyCustomPatternBasedCustomPatternTextBox]);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Allow);

				PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				string OutputPath = OperationModeComboBoxSelectedIndex is 1 ? PolicyFileToMergeWith! : Path.Combine(GlobalVars.UserConfigDir, $"{CustomPatternBasedFileRuleBasedSupplementalPolicyName}.xml");

				if (OperationModeComboBoxSelectedIndex is 1)
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

					PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					// Configure policy rule options
					CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental, rulesToAdd: [OptionType.DisabledRuntimeFilePathRuleProtection]);

					// Set policy version
					SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

					// Copying the policy file to the User Config directory - outside of the temporary staging area
					File.Copy(EmptyPolicyPath, OutputPath, true);
				}

				_CustomPatternBasedFileRuleSupplementalPolicyPath = OutputPath;

				PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Use the name of the user selected file for CIP file name, otherwise use the name of the supplemental policy provided by the user
				string CIPName = OperationModeComboBoxSelectedIndex is 1 ? $"{Path.GetFileNameWithoutExtension(PolicyFileToMergeWith!)}.cip" : Path.Combine(stagingArea.FullName, $"{CustomPatternBasedFileRuleBasedSupplementalPolicyName}.cip");
				string CIPPath = Path.Combine(stagingArea.FullName, CIPName);

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
				CustomFilePathRulesInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyCreatedPatternBasedFileRuleMessage"));

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
	internal async void SupplementalPolicyCustomPatternBasedFileRuleSettingsCard_Click()
	{
		// Instantiate the Content Dialog
		CustomUIElements.CustomPatternBasedFilePath customDialog = new();

		App.CurrentlyOpenContentDialog = customDialog;

		// Show the dialog
		_ = await customDialog.ShowAsync();
	}

	/// <summary>
	/// Opens a policy editor for CustomPatternBasedFileRule using a specified supplemental policy path.
	/// </summary>
	internal async void OpenInPolicyEditor_CustomPatternBasedFileRule() => await PolicyEditorViewModel.OpenInPolicyEditor(_CustomPatternBasedFileRuleSupplementalPolicyPath);

	internal async void OpenInDefaultFileHandler_CustomPatternBasedFileRule() => await OpenInDefaultFileHandler(_CustomPatternBasedFileRuleSupplementalPolicyPath);

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
	/// The mode of operation for the Supplemental creation page.
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
	internal void ClearPolicyFileToMergeWith() => PolicyFileToMergeWith = null;

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

}
