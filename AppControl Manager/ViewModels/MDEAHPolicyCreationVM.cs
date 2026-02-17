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
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.Pages;
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;
using CommonCore.IncrementalCollection;
using CommonCore.MicrosoftGraph;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.ViewModels;

internal sealed partial class MDEAHPolicyCreationVM : ViewModelBase, IGraphAuthHost, IDisposable
{

	private PolicyEditorVM PolicyEditorViewModel => ViewModelProvider.PolicyEditorVM;

	internal MDEAHPolicyCreationVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		AuthCompanionCLS = new(UpdateButtonsStates, new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher), AuthenticationContext.MDEAdvancedHunting);


		// Initialize the column manager with specific definitions for this page
		// We map the Key (for sorting/selection) to the Header Resource Key (for localization) and the Data Getter (for width measurement)
		ColumnManager = new ListViewColumnManager<FileIdentity>(
		[
			new("FileName", "FileNameHeader/Text", x => x.FileName),
			new("TimeCreated", "TimeCreatedHeader/Text", x => x.TimeCreated?.ToString()),
			new("SignatureStatus", "SignatureStatusHeader/Text", x => x.SignatureStatus_String),
			new("Action", "ActionHeader/Text", x => x.Action_String),
			new("OriginalFileName", "OriginalFileNameHeader/Text", x => x.OriginalFileName),
			new("InternalName", "InternalNameHeader/Text", x => x.InternalName),
			new("FileDescription", "FileDescriptionHeader/Text", x => x.FileDescription),
			new("FileVersion", "FileVersionHeader/Text", x => x.FileVersion_String),
			new("SHA256Hash", "SHA256HashHeader/Text", x => x.SHA256Hash, defaultVisibility: Visibility.Collapsed),
			new("SHA1Hash", "SHA1HashHeader/Text", x => x.SHA1Hash, defaultVisibility: Visibility.Collapsed),
			new("SHA256FlatHash", "SHA256FlatHashHeader/Text", x => x.SHA256FlatHash, defaultVisibility: Visibility.Collapsed),
			new("SHA1FlatHash", "SHA1FlatHashHeader/Text", x => x.SHA1FlatHash, defaultVisibility: Visibility.Collapsed),
			new("SISigningScenario", "SigningScenarioHeader/Text", x => x.SISigningScenario.ToString()),
			new("FilePath", "FilePathHeader/Text", x => x.FilePath),
			new("ComputerName", "ComputerNameHeader/Text", x => x.ComputerName),
			new("PolicyGUID", "PolicyGUIDHeader/Text", x => x.PolicyGUID),
			new("PolicyName", "PolicyNameHeader/Text", x => x.PolicyName),
			new("FilePublishersToDisplay", "FilePublishersHeader/Text", x => x.FilePublishersToDisplay)
		]);

		// To adjust the initial width of the columns, giving them nice paddings.
		ColumnManager.CalculateColumnWidths(FileIdentities);
	}

	#region Property Filter Implementation

	/// <summary>
	/// Currently selected property filter
	/// </summary>
	internal ListViewHelper.PropertyFilterItem? SelectedPropertyFilter { get; set => SP(ref field, value); }

	/// <summary>
	/// The value to filter by for the selected property
	/// </summary>
	internal string? PropertyFilterValue
	{
		get; set
		{
			if (SPT(ref field, value))
			{
				ApplyFilters();
			}
		}
	}

	/// <summary>
	/// Applies the property-based filter to the data
	/// </summary>
	internal void ApplyPropertyFilter() => ApplyFilters();

	/// <summary>
	/// Clears the current property filter
	/// </summary>
	internal void ClearPropertyFilter()
	{
		SelectedPropertyFilter = null;
		PropertyFilterValue = null;
		DatePickerDate = null;
		ApplyFilters();
	}

	#endregion Property Filter Implementation

	#region MICROSOFT GRAPH IMPLEMENTATION DETAILS

	private void UpdateButtonsStates(bool on)
	{
		// Enable the retrieve button if a valid value is set as Active Account
		AreElementsEnabled = on;
	}

	public AuthenticationCompanion AuthCompanionCLS { get; private set; }

	#endregion MICROSOFT GRAPH IMPLEMENTATION DETAILS

	internal readonly InfoBarSettings MainInfoBar;

	// To store the FileIdentities displayed on the ListView
	// Binding happens on the XAML but methods related to search update the ItemSource of the ListView from code behind otherwise there will not be an expected result
	internal readonly RangedObservableCollection<FileIdentity> FileIdentities = [];

	// Store all outputs for searching, used as a temporary storage for filtering
	// If ObservableCollection were used directly, any filtering or modification could remove items permanently
	// from the collection, making it difficult to reset or apply different filters without re-fetching data.
	internal readonly List<FileIdentity> AllFileIdentities = [];

	/// <summary>
	/// To store the MDE Advanced Hunting CSV log file path.
	/// </summary>
	internal readonly UniqueStringObservableCollection MDEAdvancedHuntingLogs = [];

	private ListViewHelper.SortState SortState { get; set; } = new();

	// The Column Manager Composition
	internal ListViewColumnManager<FileIdentity> ColumnManager { get; }

	// Variables to hold the data supplied by the UI elements
	internal string? BasePolicyGUID { get; set => SPT(ref field, value); }
	internal PolicyFileRepresent? PolicyToAddLogsTo { get; set => SP(ref field, value); }
	internal PolicyFileRepresent? BasePolicyXMLFile { get; set => SP(ref field, value); }

	internal Visibility OpenInPolicyEditorInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	/// <summary>
	/// For Animated Sidebar related actions for policy assignments.
	/// </summary>
	internal Visibility LightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Determines whether the UI elements are enabled or disabled.
	/// </summary>
	public bool AreElementsEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Used to set default selected item for the SelectorBar and also maintain selected item between page navigations since we turned off cache.
	/// </summary>
	internal string SelectedBarItemTag { get; set; } = "Local";

	internal ScanLevelsComboBoxType ScanLevelComboBoxSelectedItem { get; set => SP(ref field, value); } = DefaultScanLevel;

	/// <summary>
	/// Bound to the Date Picker on the UI.
	/// </summary>
	internal DateTimeOffset? DatePickerDate
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
	/// Bound to the Search text box on the UI.
	/// </summary>
	internal string? SearchBoxText
	{
		get; set
		{
			if (SPT(ref field, value))
			{
				ApplyFilters();
			}
		}
	}

	internal bool ScanLogsProgressRingIsActive { get; set => SP(ref field, value); }
	internal Visibility ScanLogsProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Path of the Supplemental policy that is created or the policy that user selected to add the logs to.
	/// </summary>
	private SiPolicy.PolicyFileRepresent? finalSupplementalPolicyPath;

	internal string? PolicyNameTextBox { get; set => SPT(ref field, value); }

	internal bool DeployPolicyToggle { get; set => SP(ref field, value); }

	internal bool OnlyIncludeSelectedItemsToggleButton { get; set => SP(ref field, value); }

	internal string CreatePolicyButtonContent { get; set => SP(ref field, value); } = GlobalVars.GetStr("CreatePolicyForSelectedBase");

	internal int SelectedCreationMethod
	{
		get; set
		{
			if (SP(ref field, value))
			{
				CreatePolicyButtonContent = field switch
				{
					0 => GlobalVars.GetStr("AddLogsToSelectedPolicyMessage"),
					1 => GlobalVars.GetStr("CreatePolicyForSelectedBase"),
					2 => GlobalVars.GetStr("CreatePolicyForBaseGUIDMessage"),
					_ => GlobalVars.GetStr("DefaultCreatePolicy")
				};
			}
		}
	}

	internal string? DeviceNameTextBox { get; set => SPT(ref field, value); }

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidths() => ColumnManager.CalculateColumnWidths(FileIdentities);

	// The list of queries property for x:Bind
	internal readonly List<MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage> AdvancedHuntingQueries = [

		new MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage
		{
			QueryTitle = "Default Query",
			Query = """
DeviceEvents
| where ActionType startswith "AppControlCodeIntegrity"
   or ActionType startswith "AppControlCIScriptBlocked"
   or ActionType startswith "AppControlCIScriptAudited"
"""
		},
		new MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage
		{
			QueryTitle = "Default Query with Device name filter",
			Query = """
DeviceEvents
| where (ActionType startswith "AppControlCodeIntegrity"
    or ActionType startswith "AppControlCIScriptBlocked"
    or ActionType startswith "AppControlCIScriptAudited")
    and DeviceName == "deviceName"
"""
		},
		new MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage
		{
			QueryTitle = "Default Query with Device name and Time filter",
			Query = """
DeviceEvents
| where Timestamp >= ago(1h)

| where (ActionType startswith "AppControlCodeIntegrity"
    or ActionType startswith "AppControlCIScriptBlocked"
    or ActionType startswith "AppControlCIScriptAudited")
    and DeviceName == "deviceName"
"""
		},

		new MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage
		{
			QueryTitle = "Default Query with Device name and Policy name filter",
			Query = """
DeviceEvents
| where (ActionType startswith "AppControlCodeIntegrity"
    or ActionType startswith "AppControlCIScriptBlocked"
    or ActionType startswith "AppControlCIScriptAudited")
    and DeviceName == "deviceName" | where parse_json(AdditionalFields)["PolicyName"] == 'NameOfThePolicy'
"""
		}

		];


	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	internal void ListViewFlyoutMenuCopy_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.MDE_AdvancedHunting);
		if (lv is null) return;

		// Check if there are selected items in the ListView
		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText(lv.SelectedItems, ListViewHelper.FileIdentityPropertyMappings);
		}
	}

	internal void BrowseForLogs_Flyout_Clear_Click() => MDEAdvancedHuntingLogs.Clear();

	/// <summary>
	/// Event handler for the select Code Integrity EVTX file path button
	/// </summary>
	internal void BrowseForLogs_Click()
	{
		const string filter = "CSV file|*.csv";

		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

		foreach (string item in CollectionsMarshal.AsSpan(selectedFiles))
		{
			// Store the selected csv file path
			MDEAdvancedHuntingLogs.Add(item);
		}
	}

	/// <summary>
	/// The button that browses for XML file the logs will be added to
	/// </summary>
	internal async void AddToPolicyButton_Click()
	{
		try
		{
			string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

			if (!string.IsNullOrEmpty(selectedFile))
			{
				SiPolicy.SiPolicy policyObj = await Task.Run(() => Management.Initialize(selectedFile, null));
				PolicyToAddLogsTo = new(policyObj) { FilePath = selectedFile };

				Logger.Write(string.Format(
				GlobalVars.GetStr("SelectedFileToAddLogsToMessage"),
				selectedFile));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// The button to browse for the XML file the supplemental policy that will be created will belong to
	/// </summary>
	internal async void BasePolicyFileButton_Click()
	{
		try
		{
			string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

			if (!string.IsNullOrEmpty(selectedFile))
			{
				SiPolicy.SiPolicy policyObj = await Task.Run(() => Management.Initialize(selectedFile, null));
				BasePolicyXMLFile = new(policyObj) { FilePath = selectedFile };

				Logger.Write(string.Format(
				GlobalVars.GetStr("SelectedBasePolicyFileMessage"),
				selectedFile));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// The button to submit a base policy GUID that will be used to set the base policy ID in the Supplemental policy file that will be created.
	/// </summary>
	/// <exception cref="ArgumentException"></exception>
	internal void BaseGUIDSubmitButton_Click()
	{
		if (!Guid.TryParse(BasePolicyGUID, out _))
		{
			throw new ArgumentException(GlobalVars.GetStr("InvalidGuidMessage"));
		}
	}

	/// <summary>
	/// Generates a random GUID to be used for <see cref="BasePolicyGUID"/>.
	/// </summary>
	internal void GenerateRandomGUIDButton_Click() => BasePolicyGUID = Guid.CreateVersion7().ToString().ToUpperInvariant();

	/// <summary>
	/// Event handler for the Clear Data button
	/// </summary>
	internal void ClearDataButton_Click()
	{
		FileIdentities.Clear();
		AllFileIdentities.Clear();
		CalculateColumnWidths();
	}

	/// <summary>
	/// Applies the date, search, and property filters to the data in the ListView.
	/// </summary>
	private void ApplyFilters() => ListViewHelper.ApplyFilters(
			allFileIdentities: AllFileIdentities.AsEnumerable(),
			filteredCollection: FileIdentities,
			searchText: SearchBoxText,
			selectedDate: DatePickerDate,
			regKey: ListViewHelper.ListViewsRegistry.MDE_AdvancedHunting,
			selectedPropertyFilter: SelectedPropertyFilter,
			propertyFilterValue: PropertyFilterValue
		);

	/// <summary>
	/// Selects all of the displayed rows on the ListView
	/// </summary>
	internal void SelectAll_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.MDE_AdvancedHunting);
		if (lv is null) return;

		ListViewHelper.SelectAll(lv, FileIdentities);
	}

	/// <summary>
	/// De-selects all of the displayed rows on the ListView
	/// </summary>
	internal void DeSelectAll_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.MDE_AdvancedHunting);
		if (lv is null) return;

		lv.SelectedItems.Clear(); // Deselect all rows by clearing SelectedItems
	}

	/// <summary>
	/// Deletes the selected row from the results
	/// </summary>
	internal void ListViewFlyoutMenuDelete_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.MDE_AdvancedHunting);
		if (lv is null) return;

		// Collect the selected items to delete
		List<FileIdentity> itemsToDelete = [.. lv.SelectedItems.Cast<FileIdentity>()];

		// Remove each selected item from the FileIdentities ObservableCollection, they won't be included in the policy
		foreach (FileIdentity item in itemsToDelete)
		{
			_ = FileIdentities.Remove(item);
			_ = AllFileIdentities.Remove(item); // Removing it from the other list so that when user deletes data when search filtering is applied, after removing the search, the deleted data won't be restored
		}
	}

	/// <summary>
	/// Event handler for the ScanLogs click
	/// </summary>
	internal async void ScanLogs_Click()
	{
		bool error = false;

		try
		{
			AreElementsEnabled = false;

			// Display the progress ring on the ScanLogs button
			ScanLogsProgressRingIsActive = true;
			ScanLogsProgressRingVisibility = Visibility.Visible;

			MainInfoBarIsClosable = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("ScanningMDEAdvancedHuntingCsvLogs"));

			// Clear the FileIdentities before getting and showing the new ones
			FileIdentities.Clear();
			AllFileIdentities.Clear();

			// To store the output of the MDE Advanced Hunting logs scan.
			// Ensures the data are unique and are time-prioritized.
			// NOTE: the GetMDEAdvancedHuntingLogsData.Retrieve method already uses a signature-based HashSet.
			FileIdentityTimeBasedHashSet Output = new();

			// Grab the App Control Logs
			await Task.Run(() =>
			{
				if (MDEAdvancedHuntingLogs.Count == 0)
				{
					throw new InvalidOperationException(
						GlobalVars.GetStr("NoMDEAdvancedHuntingLogProvided")
					);
				}

				using IDisposable taskTracker = TaskTracking.RegisterOperation();

				foreach (string file in MDEAdvancedHuntingLogs.UniqueItems)
				{
					List<MDEAdvancedHuntingData> MDEAHCSVData = OptimizeMDECSVData.ReadCsv(file);

					HashSet<FileIdentity> data = GetMDEAdvancedHuntingLogsData.Retrieve(MDEAHCSVData);

					foreach (FileIdentity item in data)
					{
						_ = Output.Add(item);
					}
				}

				if (Output.Count == 0)
				{
					throw new InvalidOperationException(GlobalVars.GetStr("NoResultsInMDEAdvancedHuntingCsvLogs"));
				}
			});

			// Store all of the data in the List
			foreach (FileIdentity item in Output.FileIdentitiesInternal)
			{
				AllFileIdentities.Add(item);
			}

			// Instead of manually adding items to the ObservableCollection, we call ApplyFilters.
			// This ensures that if there's an existing search text or date filter,
			// the new data respects it immediately.
			ApplyFilters();

			await Task.Run(CalculateColumnWidths);
		}
		catch (Exception ex)
		{
			error = true;
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorScanningMDEAdvancedHuntingCsvLogs"));
		}
		finally
		{
			AreElementsEnabled = true;

			// Stop displaying the Progress Ring
			ScanLogsProgressRingIsActive = false;
			ScanLogsProgressRingVisibility = Visibility.Collapsed;

			if (!error)
			{
				MainInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyCompletedScanningMDEAdvancedHuntingCsvLogs"));
			}

			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for the UI to clear the selected policy to add logs to.
	/// </summary>
	internal void Clear_PolicyToAddLogsTo() => PolicyToAddLogsTo = null;

	/// <summary>
	/// Event handler for the UI to clear the selected base policy.
	/// </summary>
	internal void Clear_BasePolicyXMLFile() => BasePolicyXMLFile = null;

	/// <summary>
	/// When the main button responsible for creating policy is pressed
	/// </summary>
	internal async void CreatePolicyButton_Click(SplitButton sender, SplitButtonClickEventArgs args)
	{
		bool Error = false;

		// Empty the class variable that stores the policy file path
		finalSupplementalPolicyPath = null;

		try
		{
			AreElementsEnabled = false;

			// Display the progress ring on the ScanLogs button
			ScanLogsProgressRingIsActive = true;
			ScanLogsProgressRingVisibility = Visibility.Visible;

			OpenInPolicyEditorInfoBarActionButtonVisibility = Visibility.Collapsed;

			if (FileIdentities.Count is 0)
			{
				throw new InvalidOperationException(
					GlobalVars.GetStr("NoLogsErrorMessage")
				);
			}

			if (PolicyToAddLogsTo is null && BasePolicyXMLFile is null && BasePolicyGUID is null)
			{
				throw new InvalidOperationException(
					GlobalVars.GetStr("NoPolicyCreationOptionSelectedErrorMessage")
				);
			}

			MainInfoBarIsClosable = false;

			// All of the File Identities that will be used to put in the policy XML file
			List<FileIdentity> SelectedLogs = [];

			ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.MDE_AdvancedHunting);

			// Check if there are selected items in the ListView and user chose to use them only in the policy
			if (OnlyIncludeSelectedItemsToggleButton && lv?.SelectedItems.Count > 0)
			{
				MainInfoBar.WriteInfo(string.Format(
					GlobalVars.GetStr("CreatingSupplementalPolicyForFilesMessage"),
					lv.SelectedItems.Count
				));

				// convert every selected item to FileIdentity and store it in the list
				foreach (var item in lv.SelectedItems)
				{
					if (item is FileIdentity item1)
					{
						SelectedLogs.Add(item1);
					}
				}
			}
			// If no item was selected from the ListView and user didn't choose to only use the selected items, then use everything in the ObservableCollection
			else
			{
				SelectedLogs = AllFileIdentities;

				MainInfoBar.WriteInfo(string.Format(
					GlobalVars.GetStr("CreatingSupplementalPolicyForFilesMessage"),
					AllFileIdentities.Count
				));
			}

			await Task.Run(() =>
			{
				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: SelectedLogs, level: ScanLevelComboBoxSelectedItem.Level);

				// Create a new SiPolicy object with the data package.
				SiPolicy.SiPolicy policyObj = Master.Initiate(DataPackage, SiPolicyIntel.Authorization.Allow);

				switch (SelectedCreationMethod)
				{
					case 0:
						{
							if (PolicyToAddLogsTo is not null)
							{
								// Merge the created policy with the user-selected policy which will result in adding the new rules to it
								PolicyToAddLogsTo.PolicyObj = Merger.Merge(PolicyToAddLogsTo.PolicyObj, [policyObj]);

								// Set a new name if it was provided
								if (!string.IsNullOrWhiteSpace(PolicyNameTextBox))
								{
									PolicyToAddLogsTo.PolicyObj = SetCiPolicyInfo.Set(PolicyToAddLogsTo.PolicyObj, false, PolicyNameTextBox, null);
								}

								// Set the HVCI to Strict
								PolicyToAddLogsTo.PolicyObj = PolicySettingsManager.UpdateHVCIOptions(PolicyToAddLogsTo.PolicyObj);

								// Save the merged policy to the user selected file path if it was provided
								if (PolicyToAddLogsTo.FilePath is not null)
								{
									Management.SavePolicyToFile(PolicyToAddLogsTo.PolicyObj, PolicyToAddLogsTo.FilePath);
								}

								// Add the supplemental policy path to the class variable
								finalSupplementalPolicyPath = PolicyToAddLogsTo;

								// Assign the created policy to the Sidebar
								ViewModelProvider.MainWindowVM.AssignToSidebar(finalSupplementalPolicyPath);

								MainWindow.TriggerTransferIconAnimationStatic(sender);

								// If user selected to deploy the policy
								if (DeployPolicyToggle)
								{
									CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(PolicyToAddLogsTo.PolicyObj));
								}
							}
							else
							{
								throw new InvalidOperationException(
									GlobalVars.GetStr("NoPolicySelectedToAddLogsMessage")
								);
							}

							break;
						}

					case 1:
						{
							if (BasePolicyXMLFile is not null)
							{
								// Create a policy name if it wasn't provided since we are creating a new policy and it needs one
								if (string.IsNullOrWhiteSpace(PolicyNameTextBox))
								{
									string formattedDate = DateTime.Now.ToString("MM-dd-yyyy 'at' HH-mm-ss");

									PolicyNameTextBox = string.Format(
										GlobalVars.GetStr("DefaultSupplementalPolicyNameFormatMDEAH"),
										formattedDate
									);
								}

								// Set the BasePolicyID of our new policy to the one from user selected policy
								// And set its name to the user-provided name.
								policyObj = SetCiPolicyInfo.Set(policyObj, true, PolicyNameTextBox, BasePolicyXMLFile.PolicyObj.BasePolicyID);

								// Configure policy rule options
								policyObj = CiRuleOptions.Set(policyObj: policyObj, template: CiRuleOptions.PolicyTemplate.Supplemental);

								// Set policy version
								policyObj = SetCiPolicyInfo.Set(policyObj, new Version("1.0.0.0"));

								// Add the supplemental policy path to the class variable
								finalSupplementalPolicyPath = new(policyObj);

								// Assign the created policy to the Sidebar
								ViewModelProvider.MainWindowVM.AssignToSidebar(finalSupplementalPolicyPath);

								MainWindow.TriggerTransferIconAnimationStatic(sender);

								// If user selected to deploy the policy
								if (DeployPolicyToggle)
								{
									CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(policyObj));
								}
							}
							else
							{
								throw new InvalidOperationException(
									GlobalVars.GetStr("NoPolicyFileSelectedToAssociateErrorMessage")
								);
							}

							break;
						}

					case 2:
						{
							if (BasePolicyGUID is not null)
							{
								// Create a policy name if it wasn't provided since we are creating a new policy and it needs one
								if (string.IsNullOrWhiteSpace(PolicyNameTextBox))
								{
									string formattedDate = DateTime.Now.ToString("MM-dd-yyyy 'at' HH-mm-ss");

									PolicyNameTextBox = string.Format(
										GlobalVars.GetStr("DefaultSupplementalPolicyNameFormatMDEAH"),
										formattedDate
									);
								}

								// Make sure the GUID that user entered is valid in case they didn't submit to validate it.
								BaseGUIDSubmitButton_Click();

								// Set the BasePolicyID of our new policy to the one supplied by user
								// And set its name to the user-provided name.
								policyObj = SetCiPolicyInfo.Set(policyObj, true, PolicyNameTextBox, BasePolicyGUID);

								// Configure policy rule options
								policyObj = CiRuleOptions.Set(policyObj: policyObj, template: CiRuleOptions.PolicyTemplate.Supplemental);

								// Set policy version
								policyObj = SetCiPolicyInfo.Set(policyObj, new Version("1.0.0.0"));

								// Add the supplemental policy path to the class variable
								finalSupplementalPolicyPath = new(policyObj);

								// Assign the created policy to the Sidebar
								ViewModelProvider.MainWindowVM.AssignToSidebar(finalSupplementalPolicyPath);

								MainWindow.TriggerTransferIconAnimationStatic(sender);

								// If user selected to deploy the policy
								if (DeployPolicyToggle)
								{
									CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(policyObj));
								}
							}
							else
							{
								throw new InvalidOperationException(
									GlobalVars.GetStr("NoBasePolicyGuidProvidedMessage")
								);
							}

							break;
						}

					default:
						{
							break;
						}
				}
			});
		}
		catch (Exception ex)
		{
			Error = true;
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorCreatingSupplementalPolicyMessage"));
		}
		finally
		{
			AreElementsEnabled = true;

			MainInfoBarIsClosable = true;

			// Display the progress ring on the ScanLogs button
			ScanLogsProgressRingIsActive = false;
			ScanLogsProgressRingVisibility = Visibility.Collapsed;

			if (!Error)
			{
				MainInfoBar.WriteSuccess(string.Format(
					GlobalVars.GetStr("SuccessfullyCreatedSupplementalPolicyMessage"),
					PolicyNameTextBox
				));

				OpenInPolicyEditorInfoBarActionButtonVisibility = Visibility.Visible;
			}
		}
	}


	/// <summary>
	/// Event handler to open the supplemental policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor() => await PolicyEditorViewModel.OpenInPolicyEditor(finalSupplementalPolicyPath);

	internal async void OpenInDefaultFileHandler_Internal() => await OpenInDefaultFileHandler(finalSupplementalPolicyPath);

	/// <summary>
	/// Event handler for the button that retrieves the logs
	/// </summary>
	internal async void RetrieveTheLogsButton_Click()
	{

		if (AuthCompanionCLS.CurrentActiveAccount is null)
			return;

		MainInfoBarIsClosable = false;

		MainInfoBar.WriteInfo(GlobalVars.GetStr("RetrievingMDEAdvancedHuntingDataMessage"));

		MDEAdvancedHuntingDataRootObject? root = null;

		try
		{
			AreElementsEnabled = false;

			// Retrieve the MDE Advanced Hunting data as a JSON string
			string? result = await CommonCore.MicrosoftGraph.Main.RunMDEAdvancedHuntingQuery(DeviceNameTextBox, AuthCompanionCLS.CurrentActiveAccount);

			// If there were results
			if (result is not null)
			{
				// Deserialize the JSON result
				root = await Task.Run(() => JsonSerializer.Deserialize(result, MDEAdvancedHuntingJSONSerializationContext.Default.MDEAdvancedHuntingDataRootObject));

				if (root is null)
				{
					MainInfoBar.WriteWarning(GlobalVars.GetStr("NoLogsRetrievedMessage"));
					return;
				}

				if (root.Results.Count is 0)
				{
					MainInfoBar.WriteWarning(GlobalVars.GetStr("ZeroLogsRetrievedMessage"));
					return;
				}

				MainInfoBar.WriteSuccess(string.Format(
					GlobalVars.GetStr("SuccessfullyRetrievedLogsFromCloudMessage"),
					root.Results.Count
				));

				Logger.Write(
					string.Format(
						GlobalVars.GetStr("DeserializationCompleteNumberOfRecordsMessage"),
						root.Results.Count
					)
				);

				// To store the output of the MDE Advanced Hunting logs scan.
				// Ensures the data are unique and are time-prioritized.
				// NOTE: the GetMDEAdvancedHuntingLogsData.Retrieve method already uses a signature-based HashSet.
				FileIdentityTimeBasedHashSet Output = new();

				// Grab the App Control Logs
				HashSet<FileIdentity> data = await Task.Run(() => GetMDEAdvancedHuntingLogsData.Retrieve(root.Results));

				await Task.Run(() =>
				{
					foreach (FileIdentity log in data)
					{
						_ = Output.Add(log);
					}
				});

				if (Output.Count is 0)
				{
					MainInfoBar.WriteWarning(GlobalVars.GetStr("NoActionableLogsFoundMessage"));
				}

				AllFileIdentities.Clear();
				FileIdentities.Clear();

				await Task.Run(() =>
				{
					// Store all of the data in the List
					foreach (FileIdentity log in Output.FileIdentitiesInternal)
					{
						AllFileIdentities.Add(log);
					}
				});

				// Adds data from the List to Observable collection and makes sure filters are respected
				ApplyFilters();

				await Task.Run(CalculateColumnWidths);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorRetrievingMDEAdvancedHuntingLogsMessage"));
		}
		finally
		{
			AreElementsEnabled = true;

			MainInfoBarIsClosable = true;
		}
	}


	/// <summary>
	/// CTRL + C shortcuts event handler
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	internal void CtrlC_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		ListViewFlyoutMenuCopy_Click();
		args.Handled = true;
	}

	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			if (ListViewHelper.FileIdentityPropertyMappings.TryGetValue(key, out (string Label, Func<FileIdentity, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					keySelector: mapping.Getter,
					searchBoxText: SearchBoxText,
					originalList: AllFileIdentities,
					observableCollection: FileIdentities,
					sortState: SortState,
					newKey: key,
					regKey: ListViewHelper.ListViewsRegistry.MDE_AdvancedHunting,
					propertyFilterValue: PropertyFilterValue,
					selectedDate: DatePickerDate);
			}
		}
	}


	#region For the toolbar menu's Selector Bar - The rest in the Page's class.

	internal bool IsLocalSelected => string.Equals(SelectedBarItemTag, "Local", StringComparison.OrdinalIgnoreCase);
	internal bool IsCloudSelected => string.Equals(SelectedBarItemTag, "Cloud", StringComparison.OrdinalIgnoreCase);
	internal bool IsCreateSelected => string.Equals(SelectedBarItemTag, "Create", StringComparison.OrdinalIgnoreCase);

	internal void MenuSelectorBar_SelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
	{
		SelectedBarItemTag = (string)sender.SelectedItem.Tag;
		OnPropertyChanged(nameof(IsLocalSelected));
		OnPropertyChanged(nameof(IsCloudSelected));
		OnPropertyChanged(nameof(IsCreateSelected));
	}

	#endregion


	public void Dispose()
	{
		// Dispose the AuthenticationCompanion which implements IDisposable
		AuthCompanionCLS.Dispose();
	}

	/// <summary>
	/// Event handler for the Export To JSON button
	/// </summary>
	internal async void ExportToJsonButton_Click()
	{
		try
		{
			AreElementsEnabled = false;
			MainInfoBarIsClosable = false;

			await FileIdentity.ExportToJson(FileIdentities, MainInfoBar);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreElementsEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

}
