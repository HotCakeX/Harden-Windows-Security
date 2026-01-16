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
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.ViewModels;

internal sealed partial class EventLogsPolicyCreationVM : ViewModelBase
{

	private PolicyEditorVM PolicyEditorViewModel { get; } = ViewModelProvider.PolicyEditorVM;

	internal EventLogsPolicyCreationVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// To adjust the initial width of the columns, giving them nice paddings.
		CalculateColumnWidths();
	}

	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	// To store the FileIdentities displayed on the ListView
	// Binding happens on the XAML but methods related to search update the ItemSource of the ListView from code behind otherwise there will not be an expected result
	internal readonly ObservableCollection<FileIdentity> FileIdentities = [];

	// Store all outputs for searching, used as a temporary storage for filtering
	// If ObservableCollection were used directly, any filtering or modification could remove items permanently
	// from the collection, making it difficult to reset or apply different filters without re-fetching data.
	internal readonly List<FileIdentity> AllFileIdentities = [];

	private ListViewHelper.SortState SortState { get; set; } = new();

	internal Visibility OpenInPolicyEditorInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	// Variables to hold the data supplied by the UI elements
	internal string? BasePolicyGUID { get; set => SPT(ref field, value); }
	internal PolicyFileRepresent? PolicyToAddLogsTo { get; set => SP(ref field, value); }
	internal PolicyFileRepresent? BasePolicyXMLFile { get; set => SP(ref field, value); }

	/// <summary>
	/// For Animated Sidebar related actions for policy assignments.
	/// </summary>
	internal Visibility LightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Determines whether the UI elements are enabled or disabled.
	/// </summary>
	internal bool AreElementsEnabled { get; set => SP(ref field, value); } = true;

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

	/// <summary>
	/// To store the Code Integrity EVTX file path
	/// </summary>
	internal string? CodeIntegrityEVTX { get; set => SP(ref field, value); }

	/// <summary>
	/// To store the AppLocker EVTX file path
	/// </summary>
	internal string? AppLockerEVTX { get; set => SP(ref field, value); }

	/// <summary>
	/// Path of the Supplemental policy that is created or the policy that user selected to add the logs to.
	/// </summary>
	internal SiPolicy.PolicyFileRepresent? finalSupplementalPolicyPath;

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
	internal GridLength ColumnWidth19 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth20 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth21 { get; set => SP(ref field, value); }

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidths()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("FileNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("TimeCreatedHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("SignatureStatusHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("ActionHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("OriginalFileNameHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.GetStr("InternalNameHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.GetStr("FileDescriptionHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.GetStr("ProductNameHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureText(GlobalVars.GetStr("FileVersionHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureText(GlobalVars.GetStr("PackageFamilyNameHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA256HashHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA1HashHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureText(GlobalVars.GetStr("SigningScenarioHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureText(GlobalVars.GetStr("FilePathHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA1FlatHashHeader/Text"));
		double maxWidth16 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA256FlatHashHeader/Text"));
		double maxWidth17 = ListViewHelper.MeasureText(GlobalVars.GetStr("FilePublishersHeader/Text"));
		double maxWidth18 = ListViewHelper.MeasureText(GlobalVars.GetStr("OpusDataHeader/Text"));
		double maxWidth19 = ListViewHelper.MeasureText(GlobalVars.GetStr("PolicyGUIDHeader/Text"));
		double maxWidth20 = ListViewHelper.MeasureText(GlobalVars.GetStr("PolicyNameHeader/Text"));
		double maxWidth21 = ListViewHelper.MeasureText(GlobalVars.GetStr("ComputerNameHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileIdentity item in FileIdentities)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.FileName, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.TimeCreated.ToString(), maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.SignatureStatus_String, maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.Action_String, maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.OriginalFileName, maxWidth5);
			maxWidth6 = ListViewHelper.MeasureText(item.InternalName, maxWidth6);
			maxWidth7 = ListViewHelper.MeasureText(item.FileDescription, maxWidth7);
			maxWidth8 = ListViewHelper.MeasureText(item.ProductName, maxWidth8);
			maxWidth9 = ListViewHelper.MeasureText(item.FileVersion_String, maxWidth9);
			maxWidth10 = ListViewHelper.MeasureText(item.PackageFamilyName, maxWidth10);
			maxWidth11 = ListViewHelper.MeasureText(item.SHA256Hash, maxWidth11);
			maxWidth12 = ListViewHelper.MeasureText(item.SHA1Hash, maxWidth12);
			maxWidth13 = ListViewHelper.MeasureText(item.SISigningScenario.ToString(), maxWidth13);
			maxWidth14 = ListViewHelper.MeasureText(item.FilePath, maxWidth14);
			maxWidth15 = ListViewHelper.MeasureText(item.SHA1FlatHash, maxWidth15);
			maxWidth16 = ListViewHelper.MeasureText(item.SHA256FlatHash, maxWidth16);
			maxWidth17 = ListViewHelper.MeasureText(item.FilePublishersToDisplay, maxWidth17);
			maxWidth18 = ListViewHelper.MeasureText(item.Opus, maxWidth18);
			maxWidth19 = ListViewHelper.MeasureText(item.PolicyGUID, maxWidth19);
			maxWidth20 = ListViewHelper.MeasureText(item.PolicyName, maxWidth20);
			maxWidth21 = ListViewHelper.MeasureText(item.ComputerName, maxWidth21);
		}

		// Set the column width properties.
		ColumnWidth1 = new(maxWidth1);
		ColumnWidth2 = new(maxWidth2);
		ColumnWidth3 = new(maxWidth3);
		ColumnWidth4 = new(maxWidth4);
		ColumnWidth5 = new(maxWidth5);
		ColumnWidth6 = new(maxWidth6);
		ColumnWidth7 = new(maxWidth7);
		ColumnWidth8 = new(maxWidth8);
		ColumnWidth9 = new(maxWidth9);
		ColumnWidth10 = new(maxWidth10);
		ColumnWidth11 = new(maxWidth11);
		ColumnWidth12 = new(maxWidth12);
		ColumnWidth13 = new(maxWidth13);
		ColumnWidth14 = new(maxWidth14);
		ColumnWidth15 = new(maxWidth15);
		ColumnWidth16 = new(maxWidth16);
		ColumnWidth17 = new(maxWidth17);
		ColumnWidth18 = new(maxWidth18);
		ColumnWidth19 = new(maxWidth19);
		ColumnWidth20 = new(maxWidth20);
		ColumnWidth21 = new(maxWidth21);
	}

	#endregion


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


	internal bool ScanLogsProgressRingIsActive { get; set => SP(ref field, value); }
	internal Visibility ScanLogsProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;


	internal string? PolicyNameTextBox { get; set => SPT(ref field, value); }

	internal bool DeployPolicyToggle { get; set => SP(ref field, value); }

	internal bool OnlyIncludeSelectedItemsToggleButton { get; set => SP(ref field, value); }

	/// <summary>
	/// Applies the date and search filters to the data grid
	/// </summary>
	private void ApplyFilters() => ListViewHelper.ApplyFilters(
		allFileIdentities: AllFileIdentities.AsEnumerable(),
		filteredCollection: FileIdentities,
		searchText: SearchBoxText,
		selectedDate: DatePickerDate,
		regKey: ListViewHelper.ListViewsRegistry.Event_Logs
		);

	/// <summary>
	/// Clears the selected AppLocker EVTX file paths
	/// </summary>
	internal void SelectedAppLockerEVTXFilesFlyout_Clear_Click() => AppLockerEVTX = null;

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
	/// Selects all of the displayed rows on the ListView
	/// </summary>
	internal void SelectAll_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Event_Logs);
		if (lv is null) return;

		ListViewHelper.SelectAll(lv, FileIdentities);
	}

	/// <summary>
	/// De-selects all of the displayed rows on the ListView
	/// </summary>
	internal void DeSelectAll_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Event_Logs);
		if (lv is null) return;

		lv.SelectedItems.Clear(); // Deselect all rows by clearing SelectedItems
	}

	/// <summary>
	/// Deletes the selected row from the results
	/// </summary>
	internal void ListViewFlyoutMenuDelete_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Event_Logs);
		if (lv is null) return;

		// Collect the selected items to delete
		List<FileIdentity> itemsToDelete = [.. lv.SelectedItems.Cast<FileIdentity>()];

		// Remove each selected item from the FileIdentities collection
		foreach (FileIdentity item in CollectionsMarshal.AsSpan(itemsToDelete))
		{
			_ = FileIdentities.Remove(item);
			_ = AllFileIdentities.Remove(item); // Removing it from the other list so that when user deletes data when search filtering is applied, after removing the search, the deleted data won't be restored
		}
	}

	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	internal void ListViewFlyoutMenuCopy_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Event_Logs);
		if (lv is null) return;

		// Check if there are selected items in the ListView
		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText(lv.SelectedItems, ListViewHelper.FileIdentityPropertyMappings);
		}
	}

	internal void SelectedCodeIntegrityEVTXFilesFlyout_Clear_Click() => CodeIntegrityEVTX = null;

	/// <summary>
	/// Event handler to open the supplemental policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor() => await PolicyEditorViewModel.OpenInPolicyEditor(finalSupplementalPolicyPath);

	internal async void OpenInDefaultFileHandler_Internal() => await OpenInDefaultFileHandler(finalSupplementalPolicyPath);

	/// <summary>
	/// Event handler for the select Code Integrity EVTX file path button
	/// </summary>
	internal void SelectCodeIntegrityEVTXFiles_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.EVTXPickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected evtx file path
			CodeIntegrityEVTX = selectedFile;

			// Log the selection with a localized message
			Logger.Write(string.Format(
				GlobalVars.GetStr("SelectedCodeIntegrityEvtxForScanning"),
				selectedFile
			));
		}
	}


	/// <summary>
	/// Event handler for the select AppLocker EVTX file path button
	/// </summary>
	internal void SelectAppLockerEVTXFiles_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.EVTXPickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected EVTX file path
			AppLockerEVTX = selectedFile;

			// Log the selection with a localized message
			Logger.Write(string.Format(
				GlobalVars.GetStr("SelectedAppLockerEvtxForScanning"),
				selectedFile
			));
		}
	}

	/// <summary>
	/// The button that browses for the policy that the logs will be added to.
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
	/// The button to submit a base policy GUID that will be used to set the base policy ID
	/// in the Supplemental policy file that will be created.
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
	/// Event handler for the ScanLogs click
	/// </summary>
	internal async void ScanLogs_Click()
	{
		bool error = false;

		try
		{
			AreElementsEnabled = false;

			MainInfoBar.IsClosable = false;

			ClearDataButton_Click();

			MainInfoBar.WriteInfo(GlobalVars.GetStr("ScanningEventLogsMessage"));

			// Display the progress ring on the ScanLogs button
			ScanLogsProgressRingIsActive = true;
			ScanLogsProgressRingVisibility = Visibility.Visible;

			// Grab the App Control Logs
			HashSet<FileIdentity> Output = await GetEventLogsData.GetAppControlEvents(
				CodeIntegrityEvtxFilePath: CodeIntegrityEVTX,
				AppLockerEvtxFilePath: AppLockerEVTX
			);

			// Store all of the data in the List
			AllFileIdentities.AddRange(Output);

			// Populates the Observable Collection and applies filters to ensure the UI reflects any currently selected Date or Search Text filters.
			ApplyFilters();

			CalculateColumnWidths();
		}
		catch (Exception ex)
		{
			error = true;
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorDuringLogsScanMessage"));
		}
		finally
		{
			AreElementsEnabled = true;

			// Clear the selected file paths
			CodeIntegrityEVTX = null;
			AppLockerEVTX = null;

			// Stop displaying the Progress Ring
			ScanLogsProgressRingIsActive = false;
			ScanLogsProgressRingVisibility = Visibility.Collapsed;

			if (!error)
			{
				MainInfoBar.WriteSuccess(string.Format(
					GlobalVars.GetStr("ScanCompleteLogsFoundMessage"),
					AllFileIdentities.Count
				));
			}

			MainInfoBar.IsClosable = true;
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
		bool error = false;

		try
		{
			AreElementsEnabled = false;

			// Display the progress ring on the ScanLogs button
			ScanLogsProgressRingIsActive = true;
			ScanLogsProgressRingVisibility = Visibility.Visible;

			OpenInPolicyEditorInfoBarActionButtonVisibility = Visibility.Collapsed;

			MainInfoBar.IsClosable = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("ProcessingLogsMessage"));

			if (FileIdentities.Count is 0)
			{
				throw new InvalidOperationException(
					GlobalVars.GetStr("NoLogsUseScanButtonMessage"));
			}

			if (PolicyToAddLogsTo is null && BasePolicyXMLFile is null && BasePolicyGUID is null)
			{
				throw new InvalidOperationException(
					GlobalVars.GetStr("MustSelectOptionMessage"));
			}

			// All of the File Identities that will be used to put in the policy XML file
			List<FileIdentity> SelectedLogs = [];

			ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Event_Logs);

			// Check if there are selected items in the ListView and user chose to use them only in the policy
			if (OnlyIncludeSelectedItemsToggleButton && lv?.SelectedItems.Count > 0)
			{
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
									PolicyToAddLogsTo.PolicyObj = SetCiPolicyInfo.Set(PolicyToAddLogsTo.PolicyObj, null, PolicyNameTextBox, null);
								}

								// Set the HVCI to Strict
								PolicyToAddLogsTo.PolicyObj = PolicySettingsManager.UpdateHVCIOptions(PolicyToAddLogsTo.PolicyObj);

								// Save the merged policy to the user selected file path if it was provided
								if (PolicyToAddLogsTo.FilePath is not null)
								{
									Management.SavePolicyToFile(PolicyToAddLogsTo.PolicyObj, PolicyToAddLogsTo.FilePath);
								}

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
									GlobalVars.GetStr("NoPolicySelectedToAddLogsMessage"));
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
										GlobalVars.GetStr("DefaultSupplementalPolicyNameFormatEventLogs"),
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
									GlobalVars.GetStr("NoPolicyFileSelectedToAssociateErrorMessage"));
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
										GlobalVars.GetStr("DefaultSupplementalPolicyNameFormatEventLogs"),
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
									GlobalVars.GetStr("NoBasePolicyGuidProvidedMessage"));
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
			error = true;
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorProcessingLogsMessage"));
		}
		finally
		{
			AreElementsEnabled = true;

			// Hide the progress ring
			ScanLogsProgressRingIsActive = false;
			ScanLogsProgressRingVisibility = Visibility.Collapsed;

			MainInfoBar.IsClosable = true;

			if (!error)
			{
				MainInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessProcessedLogsMessage"));

				OpenInPolicyEditorInfoBarActionButtonVisibility = Visibility.Visible;
			}
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
					regKey: ListViewHelper.ListViewsRegistry.Event_Logs,
					selectedDate: DatePickerDate);
			}
		}
	}

	/// <summary>
	/// Exports data to JSON.
	/// </summary>
	internal async void ExportToJsonButton_Click()
	{
		try
		{
			await FileIdentity.ExportToJson(FileIdentities, MainInfoBar);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}


	internal static async Task ClearAppControlEventLogs(int log)
	{
		await Task.Run(() =>
		{
			EventLogSession session = new();
			try
			{
				if (log is 0)
				{
					session.ClearLog("Microsoft-Windows-CodeIntegrity/Operational");
				}
				else if (log is 1)
				{
					session.ClearLog("Microsoft-Windows-AppLocker/MSI and Script");
				}
			}
			finally
			{
				session.Dispose();
			}
		});
	}

	internal async void ClearCodeIntegrityOSLogs()
	{
		try
		{
			AreElementsEnabled = false;

			// Create and configure the ContentDialog.
			using CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = GlobalVars.GetStr("OSCodeIntegrityLogsDeletionContentDialogTitle"),
				Content = GlobalVars.GetStr("OSLogsDeletionContentDialogMsg"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				PrimaryButtonText = GlobalVars.GetStr("OK"),
				FlowDirection = Enum.Parse<FlowDirection>(App.Settings.ApplicationGlobalFlowDirection),
				DefaultButton = ContentDialogButton.Close
			};

			// Show the dialog and wait for user response
			ContentDialogResult result = await dialog.ShowAsync();

			if (result is not ContentDialogResult.Primary)
				return;

			await ClearAppControlEventLogs(0);
			MainInfoBar.WriteSuccess(GlobalVars.GetStr("ClearOSCodeIntegrityLogsSuccessMsg"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreElementsEnabled = true;
		}
	}

	internal async void ClearAppLockerOSLogs()
	{
		try
		{
			AreElementsEnabled = false;

			// Create and configure the ContentDialog.
			using CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = GlobalVars.GetStr("OSAppLockerLogsDeletionContentDialogTitle"),
				Content = GlobalVars.GetStr("OSLogsDeletionContentDialogMsg"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				PrimaryButtonText = GlobalVars.GetStr("OK"),
				FlowDirection = Enum.Parse<FlowDirection>(App.Settings.ApplicationGlobalFlowDirection),
				DefaultButton = ContentDialogButton.Close
			};

			// Show the dialog and wait for user response
			ContentDialogResult result = await dialog.ShowAsync();

			if (result is not ContentDialogResult.Primary)
				return;

			await ClearAppControlEventLogs(1);
			MainInfoBar.WriteSuccess(GlobalVars.GetStr("ClearOSAppLockerLogsSuccessMsg"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreElementsEnabled = true;
		}
	}
}
