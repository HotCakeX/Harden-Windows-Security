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
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;
using CommonCore.IncrementalCollection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.ViewModels;

internal sealed partial class EventLogsPolicyCreationVM : ViewModelBase
{
	internal EventLogsPolicyCreationVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

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
			new("ProductName", "ProductNameHeader/Text", x => x.ProductName),
			new("FileVersion", "FileVersionHeader/Text", x => x.FileVersion_String),
			new("PackageFamilyName", "PackageFamilyNameHeader/Text", x => x.PackageFamilyName),
			new("SHA256Hash", "SHA256HashHeader/Text", x => x.SHA256Hash, defaultVisibility: Visibility.Collapsed),
			new("SHA1Hash", "SHA1HashHeader/Text", x => x.SHA1Hash, defaultVisibility: Visibility.Collapsed),
			new("SISigningScenario", "SigningScenarioHeader/Text", x => x.SISigningScenario.ToString()),
			new("FilePath", "FilePathHeader/Text", x => x.FilePath),
			new("SHA1FlatHash", "SHA1FlatHashHeader/Text", x => x.SHA1FlatHash, defaultVisibility: Visibility.Collapsed),
			new("SHA256FlatHash", "SHA256FlatHashHeader/Text", x => x.SHA256FlatHash, defaultVisibility: Visibility.Collapsed),
			new("FilePublishersToDisplay", "FilePublishersHeader/Text", x => x.FilePublishersToDisplay),
			new("Opus", "OpusDataHeader/Text", x => x.Opus),
			new("PolicyGUID", "PolicyGUIDHeader/Text", x => x.PolicyGUID),
			new("PolicyName", "PolicyNameHeader/Text", x => x.PolicyName),
			new("ComputerName", "ComputerNameHeader/Text", x => x.ComputerName)
		]);

		// To adjust the initial width of the columns, giving them nice paddings.
		// Passing the current list (even if empty) initializes defaults.
		ColumnManager.CalculateColumnWidths(FileIdentities);
	}

	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	// To store the FileIdentities displayed on the ListView
	// Binding happens on the XAML but methods related to search update the ItemSource of the ListView from code behind otherwise there will not be an expected result
	internal readonly RangedObservableCollection<FileIdentity> FileIdentities = [];

	// Store all outputs for searching, used as a temporary storage for filtering
	// If ObservableCollection were used directly, any filtering or modification could remove items permanently
	// from the collection, making it difficult to reset or apply different filters without re-fetching data.
	internal readonly List<FileIdentity> AllFileIdentities = [];

	private ListViewHelper.SortState SortState { get; set; } = new();

	// The Column Manager Composition
	internal ListViewColumnManager<FileIdentity> ColumnManager { get; }

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

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidths() => ColumnManager.CalculateColumnWidths(FileIdentities);

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
	internal async void OpenInPolicyEditor() => await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(finalSupplementalPolicyPath);

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

			await Task.Run(CalculateColumnWidths);

			MainInfoBar.WriteSuccess(string.Format(
					GlobalVars.GetStr("ScanCompleteLogsFoundMessage"),
					AllFileIdentities.Count
				));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorDuringLogsScanMessage"));
		}
		finally
		{
			AreElementsEnabled = true;

			// Stop displaying the Progress Ring
			ScanLogsProgressRingIsActive = false;
			ScanLogsProgressRingVisibility = Visibility.Collapsed;

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
				foreach (object? item in lv.SelectedItems)
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

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessProcessedLogsMessage"));

			OpenInPolicyEditorInfoBarActionButtonVisibility = Visibility.Visible;
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorProcessingLogsMessage"));
		}
		finally
		{
			AreElementsEnabled = true;

			// Hide the progress ring
			ScanLogsProgressRingIsActive = false;
			ScanLogsProgressRingVisibility = Visibility.Collapsed;

			MainInfoBar.IsClosable = true;
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
				FlowDirection = Enum.Parse<FlowDirection>(GlobalVars.Settings.ApplicationGlobalFlowDirection),
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
				FlowDirection = Enum.Parse<FlowDirection>(GlobalVars.Settings.ApplicationGlobalFlowDirection),
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
