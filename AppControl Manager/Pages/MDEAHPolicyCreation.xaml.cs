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
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.MicrosoftGraph;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using AppControlManager.XMLOps;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;

namespace AppControlManager.Pages;

/// <summary>
/// MDEAHPolicyCreation is a page for managing MDE Advanced Hunting policies, including scanning logs, filtering data,
/// and creating policies.
/// </summary>
internal sealed partial class MDEAHPolicyCreation : Page, INotifyPropertyChanged
{

#pragma warning disable CA1822
	private MDEAHPolicyCreationVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<MDEAHPolicyCreationVM>();
	private PolicyEditorVM PolicyEditorViewModel { get; } = App.AppHost.Services.GetRequiredService<PolicyEditorVM>();
	private ViewModelForMSGraph ViewModelMSGraph { get; } = App.AppHost.Services.GetRequiredService<ViewModelForMSGraph>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
#pragma warning restore CA1822

	/// <summary>
	/// An event that is triggered when a property value changes, allowing subscribers to be notified of updates.
	/// </summary>
	public event PropertyChangedEventHandler? PropertyChanged;

	private void OnPropertyChanged(string? propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}


	#region ✡️✡️✡️✡️✡️✡️✡️ MICROSOFT GRAPH IMPLEMENTATION DETAILS ✡️✡️✡️✡️✡️✡️✡️

	private void UpdateButtonsStates(bool on)
	{
		// Enable the retrieve button if the a valid value is set as Active Account
		RetrieveTheLogsButton.IsEnabled = on;
	}

	internal readonly AuthenticationCompanion AuthCompanionCLS;

	#endregion ✡️✡️✡️✡️✡️✡️✡️ MICROSOFT GRAPH IMPLEMENTATION DETAILS ✡️✡️✡️✡️✡️✡️✡️	


	/// <summary>
	/// Initializes the MDEAHPolicyCreation component, sets default selections, maintains navigation state, and adds a date
	/// change event handler.
	/// </summary>
	internal MDEAHPolicyCreation()
	{
		this.InitializeComponent();

		// Default selection for the toolbar menu's selector bar
		_selectedItem = SelectorBarItemMain;

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;

		this.DataContext = this;

		AuthCompanionCLS = new(UpdateButtonsStates, new InfoBarSettings(
			() => ViewModel.MainInfoBarVisibility, value => ViewModel.MainInfoBarVisibility = value,
			() => ViewModel.MainInfoBarIsOpen, value => ViewModel.MainInfoBarIsOpen = value,
			() => ViewModel.MainInfoBarMessage, value => ViewModel.MainInfoBarMessage = value,
			() => ViewModel.MainInfoBarSeverity, value => ViewModel.MainInfoBarSeverity = value,
			() => ViewModel.MainInfoBarIsClosable, value => ViewModel.MainInfoBarIsClosable = value), AuthenticationContext.MDEAdvancedHunting);

		ViewModelMSGraph.AuthenticatedAccounts.CollectionChanged += AuthCompanionCLS.AuthenticatedAccounts_CollectionChanged;

		// Add the DateChanged event handler
		FilterByDateCalendarPicker.DateChanged += FilterByDateCalendarPicker_DateChanged;
	}


	#region For the toolbar menu's Selector Bar

	private SelectorBarItem _selectedItem;

	internal bool IsLocalSelected => _selectedItem == SelectorBarItemMain;
	internal bool IsCloudSelected => _selectedItem == SelectorBarItemCloud;
	internal bool IsCreateSelected => _selectedItem == SelectorBarItemCreate;

	private void MenuSelectorBar_SelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
	{
		_selectedItem = sender.SelectedItem;
		OnPropertyChanged(nameof(IsLocalSelected));
		OnPropertyChanged(nameof(IsCloudSelected));
		OnPropertyChanged(nameof(IsCreateSelected));
	}

	#endregion


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


	private string? MDEAdvancedHuntingLogs; // To store the MDE Advanced Hunting CSV log file path

	// Variables to hold the data supplied by the UI elements
	private Guid? BasePolicyGUID;
	private string? PolicyToAddLogsTo;
	private string? BasePolicyXMLFile;

	// The user selected scan level
	private ScanLevels scanLevel = ScanLevels.FilePublisher;


	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	/// <param name="sender">The event sender.</param>
	/// <param name="e">The event arguments.</param>
	private void ListViewFlyoutMenuCopy_Click(object sender, RoutedEventArgs e)
	{
		// Check if there are selected items in the ListView
		if (FileIdentitiesListView.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText(FileIdentitiesListView.SelectedItems);
		}
	}

	/// <summary>
	/// Click event handler for copy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void CopyToClipboard_Click(object sender, RoutedEventArgs e)
	{
		// Attempt to retrieve the property mapping using the Tag as the key.
		if (ListViewHelper.PropertyMappings.TryGetValue((string)((MenuFlyoutItem)sender).Tag, out (string Label, Func<FileIdentity, object?> Getter) mapping))
		{
			// Use the mapping's Getter, converting the result to a string.
			ListViewHelper.CopyToClipboard(item => mapping.Getter(item)?.ToString(), FileIdentitiesListView);
		}
	}


	private void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			if (ListViewHelper.PropertyMappings.TryGetValue(key, out (string Label, Func<FileIdentity, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					SearchBox.Text,
					ViewModel.AllFileIdentities,
					ViewModel.FileIdentities,
					ViewModel.SortState,
					key,
					regKey: ListViewHelper.ListViewsRegistry.MDE_AdvancedHunting);
			}
		}
	}


	/// <summary>
	/// Event handler for the CalendarDatePicker date changed event
	/// </summary>
	private void FilterByDateCalendarPicker_DateChanged(CalendarDatePicker sender, CalendarDatePickerDateChangedEventArgs args)
	{
		ApplyFilters();
	}


	/// <summary>
	/// Event handler for the SearchBox text change
	/// </summary>
	private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		ApplyFilters();
	}


	/// <summary>
	/// Applies the date and search filters to the data grid
	/// </summary>
	private void ApplyFilters()
	{
		ListViewHelper.ApplyFilters(
		   allFileIdentities: ViewModel.AllFileIdentities.AsEnumerable(),
		   filteredCollection: ViewModel.FileIdentities,
		   searchText: SearchBox.Text,
		   datePicker: FilterByDateCalendarPicker,
		   regKey: ListViewHelper.ListViewsRegistry.MDE_AdvancedHunting
	   );
		UpdateTotalLogs();
	}


	/// <summary>
	/// Event handler for the ScanLogs click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void ScanLogs_Click(object sender, RoutedEventArgs e)
	{
		bool error = false;

		try
		{
			// Disable the scan button initially
			ScanLogs.IsEnabled = false;

			// Display the progress ring on the ScanLogs button
			ScanLogsProgressRing.IsActive = true;
			ScanLogsProgressRing.Visibility = Visibility.Visible;


			ViewModel.MainInfoBarVisibility = Visibility.Visible;
			ViewModel.MainInfoBarIsOpen = true;
			ViewModel.MainInfoBarMessage = "Scanning the selected MDE Advanced Hunting CSV Logs";
			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Informational;
			ViewModel.MainInfoBarIsClosable = false;


			// Disable the Policy creator button while scan is being performed
			CreatePolicyButton.IsEnabled = false;

			// Clear the FileIdentities before getting and showing the new ones
			ViewModel.FileIdentities.Clear();
			ViewModel.AllFileIdentities.Clear();

			UpdateTotalLogs(true);

			// To store the output of the MDE Advanced Hunting logs scan
			HashSet<FileIdentity> Output = [];

			// Grab the App Control Logs
			await Task.Run(() =>
			{

				if (MDEAdvancedHuntingLogs is null)
				{
					throw new InvalidOperationException("No MDE Advanced Hunting log was provided");
				}

				List<MDEAdvancedHuntingData> MDEAHCSVData = OptimizeMDECSVData.Optimize(MDEAdvancedHuntingLogs);

				if (MDEAHCSVData.Count > 0)
				{
					Output = GetMDEAdvancedHuntingLogsData.Retrieve(MDEAHCSVData);
				}
				else
				{
					throw new InvalidOperationException("No results detected in the selected MDE Advanced Hunting CSV logs.");
				}

			});


			// Store all of the data in the List
			ViewModel.AllFileIdentities.AddRange(Output);

			// Store all of the data in the ObservableCollection
			foreach (FileIdentity item in Output)
			{
				// Add a reference to the ViewModel class instance to every item so we can use it for navigation in the XAML
				item.ParentViewModelMDEAHPolicyCreationVM = ViewModel;
				ViewModel.FileIdentities.Add(item);
			}

			UpdateTotalLogs();

			ViewModel.CalculateColumnWidths();
		}
		catch (Exception ex)
		{
			error = true;

			ViewModel.MainInfoBarVisibility = Visibility.Visible;
			ViewModel.MainInfoBarIsOpen = true;
			ViewModel.MainInfoBarMessage = $"There was an error while scanning the selected MDE Advanced Hunting CSV Logs: {ex.Message}";
			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Error;
			ViewModel.MainInfoBarIsClosable = false;

			throw;
		}
		finally
		{
			// Enable the button again
			ScanLogs.IsEnabled = true;

			// Stop displaying the Progress Ring
			ScanLogsProgressRing.IsActive = false;
			ScanLogsProgressRing.Visibility = Visibility.Collapsed;

			// Enable the Policy creator button again
			CreatePolicyButton.IsEnabled = true;

			if (!error)
			{
				ViewModel.MainInfoBarVisibility = Visibility.Visible;
				ViewModel.MainInfoBarIsOpen = true;
				ViewModel.MainInfoBarMessage = "Successfully completed scanning the selected MDE Advanced Hunting CSV Logs.";
				ViewModel.MainInfoBarSeverity = InfoBarSeverity.Success;
				ViewModel.MainInfoBarIsClosable = false;
			}
		}
	}


	/// <summary>
	/// Event handler for the select Code Integrity EVTX file path button
	/// </summary>
	private void BrowseForLogs_Click()
	{
		string filter = "CSV file|*.csv";

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(filter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected csv file path
			MDEAdvancedHuntingLogs = selectedFile;

			Logger.Write($"Selected {selectedFile} for MDE Advanced Hunting scan");

			ScanLogs.IsEnabled = true;

			BrowseForLogs_SelectedFilesTextBox.Text += selectedFile + Environment.NewLine;
		}
	}


	/// <summary>
	/// Event handler for the Clear Data button
	/// </summary>
	private void ClearDataButton_Click()
	{
		ViewModel.FileIdentities.Clear();
		ViewModel.AllFileIdentities.Clear();

		UpdateTotalLogs(true);
	}


	/// <summary>
	/// Selects all of the displayed rows on the ListView
	/// </summary>
	private void SelectAll_Click()
	{
		ListViewHelper.SelectAll(FileIdentitiesListView, ViewModel.FileIdentities);
	}


	/// <summary>
	/// De-selects all of the displayed rows on the ListView
	/// </summary>
	private void DeSelectAll_Click()
	{
		FileIdentitiesListView.SelectedItems.Clear(); // Deselect all rows by clearing SelectedItems
	}

	/// <summary>
	/// Deletes the selected row from the results
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void ListViewFlyoutMenuDelete_Click(object sender, RoutedEventArgs e)
	{
		// Collect the selected items to delete
		List<FileIdentity> itemsToDelete = [.. FileIdentitiesListView.SelectedItems.Cast<FileIdentity>()];

		// Remove each selected item from the FileIdentities ObservableCollection, they won't be included in the policy
		foreach (FileIdentity item in itemsToDelete)
		{
			_ = ViewModel.FileIdentities.Remove(item);
			_ = ViewModel.AllFileIdentities.Remove(item); // Removing it from the other list so that when user deletes data when search filtering is applied, after removing the search, the deleted data won't be restored
		}

		UpdateTotalLogs();
	}

	/// <summary>
	/// Updates the total logs count displayed on the UI
	/// </summary>
	private void UpdateTotalLogs(bool? Zero = null)
	{
		if (Zero == true)
		{
			TotalCountOfTheFilesTextBox.Text = "Total logs: 0";
		}
		else
		{
			TotalCountOfTheFilesTextBox.Text = $"Total logs: {ViewModel.FileIdentities.Count}";
		}
	}

	/// <summary>
	/// The button that browses for XML file the logs will be added to
	/// </summary>
	private void AddToPolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			PolicyToAddLogsTo = selectedFile;

			Logger.Write($"Selected {PolicyToAddLogsTo} to add the logs to.");
		}
	}

	/// <summary>
	/// The button to browse for the XML file the supplemental policy that will be created will belong to
	/// </summary>
	private void BasePolicyFileButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			BasePolicyXMLFile = selectedFile;

			Logger.Write($"Selected {BasePolicyXMLFile} to associate the Supplemental policy with.");
		}
	}

	/// <summary>
	/// The button to submit a base policy GUID that will be used to set the base policy ID in the Supplemental policy file that will be created.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	/// <exception cref="ArgumentException"></exception>
	private void BaseGUIDSubmitButton_Click(object sender, RoutedEventArgs e)
	{
		if (Guid.TryParse(BaseGUIDTextBox.Text, out Guid guid))
		{
			BasePolicyGUID = guid;
		}
		else
		{
			throw new ArgumentException("Invalid GUID");
		}
	}

	/// <summary>
	/// When the main button responsible for creating policy is pressed
	/// </summary>
	private async void CreatePolicyButton_Click()
	{

		bool Error = false;

		// Empty the class variable that stores the policy file path
		finalSupplementalPolicyPath = null;

		try
		{

			// Disable the policy creator button
			CreatePolicyButton.IsEnabled = false;

			// Disable the scan logs button
			ScanLogs.IsEnabled = false;

			// Display the progress ring on the ScanLogs button
			ScanLogsProgressRing.IsActive = true;
			ScanLogsProgressRing.Visibility = Visibility.Visible;

			ViewModel.OpenInPolicyEditorInfoBarActionButtonVisibility = Visibility.Collapsed;

			if (ViewModel.FileIdentities.Count is 0)
			{
				throw new InvalidOperationException("There are no logs. Use the scan button first or adjust the filters.");
			}

			if (PolicyToAddLogsTo is null && BasePolicyXMLFile is null && BasePolicyGUID is null)
			{
				throw new InvalidOperationException("You must select an option from the policy creation list");
			}

			ViewModel.MainInfoBarVisibility = Visibility.Visible;
			ViewModel.MainInfoBarIsOpen = true;
			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Informational;
			ViewModel.MainInfoBarIsClosable = false;

			// Create a policy name if it wasn't provided
			DateTime now = DateTime.Now;
			string formattedDate = now.ToString("MM-dd-yyyy 'at' HH-mm-ss");


			// Get the policy name from the UI text box
			string? policyName = PolicyNameTextBox.Text;

			// If the UI text box was empty or whitespace then set policy name manually
			if (string.IsNullOrWhiteSpace(policyName))
			{
				policyName = $"Supplemental policy from MDE Advanced Hunting logs - {formattedDate}";
			}

			// If user selected to deploy the policy
			// Need to retrieve it while we're still at the UI thread
			bool DeployAtTheEnd = DeployPolicyToggle.IsChecked;

			// See which section of the Segmented control is selected for policy creation
			int selectedCreationMethod = segmentedControl.SelectedIndex;

			// All of the File Identities that will be used to put in the policy XML file
			List<FileIdentity> SelectedLogs = [];

			// Check if there are selected items in the ListView and user chose to use them only in the policy
			if ((OnlyIncludeSelectedItemsToggleButton.IsChecked ?? false) && FileIdentitiesListView.SelectedItems.Count > 0)
			{

				ViewModel.MainInfoBarMessage = $"Creating Supplemental policy for {FileIdentitiesListView.SelectedItems.Count} files.";

				// convert every selected item to FileIdentity and store it in the list
				foreach (var item in FileIdentitiesListView.SelectedItems)
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
				SelectedLogs = ViewModel.AllFileIdentities;

				ViewModel.MainInfoBarMessage = $"Creating Supplemental policy for {ViewModel.AllFileIdentities.Count} files.";
			}

			await Task.Run(() =>
			{

				// Create a new Staging Area
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("PolicyCreatorMDEAH");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: SelectedLogs, level: scanLevel);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Allow);

				switch (selectedCreationMethod)
				{
					case 0:
						{
							if (PolicyToAddLogsTo is not null)
							{
								// Set policy name and reset the policy ID of our new policy
								string supplementalPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, policyName, null, null);

								// Remove all policy rule options prior to merging the policies since we don't need to add/remove any policy rule options to/from the user input policy
								CiRuleOptions.Set(filePath: EmptyPolicyPath, RemoveAll: true);

								// Merge the created policy with the user-selected policy which will result in adding the new rules to it
								SiPolicy.Merger.Merge(PolicyToAddLogsTo, [EmptyPolicyPath]);

								UpdateHvciOptions.Update(PolicyToAddLogsTo);

								// Add the supplemental policy path to the class variable
								finalSupplementalPolicyPath = PolicyToAddLogsTo;

								// If user selected to deploy the policy
								if (DeployAtTheEnd)
								{
									string CIPPath = Path.Combine(stagingArea.FullName, $"{supplementalPolicyID}.cip");

									PolicyToCIPConverter.Convert(PolicyToAddLogsTo, CIPPath);

									CiToolHelper.UpdatePolicy(CIPPath);
								}
							}
							else
							{
								throw new InvalidOperationException("No policy file was selected to add the logs to.");
							}

							break;
						}
					case 1:
						{
							if (BasePolicyXMLFile is not null)
							{
								string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyName}.xml");

								// Instantiate the user selected Base policy
								SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(BasePolicyXMLFile, null);

								// Set the BasePolicyID of our new policy to the one from user selected policy
								string supplementalPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, policyName, policyObj.BasePolicyID, null);

								// Configure policy rule options
								CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);

								// Set policy version
								SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

								// Copying the policy file to the User Config directory - outside of the temporary staging area
								File.Copy(EmptyPolicyPath, OutputPath, true);

								// Add the supplemental policy path to the class variable
								finalSupplementalPolicyPath = OutputPath;

								// If user selected to deploy the policy
								if (DeployAtTheEnd)
								{
									string CIPPath = Path.Combine(stagingArea.FullName, $"{supplementalPolicyID}.cip");

									PolicyToCIPConverter.Convert(OutputPath, CIPPath);

									CiToolHelper.UpdatePolicy(CIPPath);
								}
							}
							else
							{
								throw new InvalidOperationException("No policy file was selected to associate the Supplemental policy with.");
							}

							break;
						}
					case 2:
						{

							if (BasePolicyGUID is not null)
							{
								string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyName}.xml");


								// Set the BasePolicyID of our new policy to the one supplied by user
								string supplementalPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, policyName, BasePolicyGUID.ToString(), null);

								// Configure policy rule options
								CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);


								// Set policy version
								SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

								// Copying the policy file to the User Config directory - outside of the temporary staging area
								File.Copy(EmptyPolicyPath, OutputPath, true);

								// Add the supplemental policy path to the class variable
								finalSupplementalPolicyPath = OutputPath;

								// If user selected to deploy the policy
								if (DeployAtTheEnd)
								{

									string CIPPath = Path.Combine(stagingArea.FullName, $"{supplementalPolicyID}.cip");

									PolicyToCIPConverter.Convert(OutputPath, CIPPath);

									CiToolHelper.UpdatePolicy(CIPPath);
								}
							}
							else
							{
								throw new InvalidOperationException("No Base Policy GUID was provided to use as the BasePolicyID of the supplemental policy.");
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

			ViewModel.MainInfoBarVisibility = Visibility.Visible;
			ViewModel.MainInfoBarIsOpen = true;
			ViewModel.MainInfoBarIsClosable = true;
			ViewModel.MainInfoBarMessage = $"There was an error creating the Supplemental policy: {ex.Message}";
			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Error;

			throw;
		}
		finally
		{
			// Enable the policy creator button again
			CreatePolicyButton.IsEnabled = true;

			// enable the scan logs button again
			ScanLogs.IsEnabled = true;

			// Display the progress ring on the ScanLogs button
			ScanLogsProgressRing.IsActive = false;
			ScanLogsProgressRing.Visibility = Visibility.Collapsed;

			if (!Error)
			{
				ViewModel.MainInfoBarMessage = "Successfully created the Supplemental policy.";
				ViewModel.MainInfoBarSeverity = InfoBarSeverity.Success;
				ViewModel.MainInfoBarVisibility = Visibility.Visible;
				ViewModel.MainInfoBarIsOpen = true;
				ViewModel.MainInfoBarIsClosable = true;

				ViewModel.OpenInPolicyEditorInfoBarActionButtonVisibility = Visibility.Visible;
			}
		}
	}


	/// <summary>
	/// Scan level selection event handler for ComboBox
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

		scanLevel = Enum.Parse<ScanLevels>(selectedText);
	}

	private void BrowseForLogs_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		BrowseForLogs_SelectedFilesTextBox.Text = null;
		MDEAdvancedHuntingLogs = null;
	}

	/// <summary>
	/// Event handler for the button that retrieves the logs
	/// </summary>
	private async void RetrieveTheLogsButton_Click()
	{
		ViewModel.MainInfoBarVisibility = Visibility.Visible;
		ViewModel.MainInfoBarIsOpen = true;
		ViewModel.MainInfoBarMessage = "Retrieving the Microsoft Defender for Endpoint Advanced Hunting data";
		ViewModel.MainInfoBarSeverity = InfoBarSeverity.Informational;
		ViewModel.MainInfoBarIsClosable = false;

		MDEAdvancedHuntingDataRootObject? root = null;

		try
		{
			RetrieveTheLogsButton.IsEnabled = false;
			MSGraphDeviceNameButton.IsEnabled = false;

			// Retrieve the MDE Advanced Hunting data as a JSON string
			string? result = await MicrosoftGraph.Main.RunMDEAdvancedHuntingQuery(DeviceNameTextBox.Text, AuthCompanionCLS.CurrentActiveAccount);

			// If there were results
			if (result is not null)
			{
				// Deserialize the JSON result
				root = await Task.Run(() => JsonSerializer.Deserialize(result, MDEAdvancedHuntingJSONSerializationContext.Default.MDEAdvancedHuntingDataRootObject));

				if (root is null)
				{
					ViewModel.MainInfoBarMessage = "There were no logs to be retrieved";
					ViewModel.MainInfoBarSeverity = InfoBarSeverity.Warning;
					return;
				}

				if (root.Results.Count is 0)
				{
					ViewModel.MainInfoBarMessage = "0 logs were retrieved";
					ViewModel.MainInfoBarSeverity = InfoBarSeverity.Warning;
					return;
				}

				ViewModel.MainInfoBarMessage = $"Successfully retrieved {root.Results.Count} logs from the cloud";
				ViewModel.MainInfoBarSeverity = InfoBarSeverity.Success;

				Logger.Write("Deserialization complete. Number of records: " + root.Results.Count);

				// Grab the App Control Logs
				HashSet<FileIdentity> Output = await Task.Run(() => GetMDEAdvancedHuntingLogsData.Retrieve(root.Results));

				if (Output.Count is 0)
				{
					ViewModel.MainInfoBarMessage = "No actionable logs were found among the retrieved data to create a Supplemental policy with.";
					ViewModel.MainInfoBarSeverity = InfoBarSeverity.Warning;
				}

				ViewModel.AllFileIdentities.Clear();
				ViewModel.FileIdentities.Clear();

				// Store all of the data in the List
				ViewModel.AllFileIdentities.AddRange(Output);

				// Store all of the data in the ObservableCollection
				foreach (FileIdentity item in Output)
				{
					item.ParentViewModelMDEAHPolicyCreationVM = ViewModel;
					ViewModel.FileIdentities.Add(item);
				}

				UpdateTotalLogs();

				ViewModel.CalculateColumnWidths();
			}
		}
		catch (Exception ex)
		{
			ViewModel.MainInfoBarMessage = $"There was an error retrieving the MDE Advanced Hunting logs from MSGraph: {ex.Message}";
			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Error;
			throw;
		}
		finally
		{
			RetrieveTheLogsButton.IsEnabled = true;
			MSGraphDeviceNameButton.IsEnabled = true;

			ViewModel.MainInfoBarIsClosable = true;
		}
	}


	/// <summary>
	/// Event handler for for the segmented button's selection change
	/// </summary>
	private void SegmentedControl_SelectionChanged()
	{
		CreatePolicyButton.Content = segmentedControl.SelectedIndex switch
		{
			0 => "Add logs to the selected policy",
			1 => "Create Policy for Selected Base",
			2 => "Create Policy for Base GUID",
			_ => "Create Policy"
		};

	}


	/// <summary>
	/// Handles the Copy button click.
	/// Copies the associated query text to the clipboard and plays an animation
	/// that changes the button's text from "Copy" to "Copied" and then back.
	/// </summary>
	private void CopyButton_Click(object sender, RoutedEventArgs e)
	{
		Button copyButton = (Button)sender;
		MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage queryItem = (MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage)copyButton.DataContext;

		// Copy the query text to the clipboard.
		ClipboardManagement.CopyText(queryItem.Query);

		// Retrieve the Grid that is the button's content.
		if (copyButton.Content is Grid grid)
		{
			// Find the two TextBlocks
			TextBlock normalTextBlock = (TextBlock)grid.FindName("NormalText");
			TextBlock copiedTextBlock = (TextBlock)grid.FindName("CopiedText");

			// Create a storyboard to hold both keyframe animations.
			Storyboard sb = new();

			// Create a keyframe animation for the "NormalText" (Copy)
			// Timeline:
			// 0ms: Opacity = 1
			// 200ms: fade out to 0
			// 1200ms: remain at 0
			// 1400ms: fade back in to 1
			DoubleAnimationUsingKeyFrames normalAnimation = new();
			normalAnimation.KeyFrames.Add(new DiscreteDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(0), Value = 1 });
			normalAnimation.KeyFrames.Add(new LinearDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(200), Value = 0 });
			normalAnimation.KeyFrames.Add(new DiscreteDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(1200), Value = 0 });
			normalAnimation.KeyFrames.Add(new LinearDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(1400), Value = 1 });
			Storyboard.SetTarget(normalAnimation, normalTextBlock);
			Storyboard.SetTargetProperty(normalAnimation, "Opacity");

			// Create a keyframe animation for the "CopiedText" (Copied)
			// Timeline:
			// 0ms: Opacity = 0
			// 200ms: fade in to 1
			// 1200ms: remain at 1
			// 1400ms: fade out to 0
			DoubleAnimationUsingKeyFrames copiedAnimation = new();
			copiedAnimation.KeyFrames.Add(new DiscreteDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(0), Value = 0 });
			copiedAnimation.KeyFrames.Add(new LinearDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(200), Value = 1 });
			copiedAnimation.KeyFrames.Add(new DiscreteDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(1200), Value = 1 });
			copiedAnimation.KeyFrames.Add(new LinearDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(1400), Value = 0 });
			Storyboard.SetTarget(copiedAnimation, copiedTextBlock);
			Storyboard.SetTargetProperty(copiedAnimation, "Opacity");

			// Add animations to the storyboard.
			sb.Children.Add(normalAnimation);
			sb.Children.Add(copiedAnimation);

			// Start the storyboard.
			sb.Begin();

		}
	}

	/// <summary>
	/// CTRL + C shortcuts event handler
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void CtrlC_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		ListViewFlyoutMenuCopy_Click(sender, new RoutedEventArgs());
		args.Handled = true;
	}

	/// <summary>
	/// Path of the Supplemental policy that is created or the policy that user selected to add the logs to.
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

internal sealed class MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage
{
	internal string? QueryTitle { get; init; }
	internal string? Query { get; init; }
}
