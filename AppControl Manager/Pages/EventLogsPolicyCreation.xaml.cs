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
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using AppControlManager.XMLOps;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Handles the creation and management of event logs policies, including scanning logs, filtering, and clipboard
/// operations.
/// </summary>
internal sealed partial class EventLogsPolicyCreation : Page
{

#pragma warning disable CA1822
	private EventLogsPolicyCreationVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<EventLogsPolicyCreationVM>();
	private PolicyEditorVM PolicyEditorViewModel { get; } = App.AppHost.Services.GetRequiredService<PolicyEditorVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
#pragma warning restore CA1822

	/// <summary>
	/// Initializes the EventLogsPolicyCreation component, sets navigation cache mode, and binds the DataContext to the
	/// ViewModel. Also adds a DateChanged event handler.
	/// </summary>
	internal EventLogsPolicyCreation()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;

		this.DataContext = ViewModel;

		// Add the DateChanged event handler
		FilterByDateCalendarPicker.DateChanged += FilterByDateCalendarPicker_DateChanged;
	}


	private string? CodeIntegrityEVTX; // To store the Code Integrity EVTX file path
	private string? AppLockerEVTX; // To store the AppLocker EVTX file path

	// The user selected scan level
	private ScanLevels scanLevel = ScanLevels.FilePublisher;


	// Variables to hold the data supplied by the UI elements
	private Guid? BasePolicyGUID;
	private string? PolicyToAddLogsTo;
	private string? BasePolicyXMLFile;


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
					regKey: ListViewHelper.ListViewsRegistry.Event_Logs);
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
	/// Applies the date and search filters to the data grid
	/// </summary>
	private void ApplyFilters()
	{
		ListViewHelper.ApplyFilters(
		allFileIdentities: ViewModel.AllFileIdentities.AsEnumerable(),
		filteredCollection: ViewModel.FileIdentities,
		searchText: SearchBox.Text,
		datePicker: FilterByDateCalendarPicker,
		regKey: ListViewHelper.ListViewsRegistry.Event_Logs
		);
		UpdateTotalLogs();
	}


	/// <summary>
	/// Event handler for the ScanLogs click
	/// </summary>
	private async void ScanLogs_Click()
	{

		bool error = false;

		try
		{

			MainInfoBar.Visibility = Visibility.Visible;
			MainInfoBar.IsOpen = true;
			MainInfoBar.Message = "Scanning the event logs...";
			MainInfoBar.Severity = InfoBarSeverity.Informational;
			MainInfoBar.IsClosable = false;

			// Disable the scan button initially
			ScanLogs.IsEnabled = false;

			// Display the progress ring on the ScanLogs button
			ScanLogsProgressRing.IsActive = true;
			ScanLogsProgressRing.Visibility = Visibility.Visible;

			// Disable the Policy creator button while scan is being performed
			CreatePolicyButton.IsEnabled = false;

			UpdateTotalLogs(true);

			// Grab the App Control Logs
			HashSet<FileIdentity> Output = await GetEventLogsData.GetAppControlEvents(CodeIntegrityEvtxFilePath: CodeIntegrityEVTX, AppLockerEvtxFilePath: AppLockerEVTX);

			ViewModel.AllFileIdentities.Clear();

			// Store all of the data in the List
			ViewModel.AllFileIdentities.AddRange(Output);

			// Clear the ObservableCollection before adding the new data
			ViewModel.FileIdentities.Clear();

			foreach (FileIdentity item in Output)
			{
				// Add a reference to the ViewModel class to each item so we can use it for navigation in the XAML
				item.ParentViewModelEventLogsPolicyCreationVM = ViewModel;
				ViewModel.FileIdentities.Add(item);
			}


			UpdateTotalLogs();

			ViewModel.CalculateColumnWidths();
		}
		catch (Exception ex)
		{
			error = true;

			MainInfoBar.Visibility = Visibility.Visible;
			MainInfoBar.IsOpen = true;
			MainInfoBar.Message = $"There was an error during logs scan: {ex.Message}";
			MainInfoBar.Severity = InfoBarSeverity.Error;
			MainInfoBar.IsClosable = true;

			throw;
		}
		finally
		{
			// Enable the button again
			ScanLogs.IsEnabled = true;

			// Clear the selected file paths
			CodeIntegrityEVTX = null;
			AppLockerEVTX = null;

			// Stop displaying the Progress Ring
			ScanLogsProgressRing.IsActive = false;
			ScanLogsProgressRing.Visibility = Visibility.Collapsed;

			// Enable the Policy creator button again
			CreatePolicyButton.IsEnabled = true;

			if (!error)
			{
				MainInfoBar.Visibility = Visibility.Visible;
				MainInfoBar.IsOpen = true;
				MainInfoBar.Message = $"Scan complete. {ViewModel.AllFileIdentities.Count} logs were found.";
				MainInfoBar.Severity = InfoBarSeverity.Success;
				MainInfoBar.IsClosable = true;
			}
		}
	}


	/// <summary>
	/// Event handler for the select Code Integrity EVTX file path button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SelectCodeIntegrityEVTXFiles_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.EVTXPickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected evtx file path
			CodeIntegrityEVTX = selectedFile;

			Logger.Write($"Selected {selectedFile} for Code Integrity EVTX log scanning");

			SelectedCodeIntegrityEVTXFilesFlyout_TextBox.Text = selectedFile;

			SelectedCodeIntegrityEVTXFilesFlyout.ShowAt(BrowseForEVTXDropDownButton);
		}
	}


	private void SelectedCodeIntegrityEVTXFilesFlyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		SelectedCodeIntegrityEVTXFilesFlyout_TextBox.Text = null;
		CodeIntegrityEVTX = null;
	}


	/// <summary>
	/// Event handler for the select AppLocker EVTX file path button
	/// </summary>
	private void SelectAppLockerEVTXFiles_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.EVTXPickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected EVTX file path
			AppLockerEVTX = selectedFile;

			Logger.Write($"Selected {selectedFile} for AppLocker EVTX log scanning");

			SelectedAppLockerEVTXFilesFlyout_TextBox.Text = selectedFile;

			SelectedAppLockerEVTXFilesFlyout.ShowAt(BrowseForEVTXDropDownButton);
		}
	}


	/// <summary>
	/// Clears the selected AppLocker EVTX file paths
	/// </summary>
	private void SelectedAppLockerEVTXFilesFlyout_Clear_Click()
	{
		SelectedAppLockerEVTXFilesFlyout_TextBox.Text = null;
		AppLockerEVTX = null;
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

		// Remove each selected item from the FileIdentities collection
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
			TotalCountOfTheFilesTextBox.Text = $"Total logs: 0";
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
	/// <exception cref="ArgumentException"></exception>
	private void BaseGUIDSubmitButton_Click()
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

		bool error = false;

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

			MainInfoBar.Visibility = Visibility.Visible;
			MainInfoBar.IsOpen = true;
			MainInfoBar.Message = "Processing the logs...";
			MainInfoBar.Severity = InfoBarSeverity.Informational;
			MainInfoBar.IsClosable = false;


			if (ViewModel.FileIdentities.Count is 0)
			{
				throw new InvalidOperationException("There are no logs. Use the scan button first.");
			}


			if (PolicyToAddLogsTo is null && BasePolicyXMLFile is null && BasePolicyGUID is null)
			{
				throw new InvalidOperationException("You must select an option from the policy creation list");
			}

			// Create a policy name if it wasn't provided
			DateTime now = DateTime.Now;
			string formattedDate = now.ToString("MM-dd-yyyy 'at' HH-mm-ss");


			// Get the policy name from the UI text box
			string? policyName = PolicyNameTextBox.Text;

			// If the UI text box was empty or whitespace then set policy name manually
			if (string.IsNullOrWhiteSpace(policyName))
			{
				policyName = $"Supplemental policy from event logs - {formattedDate}";
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
			}

			await Task.Run(() =>
			{

				// Create a new Staging Area
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("PolicyCreator");

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
			error = true;

			MainInfoBar.Visibility = Visibility.Visible;
			MainInfoBar.IsOpen = true;
			MainInfoBar.Message = $"There was an error while processing the logs: {ex.Message}.";
			MainInfoBar.Severity = InfoBarSeverity.Error;
			MainInfoBar.IsClosable = true;

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

			if (!error)
			{
				MainInfoBar.Visibility = Visibility.Visible;
				MainInfoBar.IsOpen = true;
				MainInfoBar.Message = "Successfully processed the logs and included them in the policy.";
				MainInfoBar.Severity = InfoBarSeverity.Success;
				MainInfoBar.IsClosable = true;

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


	private void BrowseForCodeIntegrityEVTXFilesButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!SelectedCodeIntegrityEVTXFilesFlyout.IsOpen)
			SelectedCodeIntegrityEVTXFilesFlyout.ShowAt(BrowseForEVTXDropDownButton);
	}

	private void BrowseForCodeIntegrityEVTXFilesButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!SelectedCodeIntegrityEVTXFilesFlyout.IsOpen)
				SelectedCodeIntegrityEVTXFilesFlyout.ShowAt(BrowseForEVTXDropDownButton);
	}

	private void BrowseForAppLockerEVTXFilesButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!SelectedAppLockerEVTXFilesFlyout.IsOpen)
			SelectedAppLockerEVTXFilesFlyout.ShowAt(BrowseForEVTXDropDownButton);
	}

	private void BrowseForAppLockerEVTXFilesButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!SelectedAppLockerEVTXFilesFlyout.IsOpen)
				SelectedAppLockerEVTXFilesFlyout.ShowAt(BrowseForEVTXDropDownButton);
	}


	/// <summary>
	/// Event handler for for the segmented button's selection change
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SegmentedControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
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
