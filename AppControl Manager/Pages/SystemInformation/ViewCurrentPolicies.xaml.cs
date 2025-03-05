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
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicyIntel;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;
using WinRT;

namespace AppControlManager.Pages;

// Since the columns for data in the ItemTemplate use "Binding" instead of "x:Bind", we need to use [GeneratedBindableCustomProperty] for them to work properly
[GeneratedBindableCustomProperty]
public sealed partial class ViewCurrentPolicies : Page, INotifyPropertyChanged
{

	#region LISTVIEW IMPLEMENTATIONS

	public event PropertyChangedEventHandler? PropertyChanged;
	private void OnPropertyChanged(string propertyName) =>
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

	// Properties to hold each columns' width.
	private GridLength _columnWidth1;
	public GridLength ColumnWidth1
	{
		get => _columnWidth1;
		set { _columnWidth1 = value; OnPropertyChanged(nameof(ColumnWidth1)); }
	}

	private GridLength _columnWidth2;
	public GridLength ColumnWidth2
	{
		get => _columnWidth2;
		set { _columnWidth2 = value; OnPropertyChanged(nameof(ColumnWidth2)); }
	}

	private GridLength _columnWidth3;
	public GridLength ColumnWidth3
	{
		get => _columnWidth3;
		set { _columnWidth3 = value; OnPropertyChanged(nameof(ColumnWidth3)); }
	}

	private GridLength _columnWidth4;
	public GridLength ColumnWidth4
	{
		get => _columnWidth4;
		set { _columnWidth4 = value; OnPropertyChanged(nameof(ColumnWidth4)); }
	}

	private GridLength _columnWidth5;
	public GridLength ColumnWidth5
	{
		get => _columnWidth5;
		set { _columnWidth5 = value; OnPropertyChanged(nameof(ColumnWidth5)); }
	}

	private GridLength _columnWidth6;
	public GridLength ColumnWidth6
	{
		get => _columnWidth6;
		set { _columnWidth6 = value; OnPropertyChanged(nameof(ColumnWidth6)); }
	}

	private GridLength _columnWidth7;
	public GridLength ColumnWidth7
	{
		get => _columnWidth7;
		set { _columnWidth7 = value; OnPropertyChanged(nameof(ColumnWidth7)); }
	}

	private GridLength _columnWidth8;
	public GridLength ColumnWidth8
	{
		get => _columnWidth8;
		set { _columnWidth8 = value; OnPropertyChanged(nameof(ColumnWidth8)); }
	}

	private GridLength _columnWidth9;
	public GridLength ColumnWidth9
	{
		get => _columnWidth9;
		set { _columnWidth9 = value; OnPropertyChanged(nameof(ColumnWidth9)); }
	}

	private GridLength _columnWidth10;
	public GridLength ColumnWidth10
	{
		get => _columnWidth10;
		set { _columnWidth10 = value; OnPropertyChanged(nameof(ColumnWidth10)); }
	}

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// </summary>
	private void CalculateColumnWidths()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PolicyIDHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("BasePolicyIDHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FriendlyNameHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("VersionHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsAuthorizedHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsEnforcedHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsOnDiskHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsSignedPolicyHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsSystemPolicyHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PolicyOptionsHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (CiPolicyInfo item in AllPolicies)
		{
			double w1 = ListViewHelper.MeasureTextWidth(item.PolicyID);
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewHelper.MeasureTextWidth(item.BasePolicyID);
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewHelper.MeasureTextWidth(item.FriendlyName);
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewHelper.MeasureTextWidth(item.Version!.ToString());
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewHelper.MeasureTextWidth(item.IsAuthorized.ToString());
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewHelper.MeasureTextWidth(item.IsEnforced.ToString());
			if (w6 > maxWidth6) maxWidth6 = w6;

			double w7 = ListViewHelper.MeasureTextWidth(item.IsOnDisk.ToString());
			if (w7 > maxWidth7) maxWidth7 = w7;

			double w8 = ListViewHelper.MeasureTextWidth(item.IsSignedPolicy.ToString());
			if (w8 > maxWidth8) maxWidth8 = w8;

			double w9 = ListViewHelper.MeasureTextWidth(item.IsSystemPolicy.ToString());
			if (w9 > maxWidth9) maxWidth9 = w9;

			double w10 = ListViewHelper.MeasureTextWidth(item.PolicyOptionsDisplay);
			if (w10 > maxWidth10) maxWidth10 = w10;
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
	}

	/// <summary>
	/// Converts the properties of a CiPolicyInfo row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	/// <param name="row">The selected CiPolicyInfo row from the ListView.</param>
	/// <returns>A formatted string of the row's properties with labels.</returns>
	private static string ConvertRowToText(CiPolicyInfo row)
	{
		// Use StringBuilder to format each property with its label for easy reading
		return new StringBuilder()
			.AppendLine(GlobalVars.Rizz.GetString("PolicyIDLabel") + row.PolicyID)
			.AppendLine(GlobalVars.Rizz.GetString("BasePolicyIDLabel") + row.BasePolicyID)
			.AppendLine(GlobalVars.Rizz.GetString("FriendlyNameLabel") + row.FriendlyName)
			.AppendLine(GlobalVars.Rizz.GetString("VersionLabel") + row.Version)
			.AppendLine(GlobalVars.Rizz.GetString("IsAuthorizedLabel") + row.IsAuthorized)
			.AppendLine(GlobalVars.Rizz.GetString("IsEnforcedLabel") + row.IsEnforced)
			.AppendLine(GlobalVars.Rizz.GetString("IsOnDiskLabel") + row.IsOnDisk)
			.AppendLine(GlobalVars.Rizz.GetString("IsSignedPolicyLabel") + row.IsSignedPolicy)
			.AppendLine(GlobalVars.Rizz.GetString("IsSystemPolicyLabel") + row.IsSystemPolicy)
			.AppendLine(GlobalVars.Rizz.GetString("PolicyOptionsLabel") + row.PolicyOptionsDisplay)
			.ToString();
	}

	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	/// <param name="sender">The event sender.</param>
	/// <param name="e">The event arguments.</param>
	private void ListViewFlyoutMenuCopy_Click(object sender, RoutedEventArgs e)
	{
		// Check if there are selected items in the ListView
		if (DeployedPolicies.SelectedItems.Count > 0)
		{
			// Initialize StringBuilder to store all selected rows' data with labels
			StringBuilder dataBuilder = new();

			// Loop through each selected item in the ListView
			foreach (var selectedItem in DeployedPolicies.SelectedItems)
			{
				if (selectedItem is CiPolicyInfo obj)

					// Append each row's formatted data to the StringBuilder
					_ = dataBuilder.AppendLine(ConvertRowToText(obj));

				// Add a separator between rows for readability in multi-row copies
				_ = dataBuilder.AppendLine(ListViewHelper.DefaultDelimiter);
			}

			// Create a DataPackage to hold the text data
			DataPackage dataPackage = new();

			// Set the formatted text as the content of the DataPackage
			dataPackage.SetText(dataBuilder.ToString());

			// Copy the DataPackage content to the clipboard
			Clipboard.SetContent(dataPackage);
		}
	}

	// Click event handlers for each property
	private void CopyPolicyID_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.PolicyID?.ToString());
	private void CopyBasePolicyID_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.BasePolicyID?.ToString());
	private void CopyFriendlyName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FriendlyName);
	private void CopyVersion_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.Version?.ToString());
	private void CopyIsAuthorized_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsAuthorized.ToString());
	private void CopyIsEnforced_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsEnforced.ToString());
	private void CopyIsOnDisk_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsOnDisk.ToString());
	private void CopyIsSignedPolicy_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsSignedPolicy.ToString());
	private void CopyIsSystemPolicy_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsSystemPolicy.ToString());
	private void CopyPolicyOptionsDisplay_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.PolicyOptionsDisplay);

	/// <summary>
	/// Helper method to copy a specified property to clipboard without reflection
	/// </summary>
	/// <param name="getProperty">Function that retrieves the desired property value as a string</param>
	private void CopyToClipboard(Func<CiPolicyInfo, string?> getProperty)
	{
		if (DeployedPolicies.SelectedItem is CiPolicyInfo selectedItem)
		{
			string? propertyValue = getProperty(selectedItem);
			if (propertyValue is not null)
			{
				DataPackage dataPackage = new();
				dataPackage.SetText(propertyValue);
				Clipboard.SetContent(dataPackage);
			}
		}
	}

	// Event handlers for each sort button
	private void ColumnSortingButton_PolicyID_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.PolicyID);
	}
	private void ColumnSortingButton_BasePolicyID_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.BasePolicyID);
	}
	private void ColumnSortingButton_FriendlyName_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.FriendlyName);
	}
	private void ColumnSortingButton_Version_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.Version);
	}
	private void ColumnSortingButton_IsAuthorized_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.IsAuthorized);
	}
	private void ColumnSortingButton_IsEnforced_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.IsEnforced);
	}
	private void ColumnSortingButton_IsOnDisk_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.IsOnDisk);
	}
	private void ColumnSortingButton_IsSignedPolicy_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.IsSignedPolicy);
	}
	private void ColumnSortingButton_IsSystemPolicy_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.IsSystemPolicy);
	}
	private void ColumnSortingButton_PolicyRuleOptions_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.PolicyOptionsDisplay);
	}

	/// <summary>
	/// Performs data sorting
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="keySelector"></param>
	private void SortColumn<T>(Func<CiPolicyInfo, T> keySelector)
	{
		// Determine if a search filter is active.
		bool isSearchEmpty = string.IsNullOrWhiteSpace(SearchBox.Text);
		// Use either the full list (AllPoliciesOutput) or the current display list.
		List<CiPolicyInfo> collectionToSort = isSearchEmpty ? AllPoliciesOutput : [.. AllPolicies];

		if (SortingDirectionToggle.IsChecked)
		{
			// Sort in descending order.
			AllPolicies = [.. collectionToSort.OrderByDescending(keySelector)];
		}
		else
		{
			// Sort in ascending order.
			AllPolicies = [.. collectionToSort.OrderBy(keySelector)];
		}

		// Refresh the ItemsSource so the UI updates.
		DeployedPolicies.ItemsSource = AllPolicies;
	}

	// To store the policies displayed on the ListView
	internal ObservableCollection<CiPolicyInfo> AllPolicies { get; set; }

	// Store all outputs for searching
	private readonly List<CiPolicyInfo> AllPoliciesOutput;

	#endregion

	// Keep track of the currently selected policy
	private CiPolicyInfo? selectedPolicy;

	public ViewCurrentPolicies()
	{
		this.InitializeComponent();

		DataContext = this; // Set the DataContext for x:Bind references in the header in XAML

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;

		// Initially disable the RemovePolicyButton
		RemovePolicyButton.IsEnabled = false;

		AllPolicies = [];
		AllPoliciesOutput = [];
	}

	/// <summary>
	/// Event handler for the RetrievePoliciesButton click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void RetrievePoliciesButton_Click(object sender, RoutedEventArgs e)
	{
		RetrievePolicies();
	}

	/// <summary>
	/// Helper method to retrieve the policies from the system
	/// </summary>
	private async void RetrievePolicies()
	{
		try
		{
			// Disable the button to prevent multiple clicks while retrieving
			RetrievePoliciesButton.IsEnabled = false;

			// Clear the policies before getting and showing the new ones
			// They also set the "SelectedItem" property of the ListView to null
			AllPolicies.Clear();
			AllPoliciesOutput.Clear();

			// The checkboxes belong to the UI thread so can't use their bool value directly on the Task.Run's thread
			bool ShouldIncludeSystem = IncludeSystemPolicies.IsChecked;
			bool ShouldIncludeBase = IncludeBasePolicies.IsChecked;
			bool ShouldIncludeSupplemental = IncludeSupplementalPolicies.IsChecked;
			bool ShouldIncludeAppControlManagerSupplementalPolicy = IncludeAppControlManagerSupplementalPolicy.IsChecked;

			List<CiPolicyInfo> policies = [];

			// Check if the AppControlManagerSupplementalPolicy checkbox is checked, if it is, show the automatic policy
			if (ShouldIncludeAppControlManagerSupplementalPolicy)
			{
				// Run the GetPolicies method asynchronously
				policies = await Task.Run(() => CiToolHelper.GetPolicies(ShouldIncludeSystem, ShouldIncludeBase, ShouldIncludeSupplemental));
			}
			// Filter out the AppControlManagerSupplementalPolicy automatic policies from the list
			else
			{
				// Run the GetPolicies method asynchronously
				policies = await Task.Run(() => CiToolHelper.GetPolicies(ShouldIncludeSystem, ShouldIncludeBase, ShouldIncludeSupplemental).Where(x => !string.Equals(x.FriendlyName, GlobalVars.AppControlManagerSpecialPolicyName, StringComparison.OrdinalIgnoreCase)).ToList());
			}

			// Store all of the policies in the ObservableCollection
			foreach (CiPolicyInfo policy in policies)
			{
				CiPolicyInfo temp = new()
				{
					PolicyID = policy.PolicyID,
					BasePolicyID = policy.BasePolicyID,
					FriendlyName = policy.FriendlyName,
					Version = policy.Version,
					VersionString = policy.VersionString,
					IsSystemPolicy = policy.IsSystemPolicy,
					IsSignedPolicy = policy.IsSignedPolicy,
					IsOnDisk = policy.IsOnDisk,
					IsEnforced = policy.IsEnforced,
					IsAuthorized = policy.IsAuthorized,
					PolicyOptions = policy.PolicyOptions
				};

				// Add the retrieved policies to the list in class instance
				AllPoliciesOutput.Add(temp);

				AllPolicies.Add(temp);
			}

			// Update the UI once the task completes
			PoliciesCountTextBlock.Text = GlobalVars.Rizz.GetString("NumberOfPolicies") + policies.Count;

			CalculateColumnWidths();

			DeployedPolicies.ItemsSource = AllPolicies;
		}
		finally
		{
			// Re-enable the button
			RetrievePoliciesButton.IsEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the search box text change
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		string searchTerm = SearchBox.Text.Trim().ToLowerInvariant();

		// Perform a case-insensitive search in all relevant fields
		List<CiPolicyInfo> filteredResults = [.. AllPoliciesOutput.Where(p =>
			(p.PolicyID?.ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.FriendlyName?.ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.VersionString?.ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.IsSystemPolicy.ToString().ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
            (p.IsSignedPolicy.ToString().ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
            (p.IsOnDisk.ToString().ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
            (p.IsEnforced.ToString().ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) || // Convert bool to string for comparison
            (p.PolicyOptionsDisplay?.ToLowerInvariant().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)
		)];

		// Update the ObservableCollection with the filtered results
		AllPolicies = [.. filteredResults];

		DeployedPolicies.ItemsSource = AllPolicies;

		// Update the policies count text
		PoliciesCountTextBlock.Text = GlobalVars.Rizz.GetString("NumberOfPolicies") + filteredResults.Count;
	}


	// A counter to prevent SelectionChanged event from firing twice when right-clicking on an unselected row
	private int _skipSelectionChangedCount;

	/// <summary>
	/// Event handler for when a policy is selected from the ListView. It will contain the selected policy.
	/// When the Refresh button is pressed, this event is fired again, but due to clearing the existing data in the refresh event handler, ListView's SelectedItem property will be null,
	/// so we detect it here and return from the method without assigning null to the selectedPolicy class instance.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void DeployedPolicies_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Check if we need to skip this event.
		if (_skipSelectionChangedCount > 0)
		{
			_skipSelectionChangedCount--;
			return;
		}

		await ListViewHelper.SmoothScrollIntoViewWithIndexCenterVerticallyOnlyAsync(listViewBase: (ListView)sender, listView: (ListView)sender, index: ((ListView)sender).SelectedIndex, disableAnimation: false, scrollIfVisible: true, additionalHorizontalOffset: 0, additionalVerticalOffset: 0);

		// Get the selected policy from the ListView
		CiPolicyInfo? temp = (CiPolicyInfo)DeployedPolicies.SelectedItem;

		if (temp is null)
		{
			return;
		}

		selectedPolicy = temp;

		// Check if:
		if (
			// It's a non-system policy
			!selectedPolicy.IsSystemPolicy &&
			// It's available on disk
			selectedPolicy.IsOnDisk)
		{
			// Enable the RemovePolicyButton
			RemovePolicyButton.IsEnabled = true;
		}
		else
		{
			// Disable the button if no proper policy is selected
			RemovePolicyButton.IsEnabled = false;
		}

		// Enable the Swap Policy ComboBox only when the selected policy is a base type, unsigned and non-system
		SwapPolicyComboBox.IsEnabled = string.Equals(selectedPolicy.BasePolicyID, selectedPolicy.PolicyID, StringComparison.OrdinalIgnoreCase) && !selectedPolicy.IsSignedPolicy && !selectedPolicy.IsSystemPolicy;
	}


	/// <summary>
	/// Event handler for the RemovePolicyButton click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void RemovePolicy_Click(object sender, RoutedEventArgs e)
	{

		List<CiPolicyInfo> policiesToRemove = [];

		try
		{
			// Disable the remove button while the selected policy is being processed
			// It will stay disabled until user selects another removable policy
			RemovePolicyButton.IsEnabled = false;

			// Disable interactions with the ListView while policies are being removed
			DeployedPolicies.IsHitTestVisible = false;

			// Disable the refresh policies button while policies are being removed
			RetrievePoliciesButton.IsEnabled = false;

			// Disable the search box while policies are being removed
			SearchBox.IsEnabled = false;

			// Make sure we have a valid selected non-system policy that is on disk
			if (selectedPolicy is not null && !selectedPolicy.IsSystemPolicy && selectedPolicy.IsOnDisk)
			{
				// List of all the deployed non-system policies
				List<CiPolicyInfo> currentlyDeployedPolicies = [];

				// List of all the deployed base policy IDs
				List<string?> currentlyDeployedBasePolicyIDs = [];

				// List of all the deployed AppControlManagerSupplementalPolicy
				List<CiPolicyInfo> currentlyDeployedAppControlManagerSupplementalPolicies = [];

				// Populate the lists defined above
				await Task.Run(() =>
				{
					currentlyDeployedPolicies = CiToolHelper.GetPolicies(false, true, true);

					currentlyDeployedBasePolicyIDs = [.. currentlyDeployedPolicies.Where(x => string.Equals(x.PolicyID, x.BasePolicyID, StringComparison.OrdinalIgnoreCase)).Select(p => p.BasePolicyID)];

					currentlyDeployedAppControlManagerSupplementalPolicies = [.. currentlyDeployedPolicies.Where(p => string.Equals(p.FriendlyName, GlobalVars.AppControlManagerSpecialPolicyName, StringComparison.OrdinalIgnoreCase))];
				});


				// Check if the selected policy has the FriendlyName "AppControlManagerSupplementalPolicy"
				if (string.Equals(selectedPolicy.FriendlyName, GlobalVars.AppControlManagerSpecialPolicyName, StringComparison.OrdinalIgnoreCase))
				{

					// Check if the base policy of the AppControlManagerSupplementalPolicy Supplemental policy is currently deployed on the system
					// And only then show the prompt, otherwise allow for its removal just like any other policy since it's a stray Supplemental policy
					if (currentlyDeployedBasePolicyIDs.Contains(selectedPolicy.BasePolicyID))
					{
						// Create and display a ContentDialog with Yes and No options
						ContentDialog dialog = new()
						{
							Title = GlobalVars.Rizz.GetString("WarningTitle"),
							Content = GlobalVars.Rizz.GetString("ManualRemovalWarning") + GlobalVars.AppControlManagerSpecialPolicyName + "' " + GlobalVars.Rizz.GetString("ManualRemovalWarningEnd"),
							PrimaryButtonText = GlobalVars.Rizz.GetString("Yes"),
							BorderBrush = Application.Current.Resources["AccentFillColorDefaultBrush"] as Brush ?? new SolidColorBrush(Colors.Transparent),
							BorderThickness = new Thickness(1),
							CloseButtonText = GlobalVars.Rizz.GetString("No"),
							XamlRoot = this.XamlRoot // Set XamlRoot to the current page's XamlRoot
						};

						App.CurrentlyOpenContentDialog = dialog;

						// Show the dialog and wait for user response
						ContentDialogResult result = await dialog.ShowAsync();

						// If the user did not select "Yes", return from the method
						if (result is not ContentDialogResult.Primary)
						{
							return;
						}

					}
				}

				// Add the policy to the removal list
				policiesToRemove.Add(selectedPolicy);

				#region


				// If the policy that's going to be removed is a base policy
				if (string.Equals(selectedPolicy.PolicyID, selectedPolicy.BasePolicyID, StringComparison.OrdinalIgnoreCase))
				{
					// Check if it's unsigned, Or it is signed but doesn't have the "Enabled:Unsigned System Integrity Policy" rule option
					// Meaning it was re-signed in unsigned mode and can be now safely removed
					if (!selectedPolicy.IsSignedPolicy || (selectedPolicy.IsSignedPolicy && selectedPolicy.PolicyOptions is not null && selectedPolicy.PolicyOptionsDisplay.Contains("Enabled:Unsigned System Integrity Policy", StringComparison.OrdinalIgnoreCase)))
					{
						// Find any automatic AppControlManagerSupplementalPolicy that is associated with it and still on the system
						List<CiPolicyInfo> extraPoliciesToRemove = [.. currentlyDeployedAppControlManagerSupplementalPolicies.Where(p => string.Equals(p.BasePolicyID, selectedPolicy.PolicyID, StringComparison.OrdinalIgnoreCase) && p.IsOnDisk)];

						if (extraPoliciesToRemove.Count > 0)
						{
							foreach (CiPolicyInfo item in extraPoliciesToRemove)
							{
								policiesToRemove.Add(item);
							}
						}
					}
				}

				#endregion

				// If there are policies to be removed
				if (policiesToRemove.Count > 0)
				{

					DirectoryInfo stagingArea = StagingArea.NewStagingArea("PolicyRemoval");


					foreach (CiPolicyInfo policy in policiesToRemove)
					{
						// Remove the policy directly from the system if it's unsigned or supplemental
						if (!policy.IsSignedPolicy || !string.Equals(policy.PolicyID, policy.BasePolicyID, StringComparison.OrdinalIgnoreCase))
						{
							await Task.Run(() =>
							{
								CiToolHelper.RemovePolicy(policy.PolicyID!);
							});
						}

						// At this point the policy is definitely a Signed Base policy
						else
						{
							// If the EnabledUnsignedSystemIntegrityPolicy policy rule option exists
							// Which means 1st stage already happened
							if (policy.PolicyOptions is not null && policy.PolicyOptionsDisplay.Contains("Enabled:Unsigned System Integrity Policy", StringComparison.OrdinalIgnoreCase))
							{
								// And if system was rebooted once after performing the 1st removal stage
								if (VerifyRemovalEligibility(policy.PolicyID!))
								{
									CiToolHelper.RemovePolicy(policy.PolicyID!);

									// Remove the PolicyID from the SignedPolicyStage1RemovalTimes dictionary
									UserConfiguration.RemoveSignedPolicyStage1RemovalTime(policy.PolicyID!);
								}
								else
								{
									// Create and display a ContentDialog
									ContentDialog dialog = new()
									{
										Title = GlobalVars.Rizz.GetString("WarningTitle"),
										Content = GlobalVars.Rizz.GetString("RestartRequired") + policy.FriendlyName + "' " + GlobalVars.Rizz.GetString("RestartRequiredEnd") + policy.PolicyID + "' you must restart your system.",
										PrimaryButtonText = GlobalVars.Rizz.GetString("Understand"),
										BorderBrush = Application.Current.Resources["AccentFillColorDefaultBrush"] as Brush ?? new SolidColorBrush(Colors.Transparent),
										BorderThickness = new Thickness(1),
										XamlRoot = this.XamlRoot // Set XamlRoot to the current page's XamlRoot
									};

									App.CurrentlyOpenContentDialog = dialog;

									// Show the dialog and wait for user response
									_ = await dialog.ShowAsync();

									// Exit the method, nothing more can be done about the selected policy
									return;
								}
							}

							// Treat it as a new signed policy removal
							else
							{

								#region Signing Details acquisition

								string CertCN;
								string CertPath;
								string SignToolPath;
								string XMLPolicyPath;

								// Instantiate the Content Dialog
								SigningDetailsDialogForRemoval customDialog = new(currentlyDeployedBasePolicyIDs, policy.PolicyID!);

								App.CurrentlyOpenContentDialog = customDialog;

								// Show the dialog and await its result
								ContentDialogResult result = await customDialog.ShowAsync();

								// Ensure primary button was selected
								if (result is ContentDialogResult.Primary)
								{
									SignToolPath = customDialog.SignToolPath!;
									CertPath = customDialog.CertificatePath!;
									CertCN = customDialog.CertificateCommonName!;
									XMLPolicyPath = customDialog.XMLPolicyPath!;

									// Sometimes the content dialog lingers on or re-appears so making sure it hides
									customDialog.Hide();

								}
								else
								{
									return;
								}

								#endregion

								// Add the unsigned policy rule option to the policy
								CiRuleOptions.Set(filePath: XMLPolicyPath, rulesToAdd: [SiPolicy.OptionType.EnabledUnsignedSystemIntegrityPolicy]);

								// Making sure SupplementalPolicySigners do not exist in the XML policy
								CiPolicyHandler.RemoveSupplementalSigners(XMLPolicyPath);

								// Define the path for the CIP file
								string randomString = GUIDGenerator.GenerateUniqueGUID();
								string xmlFileName = Path.GetFileName(XMLPolicyPath);
								string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

								string CIPp7SignedFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip.p7");

								// Convert the XML file to CIP, overwriting the unsigned one
								PolicyToCIPConverter.Convert(XMLPolicyPath, CIPFilePath);

								// Sign the CIP
								SignToolHelper.Sign(new FileInfo(CIPFilePath), new FileInfo(SignToolPath), CertCN);

								// Rename the .p7 signed file to .cip
								File.Move(CIPp7SignedFilePath, CIPFilePath, true);

								// Deploy the signed CIP file
								CiToolHelper.UpdatePolicy(CIPFilePath);

								SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(XMLPolicyPath, null);

								// The time of first stage of the signed policy removal
								// Since policy object has the full ID, in upper case with curly brackets,
								// We need to normalize them to match what the CiPolicyInfo class uses
								UserConfiguration.AddSignedPolicyStage1RemovalTime(policyObj.PolicyID.Trim('{', '}').ToLowerInvariant(), DateTime.UtcNow);
							}
						}
					}
				}
			}
		}
		finally
		{
			// Refresh the ListView's policies and their count
			RetrievePolicies();

			DeployedPolicies.IsHitTestVisible = true;
			RetrievePoliciesButton.IsEnabled = true;
			SearchBox.IsEnabled = true;
		}
	}


#pragma warning disable CA1822

	/// <summary>
	/// Event handler to prevent the MenuFlyout to automatically close immediately after selecting a checkbox or any button in it
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void MenuFlyout_Closing(FlyoutBase sender, FlyoutBaseClosingEventArgs args)
	{
		if (sender is MenuFlyoutV2 { IsPointerOver: true })
		{
			args.Cancel = true;
		}
	}

#pragma warning restore CA1822


	/// <summary>
	/// If returns true, the signed policy can be removed
	/// </summary>
	/// <param name="policyID"></param>
	/// <returns></returns>
	private static bool VerifyRemovalEligibility(string policyID)
	{
		// When system was last reboot
		DateTime lastRebootTimeUtc = DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);

		Logger.Write(GlobalVars.Rizz.GetString("LastRebootTime") + lastRebootTimeUtc + " (UTC)");

		// When the policy's 1st stage was completed
		DateTime? stage1RemovalTime = UserConfiguration.QuerySignedPolicyStage1RemovalTime(policyID);

		if (stage1RemovalTime is not null)
		{
			Logger.Write(GlobalVars.Rizz.GetString("PolicyStage1Completed") + policyID + "' " + GlobalVars.Rizz.GetString("CompletedAt") + stage1RemovalTime + " (UTC)");

			if (stage1RemovalTime < lastRebootTimeUtc)
			{
				Logger.Write(GlobalVars.Rizz.GetString("PolicySafeToRemove"));

				return true;
			}
		}

		return false;
	}


	/// <summary>
	/// Event handler for when the Swap Policy ComboBox's selection changes
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void SwapPolicyComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		if (selectedPolicy is null)
		{
			return;
		}

		bool reEnableButtonAtTheEnd = true;

		try
		{
			SwapPolicyComboBox.IsEnabled = false;
			RemovePolicyButton.IsEnabled = false;
			RetrievePoliciesButton.IsEnabled = false;
			SearchBox.IsEnabled = false;
			DeployedPolicies.IsEnabled = false;

			string policyID = selectedPolicy.PolicyID!.ToString();

			TextBlock formattedTextBlock = new()
			{
				TextWrapping = TextWrapping.WrapWholeWords,
				IsTextSelectionEnabled = true
			};

			SolidColorBrush violetBrush = new(Colors.Violet);
			SolidColorBrush hotPinkBrush = new(Colors.HotPink);

			// Create normal text runs
			Run normalText1 = new() { Text = GlobalVars.Rizz.GetString("SelectedPolicyName") };
			Run normalText2 = new() { Text = GlobalVars.Rizz.GetString("AndID") };
			Run normalText3 = new() { Text = GlobalVars.Rizz.GetString("WillBeChangedTo") };
			Run normalText4 = new() { Text = GlobalVars.Rizz.GetString("PolicyRedeployInfo") };

			// Create colored runs
			Run accentPolicyName = new() { Text = selectedPolicy.FriendlyName, Foreground = violetBrush };
			Run accentPolicyID = new() { Text = policyID, Foreground = violetBrush };
			Run accentPolicyType = new() { Text = (string)SwapPolicyComboBox.SelectedItem, Foreground = hotPinkBrush };

			// Create bold text run
			Bold boldText = new();
			boldText.Inlines.Add(new Run() { Text = GlobalVars.Rizz.GetString("SupplementalPolicyContinues") });

			// Add runs to the TextBlock
			formattedTextBlock.Inlines.Add(normalText1);
			formattedTextBlock.Inlines.Add(accentPolicyName);
			formattedTextBlock.Inlines.Add(normalText2);
			formattedTextBlock.Inlines.Add(accentPolicyID);
			formattedTextBlock.Inlines.Add(normalText3);
			formattedTextBlock.Inlines.Add(accentPolicyType);
			formattedTextBlock.Inlines.Add(new LineBreak());
			formattedTextBlock.Inlines.Add(new LineBreak());
			formattedTextBlock.Inlines.Add(normalText4);
			formattedTextBlock.Inlines.Add(new LineBreak());
			formattedTextBlock.Inlines.Add(new LineBreak());
			formattedTextBlock.Inlines.Add(boldText);

			// Create and display a ContentDialog with styled TextBlock
			ContentDialog dialog = new()
			{
				Title = GlobalVars.Rizz.GetString("SwappingPolicyTitle"),
				Content = formattedTextBlock,
				PrimaryButtonText = GlobalVars.Rizz.GetString("OK"),
				BorderBrush = Application.Current.Resources["AccentFillColorDefaultBrush"] as Brush ?? new SolidColorBrush(Colors.Transparent),
				BorderThickness = new Thickness(1),
				CloseButtonText = GlobalVars.Rizz.GetString("Cancel"),
				XamlRoot = this.XamlRoot // Set XamlRoot to the current page's XamlRoot
			};

			App.CurrentlyOpenContentDialog = dialog;

			// Show the dialog and wait for user response
			ContentDialogResult result = await dialog.ShowAsync();

			// If the user did not select "OK", return from the method
			if (result is not ContentDialogResult.Primary)
			{
				reEnableButtonAtTheEnd = false;
				return;
			}

			int selectedIndex = SwapPolicyComboBox.SelectedIndex;

			await Task.Run(() =>
			{

				string stagingArea = StagingArea.NewStagingArea("PolicySwapping").FullName;

				switch (selectedIndex)
				{
					case 0: // Default Windows
						{
							BasePolicyCreator.BuildDefaultWindows(
							StagingArea: stagingArea,
							IsAudit: false,
							LogSize: null,
							deploy: true,
							RequireEVSigners: false,
							EnableScriptEnforcement: false,
							TestMode: false,
							deployAppControlSupplementalPolicy: false,
							PolicyIDToUse: policyID,
							DeployMicrosoftRecommendedBlockRules: false
							);

							break;
						}
					case 1: // Allow Microsoft
						{
							BasePolicyCreator.BuildAllowMSFT(
							StagingArea: stagingArea,
							IsAudit: false,
							LogSize: null,
							deploy: true,
							RequireEVSigners: false,
							EnableScriptEnforcement: false,
							TestMode: false,
							deployAppControlSupplementalPolicy: false,
							PolicyIDToUse: policyID,
							DeployMicrosoftRecommendedBlockRules: false
							);

							break;
						}
					case 2: // Signed and Reputable
						{
							BasePolicyCreator.BuildSignedAndReputable(
							StagingArea: stagingArea,
							IsAudit: false,
							LogSize: null,
							deploy: true,
							RequireEVSigners: false,
							EnableScriptEnforcement: false,
							TestMode: false,
							deployAppControlSupplementalPolicy: false,
							PolicyIDToUse: policyID,
							DeployMicrosoftRecommendedBlockRules: false
							);

							break;
						}
					case 3: // Strict Kernel-Mode
						{
							BasePolicyCreator.BuildStrictKernelMode(
								StagingArea: stagingArea,
								IsAudit: false,
								NoFlightRoots: false,
								deploy: true,
								PolicyIDToUse: policyID);

							break;
						}
					case 4: // Strict Kernel-Mode(No Flight Roots)
						{
							BasePolicyCreator.BuildStrictKernelMode(
								StagingArea: stagingArea,
								IsAudit: false,
								NoFlightRoots: true,
								deploy: true,
								PolicyIDToUse: policyID);

							break;
						}
					default:
						{
							break;
						}
				}
			});
		}
		finally
		{
			// Refresh the ListView's policies and their count
			RetrievePolicies();

			if (reEnableButtonAtTheEnd)
			{
				SwapPolicyComboBox.IsEnabled = true;
			}

			RemovePolicyButton.IsEnabled = true;
			RetrievePoliciesButton.IsEnabled = true;
			SearchBox.IsEnabled = true;
			DeployedPolicies.IsEnabled = true;
		}
	}


	#region Ensuring right-click on rows behaves better and normally on ListView

	// When right-clicking on an unselected row, first it becomes selected and then the context menu will be shown for the selected row
	// This is a much more expected behavior. Without this, the right-click would be meaningless on the ListView unless user left-clicks on the row first

	private void ListView_ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		// When the container is being recycled, detach the handler.
		if (args.InRecycleQueue)
		{
			args.ItemContainer.RightTapped -= ListViewItem_RightTapped;
		}
		else
		{
			// Detach first to avoid multiple subscriptions, then attach the handler.
			args.ItemContainer.RightTapped -= ListViewItem_RightTapped;
			args.ItemContainer.RightTapped += ListViewItem_RightTapped;
		}
	}


	private void ListViewItem_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		// Cast the sender to a ListViewItem.
		if (sender is ListViewItem item)
		{
			// If the item isn't already selected, clear existing selections
			// and mark this item as selected.
			if (!item.IsSelected)
			{
				// Set the counter so that the SelectionChanged event handler will ignore the next 2 events.
				_skipSelectionChangedCount = 2;

				item.IsSelected = true;
			}
		}
	}


	#endregion


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
	/// Event handler for when F5 is pressed to refresh the policies
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void F5_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		RetrievePolicies();
	}
}
