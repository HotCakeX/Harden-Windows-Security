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
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.MicrosoftGraph;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812, CA1822 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class ViewOnlinePoliciesVM : ViewModelBase
{

	#region ✡️✡️✡️✡️✡️✡️✡️ MICROSOFT GRAPH IMPLEMENTATION DETAILS ✡️✡️✡️✡️✡️✡️✡️

	/// <summary>
	/// To store the view model of the MS Graph that is retrieved from the constructor
	/// </summary>
	private readonly ViewModel _ViewModelMSGraph;

	internal readonly AuthenticationCompanion AuthCompanionCLS;

	private void UpdateButtonsStates(bool on)
	{
		// Enable the retrieve button whenever a value is set as Active account
		RetrievePoliciesButtonState = on;
	}

	/// <summary>
	/// Automatically provided via constructor injection by the DI container during build.
	/// </summary>
	/// <param name="GraphVM">The view model instance used to manage data and state related to Microsoft Graph.</param>
	internal ViewOnlinePoliciesVM(ViewModel GraphVM)
	{
		_ViewModelMSGraph = GraphVM;

		AuthCompanionCLS = new(UpdateButtonsStates, new InfoBarSettings(
			() => MainInfoBarVisibility, value => MainInfoBarVisibility = value,
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value), AuthenticationContext.Intune);

		_ViewModelMSGraph.AuthenticatedAccounts.CollectionChanged += AuthCompanionCLS.AuthenticatedAccounts_CollectionChanged;
	}

	#endregion ✡️✡️✡️✡️✡️✡️✡️ MICROSOFT GRAPH IMPLEMENTATION DETAILS ✡️✡️✡️✡️✡️✡️✡️


	#region UI-Bound Properties

	private Visibility _MainInfoBarVisibility = Visibility.Collapsed;
	internal Visibility MainInfoBarVisibility
	{
		get => _MainInfoBarVisibility;
		set => SetProperty(_MainInfoBarVisibility, value, newValue => _MainInfoBarVisibility = newValue);
	}

	private bool _MainInfoBarIsOpen;
	internal bool MainInfoBarIsOpen
	{
		get => _MainInfoBarIsOpen;
		set => SetProperty(_MainInfoBarIsOpen, value, newValue => _MainInfoBarIsOpen = newValue);
	}

	private string? _MainInfoBarMessage;
	internal string? MainInfoBarMessage
	{
		get => _MainInfoBarMessage;
		set => SetProperty(_MainInfoBarMessage, value, newValue => _MainInfoBarMessage = newValue);
	}

	private InfoBarSeverity _MainInfoBarSeverity = InfoBarSeverity.Informational;
	internal InfoBarSeverity MainInfoBarSeverity
	{
		get => _MainInfoBarSeverity;
		set => SetProperty(_MainInfoBarSeverity, value, newValue => _MainInfoBarSeverity = newValue);
	}

	private bool _MainInfoBarIsClosable;
	internal bool MainInfoBarIsClosable
	{
		get => _MainInfoBarIsClosable;
		set => SetProperty(_MainInfoBarIsClosable, value, newValue => _MainInfoBarIsClosable = newValue);
	}


	private bool _ListViewState = true;
	internal bool ListViewState
	{
		get => _ListViewState;
		set => SetProperty(_ListViewState, value, newValue => _ListViewState = newValue);
	}

	private bool _SearchTextBoxState = true;
	internal bool SearchTextBoxState
	{
		get => _SearchTextBoxState;
		set => SetProperty(_SearchTextBoxState, value, newValue => _SearchTextBoxState = newValue);
	}

	private bool _RetrievePoliciesButtonState;
	internal bool RetrievePoliciesButtonState
	{
		get => _RetrievePoliciesButtonState;
		set => SetProperty(_RetrievePoliciesButtonState, value, newValue => _RetrievePoliciesButtonState = newValue);
	}

	private CiPolicyInfo? _ListViewSelectedPolicy;
	internal CiPolicyInfo? ListViewSelectedPolicy
	{
		get => _ListViewSelectedPolicy;
		set => SetProperty(_ListViewSelectedPolicy, value, newValue => _ListViewSelectedPolicy = newValue);
	}

	private int _ListViewSelectedIndex;
	internal int ListViewSelectedIndex
	{
		get => _ListViewSelectedIndex;
		set => SetProperty(_ListViewSelectedIndex, value, newValue => _ListViewSelectedIndex = newValue);
	}

	private string _PoliciesCountTextBox = "Number of Policies: 0";
	internal string PoliciesCountTextBox
	{
		get => _PoliciesCountTextBox;
		set => SetProperty(_PoliciesCountTextBox, value, newValue => _PoliciesCountTextBox = newValue);
	}

	private string? _SearchBoxTextBox;
	internal string? SearchBoxTextBox
	{
		get => _SearchBoxTextBox;
		set => SetProperty(_SearchBoxTextBox, value, newValue => _SearchBoxTextBox = newValue);
	}

	private bool _RemovePolicyButtonState;
	internal bool RemovePolicyButtonState
	{
		get => _RemovePolicyButtonState;
		set => SetProperty(_RemovePolicyButtonState, value, newValue => _RemovePolicyButtonState = newValue);
	}

	#endregion

	// To store the policies displayed on the ListView
	internal readonly ObservableCollection<CiPolicyInfo> AllPolicies = [];

	// Store all outputs for searching
	internal readonly List<CiPolicyInfo> AllPoliciesOutput = [];


	#region Properties to hold each columns' width.
	private GridLength _columnWidth1;
	internal GridLength ColumnWidth1
	{
		get => _columnWidth1;
		set { _columnWidth1 = value; OnPropertyChanged(nameof(ColumnWidth1)); }
	}

	private GridLength _columnWidth2;
	internal GridLength ColumnWidth2
	{
		get => _columnWidth2;
		set { _columnWidth2 = value; OnPropertyChanged(nameof(ColumnWidth2)); }
	}

	private GridLength _columnWidth3;
	internal GridLength ColumnWidth3
	{
		get => _columnWidth3;
		set { _columnWidth3 = value; OnPropertyChanged(nameof(ColumnWidth3)); }
	}

	private GridLength _columnWidth4;
	internal GridLength ColumnWidth4
	{
		get => _columnWidth4;
		set { _columnWidth4 = value; OnPropertyChanged(nameof(ColumnWidth4)); }
	}

	private GridLength _columnWidth5;
	internal GridLength ColumnWidth5
	{
		get => _columnWidth5;
		set { _columnWidth5 = value; OnPropertyChanged(nameof(ColumnWidth5)); }
	}

	private GridLength _columnWidth6;
	internal GridLength ColumnWidth6
	{
		get => _columnWidth6;
		set { _columnWidth6 = value; OnPropertyChanged(nameof(ColumnWidth6)); }
	}

	#endregion


	internal async void DeployedPolicies_SelectionChanged()
	{

		// Check if we need to skip this event.
		if (_skipSelectionChangedCount > 0)
		{
			_skipSelectionChangedCount--;
			return;
		}

		await ListViewHelper.SmoothScrollIntoViewWithIndexCenterVerticallyOnlyAsync(listViewBase: Pages.ViewOnlinePolicies.Instance.ListViewElement, listView: Pages.ViewOnlinePolicies.Instance.ListViewElement, index: ListViewSelectedIndex, disableAnimation: false, scrollIfVisible: true, additionalHorizontalOffset: 0, additionalVerticalOffset: 0);


		if (ListViewSelectedPolicy is null)
		{
			return;
		}

		RemovePolicyButtonState = true;
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
		double maxWidth5 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsSignedPolicyHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PolicyOptionsHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (CiPolicyInfo item in AllPolicies)
		{
			double w1 = ListViewHelper.MeasureTextWidth(item.PolicyID);
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewHelper.MeasureTextWidth(item.BasePolicyID);
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewHelper.MeasureTextWidth(item.FriendlyName);
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewHelper.MeasureTextWidth(item.VersionString);
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewHelper.MeasureTextWidth(item.IsSignedPolicy.ToString());
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewHelper.MeasureTextWidth(item.PolicyOptionsDisplay);
			if (w6 > maxWidth6) maxWidth6 = w6;
		}

		// Set the column width properties.
		ColumnWidth1 = new GridLength(maxWidth1);
		ColumnWidth2 = new GridLength(maxWidth2);
		ColumnWidth3 = new GridLength(maxWidth3);
		ColumnWidth4 = new GridLength(maxWidth4);
		ColumnWidth5 = new GridLength(maxWidth5);
		ColumnWidth6 = new GridLength(maxWidth6);
	}



	/// <summary>
	/// Retrieves the online Intune policies
	/// </summary>
	internal async void GetOnlinePolicies()
	{
		try
		{
			ManageButtonsStates(false);

			AllPoliciesOutput.Clear();
			AllPolicies.Clear();

			if (AuthCompanionCLS.CurrentActiveAccount is null)
				return;

			DeviceConfigurationPoliciesResponse? result = await MicrosoftGraph.Main.RetrieveDeviceConfigurations(AuthCompanionCLS.CurrentActiveAccount);

			if (result is not null && result.Value is not null)
			{

				foreach (DeviceConfigurationPolicy item in result.Value)
				{

					(bool, CiPolicyInfo?) policyResult = CiPolicyInfo.FromJson(item.Description);

					// If the JSON was successfully deserialized
					if (policyResult.Item1)
					{

						if (policyResult.Item2 is null)
						{
							throw new InvalidOperationException("Intune policy was deserialized successfully but the relevant object is empty.");
						}

						if (policyResult.Item2.PolicyOptions is not null)
						{

							List<string> optionsToReplaceWith = [];

							foreach (string item2 in policyResult.Item2.PolicyOptions)
							{
								try
								{
									// Ensure the number has a value in the Enum
									if (int.TryParse(item2, out int index))
									{
										// Cast the number to the enum
										OptionType option = (OptionType)index;

										// Get the enum member name and add it to the list
										optionsToReplaceWith.Add(option.ToString());
									}
								}
								catch (Exception ex)
								{
									Logger.Write($"There was an error parsing {item2} rule option number to its string value: {ex.Message}");

									continue;
								}
							}

							// Replace the rule options number with their actual string names
							policyResult.Item2.PolicyOptions = optionsToReplaceWith;

							policyResult.Item2.OnlineParentViewModel = this;


							policyResult.Item2.IntunePolicyObjectID = item.Id;

							AllPolicies.Add(policyResult.Item2);
							AllPoliciesOutput.Add(policyResult.Item2);
						}
					}

					// If the custom Intune policy doesn't have the necessary details in its description then create an entry with its name only
					else
					{

						CiPolicyInfo policy = new(
											policyID: null,
											basePolicyID: null,
											friendlyName: item.DisplayName,
											version: null,
											versionString: null,
											isSystemPolicy: false,
											isSignedPolicy: false,
											isOnDisk: false,
											isEnforced: false,
											isAuthorized: false,
											policyOptions: null
										)
						{
							OnlineParentViewModel = this,
							IntunePolicyObjectID = item.Id
						};

						AllPolicies.Add(policy);
						AllPoliciesOutput.Add(policy);
					}
				}
			}

			CalculateColumnWidths();
		}
		finally
		{
			// Update the policies count text
			PoliciesCountTextBox = GlobalVars.Rizz.GetString("NumberOfPolicies") + AllPolicies.Count;

			ManageButtonsStates(true);
		}
	}


	/// <summary>
	/// Enable or Disable button states
	/// </summary>
	/// <param name="on">True will enable and False will disable UI buttons when an operation is ongoing</param>
	private void ManageButtonsStates(bool on)
	{
		RetrievePoliciesButtonState = on;
		SearchTextBoxState = on;
		ListViewState = on;
		RemovePolicyButtonState = on;
	}


	#region Sort

	/// <summary>
	/// Enum representing the sort columns for this view.
	/// </summary>
	private enum SortColumnEnum
	{
		PolicyID,
		BasePolicyID,
		FriendlyName,
		Version,
		IsSignedPolicy,
		PolicyOptions
	}


	// Current sorting state.
	private SortColumnEnum? _currentSortColumn;
	private bool _isDescending = true; // Always sort descending on new column selection.

	/// <summary>
	/// Common sort method using a column enum.
	/// </summary>
	/// <param name="newSortColumn">The column to sort by.</param>
	private async void Sort(SortColumnEnum newSortColumn)
	{
		// Toggle sort order if the same column is clicked again.
		if (_currentSortColumn.HasValue && _currentSortColumn.Value == newSortColumn)
		{
			_isDescending = !_isDescending;
		}
		else
		{
			_currentSortColumn = newSortColumn;
			_isDescending = true;
		}

		// Determine whether a search filter is active.
		bool isSearchEmpty = string.IsNullOrWhiteSpace(SearchBoxTextBox);

		List<CiPolicyInfo> sourceData = isSearchEmpty ? AllPoliciesOutput : AllPolicies.ToList();

		List<CiPolicyInfo> sortedData = [];

		switch (newSortColumn)
		{
			case SortColumnEnum.PolicyID:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.PolicyID).ToList()
					: sourceData.OrderBy(p => p.PolicyID).ToList();
				break;
			case SortColumnEnum.BasePolicyID:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.BasePolicyID).ToList()
					: sourceData.OrderBy(p => p.BasePolicyID).ToList();
				break;
			case SortColumnEnum.FriendlyName:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.FriendlyName).ToList()
					: sourceData.OrderBy(p => p.FriendlyName).ToList();
				break;
			case SortColumnEnum.Version:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.VersionString).ToList()
					: sourceData.OrderBy(p => p.VersionString).ToList();
				break;
			case SortColumnEnum.IsSignedPolicy:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.IsSignedPolicy).ToList()
					: sourceData.OrderBy(p => p.IsSignedPolicy).ToList();
				break;
			case SortColumnEnum.PolicyOptions:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.PolicyOptionsDisplay).ToList()
					: sourceData.OrderBy(p => p.PolicyOptionsDisplay).ToList();
				break;
			default:
				break;
		}

		// Update the ObservableCollection on the UI thread.
		await Dispatcher.EnqueueAsync(() =>
		{
			AllPolicies.Clear();
			foreach (CiPolicyInfo item in sortedData)
			{
				AllPolicies.Add(item);
			}
		});
	}

	// These methods are bound to the header buttons' Click events.
	internal void SortByPolicyID()
	{
		Sort(SortColumnEnum.PolicyID);
	}

	internal void SortByBasePolicyID()
	{
		Sort(SortColumnEnum.BasePolicyID);
	}

	internal void SortByFriendlyName()
	{
		Sort(SortColumnEnum.FriendlyName);
	}

	internal void SortByVersion()
	{
		Sort(SortColumnEnum.Version);
	}

	internal void SortByIsSignedPolicy()
	{
		Sort(SortColumnEnum.IsSignedPolicy);
	}

	internal void SortByPolicyOptions()
	{
		Sort(SortColumnEnum.PolicyOptions);
	}

	#endregion


	/// <summary>
	/// Event handler for the search box text change
	/// </summary>
	internal async void SearchBox_TextChanged()
	{
		string? searchTerm = SearchBoxTextBox?.Trim();

		if (searchTerm is null)
			return;

		IEnumerable<CiPolicyInfo> filteredResults = [];

		await Task.Run(() =>
		{
			// Perform a case-insensitive search in all relevant fields
			filteredResults = AllPoliciesOutput.Where(p =>
			(p.PolicyID?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.FriendlyName?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.VersionString?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.IsSignedPolicy.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(p.PolicyOptionsDisplay?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)
			);
		});

		AllPolicies.Clear();

		// Update the ObservableCollection with the filtered results
		foreach (CiPolicyInfo item in filteredResults)
		{
			AllPolicies.Add(item);
		}

		// Update the policies count text
		PoliciesCountTextBox = GlobalVars.Rizz.GetString("NumberOfPolicies") + AllPolicies.Count;
	}



	/// <summary>
	/// Event handler for the RemovePolicyButton click
	/// </summary>
	internal async void RemovePolicy_Click()
	{
		if (ListViewSelectedPolicy is null)
			return;

		if (ListViewSelectedPolicy.IntunePolicyObjectID is null)
		{
			throw new InvalidOperationException("Intune policy object ID was null for the selected policy to be deleted");
		}

		try
		{
			ManageButtonsStates(false);

			await MicrosoftGraph.Main.DeletePolicy(AuthCompanionCLS.CurrentActiveAccount, ListViewSelectedPolicy.IntunePolicyObjectID);

			// Remove the policy from the Lists after removal from Intune
			_ = AllPolicies.Remove(ListViewSelectedPolicy);
			_ = AllPoliciesOutput.Remove(ListViewSelectedPolicy);

			// Update the policies count text
			PoliciesCountTextBox = GlobalVars.Rizz.GetString("NumberOfPolicies") + AllPolicies.Count;
		}
		finally
		{
			ManageButtonsStates(true);
		}
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
			.AppendLine(GlobalVars.Rizz.GetString("VersionLabel") + row.VersionString)
			.AppendLine(GlobalVars.Rizz.GetString("IsSignedPolicyLabel") + row.IsSignedPolicy)
			.AppendLine(GlobalVars.Rizz.GetString("PolicyOptionsLabel") + row.PolicyOptionsDisplay)
			.ToString();
	}

	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	internal void ListViewFlyoutMenuCopy_Click()
	{
		// Check if there are selected items in the ListView
		if (ListViewSelectedPolicy is not null)
		{
			// Initialize StringBuilder to store all selected rows' data with labels
			StringBuilder dataBuilder = new();

			// Append each row's formatted data to the StringBuilder
			_ = dataBuilder.AppendLine(ConvertRowToText(ListViewSelectedPolicy));

			// Add a separator between rows for readability in multi-row copies
			_ = dataBuilder.AppendLine(ListViewHelper.DefaultDelimiter);

			// Create a DataPackage to hold the text data
			DataPackage dataPackage = new();

			// Set the formatted text as the content of the DataPackage
			dataPackage.SetText(dataBuilder.ToString());

			// Copy the DataPackage content to the clipboard
			Clipboard.SetContent(dataPackage);
		}
	}

	// Click event handlers for each property
	internal void CopyPolicyID_Click() => CopyToClipboard((item) => item.PolicyID?.ToString());
	internal void CopyBasePolicyID_Click() => CopyToClipboard((item) => item.BasePolicyID?.ToString());
	internal void CopyFriendlyName_Click() => CopyToClipboard((item) => item.FriendlyName);
	internal void CopyVersion_Click() => CopyToClipboard((item) => item.VersionString);
	internal void CopyIsSignedPolicy_Click() => CopyToClipboard((item) => item.IsSignedPolicy.ToString());
	internal void CopyPolicyOptionsDisplay_Click() => CopyToClipboard((item) => item.PolicyOptionsDisplay);

#pragma warning disable CA1822

	/// <summary>
	/// Helper method to copy a specified property to clipboard without reflection
	/// </summary>
	/// <param name="getProperty">Function that retrieves the desired property value as a string</param>
	private void CopyToClipboard(Func<CiPolicyInfo, string?> getProperty)
	{
		if (ListViewSelectedPolicy is null)
			return;

		string? propertyValue = getProperty(ListViewSelectedPolicy);
		if (propertyValue is not null)
		{
			DataPackage dataPackage = new();
			dataPackage.SetText(propertyValue);
			Clipboard.SetContent(dataPackage);
		}
	}

#pragma warning restore CA1822


	// A counter to prevent SelectionChanged event from firing twice when right-clicking on an unselected row
	internal int _skipSelectionChangedCount;
}
