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

namespace AppControlManager.ViewModels;

internal sealed partial class ViewOnlinePoliciesVM : ViewModelBase, IDisposable
{

	#region MICROSOFT GRAPH IMPLEMENTATION DETAILS

	/// <summary>
	/// To store the view model of the MS Graph that is retrieved from the constructor
	/// </summary>
	internal readonly ViewModelForMSGraph _ViewModelMSGraph;

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
	internal ViewOnlinePoliciesVM(ViewModelForMSGraph GraphVM)
	{
		_ViewModelMSGraph = GraphVM;

		AuthCompanionCLS = new(UpdateButtonsStates, new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value), AuthenticationContext.Intune);

		_ViewModelMSGraph.AuthenticatedAccounts.CollectionChanged += AuthCompanionCLS.AuthenticatedAccounts_CollectionChanged;

		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			null, null);
	}

	#endregion MICROSOFT GRAPH IMPLEMENTATION DETAILS

	internal readonly InfoBarSettings MainInfoBar;

	#region UI-Bound Properties

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal bool ListViewState { get; set => SP(ref field, value); } = true;

	internal bool SearchTextBoxState { get; set => SP(ref field, value); } = true;

	internal bool RetrievePoliciesButtonState { get; set => SP(ref field, value); }

	internal CiPolicyInfo? ListViewSelectedPolicy { get; set => SP(ref field, value); }

	internal int ListViewSelectedIndex { get; set => SP(ref field, value); }

	internal string PoliciesCountTextBox { get; set => SP(ref field, value); } = "Number of Policies: 0";

	internal string? SearchBoxTextBox { get; set => SP(ref field, value); }

	internal bool RemovePolicyButtonState { get; set => SP(ref field, value); }

	#endregion

	// To store the policies displayed on the ListView
	internal readonly ObservableCollection<CiPolicyInfo> AllPolicies = [];

	// Store all outputs for searching
	internal readonly List<CiPolicyInfo> AllPoliciesOutput = [];


	#region Properties to hold each columns' width.

	internal GridLength ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth6 { get; set => SP(ref field, value); }

	#endregion


	internal void DeployedPolicies_SelectionChanged()
	{
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
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("PolicyIDHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("BasePolicyIDHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("FriendlyNameHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("VersionHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("IsSignedPolicyHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.GetStr("PolicyOptionsHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (CiPolicyInfo item in AllPolicies)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.PolicyID, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.BasePolicyID, maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.FriendlyName, maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.VersionString, maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.IsSignedPolicy.ToString(), maxWidth5);
			maxWidth6 = ListViewHelper.MeasureText(item.PolicyOptionsDisplay, maxWidth6);
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

				// Only keep App Control policies
				IEnumerable<DeviceConfigurationPolicy> filteredResults = result.Value.Where(policy =>
					policy.OmaSettings != null
					&& policy.OmaSettings.Any(setting => setting.OmaUri?.Contains(@"Vendor/MSFT/ApplicationControl", StringComparison.OrdinalIgnoreCase) == true
					));

				foreach (DeviceConfigurationPolicy item in filteredResults)
				{

					(bool, CiPolicyInfo?) policyResult = CiPolicyInfo.FromJson(item.Description);

					// If the JSON was successfully deserialized
					if (policyResult.Item1)
					{

						if (policyResult.Item2 is null)
						{
							throw new InvalidOperationException(
								GlobalVars.GetStr("IntunePolicyDeserializedButEmptyMessage"));
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
									Logger.Write(string.Format(
										GlobalVars.GetStr("ErrorParsingRuleOptionMessage"),
										item2,
										ex.Message));

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
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			// Update the policies count text
			PoliciesCountTextBox = string.Format(
				GlobalVars.GetStr("NumberOfPoliciesMessage"),
				AllPolicies.Count);

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

		// Get the ListView ScrollViewer info
		ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.Locally_Deployed_Policies);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

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

			if (Sv != null && savedHorizontal.HasValue)
			{
				// restore horizontal scroll position
				_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
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
		try
		{

			string? searchTerm = SearchBoxTextBox?.Trim();

			if (searchTerm is null)
				return;

			// Get the ListView ScrollViewer info
			ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.Locally_Deployed_Policies);

			double? savedHorizontal = null;
			if (Sv != null)
			{
				savedHorizontal = Sv.HorizontalOffset;
			}


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
			PoliciesCountTextBox = GlobalVars.GetStr("NumberOfPolicies") + AllPolicies.Count;

			if (Sv != null && savedHorizontal.HasValue)
			{
				// restore horizontal scroll position
				_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}


	/// <summary>
	/// Event handler for the RemovePolicyButton click
	/// </summary>
	internal async void RemovePolicy_Click()
	{
		if (ListViewSelectedPolicy is null)
			return;

		try
		{

			MainInfoBarIsClosable = false;

			if (ListViewSelectedPolicy.IntunePolicyObjectID is null)
			{
				throw new InvalidOperationException(
					GlobalVars.GetStr("IntunePolicyObjectIdNullMessage"));
			}

			ManageButtonsStates(false);

			await MicrosoftGraph.Main.DeletePolicy(
				AuthCompanionCLS.CurrentActiveAccount,
				ListViewSelectedPolicy.IntunePolicyObjectID);

			MainInfoBar.WriteInfo($"Successfully removed the policy with the name '{ListViewSelectedPolicy.FriendlyName}' and ID '{ListViewSelectedPolicy.PolicyID}' from Intune.");

			// Remove the policy from the Lists after removal from Intune
			_ = AllPolicies.Remove(ListViewSelectedPolicy);
			_ = AllPoliciesOutput.Remove(ListViewSelectedPolicy);

			// Update the policies count text
			PoliciesCountTextBox =
				GlobalVars.GetStr("NumberOfPolicies") + AllPolicies.Count;
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManageButtonsStates(true);
			MainInfoBarIsClosable = true;
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
			.AppendLine(GlobalVars.GetStr("PolicyIDLabel") + row.PolicyID)
			.AppendLine(GlobalVars.GetStr("BasePolicyIDLabel") + row.BasePolicyID)
			.AppendLine(GlobalVars.GetStr("FriendlyNameLabel") + row.FriendlyName)
			.AppendLine(GlobalVars.GetStr("VersionLabel/Text") + row.VersionString)
			.AppendLine(GlobalVars.GetStr("IsSignedPolicyLabel") + row.IsSignedPolicy)
			.AppendLine(GlobalVars.GetStr("PolicyOptionsLabel") + row.PolicyOptionsDisplay)
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

			ClipboardManagement.CopyText(dataBuilder.ToString());
		}
	}

	// Click event handlers for each property
	internal void CopyPolicyID_Click() => CopyToClipboard((item) => item.PolicyID?.ToString());
	internal void CopyBasePolicyID_Click() => CopyToClipboard((item) => item.BasePolicyID?.ToString());
	internal void CopyFriendlyName_Click() => CopyToClipboard((item) => item.FriendlyName);
	internal void CopyVersion_Click() => CopyToClipboard((item) => item.VersionString);
	internal void CopyIsSignedPolicy_Click() => CopyToClipboard((item) => item.IsSignedPolicy.ToString());
	internal void CopyPolicyOptionsDisplay_Click() => CopyToClipboard((item) => item.PolicyOptionsDisplay);

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
			ClipboardManagement.CopyText(propertyValue);
		}
	}

	public void Dispose()
	{
		try
		{
			// Unsubscribe from the collection changed event to prevent memory leaks
			_ViewModelMSGraph.AuthenticatedAccounts.CollectionChanged -= AuthCompanionCLS.AuthenticatedAccounts_CollectionChanged;
		}
		catch { }

		// Dispose the AuthenticationCompanion which implements IDisposable
		AuthCompanionCLS?.Dispose();
	}
}
