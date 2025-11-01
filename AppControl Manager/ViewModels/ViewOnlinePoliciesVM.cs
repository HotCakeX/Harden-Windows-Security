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
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.MicrosoftGraph;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class ViewOnlinePoliciesVM : ViewModelBase, IGraphAuthHost, IDisposable
{

	#region MICROSOFT GRAPH IMPLEMENTATION DETAILS

	public AuthenticationCompanion AuthCompanionCLS { get; private set; }

	private void UpdateButtonsStates(bool on)
	{
		// Enable the retrieve button if a valid value is set as Active Account
		AreElementsEnabled = on;
	}

	/// <summary>
	/// Automatically provided via constructor injection by the DI container during build.
	/// </summary>
	/// <param name="GraphVM">The view model instance used to manage data and state related to Microsoft Graph.</param>
	internal ViewOnlinePoliciesVM()
	{
		AuthCompanionCLS = new(UpdateButtonsStates, new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher), AuthenticationContext.Intune);

		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// To adjust the initial width of the columns, giving them nice paddings.
		CalculateColumnWidths();
	}

	#endregion MICROSOFT GRAPH IMPLEMENTATION DETAILS

	internal readonly InfoBarSettings MainInfoBar;

	#region UI-Bound Properties

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal CiPolicyInfo? ListViewSelectedPolicy { get; set => SP(ref field, value); }

	internal int ListViewSelectedIndex { get; set => SP(ref field, value); }

	internal string? SearchBoxTextBox { get; set => SPT(ref field, value); }

	/// <summary>
	/// Determines whether the UI elements are enabled or disabled.
	/// </summary>
	public bool AreElementsEnabled { get; set => SP(ref field, value); } = true;

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
			AreElementsEnabled = false;

			AllPoliciesOutput.Clear();
			AllPolicies.Clear();

			if (AuthCompanionCLS.CurrentActiveAccount is null)
				return;

			DeviceConfigurationPoliciesResponse? result = await MicrosoftGraph.Main.RetrieveDeviceConfigurations(AuthCompanionCLS.CurrentActiveAccount);

			if (result is not null && result.Value is not null)
			{

				// Only keep App Control policies
				IEnumerable<Windows10CustomConfiguration> filteredResults = result.Value.Where(policy =>
					policy.OmaSettings != null
					&& policy.OmaSettings.Any(setting => setting.OmaUri?.Contains(@"Vendor/MSFT/ApplicationControl", StringComparison.OrdinalIgnoreCase) == true
					));

				foreach (Windows10CustomConfiguration item in filteredResults)
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
			AreElementsEnabled = true;
		}
	}

	#region Sort

	private ListViewHelper.SortState SortState { get; set; } = new();

	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			// Look up the mapping in the reusable property mappings dictionary.
			if (ViewCurrentPoliciesVM.CiPolicyInfoPropertyMappings.TryGetValue(key, out (string Label, Func<CiPolicyInfo, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					keySelector: mapping.Getter,
					searchBoxText: SearchBoxTextBox,
					originalList: AllPoliciesOutput,
					observableCollection: AllPolicies,
					sortState: SortState,
					newKey: key,
					regKey: ListViewHelper.ListViewsRegistry.Online_Deployed_Policies);
			}
		}
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
			ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.Online_Deployed_Policies);

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
				p.IsSignedPolicy.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				(p.PolicyOptionsDisplay?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)
				);
			});

			AllPolicies.Clear();

			// Update the ObservableCollection with the filtered results
			foreach (CiPolicyInfo item in filteredResults)
			{
				AllPolicies.Add(item);
			}

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

			AreElementsEnabled = false;

			await MicrosoftGraph.Main.DeletePolicy(
				AuthCompanionCLS.CurrentActiveAccount,
				ListViewSelectedPolicy.IntunePolicyObjectID);

			MainInfoBar.WriteInfo($"Successfully removed the policy with the name '{ListViewSelectedPolicy.FriendlyName}' and ID '{ListViewSelectedPolicy.PolicyID}' from Intune.");

			// Remove the policy from the Lists after removal from Intune
			_ = AllPolicies.Remove(ListViewSelectedPolicy);
			_ = AllPoliciesOutput.Remove(ListViewSelectedPolicy);
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

	/// <summary>
	/// Converts the properties of a CiPolicyInfo row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	internal void CopySelectedPolicies_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Online_Deployed_Policies);

		if (lv is null) return;

		if (lv.SelectedItems.Count > 0)
		{
			// SelectedItems is an IList, and contains CiPolicyInfo
			ListViewHelper.ConvertRowToText(lv.SelectedItems, ViewCurrentPoliciesVM.CiPolicyInfoPropertyMappings);
		}
	}

	/// <summary>
	/// Copy a single property of the current selection
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void CopyPolicyProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Online_Deployed_Policies);

		if (lv is null) return;

		if (ViewCurrentPoliciesVM.CiPolicyInfoPropertyMappings.TryGetValue(key, out var map))
		{
			// TElement = CiPolicyInfo, copy just that one property
			ListViewHelper.CopyToClipboard<CiPolicyInfo>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

	public void Dispose()
	{
		// Dispose the AuthenticationCompanion which implements IDisposable
		AuthCompanionCLS.Dispose();
	}
}
