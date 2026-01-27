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
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using CommonCore.MicrosoftGraph;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class ViewOnlinePoliciesVM : ViewModelBase, IGraphAuthHost, IDisposable
{

	#region MICROSOFT GRAPH IMPLEMENTATION DETAILS

	public AuthenticationCompanion AuthCompanionCLS { get; private set; }

	// Enable the retrieve button if a valid value is set as Active Account
	private void UpdateButtonsStates(bool on) => AreElementsEnabled = on;

	/// <summary>
	/// Automatically provided via constructor injection by the DI container during build.
	/// </summary>
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

		// Initialize the column manager with specific definitions for this page
		// We map the Key (for sorting/selection) to the Header Resource Key (for localization) and the Data Getter (for width measurement)
		ColumnManager = new ListViewColumnManager<CiPolicyInfo>(
		[
			new("PolicyID", "PolicyIDHeader/Text", x => x.PolicyID),
			new("BasePolicyID", "BasePolicyIDHeader/Text", x => x.BasePolicyID),
			new("FriendlyName", "FriendlyNameHeader/Text", x => x.FriendlyName),
			new("Version", "VersionHeader/Text", x => x.VersionString),
			new("IsSignedPolicy", "IsSignedPolicyHeader/Text", x => x.IsSignedPolicy.ToString()),
			new("PolicyOptions", "PolicyOptionsHeader/Text", x => x.PolicyOptionsDisplay)
		]);

		// To adjust the initial width of the columns, giving them nice paddings.
		ColumnManager.CalculateColumnWidths(AllPolicies);
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

	// The Column Manager Composition
	internal ListViewColumnManager<CiPolicyInfo> ColumnManager { get; }

	/// <summary>
	/// Event handler for the UI button.
	/// </summary>
	internal async void GetOnlinePolicies() => await GetOnlinePoliciesInternal();

	/// <summary>
	/// Retrieves the online Intune policies
	/// </summary>
	private async Task GetOnlinePoliciesInternal()
	{
		try
		{
			AreElementsEnabled = false;

			AllPoliciesOutput.Clear();
			AllPolicies.Clear();

			if (AuthCompanionCLS.CurrentActiveAccount is null)
				return;

			// Retrieve Custom Device Configurations
			DeviceConfigurationPoliciesResponse? result = await CommonCore.MicrosoftGraph.Main.RetrieveDeviceConfigurations(AuthCompanionCLS.CurrentActiveAccount);

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

							foreach (string item2 in CollectionsMarshal.AsSpan(policyResult.Item2.PolicyOptions))
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
							policyID: string.Empty,
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

			// Retrieve Managed Installer Policies (Device Health Scripts)
			List<DeviceHealthScript> managedInstallers = await CommonCore.MicrosoftGraph.Main.RetrieveDeviceHealthScripts(AuthCompanionCLS.CurrentActiveAccount);

			foreach (DeviceHealthScript script in managedInstallers)
			{
				CiPolicyInfo miPolicy = new(
					policyID: script.Id ?? string.Empty,
					basePolicyID: null,
					friendlyName: script.DisplayName,
					version: null,
					versionString: script.Version,
					isSystemPolicy: script.IsGlobalScript ?? false,
					isSignedPolicy: script.EnforceSignatureCheck ?? false,
					isOnDisk: false,
					isEnforced: true,
					isAuthorized: true,
					policyOptions: ["Managed Installer"]
				)
				{
					IntunePolicyObjectID = script.Id, // Using the Script ID as the Intune Object ID
					IsManagedInstaller = true
				};

				AllPolicies.Add(miPolicy);
				AllPoliciesOutput.Add(miPolicy);
			}

			await Task.Run(() => ColumnManager.CalculateColumnWidths(AllPolicies));
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
				p.PolicyID.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
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
			AreElementsEnabled = false;

			if (ListViewSelectedPolicy.IntunePolicyObjectID is null)
			{
				throw new InvalidOperationException(
					GlobalVars.GetStr("IntunePolicyObjectIdNullMessage"));
			}

			// Check if it is a Managed Installer policy and call the appropriate delete method
			if (ListViewSelectedPolicy.IsManagedInstaller)
			{
				await CommonCore.MicrosoftGraph.Main.DeleteManagedInstallerPolicy(
					AuthCompanionCLS.CurrentActiveAccount,
					ListViewSelectedPolicy.IntunePolicyObjectID);
			}
			else
			{
				await CommonCore.MicrosoftGraph.Main.DeletePolicy(
					AuthCompanionCLS.CurrentActiveAccount,
					ListViewSelectedPolicy.IntunePolicyObjectID);
			}

			MainInfoBar.WriteInfo($"Successfully removed the policy with the name '{ListViewSelectedPolicy.FriendlyName}' and ID '{ListViewSelectedPolicy.PolicyID}' from Intune.");

			// Refresh the policies
			await GetOnlinePoliciesInternal();
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
	/// Deploys the predefined Managed Installer Policy
	/// </summary>
	internal async void DeployManagedInstallerPolicy_Click()
	{
		try
		{
			MainInfoBarIsClosable = false;
			AreElementsEnabled = false;

			if (AuthCompanionCLS.CurrentActiveAccount is null)
				return;

			string? policyId = await CommonCore.MicrosoftGraph.Main.CreateManagedInstallerPolicy(AuthCompanionCLS.CurrentActiveAccount);

			if (policyId is not null)
			{
				MainInfoBar.WriteSuccess($"Successfully deployed Managed Installer Policy with ID: {policyId}");
				await GetOnlinePoliciesInternal(); // Refresh the list
			}
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
