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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.Pages;
using AppControlManager.ViewModels;
using CommonCore.MicrosoftGraph;
using HardenSystemSecurity.Pages;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinRT;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class IntuneVM : ViewModelBase, IGraphAuthHost, IDisposable
{
	internal IntuneVM()
	{
		MainInfoBar = new();

		AuthCompanionCLS = new(UpdateButtonsStates, MainInfoBar, AuthenticationContext.Intune);

		// Initialize column widths so headers have padding initially.
		_ = Atlas.AppDispatcher.TryEnqueue(CalculateColumnWidths);

		// Load policy files from the hardening directory
		LoadHardeningPolicyFiles();
	}

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	public AuthenticationCompanion AuthCompanionCLS { get; }

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	public bool AreElementsEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	/// <summary>
	/// Determines whether the online features related to Online are enabled or disabled.
	/// </summary>
	internal bool AreOnlineFeaturesEnabled { get; set => SP(ref field, value); }

	/// <summary>
	/// Used to display the number of selected groups in the UI.
	/// </summary>
	internal int SelectedIntuneGroupsCount => IntuneDeploymentDetailsVM.SelectedIntuneGroups.Count;

	/// <summary>
	/// Non-custom device configuration policies (Windows) retrieved from Intune via Microsoft Graph.
	/// This Collection is bound to the ListView.
	/// </summary>
	internal readonly CommonCore.IncrementalCollection.RangedObservableCollection<DeviceManagementConfigurationPolicy> Policies = [];

	/// <summary>
	/// Backing store of all policies (used for search/sort without losing the original data).
	/// </summary>
	internal readonly List<DeviceManagementConfigurationPolicy> AllPolicies = [];

	/// <summary>
	/// Selected policy in the ListView.
	/// </summary>
	internal DeviceManagementConfigurationPolicy? SelectedPolicyInListView { get; set => SP(ref field, value); }

	// Column widths
	internal GridLength ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth6 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth7 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth8 { get; set => SP(ref field, value); }

	private void CalculateColumnWidths()
	{
		double maxWidth1 = ListViewHelper.MeasureText(Atlas.GetStr("NameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(Atlas.GetStr("DescriptionHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(Atlas.GetStr("PlatformsHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(Atlas.GetStr("TechnologiesHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(Atlas.GetStr("SettingCountHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(Atlas.GetStr("CreatedHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(Atlas.GetStr("ModifiedHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(Atlas.GetStr("IDHeader/Text"));

		foreach (DeviceManagementConfigurationPolicy item in Policies)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.Name, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.Description, maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.Platforms, maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.Technologies, maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.SettingCount?.ToString(), maxWidth5);
			maxWidth6 = ListViewHelper.MeasureText(item.CreatedDateTime?.ToString(), maxWidth6);
			maxWidth7 = ListViewHelper.MeasureText(item.LastModifiedDateTime?.ToString(), maxWidth7);
			maxWidth8 = ListViewHelper.MeasureText(item.Id, maxWidth8);
		}

		ColumnWidth1 = new(maxWidth1);
		ColumnWidth2 = new(maxWidth2);
		ColumnWidth3 = new(maxWidth3);
		ColumnWidth4 = new(maxWidth4);
		ColumnWidth5 = new(maxWidth5);
		ColumnWidth6 = new(maxWidth6);
		ColumnWidth7 = new(maxWidth7);
		ColumnWidth8 = new(maxWidth8);
	}

	/// <summary>
	/// Bound to the search TextBox. Filters the policy list.
	/// </summary>
	internal string? SearchKeyword
	{
		get; set
		{
			if (SPT(ref field, value))
				ApplyFilters();
		}
	}

	private void ApplyFilters()
	{
		ScrollViewer? sv =
			ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.OnlineIntuneDeviceConfigs);
		double? savedHorizontal = sv?.HorizontalOffset;

		string? term = SearchKeyword?.Trim();
		IEnumerable<DeviceManagementConfigurationPolicy> filtered = AllPolicies;

		if (!string.IsNullOrEmpty(term))
		{
			filtered = filtered.Where(p =>
				(p.Name?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.Description?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.Platforms?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.Technologies?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.Id?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.SettingCount?.ToString().Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.CreatedDateTime?.ToString().Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.LastModifiedDateTime?.ToString().Contains(term, StringComparison.OrdinalIgnoreCase) ?? false));
		}

		Policies.Clear();
		Policies.AddRange(filtered);

		_ = sv?.ChangeView(savedHorizontal, null, null, disableAnimation: true);
	}

	/// <summary>
	/// When online features are enabled, this method will enable the relevant buttons and perform extra necessary actions
	/// </summary>
	private void UpdateButtonsStates(bool on) => AreOnlineFeaturesEnabled = on;

	/// <summary>
	/// Event handler for the Select Groups button.
	/// </summary>
	internal async void SelectGroups_Click()
	{
		// Assign the current signed in account to the ViewModel to make it available for usage.
		IntuneDeploymentDetailsVM.TargetAccount = AuthCompanionCLS.CurrentActiveAccount;

		await ViewModelProvider.NavigationService.Navigate(typeof(IntuneDeploymentDetails), null);
	}

	/// <summary>
	/// Event handler for the UI.
	/// </summary>
	internal async void RetrievePolicies_Click()
	{
		try
		{
			AreElementsEnabled = false;
			MainInfoBar.IsClosable = false;

			if (await RetrievePolicies())
			{
				MainInfoBar.WriteSuccess(Atlas.GetStr("DeviceConfigurationsRetrievedSuccessfullyMessage"));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreElementsEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Retrieve non-custom device configuration policies from Microsoft Graph and populate the ListView.
	/// </summary>
	internal async Task<bool> RetrievePolicies()
	{
		if (AuthCompanionCLS.CurrentActiveAccount is null)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("SignInAuthenticationRequiredMsg"));
			return false;
		}

		// Fetch data
		List<DeviceManagementConfigurationPolicy> result = await Main.RetrieveConfigurationPolicies(AuthCompanionCLS.CurrentActiveAccount);

		Policies.Clear();
		AllPolicies.Clear();

		Policies.AddRange(result);
		AllPolicies.AddRange(result);

		CalculateColumnWidths();
		SearchKeyword = null;

		return true;
	}

	/// <summary>
	/// Items source for the hardening policies ListView.
	/// </summary>
	internal readonly ObservableCollection<IntunePolicyFileItem> PolicyFiles = [];

	/// <summary>
	/// The policy files selected by the multi-select ListView.
	/// </summary>
	internal readonly ObservableCollection<IntunePolicyFileItem> SelectedPolicyFiles = [];

	internal void PolicyFiles_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		foreach (object item in e.RemovedItems)
		{
			if (item is IntunePolicyFileItem policyFile)
			{
				_ = SelectedPolicyFiles.Remove(policyFile);
			}
		}

		foreach (object item in e.AddedItems)
		{
			if (item is IntunePolicyFileItem policyFile && !SelectedPolicyFiles.Contains(policyFile))
			{
				SelectedPolicyFiles.Add(policyFile);
			}
		}
	}

	/// <summary>
	/// Loads JSON files from app directory.
	/// </summary>
	private void LoadHardeningPolicyFiles()
	{
		try
		{
			PolicyFiles.Clear();

			// Only files directly within the directory, no recursion.
			foreach (string path in Directory.EnumerateFiles(Atlas.HardeningPoliciesPath, "*.json", SearchOption.TopDirectoryOnly))
			{
				string name = Path.GetFileNameWithoutExtension(path); // strip .json from display name
				PolicyFiles.Add(new IntunePolicyFileItem(name, path));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Deploys every policy selected in the flyout and assigns the selected groups to each created policy.
	/// </summary>
	internal async void DeploySelectedPolicy_Click()
	{
		if (AuthCompanionCLS.CurrentActiveAccount is null)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("SignInAuthenticationRequiredMsg"));
			return;
		}

		if (SelectedPolicyFiles.Count is 0)
		{
			MainInfoBar.WriteWarning("Please select at least one policy configuration first.");
			return;
		}

		try
		{
			AreElementsEnabled = false;
			MainInfoBar.IsClosable = false;

			MainInfoBar.WriteInfo("Deploying the selected policies, please wait.");

			// Extract group IDs from selected groups
			List<string> groupIds = new(IntuneDeploymentDetailsVM.SelectedIntuneGroups.Count);
			foreach (IntuneGroupItemListView group in IntuneDeploymentDetailsVM.SelectedIntuneGroups)
			{
				groupIds.Add(group.GroupID);
			}

			int deployed = 0;
			foreach (IntunePolicyFileItem policyFile in SelectedPolicyFiles)
			{
				// Create the configuration policy from JSON
				string? createdPolicyId = await Main.CreateConfigurationPolicyFromJson(AuthCompanionCLS.CurrentActiveAccount, policyFile.FullPath);
				if (string.IsNullOrEmpty(createdPolicyId))
				{
					continue;
				}
				if (groupIds.Count > 0)
				{
					await Main.AssignConfigurationPolicyToGroups(AuthCompanionCLS.CurrentActiveAccount, createdPolicyId, groupIds);
				}
				deployed++;
			}
			MainInfoBar.WriteSuccess($"Successfully deployed {deployed} selected policies.");

			// Refresh the list after deployments
			_ = await RetrievePolicies();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreElementsEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Deletes the currently selected policy from the ListView.
	/// </summary>
	internal async void DeleteSelectedPolicy_Click()
	{
		if (AuthCompanionCLS.CurrentActiveAccount is null)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("SignInAuthenticationRequiredMsg"));
			return;
		}

		if (SelectedPolicyInListView is null || string.IsNullOrWhiteSpace(SelectedPolicyInListView.Id))
		{
			MainInfoBar.WriteWarning("Please select a policy in the list to delete.");
			return;
		}

		try
		{
			AreElementsEnabled = false;
			MainInfoBar.IsClosable = false;

			await Main.DeleteConfigurationPolicy(
				AuthCompanionCLS.CurrentActiveAccount,
				SelectedPolicyInListView.Id);

			MainInfoBar.WriteSuccess("Policy deleted successfully.");

			// Refresh the list after deletion
			_ = await RetrievePolicies();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreElementsEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Deletes every policy currently present in the complete tenant policy collection.
	/// </summary>
	internal async void DeleteAllPolicies_Click()
	{
		if (AuthCompanionCLS.CurrentActiveAccount is null)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("SignInAuthenticationRequiredMsg"));
			return;
		}
		if (AllPolicies.Count is 0)
		{
			MainInfoBar.WriteWarning("There are no policies to delete.");
			return;
		}

		try
		{
			AreElementsEnabled = false;
			MainInfoBar.IsClosable = false;

			MainInfoBar.WriteInfo("Deleting the selected policies, please wait.");

			int deleted = 0;
			foreach (DeviceManagementConfigurationPolicy policy in AllPolicies)
			{
				if (string.IsNullOrWhiteSpace(policy.Id))
				{
					continue;
				}
				await Main.DeleteConfigurationPolicy(AuthCompanionCLS.CurrentActiveAccount, policy.Id);
				deleted++;
			}
			MainInfoBar.WriteSuccess($"Deleted {deleted} policy item(s).");

			// Refresh the list after deletions
			_ = await RetrievePolicies();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreElementsEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	#region Policy Details - When user clicks on each item in the main list view.

	internal DeviceManagementConfigurationPolicy? PolicyDetailsPolicy { get; set => SP(ref field, value); }

	internal readonly ObservableCollection<PolicyAssignmentDisplay> PolicyDetailsAssignments = [];

	internal bool PolicyDetailsIsLoading { get; set => SP(ref field, value); }

	internal bool PolicyDetailsActionsEnabled { get; set => SP(ref field, value); } = true;

	internal bool IsPolicyDetailsWideLayout { get; set => SP(ref field, value); } = true;

	internal bool IsPolicyDetailsCompactLayout { get; set => SP(ref field, value); }

	/// <summary>
	/// Updates which deferred responsive assignment layout is loaded.
	/// </summary>
	internal void SetPolicyDetailsLayout(bool useWideLayout)
	{
		if (IsPolicyDetailsWideLayout == useWideLayout)
		{
			return;
		}

		IsPolicyDetailsWideLayout = useWideLayout;
		IsPolicyDetailsCompactLayout = !useWideLayout;
	}

	internal async void OpenPolicyDetails_Click(object sender, ItemClickEventArgs e)
	{
		if (e.ClickedItem is not DeviceManagementConfigurationPolicy policy || string.IsNullOrEmpty(policy.Id))
		{
			return;
		}
		PolicyDetailsAssignments.Clear();
		PolicyDetailsPolicy = policy;
		PolicyDetailsActionsEnabled = false;
		try
		{
			await ViewModelProvider.NavigationService.Navigate(typeof(IntunePolicyDetails), null);
			await LoadPolicyDetailsAsync(policy);
		}
		finally
		{
			PolicyDetailsActionsEnabled = true;
		}
	}

	internal async void RefreshPolicyDetails_Click()
	{
		if (PolicyDetailsPolicy is null || !PolicyDetailsActionsEnabled)
		{
			return;
		}

		try
		{
			PolicyDetailsActionsEnabled = false;
			await LoadPolicyDetailsAsync(PolicyDetailsPolicy);
		}
		finally
		{
			PolicyDetailsActionsEnabled = true;
		}
	}

	[DynamicWindowsRuntimeCast(typeof(Button))]
	internal async void RemovePolicyAssignment_Click(object sender, RoutedEventArgs e)
	{
		if (sender is not Button { Tag: PolicyAssignmentDisplay assignment } ||
			PolicyDetailsPolicy is null ||
			string.IsNullOrEmpty(PolicyDetailsPolicy.Id) ||
			string.IsNullOrEmpty(assignment.AssignmentId) ||
			AuthCompanionCLS.CurrentActiveAccount is null)
		{
			return;
		}
		try
		{
			PolicyDetailsActionsEnabled = false;
			PolicyDetailsIsLoading = true;
			await Main.DeleteConfigurationPolicyAssignment(
				AuthCompanionCLS.CurrentActiveAccount,
				PolicyDetailsPolicy.Id,
				assignment.AssignmentId);
			await LoadPolicyDetailsAsync(PolicyDetailsPolicy);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			PolicyDetailsIsLoading = false;
			PolicyDetailsActionsEnabled = true;
		}
	}

	internal async void RemoveAllPolicyAssignments_Click()
	{
		// Don't display the confirmation check if there are no assignments
		if (PolicyDetailsPolicy is null || PolicyDetailsAssignments.Count is 0)
		{
			return;
		}

		using ContentDialogV2 dialog = new()
		{
			Title = "Remove All Assignments?",
			Content = $"This will remove all assignments from '{PolicyDetailsPolicy.Name}'. This action cannot be undone.",
			PrimaryButtonText = "Remove All",
			CloseButtonText = "Cancel",
			DefaultButton = ContentDialogButton.Close
		};

		if (await dialog.ShowAsync() is ContentDialogResult.Primary)
		{
			await UpdatePolicyAssignmentsAsync(null);
		}
	}

	internal async void AddAllUsersPolicyAssignment_Click() =>
		await UpdatePolicyAssignmentsAsync("#microsoft.graph.allLicensedUsersAssignmentTarget");

	internal async void AddAllDevicesPolicyAssignment_Click() =>
		await UpdatePolicyAssignmentsAsync("#microsoft.graph.allDevicesAssignmentTarget");

	/// <summary>
	/// Adds one virtual target or clears all targets while disabling assignment actions until the operation completes.
	/// </summary>
	private async Task UpdatePolicyAssignmentsAsync(string? targetType)
	{
		if (PolicyDetailsPolicy is null ||
			string.IsNullOrEmpty(PolicyDetailsPolicy.Id) ||
			AuthCompanionCLS.CurrentActiveAccount is null)
		{
			return;
		}

		try
		{
			PolicyDetailsActionsEnabled = false;
			PolicyDetailsIsLoading = true;
			if (targetType is null)
			{
				await Main.RemoveAllConfigurationPolicyAssignments(
					AuthCompanionCLS.CurrentActiveAccount,
					PolicyDetailsPolicy.Id);
			}
			else
			{
				await Main.AddConfigurationPolicyVirtualAssignment(
					AuthCompanionCLS.CurrentActiveAccount,
					PolicyDetailsPolicy.Id,
					targetType);
			}

			await LoadPolicyDetailsAsync(PolicyDetailsPolicy);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			PolicyDetailsIsLoading = false;
			PolicyDetailsActionsEnabled = true;
		}
	}

	private async Task LoadPolicyDetailsAsync(DeviceManagementConfigurationPolicy policy)
	{
		if (AuthCompanionCLS.CurrentActiveAccount is null || string.IsNullOrEmpty(policy.Id))
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("SignInAuthenticationRequiredMsg"));
			return;
		}
		try
		{
			PolicyDetailsIsLoading = true;
			List<PolicyAssignmentDisplay> assignments = await Main.RetrieveConfigurationPolicyAssignmentImpacts(AuthCompanionCLS.CurrentActiveAccount, policy.Id);
			PolicyDetailsAssignments.Clear();
			foreach (PolicyAssignmentDisplay assignment in assignments)
			{
				PolicyDetailsAssignments.Add(assignment);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			PolicyDetailsIsLoading = false;
		}
	}

	#endregion

	#region Copy

	/// <summary>
	/// Property mappings for DeviceManagementConfigurationPolicy rows (used for row and cell copying).
	/// Keys must match Tags used in the context flyout.
	/// </summary>
	private static readonly FrozenDictionary<string, (string Label, Func<DeviceManagementConfigurationPolicy, object?> Getter)> DeviceManagementConfigurationPolicyPropertyMappings =
		new Dictionary<string, (string Label, Func<DeviceManagementConfigurationPolicy, object?> Getter)>
		{
			{ "Name", (Atlas.GetStr("NameHeader/Text"), p => p.Name) },
			{ "Description", (Atlas.GetStr("DescriptionHeader/Text"), p => p.Description) },
			{ "Platforms", (Atlas.GetStr("PlatformsHeader/Text"), p => p.Platforms) },
			{ "Technologies", (Atlas.GetStr("TechnologiesHeader/Text"), p => p.Technologies) },
			{ "SettingCount", (Atlas.GetStr("SettingCountHeader/Text"), p => p.SettingCount) },
			{ "CreatedDateTime", (Atlas.GetStr("CreatedHeader/Text"), p => p.CreatedDateTime) },
			{ "LastModifiedDateTime", (Atlas.GetStr("ModifiedHeader/Text"), p => p.LastModifiedDateTime) },
			{ "Id", (Atlas.GetStr("IDHeader/Text"), p => p.Id) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Copies all selected policies (entire rows) to the clipboard with labeled properties.
	/// </summary>
	internal void CopySelectedPolicies_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.OnlineIntuneDeviceConfigs);

		if (lv is null || lv.SelectedItems.Count == 0)
			return;

		ListViewHelper.ConvertRowToText<DeviceManagementConfigurationPolicy>(lv.SelectedItems, DeviceManagementConfigurationPolicyPropertyMappings);
	}

	/// <summary>
	/// Copies a single property of the currently selected policy to the clipboard.
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(MenuFlyoutItem))]
	internal void CopyPolicyProperty_Click(object sender, RoutedEventArgs e)
	{
		if (sender is not MenuFlyoutItem mfi || mfi.Tag is not string key)
			return;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.OnlineIntuneDeviceConfigs);

		if (lv is null)
			return;

		if (DeviceManagementConfigurationPolicyPropertyMappings.TryGetValue(key, out (string Label, Func<DeviceManagementConfigurationPolicy, object?> Getter) map))
		{
			ListViewHelper.CopyToClipboard<DeviceManagementConfigurationPolicy>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

	#endregion

	public void Dispose()
	{
		// Dispose the AuthenticationCompanion which implements IDisposable
		AuthCompanionCLS.Dispose();
	}
}
