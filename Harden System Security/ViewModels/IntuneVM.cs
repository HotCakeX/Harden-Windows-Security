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
using AppControlManager.Pages;
using AppControlManager.ViewModels;
using CommonCore.MicrosoftGraph;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class IntuneVM : ViewModelBase, IGraphAuthHost, IDisposable
{
	internal IntuneVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		AuthCompanionCLS = new(UpdateButtonsStates, new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher), AuthenticationContext.Intune);

		// Initialize column widths so headers have padding initially.
		_ = Dispatcher.TryEnqueue(CalculateColumnWidths);

		// Load policy files from the hardening directory
		LoadHardeningPolicyFiles();
	}

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	public AuthenticationCompanion AuthCompanionCLS { get; private set; }
	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

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
	/// This ObservableCollection is bound to the ListView.
	/// </summary>
	internal ObservableCollection<DeviceManagementConfigurationPolicy> Policies { get; } = [];

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

	internal void CalculateColumnWidths()
	{
		double maxWidth1 = AppControlManager.Others.ListViewHelper.MeasureText(GlobalVars.GetStr("NameHeader/Text"));
		double maxWidth2 = AppControlManager.Others.ListViewHelper.MeasureText(GlobalVars.GetStr("DescriptionHeader/Text"));
		double maxWidth3 = AppControlManager.Others.ListViewHelper.MeasureText(GlobalVars.GetStr("PlatformsHeader/Text"));
		double maxWidth4 = AppControlManager.Others.ListViewHelper.MeasureText(GlobalVars.GetStr("TechnologiesHeader/Text"));
		double maxWidth5 = AppControlManager.Others.ListViewHelper.MeasureText(GlobalVars.GetStr("SettingCountHeader/Text"));
		double maxWidth6 = AppControlManager.Others.ListViewHelper.MeasureText(GlobalVars.GetStr("CreatedHeader/Text"));
		double maxWidth7 = AppControlManager.Others.ListViewHelper.MeasureText(GlobalVars.GetStr("ModifiedHeader/Text"));
		double maxWidth8 = AppControlManager.Others.ListViewHelper.MeasureText(GlobalVars.GetStr("IDHeader/Text"));

		foreach (DeviceManagementConfigurationPolicy item in Policies)
		{
			maxWidth1 = AppControlManager.Others.ListViewHelper.MeasureText(item.Name, maxWidth1);
			maxWidth2 = AppControlManager.Others.ListViewHelper.MeasureText(item.Description, maxWidth2);
			maxWidth3 = AppControlManager.Others.ListViewHelper.MeasureText(item.Platforms, maxWidth3);
			maxWidth4 = AppControlManager.Others.ListViewHelper.MeasureText(item.Technologies, maxWidth4);
			maxWidth5 = AppControlManager.Others.ListViewHelper.MeasureText(item.SettingCount?.ToString(), maxWidth5);
			maxWidth6 = AppControlManager.Others.ListViewHelper.MeasureText(item.CreatedDateTime?.ToString(), maxWidth6);
			maxWidth7 = AppControlManager.Others.ListViewHelper.MeasureText(item.LastModifiedDateTime?.ToString(), maxWidth7);
			maxWidth8 = AppControlManager.Others.ListViewHelper.MeasureText(item.Id, maxWidth8);
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
		Microsoft.UI.Xaml.Controls.ScrollViewer? sv =
			AppControlManager.Others.ListViewHelper.GetScrollViewerFromCache(AppControlManager.Others.ListViewHelper.ListViewsRegistry.OnlineIntuneDeviceConfigs);
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
		foreach (DeviceManagementConfigurationPolicy item in filtered)
		{
			Policies.Add(item);
		}

		if (savedHorizontal.HasValue && sv is not null)
		{
			_ = sv.ChangeView(savedHorizontal, null, null, disableAnimation: true);
		}
	}

	/// <summary>
	/// When online features are enabled, this method will enable the relevant buttons and performs extra necessary actions
	/// </summary>
	private void UpdateButtonsStates(bool on)
	{
		// Enable the options if a valid value is set as Active Account
		AreOnlineFeaturesEnabled = on;
	}

	/// <summary>
	/// Event handler for the Select Groups button.
	/// </summary>
	internal void SelectGroups_Click()
	{
		// Assign the current signed in account to the ViewModel to make it available for usage.
		AppControlManager.ViewModels.IntuneDeploymentDetailsVM.TargetAccount = AuthCompanionCLS.CurrentActiveAccount;

		ViewModelProvider.NavigationService.Navigate(typeof(IntuneDeploymentDetails), null);
	}

	/// <summary>
	/// Retrieve non-custom device configuration policies from Microsoft Graph and populate the ListView.
	/// </summary>
	internal async void RetrievePolicies_Click()
	{
		if (AuthCompanionCLS.CurrentActiveAccount is null)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SignInAuthenticationRequiredMsg"));
			return;
		}

		try
		{
			AreElementsEnabled = false;
			MainInfoBarIsClosable = false;

			// Fetch data
			List<DeviceManagementConfigurationPolicy> result = await Main.RetrieveConfigurationPolicies(AuthCompanionCLS.CurrentActiveAccount);

			Policies.Clear();
			AllPolicies.Clear();

			foreach (DeviceManagementConfigurationPolicy item in result)
			{
				Policies.Add(item);
				AllPolicies.Add(item);
			}

			CalculateColumnWidths();
			SearchKeyword = null;

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("DeviceConfigurationsRetrievedSuccessfullyMessage"));
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
	/// Items source for the hardening policies ComboBox.
	/// </summary>
	internal ObservableCollection<IntunePolicyFileItem> PolicyFiles { get; } = [];

	/// <summary>
	/// Selected file in the ComboBox.
	/// </summary>
	internal IntunePolicyFileItem? SelectedPolicyFile { get; set => SP(ref field, value); }

	/// <summary>
	/// Loads JSON files from app directory.
	/// </summary>
	private void LoadHardeningPolicyFiles()
	{
		try
		{
			PolicyFiles.Clear();

			// Only files directly within the directory, no recursion.
			string[] files = Directory.GetFiles(CommonCore.Others.GlobalVars.HardeningPoliciesPath, "*.json", SearchOption.TopDirectoryOnly);

			foreach (string path in files)
			{
				string name = Path.GetFileNameWithoutExtension(path); // strip .json from display name
				PolicyFiles.Add(new IntunePolicyFileItem(name, path));
			}

			// Auto select first
			if (PolicyFiles.Count > 0)
			{
				SelectedPolicyFile = PolicyFiles[0];
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Deploys the selected policy JSON (from the ComboBox) to Intune and assigns selected groups.
	/// </summary>
	internal async void DeploySelectedPolicy_Click()
	{
		if (AuthCompanionCLS.CurrentActiveAccount is null)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SignInAuthenticationRequiredMsg"));
			return;
		}

		if (SelectedPolicyFile is null)
		{
			MainInfoBar.WriteWarning("Please select a policy JSON file first.");
			return;
		}

		try
		{
			AreElementsEnabled = false;
			MainInfoBarIsClosable = false;

			// Create the configuration policy from JSON
			string? createdPolicyId = await Main.CreateConfigurationPolicyFromJson(
				AuthCompanionCLS.CurrentActiveAccount,
				SelectedPolicyFile.FullPath);

			// Assign selected groups (if any) to the created policy
			if (!string.IsNullOrEmpty(createdPolicyId) && IntuneDeploymentDetailsVM.SelectedIntuneGroups.Count > 0)
			{
				// Extract group IDs from selected groups
				List<string> groupIds = IntuneDeploymentDetailsVM.SelectedIntuneGroups.Select(g => g.GroupID).ToList();

				await Main.AssignConfigurationPolicyToGroups(
					AuthCompanionCLS.CurrentActiveAccount,
					createdPolicyId,
					groupIds);

				MainInfoBar.WriteSuccess("Selected groups were successfully assigned to the deployed policy.");
			}

			if (!string.IsNullOrEmpty(createdPolicyId))
			{
				MainInfoBar.WriteSuccess(string.Format("Successfully deployed policy. ID: {0}", createdPolicyId));
			}

			// Refresh the list after deployment
			RetrievePolicies_Click();
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
	/// Deletes the currently selected policy from the ListView.
	/// </summary>
	internal async void DeleteSelectedPolicy_Click()
	{
		if (AuthCompanionCLS.CurrentActiveAccount is null)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SignInAuthenticationRequiredMsg"));
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
			MainInfoBarIsClosable = false;

			await Main.DeleteConfigurationPolicy(
				AuthCompanionCLS.CurrentActiveAccount,
				SelectedPolicyInListView.Id!);

			MainInfoBar.WriteSuccess("Policy deleted successfully.");

			// Refresh the list after deletion
			RetrievePolicies_Click();
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

	#region Copy

	/// <summary>
	/// Property mappings for DeviceManagementConfigurationPolicy rows (used for row and cell copying).
	/// Keys must match Tags used in the context flyout.
	/// </summary>
	private static readonly FrozenDictionary<string, (string Label, Func<DeviceManagementConfigurationPolicy, object?> Getter)> DeviceManagementConfigurationPolicyPropertyMappings =
		new Dictionary<string, (string Label, Func<DeviceManagementConfigurationPolicy, object?> Getter)>
		{
			{ "Name", (GlobalVars.GetStr("NameHeader/Text"), p => p.Name) },
			{ "Description", (GlobalVars.GetStr("DescriptionHeader/Text"), p => p.Description) },
			{ "Platforms", (GlobalVars.GetStr("PlatformsHeader/Text"), p => p.Platforms) },
			{ "Technologies", (GlobalVars.GetStr("TechnologiesHeader/Text"), p => p.Technologies) },
			{ "SettingCount", (GlobalVars.GetStr("SettingCountHeader/Text"), p => p.SettingCount) },
			{ "CreatedDateTime", (GlobalVars.GetStr("CreatedHeader/Text"), p => p.CreatedDateTime) },
			{ "LastModifiedDateTime", (GlobalVars.GetStr("ModifiedHeader/Text"), p => p.LastModifiedDateTime) },
			{ "Id", (GlobalVars.GetStr("IDHeader/Text"), p => p.Id) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Copies all selected policies (entire rows) to the clipboard with labeled properties.
	/// </summary>
	internal void CopySelectedPolicies_Click()
	{
		ListView? lv = AppControlManager.Others.ListViewHelper.GetListViewFromCache(AppControlManager.Others.ListViewHelper.ListViewsRegistry.OnlineIntuneDeviceConfigs);

		if (lv is null || lv.SelectedItems.Count == 0)
			return;

		AppControlManager.Others.ListViewHelper.ConvertRowToText<DeviceManagementConfigurationPolicy>(lv.SelectedItems.Cast<object>().ToList(), DeviceManagementConfigurationPolicyPropertyMappings);
	}

	/// <summary>
	/// Copies a single property of the currently selected policy to the clipboard.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void CopyPolicyProperty_Click(object sender, RoutedEventArgs e)
	{
		if (sender is not MenuFlyoutItem mfi || mfi.Tag is not string key)
			return;

		ListView? lv = AppControlManager.Others.ListViewHelper.GetListViewFromCache(AppControlManager.Others.ListViewHelper.ListViewsRegistry.OnlineIntuneDeviceConfigs);

		if (lv is null)
			return;

		if (DeviceManagementConfigurationPolicyPropertyMappings.TryGetValue(key, out (string Label, Func<DeviceManagementConfigurationPolicy, object?> Getter) map))
		{
			AppControlManager.Others.ListViewHelper.CopyToClipboard<DeviceManagementConfigurationPolicy>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

	#endregion

	public void Dispose()
	{
		// Dispose the AuthenticationCompanion which implements IDisposable
		AuthCompanionCLS.Dispose();
	}
}
