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
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using AppControlManager.Others;
using CommonCore.MicrosoftGraph;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.ViewModels;

internal sealed partial class IntuneDeploymentDetailsVM : ViewModelBase
{
	internal IntuneDeploymentDetailsVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		CalculateColumnWidths();
	}

	internal readonly InfoBarSettings MainInfoBar;
	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	/// <summary>
	/// The target account used for fetching Intune groups.
	/// </summary>
	internal static AuthenticatedAccounts? TargetAccount { get; set; }

	/// <summary>
	/// Determines whether the UI elements are enabled or disabled.
	/// </summary>
	internal bool AreElementsEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// A flag to make sure only one method is adding/removing items between ListView and the selected items collection.
	/// </summary>
	private volatile bool IsAdding;

	/// <summary>
	/// Bound to the UI ListView and holds the Intune group Names/IDs (filtered view).
	/// </summary>
	internal readonly ObservableCollection<IntuneGroupItemListView> GroupNamesCollection = [];

	/// <summary>
	/// Stores all Intune groups retrieved (unfiltered) to support search/sort without losing original data.
	/// </summary>
	internal readonly List<IntuneGroupItemListView> AllGroupItems = [];

	/// <summary>
	/// Stores current sorting state (column + direction).
	/// </summary>
	private ListViewHelper.SortState SortState { get; } = new();

	#region LISTVIEW IMPLEMENTATIONS - COLUMN WIDTHS

	// Grid Widths for the ListView
	internal GridLength ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth5 { get; set => SP(ref field, value); }

	internal void CalculateColumnWidths()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("GroupNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("GroupIDHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("GroupDescriptionHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("GroupSecurityIdentifierHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("GroupCreatedDateTimeHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (IntuneGroupItemListView item in GroupNamesCollection)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.GroupName, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.GroupID, maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.Description, maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.SecurityIdentifier, maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.CreatedDateTime.ToString(), maxWidth5);
		}

		// Set the column width properties.
		ColumnWidth1 = new GridLength(maxWidth1);
		ColumnWidth2 = new GridLength(maxWidth2);
		ColumnWidth3 = new GridLength(maxWidth3);
		ColumnWidth4 = new GridLength(maxWidth4);
		ColumnWidth5 = new GridLength(maxWidth5);
	}

	#endregion

	#region SEARCH / FILTER

	/// <summary>
	/// Bound to the Search TextBox on the UI.
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
	/// Applies search filtering to the list view.
	/// </summary>
	private void ApplyFilters()
	{
		ScrollViewer? sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.Deployment_IntuneGroupsListView);
		double? savedHorizontal = sv?.HorizontalOffset;

		string? term = SearchBoxText?.Trim();
		IEnumerable<IntuneGroupItemListView> filtered = AllGroupItems;

		if (!string.IsNullOrEmpty(term))
		{
			filtered = filtered.Where(g =>
				(g.GroupName?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(g.GroupID?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(g.Description?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(g.SecurityIdentifier?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				g.CreatedDateTime.ToString().Contains(term, StringComparison.OrdinalIgnoreCase));
		}

		GroupNamesCollection.Clear();
		foreach (IntuneGroupItemListView item in filtered)
		{
			GroupNamesCollection.Add(item);
		}

		if (savedHorizontal.HasValue && sv is not null)
		{
			_ = sv.ChangeView(savedHorizontal, null, null, disableAnimation: true);
		}
	}

	#endregion

	#region SORT / COPY SUPPORT

	/// <summary>
	/// Property mappings for IntuneGroupItemListView used for sorting and copy operations.
	/// Keys must match the Tag values of header buttons & flyout items.
	/// </summary>
	private static readonly FrozenDictionary<string, (string Label, Func<IntuneGroupItemListView, object?> Getter)> IntuneGroupPropertyMappings =
		new Dictionary<string, (string Label, Func<IntuneGroupItemListView, object?> Getter)>(StringComparer.OrdinalIgnoreCase)
		{
			["GroupName"] = (GlobalVars.GetStr("GroupNameHeader/Text"), g => g.GroupName),
			["GroupID"] = (GlobalVars.GetStr("GroupIDHeader/Text"), g => g.GroupID),
			["Description"] = (GlobalVars.GetStr("GroupDescriptionHeader/Text"), g => g.Description),
			["SecurityIdentifier"] = (GlobalVars.GetStr("GroupSecurityIdentifierHeader/Text"), g => g.SecurityIdentifier),
			["CreatedDateTime"] = (GlobalVars.GetStr("GroupCreatedDateTimeHeader/Text"), g => g.CreatedDateTime)
		}.ToFrozenDictionary();

	#endregion

	#region UI COMMAND HANDLERS

	/// <summary>
	/// Handles the click event for the Refresh Intune Groups button. It fetches groups from Microsoft Graph and updates
	/// the ListView with group names.
	/// </summary>
	internal async void RefreshIntuneGroupsButton_Click()
	{
		await RefreshIntuneGroups();
	}

	private async Task RefreshIntuneGroups()
	{
		if (TargetAccount is null)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SignInAuthenticationRequiredMsg"));
			return;
		}

		try
		{
			AreElementsEnabled = false;

			List<IntuneGroupItemListView> groups = await CommonCore.MicrosoftGraph.Main.FetchGroups(TargetAccount);

			// Clear the observable collection and internal storage.
			GroupNamesCollection.Clear();
			AllGroupItems.Clear();

			// Clear the selected items in the DeploymentVM as well.
			DeploymentVM.SelectedIntuneGroups.Clear();

			// Update the ListView with group names
			foreach (IntuneGroupItemListView item in groups)
			{
				GroupNamesCollection.Add(item);
				AllGroupItems.Add(item);
			}

			// Recalculate column widths
			CalculateColumnWidths();

			// Reset search if any
			SearchBoxText = null;
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
	/// Event handler for the SelectionChanged event of the ListView.
	/// Is also triggered when using SelectAll or De-Select all buttons.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void ListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		if (IsAdding) return;

		try
		{
			IsAdding = true;

			foreach (IntuneGroupItemListView item in e.AddedItems.Cast<IntuneGroupItemListView>())
			{
				DeploymentVM.SelectedIntuneGroups.Add(item);
			}

			foreach (IntuneGroupItemListView item in e.RemovedItems.Cast<IntuneGroupItemListView>())
			{
				_ = DeploymentVM.SelectedIntuneGroups.Remove(item);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			IsAdding = false;
		}
	}

	/// <summary>
	/// Event handler for when the List View is loaded.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal async void MainListView_Loaded(object sender, RoutedEventArgs e)
	{
		while (IsAdding)
		{
			// Yield control to keep the UI responsive and let other continuations run.
			await Task.Yield();
		}

		try
		{
			IsAdding = true;

			ListView lv = (ListView)sender;

			// Re-select all of the items after the page was navigated away and then navigated back to since we don't use navigation cache.
			foreach (IntuneGroupItemListView item in DeploymentVM.SelectedIntuneGroups)
			{
				lv.SelectedItems.Add(item);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			IsAdding = false;
		}
	}

	/// <summary>
	/// Exports (currently displayed) data to JSON.
	/// </summary>
	internal async void ExportToJsonButton_Click()
	{
		try
		{

			DateTime now = DateTime.Now;
			string formattedDateTime = now.ToString("yyyy-MM-dd_HH-mm-ss");
			string fileName = $"AppControlManager_IntuneGroupsData_Export_{formattedDateTime}.json";

			string? savePath = FileDialogHelper.ShowSaveFileDialog(GlobalVars.JSONPickerFilter, fileName);

			if (savePath is null)
				return;

			List<IntuneGroupItemListView> dataToExport = [];

			await Task.Run(() =>
			{
				// Export the currently filtered view
				dataToExport = GroupNamesCollection.ToList();

				string jsonString = JsonSerializer.Serialize(
					dataToExport,
					IntuneGroupItemListViewJsonSerializationContext.Default.ListIntuneGroupItemListView);

				File.WriteAllText(savePath, jsonString);
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Sort header button click handler.
	/// </summary>
	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			if (IntuneGroupPropertyMappings.TryGetValue(key, out (string Label, Func<IntuneGroupItemListView, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					keySelector: mapping.Getter,
					searchBoxText: SearchBoxText,
					originalList: AllGroupItems,
					observableCollection: GroupNamesCollection,
					sortState: SortState,
					newKey: key,
					regKey: ListViewHelper.ListViewsRegistry.Deployment_IntuneGroupsListView);
			}
		}
	}

	/// <summary>
	/// Copies all selected rows (with labels) to clipboard.
	/// </summary>
	internal void CopySelectedRows_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Deployment_IntuneGroupsListView);
		if (lv is null || lv.SelectedItems.Count is 0)
		{
			return;
		}

		ListViewHelper.ConvertRowToText(lv.SelectedItems, IntuneGroupPropertyMappings);
	}

	/// <summary>
	/// Copies a single property (column) of the currently selected row.
	/// </summary>
	internal void CopySinglePropertyMenuItem_Click(object sender, RoutedEventArgs e)
	{
		if (sender is not MenuFlyoutItem mfi || mfi.Tag is not string key)
		{
			return;
		}

		if (!IntuneGroupPropertyMappings.TryGetValue(key, out (string Label, Func<IntuneGroupItemListView, object?> Getter) mapping))
		{
			return;
		}

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Deployment_IntuneGroupsListView);
		if (lv is null)
		{
			return;
		}

		ListViewHelper.CopyToClipboard<IntuneGroupItemListView>(g => mapping.Getter(g)?.ToString(), lv);
	}

	/// <summary>
	/// Keyboard accelerator (Ctrl + C) to copy selected rows.
	/// </summary>
	internal void CtrlC_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		CopySelectedRows_Click();
		args.Handled = true;
	}

	/// <summary>
	/// Select all rows currently displayed (filtered).
	/// </summary>
	internal void SelectAll_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Deployment_IntuneGroupsListView);
		if (lv is null)
		{
			return;
		}

		ListViewHelper.SelectAll(lv, GroupNamesCollection);
	}

	/// <summary>
	/// De-select all rows.
	/// </summary>
	internal void DeSelectAll_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Deployment_IntuneGroupsListView);
		if (lv is null)
		{
			return;
		}

		lv.SelectedItems.Clear();
	}

	/// <summary>
	/// Displays a ContentDialog to create a new group.
	/// </summary>
	internal async void CreateGroupButton_Click()
	{
		if (TargetAccount is null)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SignInAuthenticationRequiredMsg"));
			return;
		}

		try
		{
			TextBox nameBox = new()
			{
				PlaceholderText = GlobalVars.GetStr("PFNDisplayNameLabelText"),
				Width = 320
			};

			TextBox descriptionBox = new()
			{
				PlaceholderText = GlobalVars.GetStr("GroupDescriptionHeader/Text"),
				AcceptsReturn = true,
				TextWrapping = TextWrapping.Wrap,
				Width = 320,
				Height = 80
			};

			ComboBox typeCombo = new()
			{
				Width = 320,
				SelectedIndex = 0
			};
			typeCombo.Items.Add("Security Group");
			typeCombo.Items.Add("Microsoft 365 Group");

			StackPanel panel = new()
			{
				Spacing = 12
			};
			panel.Children.Add(new TextBlock { Text = GlobalVars.GetStr("ProvideNewGroupDetails") });
			panel.Children.Add(nameBox);
			panel.Children.Add(descriptionBox);
			panel.Children.Add(new TextBlock { Text = GlobalVars.GetStr("GroupType") });
			panel.Children.Add(typeCombo);

			using CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = GlobalVars.GetStr("CreateGroupButton/Content"),
				PrimaryButtonText = GlobalVars.GetStr("CreateTextBlock/Text"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Primary,
				Content = panel
			};

			ContentDialogResult result = await dialog.ShowAsync();
			if (result != ContentDialogResult.Primary)
			{
				return;
			}

			string displayName = nameBox.Text?.Trim() ?? string.Empty;
			if (string.IsNullOrWhiteSpace(displayName))
			{
				return;
			}

			string? description = string.IsNullOrWhiteSpace(descriptionBox.Text) ? null : descriptionBox.Text.Trim();
			bool unifiedGroup = typeCombo.SelectedIndex == 1;

			AreElementsEnabled = false;

			await CommonCore.MicrosoftGraph.Main.CreateGroup(
				TargetAccount,
				displayName,
				description,
				unifiedGroup);

			// Refresh the groups after adding a new one
			await RefreshIntuneGroups();
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
	/// Event handler for the delete group button.
	/// </summary>
	internal async void DeleteGroupButton_Click()
	{

		if (TargetAccount is null)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SignInAuthenticationRequiredMsg"));
			return;
		}

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Deployment_IntuneGroupsListView);
		if (lv is null || lv.SelectedItems.Count == 0)
		{
			return;
		}

		try
		{

			int count = lv.SelectedItems.Count;
			string firstName = (lv.SelectedItems[0] as IntuneGroupItemListView)?.GroupName ?? string.Empty;
			string summaryText = count == 1
				? string.Format(GlobalVars.GetStr("DeleteGroupDialogIntroSingle"), firstName)
				: string.Format(GlobalVars.GetStr("DeleteGroupDialogIntroMultiple"), count);

			TextBlock warning = new()
			{
				Text = GlobalVars.GetStr("DeleteGroupDialogWarning"),
				TextWrapping = TextWrapping.Wrap,
				Width = 360
			};

			StackPanel panel = new()
			{
				Spacing = 10
			};
			panel.Children.Add(new TextBlock { Text = summaryText });
			panel.Children.Add(warning);

			using CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = GlobalVars.GetStr("DeleteGroupDialogTitle"),
				PrimaryButtonText = GlobalVars.GetStr("Delete"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Close,
				Content = panel
			};

			ContentDialogResult result = await dialog.ShowAsync();
			if (result is not ContentDialogResult.Primary)
			{
				return;
			}

			AreElementsEnabled = false;

			List<IntuneGroupItemListView> toDelete = lv.SelectedItems.Cast<IntuneGroupItemListView>().ToList();

			foreach (IntuneGroupItemListView grp in toDelete)
			{
				try
				{
					await CommonCore.MicrosoftGraph.Main.DeleteGroup(TargetAccount, grp.GroupID);

					MainInfoBar.WriteInfo(string.Format(
						GlobalVars.GetStr("SuccessfullyDeletedGroupMessage"),
						grp.GroupName,
						grp.GroupID));
				}
				catch (Exception ex)
				{
					MainInfoBar.WriteError(ex, string.Format(
						GlobalVars.GetStr("DeleteGroupDeletionErrorLogTemplate"),
						grp.GroupID,
						ex.Message));
				}
			}

			// Refresh the groups after removals finished
			await RefreshIntuneGroups();
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
	/// Event handler for the Clear Data button.
	/// </summary>
	internal void ClearData()
	{
		GroupNamesCollection.Clear();
		AllGroupItems.Clear();
		DeploymentVM.SelectedIntuneGroups.Clear();
	}

	#endregion

	#region DUMMY GROUPS GENERATOR

	/// <summary>
	/// Creates 50 random groups (M365 + Security) for testing purposes.
	/// </summary>
	/// <returns></returns>
	internal async void CreateRandomGroups()
	{
		if (TargetAccount is null)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SignInAuthenticationRequiredMsg"));
			return;
		}

		try
		{

			AreElementsEnabled = false;

			using CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = GlobalVars.GetStr("WarningTitle"),
				PrimaryButtonText = GlobalVars.GetStr("CreateTextBlock/Text"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Primary,
				Content = GlobalVars.GetStr("ConfirmationTextForDummyGroupsCreation")
			};

			ContentDialogResult result = await dialog.ShowAsync();
			if (result != ContentDialogResult.Primary)
			{
				return;
			}

			const int total = 50;

			const int interRequestDelayMilliseconds = 120;

			for (int i = 1; i <= total; i++)
			{
				// Decide randomly whether to create a unified (M365) group or a security group.
				bool unifiedGroup = (i % 2) == 0;

				string displayName = BuildRandomDisplayName(i);
				string description = BuildRandomDescription(i);

				try
				{
					await CommonCore.MicrosoftGraph.Main.CreateGroup(
						TargetAccount,
						displayName,
						description,
						unifiedGroup);

					MainInfoBar.WriteInfo($"[BulkGroupCreate] ({i}/{total}) Created {(unifiedGroup ? "M365" : "Security")} group: {displayName}");
				}
				catch (Exception ex)
				{
					MainInfoBar.WriteError(ex, $"[BulkGroupCreate] Failed creating group #{i} ({displayName}).");
				}

				// Light pacing between calls (skip after last).
				if (i < total && interRequestDelayMilliseconds > 0)
				{
					await Task.Delay(interRequestDelayMilliseconds);
				}
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
	/// Builds a random display name with a stable prefix + index + random segment.
	/// </summary>
	private static string BuildRandomDisplayName(int index)
	{
		// Total length kept well below Graph limits (<=256).
		string randomSegment = RandomSegment(8);
		return $"ACM-AUTO-{index:D3}-{randomSegment}";
	}

	/// <summary>
	/// Builds a random description using a small word pool for variety.
	/// </summary>
	private static string BuildRandomDescription(int index)
	{
		string[] words = [
				"policy","secure","deployment","baseline","config","ops","device","endpoint",
				"control","trusted","integrity","enforced","adaptive","managed","fleet","tenant"
			];

		string part1 = words[GetRandomNumber(words.Length)];
		string part2 = words[GetRandomNumber(words.Length)];
		string part3 = words[GetRandomNumber(words.Length)];

		return $"Auto generated group #{index} - {part1}-{part2}-{part3}";
	}

	/// <summary>
	/// Generates a random alphanumeric segment of the requested length.
	/// </summary>
	private static string RandomSegment(int length)
	{
		const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		int alphabetLength = alphabet.Length;

		char[] buffer = new char[length];

		// Use a single RNG fill.
		byte[] raw = new byte[length];
		RandomNumberGenerator.Fill(raw);

		for (int i = 0; i < length; i++)
		{
			// Map byte to index
			int idx = raw[i] % alphabetLength;
			buffer[i] = alphabet[idx];
		}

		return new string(buffer);
	}

	/// <summary>
	/// Returns a pseudo-random integer in [0, maxExclusive).
	/// </summary>
	private static int GetRandomNumber(int maxExclusive)
	{
		if (maxExclusive <= 0)
			return 0;

		return RandomNumberGenerator.GetInt32(maxExclusive);
	}

	#endregion
}
