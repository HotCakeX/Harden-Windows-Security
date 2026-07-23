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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HardenSystemSecurity.CustomUIElements;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Data;
using Windows.Foundation;
using Windows.Management.Deployment;
using Windows.System;
using WinRT;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class InstalledAppsManagementVM : ViewModelBase
{
	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar = new();

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool ElementsAreEnabled
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
	/// Items Source of the ListView that displays the list of the installed packaged apps.
	/// </summary>
	internal ObservableCollection<GroupInfoListForPackagedAppView> AppsListItemsSource { get; set => SP(ref field, value); } = [];

	/// <summary>
	/// Tracks the active SemanticZoom view for the installed apps list.
	/// </summary>
	internal bool IsPackagedAppsZoomedInViewActive { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Search text entered in the UI text box.
	/// </summary>
	internal string? SearchKeyword
	{
		get; set
		{
			if (SPT(ref field, value))
			{
				PFNAppFilteringTextBox_TextChanged();
			}
		}
	}

	/// <summary>
	/// Backing field of the ListView's ItemsSource.
	/// </summary>
	private List<GroupInfoListForPackagedAppView> AppsListItemsSourceBackingList { get; set; } = [];

	/// <summary>
	/// To store the selected items.
	/// Using a HashSet with a StableIdentity-based comparer to deduplicate and allow value-based lookups across reloads/filters.
	/// </summary>
	private readonly HashSet<PackagedAppView> AppsListItemsSourceSelectedItems = new(new PackagedAppViewIdentityComparer());

	/// <summary>
	/// Total number of items loaded (all apps)
	/// </summary>
	internal int TotalItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items currently displayed after filtering
	/// </summary>
	internal int FilteredItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of currently selected items
	/// </summary>
	internal int SelectedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Package Manager used in the view model.
	/// </summary>
	private readonly PackageManager PackageMgr = new();

	/// <summary>
	/// Flag to prevent recursive selection change events during selection restoration
	/// </summary>
	private volatile bool _isRestoringSelection;

	/// <summary>
	/// Flag to suppress SelectionChanged handling while ItemsSource is being programmatically updated
	/// (e.g., during refresh or filtering). Prevents clearing the persisted selection set when the ListView
	/// raises SelectionChanged due to ItemsSource replacement.
	/// </summary>
	private volatile bool _isUpdatingItemsSource;

	private CancellationTokenSource? _searchFilterCancellationTokenSource;
	private int _searchFilterVersion;

	/// <summary>
	/// Event handler for the Refresh button to get the apps list
	/// </summary>
	internal async void RefreshAppsListButton_Click()
	{
		try
		{
			await RefreshAppsList();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	private async Task RefreshAppsList()
	{
		try
		{
			ElementsAreEnabled = false;
			CancelPendingSearchFilter();

			// Get the new data first
			(ObservableCollection<GroupInfoListForPackagedAppView>, List<GroupInfoListForPackagedAppView>) results = await GetAppsList.GetAppsGroupedAsync(this);
			AppContainerLoopbackManager.UpdatePackagedAppsLoopbackState(GetAllLoadedApps(results.Item2).ToList());

			// Suppress selection change side effects while replacing ItemsSource to preserve persisted selection
			_isUpdatingItemsSource = true;
			try
			{
				AppsListItemsSourceBackingList = SortPackagedAppGroups(results.Item2);

				// Remove any stale selections that are no longer present in the refreshed list (e.g., apps that were uninstalled).
				PruneSelectionToLoadedApps();

				// Keep the current search filter active after retrieval if the search box still contains text.
				AppsListItemsSource = string.IsNullOrWhiteSpace(SearchKeyword) ? new(AppsListItemsSourceBackingList) : new(BuildFilteredAppsList(AppsListItemsSourceBackingList, SearchKeyword));

				// Update counts after loading apps
				UpdateCounts();
			}
			finally
			{
				_isUpdatingItemsSource = false;
			}

			// Restore selection after loading new data
			RestoreSelectionFromViewModel();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Keeps the persisted selection list consistent with the current loaded apps list.
	/// This is important after uninstall/refresh, because removed apps are no longer visible
	/// and won't appear in SelectionChanged.RemovedItems.
	/// </summary>
	private void PruneSelectionToLoadedApps()
	{
		if (AppsListItemsSourceSelectedItems.Count == 0)
		{
			return;
		}

		HashSet<PackagedAppView> loadedApps = new(new PackagedAppViewIdentityComparer());
		foreach (GroupInfoListForPackagedAppView group in AppsListItemsSourceBackingList)
		{
			foreach (PackagedAppView app in group)
			{
				_ = loadedApps.Add(app);
			}
		}

		if (loadedApps.Count == 0)
		{
			AppsListItemsSourceSelectedItems.Clear();
			SelectedItemsCount = 0;
			return;
		}

		AppsListItemsSourceSelectedItems.IntersectWith(loadedApps);
		SelectedItemsCount = AppsListItemsSourceSelectedItems.Count;
	}

	/// <summary>
	/// Updates the count properties based on current data
	/// </summary>
	private void UpdateCounts()
	{
		// Calculate total count from backing field
		int totalCount = 0;
		foreach (GroupInfoListForPackagedAppView group in AppsListItemsSourceBackingList)
		{
			totalCount += group.Count;
		}
		TotalItemsCount = totalCount;

		// Calculate filtered count from current items source
		int filteredCount = 0;
		foreach (GroupInfoListForPackagedAppView group in AppsListItemsSource)
		{
			filteredCount += group.Count;
		}
		FilteredItemsCount = filteredCount;

		// Selected count is updated in selection changed event
		SelectedItemsCount = AppsListItemsSourceSelectedItems.Count;
	}

	/// <summary>
	/// ListView reference of the UI.
	/// </summary>
	private volatile ListViewBase? UIListView;

	/// <summary>
	/// Event handler for when the ListView is loaded - store reference and sync selection
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	[DynamicWindowsRuntimeCast(typeof(ListViewBase))]
	internal void MainListView_Loaded(object sender, RoutedEventArgs e)
	{
		UIListView = sender as ListViewBase;
		// Restore selection when ListView is loaded
		RestoreSelectionFromViewModel();
	}

	internal void PackagedAppsZoomedOutGroup_Click(object sender, RoutedEventArgs e)
	{
		if (sender is not FrameworkElement { DataContext: ICollectionViewGroup viewGroup })
		{
			return;
		}

		ZoomInToPackagedAppsGroup(viewGroup);
	}

	private void ZoomInToPackagedAppsGroup(ICollectionViewGroup viewGroup)
	{
		if (viewGroup.GroupItems is null || viewGroup.GroupItems.Count is 0)
		{
			return;
		}

		object firstItem = viewGroup.GroupItems[0];

		IsPackagedAppsZoomedInViewActive = true;

		if (UIListView is null)
		{
			return;
		}

		_ = Atlas.AppDispatcher.TryEnqueue(() =>
		{
			UIListView.ScrollIntoView(firstItem);
		});
	}

	/// <summary>
	/// Restores ListView selection from ViewModel's persisted selection state. Runs for the Loaded event handler of the ListView too in order to restore selection when ListView is loaded (important for navigation scenarios).
	/// This is crucial for maintaining selection across navigation when NavigationCacheMode is disabled.
	/// So that when we navigate away and then back to the page, the items that were selected will remain selected.
	/// </summary>
	private void RestoreSelectionFromViewModel()
	{
		if (UIListView == null || AppsListItemsSource.Count == 0 || _isRestoringSelection)
			return;

		// Only restore if there are items to restore and ListView has items
		if (AppsListItemsSourceSelectedItems.Count == 0)
			return;

		_isRestoringSelection = true;

		try
		{
			// Clearing the current ListView selection without triggering selection changed events
			UIListView.SelectedItems.Clear();

			// Building a HashSet of all currently visible PackagedAppView items with the identity comparer.
			HashSet<PackagedAppView> visibleApps = new(new PackagedAppViewIdentityComparer());
			foreach (GroupInfoListForPackagedAppView group in AppsListItemsSource)
			{
				foreach (PackagedAppView app in group)
				{
					_ = visibleApps.Add(app);
				}
			}

			// Restore selection for items that are in the ViewModel's selection list and currently visible
			foreach (PackagedAppView selectedApp in AppsListItemsSourceSelectedItems)
			{
				if (visibleApps.TryGetValue(selectedApp, out PackagedAppView? currentInstance))
				{
					UIListView.SelectedItems.Add(currentInstance);
				}
			}
		}
		finally
		{
			_isRestoringSelection = false;
		}
	}

	/// <summary>
	/// For selecting all items on the UI. Will automatically trigger <see cref="MainListView_SelectionChanged"/> method as well,
	/// Adding the items to <see cref="AppsListItemsSourceSelectedItems"/>.
	/// </summary>
	internal void SelectAllMenuFlyoutItem_Click()
	{
		foreach (GroupInfoListForPackagedAppView group in AppsListItemsSource)
		{
			foreach (PackagedAppView item in group)
			{
				UIListView?.SelectedItems.Add(item);
			}
		}
	}

	/// <summary>
	/// For De-selecting all items on the UI. Will automatically trigger <see cref="MainListView_SelectionChanged"/> method as well,
	/// Removing the items from <see cref="AppsListItemsSourceSelectedItems"/>.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void RemoveSelectionsMenuFlyoutItem_Click()
	{
		AppsListItemsSourceSelectedItems.Clear();
		SelectedItemsCount = 0;
		UIListView?.SelectedItems.Clear();
	}

	/// <summary>
	/// Event handler for the SelectionChanged event of the ListView.
	/// Triggered by <see cref="SelectAllMenuFlyoutItem_Click(object, RoutedEventArgs)"/> and <see cref="RemoveSelectionsMenuFlyoutItem_Click(object, RoutedEventArgs)"/> to keep things consistent.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void MainListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Skip processing if we're currently restoring selection to prevent recursion
		// Also skip while ItemsSource is being updated to avoid clearing persisted selection on ItemsSource replacement
		if (_isRestoringSelection || _isUpdatingItemsSource)
			return;

		foreach (PackagedAppView item in e.AddedItems.Cast<PackagedAppView>())
		{
			_ = AppsListItemsSourceSelectedItems.Add(item);
		}

		foreach (PackagedAppView item in e.RemovedItems.Cast<PackagedAppView>())
		{
			_ = AppsListItemsSourceSelectedItems.Remove(item);
		}

		// Update the selected count based on selection
		SelectedItemsCount = AppsListItemsSourceSelectedItems.Count;
	}

	/// <summary>
	/// Event handler for when the search box of apps list changes
	/// </summary>
	private async void PFNAppFilteringTextBox_TextChanged()
	{
		CancellationTokenSource searchCancellationTokenSource = BeginSearchFilterOperation();
		CancellationToken cancellationToken = searchCancellationTokenSource.Token;
		int filterVersion = Interlocked.Increment(ref _searchFilterVersion);

		try
		{
			await Task.Delay(millisecondsDelay: 250, cancellationToken);

			string searchKeyword = SearchKeyword?.Trim() ?? string.Empty;
			List<GroupInfoListForPackagedAppView> filteredGroups = string.IsNullOrWhiteSpace(searchKeyword)
				? SortPackagedAppGroups(AppsListItemsSourceBackingList)
				: await Task.Run(() => BuildFilteredAppsList(AppsListItemsSourceBackingList, searchKeyword), cancellationToken);

			if (cancellationToken.IsCancellationRequested || filterVersion != _searchFilterVersion)
			{
				return;
			}

			ApplyFilteredAppsList(filteredGroups);
		}
		catch (OperationCanceledException)
		{
			// Intentionally ignored; a newer search request superseded this one.
		}
		finally
		{
			if (ReferenceEquals(Interlocked.CompareExchange(ref _searchFilterCancellationTokenSource, null, searchCancellationTokenSource), searchCancellationTokenSource))
			{
				searchCancellationTokenSource.Dispose();
			}
		}
	}

	/// <summary>
	/// Filters the backing installed apps list using the current search query.
	/// </summary>
	private static List<GroupInfoListForPackagedAppView> BuildFilteredAppsList(IEnumerable<GroupInfoListForPackagedAppView> sourceGroups, string searchKeyword)
	{
		return sourceGroups
			.Select(group => new GroupInfoListForPackagedAppView(
				items: group.Where(app => app.MatchesSearch(searchKeyword)),
				key: group.Key))
			.Where(group => group.Any())
			.OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
			.ToList();
	}

	/// <summary>
	/// Opens the AppContainer loopback exemptions dialog for the currently loaded apps.
	/// </summary>
	internal async void OpenLoopbackExemptionsDialog_Click()
	{
		try
		{
			if (AppsListItemsSourceBackingList.Count == 0)
			{
				await RefreshAppsList();
			}

			List<PackagedAppView> loadedApps = GetAllLoadedApps(AppsListItemsSourceBackingList).ToList();

			using LoopbackExemptionsDialog dialog = new(loadedApps);
			_ = await dialog.ShowAsync();

			if (dialog.HasChanges)
			{
				AppContainerLoopbackManager.UpdatePackagedAppsLoopbackState(loadedApps);
				ApplyCurrentSearchFilterImmediately();
				MainInfoBar.WriteSuccess(Atlas.GetStr("LoopbackDialogChangesApplied"));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal void AddLoopbackExemption_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			PackagedAppView? targetApp = GetPackagedAppFromMenuFlyoutSender(sender);
			if (targetApp is null)
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("CouldNotDetermineWhichAppToAddLoopbackExemption"));
				return;
			}

			ElementsAreEnabled = false;
			MainInfoBar.IsClosable = false;

			AppContainerLoopbackManager.UpdatePackagedAppsLoopbackState([targetApp]);

			if (!targetApp.HasAppContainerSid)
			{
				MainInfoBar.WriteWarning(string.Format(CultureInfo.CurrentCulture, Atlas.GetStr("LoopbackExemptionUnavailableForApp"), targetApp.DisplayName));
				return;
			}

			if (targetApp.LoopbackExempt)
			{
				MainInfoBar.WriteInfo(string.Format(CultureInfo.CurrentCulture, Atlas.GetStr("LoopbackExemptionAlreadyPresent"), targetApp.DisplayName));
				return;
			}

			AppContainerLoopbackManager.SetLoopbackExemption(targetApp.AppContainerSid, true);
			List<PackagedAppView> loadedApps = GetAllLoadedApps(AppsListItemsSourceBackingList).ToList();
			AppContainerLoopbackManager.UpdatePackagedAppsLoopbackState(loadedApps);
			ApplyCurrentSearchFilterImmediately();

			MainInfoBar.WriteSuccess(string.Format(CultureInfo.CurrentCulture, Atlas.GetStr("LoopbackExemptionAddedMessage"), targetApp.DisplayName));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	private CancellationTokenSource BeginSearchFilterOperation()
	{
		CancellationTokenSource searchCancellationTokenSource = new();
		CancellationTokenSource? previousSearchCancellationTokenSource = Interlocked.Exchange(ref _searchFilterCancellationTokenSource, searchCancellationTokenSource);
		try
		{
			previousSearchCancellationTokenSource?.Cancel();
		}
		finally
		{
			previousSearchCancellationTokenSource?.Dispose();
		}
		return searchCancellationTokenSource;
	}

	private void CancelPendingSearchFilter()
	{
		CancellationTokenSource? previousSearchCancellationTokenSource = Interlocked.Exchange(ref _searchFilterCancellationTokenSource, null);
		try
		{
			previousSearchCancellationTokenSource?.Cancel();
		}
		finally
		{
			previousSearchCancellationTokenSource?.Dispose();
		}
	}

	/// <summary>
	/// Releases view-specific references when the page unloads so the singleton view model does not retain stale UI state.
	/// </summary>
	internal void CleanupTransientViewState()
	{
		CancelPendingSearchFilter();

		// The view model outlives the page, so clear the ListView reference to avoid retaining the unloaded visual tree.
		UIListView = null;
	}

	private void ApplyCurrentSearchFilterImmediately()
	{
		CancelPendingSearchFilter();

		List<GroupInfoListForPackagedAppView> filteredGroups = string.IsNullOrWhiteSpace(SearchKeyword)
			? SortPackagedAppGroups(AppsListItemsSourceBackingList)
			: BuildFilteredAppsList(AppsListItemsSourceBackingList, SearchKeyword);

		ApplyFilteredAppsList(filteredGroups);
	}

	private void ApplyFilteredAppsList(List<GroupInfoListForPackagedAppView> filteredGroups)
	{
		_isUpdatingItemsSource = true;
		try
		{
			AppsListItemsSource = new ObservableCollection<GroupInfoListForPackagedAppView>(filteredGroups);
			UpdateCounts();
		}
		finally
		{
			_isUpdatingItemsSource = false;
		}

		RestoreSelectionFromViewModel();
	}

	/// <summary>
	/// Loads expensive storage-size details only when the user opens an app's details area.
	/// This keeps the initial apps list retrieval fast and avoids unnecessary full directory scans.
	/// </summary>
	internal async void AppDetailsExpander_Expanding(Expander sender, ExpanderExpandingEventArgs args)
	{
		try
		{
			if (sender.DataContext is not PackagedAppView app)
			{
				return;
			}

			await GetAppsList.PopulateStorageDetailsAsync(app);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Sorts app groups by their displayed SemanticZoom key so the zoomed-out letters are shown alphabetically.
	/// </summary>
	private static List<GroupInfoListForPackagedAppView> SortPackagedAppGroups(IEnumerable<GroupInfoListForPackagedAppView> groups) =>
		 groups.OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase).ToList();

	private static IEnumerable<PackagedAppView> GetAllLoadedApps(IEnumerable<GroupInfoListForPackagedAppView> groups) =>
		groups.SelectMany(static group => group);

	/// <summary>
	/// Gets the group letter displayed in SemanticZoom's zoomed-out view.
	/// </summary>
	internal static string GetPackagedAppsGroupKey(object? group) => group is GroupInfoListForPackagedAppView packagedAppsGroup ? packagedAppsGroup.Key : string.Empty;

	/// <summary>
	/// Gets the packaged app represented by a context-menu item.
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(MenuFlyoutItem))]
	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	private static PackagedAppView? GetPackagedAppFromMenuFlyoutSender(object sender)
	{
		if (sender is not MenuFlyoutItem menuItem)
		{
			return null;
		}

		DependencyObject? current = menuItem;

		while (current is not null)
		{
			if (current is FrameworkElement element && element.DataContext is PackagedAppView app)
			{
				return app;
			}

			current = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(current);
		}

		return null;
	}

	/// <summary>
	/// Event handler for uninstalling a single app from the context menu.
	/// </summary>
	/// <param name="sender">The MenuFlyoutItem that was clicked</param>
	/// <param name="e">Event arguments</param>
	[DynamicWindowsRuntimeCast(typeof(MenuFlyoutItem))]
	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	internal async void UninstallSingleApp_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			if (sender is not MenuFlyoutItem menuItem)
			{
				return;
			}

			// Navigate up the visual tree to find the PackagedAppView data context
			DependencyObject? current = menuItem;
			PackagedAppView? targetApp = null;

			while (current is not null)
			{
				if (current is FrameworkElement element && element.DataContext is PackagedAppView app)
				{
					targetApp = app;
					break;
				}
				current = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(current);
			}

			if (targetApp is null)
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("CouldNotDetermineWhichAppToUninstall"));
				return;
			}

			if (string.Equals(targetApp.PackageFamilyName, Atlas.PFN, StringComparison.OrdinalIgnoreCase) &&
				await ShowCurrentApplicationUninstallWarningAsync() != ContentDialogResult.Primary)
			{
				return;
			}

			ElementsAreEnabled = false;
			MainInfoBar.IsClosable = false;

			MainInfoBar.WriteInfo(string.Format(Atlas.GetStr("StartingUninstallationOfApp"), targetApp.DisplayName));

			bool error = await UninstallApp(targetApp);

			// Refresh the apps list to reflect changes
			await RefreshAppsList();

			// Show success only if no errors
			if (!error)
			{
				MainInfoBar.WriteSuccess(string.Format(Atlas.GetStr("SuccessfullyUninstalledApp"), targetApp.DisplayName));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for repairing a single app from the context menu.
	/// </summary>
	/// <param name="sender">The MenuFlyoutItem that was clicked</param>
	/// <param name="e">Event arguments</param>
	internal async void RepairApp_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBar.IsClosable = false;

			PackagedAppView? targetApp = GetPackagedAppFromMenuFlyoutSender(sender);
			if (targetApp is null)
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("CouldNotDetermineWhichAppToRepair"));
				return;
			}

			MainInfoBar.WriteInfo(string.Format(CultureInfo.InvariantCulture, Atlas.GetStr("StartingRepairOfApp"), targetApp.DisplayName));

			bool error = await RunPackageMaintenanceOperation(targetApp, PackageMaintenanceOperation.Repair);
			if (!error)
			{
				MainInfoBar.WriteSuccess(string.Format(CultureInfo.InvariantCulture, Atlas.GetStr("SuccessfullyRepairedApp"), targetApp.DisplayName));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for resetting a single app from the context menu.
	/// </summary>
	/// <param name="sender">The MenuFlyoutItem that was clicked</param>
	/// <param name="e">Event arguments</param>
	internal async void ResetApp_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			PackagedAppView? targetApp = GetPackagedAppFromMenuFlyoutSender(sender);
			if (targetApp is null)
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("CouldNotDetermineWhichAppToReset"));
				return;
			}

			using AppControlManager.CustomUIElements.ContentDialogV2 confirmDialog = new()
			{
				Title = Atlas.GetStr("ResetAppConfirmationTitle"),
				Content = string.Format(CultureInfo.InvariantCulture, Atlas.GetStr("ResetAppConfirmationContent"), targetApp.DisplayName),
				PrimaryButtonText = Atlas.GetStr("ResetButton/Content"),
				SecondaryButtonText = Atlas.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Secondary
			};

			ContentDialogResult result = await confirmDialog.ShowAsync();
			if (result is not ContentDialogResult.Primary)
			{
				return;
			}

			ElementsAreEnabled = false;
			MainInfoBar.IsClosable = false;
			MainInfoBar.WriteInfo(string.Format(CultureInfo.InvariantCulture, Atlas.GetStr("StartingResetOfApp"), targetApp.DisplayName));

			bool error = await RunPackageMaintenanceOperation(targetApp, PackageMaintenanceOperation.Reset);
			if (!error)
			{
				MainInfoBar.WriteSuccess(string.Format(CultureInfo.InvariantCulture, Atlas.GetStr("SuccessfullyResetApp"), targetApp.DisplayName));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for terminating a single running packaged app from the context menu.
	/// </summary>
	internal async void TerminateApp_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			PackagedAppView? targetApp = GetPackagedAppFromMenuFlyoutSender(sender);
			if (targetApp is null)
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("CouldNotDetermineWhichAppToTerminate"));
				return;
			}

			ElementsAreEnabled = false;
			MainInfoBar.IsClosable = false;
			MainInfoBar.WriteInfo(string.Format(CultureInfo.InvariantCulture, Atlas.GetStr("StartingTerminationOfApp"), targetApp.DisplayName));

			bool error = await TerminateAppAsync(targetApp);
			if (!error)
			{
				MainInfoBar.WriteSuccess(string.Format(CultureInfo.InvariantCulture, Atlas.GetStr("SuccessfullyTerminatedApp"), targetApp.DisplayName));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Terminates all running resource groups for the selected packaged app.
	/// </summary>
	private async Task<bool> TerminateAppAsync(PackagedAppView package)
	{
		try
		{
			IReadOnlyList<AppResourceGroupInfo> resourceGroups = await GetRunningAppResourceGroupsAsync(package);

			foreach (AppResourceGroupInfo resourceGroup in resourceGroups)
			{
				AppExecutionStateChangeResult terminationResult = await resourceGroup.StartTerminateAsync();
				Exception? extendedError = terminationResult.ExtendedError;

				if (extendedError is not null)
				{
					throw extendedError;
				}
			}

			return false;
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteWarning(string.Format(CultureInfo.InvariantCulture, Atlas.GetStr("AppTerminationFailed"), package.FullName, $"0x{ex.HResult:X8}", ex.Message));
			return true;
		}
	}

	/// <summary>
	/// Gets all running resource groups for a packaged app after validating diagnostic access.
	/// </summary>
	private static async Task<IReadOnlyList<AppResourceGroupInfo>> GetRunningAppResourceGroupsAsync(PackagedAppView package)
	{
		DiagnosticAccessStatus diagnosticAccessStatus = await AppDiagnosticInfo.RequestAccessAsync();
		bool isCurrentPackage = string.Equals(package.PackageFamilyName, Atlas.PFN, StringComparison.OrdinalIgnoreCase);

		if (diagnosticAccessStatus is DiagnosticAccessStatus.Denied or DiagnosticAccessStatus.Unspecified ||
			(diagnosticAccessStatus is DiagnosticAccessStatus.Limited && !isCurrentPackage))
		{
			throw new InvalidOperationException(Atlas.GetStr("AppDiagnosticsAccessDenied"));
		}

		IList<AppDiagnosticInfo> diagnosticInfos = await AppDiagnosticInfo.RequestInfoForPackageAsync(package.PackageFamilyName);
		List<AppResourceGroupInfo> resourceGroups = [];

		foreach (AppDiagnosticInfo diagnosticInfo in diagnosticInfos)
		{
			foreach (AppResourceGroupInfo resourceGroup in diagnosticInfo.GetResourceGroups())
			{
				resourceGroups.Add(resourceGroup);
			}
		}

		if (resourceGroups.Count == 0)
		{
			throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, Atlas.GetStr("AppIsNotCurrentlyRunning"), package.DisplayName));
		}

		return resourceGroups;
	}

	/// <summary>
	/// Runs the selected package maintenance operation on an installed packaged app.
	/// </summary>
	/// <param name="package">The target packaged app.</param>
	/// <param name="operation">The maintenance operation to run.</param>
	/// <returns>true if error occurred, false if OK</returns>
	private async Task<bool> RunPackageMaintenanceOperation(PackagedAppView package, PackageMaintenanceOperation operation)
	{
		try
		{
			if (operation is PackageMaintenanceOperation.Repair)
			{
				await RunNativePackageMaintenanceOperation(package, PackageMaintenanceOperation.Repair);
			}
			else
			{
				await RunNativePackageMaintenanceOperation(package, PackageMaintenanceOperation.Reset);
			}

			return false;
		}
		catch (Exception ex)
		{
			string operationName = operation is PackageMaintenanceOperation.Repair ? Atlas.GetStr("RepairAppText/Text") : Atlas.GetStr("ResetButton/Content");
			MainInfoBar.WriteWarning(string.Format(CultureInfo.InvariantCulture, Atlas.GetStr("PackageMaintenanceOperationFailed"), operationName, package.FullName, $"0x{ex.HResult:X8}", ex.Message));
			return true;
		}
	}

	/// <summary>
	/// Runs a native MSIX package deployment maintenance operation and validates the WinRT deployment result.
	/// </summary>
	/// <param name="package">The target packaged app.</param>
	/// <param name="operation">The maintenance operation to run.</param>
	private static async Task RunNativePackageMaintenanceOperation(PackagedAppView package, PackageMaintenanceOperation operation)
	{
		await Task.Run(() =>
		{
			IntPtr nativeDeploymentOperation = IntPtr.Zero;

			try
			{
				int hResult = operation is PackageMaintenanceOperation.Repair
					? NativeMethods.MsixRepairPackageAsync(package.FullName, out nativeDeploymentOperation)
					: NativeMethods.MsixResetPackageAsync(package.FullName, out nativeDeploymentOperation);

				Marshal.ThrowExceptionForHR(hResult);

				if (nativeDeploymentOperation == IntPtr.Zero)
				{
					throw new InvalidOperationException(Atlas.GetStr("RemovalStatusUnknown"));
				}

				NativeMethods.PackageDeploymentOperationResult operationResult = NativeMethods.WaitForPackageDeploymentOperation(nativeDeploymentOperation);

				if (operationResult.Status is NativeMethods.AsyncStatusError)
				{
					int errorCode = operationResult.ErrorCode < 0
						? operationResult.ErrorCode
						: operationResult.ExtendedErrorCode < 0 ? operationResult.ExtendedErrorCode : unchecked((int)0x80004005);

					Exception? exception = Marshal.GetExceptionForHR(errorCode);

					string errorText = string.IsNullOrWhiteSpace(operationResult.ErrorText) ? exception?.Message ?? string.Format(CultureInfo.InvariantCulture, "0x{0:X8}", errorCode) : operationResult.ErrorText;

					throw new InvalidOperationException($"{errorText} - {errorCode}");
				}
				else if (operationResult.Status is NativeMethods.AsyncStatusCanceled)
				{
					throw new OperationCanceledException(Atlas.GetStr("RemovalCanceled"));
				}
				else if (operationResult.Status is not NativeMethods.AsyncStatusCompleted)
				{
					throw new InvalidOperationException(Atlas.GetStr("RemovalStatusUnknown"));
				}
			}
			finally
			{
				if (nativeDeploymentOperation != IntPtr.Zero)
				{
					NativeMethods.ReleaseComObject(nativeDeploymentOperation);
				}
			}
		});
	}

	/// <summary>
	/// App package maintenance operations supported by the context menu.
	/// </summary>
	private enum PackageMaintenanceOperation
	{
		Repair,
		Reset
	}

	/// <summary>
	/// Event handler for uninstalling multiple selected apps from the toolbar button.
	/// </summary>
	internal async void UninstallSelectedApps_Click()
	{
		if (AppsListItemsSourceSelectedItems.Count == 0)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("NoAppsSelectedForUninstallation"));
			return;
		}

		// Create a copy of selected items to avoid collection modification during iteration
		List<PackagedAppView> appsToUninstall = AppsListItemsSourceSelectedItems.ToList();

		PackagedAppView? currentApplicationPackage = appsToUninstall.FirstOrDefault(x => string.Equals(x.PackageFamilyName, Atlas.PFN, StringComparison.OrdinalIgnoreCase));
		if (currentApplicationPackage is not null && await ShowCurrentApplicationUninstallWarningAsync() != ContentDialogResult.Primary)
		{
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBar.IsClosable = false;

			MainInfoBar.WriteInfo(string.Format(Atlas.GetStr("StartingUninstallationOfMultipleApps"), appsToUninstall.Count));

			using IDisposable taskTracker = TaskTracking.RegisterOperation();

			bool error = false;

			int failed = 0;

			List<string> successfullAppNames = [];
			List<string> failedAppNames = [];

			foreach (PackagedAppView app in appsToUninstall)
			{
				bool currentAppError = await UninstallApp(app);

				if (currentAppError)
				{
					failed++;
					failedAppNames.Add(app.DisplayName);
				}
				else
				{
					successfullAppNames.Add(app.DisplayName);
				}

				if (!error && currentAppError)
				{
					error = currentAppError;
				}
			}

			// Refresh the apps list to reflect changes
			await RefreshAppsList();

			// Show success only if no errors
			if (!error)
			{
				MainInfoBar.WriteInfo($"Apps that were successfully uninstalled: {string.Join(", ", successfullAppNames)}");
				MainInfoBar.WriteSuccess(Atlas.GetStr("AllAppsSuccessfullyUninstalled"));
			}
			else
			{
				if (successfullAppNames.Count > 0)
					MainInfoBar.WriteInfo($"Apps that were successfully uninstalled: {string.Join(", ", successfullAppNames)}");

				MainInfoBar.WriteInfo($"Apps that could not be uninstalled: {string.Join(", ", failedAppNames)}");

				MainInfoBar.WriteInfo($"Some apps could not be successfully uninstalled. Total: {appsToUninstall.Count} - Failed: {failed} - Successful: {appsToUninstall.Count - failed}. Please view the logs for more information.");
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Shows a warning dialog when the user tries to uninstall the running app.
	/// </summary>
	private static async Task<ContentDialogResult> ShowCurrentApplicationUninstallWarningAsync()
	{
		using AppControlManager.CustomUIElements.ContentDialogV2 warningDialog = new()
		{
			Title = Atlas.GetStr("WarningTitle"),
			Content = Atlas.GetStr("InstalledAppsManagementCurrentAppUninstallWarning"),
			CloseButtonText = Atlas.GetStr("Cancel"),
			PrimaryButtonText = Atlas.GetStr("Continue"),
			DefaultButton = ContentDialogButton.Close
		};

		return await warningDialog.ShowAsync();
	}

	/// <summary>
	/// The main method that actually uninstalls an app.
	/// </summary>
	/// <param name="package"></param>
	/// <returns>true if error occurred, false if OK</returns>
	private async Task<bool> UninstallApp(PackagedAppView package)
	{
		bool error = false;

		try
		{
			await Task.Run(async () =>
			{
				// Remove the app
				IAsyncOperationWithProgress<DeploymentResult, DeploymentProgress> deploymentOperation = PackageMgr.RemovePackageAsync(package.FullName, RemovalOptions.RemoveForAllUsers);

				// This event is signaled when the operation completes
				using ManualResetEvent opCompletedEvent = new(false);

				// Define the delegate using a statement lambda
				deploymentOperation.Completed = (depProgress, status) => { _ = opCompletedEvent.Set(); };

				// Wait until the operation completes
				_ = opCompletedEvent.WaitOne();

				// Check the status of the operation
				if (deploymentOperation.Status is AsyncStatus.Error)
				{
					DeploymentResult deploymentResult = deploymentOperation.GetResults();

					error = true;

					MainInfoBar.WriteWarning(string.Format(Atlas.GetStr("ErrorCodeAndText"), deploymentOperation.ErrorCode, deploymentResult.ErrorText));

					if (deploymentOperation.ErrorCode is UnauthorizedAccessException)
					{
						throw new UnauthorizedAccessException();
					}
				}
				else if (deploymentOperation.Status is AsyncStatus.Canceled)
				{
					error = true;
					MainInfoBar.WriteWarning(Atlas.GetStr("RemovalCanceled"));
				}
				else if (deploymentOperation.Status is AsyncStatus.Completed)
				{
					error = false;
					MainInfoBar.WriteInfo(string.Format(Atlas.GetStr("AppSuccessfullyRemoved"), package.FullName));
				}
				else
				{
					error = true;
					MainInfoBar.WriteWarning(Atlas.GetStr("RemovalStatusUnknown"));
				}
			});
		}
		catch (UnauthorizedAccessException)
		{
			MainInfoBar.WriteInfo(string.Format(Atlas.GetStr("TryingToRemoveAppForCurrentUserOnly"), package.FullName));

			await Task.Run(async () =>
			{
				// Remove the app
				IAsyncOperationWithProgress<DeploymentResult, DeploymentProgress> deploymentOperation = PackageMgr.RemovePackageAsync(package.FullName, RemovalOptions.None);

				// This event is signaled when the operation completes
				using ManualResetEvent opCompletedEvent = new(false);

				// Define the delegate using a statement lambda
				deploymentOperation.Completed = (depProgress, status) => { _ = opCompletedEvent.Set(); };

				// Wait until the operation completes
				_ = opCompletedEvent.WaitOne();

				// Check the status of the operation
				if (deploymentOperation.Status is AsyncStatus.Error)
				{
					DeploymentResult deploymentResult = deploymentOperation.GetResults();

					error = true;
					MainInfoBar.WriteWarning(string.Format(Atlas.GetStr("ErrorCodeAndText"), deploymentOperation.ErrorCode, deploymentResult.ErrorText));
				}
				else if (deploymentOperation.Status is AsyncStatus.Canceled)
				{
					error = true;
					MainInfoBar.WriteWarning(Atlas.GetStr("RemovalCanceled"));
				}
				else if (deploymentOperation.Status is AsyncStatus.Completed)
				{
					error = false;
					MainInfoBar.WriteInfo(string.Format(Atlas.GetStr("AppSuccessfullyRemoved"), package.FullName));
				}
				else
				{
					error = true;
					MainInfoBar.WriteWarning(Atlas.GetStr("RemovalStatusUnknown"));
				}
			});
		}

		return error;
	}

	/// <summary>
	/// Event handler for opening the installation location of a single app from the context menu.
	/// </summary>
	/// <param name="sender">The MenuFlyoutItem that was clicked</param>
	/// <param name="e">Event arguments</param>
	[DynamicWindowsRuntimeCast(typeof(MenuFlyoutItem))]
	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	internal async void OpenAppLocation_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			MainInfoBar.IsClosable = false;

			if (sender is not MenuFlyoutItem menuItem)
			{
				return;
			}

			// Navigate up the visual tree to find the PackagedAppView data context
			DependencyObject? current = menuItem;
			PackagedAppView? targetApp = null;

			while (current is not null)
			{
				if (current is FrameworkElement element && element.DataContext is PackagedAppView app)
				{
					targetApp = app;
					break;
				}
				current = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(current);
			}

			if (targetApp is null)
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("CouldNotDetermineWhichAppLocationToOpen"));
				return;
			}

			if (string.IsNullOrWhiteSpace(targetApp.InstallLocation))
			{
				MainInfoBar.WriteWarning(string.Format(Atlas.GetStr("NoInstallationLocationAvailable"), targetApp.DisplayName));
				return;
			}

			// Check if the directory exists
			if (!Directory.Exists(targetApp.InstallLocation))
			{
				MainInfoBar.WriteWarning(string.Format(Atlas.GetStr("InstallationLocationDoesNotExist"), targetApp.InstallLocation));
				return;
			}

			// Open the folder in File Explorer
			await OpenFileInDefaultFileHandler(targetApp.InstallLocation);

			MainInfoBar.WriteInfo(string.Format(Atlas.GetStr("OpenedInstallationLocation"), targetApp.DisplayName));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for copying app details to clipboard from the context menu.
	/// </summary>
	/// <param name="sender">The MenuFlyoutItem that was clicked</param>
	/// <param name="e">Event arguments</param>
	[DynamicWindowsRuntimeCast(typeof(MenuFlyoutItem))]
	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	internal async void CopyAppDetails_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			MainInfoBar.IsClosable = false;

			if (sender is not MenuFlyoutItem menuItem)
			{
				return;
			}

			// Navigate up the visual tree to find the PackagedAppView data context
			DependencyObject? current = menuItem;
			PackagedAppView? targetApp = null;

			while (current is not null)
			{
				if (current is FrameworkElement element && element.DataContext is PackagedAppView app)
				{
					targetApp = app;
					break;
				}
				current = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(current);
			}

			if (targetApp is null)
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("CouldNotDetermineWhichAppDetailsToCopy"));
				return;
			}

			await GetAppsList.PopulateStorageDetailsAsync(targetApp);

			ListViewHelper.ConvertRowToText([targetApp], ListViewHelper.PackagedAppPropertyMappings);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBar.IsClosable = true;
		}
	}

	#region Export to JSON

	/// <summary>
	/// Exports all of the installed apps to a JSON file.
	/// </summary>
	internal async void ExportToJson_Click()
	{
		try
		{
			if (AppsListItemsSourceBackingList.Count == 0)
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("NoInstalledAppsForExport"));
				return;
			}

			ElementsAreEnabled = false;
			MainInfoBar.IsClosable = false;

			// Flatten the groups into a single list
			List<PackagedAppView> itemsToExport = [];
			foreach (GroupInfoListForPackagedAppView group in AppsListItemsSourceBackingList)
			{
				foreach (PackagedAppView m in group)
				{
					itemsToExport.Add(m);
				}
			}

			if (itemsToExport.Count == 0)
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("NoInstalledAppsForExport"));
				return;
			}

			foreach (PackagedAppView item in itemsToExport)
			{
				await GetAppsList.PopulateStorageDetailsAsync(item);
			}

			DateTime now = DateTime.Now;
			string defaultFileName = $"Installed Apps {now:yyyy-MM-dd_HH-mm-ss}.json";

			string? savePath = FileDialogHelper.ShowSaveFileDialog(Atlas.JSONPickerFilter, defaultFileName);
			if (string.IsNullOrWhiteSpace(savePath))
			{
				return;
			}

			await Task.Run(() =>
			{
				string json = PackagedAppViewJsonContext.SerializeList(itemsToExport);
				File.WriteAllText(savePath, json, Encoding.UTF8);
			});

			MainInfoBar.WriteSuccess(string.Format(Atlas.GetStr("SuccessfullyExportedInstalledApps"), itemsToExport.Count, savePath));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	#endregion

}
