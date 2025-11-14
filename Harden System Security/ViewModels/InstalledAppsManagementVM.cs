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
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using HardenSystemSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Foundation;
using Windows.Management.Deployment;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class InstalledAppsManagementVM : ViewModelBase
{

	internal InstalledAppsManagementVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);
	}

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	public InfoBarSettings MainInfoBar { get; }

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	public Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	public bool ElementsAreEnabled
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
	internal static PackageManager PackageMgr = new();

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

	internal async Task RefreshAppsList()
	{
		try
		{
			ElementsAreEnabled = false;

			// Get the new data first
			ObservableCollection<GroupInfoListForPackagedAppView> newItems = await GetAppsList.GetContactsGroupedAsync(this);

			// Suppress selection change side effects while replacing ItemsSource to preserve persisted selection
			_isUpdatingItemsSource = true;
			try
			{
				AppsListItemsSource = newItems;
				AppsListItemsSourceBackingList = AppsListItemsSource.ToList();

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
	internal volatile ListViewBase? UIListView;

	/// <summary>
	/// Event handler for when the ListView is loaded - store reference and sync selection
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void MainListView_Loaded(object sender, RoutedEventArgs e)
	{
		UIListView = sender as ListViewBase;
		// Restore selection when ListView is loaded
		RestoreSelectionFromViewModel();
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
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void SelectAllMenuFlyoutItem_Click(object sender, RoutedEventArgs e)
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
	internal void RemoveSelectionsMenuFlyoutItem_Click(object sender, RoutedEventArgs e)
	{
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
	private void PFNAppFilteringTextBox_TextChanged()
	{
		if (string.IsNullOrWhiteSpace(SearchKeyword))
		{
			_isUpdatingItemsSource = true;
			try
			{
				// If the filter is cleared, restore the original collection
				AppsListItemsSource = new(AppsListItemsSourceBackingList);
				UpdateCounts();
			}
			finally
			{
				_isUpdatingItemsSource = false;
			}

			// Restore selection after clearing search
			RestoreSelectionFromViewModel();
			return;
		}

		// Filter the original collection
		List<GroupInfoListForPackagedAppView> filtered = AppsListItemsSourceBackingList
			.Select(group => new GroupInfoListForPackagedAppView(
				items: group.Where(app =>
					(app.DisplayName?.Contains(SearchKeyword, StringComparison.OrdinalIgnoreCase) == true) ||
					(app.Version?.Contains(SearchKeyword, StringComparison.OrdinalIgnoreCase) == true) ||
					(app.PackageFamilyName?.Contains(SearchKeyword, StringComparison.OrdinalIgnoreCase) == true) ||
					(app.Publisher?.Contains(SearchKeyword, StringComparison.OrdinalIgnoreCase) == true) ||
					(app.Architecture?.Contains(SearchKeyword, StringComparison.OrdinalIgnoreCase) == true) ||
					(app.PublisherID?.Contains(SearchKeyword, StringComparison.OrdinalIgnoreCase) == true) ||
					(app.FullName?.Contains(SearchKeyword, StringComparison.OrdinalIgnoreCase) == true) ||
					(app.Description?.Contains(SearchKeyword, StringComparison.OrdinalIgnoreCase) == true) ||
					(app.InstallLocation?.Contains(SearchKeyword, StringComparison.OrdinalIgnoreCase) == true) ||
					(app.InstalledDate?.Contains(SearchKeyword, StringComparison.OrdinalIgnoreCase) == true)
				),
				key: group.Key)).Where(group => group.Any()).ToList();

		_isUpdatingItemsSource = true;
		try
		{
			// Update the ListView source with the filtered data
			AppsListItemsSource = new ObservableCollection<GroupInfoListForPackagedAppView>(filtered);
			UpdateCounts();
		}
		finally
		{
			_isUpdatingItemsSource = false;
		}

		// Restore selection after filtering (only items that match search will be selected)
		RestoreSelectionFromViewModel();
	}

	/// <summary>
	/// Event handler for uninstalling a single app from the context menu.
	/// </summary>
	/// <param name="sender">The MenuFlyoutItem that was clicked</param>
	/// <param name="e">Event arguments</param>
	internal async void UninstallSingleApp_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

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
				MainInfoBar.WriteWarning(GlobalVars.GetStr("CouldNotDetermineWhichAppToUninstall"));
				return;
			}

			MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("StartingUninstallationOfApp"), targetApp.DisplayName));

			// Show success only if no errors
			if (!await UninstallApp(targetApp))
				MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyUninstalledApp"), targetApp.DisplayName));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for uninstalling multiple selected apps from the toolbar button.
	/// </summary>
	/// <param name="sender">The Button that was clicked</param>
	/// <param name="e"></param>
	internal async void UninstallSelectedApps_Click(object sender, RoutedEventArgs e)
	{
		if (AppsListItemsSourceSelectedItems.Count == 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("NoAppsSelectedForUninstallation"));
			return;
		}

		// Create a copy of selected items to avoid collection modification during iteration
		List<PackagedAppView> appsToUninstall = AppsListItemsSourceSelectedItems.ToList();

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("StartingUninstallationOfMultipleApps"), appsToUninstall.Count));

			bool error = false;

			foreach (PackagedAppView app in appsToUninstall)
			{
				error = await UninstallApp(app);

				if (error) break;
			}

			// Show success only if no errors
			if (!error)
				MainInfoBar.WriteSuccess(GlobalVars.GetStr("AllAppsSuccessfullyUninstalled"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// The main method that actually uninstalls an app.
	/// </summary>
	/// <param name="package"></param>
	/// <returns>true if error occurred, false if OK</returns>
	internal async Task<bool> UninstallApp(PackagedAppView package)
	{
		bool error = false;

		try
		{
			await Task.Run(async () =>
			{
				// Remove the app
				IAsyncOperationWithProgress<DeploymentResult, DeploymentProgress> deploymentOperation = PackageMgr.RemovePackageAsync(package.FullName, RemovalOptions.RemoveForAllUsers);

				// This event is signaled when the operation completes
				ManualResetEvent opCompletedEvent = new(false);

				// Define the delegate using a statement lambda
				deploymentOperation.Completed = (depProgress, status) => { _ = opCompletedEvent.Set(); };

				// Wait until the operation completes
				_ = opCompletedEvent.WaitOne();

				// Check the status of the operation
				if (deploymentOperation.Status is AsyncStatus.Error)
				{
					DeploymentResult deploymentResult = deploymentOperation.GetResults();

					error = true;

					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("ErrorCodeAndText"), deploymentOperation.ErrorCode, deploymentResult.ErrorText));

					if (deploymentOperation.ErrorCode is UnauthorizedAccessException)
					{
						throw new UnauthorizedAccessException();
					}
				}
				else if (deploymentOperation.Status is AsyncStatus.Canceled)
				{
					error = true;
					MainInfoBar.WriteWarning(GlobalVars.GetStr("RemovalCanceled"));
				}
				else if (deploymentOperation.Status is AsyncStatus.Completed)
				{
					error = false;
					MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("AppSuccessfullyRemoved"), package.FullName));
				}
				else
				{
					error = true;
					MainInfoBar.WriteWarning(GlobalVars.GetStr("RemovalStatusUnknown"));
				}
			});
		}
		catch (UnauthorizedAccessException)
		{
			MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("TryingToRemoveAppForCurrentUserOnly"), package.FullName));

			await Task.Run(async () =>
			{
				// Remove the app
				IAsyncOperationWithProgress<DeploymentResult, DeploymentProgress> deploymentOperation = PackageMgr.RemovePackageAsync(package.FullName, RemovalOptions.None);

				// This event is signaled when the operation completes
				ManualResetEvent opCompletedEvent = new(false);

				// Define the delegate using a statement lambda
				deploymentOperation.Completed = (depProgress, status) => { _ = opCompletedEvent.Set(); };

				// Wait until the operation completes
				_ = opCompletedEvent.WaitOne();

				// Check the status of the operation
				if (deploymentOperation.Status is AsyncStatus.Error)
				{
					DeploymentResult deploymentResult = deploymentOperation.GetResults();

					error = true;
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("ErrorCodeAndText"), deploymentOperation.ErrorCode, deploymentResult.ErrorText));
				}
				else if (deploymentOperation.Status is AsyncStatus.Canceled)
				{
					error = true;
					MainInfoBar.WriteWarning(GlobalVars.GetStr("RemovalCanceled"));
				}
				else if (deploymentOperation.Status is AsyncStatus.Completed)
				{
					error = false;
					MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("AppSuccessfullyRemoved"), package.FullName));
				}
				else
				{
					error = true;
					MainInfoBar.WriteWarning(GlobalVars.GetStr("RemovalStatusUnknown"));
				}
			});
		}

		// Refresh the apps list to reflect changes
		await RefreshAppsList();

		return error;
	}


	/// <summary>
	/// Event handler for opening the installation location of a single app from the context menu.
	/// </summary>
	/// <param name="sender">The MenuFlyoutItem that was clicked</param>
	/// <param name="e">Event arguments</param>
	internal async void OpenAppLocation_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			MainInfoBarIsClosable = false;

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
				MainInfoBar.WriteWarning(GlobalVars.GetStr("CouldNotDetermineWhichAppLocationToOpen"));
				return;
			}

			if (string.IsNullOrWhiteSpace(targetApp.InstallLocation))
			{
				MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("NoInstallationLocationAvailable"), targetApp.DisplayName));
				return;
			}

			// Check if the directory exists
			if (!Directory.Exists(targetApp.InstallLocation))
			{
				MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("InstallationLocationDoesNotExist"), targetApp.InstallLocation));
				return;
			}

			// Open the folder in File Explorer
			await OpenInDefaultFileHandler(targetApp.InstallLocation);

			MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("OpenedInstallationLocation"), targetApp.DisplayName));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for copying app details to clipboard from the context menu.
	/// </summary>
	/// <param name="sender">The MenuFlyoutItem that was clicked</param>
	/// <param name="e">Event arguments</param>
	internal void CopyAppDetails_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			MainInfoBarIsClosable = false;

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
				MainInfoBar.WriteWarning(GlobalVars.GetStr("CouldNotDetermineWhichAppDetailsToCopy"));
				return;
			}

			ListViewHelper.ConvertRowToText([targetApp], ListViewHelper.PackagedAppPropertyMappings);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBarIsClosable = true;
		}
	}

	#region Export to JSON

	/// <summary>
	/// Exports all of the installed apps to a JSON file.
	/// </summary>
	internal async void ExportToJson_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			if (AppsListItemsSourceBackingList.Count == 0)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("NoInstalledAppsForExport"));
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
				MainInfoBar.WriteWarning(GlobalVars.GetStr("NoInstalledAppsForExport"));
				return;
			}

			DateTime now = DateTime.Now;
			string defaultFileName = $"Installed Apps {now:yyyy-MM-dd_HH-mm-ss}.json";

			string? savePath = FileDialogHelper.ShowSaveFileDialog(GlobalVars.JSONPickerFilter, defaultFileName);
			if (string.IsNullOrWhiteSpace(savePath))
			{
				return;
			}

			await Task.Run(() =>
			{
				string json = PackagedAppViewJsonContext.SerializeList(itemsToExport);
				File.WriteAllText(savePath, json, Encoding.UTF8);
			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyExportedInstalledApps"), itemsToExport.Count, savePath));
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
