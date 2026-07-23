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
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using CommonCore.IncrementalCollection;
using HardenSystemSecurity.WinGet;
using Microsoft.Management.Deployment;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.Foundation;
using Windows.System;
using WinRT;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class WinGetManagementVM : ViewModelBase, IDisposable
{
	/*
	WinGet page behavior rules. The core logic is based on: https://github.com/microsoft/winget-cli

	1. The Search results surface represents package results returned from configured WinGet sources. It offers install or update, download, refresh status, installation notes, and cancellation. Repair and uninstall are intentionally not offered on this surface because a search result is not treated as the authoritative installed program entry.

	2. The Installed programs surface represents packages that are installed on the device and naturally marks programs with available updates. It can offer update, reinstall, download, repair, uninstall, refresh status, and cancellation.

	3. Install and update actions follow WinGet's explicit mode and scope model. The primary install or update click uses PackageInstallMode.Default with PackageInstallScope.Any, which corresponds to not forcing silent mode, interactive mode, user scope, or system scope.

	4. Silent and Interactive install choices are separate SplitMenuFlyoutItem entries. Clicking the Silent row uses PackageInstallMode.Silent with PackageInstallScope.Any. Clicking the Interactive row uses PackageInstallMode.Interactive with PackageInstallScope.Any. Their child menu items are explicit scope overrides: Current user maps to PackageInstallScope.User, and System maps to PackageInstallScope.System.

	5. Uninstall actions follow the same pattern. The primary Uninstall click uses PackageUninstallMode.Default with PackageUninstallScope.Any. Silent uninstall is available as an explicit user choice, but it is not forced as the default uninstall path. Clicking the Silent row uses PackageUninstallMode.Silent with PackageUninstallScope.Any, and clicking the Interactive row uses PackageUninstallMode.Interactive with PackageUninstallScope.Any.

	6. Current user and System child items under uninstall are explicit scope overrides. Current user maps to PackageUninstallScope.User, and System maps to PackageUninstallScope.System.

	7. System scope menu items are enabled only when the app process is elevated. XAML binds directly to the static Atlas.IsElevated property with compiled x:Bind. User scope remains available without elevation.

	8. The selected mode and scope values are passed through to the WinGet COM API service layer. Install and update actions set InstallOptions.PackageInstallMode and InstallOptions.PackageInstallScope. Uninstall actions set UninstallOptions.PackageUninstallMode and UninstallOptions.PackageUninstallScope.

	9. Reinstall is treated as an install or update request for a package that is already installed and has no available update. Before reinstalling, package metadata is refreshed so the operation has the latest available installer information. If no applicable installer is found, the operation reports a warning instead of surfacing an unclear install failure.

	10. Individual package install and update actions show the app-level package agreements dialog before the WinGet operation starts. Search results toolbar bulk install and update actions skip that app-level dialog so selected packages can be installed unattended. The WinGet service layer still passes AcceptPackageAgreements to the API operation.

	11. Individual package uninstall actions show the app-level confirmation dialog before the WinGet operation starts. Installed programs toolbar bulk uninstall actions skip that app-level dialog so selected packages can be uninstalled unattended.

	12. Bulk package actions run sequentially against the selected items captured at the beginning of the operation. Each ListView registry key has its own CancellationTokenSource and selected item snapshot so Search results and Installed programs can be canceled independently.

	13. The toolbar Cancel buttons cancel the section bulk action token and also request cancellation of the active WinGet operation through the active package operation cancellation registration.

	14. Installed programs are cached and filtered locally by the search box and the updates-only toggle. Individual successful uninstalls refresh package status and then reload Installed programs immediately. Installed programs toolbar bulk uninstall actions refresh each package status but defer the full Installed programs reload until the selected uninstall loop finishes successfully.

	15. Private async helpers that accept a CancellationToken keep the token as the last parameter to comply with CA1068.
	*/

	private CancellationTokenSource? searchCancellationTokenSource;
	private CancellationTokenSource? installedCancellationTokenSource;
	private readonly Dictionary<ListViewHelper.ListViewsRegistry, CancellationTokenSource> bulkPackageActionCancellationTokenSources = [];
	private CancellationTokenSource? bulkSourceActionCancellationTokenSource;
	private IAsyncInfo? sourceOperation;
	private bool isSourceOperationCancellationRequested;
	private const string AnyPackageSearchSourceOption = "Any";
	private readonly List<WinGetPackageSearchResult> installedProgramsCache = [];
	internal readonly InfoBarSettings MainInfoBar = new();
	internal readonly RangedObservableCollection<WinGetPackageSearchResult> SearchResults = [];
	internal readonly ObservableCollection<WinGetPackageSearchResult> InstalledPrograms = [];
	internal readonly ObservableCollection<WinGetSourceInfo> Sources = [];

	#region WinGet package bundles

	private CancellationTokenSource? bundleOperationCancellationTokenSource;
	internal readonly List<WinGetPackageBundle> PackageBundles = CreatePackageBundles();

	internal WinGetPackageBundle? SelectedPackageBundle
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(SelectedPackageBundleTitle));
				OnPropertyChanged(nameof(SelectedPackageBundlePackages));
			}
		}
	}

	internal string SelectedPackageBundleTitle => SelectedPackageBundle?.Name ?? string.Empty;

	internal IReadOnlyList<WinGetPackageBundlePackage> SelectedPackageBundlePackages => SelectedPackageBundle?.Packages ?? [];

	internal bool BundlesUIElementsAreEnabled
	{
		get; private set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(IsBundleOperationCancelButtonEnabled));
				OnPropertyChanged(nameof(BundleOperationProgressRingVisibility));
			}
		}
	} = true;

	internal bool IsBundleOperationCancelButtonEnabled => !BundlesUIElementsAreEnabled && bundleOperationCancellationTokenSource is not null;

	internal Visibility BundleOperationProgressRingVisibility => BundlesUIElementsAreEnabled ? Visibility.Collapsed : Visibility.Visible;

	internal string BundleOperationStatus { get; private set => SP(ref field, value); } = "Choose an app bundle to install or uninstall.";

	#endregion

	internal readonly List<string> PackageSearchFieldOptions = ["Default", "Package ID", "App name", "Moniker", "Tag", "Command"];
	internal readonly List<string> PackageSearchMatchModeOptions = ["Contains, ignore case", "Equals, ignore case", "Equals, match case"];
	internal readonly ObservableCollection<string> PackageSearchSourceOptions = [];
	internal readonly List<string> SourceTrustLevelOptions = [PackageCatalogTrustLevel.None.ToString(), PackageCatalogTrustLevel.Trusted.ToString()];
	// Keep source type selection constrained to the source types documented by WinGet.
	internal readonly List<string> SourceTypeOptions = ["Microsoft.PreIndexed.Package", "Microsoft.Rest"];
	internal readonly string WinGetEngineVersion = WinGetPackageSearchService.GetWinGetEngineVersion();

	internal WinGetManagementVM() => RefreshPackageSearchSourceOptions();

	internal string SourceName
	{
		get; set
		{
			if (SP(ref field, value ?? string.Empty))
			{
				OnPropertyChanged(nameof(IsAddSourceButtonEnabled));
			}
		}
	} = string.Empty;

	internal string SourceUri
	{
		get; set
		{
			if (SP(ref field, value ?? string.Empty))
			{
				OnPropertyChanged(nameof(IsAddSourceButtonEnabled));
			}
		}
	} = string.Empty;

	internal string SourceType => SourceTypeOptions[SelectedSourceTypeValue];

	internal int SelectedSourceTypeValue
	{
		get; set
		{
			int normalizedValue = Math.Clamp(value, 0, SourceTypeOptions.Count - 1);
			_ = SP(ref field, normalizedValue);
		}
	}

	internal int SelectedSourceTrustLevelValue { get; set => SP(ref field, value); }

	internal string SearchQuery { get; set => SP(ref field, value ?? string.Empty); } = string.Empty;

	internal string InstalledProgramsSearchQuery
	{
		get; set
		{
			if (SP(ref field, value ?? string.Empty))
			{
				ApplyInstalledProgramsFilter();
			}
		}
	} = string.Empty;

	internal bool ShowOnlyInstalledProgramsWithUpdates
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ApplyInstalledProgramsFilter();
			}
		}
	}

	internal bool SearchPackageUIElementsAreEnabled
	{
		get; private set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(IsSearchCancelButtonEnabled));
				OnPropertyChanged(nameof(SearchProgressRingVisibility));
			}
		}
	} = true;

	internal bool InstalledProgramsUIElementsAreEnabled
	{
		get; private set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(IsInstalledProgramsCancelButtonEnabled));
				OnPropertyChanged(nameof(InstalledProgramsProgressRingVisibility));
			}
		}
	} = true;

	internal bool SourcesUIElementsAreEnabled
	{
		get; private set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(IsSourceOperationCancelButtonEnabled));
			}
		}
	} = true;

	internal bool IsLoadingInstalledPrograms
	{
		get; private set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(IsInstalledProgramsCancelButtonEnabled));
				OnPropertyChanged(nameof(InstalledProgramsProgressRingVisibility));
			}
		}
	}

	internal bool IsSourceOperationRunning
	{
		get; private set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(IsAddSourceButtonEnabled));
				OnPropertyChanged(nameof(IsSourceOperationCancelButtonEnabled));
			}
		}
	}

	internal bool IsAddSourceButtonEnabled => SourcesUIElementsAreEnabled && !IsSourceOperationRunning && !string.IsNullOrWhiteSpace(SourceName) && !string.IsNullOrWhiteSpace(SourceUri);
	internal bool IsSearchCancelButtonEnabled => !SearchPackageUIElementsAreEnabled;
	internal bool IsInstalledProgramsCancelButtonEnabled => !InstalledProgramsUIElementsAreEnabled;
	internal bool IsSourceOperationCancelButtonEnabled => !SourcesUIElementsAreEnabled;
	internal Visibility SearchProgressRingVisibility => SearchPackageUIElementsAreEnabled ? Visibility.Collapsed : Visibility.Visible;
	internal Visibility InstalledProgramsProgressRingVisibility => InstalledProgramsUIElementsAreEnabled ? Visibility.Collapsed : Visibility.Visible;
	internal bool HasSearchResults => SearchResults.Count > 0;
	internal bool HasInstalledPrograms => InstalledPrograms.Count > 0;
	internal bool HasSources => Sources.Count > 0;
	internal int SearchResultsCount => SearchResults.Count;
	internal int InstalledProgramsCount => InstalledPrograms.Count;
	internal int InstalledProgramsTotalCount => installedProgramsCache.Count;
	internal int SourcesCount => Sources.Count;
	internal int SelectedSearchResultsCount { get; private set => SP(ref field, value); }
	internal int SelectedInstalledProgramsCount { get; private set => SP(ref field, value); }
	internal int SelectedSourcesCount { get; private set => SP(ref field, value); }
	internal bool IsWinGetSettingsPaneOpen { get; set => SP(ref field, value); }
	internal string ResultsStatusText { get; private set => SP(ref field, value); } = "Search for packages by name, ID, moniker, command, or tag.";
	internal string InstalledProgramsStatusText { get; private set => SP(ref field, value); } = "Select refresh to query installed programs.";
	internal string SourcesStatusText { get; private set => SP(ref field, value); } = "Select refresh to list configured WinGet sources.";
	internal string CustomDownloadDirectorySetting
	{
		get; set
		{
			string normalized = string.IsNullOrWhiteSpace(value)
				? string.Empty
				: Path.GetFullPath(value);
			if (SP(ref field, normalized))
			{
				Atlas.Settings.WinGetDownloadDirectory = field;
				OnPropertyChanged(nameof(ResolvedDownloadDirectory));
				OnPropertyChanged(nameof(IsUsingDefaultDownloadDirectory));
				OnPropertyChanged(nameof(CanResetDownloadDirectory));
			}
		}
	} = Atlas.Settings.WinGetDownloadDirectory;

	internal string ResolvedDownloadDirectory => string.IsNullOrWhiteSpace(CustomDownloadDirectorySetting)
		? DownloadManagerVM.ResolveDefaultDownloadsDirectory()
		: CustomDownloadDirectorySetting;
	internal bool IsUsingDefaultDownloadDirectory => string.IsNullOrWhiteSpace(CustomDownloadDirectorySetting);
	internal bool CanResetDownloadDirectory => !IsUsingDefaultDownloadDirectory;

	internal int SelectedPackageSearchFieldValue
	{
		get; set
		{
			int normalizedValue = (WinGetPackageSearchField)value switch
			{
				WinGetPackageSearchField.CatalogDefault or WinGetPackageSearchField.PackageId or WinGetPackageSearchField.Name or WinGetPackageSearchField.Moniker or WinGetPackageSearchField.Tag or WinGetPackageSearchField.Command => value,
				_ => (int)WinGetPackageSearchField.CatalogDefault
			};
			_ = SP(ref field, normalizedValue);
		}
	}

	internal int SelectedPackageSearchMatchModeValue
	{
		get; set
		{
			int normalizedValue = (WinGetPackageSearchMatchMode)value switch
			{
				WinGetPackageSearchMatchMode.ContainsCaseInsensitive or WinGetPackageSearchMatchMode.EqualsCaseInsensitive or WinGetPackageSearchMatchMode.EqualsCaseSensitive => value,
				_ => (int)WinGetPackageSearchMatchMode.ContainsCaseInsensitive
			};
			_ = SP(ref field, normalizedValue);
		}
	}

	internal int SelectedPackageSearchSourceValue
	{
		get; set
		{
			int normalizedValue = Math.Clamp(value, 0, Math.Max(0, PackageSearchSourceOptions.Count - 1));
			// Re-notify even when the selected index did not change because rebuilding PackageSearchSourceOptions can clear the ComboBox selection while the ViewModel value remains valid.
			if (!SP(ref field, normalizedValue)) _ = Atlas.AppDispatcher.TryEnqueue(() => OnPropertyChanged(nameof(SelectedPackageSearchSourceValue)));
		}
	}

	internal int SearchResultLimit
	{
		get; set
		{
			int normalizedValue = Math.Clamp(value, 1, WinGetPackageSearchService.MaximumResultLimit);
			if (SP(ref field, normalizedValue))
			{
				OnPropertyChanged(nameof(SearchResultLimitValue));
			}
		}
	} = 50;

	internal double SearchResultLimitValue
	{
		get => SearchResultLimit;
		set
		{
			if (double.IsNaN(value) || double.IsInfinity(value))
			{
				OnPropertyChanged(nameof(SearchResultLimitValue));
				return;
			}

			SearchResultLimit = (int)Math.Round(value, MidpointRounding.AwayFromZero);
		}
	}

	internal void SearchResultLimitNumberBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
	{
		// NumberBox can temporarily report NaN for cleared or invalid text, so immediately restore the last valid limit.
		double newValue = args.NewValue;
		if (double.IsNaN(newValue) || double.IsInfinity(newValue))
		{
			sender.Value = SearchResultLimitValue;
			return;
		}

		double normalizedValue = Math.Clamp(Math.Round(newValue, MidpointRounding.AwayFromZero), 1D, WinGetPackageSearchService.MaximumResultLimit);
		SearchResultLimit = (int)normalizedValue;

		if (Math.Abs(sender.Value - SearchResultLimitValue) > double.Epsilon)
		{
			sender.Value = SearchResultLimitValue;
		}
	}

	internal void ClearSearchResults()
	{
		CancelCurrentSearch();
		SearchResults.Clear();
		SelectedSearchResultsCount = 0;
		NotifySearchResultsChanged();
		ResultsStatusText = "Search for packages by name, ID, moniker, command, or tag.";
		MainInfoBar.IsOpen = false;
	}

	public void Dispose()
	{
		// Dispose the owned query token sources directly
		if (searchCancellationTokenSource is not null)
		{
			searchCancellationTokenSource.Cancel();
			searchCancellationTokenSource.Dispose();
			searchCancellationTokenSource = null;
		}

		if (installedCancellationTokenSource is not null)
		{
			installedCancellationTokenSource.Cancel();
			installedCancellationTokenSource.Dispose();
			installedCancellationTokenSource = null;
		}

		CancelAllBulkPackageActions();
		CancelCurrentBundleOperation();
		bulkSourceActionCancellationTokenSource?.Cancel();
		bulkSourceActionCancellationTokenSource?.Dispose();
		bundleOperationCancellationTokenSource?.Dispose();
	}

	internal async void RefreshPackageStatus(WinGetPackageSearchResult packageSearchResult) => await RefreshPackageStatusAsync(packageSearchResult);

	internal async void DownloadPackage(WinGetPackageSearchResult packageSearchResult) => await DownloadPackageAsync(packageSearchResult);

	internal async void RepairPackage(WinGetPackageSearchResult packageSearchResult) => await RepairPackageAsync(packageSearchResult);

	internal async void ShowInstallationNotes(WinGetPackageSearchResult packageSearchResult) => await ShowInstallationNotesAsync(packageSearchResult);

	internal async void LoadInstalledPrograms() => await LoadInstalledProgramsAsync();

	internal async void ExportSearchResultsToJson_Click() => await ExportPackagesToJsonAsync("Search packages", SearchResults, "Harden System Security WinGet Search Results.json");

	internal async void ExportInstalledProgramsToJson_Click() => await ExportPackagesToJsonAsync("Installed programs", InstalledPrograms, "Harden System Security WinGet Installed Programs.json");

	[DynamicWindowsRuntimeCast(typeof(ListView))]
	internal void SearchResultsListView_SelectionChanged(object sender, SelectionChangedEventArgs args) => SelectedSearchResultsCount = sender is ListView listView ? listView.SelectedItems.Count : 0;

	[DynamicWindowsRuntimeCast(typeof(ListView))]
	internal void InstalledProgramsListView_SelectionChanged(object sender, SelectionChangedEventArgs args) => SelectedInstalledProgramsCount = sender is ListView listView ? listView.SelectedItems.Count : 0;

	[DynamicWindowsRuntimeCast(typeof(ListView))]
	internal void SourcesListView_SelectionChanged(object sender, SelectionChangedEventArgs args) => SelectedSourcesCount = sender is ListView listView ? listView.SelectedItems.Count : 0;


	#region WinGet package bundles

	internal void BundleGridView_ItemClick(object sender, ItemClickEventArgs args)
	{
		if (args.ClickedItem is not WinGetPackageBundle packageBundle)
		{
			return;
		}

		SelectedPackageBundle = packageBundle;
	}

	internal void CloseSelectedBundle_Click() => SelectedPackageBundle = null;

	internal async void InstallSelectedBundle_Click() => await RunSelectedPackageBundleInstallActionAsync(PackageInstallMode.Default, PackageInstallScope.Any);

	internal async void InstallSelectedBundleSilent_Click() => await RunSelectedPackageBundleInstallActionAsync(PackageInstallMode.Silent, PackageInstallScope.Any);

	internal async void InstallSelectedBundleSilentUser_Click() => await RunSelectedPackageBundleInstallActionAsync(PackageInstallMode.Silent, PackageInstallScope.User);

	internal async void InstallSelectedBundleSilentMachine_Click() => await RunSelectedPackageBundleInstallActionAsync(PackageInstallMode.Silent, PackageInstallScope.System);

	internal async void InstallSelectedBundleInteractive_Click() => await RunSelectedPackageBundleInstallActionAsync(PackageInstallMode.Interactive, PackageInstallScope.Any);

	internal async void InstallSelectedBundleInteractiveUser_Click() => await RunSelectedPackageBundleInstallActionAsync(PackageInstallMode.Interactive, PackageInstallScope.User);

	internal async void InstallSelectedBundleInteractiveMachine_Click() => await RunSelectedPackageBundleInstallActionAsync(PackageInstallMode.Interactive, PackageInstallScope.System);

	internal async void UninstallSelectedBundle_Click() => await RunSelectedPackageBundleUninstallActionAsync(PackageUninstallMode.Default, PackageUninstallScope.Any);

	internal async void UninstallSelectedBundleSilent_Click() => await RunSelectedPackageBundleUninstallActionAsync(PackageUninstallMode.Silent, PackageUninstallScope.Any);

	internal async void UninstallSelectedBundleSilentUser_Click() => await RunSelectedPackageBundleUninstallActionAsync(PackageUninstallMode.Silent, PackageUninstallScope.User);

	internal async void UninstallSelectedBundleSilentMachine_Click() => await RunSelectedPackageBundleUninstallActionAsync(PackageUninstallMode.Silent, PackageUninstallScope.System);

	internal async void UninstallSelectedBundleInteractive_Click() => await RunSelectedPackageBundleUninstallActionAsync(PackageUninstallMode.Interactive, PackageUninstallScope.Any);

	internal async void UninstallSelectedBundleInteractiveUser_Click() => await RunSelectedPackageBundleUninstallActionAsync(PackageUninstallMode.Interactive, PackageUninstallScope.User);

	internal async void UninstallSelectedBundleInteractiveMachine_Click() => await RunSelectedPackageBundleUninstallActionAsync(PackageUninstallMode.Interactive, PackageUninstallScope.System);

	internal async void InstallBundlePackage_Click(object sender, RoutedEventArgs args) => await RunBundlePackageInstallActionAsync(sender, PackageInstallMode.Default, PackageInstallScope.Any);

	internal async void InstallBundlePackageSilent_Click(object sender, RoutedEventArgs args) => await RunBundlePackageInstallActionAsync(sender, PackageInstallMode.Silent, PackageInstallScope.Any);

	internal async void InstallBundlePackageSilentUser_Click(object sender, RoutedEventArgs args) => await RunBundlePackageInstallActionAsync(sender, PackageInstallMode.Silent, PackageInstallScope.User);

	internal async void InstallBundlePackageSilentMachine_Click(object sender, RoutedEventArgs args) => await RunBundlePackageInstallActionAsync(sender, PackageInstallMode.Silent, PackageInstallScope.System);

	internal async void InstallBundlePackageInteractive_Click(object sender, RoutedEventArgs args) => await RunBundlePackageInstallActionAsync(sender, PackageInstallMode.Interactive, PackageInstallScope.Any);

	internal async void InstallBundlePackageInteractiveUser_Click(object sender, RoutedEventArgs args) => await RunBundlePackageInstallActionAsync(sender, PackageInstallMode.Interactive, PackageInstallScope.User);

	internal async void InstallBundlePackageInteractiveMachine_Click(object sender, RoutedEventArgs args) => await RunBundlePackageInstallActionAsync(sender, PackageInstallMode.Interactive, PackageInstallScope.System);

	internal async void UninstallBundlePackage_Click(object sender, RoutedEventArgs args) => await RunBundlePackageUninstallActionAsync(sender, PackageUninstallMode.Default, PackageUninstallScope.Any);

	internal async void UninstallBundlePackageSilent_Click(object sender, RoutedEventArgs args) => await RunBundlePackageUninstallActionAsync(sender, PackageUninstallMode.Silent, PackageUninstallScope.Any);

	internal async void UninstallBundlePackageSilentUser_Click(object sender, RoutedEventArgs args) => await RunBundlePackageUninstallActionAsync(sender, PackageUninstallMode.Silent, PackageUninstallScope.User);

	internal async void UninstallBundlePackageSilentMachine_Click(object sender, RoutedEventArgs args) => await RunBundlePackageUninstallActionAsync(sender, PackageUninstallMode.Silent, PackageUninstallScope.System);

	internal async void UninstallBundlePackageInteractive_Click(object sender, RoutedEventArgs args) => await RunBundlePackageUninstallActionAsync(sender, PackageUninstallMode.Interactive, PackageUninstallScope.Any);

	internal async void UninstallBundlePackageInteractiveUser_Click(object sender, RoutedEventArgs args) => await RunBundlePackageUninstallActionAsync(sender, PackageUninstallMode.Interactive, PackageUninstallScope.User);

	internal async void UninstallBundlePackageInteractiveMachine_Click(object sender, RoutedEventArgs args) => await RunBundlePackageUninstallActionAsync(sender, PackageUninstallMode.Interactive, PackageUninstallScope.System);

	#endregion

	internal void SelectAllSearchResults_Click() => SelectedSearchResultsCount = SelectAllListView(ListViewHelper.ListViewsRegistry.WinGet_SearchResults);

	internal void DeselectAllSearchResults_Click() => SelectedSearchResultsCount = DeselectListView(ListViewHelper.ListViewsRegistry.WinGet_SearchResults);

	internal void SelectAllInstalledPrograms_Click() => SelectedInstalledProgramsCount = SelectAllListView(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages);

	internal void DeselectAllInstalledPrograms_Click() => SelectedInstalledProgramsCount = DeselectListView(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages);

	internal void SelectAllSources_Click() => SelectedSourcesCount = SelectAllListView(ListViewHelper.ListViewsRegistry.WinGet_Sources);

	internal void DeselectAllSources_Click() => SelectedSourcesCount = DeselectListView(ListViewHelper.ListViewsRegistry.WinGet_Sources);

	internal async void InstallOrUpdateSelectedSearchResults_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_SearchResults, PackageInstallMode.Default, PackageInstallScope.Any, "Select one or more search results first.", false);

	internal async void DownloadSelectedSearchResults_Click() => await RunSelectedPackageActionAsync(ListViewHelper.ListViewsRegistry.WinGet_SearchResults, DownloadPackageAsync, "Select one or more search results first.");

	internal async void RefreshSelectedSearchResultsStatus_Click() => await RunSelectedPackageActionAsync(ListViewHelper.ListViewsRegistry.WinGet_SearchResults, RefreshPackageStatusAsync, "Select one or more search results first.");

	internal async void InstallOrUpdateSelectedSearchResultsSilent_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_SearchResults, PackageInstallMode.Silent, PackageInstallScope.Any, "Select one or more search results first.", false);

	internal async void InstallOrUpdateSelectedSearchResultsSilentUser_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_SearchResults, PackageInstallMode.Silent, PackageInstallScope.User, "Select one or more search results first.", false);

	internal async void InstallOrUpdateSelectedSearchResultsSilentMachine_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_SearchResults, PackageInstallMode.Silent, PackageInstallScope.System, "Select one or more search results first.", false);

	internal async void InstallOrUpdateSelectedSearchResultsInteractive_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_SearchResults, PackageInstallMode.Interactive, PackageInstallScope.Any, "Select one or more search results first.", false);

	internal async void InstallOrUpdateSelectedSearchResultsInteractiveUser_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_SearchResults, PackageInstallMode.Interactive, PackageInstallScope.User, "Select one or more search results first.", false);

	internal async void InstallOrUpdateSelectedSearchResultsInteractiveMachine_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_SearchResults, PackageInstallMode.Interactive, PackageInstallScope.System, "Select one or more search results first.", false);

	internal async void UpdateOrReinstallSelectedInstalledPrograms_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageInstallMode.Default, PackageInstallScope.Any, "Select one or more installed programs first.");

	internal async void UpdateOrReinstallSelectedInstalledProgramsSilent_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageInstallMode.Silent, PackageInstallScope.Any, "Select one or more installed programs first.");

	internal async void UpdateOrReinstallSelectedInstalledProgramsSilentUser_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageInstallMode.Silent, PackageInstallScope.User, "Select one or more installed programs first.");

	internal async void UpdateOrReinstallSelectedInstalledProgramsSilentMachine_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageInstallMode.Silent, PackageInstallScope.System, "Select one or more installed programs first.");

	internal async void UpdateOrReinstallSelectedInstalledProgramsInteractive_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageInstallMode.Interactive, PackageInstallScope.Any, "Select one or more installed programs first.");

	internal async void UpdateOrReinstallSelectedInstalledProgramsInteractiveUser_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageInstallMode.Interactive, PackageInstallScope.User, "Select one or more installed programs first.");

	internal async void UpdateOrReinstallSelectedInstalledProgramsInteractiveMachine_Click() => await RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageInstallMode.Interactive, PackageInstallScope.System, "Select one or more installed programs first.");

	internal async void DownloadSelectedInstalledPrograms_Click() => await RunSelectedPackageActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, DownloadPackageAsync, "Select one or more installed programs first.");

	internal async void RepairSelectedInstalledPrograms_Click() => await RunSelectedPackageActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, RepairPackageAsync, "Select one or more installed programs first.");

	internal async void UninstallSelectedInstalledPrograms_Click() => await RunSelectedPackageUninstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageUninstallMode.Default, PackageUninstallScope.Any, "Select one or more installed programs first.", false, false, true);

	internal async void UninstallSelectedInstalledProgramsSilent_Click() => await RunSelectedPackageUninstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageUninstallMode.Silent, PackageUninstallScope.Any, "Select one or more installed programs first.", false, false, true);

	internal async void UninstallSelectedInstalledProgramsSilentUser_Click() => await RunSelectedPackageUninstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageUninstallMode.Silent, PackageUninstallScope.User, "Select one or more installed programs first.", false, false, true);

	internal async void UninstallSelectedInstalledProgramsSilentMachine_Click() => await RunSelectedPackageUninstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageUninstallMode.Silent, PackageUninstallScope.System, "Select one or more installed programs first.", false, false, true);

	internal async void UninstallSelectedInstalledProgramsInteractive_Click() => await RunSelectedPackageUninstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageUninstallMode.Interactive, PackageUninstallScope.Any, "Select one or more installed programs first.", false, false, true);

	internal async void UninstallSelectedInstalledProgramsInteractiveUser_Click() => await RunSelectedPackageUninstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageUninstallMode.Interactive, PackageUninstallScope.User, "Select one or more installed programs first.", false, false, true);

	internal async void UninstallSelectedInstalledProgramsInteractiveMachine_Click() => await RunSelectedPackageUninstallActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, PackageUninstallMode.Interactive, PackageUninstallScope.System, "Select one or more installed programs first.", false, false, true);

	internal async void RefreshSelectedInstalledProgramsStatus_Click() => await RunSelectedPackageActionAsync(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages, RefreshPackageStatusAsync, "Select one or more installed programs first.");

	internal async void UpdateSelectedSources_Click() => await RunSelectedSourceActionAsync(UpdateSourceAsync, "Select one or more sources first.");

	internal async void RemoveSelectedSources_Click() => await RunSelectedSourceActionAsync(RemoveSourceAsync, "Select one or more sources first.");

	internal async void RemoveSource(WinGetSourceInfo sourceInfo) => await RemoveSourceAsync(sourceInfo);

	internal async void UpdateSource(WinGetSourceInfo sourceInfo) => await UpdateSourceAsync(sourceInfo);

	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	internal void CopyPackageDetail_Click(object sender, RoutedEventArgs args)
	{
		if (sender is not FrameworkElement frameworkElement || frameworkElement.Tag is not string detailValue || string.IsNullOrWhiteSpace(detailValue))
		{
			return;
		}

		try
		{
			ClipboardManagement.CopyText(detailValue);
			MainInfoBar.WriteSuccess("Package detail copied to clipboard.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal void InstallOrUpdatePackage_Click(object sender, RoutedEventArgs args) => InstallOrUpdatePackageWithOptions(sender, PackageInstallMode.Default, PackageInstallScope.Any);

	internal void InstallOrUpdatePackageSilent_Click(object sender, RoutedEventArgs args) => InstallOrUpdatePackageWithOptions(sender, PackageInstallMode.Silent, PackageInstallScope.Any);

	internal void InstallOrUpdatePackageSilentUser_Click(object sender, RoutedEventArgs args) => InstallOrUpdatePackageWithOptions(sender, PackageInstallMode.Silent, PackageInstallScope.User);

	internal void InstallOrUpdatePackageSilentMachine_Click(object sender, RoutedEventArgs args) => InstallOrUpdatePackageWithOptions(sender, PackageInstallMode.Silent, PackageInstallScope.System);

	internal void InstallOrUpdatePackageInteractive_Click(object sender, RoutedEventArgs args) => InstallOrUpdatePackageWithOptions(sender, PackageInstallMode.Interactive, PackageInstallScope.Any);

	internal void InstallOrUpdatePackageInteractiveUser_Click(object sender, RoutedEventArgs args) => InstallOrUpdatePackageWithOptions(sender, PackageInstallMode.Interactive, PackageInstallScope.User);

	internal void InstallOrUpdatePackageInteractiveMachine_Click(object sender, RoutedEventArgs args) => InstallOrUpdatePackageWithOptions(sender, PackageInstallMode.Interactive, PackageInstallScope.System);

	private async void InstallOrUpdatePackageWithOptions(object sender, PackageInstallMode packageInstallMode, PackageInstallScope packageInstallScope)
	{
		if (TryGetPackageSearchResult(sender, out WinGetPackageSearchResult? packageSearchResult))
		{
			await InstallOrUpdatePackageAsync(packageSearchResult, packageInstallMode, packageInstallScope, packageInstallMode is not PackageInstallMode.Silent, CancellationToken.None);
		}
	}

	internal void DownloadPackage_Click(object sender, RoutedEventArgs args)
	{
		if (TryGetPackageSearchResult(sender, out WinGetPackageSearchResult? packageSearchResult))
		{
			DownloadPackage(packageSearchResult);
		}
	}

	internal void RepairPackage_Click(object sender, RoutedEventArgs args)
	{
		if (TryGetPackageSearchResult(sender, out WinGetPackageSearchResult? packageSearchResult))
		{
			RepairPackage(packageSearchResult);
		}
	}

	internal void CancelPackageOperation_Click(object sender, RoutedEventArgs args)
	{
		if (TryGetPackageSearchResult(sender, out WinGetPackageSearchResult? packageSearchResult))
		{
			packageSearchResult.CancelPackageOperation();
		}
	}

	internal void UninstallPackage_Click(object sender, RoutedEventArgs args) => UninstallPackageWithOptions(sender, PackageUninstallMode.Default, PackageUninstallScope.Any);

	internal void UninstallPackageSilent_Click(object sender, RoutedEventArgs args) => UninstallPackageWithOptions(sender, PackageUninstallMode.Silent, PackageUninstallScope.Any);

	internal void UninstallPackageSilentUser_Click(object sender, RoutedEventArgs args) => UninstallPackageWithOptions(sender, PackageUninstallMode.Silent, PackageUninstallScope.User);

	internal void UninstallPackageSilentMachine_Click(object sender, RoutedEventArgs args) => UninstallPackageWithOptions(sender, PackageUninstallMode.Silent, PackageUninstallScope.System);

	internal void UninstallPackageInteractive_Click(object sender, RoutedEventArgs args) => UninstallPackageWithOptions(sender, PackageUninstallMode.Interactive, PackageUninstallScope.Any);

	internal void UninstallPackageInteractiveUser_Click(object sender, RoutedEventArgs args) => UninstallPackageWithOptions(sender, PackageUninstallMode.Interactive, PackageUninstallScope.User);

	internal void UninstallPackageInteractiveMachine_Click(object sender, RoutedEventArgs args) => UninstallPackageWithOptions(sender, PackageUninstallMode.Interactive, PackageUninstallScope.System);

	private async void UninstallPackageWithOptions(object sender, PackageUninstallMode packageUninstallMode, PackageUninstallScope packageUninstallScope)
	{
		if (TryGetPackageSearchResult(sender, out WinGetPackageSearchResult? packageSearchResult))
		{
			await UninstallPackageAsync(packageSearchResult, packageUninstallMode, packageUninstallScope, true, true, CancellationToken.None);
		}
	}

	internal void RefreshPackageStatus_Click(object sender, RoutedEventArgs args)
	{
		if (TryGetPackageSearchResult(sender, out WinGetPackageSearchResult? packageSearchResult))
		{
			RefreshPackageStatus(packageSearchResult);
		}
	}

	internal void ShowInstallationNotes_Click(object sender, RoutedEventArgs args)
	{
		if (TryGetPackageSearchResult(sender, out WinGetPackageSearchResult? packageSearchResult))
		{
			ShowInstallationNotes(packageSearchResult);
		}
	}

	internal void UpdateSource_Click(object sender, RoutedEventArgs args)
	{
		if (TryGetSourceInfo(sender, out WinGetSourceInfo? sourceInfo))
		{
			UpdateSource(sourceInfo);
		}
	}

	internal void CancelSourceOperation_Click(object sender, RoutedEventArgs args)
	{
		if (TryGetSourceInfo(sender, out WinGetSourceInfo? sourceInfo))
		{
			sourceInfo.CancelOperation();
		}
	}

	internal void RemoveSource_Click(object sender, RoutedEventArgs args)
	{
		if (TryGetSourceInfo(sender, out WinGetSourceInfo? sourceInfo))
		{
			RemoveSource(sourceInfo);
		}
	}

	internal void ToggleSettingsPane() => IsWinGetSettingsPaneOpen = !IsWinGetSettingsPaneOpen;

	internal void BrowseDownloadDirectory()
	{
		try
		{
			string? selectedDirectory = FileDialogHelper.ShowDirectoryPickerDialog();
			if (string.IsNullOrWhiteSpace(selectedDirectory))
			{
				return;
			}

			_ = Directory.CreateDirectory(selectedDirectory);
			CustomDownloadDirectorySetting = selectedDirectory;
			MainInfoBar.WriteSuccess($"WinGet download directory set to '{ResolvedDownloadDirectory}'.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, "WinGet download directory selection failed.");
		}
	}

	internal void ResetDownloadDirectory()
	{
		CustomDownloadDirectorySetting = string.Empty;
		MainInfoBar.WriteSuccess($"WinGet download directory restored to '{ResolvedDownloadDirectory}'.");
	}

	private void RefreshPackageSearchSourceOptions()
	{
		try
		{
			IReadOnlyList<WinGetSourceInfo> sources = WinGetPackageSearchService.GetSources();
			RefreshPackageSearchSourceOptions(sources);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			RefreshPackageSearchSourceOptions([]);
		}
	}

	private void RefreshPackageSearchSourceOptions(IReadOnlyList<WinGetSourceInfo> sources)
	{
		string selectedSourceName = GetSelectedPackageSearchSourceName();
		PackageSearchSourceOptions.Clear();
		PackageSearchSourceOptions.Add(AnyPackageSearchSourceOption);
		HashSet<string> seenSourceNames = new(StringComparer.OrdinalIgnoreCase)
		{
			AnyPackageSearchSourceOption
		};

		for (int index = 0; index < sources.Count; index++)
		{
			string sourceName = sources[index].Name;
			if (!string.IsNullOrWhiteSpace(sourceName) && !string.Equals(sourceName, WinGetPackageSearchService.UnavailableValue, StringComparison.OrdinalIgnoreCase) && seenSourceNames.Add(sourceName))
			{
				PackageSearchSourceOptions.Add(sourceName);
			}
		}

		int selectedSourceIndex = 0;
		if (!string.IsNullOrWhiteSpace(selectedSourceName))
		{
			for (int index = 1; index < PackageSearchSourceOptions.Count; index++)
			{
				if (string.Equals(PackageSearchSourceOptions[index], selectedSourceName, StringComparison.OrdinalIgnoreCase))
				{
					selectedSourceIndex = index;
					break;
				}
			}
		}

		SelectedPackageSearchSourceValue = selectedSourceIndex;
	}

	private string GetSelectedPackageSearchSourceName() => SelectedPackageSearchSourceValue is 0 || SelectedPackageSearchSourceValue >= PackageSearchSourceOptions.Count ? string.Empty : PackageSearchSourceOptions[SelectedPackageSearchSourceValue];

	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	private static bool TryGetPackageSearchResult(object sender, [NotNullWhen(true)] out WinGetPackageSearchResult? packageSearchResult)
	{
		packageSearchResult = sender is FrameworkElement frameworkElement
			? frameworkElement.Tag as WinGetPackageSearchResult ?? frameworkElement.DataContext as WinGetPackageSearchResult
			: null;
		return packageSearchResult is not null;
	}

	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	private static bool TryGetSourceInfo(object sender, [NotNullWhen(true)] out WinGetSourceInfo? sourceInfo)
	{
		sourceInfo = sender is FrameworkElement frameworkElement ? frameworkElement.DataContext as WinGetSourceInfo : null;
		return sourceInfo is not null;
	}

	private void NotifySearchResultsChanged()
	{
		OnPropertyChanged(nameof(HasSearchResults));
		OnPropertyChanged(nameof(SearchResultsCount));
	}

	private void NotifyInstalledProgramsChanged()
	{
		OnPropertyChanged(nameof(HasInstalledPrograms));
		OnPropertyChanged(nameof(InstalledProgramsCount));
		OnPropertyChanged(nameof(InstalledProgramsTotalCount));
	}

	private void NotifySourcesChanged()
	{
		OnPropertyChanged(nameof(HasSources));
		OnPropertyChanged(nameof(SourcesCount));
	}

	private static int SelectAllListView(ListViewHelper.ListViewsRegistry registryKey)
	{
		ListView? listView = ListViewHelper.GetListViewFromCache(registryKey);
		ListViewHelper.SelectAll(listView);
		return listView?.SelectedItems.Count ?? 0;
	}

	private static int DeselectListView(ListViewHelper.ListViewsRegistry registryKey)
	{
		ListView? listView = ListViewHelper.GetListViewFromCache(registryKey);
		if (listView is null)
		{
			return 0;
		}

		listView.SelectedItems.Clear();
		listView.SelectedItem = null;
		return 0;
	}

	private async Task RunSelectedPackageInstallActionAsync(ListViewHelper.ListViewsRegistry registryKey, PackageInstallMode packageInstallMode, PackageInstallScope packageInstallScope, string emptySelectionMessage, bool showPackageAgreements = false) => await RunSelectedPackageActionAsync(registryKey, (packageSearchResult, cancellationToken) => InstallOrUpdatePackageAsync(packageSearchResult, packageInstallMode, packageInstallScope, showPackageAgreements, cancellationToken), emptySelectionMessage);

	private async Task RunSelectedPackageUninstallActionAsync(ListViewHelper.ListViewsRegistry registryKey, PackageUninstallMode packageUninstallMode, PackageUninstallScope packageUninstallScope, string emptySelectionMessage, bool showConfirmation = false, bool refreshListsAfterUninstall = true, bool refreshListsAfterBulkAction = false)
	{
		bool completed = await RunSelectedPackageActionAsync(registryKey, (packageSearchResult, cancellationToken) => UninstallPackageAsync(packageSearchResult, packageUninstallMode, packageUninstallScope, showConfirmation, refreshListsAfterUninstall, cancellationToken), emptySelectionMessage);
		if (completed && refreshListsAfterBulkAction)
		{
			await LoadInstalledProgramsAsync();
		}
	}

	private async Task<bool> RunSelectedPackageActionAsync(ListViewHelper.ListViewsRegistry registryKey, Func<WinGetPackageSearchResult, CancellationToken, Task> action, string emptySelectionMessage)
	{
		if (registryKey is ListViewHelper.ListViewsRegistry.WinGet_SearchResults && !SearchPackageUIElementsAreEnabled ||
			registryKey is ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages && !InstalledProgramsUIElementsAreEnabled)
		{
			return false;
		}

		List<WinGetPackageSearchResult> selectedPackages = GetSelectedPackages(registryKey);
		if (selectedPackages.Count is 0)
		{
			MainInfoBar.WriteWarning(emptySelectionMessage);
			return false;
		}

		CancelBulkPackageAction(registryKey);
		using CancellationTokenSource cancellationTokenSource = new();
		bulkPackageActionCancellationTokenSources[registryKey] = cancellationTokenSource;
		CancellationToken cancellationToken = cancellationTokenSource.Token;
		bool searchPackageUIElementsWereEnabled = registryKey is ListViewHelper.ListViewsRegistry.WinGet_SearchResults;
		bool installedProgramsUIElementsWereEnabled = registryKey is ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages;
		if (searchPackageUIElementsWereEnabled)
		{
			SearchPackageUIElementsAreEnabled = false;
		}
		else if (installedProgramsUIElementsWereEnabled)
		{
			InstalledProgramsUIElementsAreEnabled = false;
		}

		bool completed = false;
		try
		{
			foreach (WinGetPackageSearchResult packageSearchResult in selectedPackages)
			{
				cancellationToken.ThrowIfCancellationRequested();
				await action(packageSearchResult, cancellationToken);
				if (cancellationToken.IsCancellationRequested)
				{
					break;
				}
			}

			completed = !cancellationToken.IsCancellationRequested;
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			MainInfoBar.WriteInfo(string.Format(CultureInfo.InvariantCulture, "Selected package operation canceled for {0} package(s).", selectedPackages.Count));
		}
		finally
		{
			if (bulkPackageActionCancellationTokenSources.TryGetValue(registryKey, out CancellationTokenSource? currentCancellationTokenSource) && ReferenceEquals(currentCancellationTokenSource, cancellationTokenSource))
			{
				_ = bulkPackageActionCancellationTokenSources.Remove(registryKey);
			}

			if (searchPackageUIElementsWereEnabled)
			{
				SearchPackageUIElementsAreEnabled = true;
			}
			else if (installedProgramsUIElementsWereEnabled)
			{
				InstalledProgramsUIElementsAreEnabled = true;
			}
		}

		return completed;
	}

	private void CancelBulkPackageAction(ListViewHelper.ListViewsRegistry registryKey)
	{
		if (!bulkPackageActionCancellationTokenSources.TryGetValue(registryKey, out CancellationTokenSource? cancellationTokenSource))
		{
			return;
		}

		cancellationTokenSource.Cancel();
	}

	private static void CancelActivePackageOperations(IEnumerable<WinGetPackageSearchResult> packages)
	{
		foreach (WinGetPackageSearchResult package in packages)
		{
			if (package.IsPackageOperationCancellationAvailable)
			{
				package.CancelPackageOperation();
			}
		}
	}

	private void CancelAllBulkPackageActions()
	{
		List<CancellationTokenSource> cancellationTokenSources = [];
		foreach (KeyValuePair<ListViewHelper.ListViewsRegistry, CancellationTokenSource> bulkAction in bulkPackageActionCancellationTokenSources)
		{
			cancellationTokenSources.Add(bulkAction.Value);
		}

		foreach (CancellationTokenSource cancellationTokenSource in cancellationTokenSources)
		{
			cancellationTokenSource.Cancel();
		}
	}

	private static List<WinGetPackageSearchResult> GetSelectedPackages(ListViewHelper.ListViewsRegistry registryKey)
	{
		List<WinGetPackageSearchResult> selectedPackages = [];
		ListView? listView = ListViewHelper.GetListViewFromCache(registryKey);
		if (listView is null)
		{
			return selectedPackages;
		}

		foreach (object selectedItem in listView.SelectedItems)
		{
			if (selectedItem is WinGetPackageSearchResult packageSearchResult)
			{
				selectedPackages.Add(packageSearchResult);
			}
		}

		return selectedPackages;
	}

	private static List<WinGetSourceInfo> GetSelectedSources()
	{
		List<WinGetSourceInfo> selectedSources = [];
		ListView? listView = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.WinGet_Sources);
		if (listView is null)
		{
			return selectedSources;
		}

		foreach (object selectedItem in listView.SelectedItems)
		{
			if (selectedItem is WinGetSourceInfo sourceInfo)
			{
				selectedSources.Add(sourceInfo);
			}
		}

		return selectedSources;
	}

	private async Task RunSelectedSourceActionAsync(Func<WinGetSourceInfo, CancellationToken, Task> action, string emptySelectionMessage)
	{
		if (!SourcesUIElementsAreEnabled)
		{
			return;
		}

		List<WinGetSourceInfo> selectedSources = GetSelectedSources();
		if (selectedSources.Count is 0)
		{
			MainInfoBar.WriteWarning(emptySelectionMessage);
			return;
		}

		if (bulkSourceActionCancellationTokenSource is not null)
			await bulkSourceActionCancellationTokenSource.CancelAsync();

		using IDisposable taskTracker = TaskTracking.RegisterOperation();

		using CancellationTokenSource cancellationTokenSource = new();
		bulkSourceActionCancellationTokenSource = cancellationTokenSource;
		CancellationToken cancellationToken = cancellationTokenSource.Token;
		SourcesUIElementsAreEnabled = false;

		try
		{
			foreach (WinGetSourceInfo sourceInfo in selectedSources)
			{
				cancellationToken.ThrowIfCancellationRequested();
				await action(sourceInfo, cancellationToken);
				if (cancellationToken.IsCancellationRequested)
				{
					break;
				}
			}
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			MainInfoBar.WriteInfo(string.Format(CultureInfo.InvariantCulture, "Selected source operation canceled for {0} source(s).", selectedSources.Count));
		}
		finally
		{
			// Only the current bulk source operation can restore source UI state.
			if (ReferenceEquals(bulkSourceActionCancellationTokenSource, cancellationTokenSource))
			{
				bulkSourceActionCancellationTokenSource = null;
				SourcesUIElementsAreEnabled = true;
			}
		}
	}

	#region WinGet package bundles

	internal void CancelCurrentBundleOperation()
	{
		CancellationTokenSource? cancellationTokenSource = bundleOperationCancellationTokenSource;
		if (cancellationTokenSource is null)
		{
			return;
		}

		cancellationTokenSource.Cancel();
		BundleOperationStatus = "Canceling bundle operation.";
		OnPropertyChanged(nameof(IsBundleOperationCancelButtonEnabled));
	}

	private async Task RunSelectedPackageBundleInstallActionAsync(PackageInstallMode packageInstallMode, PackageInstallScope packageInstallScope)
	{
		WinGetPackageBundle? selectedPackageBundle = SelectedPackageBundle;
		if (selectedPackageBundle is null)
		{
			MainInfoBar.WriteWarning("Select an app bundle first.");
			return;
		}

		await RunBundleInstallActionAsync(selectedPackageBundle, packageInstallMode, packageInstallScope);
	}

	private async Task RunSelectedPackageBundleUninstallActionAsync(PackageUninstallMode packageUninstallMode, PackageUninstallScope packageUninstallScope)
	{
		WinGetPackageBundle? selectedPackageBundle = SelectedPackageBundle;
		if (selectedPackageBundle is null)
		{
			MainInfoBar.WriteWarning("Select an app bundle first.");
			return;
		}

		await RunBundleUninstallActionAsync(selectedPackageBundle, packageUninstallMode, packageUninstallScope);
	}

	private async Task RunBundlePackageInstallActionAsync(object sender, PackageInstallMode packageInstallMode, PackageInstallScope packageInstallScope)
	{
		if (!TryGetBundlePackage(sender, out WinGetPackageBundlePackage? bundlePackage))
		{
			return;
		}

		await RunSingleBundlePackageActionAsync(
			bundlePackage,
			string.Format(CultureInfo.InvariantCulture, "Installing {0}", bundlePackage.DisplayName),
			resolveInstalledPackageOnly: false,
			async (packageSearchResult, cancellationToken) => await InstallOrUpdatePackageAsync(packageSearchResult, packageInstallMode, packageInstallScope, packageInstallMode is not PackageInstallMode.Silent, cancellationToken));
	}

	private async Task RunBundlePackageUninstallActionAsync(object sender, PackageUninstallMode packageUninstallMode, PackageUninstallScope packageUninstallScope)
	{
		if (!TryGetBundlePackage(sender, out WinGetPackageBundlePackage? bundlePackage))
		{
			return;
		}

		await RunSingleBundlePackageActionAsync(
			bundlePackage,
			string.Format(CultureInfo.InvariantCulture, "Uninstalling {0}", bundlePackage.DisplayName),
			resolveInstalledPackageOnly: true,
			async (packageSearchResult, cancellationToken) => await UninstallPackageAsync(packageSearchResult, packageUninstallMode, packageUninstallScope, true, true, cancellationToken));
	}

	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	private static bool TryGetBundlePackage(object sender, [NotNullWhen(true)] out WinGetPackageBundlePackage? bundlePackage)
	{
		bundlePackage = sender is FrameworkElement frameworkElement ? frameworkElement.Tag as WinGetPackageBundlePackage : null;
		return bundlePackage is not null;
	}

	private async Task RunSingleBundlePackageActionAsync(WinGetPackageBundlePackage bundlePackage, string actionDescription, bool resolveInstalledPackageOnly, Func<WinGetPackageSearchResult, CancellationToken, Task> packageAction)
	{
		if (!BundlesUIElementsAreEnabled)
		{
			return;
		}

		CancelCurrentBundleOperation();
		using CancellationTokenSource cancellationTokenSource = new();
		bundleOperationCancellationTokenSource = cancellationTokenSource;
		CancellationToken cancellationToken = cancellationTokenSource.Token;
		BundlesUIElementsAreEnabled = false;

		try
		{
			BundleOperationStatus = string.Format(CultureInfo.InvariantCulture, "{0}: resolving {1}.", actionDescription, bundlePackage.DisplayName);
			// Individual bundle uninstall actions must resolve against the installed catalog so Microsoft Store package identities uninstall correctly.
			WinGetPackageSearchResult? packageSearchResult = resolveInstalledPackageOnly
				? await WinGetPackageSearchService.ResolveInstalledPackageByIdAsync(bundlePackage.Id, bundlePackage.SourceName, cancellationToken)
				: await ResolveBundlePackageAsync(bundlePackage, cancellationToken);
			if (packageSearchResult is null)
			{
				BundleOperationStatus = resolveInstalledPackageOnly
					? string.Format(CultureInfo.InvariantCulture, "Package {0} was not found in installed WinGet packages.", bundlePackage.Id)
					: string.Format(CultureInfo.InvariantCulture, "Package {0} was not found in configured WinGet sources.", bundlePackage.Id);
				MainInfoBar.WriteWarning(BundleOperationStatus);
				return;
			}

			BundleOperationStatus = string.Format(CultureInfo.InvariantCulture, "{0}: starting {1}.", actionDescription, bundlePackage.DisplayName);
			await packageAction(packageSearchResult, cancellationToken);
			BundleOperationStatus = string.IsNullOrWhiteSpace(packageSearchResult.PackageOperationStatus)
				? string.Format(CultureInfo.InvariantCulture, "{0} finished for {1}.", actionDescription, bundlePackage.DisplayName)
				: packageSearchResult.PackageOperationStatus;
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			BundleOperationStatus = string.Format(CultureInfo.InvariantCulture, "{0} canceled for {1}.", actionDescription, bundlePackage.DisplayName);
		}
		catch (Exception ex)
		{
			BundleOperationStatus = string.Format(CultureInfo.InvariantCulture, "{0} failed for {1}.", actionDescription, bundlePackage.DisplayName);
			MainInfoBar.WriteError(ex, BundleOperationStatus);
		}
		finally
		{
			if (ReferenceEquals(bundleOperationCancellationTokenSource, cancellationTokenSource))
			{
				bundleOperationCancellationTokenSource = null;
				BundlesUIElementsAreEnabled = true;
				OnPropertyChanged(nameof(IsBundleOperationCancelButtonEnabled));
			}
		}
	}

	private static List<WinGetPackageBundle> CreatePackageBundles()
	{
		const string DevelopmentBundleIconFolder = "ms-appx:///Assets/WinGetManagementAppBundles/Development/";
		const string GamingBundleIconFolder = "ms-appx:///Assets/WinGetManagementAppBundles/Gaming/";
		const string DebuggingBundleIconFolder = "ms-appx:///Assets/WinGetManagementAppBundles/Debugging/";
		const string ProductivityBundleIconFolder = "ms-appx:///Assets/WinGetManagementAppBundles/Productivity/";
		List<WinGetPackageBundle> bundles = new(4);
		bundles.Add(new WinGetPackageBundle(
			"Development",
			[
				new WinGetPackageBundlePackage("Git.Git", "Git", new Uri(DevelopmentBundleIconFolder + "icons8-git.svg")),
				new WinGetPackageBundlePackage("Python.Python.3.14", "Python", new Uri(DevelopmentBundleIconFolder + "icons8-python.svg")),
				new WinGetPackageBundlePackage("Microsoft.VisualStudio.Community", "Visual Studio", new Uri(DevelopmentBundleIconFolder + "icons8-visual-studio.svg")),
				new WinGetPackageBundlePackage("Microsoft.VisualStudioCode", "Visual Studio Code", new Uri(DevelopmentBundleIconFolder + "icons8-visual-studio-code.svg")),
				new WinGetPackageBundlePackage("GitHub.GitHubDesktop", "GitHub Desktop", new Uri(DevelopmentBundleIconFolder + "icons8-github.svg"),displayIconBackground: true),
				new WinGetPackageBundlePackage("Microsoft.PowerShell", "PowerShell", new Uri(DevelopmentBundleIconFolder + "icons8-powershell.svg"), displayIconBackground: true),
				new WinGetPackageBundlePackage("Rustlang.Rustup", "Rust Language", new Uri(DevelopmentBundleIconFolder + "icons8-rust-programming-language.svg"))
			]));
		bundles.Add(new WinGetPackageBundle(
			"Gaming",
			[
				new WinGetPackageBundlePackage("Valve.Steam", "Steam", new Uri(GamingBundleIconFolder + "icons8-steam.svg")),
				new WinGetPackageBundlePackage("Discord.Discord", "Discord", new Uri(GamingBundleIconFolder + "icons8-discord.svg")),
				new WinGetPackageBundlePackage("Mojang.MinecraftLauncher", "Minecraft Launcher", new Uri(GamingBundleIconFolder + "icons8-minecraft.svg")),
				new WinGetPackageBundlePackage("Blizzard.BattleNet", "BattleNet", new Uri(GamingBundleIconFolder + "icons8-battle.net.svg")),
				new WinGetPackageBundlePackage("GOG.Galaxy", "GOG Galaxy", new Uri(GamingBundleIconFolder + "icons8-gog-galaxy.svg"))
			]));
		bundles.Add(new WinGetPackageBundle(
			"Investigation Tools",
			[
				new WinGetPackageBundlePackage("WiresharkFoundation.Wireshark", "Wireshark", new Uri(DebuggingBundleIconFolder + "icons8-wireshark.svg")),
				new WinGetPackageBundlePackage("9PGJGD53TN86", "WinDbg", new Uri(DebuggingBundleIconFolder + "icons8-code.svg"), WinGetPackageSearchService.MicrosoftStoreSourceName),
				new WinGetPackageBundlePackage("Hex-Rays.IDA.Free", "IDA Free", new Uri(DebuggingBundleIconFolder + "icons8-source-code.svg")),
				new WinGetPackageBundlePackage("Microsoft.Sysinternals.Suite", "Sysinternals", new Uri(DebuggingBundleIconFolder + "icons8-microsoft.svg"))
			]));
		bundles.Add(new WinGetPackageBundle(
			"Productivity",
			[
				new WinGetPackageBundlePackage("XPFFH613W8V6LV", "OBS Studio", new Uri(ProductivityBundleIconFolder + "icons8-obs.svg"), WinGetPackageSearchService.MicrosoftStoreSourceName,displayIconBackground: true),
				new WinGetPackageBundlePackage("VideoLAN.VLC", "VLC Media Player", new Uri(ProductivityBundleIconFolder + "icons8-vlc.svg")),
				new WinGetPackageBundlePackage("ShareX.ShareX", "ShareX", new Uri(ProductivityBundleIconFolder + "icons8-sharex.svg")),
				new WinGetPackageBundlePackage("Microsoft.PowerToys", "PowerToys", new Uri(ProductivityBundleIconFolder + "icons8-microsoft-powertoys.svg")),
				new WinGetPackageBundlePackage("9NT1R1C2HH7J", "ChatGPT", new Uri(ProductivityBundleIconFolder + "icons8-chat-gpt.svg"),WinGetPackageSearchService.MicrosoftStoreSourceName),
				new WinGetPackageBundlePackage("XPDP273C0XHQH2", "Adobe Acrobat Reader DC", new Uri(ProductivityBundleIconFolder + "icons8-adobe-acrobat-reader.svg"),WinGetPackageSearchService.MicrosoftStoreSourceName)
			]));
		return bundles;
	}

	private async Task RunBundleInstallActionAsync(WinGetPackageBundle packageBundle, PackageInstallMode packageInstallMode, PackageInstallScope packageInstallScope) =>
		await RunBundleActionCoreAsync(
			packageBundle,
			string.Format(CultureInfo.InvariantCulture, "Installing {0}", packageBundle.Name),
			async (packageSearchResult, cancellationToken) => await InstallOrUpdatePackageAsync(packageSearchResult, packageInstallMode, packageInstallScope, false, cancellationToken));

	private async Task RunBundleUninstallActionAsync(WinGetPackageBundle packageBundle, PackageUninstallMode packageUninstallMode, PackageUninstallScope packageUninstallScope)
	{
		if (!await ConfirmBundleUninstallAsync(packageBundle))
		{
			return;
		}

		await RunBundleActionCoreAsync(
			packageBundle,
			string.Format(CultureInfo.InvariantCulture, "Uninstalling {0}", packageBundle.Name),
			async (packageSearchResult, cancellationToken) => await UninstallPackageAsync(packageSearchResult, packageUninstallMode, packageUninstallScope, false, true, cancellationToken),
			true);
	}

	private async Task RunBundleActionCoreAsync(WinGetPackageBundle packageBundle, string actionDescription, Func<WinGetPackageSearchResult, CancellationToken, Task> packageAction, bool resolveInstalledPackageOnly = false)
	{
		if (!BundlesUIElementsAreEnabled)
		{
			return;
		}

		CancelCurrentBundleOperation();
		using CancellationTokenSource cancellationTokenSource = new();
		bundleOperationCancellationTokenSource = cancellationTokenSource;
		CancellationToken cancellationToken = cancellationTokenSource.Token;
		BundlesUIElementsAreEnabled = false;
		int succeeded = 0;
		int skipped = 0;
		int failed = 0;

		try
		{
			for (int index = 0; index < packageBundle.Packages.Count; index++)
			{
				cancellationToken.ThrowIfCancellationRequested();
				WinGetPackageBundlePackage bundlePackage = packageBundle.Packages[index];
				BundleOperationStatus = string.Format(CultureInfo.InvariantCulture, "{0}: resolving {1} of {2}, {3}.", actionDescription, index + 1, packageBundle.PackageCount, bundlePackage.DisplayName);
				// Uninstall always resolves the installed package identity from the local installed catalog, including Microsoft Store packages, because the remote store listing is not marked installed and would be skipped.
				WinGetPackageSearchResult? packageSearchResult = resolveInstalledPackageOnly
					? await WinGetPackageSearchService.ResolveInstalledPackageByIdAsync(bundlePackage.Id, bundlePackage.SourceName, cancellationToken)
					: await ResolveBundlePackageAsync(bundlePackage, cancellationToken);
				if (packageSearchResult is null)
				{
					if (resolveInstalledPackageOnly)
					{
						skipped++;
						BundleOperationStatus = string.Format(CultureInfo.InvariantCulture, "Skipped {0} because it is not installed.", bundlePackage.DisplayName);
					}
					else
					{
						failed++;
						BundleOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package {0} was not found in configured WinGet sources.", bundlePackage.Id);
					}

					continue;
				}

				await packageAction(packageSearchResult, cancellationToken);

				if (packageSearchResult.PackageOperationStatus.Contains("succeeded", StringComparison.OrdinalIgnoreCase))
				{
					succeeded++;
				}
				else if (!packageSearchResult.IsPackageOperationCancellationRequested)
				{
					failed++;
				}
			}

			BundleOperationStatus = string.Format(CultureInfo.InvariantCulture, "Bundle {0} completed. Succeeded: {1}. Skipped: {2}. Failed: {3}.", packageBundle.Name, succeeded, skipped, failed);
			MainInfoBar.WriteSuccess(BundleOperationStatus);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			BundleOperationStatus = string.Format(CultureInfo.InvariantCulture, "Bundle {0} operation canceled. Succeeded: {1}. Skipped: {2}. Failed: {3}.", packageBundle.Name, succeeded, skipped, failed);
			MainInfoBar.WriteInfo(BundleOperationStatus);
		}
		catch (Exception ex)
		{
			BundleOperationStatus = string.Format(CultureInfo.InvariantCulture, "Bundle {0} operation failed.", packageBundle.Name);
			MainInfoBar.WriteError(ex, BundleOperationStatus);
		}
		finally
		{
			if (ReferenceEquals(bundleOperationCancellationTokenSource, cancellationTokenSource))
			{
				bundleOperationCancellationTokenSource = null;
				BundlesUIElementsAreEnabled = true;
				OnPropertyChanged(nameof(IsBundleOperationCancelButtonEnabled));
			}
		}
	}

	private static async Task<bool> ConfirmBundleUninstallAsync(WinGetPackageBundle packageBundle)
	{
		using ContentDialogV2 confirmDialog = new()
		{
			Title = "Uninstall app bundle",
			Content = string.Format(CultureInfo.InvariantCulture, "Uninstall installed apps from the {0} bundle? Apps that are not installed will be skipped.", packageBundle.Name),
			PrimaryButtonText = "Uninstall bundle",
			SecondaryButtonText = Atlas.GetStr("Cancel"),
			DefaultButton = ContentDialogButton.Secondary
		};

		ContentDialogResult confirmation = await confirmDialog.ShowAsync();
		return confirmation is ContentDialogResult.Primary;
	}

	private static Task<WinGetPackageSearchResult?> ResolveBundlePackageAsync(WinGetPackageBundlePackage bundlePackage, CancellationToken cancellationToken) =>
		Task.Run(async () => await WinGetPackageSearchService.ResolvePackageByIdAsync(bundlePackage.Id, bundlePackage.SourceName, cancellationToken),
			cancellationToken);

	#endregion

	internal void PackageSearchTextBox_KeyDown(object sender, KeyRoutedEventArgs args)
	{
		if (args.Key is not VirtualKey.Enter)
		{
			return;
		}
		args.Handled = true;
		SearchPackagesAsync();
	}

	internal async void SearchPackagesAsync() => await SearchPackages_Internal();

	private async Task SearchPackages_Internal()
	{
		string trimmedQuery = SearchQuery.Trim();
		if (string.IsNullOrWhiteSpace(trimmedQuery))
		{
			MainInfoBar.WriteWarning("Enter a package search query first.");
			return;
		}

		using IDisposable taskTracker = TaskTracking.RegisterOperation();

		CancelCurrentSearch();
		CancellationTokenSource cancellationTokenSource = new();
		searchCancellationTokenSource = cancellationTokenSource;
		CancellationToken cancellationToken = cancellationTokenSource.Token;

		try
		{
			SearchPackageUIElementsAreEnabled = false;
			SearchResults.Clear();
			SelectedSearchResultsCount = 0;
			NotifySearchResultsChanged();
			ResultsStatusText = "Searching packages.";
			string packageSearchSourceName = GetSelectedPackageSearchSourceName();
			string packageSearchSourceDisplayName = string.IsNullOrWhiteSpace(packageSearchSourceName) ? AnyPackageSearchSourceOption : packageSearchSourceName;
			WinGetPackageSearchMatchMode packageSearchMatchMode = (WinGetPackageSearchMatchMode)SelectedPackageSearchMatchModeValue;
			string packageSearchMatchModeName = PackageSearchMatchModeOptions[SelectedPackageSearchMatchModeValue];
			MainInfoBar.WriteInfo(string.Format(CultureInfo.InvariantCulture, "Searching WinGet source selection: {0}. Match mode: {1}.", packageSearchSourceDisplayName, packageSearchMatchModeName));

			WinGetPackageSearchField packageSearchField = (WinGetPackageSearchField)SelectedPackageSearchFieldValue;
			string packageSearchFieldName = PackageSearchFieldOptions[SelectedPackageSearchFieldValue];
			List<WinGetPackageSearchResult> results = await Task.Run(
				async () => await WinGetPackageSearchService.SearchAsync(trimmedQuery, SearchResultLimit, packageSearchField, packageSearchSourceName, packageSearchMatchMode, cancellationToken),
				cancellationToken);
			cancellationToken.ThrowIfCancellationRequested();
			SearchResults.AddRange(results);
			NotifySearchResultsChanged();
			ResultsStatusText = GetResultStatusText(string.Format(CultureInfo.InvariantCulture, "Found {0} package(s) for {1} using {2} search with {3} match mode in {4}.", SearchResults.Count, trimmedQuery, packageSearchFieldName, packageSearchMatchModeName, packageSearchSourceDisplayName), results);
			MainInfoBar.WriteSuccess(ResultsStatusText);
		}
		catch (OperationCanceledException)
		{
			ResultsStatusText = "Package search canceled.";
			MainInfoBar.WriteInfo(ResultsStatusText);
		}
		catch (Exception ex)
		{
			ResultsStatusText = "Package search failed.";
			MainInfoBar.WriteError(ex, "Package search failed.");
		}
		finally
		{
			// Only the operation that still owns the section state restores the UI.
			bool shouldRestoreSearchUI = ReferenceEquals(searchCancellationTokenSource, cancellationTokenSource) || searchCancellationTokenSource is null;
			if (ReferenceEquals(searchCancellationTokenSource, cancellationTokenSource))
			{
				searchCancellationTokenSource = null;
			}

			cancellationTokenSource.Dispose();
			if (shouldRestoreSearchUI)
			{
				SearchPackageUIElementsAreEnabled = true;
			}
		}
	}

	private async Task InstallOrUpdatePackageAsync(WinGetPackageSearchResult packageSearchResult, PackageInstallMode packageInstallMode, PackageInstallScope packageInstallScope, bool showPackageAgreements, CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (packageSearchResult.IsPackageOperationRunning)
		{
			return;
		}

		bool isReinstall = packageSearchResult.IsInstalled && !packageSearchResult.IsUpdateAvailable;
		if (isReinstall)
		{
			packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Refreshing package install metadata for {0}.", GetPackageLogDisplayName(packageSearchResult));
			if (!await ApplyRefreshedPackageStatusAsync(packageSearchResult, cancellationToken))
			{
				packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "No applicable installer for {0}. {1}", GetPackageLogDisplayName(packageSearchResult), WinGetPackageSearchService.GetNoApplicableInstallInstallerMessage());
				MainInfoBar.WriteWarning(packageSearchResult.PackageOperationStatus);
				return;
			}

			isReinstall = packageSearchResult.IsInstalled && !packageSearchResult.IsUpdateAvailable;
		}
		// Individual package actions keep the app-level agreement dialog. Bulk toolbar install actions can skip it because WinGet receives AcceptPackageAgreements.
		if (showPackageAgreements && !await ShowPackageAgreementsAsync(packageSearchResult))
		{
			return;
		}
		cancellationToken.ThrowIfCancellationRequested();

		using IDisposable taskTracker = TaskTracking.RegisterOperation();

		// Default font installs must stay per-user when unelevated because WinGet font manifests are scope-flexible.
		packageInstallScope = packageInstallScope is PackageInstallScope.Any && !Atlas.IsElevated && (string.Equals(packageSearchResult.Source, WinGetPackageSearchService.WinGetFontSourceName, StringComparison.OrdinalIgnoreCase) || string.Equals(packageSearchResult.InstallerType, "Font", StringComparison.OrdinalIgnoreCase) || string.Equals(packageSearchResult.InstallerNestedType, "Font", StringComparison.OrdinalIgnoreCase)) ? PackageInstallScope.User : packageInstallScope;
		bool force = packageSearchResult.IsInstalled && !packageSearchResult.IsUpdateAvailable;
		WinGetPackageSearchService.ApplyApplicableInstallerDetails(packageSearchResult, packageInstallMode, packageInstallScope, force);
		bool searchPackageUIElementsWereEnabled = SearchResults.Contains(packageSearchResult) && SearchPackageUIElementsAreEnabled;
		bool installedProgramsUIElementsWereEnabled = InstalledPrograms.Contains(packageSearchResult) && InstalledProgramsUIElementsAreEnabled;
		if (searchPackageUIElementsWereEnabled)
		{
			SearchPackageUIElementsAreEnabled = false;
		}
		else if (installedProgramsUIElementsWereEnabled)
		{
			InstalledProgramsUIElementsAreEnabled = false;
		}

		try
		{
			packageSearchResult.IsPackageOperationRunning = true;
			packageSearchResult.IsPackageOperationProgressIndeterminate = true;
			packageSearchResult.PackageOperationProgress = 0D;
			packageSearchResult.PackageOperationStatus = isReinstall
				? string.Format(CultureInfo.InvariantCulture, "Reinstall queued for {0}.", GetPackageLogDisplayName(packageSearchResult))
				: string.Format(CultureInfo.InvariantCulture, "Package operation queued for {0}.", GetPackageLogDisplayName(packageSearchResult));

			IAsyncOperationWithProgress<InstallResult, InstallProgress> installOperation = WinGetPackageSearchService.InstallOrUpdatePackage(packageSearchResult, packageInstallMode, packageInstallScope, force);
			packageSearchResult.BeginPackageOperation(installOperation);
			using CancellationTokenRegistration cancellationRegistration = cancellationToken.Register(packageSearchResult.CancelPackageOperation);
			installOperation.Progress = (operation, progress) => Atlas.AppDispatcher.TryEnqueue(() => ApplyInstallProgress(packageSearchResult, progress));

			InstallResult installResult = await installOperation;
			if (packageSearchResult.IsPackageOperationCancellationRequested)
			{
				SetPackageOperationCanceled(packageSearchResult);
				return;
			}

			if (installResult.Status is not InstallResultStatus.Ok)
			{
				if (WinGetPackageSearchService.TryGetFriendlyInstallFailureMessage(installResult, out string? friendlyInstallFailureMessage))
				{
					packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package operation failed for {0}. {1}", GetPackageLogDisplayName(packageSearchResult), friendlyInstallFailureMessage);
					MainInfoBar.WriteWarning(packageSearchResult.PackageOperationStatus);
					return;
				}

				string installError = WinGetPackageSearchService.GetInstallResultError(installResult);
				packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package operation failed for {0}. {1}", GetPackageLogDisplayName(packageSearchResult), installError);
				MainInfoBar.WriteError(new InvalidOperationException(packageSearchResult.PackageOperationStatus), "Package operation failed.");
				return;
			}

			packageSearchResult.PackageOperationProgress = 100D;
			packageSearchResult.IsPackageOperationProgressIndeterminate = false;
			packageSearchResult.PackageOperationStatus = installResult.RebootRequired
				? string.Format(CultureInfo.InvariantCulture, "Package operation succeeded for {0}. A reboot is required.", GetPackageLogDisplayName(packageSearchResult))
				: string.Format(CultureInfo.InvariantCulture, "Package operation succeeded for {0}.", GetPackageLogDisplayName(packageSearchResult));
			MainInfoBar.WriteSuccess(packageSearchResult.PackageOperationStatus);

			_ = await ApplyRefreshedPackageStatusAsync(packageSearchResult, CancellationToken.None);
		}
		catch (Exception) when (packageSearchResult.IsPackageOperationCancellationRequested)
		{
			SetPackageOperationCanceled(packageSearchResult);
		}
		catch (OperationCanceledException)
		{
			SetPackageOperationCanceled(packageSearchResult);
		}
		catch (Exception ex)
		{
			packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package operation failed for {0}.", GetPackageLogDisplayName(packageSearchResult));
			MainInfoBar.WriteError(ex, "Package operation failed.");
		}
		finally
		{
			if (searchPackageUIElementsWereEnabled)
			{
				SearchPackageUIElementsAreEnabled = true;
			}
			else if (installedProgramsUIElementsWereEnabled)
			{
				InstalledProgramsUIElementsAreEnabled = true;
			}
			packageSearchResult.EndPackageOperation();
			packageSearchResult.IsPackageOperationRunning = false;
		}
	}

	private async Task UninstallPackageAsync(WinGetPackageSearchResult packageSearchResult, PackageUninstallMode packageUninstallMode, PackageUninstallScope packageUninstallScope, bool showConfirmation, bool refreshListsAfterUninstall, CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (packageSearchResult.IsPackageOperationRunning || !packageSearchResult.IsInstalled)
		{
			return;
		}

		// Individual package actions keep the confirmation dialog. Bulk toolbar uninstall actions can skip it so selected packages can uninstall unattended.
		if (showConfirmation)
		{
			using ContentDialogV2 confirmDialog = new()
			{
				Title = "Uninstall package",
				Content = $"Uninstall {packageSearchResult.Name}?",
				PrimaryButtonText = "Uninstall",
				SecondaryButtonText = Atlas.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Secondary
			};

			ContentDialogResult confirmation = await confirmDialog.ShowAsync();
			if (confirmation is not ContentDialogResult.Primary)
			{
				return;
			}
		}
		cancellationToken.ThrowIfCancellationRequested();

		bool searchPackageUIElementsWereEnabled = SearchResults.Contains(packageSearchResult) && SearchPackageUIElementsAreEnabled;
		bool installedProgramsUIElementsWereEnabled = InstalledPrograms.Contains(packageSearchResult) && InstalledProgramsUIElementsAreEnabled;
		if (searchPackageUIElementsWereEnabled)
		{
			SearchPackageUIElementsAreEnabled = false;
		}
		else if (installedProgramsUIElementsWereEnabled)
		{
			InstalledProgramsUIElementsAreEnabled = false;
		}

		try
		{
			packageSearchResult.IsPackageOperationRunning = true;
			packageSearchResult.IsPackageOperationProgressIndeterminate = true;
			packageSearchResult.PackageOperationProgress = 0D;
			packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Uninstall queued for {0}.", GetPackageLogDisplayName(packageSearchResult));

			IAsyncOperationWithProgress<UninstallResult, UninstallProgress> uninstallOperation = WinGetPackageSearchService.UninstallPackage(packageSearchResult, packageUninstallMode, packageUninstallScope);
			packageSearchResult.BeginPackageOperation(uninstallOperation);
			using CancellationTokenRegistration cancellationRegistration = cancellationToken.Register(packageSearchResult.CancelPackageOperation);
			uninstallOperation.Progress = (operation, progress) => Atlas.AppDispatcher.TryEnqueue(() => ApplyUninstallProgress(packageSearchResult, progress));

			UninstallResult uninstallResult = await uninstallOperation;
			if (packageSearchResult.IsPackageOperationCancellationRequested)
			{
				SetPackageOperationCanceled(packageSearchResult);
				return;
			}

			if (uninstallResult.Status is not UninstallResultStatus.Ok)
			{
				string uninstallError = WinGetPackageSearchService.GetUninstallResultError(uninstallResult);
				packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package uninstall failed for {0}. {1}", GetPackageLogDisplayName(packageSearchResult), uninstallError);
				MainInfoBar.WriteError(new InvalidOperationException(packageSearchResult.PackageOperationStatus), "Package uninstall failed.");
				return;
			}

			packageSearchResult.PackageOperationProgress = 100D;
			packageSearchResult.IsPackageOperationProgressIndeterminate = false;
			packageSearchResult.PackageOperationStatus = uninstallResult.RebootRequired
				? string.Format(CultureInfo.InvariantCulture, "Package uninstall succeeded for {0}. A reboot is required.", GetPackageLogDisplayName(packageSearchResult))
				: string.Format(CultureInfo.InvariantCulture, "Package uninstall succeeded for {0}.", GetPackageLogDisplayName(packageSearchResult));
			MainInfoBar.WriteSuccess(packageSearchResult.PackageOperationStatus);

			_ = await ApplyRefreshedPackageStatusAsync(packageSearchResult, CancellationToken.None);
			if (refreshListsAfterUninstall)
			{
				await LoadInstalledProgramsAsync();
			}
		}
		catch (Exception) when (packageSearchResult.IsPackageOperationCancellationRequested)
		{
			SetPackageOperationCanceled(packageSearchResult);
		}
		catch (OperationCanceledException)
		{
			SetPackageOperationCanceled(packageSearchResult);
		}
		catch (Exception ex)
		{
			packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package uninstall failed for {0}.", GetPackageLogDisplayName(packageSearchResult));
			MainInfoBar.WriteError(ex, packageSearchResult.PackageOperationStatus);
		}
		finally
		{
			if (searchPackageUIElementsWereEnabled)
			{
				SearchPackageUIElementsAreEnabled = true;
			}
			else if (installedProgramsUIElementsWereEnabled)
			{
				InstalledProgramsUIElementsAreEnabled = true;
			}
			packageSearchResult.EndPackageOperation();
			packageSearchResult.IsPackageOperationRunning = false;
		}
	}

	private async Task DownloadPackageAsync(WinGetPackageSearchResult packageSearchResult, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (packageSearchResult.IsPackageOperationRunning)
		{
			return;
		}

		string downloadDirectory = GetDownloadDirectory();

		bool searchPackageUIElementsWereEnabled = SearchResults.Contains(packageSearchResult) && SearchPackageUIElementsAreEnabled;
		bool installedProgramsUIElementsWereEnabled = InstalledPrograms.Contains(packageSearchResult) && InstalledProgramsUIElementsAreEnabled;
		if (searchPackageUIElementsWereEnabled)
		{
			SearchPackageUIElementsAreEnabled = false;
		}
		else if (installedProgramsUIElementsWereEnabled)
		{
			InstalledProgramsUIElementsAreEnabled = false;
		}

		try
		{
			packageSearchResult.IsPackageOperationRunning = true;
			packageSearchResult.IsPackageOperationProgressIndeterminate = true;
			packageSearchResult.PackageOperationProgress = 0D;
			packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Refreshing package download metadata for {0}.", GetPackageLogDisplayName(packageSearchResult));
			if (!await ApplyRefreshedPackageStatusAsync(packageSearchResult, cancellationToken))
			{
				packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "No applicable downloadable installer for {0}. {1}", GetPackageLogDisplayName(packageSearchResult), WinGetPackageSearchService.GetNoApplicableDownloadInstallerMessage());
				MainInfoBar.WriteWarning(packageSearchResult.PackageOperationStatus);
				return;
			}
			cancellationToken.ThrowIfCancellationRequested();

			packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Download queued for {0}.", GetPackageLogDisplayName(packageSearchResult));

			IAsyncOperationWithProgress<DownloadResult, PackageDownloadProgress> downloadOperation = WinGetPackageSearchService.DownloadPackage(packageSearchResult, downloadDirectory);
			packageSearchResult.BeginPackageOperation(downloadOperation);
			using CancellationTokenRegistration cancellationRegistration = cancellationToken.Register(packageSearchResult.CancelPackageOperation);
			downloadOperation.Progress = (operation, progress) => Atlas.AppDispatcher.TryEnqueue(() => ApplyDownloadProgress(packageSearchResult, progress));

			DownloadResult downloadResult = await downloadOperation;
			if (packageSearchResult.IsPackageOperationCancellationRequested)
			{
				SetPackageOperationCanceled(packageSearchResult);
				return;
			}

			if (downloadResult.Status is not DownloadResultStatus.Ok)
			{
				if (WinGetPackageSearchService.IsNoApplicableDownloadInstallerResult(downloadResult))
				{
					packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "No applicable downloadable installer for {0}. {1}", GetPackageLogDisplayName(packageSearchResult), WinGetPackageSearchService.GetNoApplicableDownloadInstallerMessage());
					MainInfoBar.WriteWarning(packageSearchResult.PackageOperationStatus);
					return;
				}

				string downloadError = WinGetPackageSearchService.GetDownloadResultError(downloadResult);
				packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package download failed for {0}. {1}", GetPackageLogDisplayName(packageSearchResult), downloadError);
				MainInfoBar.WriteError(new InvalidOperationException(packageSearchResult.PackageOperationStatus), "Package download failed.");
				return;
			}

			packageSearchResult.PackageOperationProgress = 100D;
			packageSearchResult.IsPackageOperationProgressIndeterminate = false;
			packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package downloaded for {0} to {1}.", GetPackageLogDisplayName(packageSearchResult), downloadDirectory);
			MainInfoBar.WriteSuccess(packageSearchResult.PackageOperationStatus);
		}
		catch (Exception) when (packageSearchResult.IsPackageOperationCancellationRequested)
		{
			SetPackageOperationCanceled(packageSearchResult);
		}
		catch (OperationCanceledException)
		{
			SetPackageOperationCanceled(packageSearchResult);
		}
		catch (Exception ex)
		{
			packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package download failed for {0}.", GetPackageLogDisplayName(packageSearchResult));
			MainInfoBar.WriteError(ex, packageSearchResult.PackageOperationStatus);
		}
		finally
		{
			if (searchPackageUIElementsWereEnabled)
			{
				SearchPackageUIElementsAreEnabled = true;
			}
			else if (installedProgramsUIElementsWereEnabled)
			{
				InstalledProgramsUIElementsAreEnabled = true;
			}
			packageSearchResult.EndPackageOperation();
			packageSearchResult.IsPackageOperationProgressIndeterminate = false;
			packageSearchResult.IsPackageOperationRunning = false;
		}
	}

	private async Task RepairPackageAsync(WinGetPackageSearchResult packageSearchResult, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (packageSearchResult.IsPackageOperationRunning || !packageSearchResult.IsInstalled)
		{
			return;
		}

		bool searchPackageUIElementsWereEnabled = SearchResults.Contains(packageSearchResult) && SearchPackageUIElementsAreEnabled;
		bool installedProgramsUIElementsWereEnabled = InstalledPrograms.Contains(packageSearchResult) && InstalledProgramsUIElementsAreEnabled;
		if (searchPackageUIElementsWereEnabled)
		{
			SearchPackageUIElementsAreEnabled = false;
		}
		else if (installedProgramsUIElementsWereEnabled)
		{
			InstalledProgramsUIElementsAreEnabled = false;
		}

		try
		{
			packageSearchResult.IsPackageOperationRunning = true;
			packageSearchResult.IsPackageOperationProgressIndeterminate = true;
			packageSearchResult.PackageOperationProgress = 0D;
			packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Repair queued for {0}.", GetPackageLogDisplayName(packageSearchResult));

			IAsyncOperationWithProgress<RepairResult, RepairProgress> repairOperation = WinGetPackageSearchService.RepairPackage(packageSearchResult);
			packageSearchResult.BeginPackageOperation(repairOperation);
			using CancellationTokenRegistration cancellationRegistration = cancellationToken.Register(packageSearchResult.CancelPackageOperation);
			repairOperation.Progress = (operation, progress) => Atlas.AppDispatcher.TryEnqueue(() => ApplyRepairProgress(packageSearchResult, progress));

			RepairResult repairResult = await repairOperation;
			if (packageSearchResult.IsPackageOperationCancellationRequested)
			{
				SetPackageOperationCanceled(packageSearchResult);
				return;
			}

			if (WinGetPackageSearchService.IsNoApplicableRepairerResult(repairResult))
			{
				packageSearchResult.PackageOperationStatus = "WinGet could not find an applicable repairer for this package.";
				MainInfoBar.WriteWarning(packageSearchResult.PackageOperationStatus);
				return;
			}

			if (repairResult.Status is not RepairResultStatus.Ok)
			{
				string repairError = WinGetPackageSearchService.GetRepairResultError(repairResult);
				packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package repair failed for {0}. {1}", GetPackageLogDisplayName(packageSearchResult), repairError);
				MainInfoBar.WriteError(new InvalidOperationException(packageSearchResult.PackageOperationStatus), "Package repair failed.");
				return;
			}

			packageSearchResult.PackageOperationProgress = 100D;
			packageSearchResult.IsPackageOperationProgressIndeterminate = false;
			packageSearchResult.PackageOperationStatus = repairResult.RebootRequired
				? string.Format(CultureInfo.InvariantCulture, "Package repair succeeded for {0}. A reboot is required.", GetPackageLogDisplayName(packageSearchResult))
				: string.Format(CultureInfo.InvariantCulture, "Package repair succeeded for {0}.", GetPackageLogDisplayName(packageSearchResult));
			MainInfoBar.WriteSuccess(packageSearchResult.PackageOperationStatus);
		}
		catch (Exception) when (packageSearchResult.IsPackageOperationCancellationRequested)
		{
			SetPackageOperationCanceled(packageSearchResult);
		}
		catch (OperationCanceledException)
		{
			SetPackageOperationCanceled(packageSearchResult);
		}
		catch (Exception ex)
		{
			packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package repair failed for {0}.", GetPackageLogDisplayName(packageSearchResult));
			MainInfoBar.WriteError(ex, packageSearchResult.PackageOperationStatus);
		}
		finally
		{
			if (searchPackageUIElementsWereEnabled)
			{
				SearchPackageUIElementsAreEnabled = true;
			}
			else if (installedProgramsUIElementsWereEnabled)
			{
				InstalledProgramsUIElementsAreEnabled = true;
			}
			packageSearchResult.EndPackageOperation();
			packageSearchResult.IsPackageOperationRunning = false;
		}
	}

	private async Task RefreshPackageStatusAsync(WinGetPackageSearchResult packageSearchResult, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (packageSearchResult.IsPackageOperationRunning)
		{
			return;
		}

		bool searchPackageUIElementsWereEnabled = SearchResults.Contains(packageSearchResult) && SearchPackageUIElementsAreEnabled;
		bool installedProgramsUIElementsWereEnabled = InstalledPrograms.Contains(packageSearchResult) && InstalledProgramsUIElementsAreEnabled;
		if (searchPackageUIElementsWereEnabled)
		{
			SearchPackageUIElementsAreEnabled = false;
		}
		else if (installedProgramsUIElementsWereEnabled)
		{
			InstalledProgramsUIElementsAreEnabled = false;
		}

		try
		{
			packageSearchResult.IsPackageOperationRunning = true;
			packageSearchResult.IsPackageOperationProgressIndeterminate = true;
			packageSearchResult.PackageOperationProgress = 0D;
			packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Refreshing package status for {0}.", GetPackageLogDisplayName(packageSearchResult));

			using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			packageSearchResult.BeginPackageOperation(cancellationTokenSource);
			bool refreshed = await ApplyRefreshedPackageStatusAsync(packageSearchResult, cancellationTokenSource.Token);
			if (packageSearchResult.IsPackageOperationCancellationRequested)
			{
				SetPackageOperationCanceled(packageSearchResult);
				return;
			}

			if (refreshed)
			{
				packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package status refreshed for {0}.", GetPackageLogDisplayName(packageSearchResult));
				MainInfoBar.WriteSuccess(packageSearchResult.PackageOperationStatus);
			}
			else
			{
				packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package was not found in configured WinGet sources for {0}.", GetPackageLogDisplayName(packageSearchResult));
				MainInfoBar.WriteWarning(packageSearchResult.PackageOperationStatus);
			}
		}
		catch (Exception) when (packageSearchResult.IsPackageOperationCancellationRequested)
		{
			SetPackageOperationCanceled(packageSearchResult);
		}
		catch (Exception ex)
		{
			packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package status refresh failed for {0}.", GetPackageLogDisplayName(packageSearchResult));
			MainInfoBar.WriteError(ex, "Package status refresh failed.");
		}
		finally
		{
			if (searchPackageUIElementsWereEnabled)
			{
				SearchPackageUIElementsAreEnabled = true;
			}
			else if (installedProgramsUIElementsWereEnabled)
			{
				InstalledProgramsUIElementsAreEnabled = true;
			}
			packageSearchResult.EndPackageOperation();
			packageSearchResult.IsPackageOperationProgressIndeterminate = false;
			packageSearchResult.IsPackageOperationRunning = false;
		}
	}

	private static async Task ShowInstallationNotesAsync(WinGetPackageSearchResult packageSearchResult, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		string installationNotes = string.IsNullOrWhiteSpace(packageSearchResult.InstallationNotes)
			? "No installation notes are published for this package."
			: packageSearchResult.InstallationNotes;

		ScrollViewer scrollViewer = new()
		{
			MaxHeight = 520,
			Content = new TextBlock
			{
				Text = installationNotes,
				TextWrapping = TextWrapping.Wrap
			}
		};

		using ContentDialogV2 dialog = new()
		{
			Title = $"Installation notes for {packageSearchResult.Name}",
			Content = scrollViewer,
			CloseButtonText = "Close"
		};

		_ = await dialog.ShowAsync();
	}

	private static async Task<bool> ApplyRefreshedPackageStatusAsync(WinGetPackageSearchResult packageSearchResult, CancellationToken cancellationToken)
	{
		WinGetPackageSearchResult? refreshedResult = await WinGetPackageSearchService.RefreshPackageStatusAsync(packageSearchResult, cancellationToken);
		if (refreshedResult is null)
		{
			return false;
		}

		packageSearchResult.ApplyRefreshedState(refreshedResult);
		return true;
	}

	private static string GetPackageLogDisplayName(WinGetPackageSearchResult packageSearchResult)
	{
		string packageName = string.IsNullOrWhiteSpace(packageSearchResult.Name) ? "Unknown package" : packageSearchResult.Name;
		string packageId = string.IsNullOrWhiteSpace(packageSearchResult.Id) ? "Unknown ID" : packageSearchResult.Id;
		string packageVersion = string.IsNullOrWhiteSpace(packageSearchResult.Version) ? string.Empty : packageSearchResult.Version;
		string packageSource = string.IsNullOrWhiteSpace(packageSearchResult.Source) ? string.Empty : packageSearchResult.Source;
		string versionText = string.IsNullOrWhiteSpace(packageVersion) ? string.Empty : string.Format(CultureInfo.InvariantCulture, ", version {0}", packageVersion);
		string sourceText = string.IsNullOrWhiteSpace(packageSource) ? string.Empty : string.Format(CultureInfo.InvariantCulture, ", source {0}", packageSource);
		return string.Format(CultureInfo.InvariantCulture, "{0} ({1}{2}{3})", packageName, packageId, versionText, sourceText);
	}

	private static string GetSourceLogDisplayName(string sourceName) => string.IsNullOrWhiteSpace(sourceName) ? "unknown source" : sourceName;

	private static void ApplyInstallProgress(WinGetPackageSearchResult packageSearchResult, InstallProgress installProgress)
	{
		double progressValue = installProgress.State switch
		{
			PackageInstallProgressState.Downloading => installProgress.DownloadProgress,
			PackageInstallProgressState.Installing => installProgress.InstallationProgress,
			PackageInstallProgressState.PostInstall => installProgress.InstallationProgress,
			PackageInstallProgressState.Finished => 100D,
			_ => 0D
		};
		double progressPercentage = NormalizeProgress(progressValue);
		packageSearchResult.PackageOperationProgress = progressPercentage;
		packageSearchResult.IsPackageOperationProgressIndeterminate = progressPercentage <= 0D && installProgress.State is not PackageInstallProgressState.Finished;
		packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package operation status for {0}: {1}, {2:N0}% complete.", GetPackageLogDisplayName(packageSearchResult), installProgress.State, progressPercentage);
	}

	private static void ApplyUninstallProgress(WinGetPackageSearchResult packageSearchResult, UninstallProgress uninstallProgress)
	{
		double progressValue = uninstallProgress.State switch
		{
			PackageUninstallProgressState.Uninstalling => uninstallProgress.UninstallationProgress,
			PackageUninstallProgressState.PostUninstall => uninstallProgress.UninstallationProgress,
			PackageUninstallProgressState.Finished => 100D,
			_ => 0D
		};
		double progressPercentage = NormalizeProgress(progressValue);
		packageSearchResult.PackageOperationProgress = progressPercentage;
		packageSearchResult.IsPackageOperationProgressIndeterminate = progressPercentage <= 0D && uninstallProgress.State is not PackageUninstallProgressState.Finished;
		packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Uninstall status for {0}: {1}, {2:N0}% complete.", GetPackageLogDisplayName(packageSearchResult), uninstallProgress.State, progressPercentage);
	}

	private static void ApplyDownloadProgress(WinGetPackageSearchResult packageSearchResult, PackageDownloadProgress downloadProgress)
	{
		double progressPercentage = NormalizeProgress(downloadProgress.State is PackageDownloadProgressState.Finished ? 100D : downloadProgress.DownloadProgress);
		string downloadedSize = FormatDownloadSize(downloadProgress.BytesDownloaded);
		string requiredSize = FormatDownloadSize(downloadProgress.BytesRequired);
		packageSearchResult.PackageOperationProgress = progressPercentage;
		packageSearchResult.IsPackageOperationProgressIndeterminate = progressPercentage <= 0D && downloadProgress.State is not PackageDownloadProgressState.Finished;
		packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Download status for {0}: {1}, {2:N0}% complete. {3}/{4}.", GetPackageLogDisplayName(packageSearchResult), downloadProgress.State, progressPercentage, downloadedSize, requiredSize);
	}

	private static string FormatDownloadSize(double byteCount)
	{
		double safeByteCount = Math.Max(0D, byteCount);
		double megabytes = safeByteCount / (1024D * 1024D);
		if (megabytes < 1024D)
		{
			return string.Format(CultureInfo.InvariantCulture, "{0:N2} MB", megabytes);
		}
		double gigabytes = megabytes / 1024D;
		return string.Format(CultureInfo.InvariantCulture, "{0:N2} GB", gigabytes);
	}

	private static void ApplyRepairProgress(WinGetPackageSearchResult packageSearchResult, RepairProgress repairProgress)
	{
		double progressPercentage = NormalizeProgress(repairProgress.State is PackageRepairProgressState.Finished ? 100D : repairProgress.RepairCompletionProgress);
		packageSearchResult.PackageOperationProgress = progressPercentage;
		packageSearchResult.IsPackageOperationProgressIndeterminate = progressPercentage <= 0D && repairProgress.State is not PackageRepairProgressState.Finished;
		packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Repair status for {0}: {1}, {2:N0}% complete.", GetPackageLogDisplayName(packageSearchResult), repairProgress.State, progressPercentage);
	}

	private static void SetPackageOperationCanceled(WinGetPackageSearchResult packageSearchResult)
	{
		packageSearchResult.PackageOperationProgress = 0D;
		packageSearchResult.IsPackageOperationProgressIndeterminate = false;
		packageSearchResult.PackageOperationStatus = string.Format(CultureInfo.InvariantCulture, "Package operation canceled for {0}.", GetPackageLogDisplayName(packageSearchResult));
	}

	private static double NormalizeProgress(double progressValue)
	{
		if (progressValue > 0D && progressValue <= 1D)
		{
			progressValue *= 100D;
		}

		return Math.Clamp(progressValue, 0D, 100D);
	}

	private void ApplyInstalledProgramsFilter()
	{
		string trimmedFilter = InstalledProgramsSearchQuery.Trim();
		InstalledPrograms.Clear();
		SelectedInstalledProgramsCount = 0;

		for (int index = 0; index < installedProgramsCache.Count; index++)
		{
			WinGetPackageSearchResult package = installedProgramsCache[index];
			if ((!ShowOnlyInstalledProgramsWithUpdates || package.IsUpdateAvailable) && PackageMatchesFilter(package, trimmedFilter))
			{
				InstalledPrograms.Add(package);
			}
		}

		NotifyInstalledProgramsChanged();
		string statusText = ShowOnlyInstalledProgramsWithUpdates && string.IsNullOrWhiteSpace(trimmedFilter)
			? string.Format(CultureInfo.InvariantCulture, "Showing {0} of {1} installed program(s) with updates available.", InstalledPrograms.Count, installedProgramsCache.Count)
			: ShowOnlyInstalledProgramsWithUpdates
				? string.Format(CultureInfo.InvariantCulture, "Showing {0} of {1} installed program(s) with updates available matching {2}.", InstalledPrograms.Count, installedProgramsCache.Count, trimmedFilter)
				: string.IsNullOrWhiteSpace(trimmedFilter)
				? string.Format(CultureInfo.InvariantCulture, "Found {0} installed program(s).", InstalledPrograms.Count)
				: string.Format(CultureInfo.InvariantCulture, "Showing {0} of {1} installed program(s) matching {2}.", InstalledPrograms.Count, installedProgramsCache.Count, trimmedFilter);
		InstalledProgramsStatusText = GetResultStatusText(statusText, installedProgramsCache);
	}

	private static string GetResultStatusText(string statusText, IEnumerable<WinGetPackageSearchResult> packages)
	{
		foreach (WinGetPackageSearchResult package in packages)
		{
			if (package.WasLimitExceeded)
			{
				return $"{statusText} More matching packages are available than the current result limit allows. Narrow the search query.";
			}
		}

		return statusText;
	}

	private static bool PackageMatchesFilter(WinGetPackageSearchResult packageSearchResult, string filter) =>
		string.IsNullOrWhiteSpace(filter)
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.Name) && packageSearchResult.Name.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.Id) && packageSearchResult.Id.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.Version) && packageSearchResult.Version.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.InstalledVersion) && packageSearchResult.InstalledVersion.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.Publisher) && packageSearchResult.Publisher.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.Source) && packageSearchResult.Source.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.Description) && packageSearchResult.Description.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.MatchValue) && packageSearchResult.MatchValue.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.UpdateStatus) && packageSearchResult.UpdateStatus.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.Tags) && packageSearchResult.Tags.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.DocumentationUrls) && packageSearchResult.DocumentationUrls.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.IconUrls) && packageSearchResult.IconUrls.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.License) && packageSearchResult.License.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.LicenseUrl) && packageSearchResult.LicenseUrl.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.PrivacyUrl) && packageSearchResult.PrivacyUrl.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.PublisherUrl) && packageSearchResult.PublisherUrl.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.PublisherSupportUrl) && packageSearchResult.PublisherSupportUrl.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.PackageUrl) && packageSearchResult.PackageUrl.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.PurchaseUrl) && packageSearchResult.PurchaseUrl.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.ReleaseNotes) && packageSearchResult.ReleaseNotes.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.ReleaseNotesUrl) && packageSearchResult.ReleaseNotesUrl.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.InstallerElevationRequirement) && packageSearchResult.InstallerElevationRequirement.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.InstallerArchitecture) && packageSearchResult.InstallerArchitecture.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.InstallerType) && packageSearchResult.InstallerType.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.InstallerNestedType) && packageSearchResult.InstallerNestedType.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.InstallerScope) && packageSearchResult.InstallerScope.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.InstallerLocale) && packageSearchResult.InstallerLocale.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.InstalledLocation) && packageSearchResult.InstalledLocation.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.StandardUninstallCommand) && packageSearchResult.StandardUninstallCommand.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.SilentUninstallCommand) && packageSearchResult.SilentUninstallCommand.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.PackageFamilyNames) && packageSearchResult.PackageFamilyNames.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.ProductCodes) && packageSearchResult.ProductCodes.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.InstalledStatusCheck) && packageSearchResult.InstalledStatusCheck.Contains(filter, StringComparison.OrdinalIgnoreCase))
			|| (!string.IsNullOrWhiteSpace(packageSearchResult.InstalledStatusDetails) && packageSearchResult.InstalledStatusDetails.Contains(filter, StringComparison.OrdinalIgnoreCase));

	private async Task LoadInstalledProgramsAsync()
	{
		using IDisposable taskTracker = TaskTracking.RegisterOperation();

		CancelInstalledQuery();
		CancellationTokenSource cancellationTokenSource = new();
		installedCancellationTokenSource = cancellationTokenSource;
		CancellationToken cancellationToken = cancellationTokenSource.Token;

		try
		{
			InstalledProgramsUIElementsAreEnabled = false;
			IsLoadingInstalledPrograms = true;
			InstalledPrograms.Clear();
			SelectedInstalledProgramsCount = 0;
			installedProgramsCache.Clear();
			NotifyInstalledProgramsChanged();
			InstalledProgramsStatusText = "Querying installed programs.";
			MainInfoBar.WriteInfo(InstalledProgramsStatusText);
			List<WinGetPackageSearchResult> packages = await Task.Run(
				async () => await WinGetPackageSearchService.GetInstalledProgramsAsync(cancellationToken),
				cancellationToken);
			cancellationToken.ThrowIfCancellationRequested();
			installedProgramsCache.AddRange(packages);
			ApplyInstalledProgramsFilter();
			MainInfoBar.WriteSuccess(InstalledProgramsStatusText);
		}
		catch (OperationCanceledException)
		{
			InstalledProgramsStatusText = "Installed package query canceled.";
			MainInfoBar.WriteInfo(InstalledProgramsStatusText);
		}
		catch (Exception ex)
		{
			InstalledProgramsStatusText = "Installed package query failed.";
			MainInfoBar.WriteError(ex, InstalledProgramsStatusText);
		}
		finally
		{
			// Only the operation that still owns the section state restores the UI.
			bool shouldRestoreInstalledProgramsUI = ReferenceEquals(installedCancellationTokenSource, cancellationTokenSource) || installedCancellationTokenSource is null;
			if (ReferenceEquals(installedCancellationTokenSource, cancellationTokenSource))
			{
				installedCancellationTokenSource = null;
			}

			cancellationTokenSource.Dispose();
			if (shouldRestoreInstalledProgramsUI)
			{
				InstalledProgramsUIElementsAreEnabled = true;
				IsLoadingInstalledPrograms = false;
			}
		}
	}

	internal void LoadSourcesCore()
	{
		try
		{
			SourcesUIElementsAreEnabled = false;
			Sources.Clear();
			SelectedSourcesCount = 0;
			NotifySourcesChanged();
			IReadOnlyList<WinGetSourceInfo> sources = WinGetPackageSearchService.GetSources();
			foreach (WinGetSourceInfo source in sources)
			{
				Sources.Add(source);
			}

			RefreshPackageSearchSourceOptions(sources);
			SourcesStatusText = string.Format(CultureInfo.InvariantCulture, "Found {0} source(s).", Sources.Count);
			NotifySourcesChanged();
			MainInfoBar.WriteSuccess(SourcesStatusText);
		}
		catch (Exception ex)
		{
			SourcesStatusText = "Source list failed.";
			MainInfoBar.WriteError(ex, SourcesStatusText);
		}
		finally
		{
			SourcesUIElementsAreEnabled = true;
		}
	}

	internal async void AddSourceAsync()
	{
		if (!IsAddSourceButtonEnabled)
		{
			return;
		}

		string operationSourceName = SourceName.Trim();
		string operationSourceUri = SourceUri.Trim();
		string operationSourceType = SourceType.Trim();
		bool sourcesUIElementsWereEnabled = SourcesUIElementsAreEnabled;
		if (sourcesUIElementsWereEnabled)
		{
			SourcesUIElementsAreEnabled = false;
		}
		try
		{
			IsSourceOperationRunning = true;
			SourcesStatusText = string.Format(CultureInfo.InvariantCulture, "Adding source {0}.", GetSourceLogDisplayName(operationSourceName));
			PackageCatalogTrustLevel operationSourceTrustLevel = SelectedSourceTrustLevelValue is 1 ? PackageCatalogTrustLevel.Trusted : PackageCatalogTrustLevel.None;
			IAsyncOperationWithProgress<AddPackageCatalogResult, double> addOperation = WinGetPackageSearchService.AddSource(operationSourceName, operationSourceUri, operationSourceType, operationSourceTrustLevel);
			SetCurrentSourceOperation(addOperation);
			addOperation.Progress = (operation, progress) => Atlas.AppDispatcher.TryEnqueue(() => SourcesStatusText = string.Format(CultureInfo.InvariantCulture, "Adding source {0}: {1:N0}% complete.", GetSourceLogDisplayName(operationSourceName), NormalizeProgress(progress)));

			AddPackageCatalogResult addResult = await addOperation;
			if (isSourceOperationCancellationRequested)
			{
				SourcesStatusText = string.Format(CultureInfo.InvariantCulture, "Source add canceled for {0}.", GetSourceLogDisplayName(operationSourceName));
				return;
			}

			if (addResult.Status is not AddPackageCatalogStatus.Ok)
			{
				string addError = WinGetPackageSearchService.GetAddSourceResultError(addResult);
				SourcesStatusText = string.Format(CultureInfo.InvariantCulture, "Source add failed for {0}. {1}", GetSourceLogDisplayName(operationSourceName), addError);
				MainInfoBar.WriteError(new InvalidOperationException(SourcesStatusText), "Source add failed.");
				return;
			}

			SourcesStatusText = string.Format(CultureInfo.InvariantCulture, "Source added: {0}.", GetSourceLogDisplayName(operationSourceName));
			SourceName = string.Empty;
			SourceUri = string.Empty;
			MainInfoBar.WriteSuccess(SourcesStatusText);
			LoadSourcesCore();
		}
		catch (Exception) when (isSourceOperationCancellationRequested)
		{
			SourcesStatusText = string.Format(CultureInfo.InvariantCulture, "Source add canceled for {0}.", GetSourceLogDisplayName(operationSourceName));
		}
		catch (OperationCanceledException)
		{
			SourcesStatusText = string.Format(CultureInfo.InvariantCulture, "Source add canceled for {0}.", GetSourceLogDisplayName(operationSourceName));
		}
		catch (Exception ex)
		{
			SourcesStatusText = string.Format(CultureInfo.InvariantCulture, "Source add failed for {0}.", GetSourceLogDisplayName(operationSourceName));
			MainInfoBar.WriteError(ex, SourcesStatusText);
		}
		finally
		{
			if (sourcesUIElementsWereEnabled)
			{
				SourcesUIElementsAreEnabled = true;
			}
			SetCurrentSourceOperation(null);
			isSourceOperationCancellationRequested = false;
			IsSourceOperationRunning = false;
		}
	}

	private async Task RemoveSourceAsync(WinGetSourceInfo sourceInfo, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (!sourceInfo.IsActionEnabled)
		{
			return;
		}

		using ContentDialogV2 confirmDialog = new()
		{
			Title = "Remove source",
			Content = $"Remove WinGet source {sourceInfo.Name}?",
			PrimaryButtonText = "Remove",
			SecondaryButtonText = Atlas.GetStr("Cancel"),
			DefaultButton = ContentDialogButton.Secondary
		};

		ContentDialogResult confirmation = await confirmDialog.ShowAsync();
		if (confirmation is not ContentDialogResult.Primary)
		{
			return;
		}
		cancellationToken.ThrowIfCancellationRequested();

		using IDisposable taskTracker = TaskTracking.RegisterOperation();

		bool sourcesUIElementsWereEnabled = SourcesUIElementsAreEnabled;
		if (sourcesUIElementsWereEnabled)
		{
			SourcesUIElementsAreEnabled = false;
		}
		try
		{
			sourceInfo.IsOperationRunning = true;
			sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Removing source {0}.", GetSourceLogDisplayName(sourceInfo.Name));
			IAsyncOperationWithProgress<RemovePackageCatalogResult, double> removeOperation = WinGetPackageSearchService.RemoveSource(sourceInfo.Name);
			sourceInfo.BeginOperation(removeOperation);
			SetCurrentSourceOperation(removeOperation);
			using CancellationTokenRegistration cancellationRegistration = cancellationToken.Register(sourceInfo.CancelOperation);
			removeOperation.Progress = (operation, progress) => Atlas.AppDispatcher.TryEnqueue(() => sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Removing source {0}: {1:N0}% complete.", GetSourceLogDisplayName(sourceInfo.Name), NormalizeProgress(progress)));

			RemovePackageCatalogResult removeResult = await removeOperation;
			if (sourceInfo.IsOperationCancellationRequested)
			{
				sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Source remove canceled for {0}.", GetSourceLogDisplayName(sourceInfo.Name));
				return;
			}

			if (removeResult.Status is not RemovePackageCatalogStatus.Ok)
			{
				string removeError = WinGetPackageSearchService.GetRemoveSourceResultError(removeResult);
				sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Source remove failed for {0}. {1}", GetSourceLogDisplayName(sourceInfo.Name), removeError);
				MainInfoBar.WriteError(new InvalidOperationException(sourceInfo.Status), "Source remove failed.");
				return;
			}

			sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Source removed: {0}.", GetSourceLogDisplayName(sourceInfo.Name));
			MainInfoBar.WriteSuccess(sourceInfo.Status);
			LoadSourcesCore();
		}
		catch (Exception) when (sourceInfo.IsOperationCancellationRequested)
		{
			sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Source remove canceled for {0}.", GetSourceLogDisplayName(sourceInfo.Name));
		}
		catch (OperationCanceledException)
		{
			sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Source remove canceled for {0}.", GetSourceLogDisplayName(sourceInfo.Name));
		}
		catch (Exception ex)
		{
			sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Source remove failed for {0}.", GetSourceLogDisplayName(sourceInfo.Name));
			MainInfoBar.WriteError(ex, sourceInfo.Status);
		}
		finally
		{
			if (sourcesUIElementsWereEnabled)
			{
				SourcesUIElementsAreEnabled = true;
			}
			SetCurrentSourceOperation(null);
			sourceInfo.EndOperation();
			sourceInfo.IsOperationRunning = false;
		}
	}

	private async Task UpdateSourceAsync(WinGetSourceInfo sourceInfo, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (!sourceInfo.IsActionEnabled)
		{
			return;
		}

		using IDisposable taskTracker = TaskTracking.RegisterOperation();

		bool sourcesUIElementsWereEnabled = SourcesUIElementsAreEnabled;
		if (sourcesUIElementsWereEnabled)
		{
			SourcesUIElementsAreEnabled = false;
		}
		try
		{
			sourceInfo.IsOperationRunning = true;
			sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Updating source {0}.", GetSourceLogDisplayName(sourceInfo.Name));
			IAsyncOperationWithProgress<RefreshPackageCatalogResult, double> updateOperation = WinGetPackageSearchService.UpdateSource(sourceInfo);
			sourceInfo.BeginOperation(updateOperation);
			SetCurrentSourceOperation(updateOperation);
			using CancellationTokenRegistration cancellationRegistration = cancellationToken.Register(sourceInfo.CancelOperation);
			updateOperation.Progress = (operation, progress) => Atlas.AppDispatcher.TryEnqueue(() => sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Updating source {0}: {1:N0}% complete.", GetSourceLogDisplayName(sourceInfo.Name), NormalizeProgress(progress)));

			RefreshPackageCatalogResult refreshResult = await updateOperation;
			if (sourceInfo.IsOperationCancellationRequested)
			{
				sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Source update canceled for {0}.", GetSourceLogDisplayName(sourceInfo.Name));
				return;
			}

			if (refreshResult.Status is not RefreshPackageCatalogStatus.Ok)
			{
				string updateError = WinGetPackageSearchService.GetUpdateSourceResultError(refreshResult);
				sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Source update failed for {0}. {1}", GetSourceLogDisplayName(sourceInfo.Name), updateError);
				MainInfoBar.WriteError(new InvalidOperationException(sourceInfo.Status), "Source update failed.");
				return;
			}

			sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Source updated: {0}.", GetSourceLogDisplayName(sourceInfo.Name));
			MainInfoBar.WriteSuccess(sourceInfo.Status);
			LoadSourcesCore();
		}
		catch (Exception) when (sourceInfo.IsOperationCancellationRequested)
		{
			sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Source update canceled for {0}.", GetSourceLogDisplayName(sourceInfo.Name));
		}
		catch (OperationCanceledException)
		{
			sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Source update canceled for {0}.", GetSourceLogDisplayName(sourceInfo.Name));
		}
		catch (Exception ex)
		{
			sourceInfo.Status = string.Format(CultureInfo.InvariantCulture, "Source update failed for {0}.", GetSourceLogDisplayName(sourceInfo.Name));
			MainInfoBar.WriteError(ex, sourceInfo.Status);
		}
		finally
		{
			if (sourcesUIElementsWereEnabled)
			{
				SourcesUIElementsAreEnabled = true;
			}
			SetCurrentSourceOperation(null);
			sourceInfo.EndOperation();
			sourceInfo.IsOperationRunning = false;
		}
	}

	private async Task ExportPackagesToJsonAsync(string sectionName, IEnumerable<WinGetPackageSearchResult> packages, string defaultFileName)
	{
		List<WinGetPackageSearchResult> packagesToExport = [];
		foreach (WinGetPackageSearchResult package in packages)
		{
			packagesToExport.Add(package);
		}

		if (packagesToExport.Count is 0)
		{
			MainInfoBar.WriteWarning("There are no WinGet packages to export.");
			return;
		}

		string? selectedFile = FileDialogHelper.ShowSaveFileDialog(Atlas.JSONPickerFilter, defaultFileName);
		if (string.IsNullOrWhiteSpace(selectedFile))
		{
			MainInfoBar.WriteWarning("You need to select a location to export the data to.");
			return;
		}

		try
		{
			MainInfoBar.WriteInfo("Exporting data to JSON.");
			WinGetPackageExportDocument exportDocument = new(DateTimeOffset.UtcNow, sectionName, packagesToExport);

			await Task.Run(() =>
			{
				using FileStream stream = File.Create(selectedFile);
				JsonSerializer.Serialize(stream, exportDocument, WinGetPackageJsonContext.Default.WinGetPackageExportDocument);
			});

			MainInfoBar.WriteSuccess(string.Format(CultureInfo.InvariantCulture, "Successfully exported {0} item(s) to {1}.", packagesToExport.Count, selectedFile));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, "WinGet package JSON export failed.");
		}
	}

	private string GetDownloadDirectory()
	{
		try
		{
			return Directory.CreateDirectory(ResolvedDownloadDirectory).FullName;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			string fallbackDirectory = Path.Join(DownloadManagerVM.ResolveDefaultDownloadsDirectory(), "HardenSystemSecurity-WinGet");
			return Directory.CreateDirectory(fallbackDirectory).FullName;
		}
	}

	private static async Task<bool> ShowPackageAgreementsAsync(WinGetPackageSearchResult packageSearchResult)
	{
		IReadOnlyList<string> agreements = WinGetPackageSearchService.GetPackageAgreements(packageSearchResult);
		string agreementsText = agreements.Count is 0 ? "No package agreements are published for this package." : string.Join($"{Environment.NewLine}{Environment.NewLine}", agreements);

		ScrollViewer scrollViewer = new()
		{
			MaxHeight = 520,
			Content = new TextBlock
			{
				Text = agreementsText,
				TextWrapping = TextWrapping.Wrap
			}
		};

		using ContentDialogV2 dialog = new()
		{
			Title = $"Package agreements for {packageSearchResult.Name}",
			Content = scrollViewer,
			PrimaryButtonText = "Accept and install",
			SecondaryButtonText = Atlas.GetStr("Cancel"),
			DefaultButton = ContentDialogButton.Secondary
		};

		ContentDialogResult result = await dialog.ShowAsync();
		return result is ContentDialogResult.Primary;
	}

	internal void CancelCurrentSearch()
	{
		CancellationTokenSource? cancellationTokenSource = searchCancellationTokenSource;
		searchCancellationTokenSource = null;

		cancellationTokenSource?.Cancel();

		CancelBulkPackageAction(ListViewHelper.ListViewsRegistry.WinGet_SearchResults);
		CancelActivePackageOperations(SearchResults);
	}

	internal void CancelInstalledQuery()
	{
		CancellationTokenSource? cancellationTokenSource = installedCancellationTokenSource;
		installedCancellationTokenSource = null;

		cancellationTokenSource?.Cancel();

		CancelBulkPackageAction(ListViewHelper.ListViewsRegistry.WinGet_InstalledPackages);
		CancelActivePackageOperations(InstalledPrograms);
	}

	private void SetCurrentSourceOperation(IAsyncInfo? currentSourceOperation)
	{
		sourceOperation = currentSourceOperation;
		OnPropertyChanged(nameof(IsSourceOperationCancelButtonEnabled));
	}

	internal void CancelCurrentSourceOperation()
	{
		bulkSourceActionCancellationTokenSource?.Cancel();
		IAsyncInfo? currentSourceOperation = sourceOperation;
		if (currentSourceOperation is null)
		{
			return;
		}

		isSourceOperationCancellationRequested = true;
		SourcesStatusText = "Canceling source operation.";

		try
		{
			currentSourceOperation.Cancel();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}
}

#region WinGet package bundles

internal sealed class WinGetPackageBundlePackage(string id, string displayName, Uri iconUri, string sourceName = "", bool displayIconBackground = false)
{
	internal string Id => id;
	internal string DisplayName => displayName;
	internal Uri IconUri => iconUri;
	internal string SourceName => sourceName;
	internal Visibility IconBackgroundVisibility => displayIconBackground ? Visibility.Visible : Visibility.Collapsed;
}

internal sealed class WinGetPackageBundle(string name, List<WinGetPackageBundlePackage> packages)
{
	internal string Name => name;
	internal List<WinGetPackageBundlePackage> PreviewPackages { get; } = CreatePreviewPackages(packages);
	internal List<WinGetPackageBundlePackage> Packages => packages;
	internal int PackageCount => packages.Count;

	private static List<WinGetPackageBundlePackage> CreatePreviewPackages(List<WinGetPackageBundlePackage> packages)
	{
		if (packages.Count <= 4)
		{
			return packages;
		}

		return [packages[0], packages[1], packages[2], packages[3]];
	}
}

#endregion

internal sealed class WinGetPackageExportDocument(DateTimeOffset exportedAtUtc, string sectionName, List<WinGetPackageSearchResult> packages)
{
	public DateTimeOffset ExportedAtUtc => exportedAtUtc;
	public string SectionName => sectionName;
	public int Count => packages.Count;
	public List<WinGetPackageSearchResult> Packages => packages;
}

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(WinGetPackageExportDocument))]
[JsonSerializable(typeof(WinGetPackageSearchResult))]
internal sealed partial class WinGetPackageJsonContext : JsonSerializerContext;
