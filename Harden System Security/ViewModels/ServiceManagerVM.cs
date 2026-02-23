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
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.ViewModels;
using CommonCore.IncrementalCollection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class ServiceItemViewModel : ViewModelBase
{
	internal ServiceItem Item { get; }
	internal SolidColorBrush StateColorBrush { get; }

	internal Visibility PeInfoVisibility => Item.HasPeInfo ? Visibility.Visible : Visibility.Collapsed;

	// Extracts only the file name for display in the Expander header
	internal string ExecutableName => string.IsNullOrWhiteSpace(Item.CleanPath) ? "Unknown" : Path.GetFileName(Item.CleanPath);

	internal int SelectedTab
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(ConfigDetailsVisibility));
				OnPropertyChanged(nameof(PeDetailsVisibility));
			}
		}
	}

	internal Visibility ConfigDetailsVisibility => SelectedTab == 0 ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility PeDetailsVisibility => SelectedTab == 1 && Item.HasPeInfo ? Visibility.Visible : Visibility.Collapsed;

	/// <summary>
	/// Bound to the UI ComboBox's ItemsSource.
	/// </summary>
	internal readonly string[] StartTypes = [
		"Boot Start",            // 0
		"System Start",          // 1
		"Auto Start",            // 2
		"Demand / Manual",       // 3
		"Disabled",              // 4
		"Auto Start (Delayed)"   // 5
	];

	/// <summary>
	/// Bound to the UI ComboBox's ItemsSource.
	/// </summary>
	internal readonly string[] ServiceTypes = [
		"Kernel Driver",                   // 0 (0x1)
		"File System Driver",              // 1 (0x2)
		"Win32 Own Process",               // 2 (0x10)
		"Win32 Share Process",             // 3 (0x20)
		"User Service",                    // 4 (0x40)
		"User Service Instance",           // 5 (0x80)
		"Win32 Own Process (Interactive)", // 6 (0x110)
		"Win32 Share Process (Interactive)",// 7 (0x120)
		"Unknown / Custom"                 // 8
	];

	/// <summary>
	/// Bound to the UI ComboBox's ItemsSource.
	/// </summary>
	internal readonly string[] ErrorControls = ["Ignore", "Normal", "Severe", "Critical"];

	/// <summary>
	/// Bound to the UI ComboBox's ItemsSource.
	/// </summary>
	internal readonly string[] LaunchProtectedTypes = ["None", "Windows", "Windows Light", "Antimalware Light"];

	internal int OriginalStartTypeIndex { get; set; }
	internal int SelectedStartTypeIndex
	{
		get; set
		{
			// Prevent UI Virtualization from pushing -1 into the ViewModel when recycling, causing a ComboBox with nothing selected.
			if (value == -1) return;
			if (SP(ref field, value)) OnPropertyChanged(nameof(StartTypeSaveVisibility));
		}
	}
	internal Visibility StartTypeSaveVisibility => SelectedStartTypeIndex != OriginalStartTypeIndex ? Visibility.Visible : Visibility.Collapsed;

	internal int OriginalServiceTypeIndex { get; set; }
	internal int SelectedServiceTypeIndex
	{
		get; set
		{
			// Prevent UI Virtualization from pushing -1 into the ViewModel when recycling, causing a ComboBox with nothing selected.
			if (value == -1) return;
			if (SP(ref field, value)) OnPropertyChanged(nameof(ServiceTypeSaveVisibility));
		}
	}
	internal Visibility ServiceTypeSaveVisibility => SelectedServiceTypeIndex != OriginalServiceTypeIndex ? Visibility.Visible : Visibility.Collapsed;

	internal int OriginalErrorControlIndex { get; set; }
	internal int SelectedErrorControlIndex
	{
		get; set
		{
			// Prevent UI Virtualization from pushing -1 into the ViewModel when recycling, causing a ComboBox with nothing selected.
			if (value == -1) return;
			if (SP(ref field, value)) OnPropertyChanged(nameof(ErrorControlSaveVisibility));
		}
	}
	internal Visibility ErrorControlSaveVisibility => SelectedErrorControlIndex != OriginalErrorControlIndex ? Visibility.Visible : Visibility.Collapsed;

	internal int OriginalLaunchProtectedIndex { get; set; }
	internal int SelectedLaunchProtectedIndex
	{
		get; set
		{
			// Prevent UI Virtualization from pushing -1 into the ViewModel when recycling, causing a ComboBox with nothing selected.
			if (value == -1) return;
			if (SP(ref field, value)) OnPropertyChanged(nameof(LaunchProtectedSaveVisibility));
		}
	}
	internal Visibility LaunchProtectedSaveVisibility => SelectedLaunchProtectedIndex != OriginalLaunchProtectedIndex ? Visibility.Visible : Visibility.Collapsed;

	internal ServiceItemViewModel(ServiceItem item)
	{
		Item = item;
		StateColorBrush = GetStateColor(item.CurrentState);

		OriginalStartTypeIndex = MapStartType(item.RawStartType, item.IsDelayedAutoStart);
		SelectedStartTypeIndex = OriginalStartTypeIndex;

		OriginalServiceTypeIndex = MapServiceType(item.RawServiceType);
		SelectedServiceTypeIndex = OriginalServiceTypeIndex;

		OriginalErrorControlIndex = MapErrorControl(item.RawErrorControl);
		SelectedErrorControlIndex = OriginalErrorControlIndex;

		OriginalLaunchProtectedIndex = MapLaunchProtected(item.RawLaunchProtected);
		SelectedLaunchProtectedIndex = OriginalLaunchProtectedIndex;
	}

	internal void CommitStartTypeChange()
	{
		OriginalStartTypeIndex = SelectedStartTypeIndex;
		OnPropertyChanged(nameof(StartTypeSaveVisibility));
	}
	internal void CommitServiceTypeChange()
	{
		OriginalServiceTypeIndex = SelectedServiceTypeIndex;
		OnPropertyChanged(nameof(ServiceTypeSaveVisibility));
	}
	internal void CommitErrorControlChange()
	{
		OriginalErrorControlIndex = SelectedErrorControlIndex;
		OnPropertyChanged(nameof(ErrorControlSaveVisibility));
	}
	internal void CommitLaunchProtectedChange()
	{
		OriginalLaunchProtectedIndex = SelectedLaunchProtectedIndex;
		OnPropertyChanged(nameof(LaunchProtectedSaveVisibility));
	}

	private static int MapStartType(uint startType, bool isDelayed)
	{
		if (isDelayed && startType == 2) return 5;
		if (startType <= 4) return (int)startType;
		return 3;
	}

	private static int MapServiceType(uint serviceType) => serviceType switch
	{
		0x1 => 0,
		0x2 => 1,
		0x10 => 2,
		0x20 => 3,
		0x40 => 4,
		0x80 => 5,
		0x110 => 6,
		0x120 => 7,
		_ => 8
	};

	private static int MapErrorControl(uint errorControl) => errorControl <= 3 ? (int)errorControl : 1;
	private static int MapLaunchProtected(uint launchProtected) => launchProtected <= 3 ? (int)launchProtected : 0;

	internal static readonly SolidColorBrush _runningBrush = new(Microsoft.UI.Colors.MediumSeaGreen);
	private static readonly SolidColorBrush _stoppedBrush = new(Microsoft.UI.Colors.Gray);
	private static readonly SolidColorBrush _pendingBrush = new(Microsoft.UI.Colors.Goldenrod);
	private static readonly SolidColorBrush _pausedBrush = new(Microsoft.UI.Colors.Orange);
	private static readonly SolidColorBrush _unknownBrush = new(Microsoft.UI.Colors.DimGray);

	private static SolidColorBrush GetStateColor(string state)
	{
		if (string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase)) return _runningBrush;
		if (string.Equals(state, "Stopped", StringComparison.OrdinalIgnoreCase)) return _stoppedBrush;
		if (state.Contains("Pending", StringComparison.OrdinalIgnoreCase)) return _pendingBrush;
		if (string.Equals(state, "Paused", StringComparison.OrdinalIgnoreCase)) return _pausedBrush;
		return _unknownBrush;
	}
}

internal sealed partial class FilterItemVM : ViewModelBase
{
	internal string Name { get; }
	internal int OriginalCount { get; }

	internal int CurrentCount
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(DisplayName));
			}
		}
	}

	internal string DisplayName => $"{Name} ({CurrentCount})";

	internal bool IsChecked
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ActionToTrigger?.Invoke();
			}
		}
	} = true;

	internal Action? ActionToTrigger { get; set; }

	internal FilterItemVM(string name, int count)
	{
		Name = name;
		OriginalCount = count;
		CurrentCount = count;
	}
}

internal sealed partial class FilterGroupVM(string groupName) : ViewModelBase
{
	internal string GroupName => groupName;
	internal RangedObservableCollection<FilterItemVM> Filters = [];
}

internal sealed partial class ServiceManagerVM : ViewModelBase
{
	private const uint SC_MANAGER_CONNECT = 0x0001;

	internal ServiceManagerVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		FilteredServices.CollectionChanged += (s, e) => OnPropertyChanged(nameof(EmptyStatePlaceholderVisibility));
	}

	internal readonly InfoBarSettings MainInfoBar;
	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	// Whether the UI elements are enabled or disabled
	internal bool AreElementsEnabled { get; set => SP(ref field, value); } = true;
	internal bool IsFilterPanelOpen { get; set => SP(ref field, value); }

	internal bool IsDynamicCountEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				if (AllServices.Count > 0)
				{
					ApplyFilter();
				}
			}
		}
	} = true;

	private volatile bool _isBulkUpdatingFilters;

	internal bool IsLoading
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressRingVisibility = field ? Visibility.Visible : Visibility.Collapsed;
			}
		}
	}
	internal Visibility ProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal int TotalServices { get; set => SP(ref field, value); }

	internal readonly RangedObservableCollection<ServiceItemViewModel> AllServices = [];
	internal readonly RangedObservableCollection<ServiceItemViewModel> FilteredServices = [];
	internal readonly RangedObservableCollection<FilterGroupVM> FilterGroups = [];

	internal Visibility EmptyStatePlaceholderVisibility => FilteredServices.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

	internal string? SearchText
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ApplyFilter();
			}
		}
	}

	internal int SelectedSortIndex
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ApplySort();
			}
		}
	}

	internal bool IsSortDescending
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(SortDirectionIcon));
				ApplySort();
			}
		}
	}

	// Down Arrow for Descending, Up Arrow for Ascending
	internal string SortDirectionIcon => IsSortDescending ? "\xE74A" : "\xE74B";

	private void ApplySort()
	{
		if (FilteredServices.Count == 0 || _isBulkUpdatingFilters)
		{
			return;
		}

		List<ServiceItemViewModel> sorted = SortServices(FilteredServices.ToList());
		FilteredServices.Clear();
		FilteredServices.AddRange(sorted);
	}

	private List<ServiceItemViewModel> SortServices(List<ServiceItemViewModel> source)
	{
		IEnumerable<ServiceItemViewModel> query = source;

		query = SelectedSortIndex == 1
			? IsSortDescending
				? query.OrderByDescending(x => x.Item.CurrentState, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Item.ServiceName, StringComparer.OrdinalIgnoreCase)
				: query.OrderBy(x => x.Item.CurrentState, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Item.ServiceName, StringComparer.OrdinalIgnoreCase)
			: SelectedSortIndex == 2
				? IsSortDescending
				? query.OrderByDescending(x => x.Item.StartType, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Item.ServiceName, StringComparer.OrdinalIgnoreCase)
				: query.OrderBy(x => x.Item.StartType, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Item.ServiceName, StringComparer.OrdinalIgnoreCase)
				: IsSortDescending
				? query.OrderByDescending(x => x.Item.ServiceName, StringComparer.OrdinalIgnoreCase)
				: query.OrderBy(x => x.Item.ServiceName, StringComparer.OrdinalIgnoreCase);

		return query.ToList();
	}

	internal void SelectorBar_Loaded(object sender, RoutedEventArgs e)
	{
		// Default select the "Configuration Details" tab when the UI loads
		if (sender is SelectorBar sb && sb.DataContext is ServiceItemViewModel svm)
		{
			if (svm.SelectedTab >= 0 && svm.SelectedTab < sb.Items.Count)
			{
				sb.SelectedItem = sb.Items[svm.SelectedTab];
			}

			// Unsubscribe first to avoid memory leaks/duplicate fires, then subscribe to handle list virtualization
			sb.DataContextChanged -= SelectorBar_DataContextChanged;
			sb.DataContextChanged += SelectorBar_DataContextChanged;
		}
	}

	private void SelectorBar_DataContextChanged(FrameworkElement sender, DataContextChangedEventArgs args)
	{
		// Forces the SelectorBar to update visually when the ListView recycles the container
		if (sender is SelectorBar sb && args.NewValue is ServiceItemViewModel svm)
		{
			if (svm.SelectedTab >= 0 && svm.SelectedTab < sb.Items.Count)
			{
				sb.SelectedItem = sb.Items[svm.SelectedTab];
			}
		}
	}

	internal void SelectorBar_SelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
	{
		// Map the UI selection down to the ViewModel's state to trigger layout switching
		if (sender.DataContext is ServiceItemViewModel svm)
		{
			int index = sender.Items.IndexOf(sender.SelectedItem);
			svm.SelectedTab = index == -1 ? 0 : index;
		}
	}

	internal void BrowseService_Click(object sender, RoutedEventArgs e)
	{
		if (sender is MenuFlyoutItem button && button.Tag is ServiceItemViewModel svm)
		{
			string fileToOpen = svm.Item.CleanPath;
			if (!string.IsNullOrWhiteSpace(fileToOpen) && Path.Exists(fileToOpen))
			{
				ProcessStartInfo processInfo = new()
				{
					FileName = "explorer.exe",
					Arguments = $"/select,\"{fileToOpen}\"", // Scroll to the file in File Explorer and highlight it.
					Verb = "runas",
					UseShellExecute = true
				};

				Process? process = null;
				try
				{
					process = Process.Start(processInfo);
				}
				finally
				{
					process?.Dispose();
				}
			}
			else if (!string.IsNullOrWhiteSpace(fileToOpen))
			{
				MainInfoBar.WriteWarning($"The executable path does not exist on disk: {fileToOpen}");
			}
		}
	}

	internal void OpenInRegistry_Click(object sender, RoutedEventArgs e)
	{
		if (sender is MenuFlyoutItem button && button.Tag is ServiceItemViewModel svm)
		{
			try
			{
				// Tell ingregedit.exe to open to the specific service by pre-setting the LastKey value
				string keyPath = $@"Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{svm.Item.ServiceName}";
				using Microsoft.Win32.RegistryKey? key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit");
				key?.SetValue("LastKey", keyPath, Microsoft.Win32.RegistryValueKind.String);

				ProcessStartInfo psi = new()
				{
					FileName = "regedit.exe",
					UseShellExecute = true,
					Verb = "runas"
				};
				_ = Process.Start(psi);
			}
			catch (Exception ex)
			{
				MainInfoBar.WriteError(ex);
			}
		}
	}

	internal async void SearchService_Click(object sender, RoutedEventArgs e)
	{
		if (sender is MenuFlyoutItem button && button.Tag is ServiceItemViewModel svm)
		{
			string query = Uri.EscapeDataString($"{svm.Item.ServiceName} {svm.Item.DisplayName} service");
			_ = await Windows.System.Launcher.LaunchUriAsync(new Uri($"https://www.bing.com/search?q={query}"));
		}
	}

	internal void SecurityService_Click(object sender, RoutedEventArgs e)
	{
		if (sender is MenuFlyoutItem button && button.Tag is ServiceItemViewModel svm)
		{
			using ServiceSecurityInformation si = new(svm.Item.ServiceName, svm.Item.DisplayName);

			_ = NativeMethods.EditSecurityAdvanced(IntPtr.Zero, si, 0x10000);
		}
	}

	internal void FileSecurity_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is ServiceItemViewModel svm)
		{
			string fileToOpen = svm.Item.CleanPath;
			if (!string.IsNullOrWhiteSpace(fileToOpen) && Path.Exists(fileToOpen))
			{
				// 2 = SHOP_FILEPATH, opens the Windows properties dialog targeting the Security tab
				_ = NativeMethods.SHObjectProperties(IntPtr.Zero, 2, fileToOpen, "Security");
			}
		}
	}

	internal void SelectAllFilters_Click() => SetAllFilters(true);

	internal void DeselectAllFilters_Click() => SetAllFilters(false);

	private void SetAllFilters(bool isChecked)
	{
		if (FilterGroups.Count == 0)
		{
			return;
		}

		// Suppress ApplyFilter from executing individually for each checkbox
		_isBulkUpdatingFilters = true;

		foreach (FilterGroupVM group in FilterGroups)
		{
			foreach (FilterItemVM filter in group.Filters)
			{
				filter.IsChecked = isChecked;
			}
		}

		// Re-enable and explicitly call ApplyFilter once
		_isBulkUpdatingFilters = false;
		ApplyFilter();
	}

	internal void LoadServices_Accelerator(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		LoadServices_Click();
		args.Handled = true;
	}

	internal async void LoadServices_Click()
	{
		if (IsLoading)
		{
			return;
		}

		try
		{
			AreElementsEnabled = false;
			IsLoading = true;
			MainInfoBarIsOpen = false;

			// Cache current filter states before clearing so they aren't lost on refresh
			Dictionary<string, HashSet<string>> previousFilters = new(StringComparer.OrdinalIgnoreCase);
			foreach (FilterGroupVM group in FilterGroups)
			{
				HashSet<string> uncheckedItems = new(StringComparer.OrdinalIgnoreCase);
				foreach (FilterItemVM filter in group.Filters)
				{
					if (!filter.IsChecked)
					{
						_ = uncheckedItems.Add(filter.Name);
					}
				}
				previousFilters[group.GroupName] = uncheckedItems;
			}

			// Suspend UI filter updates while we rebuild
			_isBulkUpdatingFilters = true;

			AllServices.Clear();
			FilteredServices.Clear();
			FilterGroups.Clear();
			TotalServices = 0;

			List<ServiceItem> services = await Task.Run(ServiceManagement.GetAllServices);

			List<ServiceItemViewModel> viewModels = new(services.Count);

			Dictionary<string, int> companyCounts = new(StringComparer.OrdinalIgnoreCase) { { "Microsoft Corporation", 0 }, { "Other", 0 } };
			Dictionary<string, int> statusCounts = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> startTypeCounts = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> serviceTypeCounts = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> errorControlCounts = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> launchProtectedCounts = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> serviceFlagsCounts = new(StringComparer.OrdinalIgnoreCase);

			foreach (ServiceItem service in services)
			{
				ServiceItemViewModel vm = new(service);
				viewModels.Add(vm);

				// Process specific Company Requirement
				if (string.Equals(service.PeCompany, "Microsoft Corporation", StringComparison.OrdinalIgnoreCase))
				{
					companyCounts["Microsoft Corporation"]++;
				}
				else
				{
					companyCounts["Other"]++;
				}

				// Process single-value items
				IncrementCount(statusCounts, service.CurrentState);
				IncrementCount(startTypeCounts, service.StartType);
				IncrementCount(errorControlCounts, service.ErrorControl);
				IncrementCount(launchProtectedCounts, service.LaunchProtected);
				IncrementCount(serviceFlagsCounts, service.ServiceFlags);

				// Process multi-value items (Separated by |)
				ProcessMultiValue(serviceTypeCounts, service.ServiceType);
			}

			FilterGroups.Add(CreateGroup("Company", companyCounts));
			FilterGroups.Add(CreateGroup("Status", statusCounts));
			FilterGroups.Add(CreateGroup("Start Type", startTypeCounts));
			FilterGroups.Add(CreateGroup("Service Type", serviceTypeCounts));
			FilterGroups.Add(CreateGroup("Error Control", errorControlCounts));
			FilterGroups.Add(CreateGroup("Launch Protected", launchProtectedCounts));
			FilterGroups.Add(CreateGroup("Service Flags", serviceFlagsCounts));

			// Restore previously unchecked filter states
			foreach (FilterGroupVM group in FilterGroups)
			{
				if (previousFilters.TryGetValue(group.GroupName, out HashSet<string>? uncheckedItems))
				{
					foreach (FilterItemVM filter in group.Filters)
					{
						if (uncheckedItems.Contains(filter.Name))
						{
							filter.IsChecked = false;
						}
					}
				}
			}

			AllServices.AddRange(viewModels);

			// Re-enable filter updates and apply the filter once
			_isBulkUpdatingFilters = false;
			ApplyFilter();

			MainInfoBar.WriteSuccess($"Successfully loaded {services.Count} services.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreElementsEnabled = true;
			IsLoading = false;
		}
	}

	private static void IncrementCount(Dictionary<string, int> dict, string key)
	{
		string safeKey = string.IsNullOrWhiteSpace(key) ? "None" : key.Trim();
		dict[safeKey] = dict.TryGetValue(safeKey, out int count) ? count + 1 : 1;
	}

	private static void ProcessMultiValue(Dictionary<string, int> dict, string multiValue)
	{
		if (string.IsNullOrWhiteSpace(multiValue))
		{
			IncrementCount(dict, "None");
			return;
		}

		string[] parts = multiValue.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
		if (parts.Length == 0)
		{
			IncrementCount(dict, "None");
			return;
		}

		foreach (string part in parts)
		{
			IncrementCount(dict, part);
		}
	}

	private static IEnumerable<string> GetMultiValues(string multiValueString)
	{
		if (string.IsNullOrWhiteSpace(multiValueString))
		{
			yield return "None";
			yield break;
		}

		string[] parts = multiValueString.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
		if (parts.Length == 0)
		{
			yield return "None";
			yield break;
		}

		foreach (string part in parts)
		{
			yield return part;
		}
	}

	private FilterGroupVM CreateGroup(string name, Dictionary<string, int> counts)
	{
		FilterGroupVM group = new(name);

		// Sort the filters descending by count frequency
		foreach (KeyValuePair<string, int> kvp in counts.OrderByDescending(x => x.Value))
		{
			FilterItemVM item = new(kvp.Key, kvp.Value)
			{
				ActionToTrigger = ApplyFilter
			};
			group.Filters.Add(item);
		}
		return group;
	}

	private void ApplyFilter()
	{
		if (_isBulkUpdatingFilters)
		{
			return; // Suppress execution during a bulk select/deselect operation
		}

		FilteredServices.Clear();

		// Retrieve the allowed items currently toggled active
		HashSet<string> allowedCompanies = GetAllowed(FilterGroups.FirstOrDefault(g => string.Equals(g.GroupName, "Company", StringComparison.OrdinalIgnoreCase)));
		HashSet<string> allowedStatuses = GetAllowed(FilterGroups.FirstOrDefault(g => string.Equals(g.GroupName, "Status", StringComparison.OrdinalIgnoreCase)));
		HashSet<string> allowedStartTypes = GetAllowed(FilterGroups.FirstOrDefault(g => string.Equals(g.GroupName, "Start Type", StringComparison.OrdinalIgnoreCase)));
		HashSet<string> allowedServiceTypes = GetAllowed(FilterGroups.FirstOrDefault(g => string.Equals(g.GroupName, "Service Type", StringComparison.OrdinalIgnoreCase)));
		HashSet<string> allowedErrorControls = GetAllowed(FilterGroups.FirstOrDefault(g => string.Equals(g.GroupName, "Error Control", StringComparison.OrdinalIgnoreCase)));
		HashSet<string> allowedLaunchProtected = GetAllowed(FilterGroups.FirstOrDefault(g => string.Equals(g.GroupName, "Launch Protected", StringComparison.OrdinalIgnoreCase)));
		HashSet<string> allowedServiceFlags = GetAllowed(FilterGroups.FirstOrDefault(g => string.Equals(g.GroupName, "Service Flags", StringComparison.OrdinalIgnoreCase)));

		string query = SearchText?.Trim() ?? string.Empty;
		bool hasQuery = !string.IsNullOrWhiteSpace(query);

		List<ServiceItemViewModel> results = new(AllServices.Count);

		Dictionary<string, Dictionary<string, int>> dynamicCounts = new(StringComparer.OrdinalIgnoreCase);
		if (IsDynamicCountEnabled)
		{
			foreach (FilterGroupVM group in FilterGroups)
			{
				dynamicCounts[group.GroupName] = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
				foreach (FilterItemVM filter in group.Filters)
				{
					dynamicCounts[group.GroupName][filter.Name] = 0;
				}
			}
		}

		foreach (ServiceItemViewModel s in AllServices)
		{
			// Text Search Check
			bool passSearch = true;
			if (hasQuery)
			{
				passSearch = s.Item.ServiceName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
							 s.Item.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
							 s.Item.Description.Contains(query, StringComparison.OrdinalIgnoreCase);
			}

			string companyCategory = string.Equals(s.Item.PeCompany, "Microsoft Corporation", StringComparison.OrdinalIgnoreCase) ? "Microsoft Corporation" : "Other";
			bool passCompany = allowedCompanies.Contains(companyCategory);

			string statusCat = string.IsNullOrWhiteSpace(s.Item.CurrentState) ? "None" : s.Item.CurrentState.Trim();
			bool passStatus = allowedStatuses.Contains(statusCat);

			string startCat = string.IsNullOrWhiteSpace(s.Item.StartType) ? "None" : s.Item.StartType.Trim();
			bool passStartType = allowedStartTypes.Contains(startCat);

			string errorCat = string.IsNullOrWhiteSpace(s.Item.ErrorControl) ? "None" : s.Item.ErrorControl.Trim();
			bool passError = allowedErrorControls.Contains(errorCat);

			string launchCat = string.IsNullOrWhiteSpace(s.Item.LaunchProtected) ? "None" : s.Item.LaunchProtected.Trim();
			bool passLaunch = allowedLaunchProtected.Contains(launchCat);

			string flagsCat = string.IsNullOrWhiteSpace(s.Item.ServiceFlags) ? "None" : s.Item.ServiceFlags.Trim();
			bool passFlags = allowedServiceFlags.Contains(flagsCat);

			bool passServiceType = HasAnyIntersection(s.Item.ServiceType, allowedServiceTypes);

			// Add to final UI results if it passes all filters
			if (passSearch && passCompany && passStatus && passStartType && passError && passLaunch && passFlags && passServiceType)
			{
				results.Add(s);
			}

			// Accurate mathematical Faceted Counts Calculation
			// An item contributes to a specific category's count only if it passes the filters for every other category
			if (IsDynamicCountEnabled)
			{
				if (passSearch && passStatus && passStartType && passError && passLaunch && passFlags && passServiceType)
				{
					if (dynamicCounts["Company"].TryGetValue(companyCategory, out int value))
					{
						dynamicCounts["Company"][companyCategory] = ++value;
					}
				}

				if (passSearch && passCompany && passStartType && passError && passLaunch && passFlags && passServiceType)
				{
					if (dynamicCounts["Status"].TryGetValue(statusCat, out int value))
					{
						dynamicCounts["Status"][statusCat] = ++value;
					}
				}

				if (passSearch && passCompany && passStatus && passError && passLaunch && passFlags && passServiceType)
				{
					if (dynamicCounts["Start Type"].TryGetValue(startCat, out int value))
					{
						dynamicCounts["Start Type"][startCat] = ++value;
					}
				}

				if (passSearch && passCompany && passStatus && passStartType && passLaunch && passFlags && passServiceType)
				{
					if (dynamicCounts["Error Control"].TryGetValue(errorCat, out int value))
					{
						dynamicCounts["Error Control"][errorCat] = ++value;
					}
				}

				if (passSearch && passCompany && passStatus && passStartType && passError && passFlags && passServiceType)
				{
					if (dynamicCounts["Launch Protected"].TryGetValue(launchCat, out int value))
					{
						dynamicCounts["Launch Protected"][launchCat] = ++value;
					}
				}

				if (passSearch && passCompany && passStatus && passStartType && passError && passLaunch && passServiceType)
				{
					if (dynamicCounts["Service Flags"].TryGetValue(flagsCat, out int value))
					{
						dynamicCounts["Service Flags"][flagsCat] = ++value;
					}
				}

				if (passSearch && passCompany && passStatus && passStartType && passError && passLaunch && passFlags)
				{
					foreach (string part in GetMultiValues(s.Item.ServiceType))
					{
						if (dynamicCounts["Service Type"].TryGetValue(part, out int value))
						{
							dynamicCounts["Service Type"][part] = ++value;
						}
					}
				}
			}
		}

		// Apply final counts to models
		if (IsDynamicCountEnabled)
		{
			foreach (FilterGroupVM group in FilterGroups)
			{
				foreach (FilterItemVM filter in group.Filters)
				{
					filter.CurrentCount = dynamicCounts[group.GroupName][filter.Name];
				}
			}
		}
		else
		{
			// Revert to Original counts
			foreach (FilterGroupVM group in FilterGroups)
			{
				foreach (FilterItemVM filter in group.Filters)
				{
					filter.CurrentCount = filter.OriginalCount;
				}
			}
		}

		List<ServiceItemViewModel> sortedResults = SortServices(results);

		FilteredServices.AddRange(sortedResults);
		TotalServices = FilteredServices.Count;
	}

	private static HashSet<string> GetAllowed(FilterGroupVM? group)
	{
		HashSet<string> allowed = new(StringComparer.OrdinalIgnoreCase);
		if (group is null) return allowed;

		foreach (FilterItemVM filter in group.Filters)
		{
			if (filter.IsChecked)
				_ = allowed.Add(filter.Name);
		}
		return allowed;
	}

	private static bool HasAnyIntersection(string multiValueString, HashSet<string> allowed)
	{
		if (string.IsNullOrWhiteSpace(multiValueString))
		{
			return allowed.Contains("None");
		}

		string[] parts = multiValueString.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
		if (parts.Length == 0)
		{
			return allowed.Contains("None");
		}

		foreach (string part in parts)
		{
			if (allowed.Contains(part)) return true;
		}

		return false;
	}

	internal async void CopyItem_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is not null)
		{
			string textToCopy = button.Tag.ToString() ?? string.Empty;
			if (!string.IsNullOrWhiteSpace(textToCopy))
			{
				Windows.ApplicationModel.DataTransfer.DataPackage package = new();
				package.SetText(textToCopy);
				Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(package);

				// Visually animate the button to show a checkmark, then revert back smoothly
				if (button.Content is FontIcon icon)
				{
					button.IsEnabled = false;
					string originalGlyph = icon.Glyph;

					try
					{
						// Smooth fade out
						while (icon.Opacity > 0.1)
						{
							if (!button.IsLoaded) return;
							icon.Opacity -= 0.15;
							await Task.Delay(10);
						}

						icon.Glyph = "\xE8FB"; // Accept/Checkmark Unicode Glyph
						icon.Foreground = ServiceItemViewModel._runningBrush;

						// Smooth fade in
						while (icon.Opacity < 1.0)
						{
							if (!button.IsLoaded) return;
							icon.Opacity += 0.15;
							await Task.Delay(10);
						}

						icon.Opacity = 1.0;
						await Task.Delay(1500); // Wait for 1.5 seconds

						if (!button.IsLoaded) return;

						// Smooth fade out
						while (icon.Opacity > 0.1)
						{
							if (!button.IsLoaded) return;
							icon.Opacity -= 0.15;
							await Task.Delay(10);
						}

						// Revert to original
						icon.Glyph = originalGlyph;
						icon.ClearValue(IconElement.ForegroundProperty); // Revert to styled foreground

						// Smooth fade in
						while (icon.Opacity < 1.0)
						{
							if (!button.IsLoaded) return;
							icon.Opacity += 0.15;
							await Task.Delay(10);
						}

						icon.Opacity = 1.0;
					}
					catch (COMException)
					{
						// Catch if the element gets destroyed mid-animation from the Visual Tree
					}
					finally
					{
						if (button.IsLoaded)
						{
							button.IsEnabled = true;
						}
					}
				}
			}
		}
	}


	private bool ModifyServiceConfig(string serviceName, uint serviceType, uint startType, uint errorControl)
	{
		IntPtr scManager = NativeMethods.OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
		if (scManager == IntPtr.Zero) return false;
		try
		{
			IntPtr hService = NativeMethods.OpenServiceW(scManager, serviceName, NativeMethods.SERVICE_CHANGE_CONFIG);
			if (hService == IntPtr.Zero) return false;
			try
			{
				return NativeMethods.ChangeServiceConfigW(hService, serviceType, startType, errorControl, null, null, IntPtr.Zero, IntPtr.Zero, null, null, null);
			}
			finally { _ = NativeMethods.CloseServiceHandle(hService); }
		}
		finally { _ = NativeMethods.CloseServiceHandle(scManager); }
	}

	private unsafe bool SetDelayedAutoStart(string serviceName, bool isDelayed)
	{
		IntPtr scManager = NativeMethods.OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
		if (scManager == IntPtr.Zero) return false;
		try
		{
			IntPtr hService = NativeMethods.OpenServiceW(scManager, serviceName, NativeMethods.SERVICE_CHANGE_CONFIG);
			if (hService == IntPtr.Zero) return false;
			try
			{
				SERVICE_DELAYED_AUTO_START_INFO info = new() { fDelayedAutostart = isDelayed ? 1 : 0 };
				return NativeMethods.ChangeServiceConfig2W(hService, 3, (IntPtr)(&info)); // 3 = SERVICE_CONFIG_DELAYED_AUTO_START_INFO
			}
			finally { _ = NativeMethods.CloseServiceHandle(hService); }
		}
		finally { _ = NativeMethods.CloseServiceHandle(scManager); }
	}

	private unsafe bool SetLaunchProtected(string serviceName, uint launchProtected)
	{
		IntPtr scManager = NativeMethods.OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
		if (scManager == IntPtr.Zero) return false;
		try
		{
			IntPtr hService = NativeMethods.OpenServiceW(scManager, serviceName, NativeMethods.SERVICE_CHANGE_CONFIG);
			if (hService == IntPtr.Zero) return false;
			try
			{
				SERVICE_LAUNCH_PROTECTED_INFO info = new() { dwLaunchProtected = launchProtected };
				return NativeMethods.ChangeServiceConfig2W(hService, 12, (IntPtr)(&info)); // 12 = SERVICE_CONFIG_LAUNCH_PROTECTED
			}
			finally { _ = NativeMethods.CloseServiceHandle(hService); }
		}
		finally { _ = NativeMethods.CloseServiceHandle(scManager); }
	}

	internal async void SaveStartType_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is ServiceItemViewModel svm)
		{
			await Task.Run(() =>
			{
				uint newStartType = 0;
				bool isDelayed = false;
				switch (svm.SelectedStartTypeIndex)
				{
					case 0: newStartType = 0; break;
					case 1: newStartType = 1; break;
					case 2: newStartType = 2; break;
					case 3: newStartType = 3; break;
					case 4: newStartType = 4; break;
					case 5: newStartType = 2; isDelayed = true; break;
					default: break;
				}

				uint currentStartType = 0;
				switch (svm.OriginalStartTypeIndex)
				{
					case 0: currentStartType = 0; break;
					case 1: currentStartType = 1; break;
					case 2: currentStartType = 2; break;
					case 3: currentStartType = 3; break;
					case 4: currentStartType = 4; break;
					case 5: currentStartType = 2; break;
					default: break;
				}

				bool success = true;

				// Only call ModifyServiceConfig if the underlying base Start Type is actually changing.
				if (currentStartType != newStartType)
				{
					success = ModifyServiceConfig(svm.Item.ServiceName, NativeMethods.SERVICE_NO_CHANGE, newStartType, NativeMethods.SERVICE_NO_CHANGE);
				}

				// Only handle delayed autostart configurations if the selected type is genuinely Auto Start
				if (success && newStartType == 2)
				{
					bool delaySuccess = SetDelayedAutoStart(svm.Item.ServiceName, isDelayed);

					if (!delaySuccess)
					{
						success = false;
					}
				}

				if (success)
				{
					_ = Dispatcher.TryEnqueue(() =>
					{
						svm.CommitStartTypeChange();
						MainInfoBar.WriteSuccess($"Successfully updated Start Type for {svm.Item.ServiceName}.");
					});
				}
				else
				{
					int error = Marshal.GetLastPInvokeError();
					_ = Dispatcher.TryEnqueue(() => MainInfoBar.WriteWarning($"Failed to update Start Type. Error Code: {error}"));
				}
			});
		}
	}

	internal async void SaveServiceType_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is ServiceItemViewModel svm)
		{
			using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = "Changing Service Type",
				Content = new TextBlock
				{
					Text = $"Are you sure you want to change the Service Type for '{svm.Item.ServiceName}'?\n\nChanging this value to something you're not sure about can lead to boot failure on the next reboot if it's a critical service.\n\nAre you absolutely sure you want to proceed?",
					TextWrapping = TextWrapping.Wrap
				},
				PrimaryButtonText = "Yes, I'm Sure.",
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Close,
				Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"],
				FlowDirection = Enum.Parse<FlowDirection>(AppSettings.ApplicationGlobalFlowDirection)
			};

			ContentDialogResult result = await dialog.ShowAsync();

			// If the user clicks Close/Cancel OR has selected "Unknown / Custom", revert the selection and exit
			if (result != ContentDialogResult.Primary || svm.SelectedServiceTypeIndex == 8)
			{
				svm.SelectedServiceTypeIndex = svm.OriginalServiceTypeIndex;
				return;
			}

			await Task.Run(() =>
			{
				uint newServiceType = svm.SelectedServiceTypeIndex switch
				{
					0 => 0x1,
					1 => 0x2,
					2 => 0x10,
					3 => 0x20,
					4 => 0x40,
					5 => 0x80,
					6 => 0x110,
					7 => 0x120,
					_ => NativeMethods.SERVICE_NO_CHANGE
				};

				if (ModifyServiceConfig(svm.Item.ServiceName, newServiceType, NativeMethods.SERVICE_NO_CHANGE, NativeMethods.SERVICE_NO_CHANGE))
				{
					_ = Dispatcher.TryEnqueue(() =>
					{
						svm.CommitServiceTypeChange();
						MainInfoBar.WriteSuccess($"Successfully updated Service Type for {svm.Item.ServiceName}.");
					});
				}
				else
				{
					int error = Marshal.GetLastPInvokeError();
					_ = Dispatcher.TryEnqueue(() => MainInfoBar.WriteWarning($"Failed to update Service Type. Error Code: {error}"));
				}
			});
		}
	}

	internal async void SaveErrorControl_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is ServiceItemViewModel svm)
		{
			await Task.Run(() =>
			{
				uint newErrorControl = (uint)svm.SelectedErrorControlIndex;
				if (ModifyServiceConfig(svm.Item.ServiceName, NativeMethods.SERVICE_NO_CHANGE, NativeMethods.SERVICE_NO_CHANGE, newErrorControl))
				{
					_ = Dispatcher.TryEnqueue(() =>
					{
						svm.CommitErrorControlChange();
						MainInfoBar.WriteSuccess($"Successfully updated Error Control for {svm.Item.ServiceName}.");
					});
				}
				else
				{
					int error = Marshal.GetLastPInvokeError();
					_ = Dispatcher.TryEnqueue(() => MainInfoBar.WriteWarning($"Failed to update Error Control. Error Code: {error}"));
				}
			});
		}
	}

	internal async void SaveLaunchProtected_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is ServiceItemViewModel svm)
		{
			uint newLaunchProtected = (uint)svm.SelectedLaunchProtectedIndex;

			using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = "Changing Launch Protected Mode",
				Content = new TextBlock
				{
					Text = $"Are you sure you want to change the Launch Protected mode for '{svm.Item.ServiceName}'?\n\nIf the service's executables and dependencies are not signed with the appropriate Microsoft certificate, the Windows kernel will block them from loading, which may cause the service to fail, crash, or break system functionality.\n\nWARNING: Once set to a protected mode, you will NOT be able to revert this change using this app due to Windows security boundaries. You will have to manually edit the Registry and reboot to restore it.\n\nAre you absolutely sure you want to proceed?",
					TextWrapping = TextWrapping.Wrap
				},
				PrimaryButtonText = "Yes, I'm Sure.",
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Close,
				Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"],
				FlowDirection = Enum.Parse<FlowDirection>(AppSettings.ApplicationGlobalFlowDirection)
			};

			ContentDialogResult result = await dialog.ShowAsync();

			// If the user clicks Close/Cancel, revert the selection and exit
			if (result != ContentDialogResult.Primary)
			{
				svm.SelectedLaunchProtectedIndex = svm.OriginalLaunchProtectedIndex;
				return;
			}

			// Execute the change since the user explicitly proceeded
			await Task.Run(() =>
			{
				if (SetLaunchProtected(svm.Item.ServiceName, newLaunchProtected))
				{
					_ = Dispatcher.TryEnqueue(() =>
					{
						svm.CommitLaunchProtectedChange();
						MainInfoBar.WriteSuccess($"Successfully updated Launch Protected for {svm.Item.ServiceName}.");
					});
				}
				else
				{
					int error = Marshal.GetLastPInvokeError();
					_ = Dispatcher.TryEnqueue(() => MainInfoBar.WriteWarning($"Failed to update Launch Protected. Error Code: {error}"));
				}
			});
		}
	}

	private bool ChangeServiceState(ServiceItemViewModel svm, uint controlCode)
	{
		string serviceName = svm.Item.ServiceName;
		IntPtr scManager = NativeMethods.OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
		if (scManager == IntPtr.Zero)
		{
			_ = Dispatcher.TryEnqueue(() => MainInfoBar.WriteWarning("Failed to open Service Control Manager."));
			return false;
		}

		try
		{
			uint access = controlCode == 0 ? NativeMethods.SERVICE_START : NativeMethods.SERVICE_STOP;
			if (controlCode == NativeMethods.SERVICE_CONTROL_PAUSE || controlCode == NativeMethods.SERVICE_CONTROL_CONTINUE)
				access = NativeMethods.SERVICE_PAUSE_CONTINUE;

			IntPtr hService = NativeMethods.OpenServiceW(scManager, serviceName, access | NativeMethods.SERVICE_QUERY_STATUS);
			if (hService == IntPtr.Zero)
			{
				int error = Marshal.GetLastPInvokeError();
				_ = Dispatcher.TryEnqueue(() => MainInfoBar.WriteWarning($"Failed to open service {serviceName}. Error Code: {error}"));
				return false;
			}

			try
			{
				bool success;
				if (controlCode == 0) // Start
				{
					success = NativeMethods.StartServiceW(hService, 0, IntPtr.Zero);
				}
				else
				{
					SERVICE_STATUS status = new();
					success = NativeMethods.ControlService(hService, controlCode, ref status);
				}

				if (success)
				{
					string action = controlCode == 0 ? "started" : controlCode == NativeMethods.SERVICE_CONTROL_STOP ? "stopped" : controlCode == NativeMethods.SERVICE_CONTROL_PAUSE ? "paused" : "resumed";
					_ = Dispatcher.TryEnqueue(() => MainInfoBar.WriteSuccess($"Successfully {action} service {serviceName}."));
					return true;
				}
				else
				{
					int error = Marshal.GetLastPInvokeError();
					_ = Dispatcher.TryEnqueue(() => MainInfoBar.WriteWarning($"Failed to modify state for {serviceName}. Error Code: {error}"));
					return false;
				}
			}
			finally { _ = NativeMethods.CloseServiceHandle(hService); }
		}
		finally { _ = NativeMethods.CloseServiceHandle(scManager); }
	}

	internal async void DeleteService_Click(object sender, RoutedEventArgs e)
	{
		if (sender is MenuFlyoutItem item && item.Tag is ServiceItemViewModel svm)
		{
			using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = "Delete Service",
				Content = new TextBlock
				{
					Text = $"Are you sure you want to completely delete the service '{svm.Item.ServiceName}' ({svm.Item.DisplayName})?\n\nThis action cannot be undone and may cause system instability if a critical service is removed.\n\nAre you absolutely sure you want to proceed?",
					TextWrapping = TextWrapping.Wrap
				},
				PrimaryButtonText = "Delete",
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Close,
				Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"],
				FlowDirection = Enum.Parse<FlowDirection>(AppSettings.ApplicationGlobalFlowDirection)
			};

			ContentDialogResult result = await dialog.ShowAsync();

			if (result == ContentDialogResult.Primary)
			{
				await Task.Run(() =>
				{
					IntPtr scManager = NativeMethods.OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
					if (scManager == IntPtr.Zero)
					{
						_ = Dispatcher.TryEnqueue(() => MainInfoBar.WriteWarning("Failed to open Service Control Manager for deletion."));
						return;
					}

					try
					{
						// Requires DELETE access right (0x00010000)
						IntPtr hService = NativeMethods.OpenServiceW(scManager, svm.Item.ServiceName, NativeMethods.DELETE);
						if (hService == IntPtr.Zero)
						{
							int error = Marshal.GetLastPInvokeError();
							_ = Dispatcher.TryEnqueue(() => MainInfoBar.WriteWarning($"Failed to open service {svm.Item.ServiceName} for deletion. Error Code: {error}"));
							return;
						}

						try
						{
							if (NativeMethods.DeleteService(hService))
							{
								_ = Dispatcher.TryEnqueue(() =>
								{
									MainInfoBar.WriteSuccess($"Successfully deleted service {svm.Item.ServiceName}.");
									RefreshList();
								});
							}
							else
							{
								int error = Marshal.GetLastPInvokeError();
								_ = Dispatcher.TryEnqueue(() => MainInfoBar.WriteWarning($"Failed to delete service {svm.Item.ServiceName}. Error Code: {error}"));
							}
						}
						finally { _ = NativeMethods.CloseServiceHandle(hService); }
					}
					finally { _ = NativeMethods.CloseServiceHandle(scManager); }
				});
			}
		}
	}

	private unsafe static void WaitForServiceState(string serviceName, uint desiredState, int timeoutMs)
	{
		IntPtr scManager = NativeMethods.OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
		if (scManager == IntPtr.Zero) return;
		try
		{
			IntPtr hService = NativeMethods.OpenServiceW(scManager, serviceName, NativeMethods.SERVICE_QUERY_STATUS);
			if (hService == IntPtr.Zero) return;
			try
			{
				int elapsed = 0;
				while (elapsed < timeoutMs)
				{
					SERVICE_STATUS_PROCESS status = new();
					// SC_STATUS_PROCESS_INFO = 0
					if (NativeMethods.QueryServiceStatusEx(hService, 0, (IntPtr)(&status), (uint)sizeof(SERVICE_STATUS_PROCESS), out uint _))
					{
						if (status.dwCurrentState == desiredState) return;
					}
					Thread.Sleep(500);
					elapsed += 500;
				}
			}
			finally { _ = NativeMethods.CloseServiceHandle(hService); }
		}
		finally { _ = NativeMethods.CloseServiceHandle(scManager); }
	}

	private void RefreshList()
	{
		Thread.Sleep(500);
		_ = Dispatcher.TryEnqueue(LoadServices_Click);
	}

	internal async void StartService_Click(object sender, RoutedEventArgs e)
	{
		if (sender is MenuFlyoutItem item && item.Tag is ServiceItemViewModel svm)
			await Task.Run(() => { if (ChangeServiceState(svm, 0)) RefreshList(); });
	}

	internal async void StopService_Click(object sender, RoutedEventArgs e)
	{
		if (sender is MenuFlyoutItem item && item.Tag is ServiceItemViewModel svm)
			await Task.Run(() => { if (ChangeServiceState(svm, NativeMethods.SERVICE_CONTROL_STOP)) RefreshList(); });
	}

	internal async void PauseService_Click(object sender, RoutedEventArgs e)
	{
		if (sender is MenuFlyoutItem item && item.Tag is ServiceItemViewModel svm)
			await Task.Run(() => { if (ChangeServiceState(svm, NativeMethods.SERVICE_CONTROL_PAUSE)) RefreshList(); });
	}

	internal async void ResumeService_Click(object sender, RoutedEventArgs e)
	{
		if (sender is MenuFlyoutItem item && item.Tag is ServiceItemViewModel svm)
			await Task.Run(() => { if (ChangeServiceState(svm, NativeMethods.SERVICE_CONTROL_CONTINUE)) RefreshList(); });
	}

	internal async void RestartService_Click(object sender, RoutedEventArgs e)
	{
		if (sender is MenuFlyoutItem item && item.Tag is ServiceItemViewModel svm)
		{
			await Task.Run(() =>
			{
				if (ChangeServiceState(svm, NativeMethods.SERVICE_CONTROL_STOP))
				{
					// Wait up to 10 seconds for the service to actually reach the stopped state before trying to start
					WaitForServiceState(svm.Item.ServiceName, (uint)SERVICE_STATE.SERVICE_STOPPED, 10000);

					_ = ChangeServiceState(svm, 0); // Discarding bool return value since we refresh regardless
					RefreshList();
				}
			});
		}
	}
}

[System.Runtime.InteropServices.Marshalling.GeneratedComClass]
internal sealed partial class ServiceSecurityInformation :
	ISecurityInformation,
	ISecurityInformation2,
	ISecurityInformation3,
	IEffectivePermission,
	ISecurityObjectTypeInfo,
	IDisposable
{
	private readonly string _serviceName;
	private readonly string _displayName;
	private IntPtr _objectNamePtr;

	internal ServiceSecurityInformation(string serviceName, string displayName)
	{
		_serviceName = serviceName;
		_displayName = string.IsNullOrWhiteSpace(displayName) ? serviceName : displayName;
		_objectNamePtr = Marshal.StringToCoTaskMemUni(_displayName);
	}

	~ServiceSecurityInformation() => ReleaseUnmanagedResources();

	public void Dispose()
	{
		ReleaseUnmanagedResources();
		GC.SuppressFinalize(this);
	}

	private void ReleaseUnmanagedResources()
	{
		if (_objectNamePtr != IntPtr.Zero)
		{
			Marshal.FreeCoTaskMem(_objectNamePtr);
			_objectNamePtr = IntPtr.Zero;
		}
	}

	private static int HRESULT_FROM_WIN32(int x)
	{
		if (x <= 0) return x;
		return unchecked((int)((x & 0x0000FFFF) | (7 << 16) | 0x80000000));
	}

	private static unsafe void EnableSecurityPrivilege()
	{
		if (NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), 0x0020 | 0x0008, out IntPtr hToken))
		{
			try
			{
				if (NativeMethods.LookupPrivilegeValueW(null, "SeSecurityPrivilege", out LUID luid))
				{
					TOKEN_PRIVILEGES tp = new()
					{
						PrivilegeCount = 1,
						Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = 0x00000002 }
					};
					_ = NativeMethods.AdjustTokenPrivileges(hToken, false, ref tp, (uint)sizeof(TOKEN_PRIVILEGES), IntPtr.Zero, IntPtr.Zero);
				}
			}
			finally
			{
				_ = NativeMethods.CloseHandle(hToken);
			}
		}
	}

	public unsafe int GetObjectInformation(SI_OBJECT_INFO* pObjectInfo)
	{
		if (pObjectInfo == null) return unchecked((int)0x80070057);

		pObjectInfo->dwFlags = 0 | 1 | 2 | 0x10 | 0x20000 | 0x00400000;

		pObjectInfo->hInstance = IntPtr.Zero;
		pObjectInfo->pszServerName = IntPtr.Zero;
		pObjectInfo->pszObjectName = _objectNamePtr;
		pObjectInfo->pszPageTitle = _objectNamePtr;
		pObjectInfo->guidObjectType = Guid.Empty;

		return 0; // S_OK
	}

	public unsafe int GetSecurity(uint RequestedInformation, IntPtr* ppSecurityDescriptor, int fDefault)
	{
		if (ppSecurityDescriptor == null) return unchecked((int)0x80070057);
		*ppSecurityDescriptor = IntPtr.Zero;

		EnableSecurityPrivilege();

		IntPtr scManager = NativeMethods.OpenSCManagerW(null, null, 0x0001); // SC_MANAGER_CONNECT

		if (scManager == IntPtr.Zero) return HRESULT_FROM_WIN32(Marshal.GetLastPInvokeError());

		try
		{
			uint access = 0x00020000; // READ_CONTROL
			if ((RequestedInformation & 8) != 0) // SACL_SECURITY_INFORMATION
			{
				access |= 0x01000000; // ACCESS_SYSTEM_SECURITY
			}

			IntPtr hService = NativeMethods.OpenServiceW(scManager, _serviceName, access);
			if (hService == IntPtr.Zero)
			{
				int err = Marshal.GetLastPInvokeError();
				return HRESULT_FROM_WIN32(err);
			}

			try
			{
				int hr = 0;
				_ = NativeMethods.QueryServiceObjectSecurity(hService, RequestedInformation, IntPtr.Zero, 0, out uint bytesNeeded);

				if (bytesNeeded > 0)
				{
					IntPtr localSD = NativeMethods.LocalAlloc(0x0040, bytesNeeded);

					if (localSD != IntPtr.Zero)
					{
						if (!NativeMethods.QueryServiceObjectSecurity(hService, RequestedInformation, localSD, bytesNeeded, out _))
						{
							hr = HRESULT_FROM_WIN32(Marshal.GetLastPInvokeError());
							_ = NativeMethods.LocalFree(localSD);
						}
						else
						{
							*ppSecurityDescriptor = localSD;
						}
					}
					else
					{
						hr = unchecked((int)0x8007000E); // E_OUTOFMEMORY
					}
				}
				else
				{
					hr = HRESULT_FROM_WIN32(Marshal.GetLastPInvokeError());
				}

				return hr;
			}
			finally
			{
				_ = NativeMethods.CloseServiceHandle(hService);
			}
		}
		finally
		{
			_ = NativeMethods.CloseServiceHandle(scManager);
		}
	}

	public int SetSecurity(uint SecurityInformation, IntPtr pSecurityDescriptor)
	{
		EnableSecurityPrivilege();

		IntPtr scManager = NativeMethods.OpenSCManagerW(null, null, 0x0001); // SC_MANAGER_CONNECT

		if (scManager == IntPtr.Zero) return HRESULT_FROM_WIN32(Marshal.GetLastPInvokeError());

		try
		{
			uint access = 0;
			if ((SecurityInformation & 1) != 0) access |= 0x00080000; // WRITE_OWNER
			if ((SecurityInformation & 2) != 0) access |= 0x00080000; // WRITE_OWNER
			if ((SecurityInformation & 4) != 0) access |= 0x00040000; // WRITE_DAC
			if ((SecurityInformation & 8) != 0) access |= 0x01000000; // ACCESS_SYSTEM_SECURITY

			IntPtr hService = NativeMethods.OpenServiceW(scManager, _serviceName, access);
			if (hService == IntPtr.Zero)
			{
				int err = Marshal.GetLastPInvokeError();
				return HRESULT_FROM_WIN32(err);
			}

			try
			{
				int hr = 0;
				if (!NativeMethods.SetServiceObjectSecurity(hService, SecurityInformation, pSecurityDescriptor))
				{
					hr = HRESULT_FROM_WIN32(Marshal.GetLastPInvokeError());
				}

				return hr;
			}
			finally
			{
				_ = NativeMethods.CloseServiceHandle(hService);
			}
		}
		finally
		{
			_ = NativeMethods.CloseServiceHandle(scManager);
		}
	}

	private static IntPtr _accessRightsPtr = IntPtr.Zero;
	private static readonly Lock _accessRightsLock = new();

	public unsafe int GetAccessRights(Guid* pguidObjectType, uint dwFlags, IntPtr* ppAccess, uint* pcAccesses, uint* piDefaultAccess)
	{
		if (ppAccess == null || pcAccesses == null || piDefaultAccess == null) return unchecked((int)0x80070057);

		if (_accessRightsPtr == IntPtr.Zero)
		{
			lock (_accessRightsLock)
			{
				if (_accessRightsPtr == IntPtr.Zero)
				{
					uint accessFlags = 0x00030000u; // SI_ACCESS_SPECIFIC | SI_ACCESS_GENERAL

					(uint mask, string name, uint flags)[] accesses =
					[
						(0xF01FFu, "Full Control", accessFlags),
						(0x20000u, "Read Control", accessFlags),
						(0x40000u, "Write DAC", accessFlags),
						(0x80000u, "Write Owner", accessFlags),
						(0x0001u, "Query Config", accessFlags),
						(0x0002u, "Change Config", accessFlags),
						(0x0004u, "Query Status", accessFlags),
						(0x0008u, "Enumerate Dependents", accessFlags),
						(0x0010u, "Start", accessFlags),
						(0x0020u, "Stop", accessFlags),
						(0x0040u, "Pause/Continue", accessFlags),
						(0x0080u, "Interrogate", accessFlags),
						(0x0100u, "User-Defined Control", accessFlags)
					];

					int structSize = sizeof(SI_ACCESS);
					IntPtr memory = Marshal.AllocCoTaskMem(structSize * accesses.Length);
					SI_ACCESS* ptr = (SI_ACCESS*)memory;

					for (int i = 0; i < accesses.Length; i++)
					{
						ptr[i].pguid = IntPtr.Zero;
						ptr[i].mask = accesses[i].mask;
						ptr[i].pszName = Marshal.StringToCoTaskMemUni(accesses[i].name);
						ptr[i].dwFlags = accesses[i].flags;
					}

					_accessRightsPtr = memory;
				}
			}
		}

		*ppAccess = _accessRightsPtr;
		*pcAccesses = 13;
		*piDefaultAccess = 0;
		return 0; // S_OK
	}

	public unsafe int MapGeneric(Guid* pguidObjectType, byte* pAceFlags, uint* pMask)
	{
		if (pMask == null) return unchecked((int)0x80070057);

		uint GENERIC_READ = 0x80000000;
		uint GENERIC_WRITE = 0x40000000;
		uint GENERIC_EXECUTE = 0x20000000;
		uint GENERIC_ALL = 0x10000000;

		if ((*pMask & GENERIC_READ) != 0)
		{
			*pMask &= ~GENERIC_READ;
			*pMask |= 0x20000 | 0x0001 | 0x0004 | 0x0080 | 0x0008;
		}
		if ((*pMask & GENERIC_WRITE) != 0)
		{
			*pMask &= ~GENERIC_WRITE;
			*pMask |= 0x20000 | 0x0002;
		}
		if ((*pMask & GENERIC_EXECUTE) != 0)
		{
			*pMask &= ~GENERIC_EXECUTE;
			*pMask |= 0x20000 | 0x0010 | 0x0020 | 0x0040 | 0x0100;
		}
		if ((*pMask & GENERIC_ALL) != 0)
		{
			*pMask &= ~GENERIC_ALL;
			*pMask |= 0xF01FF;
		}

		return 0; // S_OK
	}

	private static IntPtr _inheritTypesPtr = IntPtr.Zero;

	public unsafe int GetInheritTypes(IntPtr* ppInheritTypes, uint* pcInheritTypes)
	{
		if (ppInheritTypes == null || pcInheritTypes == null) return unchecked((int)0x80070057);

		if (_inheritTypesPtr == IntPtr.Zero)
		{
			lock (_accessRightsLock)
			{
				if (_inheritTypesPtr == IntPtr.Zero)
				{
					// Tricking aclui.dll to lie to the dialog and treat the service as a folder so it displays the Effective Access and Advanced permission tabs.
					int structSize = sizeof(SI_INHERIT_TYPE);
					IntPtr memory = Marshal.AllocCoTaskMem(structSize * 3);
					SI_INHERIT_TYPE* ptr = (SI_INHERIT_TYPE*)memory;

					ptr[0].pguid = IntPtr.Zero;
					ptr[0].dwFlags = 0;
					ptr[0].pszName = Marshal.StringToCoTaskMemUni("This folder only");

					ptr[1].pguid = IntPtr.Zero;
					ptr[1].dwFlags = 3; // CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
					ptr[1].pszName = Marshal.StringToCoTaskMemUni("This folder, subfolders and files");

					ptr[2].pguid = IntPtr.Zero;
					ptr[2].dwFlags = 11; // INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
					ptr[2].pszName = Marshal.StringToCoTaskMemUni("Subfolders and files only");

					_inheritTypesPtr = memory;
				}
			}
		}

		*ppInheritTypes = _inheritTypesPtr;
		*pcInheritTypes = 3;
		return 0; // S_OK
	}

	public int PropertySheetPageCallback(IntPtr hwnd, uint uMsg, uint uPage) => unchecked((int)0x80004001); // E_NOTIMPL

	public int IsDaclCanonical(IntPtr pDacl) => 1; // 1 = TRUE

	public int LookupSids(uint cSids, IntPtr rgpSids, out IntPtr ppdo)
	{
		ppdo = IntPtr.Zero;
		return unchecked((int)0x80004001); // E_NOTIMPL
	}

	public unsafe int GetFullResourceName(IntPtr* ppszResourceName)
	{
		if (ppszResourceName == null) return unchecked((int)0x80070057);

		string resourceName = $"Service: {_displayName} ({_serviceName})";
		int byteCount = (resourceName.Length + 1) * 2;
		IntPtr ptr = NativeMethods.LocalAlloc(0x0040, (nuint)byteCount); // LMEM_ZEROINIT

		if (ptr == IntPtr.Zero)
		{
			*ppszResourceName = IntPtr.Zero;
			return unchecked((int)0x8007000E); // E_OUTOFMEMORY
		}

		Marshal.Copy(resourceName.ToCharArray(), 0, ptr, resourceName.Length);
		*ppszResourceName = ptr;
		return 0; // S_OK
	}

	public int OpenElevatedEditor(IntPtr hWnd, uint uPage) => unchecked((int)0x80004001); // E_NOTIMPL	

	public unsafe int GetEffectivePermission(
		Guid* pguidObjectType, IntPtr pUserSid, IntPtr pszServerName, IntPtr pSD,
		IntPtr* ppObjectTypeList, uint* pcObjectTypeListLength,
		IntPtr* ppGrantedAccessList, uint* pcGrantedAccessListLength)
	{
		if (ppObjectTypeList == null || pcObjectTypeListLength == null || ppGrantedAccessList == null || pcGrantedAccessListLength == null)
			return unchecked((int)0x80070057);

		*ppObjectTypeList = IntPtr.Zero;
		*pcObjectTypeListLength = 0;
		*ppGrantedAccessList = IntPtr.Zero;
		*pcGrantedAccessListLength = 0;

		if (pSD == IntPtr.Zero) return unchecked((int)0x80070057);

		if (NativeMethods.GetSecurityDescriptorDacl(pSD, out int daclPresent, out IntPtr dacl, out int daclDefaulted) && daclPresent != 0 && dacl != IntPtr.Zero)
		{
			TRUSTEE_W trustee = new()
			{
				pMultipleTrustee = IntPtr.Zero,
				MultipleTrusteeOperation = 0, // NO_MULTIPLE_TRUSTEE
				TrusteeForm = 0, // TRUSTEE_IS_SID
				TrusteeType = 1, // TRUSTEE_IS_USER
				ptstrName = pUserSid
			};

			int result = NativeMethods.GetEffectiveRightsFromAclW(dacl, ref trustee, out uint accessRights);
			if (result == 0) // ERROR_SUCCESS
			{
				IntPtr pObjectTypeList = NativeMethods.LocalAlloc(0x0040, (nuint)sizeof(OBJECT_TYPE_LIST));
				if (pObjectTypeList == IntPtr.Zero) return unchecked((int)0x8007000E);

				OBJECT_TYPE_LIST otl = new() { Level = 0, Sbz = 0, ObjectType = IntPtr.Zero };
				*(OBJECT_TYPE_LIST*)pObjectTypeList = otl;

				IntPtr pAccess = NativeMethods.LocalAlloc(0x0040, 4);
				if (pAccess == IntPtr.Zero)
				{
					_ = NativeMethods.LocalFree(pObjectTypeList);
					return unchecked((int)0x8007000E);
				}
				Marshal.WriteInt32(pAccess, (int)accessRights);

				*ppObjectTypeList = pObjectTypeList;
				*pcObjectTypeListLength = 1;
				*ppGrantedAccessList = pAccess;
				*pcGrantedAccessListLength = 1;

				return 0; // S_OK
			}
			return HRESULT_FROM_WIN32(result);
		}

		return unchecked((int)0x80004005); // E_FAIL
	}

	// Return 5023 because the Service is not a File type.
	public unsafe int GetInheritSource(uint si, IntPtr pACL, IntPtr* ppInheritArray) => HRESULT_FROM_WIN32(5023);

}
