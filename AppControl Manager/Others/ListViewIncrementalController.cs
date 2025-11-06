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
using System.Collections.Specialized;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.IncrementalCollection;
using AppControlManager.IntelGathering;
using AppControlManager.ViewModels;
using CommunityToolkit.WinUI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.Others;

internal sealed partial class ListViewIncrementalController(
	ListViewHelper.ListViewsRegistry registryKey,
	Action<int, double> applyWidthCallback,
	Func<IReadOnlyList<double>> getCurrentWidthsCallback,
	string[] headerResourceKeys,
	string[] columnPropertyKeys)
	: ViewModelBase, IDisposable
{

	#region Items that would be in ViewModel class usually.

	/// <summary>
	/// Used as the source for the ListView's displayed data.
	/// </summary>
	internal GenericIncrementalCollection<FileIdentityIncrementalSource, FileIdentity>? ObservableSource;

	/// <summary>
	/// Backing full source for the data.
	/// </summary>
	internal readonly List<FileIdentity> FullSource = [];

	/// <summary>
	/// Count of the <see cref="FullSource"/> bound to the UI.
	/// </summary>
	internal int FullSourceCount => FullSource.Count;

	/// <summary>
	/// Raise PropertyChanged so x:Bind updates the Total chip.
	/// </summary>
	internal void NotifyFullSourceChanged() => OnPropertyChanged(nameof(FullSourceCount));

	/// <summary>
	/// De-selects all of the displayed rows on the ListView
	/// </summary>
	internal void DeSelectAll_Click()
	{
		ListViewRef?.SelectedItems.Clear();
	}

	/// <summary>
	/// Selects all of the displayed rows on the ListView
	/// </summary>
	internal void SelectAll_Click()
	{
		if (ListViewRef is null) return;
		if (ObservableSource is null) return;

		ListViewHelper.SelectAll(ListViewRef, ObservableSource);
	}

	/// <summary>
	/// Event handler for the Clear Data button
	/// </summary>
	internal async void ClearDataButton_Click()
	{
		if (ObservableSource is null) return;

		await ObservableSource.ReplaceAllExclusiveAsync(Array.Empty<FileIdentity>());

		// Clear the backing full source list as well
		FullSource.Clear();

		NotifyFullSourceChanged();

		// Recompute column widths (header-only now)
		RecalculateVisibleColumnWidths();
	}

	#endregion

	/// <summary>
	/// Sorting state reused across user interactions
	/// </summary>
	private readonly ListViewHelper.SortState _sortState = new();

	// Debounce timer for width recalculation
	// Created lazily; used to coalesce frequent scroll/realization changes into a single sizing pass.
	private DispatcherQueueTimer? _recalcTimer;

	// References to the ListView and its ScrollViewer that this controller works with.
	private ScrollViewer? ScrollViewerRef;
	private ListView? ListViewRef;

	// Column width change threshold (avoid micro layout churn)
	// Only apply a width change when the delta exceeds this threshold to keep layout stable.
	private const double ColumnWidthUpdateThreshold = 0.5;

	// Look-ahead row count for proactive width fit while scrolling
	// We measure a small buffer before/after visible rows to pre-fit widths and reduce visible pops.
	private const int LookAheadRowCount = 10;

	// Search cache (to re-apply after sorts if needed)
	private string? _lastSearchTerm;

	// Track per-registry key transitions and OFF-mode one-time calculation across navigations.
	// Related to App Setting that defines whether auto-resizing is enabled or disabled.
	// These static dictionaries persist across controller instances (pages).
	private static readonly Dictionary<ListViewHelper.ListViewsRegistry, bool> s_lastAutoResizeState = new();
	private static readonly Dictionary<ListViewHelper.ListViewsRegistry, bool> s_offModeFullCalcDone = new();

	/// <summary>
	/// Debounce for search to avoid running a heavy filter on every keystroke
	/// </summary>
	private DispatcherQueueTimer? _searchDebounceTimer;

	/// <summary>
	/// Holds the latest search term pending execution
	/// </summary>
	private string? _pendingSearchTerm;

	/// <summary>
	/// Re-run after navigation (ListView Loaded event). Retries hook until ListView + ScrollViewer are registered.
	/// </summary>
	internal void ListView_Loaded(object sender, RoutedEventArgs e)
	{
		// Get the ListView instance from the Loaded event's sender.
		ListViewRef = (ListView)sender;

		ScrollViewerRef = ListViewRef.FindScrollViewer();

		if (ObservableSource is null) return;

		// Attach scroll + realization handlers so we can debounce width recalcs during user interaction/virtualization.
		ScrollViewerRef?.ViewChanged += ScrollViewer_ViewChanged;

		// Attach collection changed so that inserts/removes trigger recalcs + count updates.
		ObservableSource.CollectionChanged += Collection_CollectionChanged;

		// Handle ON→OFF or OFF→ON transitions at page entry (per registry key).
		HandleAutoResizeTransitionOnEntry();

		// Initial widths (headers only). As items realize later, debounced passes will refine widths.
		RecalculateVisibleColumnWidths();
	}

	/// <summary>
	/// Update the bound observable collection if the VM replaces it.
	/// </summary>
	internal void UpdateCollection(GenericIncrementalCollection<FileIdentityIncrementalSource, FileIdentity> newCollection)
	{
		// Capture old reference (may be null on first assignment).
		GenericIncrementalCollection<FileIdentityIncrementalSource, FileIdentity>? old = ObservableSource;

		// Detach from the old collection first (if any) so we don't get duplicate handlers.
		old?.CollectionChanged -= Collection_CollectionChanged;

		// Swap to the new collection (updates binding).
		ObservableSource = newCollection;

		// Attach to the new collection so the controller continues to receive change notifications.
		ObservableSource.CollectionChanged += Collection_CollectionChanged;

		// Re-apply the last search term if any, to maintain the user's filter when the collection instance switches.
		if (!string.IsNullOrWhiteSpace(_lastSearchTerm))
		{
			ApplySearch(_lastSearchTerm);
		}

		// Force widths re-evaluation (headers only or newly realized rows) after collection swap.
		RecalculateVisibleColumnWidths();

		// Now that binding points to the new instance, dispose the old incremental collection (if any).
		if (old is IDisposable disposableOld)
		{
			try { disposableOld.Dispose(); } catch { }
		}
	}

	/// <summary>
	/// Apply search/filter semantics with horizontal anchor preservation and width recalculation.
	/// Debounced to avoid running on every keystroke; also waits for any in-flight incremental page to finish.
	/// </summary>
	internal void ApplySearch(string? searchText)
	{
		_lastSearchTerm = searchText;

		// Initialize a single, reusable debounce timer
		if (_searchDebounceTimer is null)
		{
			_searchDebounceTimer = Dispatcher.CreateTimer();
			_searchDebounceTimer.IsRepeating = false;
			_searchDebounceTimer.Tick += (DispatcherQueueTimer s, object e) =>
			{
				s.Stop();
				_ = ApplySearchCoreAsync(_pendingSearchTerm);
			};
		}

		// Update the pending term and (re)start debounce
		_pendingSearchTerm = searchText;
		_searchDebounceTimer.Interval = TimeSpan.FromMilliseconds(120); // small, responsive debounce
		_searchDebounceTimer.Start();
	}

	/// <summary>
	/// Runs the actual filter apply. If the bound collection is still loading a page, retry shortly without blocking the UI thread.
	/// </summary>
	/// <param name="searchText"></param>
	private async Task ApplySearchCoreAsync(string? searchText)
	{
		if (ObservableSource is null) return;

		// If a page is mid-append, wait a tick and retry.
		if (ObservableSource.IsCurrentlyLoading)
		{
			// Re-arm a very short retry; avoids running filter while a page is appending.
			if (_searchDebounceTimer is null)
			{
				_searchDebounceTimer = Dispatcher.CreateTimer();
				_searchDebounceTimer.IsRepeating = false;
				_searchDebounceTimer.Tick += (DispatcherQueueTimer s, object e2) =>
				{
					s.Stop();
					_ = ApplySearchCoreAsync(_pendingSearchTerm);
				};
			}
			_searchDebounceTimer.Interval = TimeSpan.FromMilliseconds(40);
			_searchDebounceTimer.Start();
			return;
		}

		// Perform in-place filter over the bound observable.
		// - Suspends incremental loads while a filter is active.
		// - Replaces items atomically under the same semaphore (prevents reentrancy and UI thrash).
		// - Resumes paging + ForceReload when filter clears.
		await ApplyFilters_NoSnap(
			allFileIdentities: FullSource.AsEnumerable(),
			filteredCollection: ObservableSource,
			searchText: searchText,
			selectedDate: null,
			regKey: registryKey);

		// Re-fit columns to current visible slice.
		RecalculateVisibleColumnWidths();

		// Restore the exact horizontal position saved before.
		if (ScrollViewerRef is not null)
		{
			double clamped = ScrollViewerRef.HorizontalOffset;
			if (clamped < 0) clamped = 0;
			if (clamped > ScrollViewerRef.ScrollableWidth) clamped = ScrollViewerRef.ScrollableWidth;
			_ = ScrollViewerRef.ChangeView(clamped, null, null, true);
		}
	}

	/// Sort by header Tag key (FileIdentity mapping key). Preserves horizontal position. Honors search results.
	internal void SortByHeader(string? key, string? currentSearchTerm)
	{
		if (string.IsNullOrWhiteSpace(key))
		{
			return;
		}

		if (ObservableSource is null) return;

		bool filterActive = !string.IsNullOrWhiteSpace(currentSearchTerm);

		if (ListViewRef is not null)
			// Suppress smooth centering that is triggered by SelectionChanged during reorder (filtered sort only).
			// Using 2 to be robust in case selection changes twice due to container recycling/realization.
			((CustomUIElements.ListViewV2)ListViewRef).SuppressSelectionChanged(2);

		// Sort via incremental-aware path (keeps full source sorted; reorders filtered subset in-place).
		if (ListViewHelper.FileIdentityPropertyMappings.TryGetValue(key, out (string Label, Func<FileIdentity, object?> Getter) mapping))
		{
			SortColumnIncremental(
				keySelector: mapping.Getter,
				searchBoxText: currentSearchTerm,
				originalList: FullSource,
				observableCollection: ObservableSource,
				sortState: _sortState,
				newKey: key,
				sv: ScrollViewerRef);
		}

		// After the sort the leading items changed; recompute widths on debounce if auto-resize is enabled.
		if (App.Settings.AutoResizeListViewColumns)
		{
			ScheduleWidthRecalc();
		}

		// When a filter is active pin vertical scroll to the top
		if (filterActive)
		{
			_ = ResetFilteredViewToTopAsync();
		}
		else
		{
			// Preserve horizontal offset for the unfiltered case.
			if (ScrollViewerRef is not null)
			{
				double clamped = ScrollViewerRef.HorizontalOffset;
				if (clamped < 0) clamped = 0;
				if (clamped > ScrollViewerRef.ScrollableWidth) clamped = ScrollViewerRef.ScrollableWidth;
				_ = ScrollViewerRef.ChangeView(clamped, null, null, true);
			}
		}
	}

	private async Task ResetFilteredViewToTopAsync()
	{
		// If we have no viewer, nothing to do.
		if (ScrollViewerRef is null)
			return;

		// Immediately clamp vertical to 0, preserve horizontal.
		double clamped = ScrollViewerRef.HorizontalOffset;
		if (clamped < 0) clamped = 0;
		if (clamped > ScrollViewerRef.ScrollableWidth) clamped = ScrollViewerRef.ScrollableWidth;
		_ = ScrollViewerRef.ChangeView(clamped, 0, null, true);

		if (ListViewRef is null || ListViewRef.Items.Count == 0)
		{
			return;
		}

		// Let the UI process the collection change and realize/recycle containers, then anchor to the very first item.
		await Dispatcher.EnqueueAsync(() =>
		{
			try
			{
				ListViewRef.ScrollIntoView(ListViewRef.Items[0], ScrollIntoViewAlignment.Leading);
			}
			catch { }
		});

		// Clamp again to ensure vertical remains at the very top after the ScrollIntoView operation.
		await Dispatcher.EnqueueAsync(() =>
		{
			if (ScrollViewerRef is null) return;

			double h = ScrollViewerRef.HorizontalOffset;
			if (h < 0) h = 0;
			if (h > ScrollViewerRef.ScrollableWidth) h = ScrollViewerRef.ScrollableWidth;

			_ = ScrollViewerRef.ChangeView(h, 0, null, true);
		});
	}

	internal void CopySelectedRows()
	{
		if (ListViewRef is not null && ListViewRef.SelectedItems.Count > 0)
		{
			// Convert selected row(s) into text via property mappings and place into clipboard.
			ListViewHelper.ConvertRowToText(ListViewRef.SelectedItems, ListViewHelper.FileIdentityPropertyMappings);
		}
	}

	internal void CopySingleCell(string? propertyKey)
	{
		if (string.IsNullOrWhiteSpace(propertyKey) || ListViewRef is null)
		{
			return;
		}

		// Copy a single mapped cell from the selected item.
		if (ListViewHelper.FileIdentityPropertyMappings.TryGetValue(propertyKey, out (string Label, Func<FileIdentity, object?> Getter) mapping))
		{
			ListViewHelper.CopyToClipboard<FileIdentity>(fi => mapping.Getter(fi)?.ToString(), ListViewRef);
		}
	}

	// Cleans up controller's own bindings to the currently bound ListView/ScrollViewer.
	// Safe to call multiple times.
	private void CleanupBindings()
	{
		// Detach our collection change handler from the current observable (if any).
		ObservableSource?.CollectionChanged -= Collection_CollectionChanged;

		// Detach ViewChanged event from ScrollViewer (if any)
		ScrollViewerRef?.ViewChanged -= ScrollViewer_ViewChanged;

		// Stop and release timers to avoid holding controller references past teardown
		_recalcTimer?.Stop();
		_recalcTimer = null;

		_searchDebounceTimer?.Stop();
		_searchDebounceTimer = null;

		ListViewRef = null;
		ScrollViewerRef = null;
	}

	// Handler to clean up our controller bindings as soon as the ListView leaves the tree.
	internal void ListView_Unloaded(object sender, RoutedEventArgs e)
	{
		CleanupBindings();
	}

	private void ScrollViewer_ViewChanged(object? sender, ScrollViewerViewChangedEventArgs e)
	{
		// While the user is scrolling (intermediate), debounce recomputations to avoid excessive layout passes.
		// When auto-resize is disabled, never recompute on scroll.
		if (!App.Settings.AutoResizeListViewColumns)
		{
			return;
		}

		if (e.IsIntermediate)
		{
			ScheduleWidthRecalc();
		}
		else
		{
			// When scrolling settles, perform a definitive pass to reflect the presently visible window + look-ahead.
			RecalculateVisibleColumnWidths();
		}
	}

	internal void ListView_ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		// Virtualization/realization changed (new rows realized). Debounce column width recalculation.
		// When auto-resize is disabled, never recompute on realization.
		if (!App.Settings.AutoResizeListViewColumns)
		{
			return;
		}

		ScheduleWidthRecalc();
	}

	private void Collection_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
	{
		// Any display-changing update should trigger a width recomputation (on debounce) and update the total count.
		if (e.Action is NotifyCollectionChangedAction.Add
			|| e.Action is NotifyCollectionChangedAction.Remove
			|| e.Action is NotifyCollectionChangedAction.Replace
			|| e.Action is NotifyCollectionChangedAction.Move
			|| e.Action is NotifyCollectionChangedAction.Reset)
		{
			// Only auto-resize when the setting is enabled.
			if (App.Settings.AutoResizeListViewColumns)
			{
				ScheduleWidthRecalc();
			}
		}
	}

	// Ensure the debounce timer is created once.
	private void EnsureRecalcTimer()
	{
		if (_recalcTimer is not null)
		{
			return;
		}

		_recalcTimer = Dispatcher.CreateTimer();
		_recalcTimer.IsRepeating = false;
		_recalcTimer.Interval = TimeSpan.FromMilliseconds(15);
		_recalcTimer.Tick += (DispatcherQueueTimer s, object e) =>
		{
			RecalculateVisibleColumnWidths();
		};
	}

	// Start (or restart) the debounce timer.
	private void ScheduleWidthRecalc()
	{
		EnsureRecalcTimer();
		_recalcTimer!.Stop();
		_recalcTimer.Start();
	}

	/// <summary>
	/// Measures header text plus a slice of visible (and look-ahead) rows to compute the best-fit width per column.
	/// Applies only when the proposed width differs from current by a threshold to avoid layout churn.
	/// </summary>
	internal void RecalculateVisibleColumnWidths()
	{
		// When auto-resize is disabled, perform the one-time full-dataset pass only if not already done for this OFF period.
		if (!App.Settings.AutoResizeListViewColumns)
		{
			bool offDone = s_offModeFullCalcDone.TryGetValue(registryKey, out bool doneFlag) && doneFlag;

			// Perform the one-time full dataset sizing only once per OFF period, and only when data exists.
			if (!offDone && FullSource.Count > 0)
			{
				RecalculateFullDatasetColumnWidths();
				s_offModeFullCalcDone[registryKey] = true;
			}

			// In OFF mode we never auto-resize on scroll/realization; return after the one-shot opportunity.
			return;
		}

		// Get total number of columns
		int columnCount = columnPropertyKeys.Length;

		// Create an array of doubles, each index storing a column's width
		// Baseline widths come from headers
		double[] headerWidths = new double[columnCount];
		for (int i = 0; i < columnCount; i++)
		{
			string headerResourceKey = headerResourceKeys[i];
			string headerText = GlobalVars.GetStr(headerResourceKey);

			// Measure header text as the baseline minimum per column.
			headerWidths[i] = ListViewHelper.MeasureText(headerText);
		}

		// Measure only the visible slice (plus a small look-ahead buffer) instead of every loaded row.
		if (ListViewRef is not null && ListViewRef.Items.Count > 0)
		{
			int startIndex = 0;
			int endIndex = ListViewRef.Items.Count - 1;

			ItemsStackPanel? isp = ListViewRef.ItemsPanelRoot as ItemsStackPanel;
			if (isp is not null)
			{
				int first = isp.FirstVisibleIndex;
				int last = isp.LastVisibleIndex;

				// Clamp to valid bounds and extend by LookAheadRowCount to reduce visible width pops.
				if (first >= 0 && last >= first)
				{
					startIndex = Math.Max(0, first - LookAheadRowCount);
					endIndex = Math.Min(endIndex, last + LookAheadRowCount);
				}
			}

			for (int row = startIndex; row <= endIndex; row++)
			{
				if (ListViewRef.Items[row] is not FileIdentity fi)
				{
					continue;
				}

				// Measure each mapped column cell text and expand if needed.
				// The baseline for comparison is the header width, enabling both growth and shrink across scrolls.
				for (int c = 0; c < columnCount; c++)
				{
					string propertyKey = columnPropertyKeys[c];
					if (ListViewHelper.FileIdentityPropertyMappings.TryGetValue(propertyKey, out (string Label, Func<FileIdentity, object?> Getter) mapping))
					{
						object? raw = mapping.Getter(fi);
						string? cell = raw?.ToString();

						double currentBaseline = headerWidths[c];
						double measured = ListViewHelper.MeasureTextEx(cell);

						// Only expand above the current computed baseline for this pass.
						// Shrinking happens naturally because each pass starts from the header baseline, not previous column width.
						if (measured > currentBaseline)
						{
							headerWidths[c] = measured;
						}
					}
				}
			}
		}
		// If there are no realized rows yet: we still have header-based widths, which is safe.

		// Apply computed widths when they differ meaningfully from current values.
		ApplyWidthsIfChanged(headerWidths);
	}

	// Apply computed widths only when they meaningfully differ from current, to minimize UI thrash.
	private void ApplyWidthsIfChanged(double[] newWidths)
	{
		IReadOnlyList<double> current = getCurrentWidthsCallback();
		int limit = Math.Min(newWidths.Length, current.Count);

		for (int i = 0; i < limit; i++)
		{
			double proposed = newWidths[i];

			double existing = current[i];
			if (Math.Abs(proposed - existing) > ColumnWidthUpdateThreshold)
			{
				applyWidthCallback(i, proposed);
			}
		}
	}

	public void Dispose()
	{
		try
		{
			// Clean up any ListView/ScrollViewer bindings owned by this controller.
			CleanupBindings();

			ObservableSource?.Dispose();
		}
		catch { } // Swallow cleanup exceptions
	}

	// Detects ON→OFF and OFF→ON transitions and performs the correct one-shot behavior.
	// - ON→OFF (or first-time load with OFF): do a single full-dataset width calculation and mark done.
	// - OFF→OFF on subsequent visits: do nothing (VM already has widths stored).
	// - Any time we are ON: ensure the OFF-mode "done" flag is reset so a later OFF will run one pass again.
	private void HandleAutoResizeTransitionOnEntry()
	{
		bool current = App.Settings.AutoResizeListViewColumns;

		bool hadLast = s_lastAutoResizeState.TryGetValue(registryKey, out bool last);

		if (!current)
		{
			// OFF mode: run the one-time full-dataset pass only when data exists, and only once per OFF period.
			bool offDone = s_offModeFullCalcDone.TryGetValue(registryKey, out bool doneFlag) && doneFlag;
			bool lastWasOn = hadLast && last; // last == true means previously ON

			// If we just transitioned from ON→OFF, or it's not done yet, try to run it - but only if we have data.
			if ((lastWasOn || !offDone) && FullSource.Count > 0)
			{
				RecalculateFullDatasetColumnWidths();
				s_offModeFullCalcDone[registryKey] = true;
			}
			else
			{
				// No data yet or already done: ensure the "done" flag remains accurate and do nothing now.
				if (!offDone)
				{
					// Keep it false; the one-shot will be picked up later by RecalculateVisibleColumnWidths when data exists.
					s_offModeFullCalcDone[registryKey] = false;
				}
			}
		}
		else
		{
			// ON mode: allow auto-resize and reset the OFF-mode completion flag
			// so a later OFF period will recompute once again.
			s_offModeFullCalcDone[registryKey] = false;
		}

		// Remember current state for the next entry
		s_lastAutoResizeState[registryKey] = current;
	}

	// One-shot full-dataset width computation used when auto-resize is OFF for the current period.
	// Measures headers and then every row in fullSource to find the true max per column.
	private void RecalculateFullDatasetColumnWidths()
	{
		int columnCount = columnPropertyKeys.Length;

		// Do not re-measure headers here because the VM constructor calculates header column widths.
		// Start from the current widths (the VM properties).
		IReadOnlyList<double> currentWidths = getCurrentWidthsCallback();

		double[] maxWidths = new double[columnCount];
		for (int i = 0; i < columnCount; i++)
		{
			maxWidths[i] = i < currentWidths.Count ? currentWidths[i] : 0;
		}

		// Iterate the full logical dataset to compute stable maxima above the current baseline.
		for (int i = 0; i < FullSource.Count; i++)
		{
			FileIdentity fi = FullSource[i];
			for (int c = 0; c < columnCount; c++)
			{
				string propertyKey = columnPropertyKeys[c];
				if (ListViewHelper.FileIdentityPropertyMappings.TryGetValue(propertyKey, out (string Label, Func<FileIdentity, object?> Getter) mapping))
				{
					object? raw = mapping.Getter(fi);
					string? cell = raw?.ToString();
					double current = maxWidths[c];
					double measured = ListViewHelper.MeasureTextEx(cell);
					if (measured > current)
					{
						maxWidths[c] = measured;
					}
				}
			}
		}

		ApplyWidthsIfChanged(maxWidths);
	}

	/// <summary>
	/// One-time header-only width initialization.
	/// Runs independently of auto-resize setting and before any data exists,
	/// so headers have proper widths as soon as the ViewModel is created.
	/// </summary>
	internal void InitializeHeaderOnlyColumnWidths()
	{
		// Compute widths solely from header resource texts
		int columnCount = columnPropertyKeys.Length;

		double[] headerWidths = new double[columnCount];
		for (int i = 0; i < columnCount; i++)
		{
			string headerResourceKey = headerResourceKeys[i];
			string headerText = GlobalVars.GetStr(headerResourceKey);
			headerWidths[i] = ListViewHelper.MeasureText(headerText);
		}

		// Apply once; later passes (if any) will only update when there is a meaningful delta.
		ApplyWidthsIfChanged(headerWidths);
	}

	#region STATICS

	internal static async Task ApplyFilters_NoSnap(
		IEnumerable<FileIdentity> allFileIdentities,
		GenericIncrementalCollection<FileIdentityIncrementalSource, FileIdentity> filteredCollection,
		string? searchText,
		DateTimeOffset? selectedDate,
		ListViewHelper.ListViewsRegistry regKey,
		ListViewHelper.PropertyFilterItem? selectedPropertyFilter = null,
		string? propertyFilterValue = null)
	{
		// Filtering pipeline:
		// 1) Start from the full enumerable.
		// 2) Optionally filter by date.
		// 3) Optionally filter by free-text search across multiple properties.
		// 4) Optionally apply a property-specific filter.
		// 5) Materialize into the bound collection.
		string? searchTerm = searchText?.Trim();
		IEnumerable<FileIdentity> filteredResults = allFileIdentities;

		if (selectedDate is not null)
		{
			filteredResults = filteredResults.Where(item => item.TimeCreated.HasValue && item.TimeCreated.Value >= selectedDate);
		}

		if (!string.IsNullOrWhiteSpace(searchTerm))
		{
			filteredResults = filteredResults.Where(output =>
				(output.FileName is not null && output.FileName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				output.SignatureStatus.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				output.Action.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				(output.OriginalFileName is not null && output.OriginalFileName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.InternalName is not null && output.InternalName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FileDescription is not null && output.FileDescription.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.ProductName is not null && output.ProductName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FileVersion is not null && output.FileVersion.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.PackageFamilyName is not null && output.PackageFamilyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FilePath is not null && output.FilePath.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.SHA256FlatHash is not null && output.SHA256FlatHash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.SHA256Hash is not null && output.SHA256Hash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FilePublishersToDisplay is not null && output.FilePublishersToDisplay.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.Opus is not null && output.Opus.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.PolicyName is not null && output.PolicyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.ComputerName is not null && output.ComputerName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
			);
		}

		if (selectedPropertyFilter is not null && !string.IsNullOrEmpty(propertyFilterValue))
		{
			string filterValue = propertyFilterValue.Trim();
			filteredResults = filteredResults.Where(item =>
			{
				object? propertyValue = selectedPropertyFilter.Getter(item);
				return propertyValue is not null &&
					   propertyValue.ToString()?.Contains(filterValue, StringComparison.OrdinalIgnoreCase) == true;
			});
		}

		bool filterActive =
			!string.IsNullOrWhiteSpace(searchTerm) ||
			(selectedPropertyFilter is not null && !string.IsNullOrWhiteSpace(propertyFilterValue)) ||
			selectedDate is not null;

		if (filterActive)
		{
			// Materialize the filtered subset once.
			List<FileIdentity> subset = filteredResults.ToList();

			// Stop the control from pulling more pages while we replace the view.
			filteredCollection.SuspendLoads(true);

			// Replace atomically under the same semaphore as incremental loading.
			await filteredCollection.ReplaceAllExclusiveAsync(subset);
		}
		else
		{
			// Filter cleared: resume loads and refresh to page 1 of the original (unfiltered) data.
			filteredCollection.SuspendLoads(false);

			// Clear current items under the semaphore, then trigger a clean first-page reload.
			await filteredCollection.ReplaceAllExclusiveAsync(Array.Empty<FileIdentity>());

			// Kick paging: let the incremental collection repopulate from its data source.
			await filteredCollection.ForceReloadAsync();
		}
	}

	/// <summary>
	/// Uses bulk replace to avoid N per-item CollectionChanged events when sorting large datasets.
	/// Safe fallback to classic approach if the provided observableCollection does not implement IBulkUpdatableCollection.
	/// </summary>
	/// <typeparam name="TElement">Element type.</typeparam>
	/// <param name="keySelector">Projection for sorting.</param>
	/// <param name="searchBoxText">Current search text (determines data source selection).</param>
	/// <param name="originalList">Original full list (unfiltered) reference.</param>
	/// <param name="observableCollection">The bound observable collection.</param>
	/// <param name="sortState">State tracker (column + direction).</param>
	/// <param name="newKey">New column key (header Tag).</param>
	/// <param name="sv">ScrollViewer Reference</param>
	/// <param name="propertyFilterValue">Optional property filter text.</param>
	internal static void SortColumnIncremental<TElement>(
		Func<TElement, object?> keySelector,
		string? searchBoxText,
		List<TElement> originalList,
		ObservableCollection<TElement> observableCollection,
		ListViewHelper.SortState sortState,
		string newKey,
		ScrollViewer? sv,
		string? propertyFilterValue = null)
	{

		if (sv is null) return;

		// Determine if a filter is active. In that case, loads are suspended by ApplyFilters_NoSnap.
		bool filterActive = !string.IsNullOrEmpty(searchBoxText) || !string.IsNullOrEmpty(propertyFilterValue);

		// Toggle sort order if same column; otherwise set to descending as initial.
		if (string.Equals(sortState.CurrentSortKey, newKey, StringComparison.OrdinalIgnoreCase))
		{
			sortState.IsDescending = !sortState.IsDescending;
		}
		else
		{
			sortState.CurrentSortKey = newKey;
			sortState.IsDescending = true;
		}

		// Always keep the FULL dataset sorted in place so that when filters are cleared
		// the unfiltered view is already in the desired order.
		List<TElement> fullySorted = sortState.IsDescending
			? originalList.OrderByDescending(keySelector).ToList()
			: originalList.OrderBy(keySelector).ToList();

		// Replace contents of originalList IN PLACE so any incremental source sharing this list sees new ordering.
		originalList.Clear();
		for (int i = 0; i < fullySorted.Count; i++)
		{
			originalList.Add(fullySorted[i]);
		}

		// When a filter is active:
		// - Do NOT force a reload (that would page the unfiltered source and break the filtered view).
		// - Just sort the currently displayed filtered subset in-place.
		if (filterActive)
		{
			// Sort the current filtered view shown in the observable collection.
			List<TElement> currentView = observableCollection.ToList();
			List<TElement> sortedView = sortState.IsDescending
				? currentView.OrderByDescending(keySelector).ToList()
				: currentView.OrderBy(keySelector).ToList();

			// High-performance bulk replace if available, otherwise fallback to clear/add.
			if (observableCollection is IBulkUpdatableCollection<TElement> bulk)
			{
				bulk.BulkReplace(sortedView);
			}
			else
			{
				observableCollection.Clear();
				for (int i = 0; i < sortedView.Count; i++)
				{
					observableCollection.Add(sortedView[i]);
				}
			}

			// After reordering a filtered view, reset the vertical offset to the top.
			double clampedv2 = sv.HorizontalOffset;
			if (clampedv2 < 0) clampedv2 = 0;
			if (clampedv2 > sv.ScrollableWidth) clampedv2 = sv.ScrollableWidth;
			_ = sv.ChangeView(clampedv2, 0, null, true);

			return;
		}

		// No filter active:
		// - Let the incremental collection repopulate from page 1 under new order.
		_ = ((IBatchReloadable)observableCollection).ForceReloadAsync();

		// Restore the exact horizontal position saved before.
		double clamped = sv.HorizontalOffset;
		if (clamped < 0) clamped = 0;
		if (clamped > sv.ScrollableWidth) clamped = sv.ScrollableWidth;
		_ = sv.ChangeView(clamped, null, null, true);
	}

	#endregion

	internal void CopyToClipboard_Click(object sender, RoutedEventArgs e)
	{
		string key = (string)((MenuFlyoutItem)sender).Tag;
		CopySingleCell(key);
	}
}
