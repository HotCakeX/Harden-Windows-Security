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
using System.Collections.Specialized;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.ViewModels;
using CommonCore.IncrementalCollection;
using CommonCore.ToolKits;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.Others;

internal sealed partial class ListViewIncrementalController(
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
	internal HighPerfIncrementalCollection<FileIdentity>? ObservableSource { get; set => SP(ref field, value); }

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
	internal void DeSelectAll_Click() => ListViewRef?.SelectedItems.Clear();

	/// <summary>
	/// Selects all of the displayed rows on the ListView
	/// </summary>
	internal void SelectAll_Click()
	{
		if (ListViewRef is null || ObservableSource is null) return;
		ListViewHelper.SelectAll(ListViewRef, ObservableSource);
	}

	/// <summary>
	/// Event handler for the Clear Data button
	/// </summary>
	internal async void ClearDataButton_Click()
	{
		if (ObservableSource is null) return;

		await _viewOperationLock.WaitAsync();
		try
		{
			await ObservableSource.ReplaceAllExclusiveAsync([]);

			// Clear the backing full source list as well
			FullSource.Clear();

			NotifyFullSourceChanged();

			// Recompute column widths (header-only now)
			RecalculateVisibleColumnWidths();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
		finally
		{
			_ = _viewOperationLock.Release();
		}
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

	// Track per-instance one-time calculation status when Auto-Resize is OFF.
	private bool _offModeFullCalcDone;

	/// <summary>
	/// Debounce for search to avoid running a heavy filter on every keystroke
	/// </summary>
	private DispatcherQueueTimer? _searchDebounceTimer;

	/// <summary>
	/// Holds the latest search term pending execution
	/// </summary>
	private string? _pendingSearchTerm;

	/// <summary>
	/// Semaphore to ensure only one heavy view operation (Search, Sort, Clear) runs at a time.
	/// </summary>
	private readonly SemaphoreSlim _viewOperationLock = new(1, 1);

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

		// If AutoResize is ON, reset the off-mode check and schedule a layout update.
		// If AutoResize is OFF, the schedule will trigger the one-time full scan if needed.
		// Using ScheduleWidthRecalc ensures the ItemsStackPanel has time to layout before we probe indices.
		if (GlobalVars.Settings.AutoResizeListViewColumns)
		{
			_offModeFullCalcDone = false;
		}

		ScheduleWidthRecalc();
	}

	/// <summary>
	/// Update the bound observable collection if the VM replaces it.
	/// </summary>
	internal void UpdateCollection(HighPerfIncrementalCollection<FileIdentity> newCollection)
	{
		// Capture old reference (may be null on first assignment).
		HighPerfIncrementalCollection<FileIdentity>? old = ObservableSource;

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
		ScheduleWidthRecalc();

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
			_searchDebounceTimer.Tick += (s, e) =>
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

		await _viewOperationLock.WaitAsync();
		try
		{
			// If a newer search term has been queued while we were waiting for the lock, skip this stale search.
			if (!string.Equals(searchText, _pendingSearchTerm, StringComparison.OrdinalIgnoreCase))
				return;

			// Perform in-place filter over the bound observable.
			// - Suspends incremental loads while a filter is active.
			// - Replaces items atomically under the same semaphore (prevents reentrancy and UI thrash).
			// - Resumes paging + ForceReload when filter clears.
			await ApplyFilters_NoSnap(
				allFileIdentities: FullSource,
				filteredCollection: ObservableSource,
				searchText: searchText,
				selectedDate: null);

			// Re-fit columns to current visible slice.
			ScheduleWidthRecalc();

			// Restore the exact horizontal position saved before.
			if (ScrollViewerRef is not null)
			{
				double clamped = ScrollViewerRef.HorizontalOffset;
				if (clamped < 0) clamped = 0;
				if (clamped > ScrollViewerRef.ScrollableWidth) clamped = ScrollViewerRef.ScrollableWidth;
				_ = ScrollViewerRef.ChangeView(clamped, null, null, true);
			}
		}
		finally
		{
			_ = _viewOperationLock.Release();
		}
	}

	/// <summary>
	/// Sort by header Tag key (FileIdentity mapping key). Preserves horizontal position.
	/// Honors search results. Bound to the UI buttons and works as event handler.
	/// </summary>
	internal async void SortByHeader(string? key, string? currentSearchTerm)
	{
		if (string.IsNullOrWhiteSpace(key) || ObservableSource is null) return;

		await _viewOperationLock.WaitAsync();
		try
		{

			bool filterActive = !string.IsNullOrWhiteSpace(currentSearchTerm);

			if (ListViewRef is not null)
				// Suppress smooth centering that is triggered by SelectionChanged during reorder (filtered sort only).
				// Using 2 to be robust in case selection changes twice due to container recycling/realization.
				((CustomUIElements.ListViewV2)ListViewRef).SuppressSelectionChanged(2);

			// Sort via incremental-aware path (keeps full source sorted; reorders filtered subset in-place).
			if (ListViewHelper.FileIdentityPropertyMappings.TryGetValue(key, out (string Label, Func<FileIdentity, object?> Getter) mapping))
			{
				await SortColumnIncrementalAsync(
					keySelector: mapping.Getter,
					searchBoxText: currentSearchTerm,
					originalList: FullSource,
					observableCollection: ObservableSource,
					sortState: _sortState,
					newKey: key,
					sv: ScrollViewerRef);
			}

			// After the sort the leading items changed; recompute widths on debounce if auto-resize is enabled.
			if (GlobalVars.Settings.AutoResizeListViewColumns)
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
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
		finally
		{
			_ = _viewOperationLock.Release();
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
			return;

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
	internal void ListView_Unloaded(object sender, RoutedEventArgs e) => CleanupBindings();

	private void ScrollViewer_ViewChanged(object? sender, ScrollViewerViewChangedEventArgs e)
	{
		// While the user is scrolling (intermediate), debounce recomputations to avoid excessive layout passes.
		// When auto-resize is disabled, never recompute on scroll.
		if (!GlobalVars.Settings.AutoResizeListViewColumns)
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
			ScheduleWidthRecalc();
		}
	}

	internal void ListView_ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		// Virtualization/realization changed (new rows realized). Debounce column width recalculation.
		// When auto-resize is disabled, never recompute on realization.
		if (!GlobalVars.Settings.AutoResizeListViewColumns)
			return;

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
			// Schedule a recalc. If AutoResize is OFF, the method itself will determine if a one-time pass is needed.
			ScheduleWidthRecalc();
		}
	}

	// Ensure the debounce timer is created once.
	private void EnsureRecalcTimer()
	{
		if (_recalcTimer is not null) return;

		_recalcTimer = Dispatcher.CreateTimer();
		_recalcTimer.IsRepeating = false;
		_recalcTimer.Interval = TimeSpan.FromMilliseconds(20);
		_recalcTimer.Tick += (s, e) =>
		{
			s.Stop();
			RecalculateVisibleColumnWidths();
		};
	}

	// Start (or restart) the debounce timer.
	private void ScheduleWidthRecalc()
	{
		EnsureRecalcTimer();
		_recalcTimer?.Stop();
		_recalcTimer?.Start();
	}

	/// <summary>
	/// Measures header text plus a slice of visible (and look-ahead) rows to compute the best-fit width per column.
	/// Applies only when the proposed width differs from current by a threshold to avoid layout churn.
	/// </summary>
	internal void RecalculateVisibleColumnWidths()
	{
		// 1. If AutoResize is Disabled:
		// Check if we have already performed the "one-time full dataset" measurement for this specific instance activation.
		// If we haven't, do it now (and mark it done). If we have, exit immediately.
		if (!GlobalVars.Settings.AutoResizeListViewColumns)
		{
			if (!_offModeFullCalcDone && FullSource.Count > 0)
			{
				RecalculateFullDatasetColumnWidths();
				_offModeFullCalcDone = true;
			}
			return;
		}

		// 2. If AutoResize is Enabled:
		// Perform measurement based on currently visible rows.

		// Get total number of columns
		int columnCount = columnPropertyKeys.Length;

		// Baseline widths come from headers
		double[] headerWidths = new double[columnCount];
		for (int i = 0; i < columnCount; i++)
		{
			string headerResourceKey = headerResourceKeys[i];
			string headerText = GlobalVars.GetStr(headerResourceKey);
			headerWidths[i] = ListViewHelper.MeasureText(headerText);
		}

		// Using a local dictionary to cache string widths for the duration of this calculation.
		// This avoids repetitive TextBlock measurement (Layout/DWrite overhead) for identical values across rows.
		Dictionary<string, double> textWidthCache = new(StringComparer.Ordinal);

		// Measure only the visible slice (plus a small look-ahead buffer) instead of every loaded row.
		if (ListViewRef is not null && ListViewRef.Items.Count > 0)
		{
			int startIndex = 0;
			int endIndex = ListViewRef.Items.Count - 1;

			if (ListViewRef.ItemsPanelRoot is ItemsStackPanel isp)
			{
				int first = isp.FirstVisibleIndex;
				int last = isp.LastVisibleIndex;

				// If virtualization hasn't reported valid indices yet, we might be in the initial layout phase.
				// In this case, we default to measuring the first page to ensure *some* sizing happens.
				if (first < 0)
				{
					first = 0;
					last = Math.Min(20, endIndex);
				}

				// Clamp to valid bounds and extend by LookAheadRowCount to reduce visible width pops.
				if (first >= 0 && last >= first)
				{
					startIndex = Math.Max(0, first - LookAheadRowCount);
					endIndex = Math.Min(endIndex, last + LookAheadRowCount);
				}
			}

			for (int row = startIndex; row <= endIndex; row++)
			{
				if (row >= ListViewRef.Items.Count) break;

				if (ListViewRef.Items[row] is not FileIdentity fi)
				{
					continue;
				}

				// Measure each mapped column cell text and expand if needed.
				for (int c = 0; c < columnCount; c++)
				{
					string propertyKey = columnPropertyKeys[c];
					if (ListViewHelper.FileIdentityPropertyMappings.TryGetValue(propertyKey, out (string Label, Func<FileIdentity, object?> Getter) mapping))
					{
						object? raw = mapping.Getter(fi);
						string? cell = raw?.ToString();

						if (cell is null) continue;

						ref double measured = ref CollectionsMarshal.GetValueRefOrAddDefault(textWidthCache, cell, out bool exists);
						if (!exists) measured = ListViewHelper.MeasureTextEx(cell);

						// Only expand above the current computed baseline for this pass.
						// Shrinking happens naturally because each pass starts from the header baseline, not previous column width.
						if (measured > headerWidths[c])
							headerWidths[c] = measured;
					}
				}
			}
		}

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
			_viewOperationLock.Dispose();
		}
		catch { } // Swallow cleanup exceptions
	}

	// One-shot full-dataset width computation used when auto-resize is OFF for the current period.
	// Measures headers and then every row in fullSource to find the true max per column.
	private void RecalculateFullDatasetColumnWidths()
	{
		int columnCount = columnPropertyKeys.Length;

		// Start from the current widths (the VM properties).
		IReadOnlyList<double> currentWidths = getCurrentWidthsCallback();

		double[] maxWidths = new double[columnCount];
		for (int i = 0; i < columnCount; i++)
		{
			// Ensure we respect header minimums
			string headerResourceKey = headerResourceKeys[i];
			string headerText = GlobalVars.GetStr(headerResourceKey);
			double headerMin = ListViewHelper.MeasureText(headerText);

			double current = i < currentWidths.Count ? currentWidths[i] : 0;
			maxWidths[i] = Math.Max(current, headerMin);
		}

		// Use a local dictionary to cache string widths for the duration of this calculation.
		Dictionary<string, double> textWidthCache = new(FullSource.Count, StringComparer.Ordinal);

		// Iterate the full logical dataset to compute stable maxima above the current baseline.
		foreach (FileIdentity fi in CollectionsMarshal.AsSpan(FullSource))
		{
			for (int c = 0; c < columnCount; c++)
			{
				string propertyKey = columnPropertyKeys[c];
				if (ListViewHelper.FileIdentityPropertyMappings.TryGetValue(propertyKey, out (string Label, Func<FileIdentity, object?> Getter) mapping))
				{
					object? raw = mapping.Getter(fi);
					string? cell = raw?.ToString();

					if (cell is null) continue;

					ref double measured = ref CollectionsMarshal.GetValueRefOrAddDefault(textWidthCache, cell, out bool exists);
					if (!exists) measured = ListViewHelper.MeasureTextEx(cell);

					if (measured > maxWidths[c])
						maxWidths[c] = measured;
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

	private static async Task ApplyFilters_NoSnap(
		List<FileIdentity> allFileIdentities,
		HighPerfIncrementalCollection<FileIdentity> filteredCollection,
		string? searchText,
		DateTimeOffset? selectedDate,
		ListViewHelper.PropertyFilterItem? selectedPropertyFilter = null,
		string? propertyFilterValue = null)
	{
		// Filtering pipeline:
		// 1) Start from the full List.
		// 2) Optionally filter by date.
		// 3) Optionally filter by free-text search across multiple properties.
		// 4) Optionally apply a property-specific filter.
		// 5) Materialize into the bound collection.
		string? searchTerm = searchText?.Trim();
		string? propFilterVal = propertyFilterValue?.Trim();

		bool hasSearchTerm = !string.IsNullOrWhiteSpace(searchTerm);
		bool hasPropFilter = selectedPropertyFilter is not null && !string.IsNullOrEmpty(propFilterVal);

		if (hasSearchTerm || selectedDate.HasValue || hasPropFilter)
		{
			List<FileIdentity> subset = await Task.Run(() =>
			{
				// The results list
				List<FileIdentity> tempResults = new(allFileIdentities.Count);

				foreach (FileIdentity item in CollectionsMarshal.AsSpan(allFileIdentities))
				{
					// 1. Date Filter
					if (selectedDate.HasValue)
					{
						if (!item.TimeCreated.HasValue || item.TimeCreated.Value.Date < selectedDate.Value.Date)
							continue;
					}

					// 2. Text Search Filter
					if (hasSearchTerm)
					{
						bool matches =
							(item.FileName is not null && item.FileName.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase)) ||
							item.SignatureStatus_String.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase) ||
							item.Action_String.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase) ||
							(item.OriginalFileName is not null && item.OriginalFileName.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase)) ||
							(item.InternalName is not null && item.InternalName.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase)) ||
							(item.FileDescription is not null && item.FileDescription.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase)) ||
							(item.ProductName is not null && item.ProductName.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase)) ||
							(item.FileVersion_String is not null && item.FileVersion_String.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase)) ||
							(item.PackageFamilyName is not null && item.PackageFamilyName.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase)) ||
							(item.FilePath is not null && item.FilePath.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase)) ||
							(item.SHA256FlatHash is not null && item.SHA256FlatHash.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase)) ||
							(item.SHA256Hash is not null && item.SHA256Hash.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase)) ||
							(item.FilePublishersToDisplay is not null && item.FilePublishersToDisplay.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase)) ||
							(item.Opus is not null && item.Opus.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase)) ||
							(item.PolicyName is not null && item.PolicyName.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase)) ||
							(item.ComputerName is not null && item.ComputerName.Contains(searchTerm!, StringComparison.OrdinalIgnoreCase));

						if (!matches) continue;
					}

					// 3. Property Specific Filter
					if (hasPropFilter)
					{
						object? propertyValue = selectedPropertyFilter?.Getter(item);
						if (propertyValue is null || propertyValue.ToString()?.Contains(propFilterVal!, StringComparison.OrdinalIgnoreCase) != true)
						{
							continue;
						}
					}

					// If we survived all active filters, add to results
					tempResults.Add(item);
				}
				return tempResults;
			});

			// Stop the control from pulling more pages while we replace the view.
			filteredCollection.SuspendLoads(true);

			// Replace atomically under the same semaphore as incremental loading.
			await filteredCollection.ReplaceAllExclusiveAsync(subset);
		}
		else
		{
			// Filter cleared: resume loads and refresh to page 1 of the original (unfiltered) data.
			filteredCollection.SuspendLoads(false);

			// Kick paging: let the incremental collection repopulate from its data source.
			await filteredCollection.ForceReloadAsync();
		}
	}

	/// <summary>
	/// Uses bulk replace to avoid N per-item CollectionChanged events when sorting large datasets.
	/// </summary>
	/// <typeparam name="TElement">Element type.</typeparam>
	private static async Task SortColumnIncrementalAsync<TElement>(
		Func<TElement, object?> keySelector,
		string? searchBoxText,
		List<TElement> originalList,
		HighPerfIncrementalCollection<TElement> observableCollection,
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
		List<TElement> fullySorted = await Task.Run(() =>
		{
			return sortState.IsDescending
				? originalList.OrderByDescending(keySelector).ToList()
				: originalList.OrderBy(keySelector).ToList();
		});

		// Replace contents of originalList so any incremental source sharing this list sees new ordering.
		// Using the collection to update the backing list under its internal semaphore.
		await observableCollection.UpdateSourceCollectionAsync(fullySorted);

		// When a filter is active:
		// - Do NOT force a reload (that would page the unfiltered source and break the filtered view).
		// - Just sort the currently displayed filtered subset in-place.
		if (filterActive)
		{
			// Sort the current filtered view shown in the observable collection.
			List<TElement> currentView = observableCollection.ToList();
			List<TElement> sortedView = await Task.Run(() =>
			{
				return sortState.IsDescending
					? currentView.OrderByDescending(keySelector).ToList()
					: currentView.OrderBy(keySelector).ToList();
			});

			// High-performance bulk replace
			await observableCollection.BulkReplaceAsync(sortedView);

			// After reordering a filtered view, reset the vertical offset to the top.
			double clampedv2 = sv.HorizontalOffset;
			if (clampedv2 < 0) clampedv2 = 0;
			if (clampedv2 > sv.ScrollableWidth) clampedv2 = sv.ScrollableWidth;
			_ = sv.ChangeView(clampedv2, 0, null, true);

			return;
		}

		// No filter active:
		// - Let the incremental collection repopulate from page 1 under new order.
		_ = observableCollection.ForceReloadAsync();

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
