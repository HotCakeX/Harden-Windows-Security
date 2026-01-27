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
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml.Data;
using Windows.Foundation;

namespace AppControlManager.IncrementalCollection;

/// <summary>
/// High Performance, UI-bindable incremental-loading collection.
///
/// Data flow and responsibilities:
/// - Wraps a List source and handles fetching "pages" of data from it.
/// - Exposes ObservableCollection<TDataType> to XAML (ItemsSource), so UI updates automatically on Add/Clear/Reset.
/// - Implements ISupportIncrementalLoading so a ListView/GridView can request more data on demand (LoadMoreItemsAsync).
/// - Provides bulk update capabilities (BulkReplace) to avoid O(N) change notifications (e.g., on large sorts).
/// - Provides ForceReloadAsync to fully reset paging after global reorder of the underlying logical dataset.
/// - Maintains paging state (ActivePageIndex), "busy" state (IsCurrentlyLoading), and "has more" state (HasAdditionalItems).
/// - Uses a SemaphoreSlim to serialize overlapping load/refresh/reload requests and prevent re-entrancy.
/// </summary>
internal sealed partial class HighPerfIncrementalCollection<TDataType>(List<TDataType> sourceList) : ObservableCollection<TDataType>, ISupportIncrementalLoading, IDisposable
{
	// Single concurrency guard for all operations that mutate this collection or paging state.
	// Ensures that UI-triggered incremental loads and programmatic refresh/reset cannot overlap.
	private readonly SemaphoreSlim LoadingMeowTex = new(1);

	// Prevents the control from loading more items while an external filter is active.
	// When true, ISupportIncrementalLoading.HasMoreItems reports false and LoadMoreItemsAsync becomes a no-op.
	private bool _loadsSuspended;

	private volatile bool _isDisposed;

	/// <summary>
	/// Number of items to load per page during incremental loading.
	/// </summary>
	private const int PageSize = 20;

	/// <summary>
	/// The current page index for data loading operations.
	/// Starts at 0; after each successful fetch we advance by 1.
	/// </summary>
	private int ActivePageIndex { get; set; }

	// Bulk update suppression fields
	// During BulkReplace we suppress per-item notifications and coalesce to a single Reset.
	private bool _suppressNotifications;
	private int _deferredChangeCount;

	/// <summary>
	/// Value indicating whether data is currently being loaded.
	/// </summary>
	internal bool IsCurrentlyLoading
	{
		get; private set
		{
			if (value != field)
			{
				field = value;

				// Notify bindings that depend on IsCurrentlyLoading
				OnPropertyChanged(new PropertyChangedEventArgs(nameof(IsCurrentlyLoading)));
			}
		}
	}

	/// <summary>
	/// Value indicating whether additional items are available for loading.
	/// When false, the ListView stops asking for more data.
	/// </summary>
	internal bool HasAdditionalItems
	{
		get; private set
		{
			if (value != field)
			{
				field = value;
				OnPropertyChanged(new PropertyChangedEventArgs(nameof(HasAdditionalItems)));
				OnPropertyChanged(new PropertyChangedEventArgs(nameof(ISupportIncrementalLoading.HasMoreItems)));
			}
		}
	} = true; // Assume more pages until proven otherwise.

	// Toggle incremental loading. When suspended, the control reports no more items and LoadMoreItemsAsync is a no-op.
	internal void SuspendLoads(bool suspend)
	{
		_loadsSuspended = suspend;

		// Reflect the suspension in HasAdditionalItems reporting so the control stops asking for more data.
		// When resuming, we mark "more items" available; the first subsequent load will determine actual availability.
		HasAdditionalItems = !suspend;
	}

	/// <summary>
	/// Triggers incremental loading from the UI.
	/// </summary>
	/// <remarks>
	/// The XAML framework calls this via ISupportIncrementalLoading when the control decides to fetch more items.
	/// We forward to our Task-based pipeline and adapt to WinRT's IAsyncOperation.
	/// </remarks>
	public IAsyncOperation<LoadMoreItemsResult> LoadMoreItemsAsync(uint itemCount)
		=> LoadAdditionalItemsAsync().AsAsyncOperation();

	/// <summary>
	/// Clears the collection and reloads data from the beginning.
	/// All operations are performed under the semaphore to prevent race conditions.
	/// </summary>
	internal async Task RefreshDataAsync()
	{
		// Serialize with any ongoing load operations to prevent race conditions.
		await LoadingMeowTex.WaitAsync();
		try
		{
			// Check if disposed while waiting for the semaphore
			if (_isDisposed) return;

			int previousItemCount = Count;

			// Clear everything and reset paging state.
			Clear();
			ActivePageIndex = 0;
			HasAdditionalItems = true;

			// If there were no items prior to the refresh,
			// kick off an immediate first page load directly while holding the semaphore to avoid race conditions.
			if (previousItemCount == 0)
			{
				_ = LoadDataInternal();
			}
		}
		finally
		{
			_ = LoadingMeowTex.Release();
		}
	}

	/// <summary>
	/// Internal method to load data. Assumes the semaphore is already held.
	/// Contains core logic shared by <see cref="LoadAdditionalItemsAsync"/> and <see cref="ForceReloadAsync"/>.
	/// </summary>
	/// <returns>Number of items loaded.</returns>
	private uint LoadDataInternal()
	{
		uint loadedCount = 0;
		IsCurrentlyLoading = true;

		try
		{
			int startIndex = ActivePageIndex * PageSize;
			int count;

			// If start index exceeds count, we've reached the end
			if (startIndex >= sourceList.Count)
			{
				// Advance page index even for empty results to maintain state consistency
				ActivePageIndex += 1;
				count = 0;
			}
			else
			{
				// Calculate safe count to grab
				count = Math.Min(PageSize, sourceList.Count - startIndex);

				// Advance page index
				ActivePageIndex += 1;
			}

			if (count > 0)
			{
				loadedCount = (uint)count;
				ReadOnlySpan<TDataType> pageSpan = CollectionsMarshal.AsSpan(sourceList).Slice(startIndex, count);
				foreach (TDataType item in pageSpan)
				{
					Add(item);
				}
			}
			else
			{
				// No data returned: mark as complete so the control won't keep requesting.
				HasAdditionalItems = false;
			}
		}
		finally
		{
			// Always flip the busy flag at the end of this serialized section.
			IsCurrentlyLoading = false;
		}

		return loadedCount;
	}

	/// <summary>
	/// Core incremental load pipeline that handles serialization, paging math, item addition, and notifications.
	/// </summary>
	private async Task<LoadMoreItemsResult> LoadAdditionalItemsAsync()
	{
		uint loadedItemCount = 0;

		// Serialize with any other load/refresh/reload work.
		await LoadingMeowTex.WaitAsync();
		try
		{
			// Check if disposed while waiting for the semaphore
			if (_isDisposed) return new LoadMoreItemsResult { Count = 0 };

			if (_loadsSuspended)
			{
				// Do nothing while suspended; the Reset/replace from the filter will keep UI consistent.
				// loadedItemCount remains 0; finally will release the semaphore.
				return new LoadMoreItemsResult { Count = 0 };
			}

			loadedItemCount = LoadDataInternal();
		}
		finally
		{
			_ = LoadingMeowTex.Release();
		}

		return new LoadMoreItemsResult { Count = loadedItemCount };
	}

	/// <summary>
	/// Begin a bulk update scope. While active, all collection change notifications are suppressed and coalesced into a single Reset.
	/// </summary>
	/// <returns>IDisposable scope token.</returns>
	private BulkUpdateScope BeginBulkUpdate()
	{
		_suppressNotifications = true;
		return new BulkUpdateScope(this);
	}

	/// <summary>
	/// Replace the entire contents with the supplied ordered list, emitting only one Reset notification.
	/// Used by high-volume operations (e.g. sorting 5K items) to avoid O(N) UI churn.
	/// </summary>
	/// <remarks>
	/// This API is intended for scenarios where the logical dataset is fully recomputed externally
	/// (e.g., a global sort of the backing list) and the bound collection should reflect it atomically.
	/// </remarks>
	public async Task BulkReplaceAsync(List<TDataType> items)
	{
		// Serialize this replace with incremental loads, refreshes, and other replaces.
		// Using the same semaphore guarantees no overlapping mutations (prevents reentrancy exceptions).
		await LoadingMeowTex.WaitAsync();
		try
		{
			// Check if disposed while waiting for the semaphore
			if (_isDisposed) return;

			// Suppress per-item notifications; emit a single Reset at the end.
			using (BeginBulkUpdate())
			{
				// Clear and re-populate
				ClearItems();

				foreach (TDataType item in CollectionsMarshal.AsSpan(items))
				{
					Items.Add(item); // suppressed notification
				}
			}
		}
		finally
		{
			_ = LoadingMeowTex.Release();
		}
	}

	/// <summary>
	/// Override to suppress per-item notifications inside bulk operations.
	/// Outside of suppression, we forward to the base implementation.
	/// </summary>
	protected override void OnCollectionChanged(NotifyCollectionChangedEventArgs e)
	{
		if (_suppressNotifications)
		{
			_deferredChangeCount++;
			return;
		}
		base.OnCollectionChanged(e);
	}

	/// <summary>
	/// Scope token that ends a bulk update and fires a single Reset if any changes occurred.
	/// </summary>
	private sealed partial class BulkUpdateScope(HighPerfIncrementalCollection<TDataType> owner) : IDisposable
	{
		private bool _hasDisposed;

		public void Dispose()
		{
			if (_hasDisposed) return;
			_hasDisposed = true;

			// End suppression and emit a single Reset if we performed any changes while suppressed.
			if (owner._suppressNotifications)
			{
				owner._suppressNotifications = false;

				if (owner._deferredChangeCount > 0)
				{
					owner._deferredChangeCount = 0;

					// Emit a single Reset to notify UI of full content change.
					// The typical ObservableCollection reset pattern:
					// - Notify Count and indexer changed so bindings refresh.
					owner.OnPropertyChanged(new PropertyChangedEventArgs("Count"));
					owner.OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));

					// - Raise the Reset change event. We call the base method through a helper to avoid suppression checks.
					owner.BaseRaiseReset();
				}
			}
		}
	}

	// Helper to invoke base OnCollectionChanged for a Reset without re-entering suppression logic.
	private void BaseRaiseReset() => base.OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));

	/// <summary>
	/// Atomically replaces the contents of this collection under the same semaphore used by incremental loads.
	/// This guarantees no mutation overlaps (no "modify during CollectionChanged" reentrancy).
	/// </summary>
	/// <param name="items">The new items to set (may be empty).</param>
	internal async Task ReplaceAllExclusiveAsync(List<TDataType> items)
	{
		// Serialize with any other load/refresh/replace operations using the same semaphore.
		await LoadingMeowTex.WaitAsync();
		try
		{
			// Check if disposed while waiting for the semaphore
			if (_isDisposed) return;

			// Suppress per-item notifications; emit a single Reset at the end.
			using (BeginBulkUpdate())
			{
				// Clear and re-populate
				ClearItems();

				foreach (TDataType item in CollectionsMarshal.AsSpan(items))
				{
					Items.Add(item); // suppressed notification
				}
			}
		}
		finally
		{
			_ = LoadingMeowTex.Release();
		}
	}

	/// <summary>
	/// Releases all resources used by the incremental collection.
	/// </summary>
	public void Dispose()
	{
		if (!_isDisposed)
		{
			// The semaphore is the only unmanaged resource here that we created
			LoadingMeowTex.Dispose();
			_isDisposed = true;
		}
	}

	// ISupportIncrementalLoading contract used by XAML controls
	bool ISupportIncrementalLoading.HasMoreItems => !_loadsSuspended && HasAdditionalItems;

	// Force a complete logical reset after external reordering (e.g., a global sort of the backing source list).
	// Clears current items, resets paging counters, marks additional items available,
	// then immediately loads the first page so UI shows fresh "page 1" post-sort.
	// Safe to call from UI thread; avoids deadlock by NOT calling LoadAdditionalItemsAsync (which re-acquires the semaphore).
	public async Task ForceReloadAsync()
	{
		// Serialize with any other load/refresh/reload operations.
		await LoadingMeowTex.WaitAsync();
		try
		{
			// Check if disposed while waiting for the semaphore
			if (_isDisposed) return;

			// Reset paging & state.
			ActivePageIndex = 0;
			HasAdditionalItems = true;
			bool hadItems = Count > 0;

			// If the collection had items, clear it atomically and notify listeners.
			if (hadItems)
			{
				using (BeginBulkUpdate())
				{
					ClearItems();
				}
			}

			// Prepare for manual first-page load
			_ = LoadDataInternal();
		}
		finally
		{
			_ = LoadingMeowTex.Release();
		}
	}

	/// <summary>
	/// Updates the backing source list under the collection's lock.
	/// This ensures no incremental loads occur while the list is being cleared or modified.
	/// </summary>
	internal async Task UpdateSourceCollectionAsync(IEnumerable<TDataType> newItems)
	{
		await LoadingMeowTex.WaitAsync();
		try
		{
			if (_isDisposed) return;

			// Safe to modify sourceList here because LoadDataInternal cannot run concurrently.
			sourceList.Clear();
			sourceList.AddRange(newItems);
		}
		finally
		{
			_ = LoadingMeowTex.Release();
		}
	}
}
