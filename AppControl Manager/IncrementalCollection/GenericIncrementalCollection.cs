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
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Common.Collections;
using Microsoft.UI.Xaml.Data;
using Windows.Foundation;

namespace AppControlManager.IncrementalCollection;

/// <summary>
/// Interface to expose a high-performance bulk replacement operation.
/// Implemented by GenericIncrementalCollection to allow external helpers (e.g. sorting)
/// to replace large datasets with a single Reset notification instead of N per-item events.
/// </summary>
internal interface IBulkUpdatableCollection<T>
{
	/// <summary>
	/// Replaces the entire contents with the supplied items, emitting only a single Reset notification.
	/// </summary>
	/// <param name="items">New ordered items.</param>
	void BulkReplace(IList<T> items);
}

// Exposes a forced full paging reset + initial page reload after external global reorder (e.g., sort).
internal interface IBatchReloadable
{
	Task ForceReloadAsync();
}

/// <summary>
/// Generic, UI-bindable incremental-loading collection.
///
/// Data flow and responsibilities:
/// - Wraps an IIncrementalSource<TDataType> (TDataSource) that knows how to fetch "pages" of data.
/// - Exposes ObservableCollection<TDataType> to XAML (ItemsSource), so UI updates automatically on Add/Clear/Reset.
/// - Implements ISupportIncrementalLoading so a ListView/GridView can request more data on demand (LoadMoreItemsAsync).
/// - Provides bulk update capabilities (IBulkUpdatableCollection) to avoid O(N) change notifications (e.g., on large sorts).
/// - Provides IBatchReloadable.ForceReloadAsync to fully reset paging after global reorder of the underlying logical dataset.
/// - Maintains paging state (ActivePageIndex), "busy" state (IsCurrentlyLoading), and "has more" state (HasAdditionalItems).
/// - Uses a SemaphoreSlim to serialize overlapping load/refresh/reload requests and prevent re-entrancy.
/// </summary>
internal sealed partial class GenericIncrementalCollection<TDataSource, TDataType> : ObservableCollection<TDataType>,
	ISupportIncrementalLoading,
	IDisposable,
	IBulkUpdatableCollection<TDataType>,
	IBatchReloadable
	where TDataSource : IIncrementalSource<TDataType>
{
	// Single concurrency guard for all operations that mutate this collection or paging state.
	// Ensures that UI-triggered incremental loads and programmatic refresh/reset cannot overlap.
	private readonly SemaphoreSlim LoadingMeowTex = new(1);

	// Prevents the control from loading more items while an external filter is active.
	// When true, ISupportIncrementalLoading.HasMoreItems reports false and LoadMoreItemsAsync becomes a no-op.
	private bool _loadsSuspended;

	private bool _isDisposed;

	/// <summary>
	/// Callback that executes when data loading starts.
	/// </summary>
	internal Action? OnLoadingStarted { get; set; }

	/// <summary>
	/// Callback that executes when data loading completes.
	/// </summary>
	internal Action? OnLoadingCompleted { get; set; }

	/// <summary>
	/// Callback that executes when an error occurs during data loading.
	/// </summary>
	internal Action<Exception>? OnLoadingError { get; set; }

	/// <summary>
	/// Raised once per incremental page after items are added to this collection.
	/// Useful for UI code to react to batch completions (e.g., sizing, snapping).
	/// </summary>
	internal event Action<IReadOnlyList<TDataType>>? ItemsBatchAdded;

	/// <summary>
	/// Raised when RefreshDataAsync clears the collection to allow consumers to reset UI state.
	/// </summary>
	internal event Action? CollectionCleared;

	/// <summary>
	/// Data source provider for incremental loading operations. Supplies the "paged" data.
	/// </summary>
	private TDataSource DataProvider { get; }

	/// <summary>
	/// Number of items to load per page during incremental loading.
	/// If the UI requests 0, we fall back to this value.
	/// </summary>
	private int PageSize { get; }

	/// <summary>
	/// The current page index for data loading operations.
	/// Starts at 0; after each successful fetch we advance by 1.
	/// </summary>
	private int ActivePageIndex { get; set; }

	/// <summary>
	/// Mirrors "Is busy" status; toggles OnLoadingStarted/OnLoadingCompleted when changed.
	/// </summary>
	private bool _isCurrentlyLoading;

	/// <summary>
	/// Tracks whether there are more pages available (true until a fetch returns no items or a terminal failure occurs).
	/// </summary>
	private bool _hasAdditionalItems;

	/// <summary>
	/// The CancellationToken supplied by the caller of the current LoadMore call; used to early-exit checks.
	/// </summary>
	private CancellationToken _activeCancellationToken;

	/// <summary>
	/// When a refresh is requested during an active load, we defer the refresh and execute it when the load completes.
	/// </summary>
	private bool _shouldRefreshAfterLoad;

	// Bulk update suppression fields (keep them private & lightweight for AOT friendliness)
	// During BulkReplace we suppress per-item notifications and coalesce to a single Reset.
	private bool _suppressNotifications;
	private int _deferredChangeCount;

	/// <summary>
	/// Value indicating whether data is currently being loaded.
	/// </summary>
	internal bool IsCurrentlyLoading
	{
		get
		{
			return _isCurrentlyLoading;
		}

		private set
		{
			if (value != _isCurrentlyLoading)
			{
				_isCurrentlyLoading = value;

				// Notify bindings that depend on IsCurrentlyLoading
				OnPropertyChanged(new PropertyChangedEventArgs(nameof(IsCurrentlyLoading)));

				// Fire lifecycle callbacks so consumers can update UI affordances.
				if (_isCurrentlyLoading)
				{
					OnLoadingStarted?.Invoke();
				}
				else
				{
					OnLoadingCompleted?.Invoke();
				}
			}
		}
	}

	/// <summary>
	/// Value indicating whether additional items are available for loading.
	/// When false, the ListView stops asking for more data.
	/// </summary>
	internal bool HasAdditionalItems
	{
		get
		{
			// Once canceled, we report "no more" for the current request path to prevent further work.
			if (_activeCancellationToken.IsCancellationRequested)
			{
				return false;
			}

			return _hasAdditionalItems;
		}

		private set
		{
			if (value != _hasAdditionalItems)
			{
				_hasAdditionalItems = value;
				OnPropertyChanged(new PropertyChangedEventArgs(nameof(HasAdditionalItems)));
			}
		}
	}

	// Toggle incremental loading. When suspended, the control reports no more items and LoadMoreItemsAsync is a no-op.
	internal void SuspendLoads(bool suspend)
	{
		_loadsSuspended = suspend;

		// Reflect the suspension in HasAdditionalItems reporting so the control stops asking for more data.
		// When resuming, we mark "more items" available; the first subsequent load will determine actual availability.
		if (suspend)
		{
			HasAdditionalItems = false;
		}
		else
		{
			HasAdditionalItems = true;
		}
	}

	/// <summary>
	/// Creates a new instance of the incremental collection.
	/// </summary>
	/// <param name="dataProvider">The backing page provider (IIncrementalSource).</param>
	/// <param name="pageSize">Default page size when the UI does not specify itemCount.</param>
	/// <param name="onLoadingStarted">Optional start callback.</param>
	/// <param name="onLoadingCompleted">Optional completion callback.</param>
	/// <param name="onLoadingError">Optional error callback.</param>
	internal GenericIncrementalCollection(TDataSource dataProvider, int pageSize = 20, Action? onLoadingStarted = null, Action? onLoadingCompleted = null, Action<Exception>? onLoadingError = null)
	{
		ArgumentNullException.ThrowIfNull(dataProvider);

		DataProvider = dataProvider;

		OnLoadingStarted = onLoadingStarted;
		OnLoadingCompleted = onLoadingCompleted;
		OnLoadingError = onLoadingError;

		PageSize = pageSize;
		_hasAdditionalItems = true; // Assume more pages until proven otherwise.
	}

	/// <summary>
	/// Triggers incremental loading from the UI.
	/// </summary>
	/// <remarks>
	/// The XAML framework calls this via ISupportIncrementalLoading when the control decides to fetch more items.
	/// We forward to our Task-based pipeline and adapt to WinRT's IAsyncOperation.
	/// </remarks>
	public IAsyncOperation<LoadMoreItemsResult> LoadMoreItemsAsync(uint itemCount)
		=> LoadAdditionalItemsAsync(itemCount, new CancellationToken(false)).AsAsyncOperation();

	/// <summary>
	/// Clears the collection and reloads data from the beginning
	/// </summary>
	/// <remarks>
	/// If a load is ongoing, we set a flag to refresh at the end (avoid re-entrancy).
	/// If no load is ongoing, we clear immediately, reset paging, notify listeners, and start a first page load
	/// when there were previously no items (so the UI gets content asap).
	/// </remarks>
	internal Task RefreshDataAsync()
	{
		if (IsCurrentlyLoading)
		{
			// Defer refresh until the current load completes.
			_shouldRefreshAfterLoad = true;
		}
		else
		{
			int previousItemCount = Count;

			// Clear everything and reset paging state.
			Clear();
			ActivePageIndex = 0;
			HasAdditionalItems = true;

			// Notify listeners (e.g., controllers) so they can reset UI state anchored to the old content.
			CollectionCleared?.Invoke();

			// If there were no items prior to the refresh, kick off an immediate first page load.
			// If there were items, the UI will likely trigger the next load automatically based on virtualization.
			if (previousItemCount == 0)
			{
				return LoadMoreItemsAsync(0).AsTask();
			}
		}

		return Task.CompletedTask;
	}

	/// <summary>
	/// Executes the actual data loading operation.
	/// </summary>
	/// <param name="requestedItemCount">Number of items to fetch for this page.</param>
	/// <param name="cancellationToken">Cancellation token passed from the outer load request.</param>
	/// <returns>Materialized page items.</returns>
	private async Task<IEnumerable<TDataType>> LoadPageDataAsync(int requestedItemCount, CancellationToken cancellationToken)
	{
		// Fetch next page directly; the constraint guarantees this method exists.
		IEnumerable<TDataType> page = await DataProvider.GetPagedItemsAsync(ActivePageIndex, requestedItemCount, cancellationToken);

		// Only advance page index if not cancelled.
		if (!cancellationToken.IsCancellationRequested)
		{
			ActivePageIndex += 1;
		}

		return page;
	}

	/// <summary>
	/// Core incremental load pipeline that handles serialization, paging math, item addition, and notifications.
	/// </summary>
	private async Task<LoadMoreItemsResult> LoadAdditionalItemsAsync(uint itemCount, CancellationToken cancellationToken)
	{
		uint loadedItemCount = 0;
		_activeCancellationToken = cancellationToken;

		// Serialize with any other load/refresh/reload work.
		await LoadingMeowTex.WaitAsync(cancellationToken);
		try
		{
			if (_loadsSuspended)
			{
				// Do nothing while suspended; the Reset/replace from the filter will keep UI consistent.
				// loadedItemCount remains 0; finally will release the semaphore.
				return new LoadMoreItemsResult { Count = 0 };
			}

			if (!_activeCancellationToken.IsCancellationRequested)
			{
				IEnumerable<TDataType>? retrievedData = null;
				try
				{
					IsCurrentlyLoading = true;

					int itemsToRetrieve = PageSize;

					// Ask the provider for the next page.
					retrievedData = await LoadPageDataAsync(itemsToRetrieve, _activeCancellationToken);
				}
				catch (OperationCanceledException)
				{
					// Cancellation is part of normal control flow; swallow to finish gracefully.
				}
				catch (Exception loadingException) when (OnLoadingError is not null)
				{
					// Surface non-cancellation errors to the host so it can show error UI or log.
					OnLoadingError.Invoke(loadingException);
				}

				// If we got data and we're still not canceled, append to the collection and notify as a batch.
				if (retrievedData is not null && retrievedData.Any() && !_activeCancellationToken.IsCancellationRequested)
				{
					// Ensure a single materialization so we can add items and raise one Reset safely (reentrancy-safe).
					List<TDataType> batch = retrievedData as List<TDataType> ?? retrievedData.ToList();

					loadedItemCount = (uint)batch.Count;

					// Suppress per-item notifications to avoid reentrancy during incremental loads.
					using (BeginBulkUpdate())
					{
						for (int i = 0; i < batch.Count; i++)
						{
							// Add will be suppressed; a single Reset is emitted when the scope disposes.
							Add(batch[i]);
						}
					}

					// One-shot notification for "a page just arrived", enabling smarter UI reactions.
					ItemsBatchAdded?.Invoke(batch.AsReadOnly());
				}
				else
				{
					// No data returned (or canceled): mark as complete so the control won't keep requesting.
					HasAdditionalItems = false;
				}
			}
		}
		finally
		{
			// Always flip the busy flag at the end of this serialized section.
			IsCurrentlyLoading = false;

			// If a refresh was requested during the load, execute it now (outside of the inner try/catch to honor errors).
			if (_shouldRefreshAfterLoad)
			{
				_shouldRefreshAfterLoad = false;
				await RefreshDataAsync();
			}

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
	/// (e.g., a global sort over the backing list) and the bound collection should reflect it atomically.
	/// </remarks>
	public void BulkReplace(IList<TDataType> items)
	{
		// Serialize this replace with incremental loads, refreshes, and other replaces.
		// Using the same semaphore guarantees no overlapping mutations (prevents reentrancy exceptions).
		LoadingMeowTex.Wait();
		try
		{
			// Suppress per-item notifications; emit a single Reset at the end.
			using (BeginBulkUpdate())
			{
				// Clear existing items (suppressed notification)
				ClearItems();

				// Add new ordered items (suppressed notifications)
				if (items is not null && items.Count > 0)
				{
					for (int i = 0; i < items.Count; i++)
					{
						InsertItem(Count, items[i]); // suppressed notification
					}
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
	private sealed partial class BulkUpdateScope : IDisposable
	{
		private GenericIncrementalCollection<TDataSource, TDataType>? _owner;

		internal BulkUpdateScope(GenericIncrementalCollection<TDataSource, TDataType> owner)
		{
			_owner = owner;
		}

		public void Dispose()
		{
			if (_owner is null)
			{
				return;
			}

			GenericIncrementalCollection<TDataSource, TDataType> local = _owner;
			_owner = null;

			// End suppression and emit a single Reset if we performed any changes while suppressed.
			if (local._suppressNotifications)
			{
				local._suppressNotifications = false;

				if (local._deferredChangeCount > 0)
				{
					local._deferredChangeCount = 0;

					// Emit a single Reset to notify UI of full content change.
					EmitReset(local);
				}
			}

			static void EmitReset(GenericIncrementalCollection<TDataSource, TDataType> collection)
			{
				// The typical ObservableCollection reset pattern:
				// - Notify Count and indexer changed so bindings refresh.
				collection.OnPropertyChanged(new PropertyChangedEventArgs("Count"));
				collection.OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));

				// - Raise the Reset change event. We call the base method through a helper to avoid suppression checks.
				collection.baseRaiseReset();
			}
		}
	}

	// Helper to invoke base OnCollectionChanged for a Reset without re-entering suppression logic.
	private void baseRaiseReset()
	{
		base.OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
	}

	/// <summary>
	/// Atomically replaces the contents of this collection under the same semaphore used by incremental loads.
	/// This guarantees no mutation overlaps (no "modify during CollectionChanged" reentrancy).
	/// </summary>
	/// <param name="items">The new items to set (may be empty).</param>
	internal async Task ReplaceAllExclusiveAsync(IList<TDataType> items)
	{
		// Serialize with any other load/refresh/replace operations using the same semaphore.
		await LoadingMeowTex.WaitAsync();
		try
		{
			// Suppress per-item notifications; emit a single Reset at the end.
			using (BeginBulkUpdate())
			{
				// Clear and re-populate
				ClearItems();

				if (items is not null && items.Count > 0)
				{
					for (int i = 0; i < items.Count; i++)
					{
						InsertItem(Count, items[i]); // suppressed notification
					}
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
		Dispose(true);
		GC.SuppressFinalize(this);
	}

	/// <summary>
	/// Releases all resources used by the incremental collection.
	/// </summary>
	private void Dispose(bool disposing)
	{
		if (!_isDisposed && disposing)
		{
			// The semaphore is the only unmanaged resource here that we created; dispose it.
			LoadingMeowTex.Dispose();
			_isDisposed = true;
		}
	}

	// ISupportIncrementalLoading contract used by XAML controls
	bool ISupportIncrementalLoading.HasMoreItems => !_loadsSuspended && HasAdditionalItems;

	// Force a complete logical reset after external reordering (e.g., a global sort of the backing source list).
	// Clears current items, resets paging counters, marks additional items available, fires CollectionCleared,
	// then immediately loads the first page so UI shows fresh "page 1" post-sort.
	// Safe to call from UI thread; avoids deadlock by NOT calling LoadAdditionalItemsAsync (which re-acquires the semaphore).
	public async Task ForceReloadAsync()
	{
		// Serialize with any other load/refresh operations.
		await LoadingMeowTex.WaitAsync();
		try
		{
			// Reset paging & state.
			ActivePageIndex = 0;
			HasAdditionalItems = true;
			bool hadItems = Count > 0;

			// If the collection had items, clear it atomically and notify listeners.
			if (hadItems)
			{
				ClearItems();
				CollectionCleared?.Invoke();
			}

			// Prepare for manual first-page load (mirrors core logic of LoadAdditionalItemsAsync without nested locking).
			_activeCancellationToken = CancellationToken.None;
			IsCurrentlyLoading = true;

			try
			{
				int itemsToRetrieve = PageSize;

				// Fetch the first page under the new ordering.
				IEnumerable<TDataType> retrieved = await LoadPageDataAsync(itemsToRetrieve, _activeCancellationToken);

				if (retrieved is not null)
				{
					List<TDataType> batch = retrieved as List<TDataType> ?? retrieved.ToList();

					if (batch.Count > 0)
					{
						// Populate page 1 items without per-item events; emit a single Reset to avoid reentrancy.
						using (BeginBulkUpdate())
						{
							for (int i = 0; i < batch.Count; i++)
							{
								Add(batch[i]);
							}
						}

						// Let consumers react to "first page loaded" as a whole.
						ItemsBatchAdded?.Invoke(batch.AsReadOnly());
					}
					else
					{
						// No items → no more pages.
						HasAdditionalItems = false;
					}
				}
				else
				{
					HasAdditionalItems = false;
				}
			}
			catch (OperationCanceledException)
			{
				// Treat cancellation as end of data for this cycle.
				HasAdditionalItems = false;
			}
			catch (Exception ex)
			{
				// Forward to error handler if provided; mark no further items to avoid repeated failures.
				OnLoadingError?.Invoke(ex);
				HasAdditionalItems = false;
			}
			finally
			{
				IsCurrentlyLoading = false;
			}
		}
		finally
		{
			_ = LoadingMeowTex.Release();
		}
	}
}
