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

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Common.Collections;
using Microsoft.UI.Xaml.Data;
using Windows.Foundation;

#pragma warning disable CA1812

namespace AppControlManager.IncrementalCollection;

internal sealed class GenericIncrementalCollection<TDataSource, TDataType> : ObservableCollection<TDataType>,
	 ISupportIncrementalLoading, IDisposable
	 where TDataSource : IIncrementalSource<TDataType>
{
	private readonly SemaphoreSlim LoadingMeowTex = new(1);
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
	/// Data source provider for incremental loading operations.
	/// </summary>
	private TDataSource DataProvider { get; }

	/// <summary>
	/// Number of items to load per page during incremental loading.
	/// </summary>
	private int PageSize { get; }

	/// <summary>
	/// The current page index for data loading operations.
	/// </summary>
	private int ActivePageIndex { get; set; }

	private bool _isCurrentlyLoading;
	private bool _hasAdditionalItems;
	private CancellationToken _activeCancellationToken;
	private bool _shouldRefreshAfterLoad;

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
				OnPropertyChanged(new PropertyChangedEventArgs(nameof(IsCurrentlyLoading)));

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
	/// </summary>
	internal bool HasAdditionalItems
	{
		get
		{
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

	/// <summary>
	/// Creates a new instance of the incremental collection.
	/// </summary>
	internal GenericIncrementalCollection(TDataSource dataProvider, int pageSize = 20, Action? onLoadingStarted = null, Action? onLoadingCompleted = null, Action<Exception>? onLoadingError = null)
	{
		ArgumentNullException.ThrowIfNull(dataProvider);

		DataProvider = dataProvider;

		OnLoadingStarted = onLoadingStarted;
		OnLoadingCompleted = onLoadingCompleted;
		OnLoadingError = onLoadingError;

		PageSize = pageSize;
		_hasAdditionalItems = true;
	}

	/// <summary>
	/// Triggers incremental loading from the UI. Need to be public to satisfy the Interface requirement.
	/// </summary>
	public IAsyncOperation<LoadMoreItemsResult> LoadMoreItemsAsync(uint itemCount)
		=> LoadAdditionalItemsAsync(itemCount, new CancellationToken(false)).AsAsyncOperation();

	/// <summary>
	/// Clears the collection and reloads data from the beginning
	/// </summary>
	internal Task RefreshDataAsync()
	{
		if (IsCurrentlyLoading)
		{
			_shouldRefreshAfterLoad = true;
		}
		else
		{
			int previousItemCount = Count;
			Clear();
			ActivePageIndex = 0;
			HasAdditionalItems = true;

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
	private async Task<IEnumerable<TDataType>> LoadPageDataAsync(int requestedItemCount, CancellationToken cancellationToken)
	{
		IEnumerable<TDataType> loadedItems = await DataProvider.GetPagedItemsAsync(ActivePageIndex, requestedItemCount, cancellationToken)
			.ContinueWith(
				taskResult =>
				{
					if (taskResult.IsFaulted)
					{
						throw taskResult.Exception!;
					}

					if (taskResult.IsCompletedSuccessfully)
					{
						ActivePageIndex += 1;
					}

					return taskResult.Result;
				}, cancellationToken, TaskContinuationOptions.None, TaskScheduler.Default);

		return loadedItems;
	}

	private async Task<LoadMoreItemsResult> LoadAdditionalItemsAsync(uint itemCount, CancellationToken cancellationToken)
	{
		uint loadedItemCount = 0;
		_activeCancellationToken = cancellationToken;

		await LoadingMeowTex.WaitAsync(cancellationToken);
		try
		{
			if (!_activeCancellationToken.IsCancellationRequested)
			{
				IEnumerable<TDataType>? retrievedData = null;
				try
				{
					IsCurrentlyLoading = true;
					// Use the requested count, or fall back to PageSize if itemCount is 0
					int itemsToRetrieve = itemCount == 0 ? PageSize : (int)itemCount;
					retrievedData = await LoadPageDataAsync(itemsToRetrieve, _activeCancellationToken);
				}
				catch (OperationCanceledException)
				{
				}
				catch (Exception loadingException) when (OnLoadingError is not null)
				{
					OnLoadingError.Invoke(loadingException);
				}

				if (retrievedData is not null && retrievedData.Any() && !_activeCancellationToken.IsCancellationRequested)
				{
					loadedItemCount = (uint)retrievedData.Count();

					foreach (TDataType dataItem in retrievedData)
					{
						Add(dataItem);
					}
				}
				else
				{
					HasAdditionalItems = false;
				}
			}
		}
		finally
		{
			IsCurrentlyLoading = false;

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
			LoadingMeowTex.Dispose();
			_isDisposed = true;
		}
	}

	bool ISupportIncrementalLoading.HasMoreItems => HasAdditionalItems;
}
