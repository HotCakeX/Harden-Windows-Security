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
using System.ComponentModel;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml.Data;
using Windows.Foundation;

#if HARDEN_SYSTEM_SECURITY
using HardenSystemSecurity;
#endif

namespace AppControlManager.Others;

/// <summary>
/// Generic incremental collection for loading items in pages with filtering support.
/// Uses memory-mapped files for efficient large file handling.
/// https://learn.microsoft.com/windows/uwp/debug-test-perf/listview-and-gridview-data-optimization#incremental-data-virtualization
/// </summary>
/// <typeparam name="T">The type of items in the collection.</typeparam>
internal sealed partial class IncrementalCollection<T>(
	Func<Task<IFileDataProvider>> dataProviderFactory,
	Func<string, string, bool> filterPredicate,
	Func<string, T> itemFactory,
	int pageSize) : ObservableCollection<T>, ISupportIncrementalLoading, INotifyPropertyChanged, IDisposable
{

	internal static async Task CollectGarbageAggressively()
	{
		await Task.Run(() =>
		{
			for (int i = 0; i < 3; i++)
			{
				GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true);
				GC.WaitForPendingFinalizers();
				GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true);

				// Small delay to allow memory to be released
				Thread.Sleep(15);
			}

			// Compact the Large Object Heap to ensure big strings are released immediately
			GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
			GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true);
			GC.WaitForPendingFinalizers();
			GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true);
		});
	}

	/// <summary>
	/// File data provider for streaming access
	/// </summary>
	private IFileDataProvider? _dataProvider;

	/// <summary>
	/// Store indices of filtered lines instead of the actual lines to save memory.
	/// </summary>
	private readonly List<int> _filteredIndices = [];

	/// <summary>
	/// Thread synchronization object to protect shared state from concurrent access
	/// </summary>
	private readonly Lock _lockObject = new();

	/// <summary>
	/// Semaphore to ensure only one filter operation can run at a time
	/// </summary>
	private readonly SemaphoreSlim _filterSemaphore = new(1, 1);

	/// <summary>
	/// Semaphore to ensure only one load-more operation can run at a time
	/// </summary>
	private readonly SemaphoreSlim _loadMoreSemaphore = new(1, 1);

	/// <summary>
	/// Current data provider factory - can be updated to load new data
	/// </summary>
	private Func<Task<IFileDataProvider>> _currentDataProviderFactory = dataProviderFactory;

	/// <summary>
	/// Track the current index position in the filtered data for UI display
	/// </summary>
	private int _currentUIIndex;

	/// <summary>
	/// Flag indicating whether there are more items available to load for the UI
	/// </summary>
	private bool _hasMoreItems;

	/// <summary>
	/// Flag indicating whether a load operation is currently in progress
	/// </summary>
	private bool _busy;

	/// <summary>
	/// Flag indicating whether the initial data loading from source has completed
	/// </summary>
	private bool _fileLoaded;

	/// <summary>
	/// Cancellation token source for canceling filter operations when new ones start
	/// </summary>
	private CancellationTokenSource? _filterCancellationTokenSource;

	/// <summary>
	/// Flag indicating whether the object has been disposed to prevent further operations
	/// </summary>
	private bool _disposed;

	/// <summary>
	/// Atomic counter to track filter operation IDs and prevent race conditions
	/// </summary>
	private volatile int _filterOperationId;

	/// <summary>
	/// Atomic flag indicating whether a filtering operation is currently in progress
	/// </summary>
	private volatile bool _isFilteringInProgress;

	/// <summary>
	/// Event raised when loading state changes.
	/// </summary>
	internal event EventHandler<bool>? LoadingStateChanged;

	/// <summary>
	/// Gets a value indicating whether there are more items to load.
	/// </summary>
	public bool HasMoreItems
	{
		get
		{
			lock (_lockObject)
			{
				return _hasMoreItems && !_isFilteringInProgress;
			}
		}
		private set
		{
			bool changed = false;

			lock (_lockObject)
			{
				if (_hasMoreItems != value)
				{
					_hasMoreItems = value;
					changed = true;
				}
			}

			if (changed)
			{
				OnPropertyChanged(nameof(HasMoreItems));
			}
		}
	}

	/// <summary>
	/// Updates the data provider factory to load new data.
	/// </summary>
	/// <param name="newDataProviderFactory">The new data provider factory.</param>
	internal void UpdateDataProviderFactory(Func<Task<IFileDataProvider>> newDataProviderFactory)
	{
		lock (_lockObject)
		{
			_currentDataProviderFactory = newDataProviderFactory;
		}
	}

	/// <summary>
	/// Raises the PropertyChanged event.
	/// </summary>
	/// <param name="propertyName">The name of the property that changed.</param>
	private void OnPropertyChanged(string propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}

	/// <summary>
	/// Occurs when a property value changes.
	/// </summary>
	public new event PropertyChangedEventHandler? PropertyChanged;

	/// <summary>
	/// Raises the LoadingStateChanged event.
	/// </summary>
	/// <param name="isLoading">Whether loading is currently active.</param>
	private void OnLoadingStateChanged(bool isLoading)
	{
		LoadingStateChanged?.Invoke(this, isLoading);
	}

	/// <summary>
	/// Forces property change notification and updates the UI state.
	/// </summary>
	private void ForceUIStateUpdate()
	{
		OnPropertyChanged(nameof(HasMoreItems));
	}

	/// <summary>
	/// Immediately clears all data and UI items to free memory aggressively.
	/// </summary>
	internal async Task ClearAllData()
	{
		// Cancel any ongoing operations first
		if (_filterCancellationTokenSource is not null)
		{
			await _filterCancellationTokenSource.CancelAsync();
			_filterCancellationTokenSource.Dispose();
			_filterCancellationTokenSource = null;
		}

		// Clear UI items immediately on the UI thread
		if (App.MainWindow?.DispatcherQueue.HasThreadAccess == true)
		{
			Clear();
		}
		else
		{
			_ = (App.MainWindow?.DispatcherQueue.TryEnqueue(Clear));
		}

		// Clear all internal data structures with aggressive memory management
		lock (_lockObject)
		{
			// Dispose the data provider
			_dataProvider?.Dispose();
			_dataProvider = null;

			// Clear and trim filtered indices
			_filteredIndices.Clear();
			_filteredIndices.TrimExcess();

			// Reset all state
			_currentUIIndex = 0;
			_hasMoreItems = false;
			_busy = false;
			_fileLoaded = false;
			_isFilteringInProgress = false;
			_filterOperationId = 0;
		}

		await CollectGarbageAggressively();
	}

	/// <summary>
	/// Loads the data content asynchronously in the background.
	/// </summary>
	/// <returns>A task representing the asynchronous operation.</returns>
	internal async Task LoadDataAsync()
	{
		if (_disposed)
			return;

		OnLoadingStateChanged(true);

		try
		{
			await Task.Run(async () =>
			{
				try
				{
					lock (_lockObject)
					{
						// Dispose previous provider
						_dataProvider?.Dispose();
						_dataProvider = null;

						// Clear any previously filtered indices
						_filteredIndices.Clear();
						_fileLoaded = false;
						_currentUIIndex = 0;
						_hasMoreItems = false;
						_busy = false;
						_isFilteringInProgress = false;
						_filterOperationId = 0;
					}

					// Create new data provider
					IFileDataProvider dataProvider = await _currentDataProviderFactory();

					lock (_lockObject)
					{
						if (_disposed)
						{
							dataProvider.Dispose();
							return;
						}

						_dataProvider = dataProvider;

						// Initially, all indices are included (no filter applied)
						int lineCount = _dataProvider.LineCount;
						for (int i = 0; i < lineCount; i++)
						{
							_filteredIndices.Add(i);
						}

						_fileLoaded = true;
						_currentUIIndex = 0;
						_busy = false;
						_isFilteringInProgress = false;
					}

					HasMoreItems = _filteredIndices.Count > 0;
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
				}
			});

			if (HasMoreItems && !_disposed)
			{
				_ = await LoadMoreItemsAsync((uint)pageSize);
			}
		}
		finally
		{
			OnLoadingStateChanged(false);
		}
	}

	/// <summary>
	/// Applies a filter to the loaded lines and resets the UI display.
	/// </summary>
	/// <param name="filter">The filter text to apply. If null or empty, no filter is applied.</param>
	/// <returns>A task representing the asynchronous operation.</returns>
	internal async Task ApplyFilterAsync(string? filter)
	{
		if (!_fileLoaded || _disposed)
			return;

		await _filterSemaphore.WaitAsync();

		try
		{
			int currentOperationId = Interlocked.Increment(ref _filterOperationId);

			lock (_lockObject)
			{
				_isFilteringInProgress = true;
				_busy = false;
			}

			if (_filterCancellationTokenSource is not null)
			{
				await _filterCancellationTokenSource.CancelAsync();
				_filterCancellationTokenSource.Dispose();
			}

			_filterCancellationTokenSource = new CancellationTokenSource();
			CancellationToken cancellationToken = _filterCancellationTokenSource.Token;

			OnLoadingStateChanged(true);

			try
			{
				List<int> newFilteredIndices = [];

				await Task.Run(() =>
				{
					if (cancellationToken.IsCancellationRequested || _disposed)
						return;

					if (currentOperationId != _filterOperationId)
						return;

					string normalizedFilter = (filter ?? string.Empty).Trim();

					lock (_lockObject)
					{
						if (_dataProvider == null)
							return;

						int lineCount = _dataProvider.LineCount;

						if (string.IsNullOrWhiteSpace(normalizedFilter))
						{
							for (int i = 0; i < lineCount; i++)
							{
								newFilteredIndices.Add(i);
							}
						}
						else
						{
							for (int i = 0; i < lineCount; i++)
							{
								if (cancellationToken.IsCancellationRequested)
									break;

								string line = _dataProvider.GetLine(i);
								if (filterPredicate(line, normalizedFilter))
								{
									newFilteredIndices.Add(i);
								}
							}
						}
					}
				}, cancellationToken);

				if (cancellationToken.IsCancellationRequested || _disposed || currentOperationId != _filterOperationId)
					return;

				bool hasItems = false;

				lock (_lockObject)
				{
					if (currentOperationId == _filterOperationId)
					{
						_filteredIndices.Clear();
						_filteredIndices.AddRange(newFilteredIndices);
						_currentUIIndex = 0;
						_busy = false;
						hasItems = _filteredIndices.Count > 0;
						_hasMoreItems = hasItems;
						_isFilteringInProgress = false;
					}
				}

				if (currentOperationId == _filterOperationId)
				{
					Clear();
					ForceUIStateUpdate();

					if (hasItems && !cancellationToken.IsCancellationRequested && !_disposed)
					{
						_ = await LoadMoreItemsAsync((uint)pageSize);
					}
				}
			}
			catch (OperationCanceledException)
			{
				// Expected when filter is cancelled
			}
			finally
			{
				lock (_lockObject)
				{
					if (currentOperationId == _filterOperationId)
					{
						_isFilteringInProgress = false;
						_busy = false;
					}
				}

				OnLoadingStateChanged(false);
				ForceUIStateUpdate();
			}
		}
		finally
		{
			try
			{
				if (!_disposed)
				{
					_ = _filterSemaphore.Release();
				}
			}
			catch (ObjectDisposedException)
			{
				// Expected during disposal
			}
		}
	}

	/// <summary>
	/// Loads more items asynchronously for the UI.
	/// </summary>
	/// <param name="count">The number of items to load.</param>
	/// <returns>A task that represents the asynchronous load operation.</returns>
	public IAsyncOperation<LoadMoreItemsResult> LoadMoreItemsAsync(uint count)
	{
		return AsyncInfo.Run(async (cancellationToken) =>
		{
			if (_disposed)
			{
				return new LoadMoreItemsResult { Count = 0 };
			}

			await _loadMoreSemaphore.WaitAsync(cancellationToken);

			try
			{
				bool canLoad = false;

				lock (_lockObject)
				{
					canLoad = !_busy && !_isFilteringInProgress && _fileLoaded && _filteredIndices.Count > 0 && _currentUIIndex < _filteredIndices.Count && _dataProvider != null;

					if (canLoad)
					{
						_busy = true;
					}
				}

				if (!canLoad)
				{
					return new LoadMoreItemsResult { Count = 0 };
				}

				try
				{
					uint actualCount = 0;
					List<T> itemsToAdd = [];
					bool hasMore = false;

					await Task.Run(() =>
					{
						lock (_lockObject)
						{
							if (_busy && !_isFilteringInProgress && _fileLoaded && _dataProvider != null)
							{
								int itemsToLoad = Math.Min((int)count, pageSize);
								int remainingItems = _filteredIndices.Count - _currentUIIndex;
								itemsToLoad = Math.Min(itemsToLoad, remainingItems);

								if (itemsToLoad > 0)
								{
									for (int i = 0; i < itemsToLoad; i++)
									{
										if (cancellationToken.IsCancellationRequested || _disposed)
											break;

										int filteredIndex = _currentUIIndex + i;

										if (filteredIndex >= _filteredIndices.Count)
											break;

										int lineIndex = _filteredIndices[filteredIndex];
										string line = _dataProvider.GetLine(lineIndex);
										itemsToAdd.Add(itemFactory(line));
										actualCount++;
									}

									_currentUIIndex += (int)actualCount;
									hasMore = _currentUIIndex < _filteredIndices.Count;
									_hasMoreItems = hasMore;
								}
							}
						}
					}, cancellationToken);

					foreach (T item in itemsToAdd)
					{
						if (cancellationToken.IsCancellationRequested || _disposed)
							break;

						Add(item);
					}

					ForceUIStateUpdate();

					return new LoadMoreItemsResult { Count = actualCount };
				}
				finally
				{
					lock (_lockObject)
					{
						_busy = false;
					}
				}
			}
			finally
			{
				try
				{
					if (!_disposed)
					{
						_ = _loadMoreSemaphore.Release();
					}
				}
				catch (ObjectDisposedException)
				{
					// Expected during disposal
				}
			}
		});
	}

	/// <summary>
	/// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
	/// </summary>
	public async void Dispose()
	{
		await Dispose(true);
		GC.SuppressFinalize(this);
	}

	/// <summary>
	/// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
	/// </summary>
	/// <param name="disposing">true if called from Dispose(); false if called from finalizer.</param>
	private async Task Dispose(bool disposing)
	{
		if (!_disposed)
		{
			_disposed = true;

			if (disposing)
			{
				await ClearAllData();

				if (_filterCancellationTokenSource is not null)
				{
					await _filterCancellationTokenSource.CancelAsync();
					_filterCancellationTokenSource.Dispose();
					_filterCancellationTokenSource = null;
				}

				_filterSemaphore?.Dispose();
				_loadMoreSemaphore?.Dispose();
			}
		}
	}
}

/// <summary>
/// Interface for file data providers that can efficiently access large files
/// </summary>
internal interface IFileDataProvider : IDisposable
{
	/// <summary>
	/// Gets the total number of lines in the file
	/// </summary>
	int LineCount { get; }

	/// <summary>
	/// Gets a specific line by index
	/// </summary>
	/// <param name="lineIndex">The zero-based line index</param>
	/// <returns>The line content</returns>
	string GetLine(int lineIndex);
}

/// <summary>
/// Memory-mapped file data provider for efficient large file access
/// </summary>
internal sealed partial class MemoryMappedFileDataProvider : IFileDataProvider
{
	private readonly MemoryMappedFile _mmf;
	private readonly MemoryMappedViewAccessor _accessor;
	private readonly List<long> _lineOffsets;
	private readonly long _fileSize;
	private bool _disposed;

	internal static readonly char[] LineSeparators = ['\r', '\n'];

	public int LineCount => _lineOffsets.Count;

	public MemoryMappedFileDataProvider(string filePath)
	{
		FileInfo fileInfo = new(filePath);
		_fileSize = fileInfo.Length;

		_mmf = MemoryMappedFile.CreateFromFile(filePath, FileMode.Open, "LogFile", _fileSize, MemoryMappedFileAccess.Read);
		_accessor = _mmf.CreateViewAccessor(0, _fileSize, MemoryMappedFileAccess.Read);

		_lineOffsets = [];
		IndexLines();
	}

	private void IndexLines()
	{
		_lineOffsets.Add(0); // First line starts at offset 0

		const int bufferSize = 8192;
		byte[] buffer = new byte[bufferSize];
		long position = 0;

		while (position < _fileSize)
		{
			int bytesToRead = (int)Math.Min(bufferSize, _fileSize - position);
			int bytesRead = _accessor.ReadArray(position, buffer, 0, bytesToRead);

			for (int i = 0; i < bytesRead; i++)
			{
				byte b = buffer[i];
				if (b == '\n')
				{
					long lineStart = position + i + 1;
					if (lineStart < _fileSize)
					{
						_lineOffsets.Add(lineStart);
					}
				}
				else if (b == '\r')
				{
					long lineStart = position + i + 1;
					// Check for \r\n
					if (lineStart < _fileSize && i + 1 < bytesRead && buffer[i + 1] == '\n')
					{
						lineStart++;
						i++; // Skip the \n
					}
					if (lineStart < _fileSize)
					{
						_lineOffsets.Add(lineStart);
					}
				}
			}

			position += bytesRead;
		}
	}

	public string GetLine(int lineIndex)
	{
		if (lineIndex < 0 || lineIndex >= _lineOffsets.Count)
			return string.Empty;

		long startOffset = _lineOffsets[lineIndex];
		long endOffset = lineIndex + 1 < _lineOffsets.Count ? _lineOffsets[lineIndex + 1] : _fileSize;

		// Remove line ending characters from length calculation
		long length = endOffset - startOffset;
		if (length > 0)
		{
			// Check for line endings and adjust length
			byte lastByte = _accessor.ReadByte(endOffset - 1);
			if (lastByte == '\n')
			{
				length--;
				if (length > 0)
				{
					byte secondLastByte = _accessor.ReadByte(endOffset - 2);
					if (secondLastByte == '\r')
					{
						length--;
					}
				}
			}
			else if (lastByte == '\r')
			{
				length--;
			}
		}

		if (length <= 0)
			return string.Empty;

		byte[] lineBytes = new byte[length];
		_ = _accessor.ReadArray(startOffset, lineBytes, 0, (int)length);

		return Encoding.UTF8.GetString(lineBytes);
	}

	public void Dispose()
	{
		if (!_disposed)
		{
			_accessor?.Dispose();
			_mmf?.Dispose();
			_disposed = true;
		}
	}
}

/// <summary>
/// Stream-based file data provider for actively written log files
/// </summary>
internal sealed partial class StreamBasedFileDataProvider : IFileDataProvider
{
	private readonly string _filePath;
	private readonly List<string> _lines;
	private bool _disposed;

	internal static readonly char[] LineSeparators = ['\r', '\n'];

	public int LineCount => _lines.Count;

	public StreamBasedFileDataProvider(string filePath)
	{
		_filePath = filePath;
		_lines = [];
		LoadLines();
	}

	private void LoadLines()
	{
		try
		{
			using FileStream stream = new(
				_filePath,
				FileMode.Open,
				FileAccess.Read,
				FileShare.ReadWrite,
				bufferSize: 4096,
				useAsync: false);
			using StreamReader reader = new(stream, Encoding.UTF8);

			string? line;
			while ((line = reader.ReadLine()) != null)
			{
				_lines.Add(line);
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	public string GetLine(int lineIndex)
	{
		if (lineIndex < 0 || lineIndex >= _lines.Count)
			return string.Empty;

		return _lines[lineIndex];
	}

	public void Dispose()
	{
		if (!_disposed)
		{
			_lines.Clear();
			_disposed = true;
		}
	}
}

/// <summary>
/// Empty file data provider for initialization
/// </summary>
internal sealed partial class EmptyFileDataProvider : IFileDataProvider
{
	public int LineCount => 0;

	public string GetLine(int lineIndex) => string.Empty;

	public void Dispose()
	{
		// Nothing to dispose
	}
}
