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
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;

#if HARDEN_WINDOWS_SECURITY
namespace HardenWindowsSecurity.ViewModels;
#endif

#if APP_CONTROL_MANAGER
namespace AppControlManager.ViewModels;
#endif

internal sealed partial class LogsVM : ViewModelBase, IDisposable
{
	private const string LogFilePattern = $"{App.AppName}_Logs_*.txt";
	internal static readonly char[] LineSeparators = ['\r', '\n'];
	private const int PageSize = 50;

	/// <summary>
	/// Cancellation token source for search debouncing.
	/// </summary>
	private CancellationTokenSource? _searchCancellationTokenSource;

	/// <summary>
	/// Semaphore to ensure only one file display operation at a time.
	/// </summary>
	private readonly SemaphoreSlim _displaySemaphore = new(1, 1);

	/// <summary>
	/// Atomic counter to track file display operations and prevent race conditions.
	/// </summary>
	private volatile int _displayOperationId;

	/// <summary>
	/// Track disposal state to prevent double disposal.
	/// </summary>
	private volatile bool _isDisposed;

	/// <summary>
	/// Filter predicate for log lines.
	/// </summary>
	private static readonly Func<string, string, bool> FilterPredicate = static (line, filter) =>
	{
		return line.Contains(filter, StringComparison.OrdinalIgnoreCase);
	};

	/// <summary>
	/// Item factory for log lines.
	/// </summary>
	private static readonly Func<string, LogLine> ItemFactory = static line => new(line);

	/// <summary>
	/// Observable collection of log file paths for the ComboBox.
	/// </summary>
	internal readonly ObservableCollection<string> LogFiles = [];

	/// <summary>
	/// Incremental collection for the ListView.
	/// </summary>
	internal readonly IncrementalCollection<LogLine> LogCollection;

	/// <summary>
	/// The currently selected log file path.
	/// </summary>
	internal string? SelectedLogFile
	{
		get;
		set
		{
			if (SP(ref field, value) && !string.IsNullOrWhiteSpace(value))
			{
				_ = DisplayLogContentAsync(value);
			}
		}
	}

	/// <summary>
	/// The search text for filtering logs.
	/// </summary>
	internal string? SearchText
	{
		get;
		set
		{
			if (SPT(ref field, value))
			{
				_ = UpdateLogDisplayAsync();
			}
		}
	}

	/// <summary>
	/// Indicates whether loading is in progress.
	/// </summary>
	internal bool IsLoading
	{
		get;
		private set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(LoadingVisibility));
			}
		}
	}

	/// <summary>
	/// Visibility for the loading progress ring.
	/// </summary>
	internal Visibility LoadingVisibility => IsLoading ? Visibility.Visible : Visibility.Collapsed;

	/// <summary>
	/// Initializes the LogsVM.
	/// </summary>
	internal LogsVM()
	{
		// Create the incremental collection once with a dummy data provider factory
		LogCollection = new IncrementalCollection<LogLine>(
			() => Task.FromResult<IFileDataProvider>(new EmptyFileDataProvider()),
			FilterPredicate,
			ItemFactory,
			PageSize);

		// Subscribe to loading state changes
		LogCollection.LoadingStateChanged += OnLoadingStateChanged;
	}

	/// <summary>
	/// Loads log file names from the logs directory into the ComboBox.
	/// Only files matching the name pattern are included.
	/// </summary>
	internal void LoadLogFiles()
	{
		try
		{
			// Get files matching the pattern;
			FileInfo[] logFiles = Directory.GetFiles(App.LogsDirectory, LogFilePattern)
				.Select(static f => new FileInfo(f))
				.OrderByDescending(static f => f.CreationTime).ToArray();

			// Clear and fill the ObservableCollection with full file paths.
			LogFiles.Clear();

			for (int i = 0; i < logFiles.Length; i++)
			{
				LogFiles.Add(logFiles[i].FullName);
			}

			// If files were found, select the first one and display its content.
			if (logFiles.Length > 0)
			{
				SelectedLogFile = logFiles[0].FullName;
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ErrorWriter.FormatException(ex));
		}
	}

	/// <summary>
	/// Creates a data provider factory for the specified file path.
	/// Uses StreamBasedFileDataProvider for active log files and MemoryMappedFileDataProvider for inactive files.
	/// </summary>
	/// <param name="filePath">The path to the log file.</param>
	/// <returns>A function that creates a data provider for the file.</returns>
	private static Func<Task<IFileDataProvider>> CreateDataProviderFactory(string filePath)
	{
		return async () =>
		{
			return await Task.Run<IFileDataProvider>(() =>
			{
				try
				{
					// Check if this is the currently active log file being written to
					bool isActiveLogFile = string.Equals(filePath, Logger.LogFileName, StringComparison.OrdinalIgnoreCase);

					if (isActiveLogFile)
					{
						// Use stream-based provider for the active log file
						return new StreamBasedFileDataProvider(filePath);
					}
					else
					{
						// Use memory-mapped provider for inactive log files
						return new MemoryMappedFileDataProvider(filePath);
					}
				}
				catch (Exception ex)
				{
					Logger.Write(ErrorWriter.FormatException(ex));
					return new EmptyFileDataProvider();
				}
			});
		};
	}

	/// <summary>
	/// Runs every time the selected log file changes on the ComboBox.
	/// </summary>
	private async Task DisplayLogContentAsync(string filePath)
	{
		if (_isDisposed) return;

		await _displaySemaphore.WaitAsync();

		try
		{
			if (_isDisposed) return;

			int currentOperationId = Interlocked.Increment(ref _displayOperationId);

			IsLoading = true;

			if (File.Exists(filePath))
			{
				// Perform immediate aggressive memory cleanup for the previous log file
				await LogCollection.ClearAllData();

				// Check if this operation is still current
				if (currentOperationId != _displayOperationId)
				{
					return;
				}

				try
				{
					Func<Task<IFileDataProvider>> dataProviderFactory = CreateDataProviderFactory(filePath);

					// Final check before starting data load
					if (currentOperationId == _displayOperationId)
					{
						// Update the data provider factory and reload data
						LogCollection.UpdateDataProviderFactory(dataProviderFactory);
						await LogCollection.LoadDataAsync();
					}
				}
				catch (Exception ex)
				{
					if (currentOperationId == _displayOperationId)
					{
						Logger.Write(ErrorWriter.FormatException(ex));

						await LogCollection.ClearAllData();
					}
				}
			}
		}
		finally
		{
			_ = _displaySemaphore.Release();

			IsLoading = false;
		}
	}

	/// <summary>
	/// Handles loading state changes from the incremental collection.
	/// </summary>
	private void OnLoadingStateChanged(object? sender, bool isLoading)
	{
		if (_isDisposed) return;

		// Update loading state on UI thread
		_ = App.MainWindow?.DispatcherQueue.TryEnqueue(() =>
		{
			if (!_isDisposed)
			{
				IsLoading = isLoading;
			}
		});
	}

	/// <summary>
	/// Updates the ListView with the current log lines.
	/// If a search term is entered, only lines containing that term (case-insensitive) are displayed.
	/// Uses debouncing to prevent excessive filtering during typing.
	/// </summary>
	private async Task UpdateLogDisplayAsync()
	{
		if (_isDisposed) return;

		try
		{
			// Cancel previous search
			if (_searchCancellationTokenSource is not null)
			{
				await _searchCancellationTokenSource.CancelAsync();
				_searchCancellationTokenSource.Dispose();
			}
			_searchCancellationTokenSource = new CancellationTokenSource();

			CancellationToken cancellationToken = _searchCancellationTokenSource.Token;

			// Debounce the search by waiting 300ms
			await Task.Delay(300, cancellationToken);

			if (cancellationToken.IsCancellationRequested)
				return;

			string? searchText = SearchText?.Trim();
			await LogCollection.ApplyFilterAsync(searchText);
		}
		catch (OperationCanceledException)
		{
			// Expected when search is cancelled
		}
		catch (Exception ex)
		{
			Logger.Write(ErrorWriter.FormatException(ex));
		}
	}

	/// <summary>
	/// Method to handle cleanup of current log collection.
	/// Called when navigating away from the page.
	/// </summary>
	internal async Task CleanupCurrentSession()
	{
		if (_isDisposed) return;

		// Cancel any pending search operations
		if (_searchCancellationTokenSource is not null)
		{
			await _searchCancellationTokenSource.CancelAsync();
			_searchCancellationTokenSource.Dispose();
			_searchCancellationTokenSource = null;
		}

		// Perform immediate aggressive memory cleanup
		await LogCollection.ClearAllData();

		// Reset loading state
		IsLoading = false;

		// Clear search text
		SearchText = string.Empty;
	}

	/// <summary>
	/// Disposes of resources used by the LogsVM.
	/// </summary>
	public void Dispose()
	{
		if (_isDisposed) return;

		_isDisposed = true;

		try
		{
			// Unsubscribe from events to prevent memory leaks
			LogCollection.LoadingStateChanged -= OnLoadingStateChanged;
		}
		catch { }

		// Cancel and dispose search cancellation token source
		if (_searchCancellationTokenSource is not null)
		{
			try
			{
				_searchCancellationTokenSource.Cancel();
				_searchCancellationTokenSource.Dispose();
				_searchCancellationTokenSource = null;
			}
			catch { }
		}

		// Dispose the semaphore
		try
		{
			_displaySemaphore?.Dispose();
		}
		catch { }

		// Dispose the LogCollection
		try
		{
			LogCollection?.Dispose();
		}
		catch { }
	}

	internal async void OpenLogsDirectory()
	{
		try
		{
			await OpenInDefaultFileHandler(App.LogsDirectory);
		}
		catch (Exception ex)
		{
			Logger.Write(ErrorWriter.FormatException(ex));
		}
	}

}
