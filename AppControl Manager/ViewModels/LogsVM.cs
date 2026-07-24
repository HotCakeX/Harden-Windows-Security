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

using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinRT;

#if HARDEN_SYSTEM_SECURITY
namespace HardenSystemSecurity.ViewModels;
#endif

#if APP_CONTROL_MANAGER
namespace AppControlManager.ViewModels;
#endif

internal sealed partial class LogsVM : ViewModelBase, IDisposable
{
	private const string LogFilePattern = $"{Atlas.AppName}_Logs_*.txt";
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
	/// Reference to the ListView control for accessing selected items.
	/// </summary>
	private ListView? LogListView { get; set; }

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
	private static readonly Func<string, string> ItemFactory = static line => line;

	/// <summary>
	/// List of log file paths for the ComboBox.
	/// </summary>
	internal readonly ObservableCollection<FileInfo> LogFiles = [];

	/// <summary>
	/// Incremental collection for the ListView.
	/// </summary>
	internal readonly IncrementalCollection<string> LogCollection;

	/// <summary>
	/// The currently selected log file path.
	/// </summary>
	internal FileInfo? SelectedLogFile
	{
		get; set
		{
			if (SP(ref field, value) && value is not null)
				_ = DisplayLogContentAsync(value);
		}
	}

	/// <summary>
	/// The search text for filtering logs.
	/// </summary>
	internal string? SearchText
	{
		get; set
		{
			if (SPT(ref field, value))
				_ = UpdateLogDisplayAsync();
		}
	}

	/// <summary>
	/// Indicates whether loading is in progress.
	/// </summary>
	internal bool IsLoading
	{
		get; private set
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
		LogCollection = new IncrementalCollection<string>(
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
	internal void LoadLogFiles() => LoadLogFilesCore(preferredSelectedLogFilePath: null);

	/// <summary>
	/// Determines whether the specified log file can be deleted.
	/// The currently active log file is excluded because it may still be in use by the logger.
	/// </summary>
	/// <param name="filePath">The full path of the log file.</param>
	/// <returns><see langword="true"/> when the file can be deleted.</returns>
	internal bool CanDeleteLogFile(string? filePath) => !string.IsNullOrWhiteSpace(filePath) && !string.Equals(filePath, Logger.LogFileName, StringComparison.OrdinalIgnoreCase);

	/// <summary>
	/// Deletes a previously generated log file after confirmation and refreshes the list.
	/// </summary>
	/// <param name="sender">The delete button that carries the selected <see cref="FileInfo"/> in its Tag.</param>
	/// <param name="e">The routed event data.</param>
	internal async void DeleteLogFile_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			if (sender is not Button { Tag: FileInfo logFile })
			{
				return;
			}

			if (!CanDeleteLogFile(logFile.FullName))
			{
				return;
			}

			using ContentDialogV2 dialog = new()
			{
				Title = Atlas.GetStr("WarningTitle"),
				Content = new TextBlock
				{
					Text = $"Delete '{logFile.Name}' from the logs directory? This action cannot be undone.",
					TextWrapping = TextWrapping.WrapWholeWords
				},
				PrimaryButtonText = Atlas.GetStr("DeleteCertificateDialogPrimaryButton"),
				CloseButtonText = Atlas.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Close
			};

			if (await dialog.ShowAsync() is not ContentDialogResult.Primary)
			{
				return;
			}

			string? preferredSelectedLogFilePath = SelectedLogFile is not null &&
				!string.Equals(SelectedLogFile.FullName, logFile.FullName, StringComparison.OrdinalIgnoreCase)
					? SelectedLogFile.FullName
					: null;

			if (File.Exists(logFile.FullName))
			{
				if (SelectedLogFile is not null &&
					string.Equals(SelectedLogFile.FullName, logFile.FullName, StringComparison.OrdinalIgnoreCase))
				{
					SelectedLogFile = null;
					await ClearDisplayedLogDataAsync(resetSearchText: false);
				}

				File.Delete(logFile.FullName);
			}

			LoadLogFilesCore(preferredSelectedLogFilePath);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Loads log file names from the logs directory into the ComboBox.
	/// Only files matching the name pattern are included.
	/// </summary>
	/// <param name="preferredSelectedLogFilePath">A specific log file path to reselect when it still exists.</param>
	private void LoadLogFilesCore(string? preferredSelectedLogFilePath)
	{
		try
		{
			IOrderedEnumerable<FileInfo> logFiles = Directory.GetFiles(Atlas.LogsDirectory, LogFilePattern)
				.Select(static f => new FileInfo(f))
				.OrderByDescending(static f => f.CreationTime);

			LogFiles.Clear();

			foreach (FileInfo logFile in logFiles)
			{
				LogFiles.Add(logFile);
			}

			FileInfo? selectedLogFile = null;

			if (!string.IsNullOrWhiteSpace(preferredSelectedLogFilePath))
			{
				selectedLogFile = LogFiles.FirstOrDefault(logFile =>
					string.Equals(logFile.FullName, preferredSelectedLogFilePath, StringComparison.OrdinalIgnoreCase));
			}

			if (selectedLogFile is null && LogFiles.Count > 0)
			{
				selectedLogFile = LogFiles[0];
			}

			SelectedLogFile = selectedLogFile;

			if (selectedLogFile is null)
			{
				_ = ClearDisplayedLogDataAsync(resetSearchText: true);
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Creates a data provider factory for the specified file path.
	/// Uses StreamBasedFileDataProvider for active log files and MemoryMappedFileDataProvider for inactive files.
	/// </summary>
	/// <param name="filePath">The path to the log file.</param>
	/// <returns>A function that creates a data provider for the file.</returns>
	private static Func<Task<IFileDataProvider>> CreateDataProviderFactory(string filePath) =>
		() => Task.Run<IFileDataProvider>(() =>
		{
			try
			{
				// Check if this is the currently active log file being written to
				bool isActiveLogFile = string.Equals(filePath, Logger.LogFileName, StringComparison.OrdinalIgnoreCase);

				return isActiveLogFile
					// Use stream-based provider for the active log file
					? new StreamBasedFileDataProvider(filePath)
					// Use memory-mapped provider for inactive log files
					: new MemoryMappedFileDataProvider(filePath);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return new EmptyFileDataProvider();
			}
		});

	/// <summary>
	/// Runs every time the selected log file changes on the ComboBox.
	/// </summary>
	private async Task DisplayLogContentAsync(FileInfo log)
	{
		if (_isDisposed) return;

		await _displaySemaphore.WaitAsync();

		try
		{
			if (_isDisposed) return;

			int currentOperationId = Interlocked.Increment(ref _displayOperationId);

			IsLoading = true;

			if (File.Exists(log.FullName))
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
					Func<Task<IFileDataProvider>> dataProviderFactory = CreateDataProviderFactory(log.FullName);

					// Update the data provider factory and reload data
					LogCollection.UpdateDataProviderFactory(dataProviderFactory);
					await LogCollection.LoadDataAsync();
				}
				catch (Exception ex)
				{
					if (currentOperationId == _displayOperationId)
					{
						Logger.Write(ex);

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
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Clears the currently displayed log data after the selected file is removed or no files remain.
	/// </summary>
	/// <param name="resetSearchText">Resets the search box when no log file remains selected.</param>
	private async Task ClearDisplayedLogDataAsync(bool resetSearchText)
	{
		if (_isDisposed)
		{
			return;
		}

		await LogCollection.ClearAllData();

		IsLoading = false;

		if (resetSearchText)
		{
			SearchText = string.Empty;
		}
	}

	/// <summary>
	/// Copies the selected log lines to the clipboard.
	/// </summary>
	internal void CopySelectedLogLines()
	{
		try
		{
			if (LogListView?.SelectedItems is null || LogListView.SelectedItems.Count == 0)
			{
				return;
			}

			StringBuilder stringBuilder = new(LogListView.SelectedItems.Count);

			// Iterate through selected items and build the text to copy
			for (int i = 0; i < LogListView.SelectedItems.Count; i++)
			{
				if (LogListView.SelectedItems[i] is string logLine)
				{
					_ = stringBuilder.AppendLine(logLine);
				}
			}

			ClipboardManagement.CopyText(stringBuilder.ToString());
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
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

		LogListView = null;
	}

	internal async void OpenLogsDirectory()
	{
		try
		{
			await OpenFileInDefaultFileHandler(Atlas.LogsDirectory);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Loaded event for the UI ListView.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	[DynamicWindowsRuntimeCast(typeof(ListView))]
	internal void ListView_Loaded(object sender, RoutedEventArgs e) => LogListView = (ListView)sender;

}
