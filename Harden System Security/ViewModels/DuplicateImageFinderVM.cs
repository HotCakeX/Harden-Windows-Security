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
using AppControlManager.Others;
using AppControlManager.ViewModels;
using CommonCore.IncrementalCollection;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.ApplicationModel.DataTransfer;
using Windows.Foundation;
using Windows.Storage;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class DuplicatePhotoFinderVM : ViewModelBase
{
	internal DuplicatePhotoFinderVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// Subscribe to collection changes so EmptyStatePlaceholderVisibility stays in sync with the UI
		FilteredDuplicateGroups.CollectionChanged += (s, e) => OnPropertyChanged(nameof(EmptyStatePlaceholderVisibility));
	}

	internal readonly InfoBarSettings MainInfoBar;
	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	// Whether the UI elements are enabled or disabled
	internal bool AreElementsEnabled { get; set => SP(ref field, value); } = true;

	// Bound to the Value property of the ProgressRing on the UI.
	internal double ScanProgress { get; set => SP(ref field, value); }

	// Store the state of the mouse wheel zoom toggle
	private bool _isMouseWheelZoomEnabled;

	// Store the state of the confirmation dialog for "Delete All in Group"
	private bool _shouldConfirmDeleteAllGroup = true;

	internal bool IsProgressIndeterminate { get; set => SP(ref field, value); }

	// Returns Visible when the results list is empty, used by the empty-state placeholder in the view.
	internal Visibility EmptyStatePlaceholderVisibility => FilteredDuplicateGroups.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

	internal int TotalProcessed { get; set => SP(ref field, value); }
	internal int DuplicateCount { get; set => SP(ref field, value); }

	// Data Collections for user-selected files and folders.
	internal readonly UniqueStringObservableCollection SelectedFiles = [];
	internal readonly UniqueStringObservableCollection SelectedFolders = [];

	// Master list of all found groups
	private readonly List<DuplicateGroup> AllDuplicateGroups = [];

	// Filtered list displayed in UI
	internal readonly RangedObservableCollection<DuplicateGroup> FilteredDuplicateGroups = [];

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

	// Similarity Threshold, bound to the UI's Slider.
	internal double SimilarityThreshold { get; set => SP(ref field, value); } = 90;

	// Selection Strategy, bound to the SelectedItem of the UI ComboBox.
	internal SelectionStrategyItem SelectedStrategy { get; set => SP(ref field, value); } = SelectionStrategies_Private[0];

	private static readonly List<SelectionStrategyItem> SelectionStrategies_Private =
	[
		new(OriginalSelectionStrategy.BiggestResolution, "Biggest Resolution"),
		new(OriginalSelectionStrategy.SmallestResolution, "Smallest Resolution"),
		new(OriginalSelectionStrategy.BiggestFileSize, "Biggest File Size"),
		new(OriginalSelectionStrategy.SmallestFileSize, "Smallest File Size"),
	];

	// Bound to the UI's ComboBox ItemsSource.
	internal List<SelectionStrategyItem> SelectionStrategies => SelectionStrategies_Private;

	// Undo Stacks and logic
	// Each "Action" is a list of DeletedFileEntry (since a single action could delete 1 or N files)
	private readonly Stack<List<DeletedFileEntry>> _undoStack = new();

	internal bool IsUndoEnabled { get; set => SP(ref field, value); }

	// Class to store deleted file info and content in memory
	private sealed class DeletedFileEntry(DuplicateFile fileData, DuplicateGroup group, ReadOnlyMemory<byte> backupData)
	{
		internal DuplicateFile FileData => fileData;
		internal DuplicateGroup Group => group;
		internal ReadOnlyMemory<byte> BackupData => backupData;
	}

	internal void BrowseFiles_Click(object sender, RoutedEventArgs e)
	{
		List<string> files = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.AnyFilePickerFilter);
		foreach (string file in CollectionsMarshal.AsSpan(files))
		{
			SelectedFiles.Add(file);
		}
	}

	internal void ClearSelectedFiles() => SelectedFiles.Clear();

	internal void BrowseFolders_Click(object sender, RoutedEventArgs e)
	{
		List<string> folders = FileDialogHelper.ShowMultipleDirectoryPickerDialog();
		foreach (string folder in CollectionsMarshal.AsSpan(folders))
		{
			SelectedFolders.Add(folder);
		}
	}

	internal void ClearSelectedFolders() => SelectedFolders.Clear();

	// Event handler for DragOver
	internal void Grid_DragOver(object sender, DragEventArgs e) => e.AcceptedOperation = DataPackageOperation.Copy;


	// Event handler for Drop
	internal async void Grid_Drop(object sender, DragEventArgs e)
	{
		if (e.DataView.Contains(StandardDataFormats.StorageItems))
		{
			// Get deferral to ensure the operation completes before the event returns
			DragOperationDeferral deferral = e.GetDeferral();
			try
			{
				IReadOnlyList<IStorageItem> items = await e.DataView.GetStorageItemsAsync();
				foreach (IStorageItem item in items)
				{
					if (item is StorageFile file)
					{
						SelectedFiles.Add(file.Path);
					}
					else if (item is StorageFolder folder)
					{
						SelectedFolders.Add(folder.Path);
					}
				}
			}
			catch { }
			finally
			{
				deferral.Complete();
			}
		}
	}

	/// <summary>
	/// Initiates the main scan task.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal async void StartScan_Click(object sender, RoutedEventArgs e)
	{
		if (SelectedFiles.Count == 0 && SelectedFolders.Count == 0)
		{
			MainInfoBar.WriteWarning("Please select at least one file or folder to scan.");
			return;
		}

		try
		{
			TotalProcessed = 0;
			DuplicateCount = 0;

			AreElementsEnabled = false;

			// Clear undo stack on new scan
			ClearUndoStack();

			// Initially the Progress Ring is determinate becaue the Progress reporter assigns accurate values to it.
			IsProgressIndeterminate = false;

			ScanProgress = 0;
			MainInfoBarIsOpen = false;

			AllDuplicateGroups.Clear();
			FilteredDuplicateGroups.Clear();

			Progress<double> progressReporter = new(value => { ScanProgress = value; });

			DuplicateScanResult result = await RedundantAssetDetection.Find(
				[.. SelectedFiles],
				[.. SelectedFolders],
				progressReporter,
				SelectedStrategy.Strategy,
				SimilarityThreshold
			);

			IsProgressIndeterminate = true;

			// Initial population
			AllDuplicateGroups.AddRange(result.Groups);
			FilteredDuplicateGroups.AddRange(result.Groups);

			// Result.TotalProcessed is the raw count of all files scanned.
			TotalProcessed = result.TotalProcessed;

			// Now run the standard update logic to set the properties
			UpdateCounts();

			if (result.DuplicateCount == 0)
			{
				MainInfoBar.WriteSuccess($"Scan complete. No duplicates found in {result.TotalProcessed} images.");
			}
			else
			{
				MainInfoBar.WriteSuccess($"Scan complete. You can review the results now.");
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreElementsEnabled = true;
			IsProgressIndeterminate = false;
			ScanProgress = 0;
		}
	}

	// Deletes a single image.
	internal void DeleteFile_Click(object sender, RoutedEventArgs e)
	{
		if (sender is not Button btn || btn.Tag is not DuplicateFile file) return;
		DeleteFileInternal(file);
	}

	// Deletes the Original image (with confirmation)
	internal async void DeleteOriginalFile_Click(object sender, RoutedEventArgs e)
	{
		if (sender is not MenuFlyoutItem menuItem || menuItem.Tag is not DuplicateGroup group) return;

		try
		{
			DuplicateFile originalFile = group.Original;

			// 1. Show Warning Dialog
			using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = "Delete Original Photo?",
				Content = new TextBlock
				{
					Text = $"Are you sure you want to delete the original photo?\n\nFile: {originalFile.FileName}\n\nPath: {originalFile.FilePath}\n\nThis action will also remove the entire group from the list but will not touch the duplicates displayed on the right side. This action CANNOT be undone.",
					TextWrapping = TextWrapping.Wrap
				},
				PrimaryButtonText = "Delete Original",
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Close,
				Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"],
				FlowDirection = Enum.Parse<FlowDirection>(AppSettings.ApplicationGlobalFlowDirection)
			};

			ContentDialogResult result = await dialog.ShowAsync();

			if (result != ContentDialogResult.Primary)
			{
				return;
			}

			// 2. Perform Deletion
			if (File.Exists(originalFile.FilePath))
			{
				// Delete from disk
				File.Delete(originalFile.FilePath);

				// 3. Update UI / Collections
				// Since the original is gone, the group is no longer valid in its current form.
				// We remove the entire group from the lists.
				_ = AllDuplicateGroups.Remove(group);
				_ = FilteredDuplicateGroups.Remove(group);

				// Recalculate counts based on current group state to keep totals consistent.
				UpdateCounts();

				MainInfoBar.WriteSuccess($"Original file deleted: {originalFile.FileName}");
			}
			else
			{
				MainInfoBar.WriteWarning($"File not found: {originalFile.FilePath}");
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}


	private void DeleteFileInternal(DuplicateFile file)
	{
		try
		{
			// 1. Find the group that contains this file.
			DuplicateGroup? targetGroup = null;

			foreach (DuplicateGroup group in CollectionsMarshal.AsSpan(AllDuplicateGroups))
			{
				if (group.Duplicates.Contains(file))
				{
					targetGroup = group;
					break;
				}
			}

			if (targetGroup is null) return;

			// Prepare undo entry in memory
			if (File.Exists(file.FilePath))
			{
				// Read bytes into memory
				byte[] fileBytes = File.ReadAllBytes(file.FilePath);

				// Delete from disk
				File.Delete(file.FilePath);

				// Add to Undo Stack as a single action
				DeletedFileEntry entry = new(file, targetGroup, fileBytes);
				_undoStack.Push([entry]);
				IsUndoEnabled = true;
			}
			else
			{
				// If file doesn't exist
				return;
			}

			// 2. Remove the file from the ObservableCollection.
			// This automatically updates the UI for this specific group.
			_ = targetGroup.Duplicates.Remove(file);

			// 3. Check if the group is empty. If so, remove the whole group.
			// Removing the group from FilteredDuplicateGroups is safe and won't reset the whole list.
			if (targetGroup.Duplicates.Count == 0)
			{
				_ = AllDuplicateGroups.Remove(targetGroup);
				_ = FilteredDuplicateGroups.Remove(targetGroup);
			}

			UpdateCounts();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal async void DeleteAllDuplicatesInGroup_Click(object sender, RoutedEventArgs e)
	{
		if (sender is not Button btn || btn.Tag is not DuplicateGroup group) return;

		try
		{
			// If user hasn't opted out of confirmation
			if (_shouldConfirmDeleteAllGroup)
			{
				CheckBox dontAskAgainCheck = new()
				{
					Content = "Don't ask again for this session"
				};

				StackPanel contentPanel = new()
				{
					Spacing = 12,
					Children =
				{
					new TextBlock
					{
						Text = "Are you sure you want to delete all duplicates in this group?",
						TextWrapping = TextWrapping.Wrap
					},
					dontAskAgainCheck
				}
				};

				using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
				{
					Title = "Confirm Group Deletion",
					Content = contentPanel,
					PrimaryButtonText = "Delete All",
					CloseButtonText = GlobalVars.GetStr("Cancel"),
					DefaultButton = ContentDialogButton.Close,
					Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"],
					FlowDirection = Enum.Parse<FlowDirection>(AppSettings.ApplicationGlobalFlowDirection)
				};

				ContentDialogResult result = await dialog.ShowAsync();

				if (result != ContentDialogResult.Primary)
				{
					return;
				}

				// Update the preference if checked
				if (dontAskAgainCheck.IsChecked == true)
				{
					_shouldConfirmDeleteAllGroup = false;
				}
			}

			int failCount = 0;
			List<DeletedFileEntry> undoBatch = [];

			// Create a copy of list to modify
			List<DuplicateFile> toDelete = [.. group.Duplicates];

			foreach (DuplicateFile file in CollectionsMarshal.AsSpan(toDelete))
			{
				try
				{
					if (!File.Exists(file.FilePath))
					{
						failCount++;
						continue;
					}

					// Read bytes into memory
					byte[] fileBytes = File.ReadAllBytes(file.FilePath);

					// Delete from disk
					File.Delete(file.FilePath);

					// Add to Undo Batch
					undoBatch.Add(new DeletedFileEntry(file, group, fileBytes));

					// Remove from UI only after successful delete
					_ = group.Duplicates.Remove(file);
				}
				catch
				{
					failCount++;
				}
			}

			// If at least one file was successfully deleted, we create an undo entry for the whole batch.
			if (undoBatch.Count > 0)
			{
				_undoStack.Push(undoBatch);
				IsUndoEnabled = true;
			}

			if (group.Duplicates.Count == 0)
			{
				_ = AllDuplicateGroups.Remove(group);
				_ = FilteredDuplicateGroups.Remove(group);
			}

			UpdateCounts();

			if (failCount > 0)
			{
				MainInfoBar.WriteWarning($"Failed to delete {failCount} files.");
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal async void AutoDeleteAll_Click(object sender, RoutedEventArgs e)
	{
		if (AllDuplicateGroups.Count == 0) return;

		AreElementsEnabled = false;

		try
		{
			using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = "Confirm Deletion",
				Content = "Are you sure you want to delete all duplicate photos? This action cannot be undone.",
				PrimaryButtonText = "Yes, Delete All",
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Close,
				Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"],
				FlowDirection = Enum.Parse<FlowDirection>(AppSettings.ApplicationGlobalFlowDirection)
			};

			ContentDialogResult result = await dialog.ShowAsync();

			if (result != ContentDialogResult.Primary)
			{
				return;
			}

			// Clear undo stack because this is a massive destructive action stated as "cannot be undone"
			ClearUndoStack();

			int deletedCount = 0;
			int failCount = 0;

			// Iterate backwards to safely remove groups
			for (int i = AllDuplicateGroups.Count - 1; i >= 0; i--)
			{
				DuplicateGroup group = AllDuplicateGroups[i];
				List<DuplicateFile> toDelete = [.. group.Duplicates];

				foreach (DuplicateFile file in CollectionsMarshal.AsSpan(toDelete))
				{
					try
					{
						if (!File.Exists(file.FilePath))
						{
							failCount++;
							continue;
						}

						File.Delete(file.FilePath);
						deletedCount++;

						// Remove from UI only after successful delete
						_ = group.Duplicates.Remove(file);
					}
					catch
					{
						failCount++;
					}
				}

				if (group.Duplicates.Count == 0)
				{
					AllDuplicateGroups.RemoveAt(i);
				}
			}

			UpdateCounts();
			ApplyFilter();
			MainInfoBar.WriteSuccess($"Auto-delete complete. Deleted {deletedCount} files. Failed: {failCount}.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreElementsEnabled = true;
		}
	}

	/// <summary>
	/// It undoes deletion actions in the reverse order they happened (Last-In, First-Out).
	/// Only Single picture deletions or Duplicte group deletions supported, not automated deletion of all duplicates because they can be too big.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void Undo_Click(object sender, RoutedEventArgs e)
	{
		if (_undoStack.Count == 0) return;

		try
		{
			AreElementsEnabled = false;
			// Keep disabled until finished
			IsUndoEnabled = false;

			List<DeletedFileEntry> lastAction = _undoStack.Pop();
			int restoredCount = 0;
			int failedCount = 0;

			foreach (DeletedFileEntry entry in CollectionsMarshal.AsSpan(lastAction))
			{
				try
				{
					// Do not overwrite an existing file
					if (File.Exists(entry.FileData.FilePath))
					{
						failedCount++;
						continue;
					}

					// 1. Restore file from RAM bytes
					// Ensure directory exists
					string? directory = Path.GetDirectoryName(entry.FileData.FilePath);
					if (!string.IsNullOrEmpty(directory))
					{
						_ = Directory.CreateDirectory(directory);
					}

					// Write bytes back to disk
					using (FileStream fs = File.Create(entry.FileData.FilePath))
					{
						fs.Write(entry.BackupData.Span);
					}

					// 2. Restore data model
					// Check if group is currently in AllDuplicateGroups
					if (!AllDuplicateGroups.Contains(entry.Group))
					{
						// Group was removed because it became empty OR because original was deleted. Add it back.
						AllDuplicateGroups.Add(entry.Group);

						// Determine if it should be visible based on filter
						// If no filter or matches filter
						if (string.IsNullOrWhiteSpace(SearchText) ||
							entry.Group.Original.FileName.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
							entry.Group.Duplicates.Any(d => d.FileName.Contains(SearchText, StringComparison.OrdinalIgnoreCase)))
						{
							// Check if not already in Filtered (it shouldn't be if we just added to All)
							if (!FilteredDuplicateGroups.Contains(entry.Group))
							{
								FilteredDuplicateGroups.Add(entry.Group);
							}
						}
					}

					// Logic to handle restoring Original vs restoring Duplicate
					// If the restored file is the Original, we don't need to add it to Duplicates list.
					// The Group object already references it as 'Original'.
					// We just needed to ensure the group is back in the list (handled above).

					// If the restored file is a duplicate, we need to add it back to the duplicates collection
					// Only if it's not already there.
					if (entry.FileData != entry.Group.Original && !entry.Group.Duplicates.Contains(entry.FileData))
					{
						entry.Group.Duplicates.Add(entry.FileData);
					}

					restoredCount++;
				}
				catch
				{
					failedCount++;
				}
			}

			UpdateCounts();

			if (!string.IsNullOrWhiteSpace(SearchText))
			{
				ApplyFilter();
			}

			if (failedCount > 0)
			{
				MainInfoBar.WriteWarning($"Undid deletion of {restoredCount} file(s). Skipped {failedCount} file(s) because they already exist or could not be restored.");
			}
			else
			{
				MainInfoBar.WriteSuccess($"Undid deletion of {restoredCount} file(s).");
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreElementsEnabled = true;
			// Re-enable if there are more items
			IsUndoEnabled = _undoStack.Count > 0;
		}
	}

	internal void UndoInvoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		// Check if undo is allowed (button enabled)
		if (IsUndoEnabled && AreElementsEnabled)
		{
			Undo_Click(sender, null!);
			args.Handled = true;
		}
	}

	private void ClearUndoStack()
	{
		// Since data is in RAM (GC managed), we just clear the collection.
		_undoStack.Clear();
		IsUndoEnabled = false;
	}

	/// <summary>
	/// Clears all internal data collections, resets counters, and clears the search text.
	/// </summary>
	internal void ClearData_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			AllDuplicateGroups.Clear();
			FilteredDuplicateGroups.Clear();

			// Clear search text without triggering ApplyFilter unnecessarily since collections are already cleared
			SearchText = null;

			// Clear Undo history on data clear
			ClearUndoStack();

			TotalProcessed = 0;
			DuplicateCount = 0;

			MainInfoBar.WriteInfo("All data has been cleared.");
		}
		finally
		{
			MainInfoBar.IsClosable = true;
		}
	}

	private void ApplyFilter()
	{
		// Get the ScrollViewer
		ScrollViewer? sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.DuplicatePhotoFinder);
		double? verticalOffset = sv?.VerticalOffset;

		FilteredDuplicateGroups.Clear();

		if (string.IsNullOrWhiteSpace(SearchText))
		{
			FilteredDuplicateGroups.AddRange(AllDuplicateGroups);
		}
		else
		{
			string query = SearchText.Trim();
			IEnumerable<DuplicateGroup> results = AllDuplicateGroups.Where(group =>
					 // Check if original or any duplicate matches
					 group.Original.FileName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
					group.Duplicates.Any(d => d.FileName.Contains(query, StringComparison.OrdinalIgnoreCase))
			);

			FilteredDuplicateGroups.AddRange(results);
		}

		// Restore scroll position
		if (sv != null && verticalOffset.HasValue)
		{
			_ = sv.ChangeView(null, verticalOffset.Value, null, true);
		}
	}

	/// <summary>
	/// Updates the counters (Duplicate Count and Total Processed) based on the current state of duplicate groups.
	/// </summary>
	private void UpdateCounts()
	{
		int currentDuplicates = 0;

		// Count files that are currently in the duplicate structure
		foreach (DuplicateGroup group in CollectionsMarshal.AsSpan(AllDuplicateGroups))
		{
			currentDuplicates += group.Duplicates.Count;
		}

		DuplicateCount = currentDuplicates;
	}

	/// <summary>
	/// Opens a full-size preview of the image in a ContentDialogV2.
	/// Includes Zoom controls, Open Location, and Delete button (if applicable, meaning the Original pic shouldn't have the delete option. Only duplicate photos should have delete option.).
	/// </summary>
	internal async void OpenImagePreview(object sender, RoutedEventArgs e)
	{
		if (sender is not Button btn) return;

		if (btn.Tag is not DuplicateFile file) return;

		// Check if this file is in a duplicate list (to determine if we show delete)
		bool isDuplicate = false;
		foreach (DuplicateGroup group in CollectionsMarshal.AsSpan(AllDuplicateGroups))
		{
			if (group.Duplicates.Contains(file))
			{
				isDuplicate = true;
				break;
			}
		}

		ScrollViewer scrollViewer = new()
		{
			HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
			VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
			ZoomMode = ZoomMode.Enabled,
			MinZoomFactor = 0.1f,
			MaxZoomFactor = 5.0f,
			HorizontalAlignment = HorizontalAlignment.Stretch,
			VerticalAlignment = VerticalAlignment.Stretch
		};

		// Named variable so OnScrollViewerLoaded can read PixelWidth/PixelHeight
		// after the image has been decoded, to compute the fit-to-viewport zoom.
		// BitmapImage does not keep the file locked/open because we use direct file path: https://github.com/microsoft/microsoft-ui-xaml/issues/633
		BitmapImage bitmapImage = new(new Uri(file.FilePath));

		Image image = new()
		{
			Source = bitmapImage,
			// Stretch.None lets the ScrollViewer's zoom factor be the sole
			// determinant of rendered size..
			Stretch = Microsoft.UI.Xaml.Media.Stretch.None,
			HorizontalAlignment = HorizontalAlignment.Center,
			VerticalAlignment = VerticalAlignment.Center
		};

		// Enable Mouse Dragging (Panning)
		// Wrapping the Image in a CursorAwareContentControl to enable cursor modification and event handling.
		CursorAwareContentControl wrapper = new()
		{
			Content = image,
			HorizontalContentAlignment = HorizontalAlignment.Center,
			VerticalContentAlignment = VerticalAlignment.Center
		};

		bool _isDragging = false;
		Point _lastMousePosition = new(0, 0);

		// Switch cursor on pointer enter/leave to indicate interactivity
		wrapper.PointerEntered += (s, args) =>
		{
			if (s is CursorAwareContentControl el)
				el.SetCursor(InputSystemCursor.Create(InputSystemCursorShape.Hand));
		};

		wrapper.PointerExited += (s, args) =>
		{
			if (s is CursorAwareContentControl el)
				el.SetCursor(InputSystemCursor.Create(InputSystemCursorShape.Arrow));
		};

		wrapper.PointerPressed += (s, args) =>
		{
			// Only react to left mouse button
			if (args.GetCurrentPoint(wrapper).Properties.IsLeftButtonPressed)
			{
				_isDragging = true;
				_lastMousePosition = args.GetCurrentPoint(scrollViewer).Position;
				_ = wrapper.CapturePointer(args.Pointer);
			}
		};

		wrapper.PointerMoved += (s, args) =>
		{
			if (_isDragging)
			{
				Point currentMousePosition = args.GetCurrentPoint(scrollViewer).Position;
				double deltaX = currentMousePosition.X - _lastMousePosition.X;
				double deltaY = currentMousePosition.Y - _lastMousePosition.Y;

				// Update scroll position
				// To move the image "with" the mouse, we subtract the delta from the offset.
				double newHorizontalOffset = scrollViewer.HorizontalOffset - deltaX;
				double newVerticalOffset = scrollViewer.VerticalOffset - deltaY;

				_ = scrollViewer.ChangeView(newHorizontalOffset, newVerticalOffset, null, true);

				_lastMousePosition = currentMousePosition;
			}
		};

		wrapper.PointerReleased += (s, args) =>
		{
			_isDragging = false;
			wrapper.ReleasePointerCapture(args.Pointer);
		};

		wrapper.PointerCanceled += (s, args) =>
		{
			_isDragging = false;
			wrapper.ReleasePointerCapture(args.Pointer);
		};

		scrollViewer.Content = wrapper;

		// Fires once after the ScrollViewer is in the visual tree and has valid
		// ViewportWidth/ViewportHeight. We compute and apply a fit-to-viewport
		// zoom at this point so the image is fully visible when the dialog opens.
		// No static size needed - we use the actual measured viewport.
		scrollViewer.Loaded += OnScrollViewerLoaded;

		void OnScrollViewerLoaded(object sv, RoutedEventArgs args)
		{
			// Unsubscribe immediately because only needs to run once.
			scrollViewer.Loaded -= OnScrollViewerLoaded;

			double naturalWidth = bitmapImage.PixelWidth;
			double naturalHeight = bitmapImage.PixelHeight;

			// PixelWidth/Height may still be 0 if decoding hasn't finished yet.
			// In that case subscribe to ImageOpened to retry once decoding completes.
			if (naturalWidth <= 0 || naturalHeight <= 0)
			{
				bitmapImage.ImageOpened += OnImageOpened;
				return;
			}

			ApplyFitZoom(naturalWidth, naturalHeight);
		}

		void OnImageOpened(object s, RoutedEventArgs args)
		{
			// Unsubscribe immediately - only needs to run once
			bitmapImage.ImageOpened -= OnImageOpened;

			double naturalWidth = bitmapImage.PixelWidth;
			double naturalHeight = bitmapImage.PixelHeight;

			if (naturalWidth <= 0 || naturalHeight <= 0) return;

			ApplyFitZoom(naturalWidth, naturalHeight);
		}

		// Computes and applies the largest zoom that fits the image fully inside
		// the ScrollViewer's current viewport.
		void ApplyFitZoom(double naturalWidth, double naturalHeight)
		{
			double viewportWidth = scrollViewer.ViewportWidth;
			double viewportHeight = scrollViewer.ViewportHeight;

			if (viewportWidth <= 0 || viewportHeight <= 0) return;

			// Standard fit-to-viewport formula: pick whichever axis is the tighter constraint
			float fitZoom = (float)Math.Min(viewportWidth / naturalWidth, viewportHeight / naturalHeight);

			// Clamp to the ScrollViewer's own min/max
			fitZoom = Math.Clamp(fitZoom, scrollViewer.MinZoomFactor, scrollViewer.MaxZoomFactor);

			// Center the image within the viewport after applying fitZoom
			double centeredH = Math.Max(0, (naturalWidth * fitZoom - viewportWidth) / 2.0);
			double centeredV = Math.Max(0, (naturalHeight * fitZoom - viewportHeight) / 2.0);

			_ = scrollViewer.ChangeView(centeredH, centeredV, fitZoom, true /* disableAnimation */);
		}

		// Toolbar for Zoom In, Zoom Out, and Open File Location
		StackPanel toolbar = new()
		{
			Orientation = Orientation.Horizontal,
			Spacing = 8,
			HorizontalAlignment = HorizontalAlignment.Center,
			Margin = new Thickness(0, 0, 0, 8)
		};

		RepeatButton zoomInBtn = new() { Content = new FontIcon() { Glyph = "\uE8A3" } };
		zoomInBtn.Click += (s, args) =>
		{
			float oldZoom = scrollViewer.ZoomFactor;
			float newZoom = oldZoom + 0.1f;

			if (newZoom > scrollViewer.MaxZoomFactor)
				return;

			// Use the center of the currently visible viewport as the zoom anchor
			double viewportCenterX = scrollViewer.HorizontalOffset + (scrollViewer.ViewportWidth / 2.0);
			double viewportCenterY = scrollViewer.VerticalOffset + (scrollViewer.ViewportHeight / 2.0);

			// Convert viewport center to unscaled content coordinates
			double contentCenterX = viewportCenterX / oldZoom;
			double contentCenterY = viewportCenterY / oldZoom;

			// Calculate new offsets so the same content point stays at the center
			double newHorizontalOffset = (contentCenterX * newZoom) - (scrollViewer.ViewportWidth / 2.0);
			double newVerticalOffset = (contentCenterY * newZoom) - (scrollViewer.ViewportHeight / 2.0);

			_ = scrollViewer.ChangeView(newHorizontalOffset, newVerticalOffset, newZoom);
		};

		ToolTipService.SetToolTip(zoomInBtn, "Zoom In (Press and hold to zoom continuously)");
		AutomationProperties.SetHelpText(zoomInBtn, "Zoom In (Press and hold to zoom continuously)");

		RepeatButton zoomOutBtn = new() { Content = new FontIcon() { Glyph = "\uE71F" } };
		zoomOutBtn.Click += (s, args) =>
		{
			float oldZoom = scrollViewer.ZoomFactor;
			float newZoom = oldZoom - 0.1f;

			if (newZoom < scrollViewer.MinZoomFactor)
				return;

			// Use the center of the currently visible viewport as the zoom anchor
			double viewportCenterX = scrollViewer.HorizontalOffset + (scrollViewer.ViewportWidth / 2.0);
			double viewportCenterY = scrollViewer.VerticalOffset + (scrollViewer.ViewportHeight / 2.0);

			// Convert viewport center to unscaled content coordinates
			double contentCenterX = viewportCenterX / oldZoom;
			double contentCenterY = viewportCenterY / oldZoom;

			// Calculate new offsets so the same content point stays at the center
			double newHorizontalOffset = (contentCenterX * newZoom) - (scrollViewer.ViewportWidth / 2.0);
			double newVerticalOffset = (contentCenterY * newZoom) - (scrollViewer.ViewportHeight / 2.0);

			_ = scrollViewer.ChangeView(newHorizontalOffset, newVerticalOffset, newZoom);
		};

		ToolTipService.SetToolTip(zoomOutBtn, "Zoom Out (Press and hold to zoom continuously)");
		AutomationProperties.SetHelpText(zoomOutBtn, "Zoom Out (Press and hold to zoom continuously)");

		// Toggle Button for Mouse Wheel Zoom
		ToggleButton wheelZoomToggle = new()
		{
			Content = new FontIcon() { Glyph = "\uE962" },
			IsChecked = _isMouseWheelZoomEnabled
		};

		ToolTipService.SetToolTip(wheelZoomToggle, "Toggle Mouse Wheel Zoom");
		AutomationProperties.SetHelpText(wheelZoomToggle, "Toggle Mouse Wheel Zoom");

		// Helper to sync ScrollViewer scroll modes with the wheel zoom toggle state.
		// When wheel zoom is enabled, we disable native scrolling so the ScrollViewer
		// does not consume wheel events for vertical/horizontal panning.
		void SyncScrollModes(bool wheelZoomOn)
		{
			scrollViewer.VerticalScrollMode = wheelZoomOn ? ScrollMode.Disabled : ScrollMode.Enabled;
			scrollViewer.HorizontalScrollMode = wheelZoomOn ? ScrollMode.Disabled : ScrollMode.Enabled;
		}

		// Apply the initial state immediately so the ScrollViewer is in the correct mode
		// when the dialog opens, matching the persisted toggle state.
		SyncScrollModes(_isMouseWheelZoomEnabled);

		// Update the class field and scroll modes whenever the button is clicked.
		wheelZoomToggle.Click += (s, args) =>
		{
			if (wheelZoomToggle.IsChecked.HasValue)
			{
				_isMouseWheelZoomEnabled = wheelZoomToggle.IsChecked.Value;
				// Disable/enable native scroll so wheel events are not consumed for panning
				// while wheel zoom mode is active.
				// Because when we zoom all the way in or out, we don't want the ScrollViewer to start scrolling the image vertically when the user tries to zoom further with the wheel.
				SyncScrollModes(_isMouseWheelZoomEnabled);
			}
		};

		// Store the delegate so we can call RemoveHandler when the dialog closes,
		// preventing the routed-event infrastructure from keeping the ScrollViewer alive.
		PointerEventHandler wheelHandler = new((s, args) =>
		{
			if (wheelZoomToggle.IsChecked == true)
			{
				// Mark handled to prevent any residual bubbling
				args.Handled = true;

				PointerPoint point = args.GetCurrentPoint(scrollViewer);
				int delta = point.Properties.MouseWheelDelta;

				// Zoom Logic
				if (delta != 0)
				{
					float oldZoom = scrollViewer.ZoomFactor;
					float zoomChange = delta > 0 ? 0.1f * oldZoom : -0.1f * oldZoom;
					float newZoom = Math.Clamp(oldZoom + zoomChange, scrollViewer.MinZoomFactor, scrollViewer.MaxZoomFactor);

					// If zoom didn't change (hit limits), do nothing
					if (Math.Abs(newZoom - oldZoom) < 0.001f)
						return;

					// Calculate the position of the pointer relative to the content (unscaled)
					// Current Offset + Mouse Position gives the position in the viewport relative to the top-left of the content area.
					// Dividing by oldZoom gives the unscaled coordinate in the content.
					double mouseX = point.Position.X;
					double mouseY = point.Position.Y;

					double horizontalOffset = scrollViewer.HorizontalOffset;
					double verticalOffset = scrollViewer.VerticalOffset;

					// The content point under the mouse
					double contentX = (horizontalOffset + mouseX) / oldZoom;
					double contentY = (verticalOffset + mouseY) / oldZoom;

					// Calculate new offsets to keep contentX/Y under mouseX/Y
					// New total dimension to the left/top of the content point = contentX * newZoom
					// Subtract mouseX to get the new scroll offset
					double newHorizontalOffset = (contentX * newZoom) - mouseX;
					double newVerticalOffset = (contentY * newZoom) - mouseY;

					_ = scrollViewer.ChangeView(newHorizontalOffset, newVerticalOffset, newZoom);
				}
			}
		});

		scrollViewer.AddHandler(UIElement.PointerWheelChangedEvent, wheelHandler, handledEventsToo: true);

		Button openLocBtn = new() { Content = new FontIcon() { Glyph = "\uE8DA" } };
		openLocBtn.Click += (s, args) =>
		{
			try
			{
				if (file.FilePath is not null)
				{
					ProcessStartInfo processInfo = new()
					{
						FileName = "explorer.exe",
						Arguments = $"/select,\"{file.FilePath}\"", // Scroll to the file in File Explorer and highlight it.
						UseShellExecute = true
					};

					_ = Process.Start(processInfo);
				}
			}
			catch { }
		};

		ToolTipService.SetToolTip(openLocBtn, "Open the file location in File Explorer");
		AutomationProperties.SetHelpText(openLocBtn, "Open the file location in File Explorer");

		toolbar.Children.Add(zoomInBtn);
		toolbar.Children.Add(zoomOutBtn);
		toolbar.Children.Add(wheelZoomToggle);
		toolbar.Children.Add(openLocBtn);

		Grid contentGrid = new() { RowSpacing = 12 };
		contentGrid.RowDefinitions.Add(new RowDefinition() { Height = GridLength.Auto });        // Toolbar
		contentGrid.RowDefinitions.Add(new RowDefinition() { Height = new GridLength(1, GridUnitType.Star) }); // Image Area
		contentGrid.RowDefinitions.Add(new RowDefinition() { Height = GridLength.Auto });        // Path Area

		Grid.SetRow(toolbar, 0);
		contentGrid.Children.Add(toolbar);

		Grid.SetRow(scrollViewer, 1);
		contentGrid.Children.Add(scrollViewer);

		TextBox pathBox = new()
		{
			Text = file.FilePath,
			IsReadOnly = true,
			TextWrapping = TextWrapping.Wrap,
			BorderThickness = new Thickness(0),
			Background = null
		};
		Grid.SetRow(pathBox, 2);
		contentGrid.Children.Add(pathBox);

		// Using a TextBlock for the Title to enable text selection
		TextBlock titleBlock = new()
		{
			Text = file.FileName,
			IsTextSelectionEnabled = true,
			TextWrapping = TextWrapping.NoWrap,
			TextTrimming = TextTrimming.CharacterEllipsis
		};

		using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
		{
			Title = titleBlock,
			Content = contentGrid,
			CloseButtonText = "Close",
			DefaultButton = ContentDialogButton.Close,
			Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"],
			FlowDirection = Enum.Parse<FlowDirection>(AppSettings.ApplicationGlobalFlowDirection)
		};

		// Only add Delete button if it is a duplicate
		if (isDuplicate)
		{
			dialog.PrimaryButtonText = "Delete File";
		}

		ContentDialogResult result = await dialog.ShowAsync();

		// Remove the wheel handler now that the dialog is closed.
		scrollViewer.RemoveHandler(UIElement.PointerWheelChangedEvent, wheelHandler);

		if (isDuplicate && result == ContentDialogResult.Primary)
		{
			DeleteFileInternal(file);
		}
	}

}

internal sealed class SelectionStrategyItem(OriginalSelectionStrategy strategy, string name)
{
	internal OriginalSelectionStrategy Strategy => strategy;
	internal string Name => name;
}

// A helper subclass to expose the ProtectedCursor property
internal sealed partial class CursorAwareContentControl : ContentControl
{
	internal void SetCursor(InputCursor cursor) => ProtectedCursor = cursor;
}
