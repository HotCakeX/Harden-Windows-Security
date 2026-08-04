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

using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using AppControlManager.Others;
using CommonCore.IncrementalCollection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using WinRT;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class EXIFManagerVM : ViewModelBase
{

	internal readonly InfoBarSettings MainInfoBar = new();

	// Whether the UI elements are enabled or disabled
	internal bool AreElementsEnabled { get; set => SP(ref field, value); } = true;

	internal string? SelectedFilePath
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(EmptyStatePlaceholderVisibility));
				OnPropertyChanged(nameof(SelectedFileUri));
				OnPropertyChanged(nameof(ImagePreviewVisibility));
			}
		}
	}

	// Used by the Image Control to display a thumbnail of the selected photo
	internal Uri? SelectedFileUri => string.IsNullOrEmpty(SelectedFilePath) ? null : new Uri(SelectedFilePath);

	// Controls the visibility of the Image Preview panel
	internal Visibility ImagePreviewVisibility => string.IsNullOrEmpty(SelectedFilePath) ? Visibility.Collapsed : Visibility.Visible;

	// Controls the visibility of the drag-and-drop empty state placeholder
	internal Visibility EmptyStatePlaceholderVisibility => string.IsNullOrEmpty(SelectedFilePath) ? Visibility.Visible : Visibility.Collapsed;

	internal readonly RangedObservableCollection<MetadataCategory> Categories = [];

	/// <summary>
	/// Data Collection for user-selected folders used by the bulk metadata removal operation.
	/// </summary>
	internal readonly UniqueStringObservableCollection SelectedFolders = [];

	/// <summary>
	/// The image file extensions supported by the EXIF scrubber.
	/// </summary>
	private static readonly string[] SupportedImageExtensions = [".jpg", ".jpeg", ".png"];

	/// <summary>
	/// Event handler for the UI to select folders for the bulk metadata removal operation.
	/// </summary>
	internal void BrowseForFolders_Click()
	{
		List<string> folders = FileDialogHelper.ShowMultipleDirectoryPickerDialog();
		foreach (string folder in CollectionsMarshal.AsSpan(folders))
		{
			SelectedFolders.Add(folder);
		}
	}

	/// <summary>
	/// Clears the user-selected folders.
	/// </summary>
	internal void ClearSelectedFolders() => SelectedFolders.Clear();

	/// <summary>
	/// Event handler for the UI to select a photo.
	/// </summary>
	internal async void BrowseForImage_Click()
	{
		string? file = FileDialogHelper.ShowFilePickerDialog("Image Files|*.jpg;*.jpeg;*.png");
		if (!string.IsNullOrEmpty(file))
		{
			SelectedFilePath = file;
			await LoadMetadata();
		}
	}

	/// <summary>
	/// Event handler for DragOver
	/// </summary>
	internal void Grid_DragOver(object sender, DragEventArgs e) => e.AcceptedOperation = DataPackageOperation.Copy;

	/// <summary>
	/// Event handler for Drop
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(StorageFile))]
	internal async void Grid_Drop(object sender, DragEventArgs e)
	{
		if (e.DataView.Contains(StandardDataFormats.StorageItems))
		{
			DragOperationDeferral deferral = e.GetDeferral();
			try
			{
				IReadOnlyList<IStorageItem> items = await e.DataView.GetStorageItemsAsync();
				foreach (IStorageItem item in items)
				{
					if (item is StorageFile file)
					{
						string extension = Path.GetExtension(file.Path);
						if (string.Equals(extension, ".jpg", StringComparison.OrdinalIgnoreCase) ||
							string.Equals(extension, ".jpeg", StringComparison.OrdinalIgnoreCase) ||
							string.Equals(extension, ".png", StringComparison.OrdinalIgnoreCase))
						{
							SelectedFilePath = file.Path;
							await LoadMetadata();
							break; // Only load the first valid image
						}
					}
				}
			}
			catch (Exception ex)
			{
				MainInfoBar.WriteError(ex);
			}
			finally
			{
				deferral.Complete();
			}
		}
	}

	/// <summary>
	/// Keyboard accelerator handler for copying all metadata (Ctrl+C).
	/// </summary>
	internal void CopyAllInvoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		if (AreElementsEnabled && Categories.Count > 0)
		{
			CopyAllToClipboard_Click();
			args.Handled = true;
		}
	}

	/// <summary>
	/// Keyboard accelerator handler for removing all metadata (Delete key).
	/// </summary>
	internal void RemoveAllInvoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		if (AreElementsEnabled && Categories.Count > 0 && !string.IsNullOrEmpty(SelectedFilePath))
		{
			RemoveAll_Click();
			args.Handled = true;
		}
	}

	/// <summary>
	/// Clears the selected file path and all the displayed info associated with the photo.
	/// </summary>
	internal void ClearSelectedImagePath()
	{
		SelectedFilePath = null;
		Categories.Clear();
	}

	/// <summary>
	/// Expands all Expanders on the UI.
	/// </summary>
	internal void ExpandAll_Click()
	{
		foreach (MetadataCategory category in Categories)
		{
			category.IsExpanded = true;
		}
	}

	/// <summary>
	/// Collapses all Expanders on the UI.
	/// </summary>
	internal void CollapseAll_Click()
	{
		foreach (MetadataCategory category in Categories)
		{
			category.IsExpanded = false;
		}
	}

	/// <summary>
	/// Copies all of the parsed EXIF metadata to the clipboard.
	/// </summary>
	internal void CopyAllToClipboard_Click()
	{
		if (Categories.Count == 0)
		{
			MainInfoBar.WriteWarning("No metadata to copy.");
			return;
		}

		try
		{
			StringBuilder sb = new();
			foreach (MetadataCategory category in Categories)
			{
				_ = sb.AppendLine($"[{category.DisplayName}]");
				foreach (MetadataTag tag in category.Tags)
				{
					_ = sb.AppendLine($"{tag.Name}: {tag.Value}");
				}
				_ = sb.AppendLine();
			}

			ClipboardManagement.CopyText(sb.ToString().TrimEnd());

			MainInfoBar.WriteSuccess("All metadata copied to clipboard.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Removes all safe to remove EXIF data from the photo.
	/// </summary>
	internal async void RemoveAll_Click()
	{
		if (string.IsNullOrEmpty(SelectedFilePath) || !File.Exists(SelectedFilePath))
		{
			return;
		}

		using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
		{
			Title = "Confirm Metadata Removal",
			Content = new TextBlock
			{
				Text = "Are you sure you want to permanently remove all safe-to-remove metadata from this image?\n\nThis action will overwrite the original file and cannot be undone.",
				TextWrapping = TextWrapping.Wrap
			},
			PrimaryButtonText = "Remove All Metadata",
			CloseButtonText = Atlas.GetStr("Cancel"),
			DefaultButton = ContentDialogButton.Close
		};

		ContentDialogResult result = await dialog.ShowAsync();

		if (result != ContentDialogResult.Primary)
		{
			return;
		}

		try
		{
			AreElementsEnabled = false;
			HashSet<string> toRemove = new(StringComparer.Ordinal);

			foreach (MetadataCategory category in Categories)
			{
				if (category.IsSafeToRemove)
				{
					_ = toRemove.Add(category.CategoryId);
				}
			}

			if (toRemove.Count == 0)
			{
				MainInfoBar.WriteInfo("No safe-to-remove metadata found.");
				return;
			}

			await Task.Run(() => EXIFScrubber.Scrub(SelectedFilePath, toRemove));

			MainInfoBar.WriteSuccess($"Successfully removed all {toRemove.Count} safe-to-remove metadata categories.");

			// Reload to reflect changes
			await LoadMetadata();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreElementsEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	private async Task LoadMetadata()
	{
		if (string.IsNullOrEmpty(SelectedFilePath))
		{
			return;
		}

		try
		{
			AreElementsEnabled = false;
			Categories.Clear();

			List<MetadataCategory> result = await Task.Run(() => EXIFScrubber.Analyze(SelectedFilePath));

			Categories.AddRange(result);

			MainInfoBar.WriteSuccess($"Successfully loaded {Categories.Count} metadata categories.");
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

	[DynamicWindowsRuntimeCast(typeof(Button))]
	internal async void RemoveCategory_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button btn && btn.Tag is MetadataCategory category)
		{
			if (string.IsNullOrEmpty(SelectedFilePath))
			{
				return;
			}

			try
			{
				AreElementsEnabled = false;
				HashSet<string> toRemove = [category.CategoryId];

				await Task.Run(() => EXIFScrubber.Scrub(SelectedFilePath, toRemove));

				MainInfoBar.WriteSuccess($"Successfully removed {category.DisplayName} metadata.");

				// Reload to reflect changes
				await LoadMetadata();
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
	}

	/// <summary>
	/// Event handler for the Start button of the bulk metadata removal operation.
	/// Enumerates every supported image inside the user-selected folders, removes all safe-to-remove
	/// metadata from each one (exactly as if each file was loaded and "Remove All" was pressed for it),
	/// and then offers to save a detailed JSON report of the whole operation to disk.
	/// </summary>
	internal async void StartBulkRemoval_Click()
	{
		if (SelectedFolders.Count == 0)
		{
			MainInfoBar.WriteWarning("Please select at least one folder first.");
			return;
		}

		using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
		{
			Title = "Confirm Bulk Metadata Removal",
			Content = new TextBlock
			{
				Text = "All supported images (JPG/JPEG/PNG) inside the selected folders and their sub-folders will have every safe-to-remove metadata category permanently removed.\n\nThis action will overwrite the original files and cannot be undone.",
				TextWrapping = TextWrapping.Wrap
			},
			PrimaryButtonText = "Start Removal",
			CloseButtonText = Atlas.GetStr("Cancel"),
			DefaultButton = ContentDialogButton.Close
		};

		ContentDialogResult result = await dialog.ShowAsync();

		if (result != ContentDialogResult.Primary)
		{
			return;
		}

		ExifBulkRemovalReport report;

		try
		{
			using IDisposable taskTracker = TaskTracking.RegisterOperation();

			AreElementsEnabled = false;
			MainInfoBar.WriteInfo("Searching for supported image files in the selected folders...");

			report = await Task.Run(() => RunBulkRemoval([.. SelectedFolders]));

			if (report.TotalFilesFound == 0)
			{
				MainInfoBar.WriteWarning("No supported image files (JPG/JPEG/PNG) were found in the selected folders.");
				return;
			}

			MainInfoBar.WriteSuccess($"Bulk removal complete. Processed {report.TotalFilesFound} files: {report.FilesCleaned} cleaned, {report.FilesWithNothingToRemove} had nothing to remove, {report.FilesFailed} failed. Reclaimed {report.TotalBytesReclaimed} bytes.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
			return;
		}
		finally
		{
			AreElementsEnabled = true;
			MainInfoBar.IsClosable = true;
		}

		// Offer the user to save the detailed JSON report of the operation to disk.
		try
		{
			string? jsonPath = FileDialogHelper.ShowSaveFileDialog(Atlas.JSONPickerFilter, "EXIFBulkRemovalReport.json");
			if (string.IsNullOrWhiteSpace(jsonPath))
			{
				return;
			}

			if (!jsonPath.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
			{
				jsonPath += ".json";
			}

			await Task.Run(() =>
			{
				string json = JsonSerializer.Serialize(report, ExifBulkRemovalJsonContext.Default.ExifBulkRemovalReport);
				File.WriteAllText(jsonPath, json, Encoding.UTF8);
			});

			MainInfoBar.WriteSuccess($"Successfully saved the bulk removal report to {jsonPath}");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Performs the actual bulk metadata removal work on a background thread and builds the detailed report.
	/// </summary>
	private ExifBulkRemovalReport RunBulkRemoval(List<string> folders)
	{
		DateTimeOffset startedAt = DateTimeOffset.Now;
		Stopwatch stopwatch = Stopwatch.StartNew();

		(IEnumerable<string> detectedFiles, int totalFilesFound) = FileUtility.GetFilesFast(folders, null, SupportedImageExtensions);

		List<ExifBulkFileResult> results = new(totalFilesFound);

		int filesCleaned = 0;
		int filesWithNothingToRemove = 0;
		int filesFailed = 0;
		long totalSizeBefore = 0;
		long totalSizeAfter = 0;
		int processedSoFar = 0;

		foreach (string filePath in detectedFiles)
		{
			processedSoFar++;

			// Periodically report progress without flooding the UI dispatcher.
			if (processedSoFar % 20 == 0)
			{
				MainInfoBar.WriteInfo($"Processing file {processedSoFar} of {totalFilesFound}...", noLogging: true);
			}

			long sizeBefore = 0;
			long sizeAfter = 0;

			try
			{
				sizeBefore = new FileInfo(filePath).Length;

				// Analyze the file exactly like loading it in the UI does.
				List<MetadataCategory> categories = EXIFScrubber.Analyze(filePath);

				// Collect every safe-to-remove category, exactly like pressing "Remove All" does.
				HashSet<string> toRemove = new(StringComparer.Ordinal);
				List<string> removedCategories = new(categories.Count);
				foreach (MetadataCategory category in categories)
				{
					if (category.IsSafeToRemove)
					{
						_ = toRemove.Add(category.CategoryId);
						removedCategories.Add(category.DisplayName);
					}
				}

				if (toRemove.Count == 0)
				{
					sizeAfter = sizeBefore;
					filesWithNothingToRemove++;
					results.Add(new ExifBulkFileResult(
						filePath: filePath,
						fileName: Path.GetFileName(filePath),
						directory: Path.GetDirectoryName(filePath) ?? string.Empty,
						status: "NothingToRemove",
						removedCategories: removedCategories,
						removedCategoryCount: 0,
						sizeBeforeBytes: sizeBefore,
						sizeAfterBytes: sizeAfter,
						sizeDifferenceBytes: 0,
						errorMessage: null));
				}
				else
				{
					EXIFScrubber.Scrub(filePath, toRemove);

					sizeAfter = new FileInfo(filePath).Length;
					filesCleaned++;
					results.Add(new ExifBulkFileResult(
						filePath: filePath,
						fileName: Path.GetFileName(filePath),
						directory: Path.GetDirectoryName(filePath) ?? string.Empty,
						status: "Cleaned",
						removedCategories: removedCategories,
						removedCategoryCount: toRemove.Count,
						sizeBeforeBytes: sizeBefore,
						sizeAfterBytes: sizeAfter,
						sizeDifferenceBytes: sizeBefore - sizeAfter,
						errorMessage: null));
				}
			}
			catch (Exception ex)
			{
				sizeAfter = sizeBefore;
				filesFailed++;
				results.Add(new ExifBulkFileResult(
					filePath: filePath,
					fileName: Path.GetFileName(filePath),
					directory: Path.GetDirectoryName(filePath) ?? string.Empty,
					status: "Failed",
					removedCategories: [],
					removedCategoryCount: 0,
					sizeBeforeBytes: sizeBefore,
					sizeAfterBytes: sizeAfter,
					sizeDifferenceBytes: 0,
					errorMessage: ex.Message));
			}

			totalSizeBefore += sizeBefore;
			totalSizeAfter += sizeAfter;
		}

		stopwatch.Stop();

		return new ExifBulkRemovalReport(
			format: "Harden System Security EXIF Bulk Removal Report",
			generatedAt: DateTimeOffset.Now,
			operationStartedAt: startedAt,
			durationMilliseconds: stopwatch.ElapsedMilliseconds,
			selectedFolders: folders,
			supportedExtensions: [.. SupportedImageExtensions],
			totalFilesFound: totalFilesFound,
			filesCleaned: filesCleaned,
			filesWithNothingToRemove: filesWithNothingToRemove,
			filesFailed: filesFailed,
			totalSizeBeforeBytes: totalSizeBefore,
			totalSizeAfterBytes: totalSizeAfter,
			totalBytesReclaimed: totalSizeBefore - totalSizeAfter,
			results: results);
	}
}

internal sealed partial class MetadataTag(string name, string value)
{
	internal string Name => name;
	internal string Value => value;
}

// Inherits from INotifyPropertyChanged to support the Expand/Collapse all features
internal sealed partial class MetadataCategory(string categoryId, string displayName, bool isSafeToRemove) : INotifyPropertyChanged
{
	public event PropertyChangedEventHandler? PropertyChanged;
	private void OnPropertyChanged([CallerMemberName] string? propertyName = null) => PropertyChanged?.Invoke(this, new(propertyName));

	internal string CategoryId => categoryId;
	internal string DisplayName => displayName;
	internal bool IsSafeToRemove { get; set; } = isSafeToRemove;
	internal Visibility RemoveButtonVisibility => IsSafeToRemove ? Visibility.Visible : Visibility.Collapsed;
	internal bool IsExpanded
	{
		get; set
		{
			if (field != value)
			{
				field = value;
				OnPropertyChanged();
			}
		}
	} = true;
	internal readonly ObservableCollection<MetadataTag> Tags = [];
}

/// <summary>
/// Identifies which Image File Directory is currently being walked.
/// This is required because the Exif specification gives every IFD kind its own independent tag number space,
/// and because only the 0th/1st IFD pair is linked together by an "offset to the next IFD" field.
/// Sources:
/// JEITA CP-3451C / CIPA DC-008-2012 - 4.6.2 IFD Structure, 4.6.3 Exif-specific IFD, Table 15 (GPS Attribute Information), Table 16 (Interoperability IFD Attribute Information)
/// TIFF 6.0 Specification - Pages 13-16 - Image File Directory
/// </summary>
internal enum ExifIfdKind
{
	// The 0th IFD. It describes the primary image and uses the TIFF/Exif tag number space.
	Primary,

	// The 1st IFD. It describes the embedded thumbnail and uses the same TIFF/Exif tag number space as the 0th IFD.
	Thumbnail,

	// The Exif private IFD referenced by tag 0x8769. It uses the TIFF/Exif tag number space.
	ExifPrivate,

	// The GPS Info IFD referenced by tag 0x8825. It has its own tag number space (0x0000 - 0x001F).
	Gps,

	// The Interoperability IFD referenced by tag 0xA005. It has its own tag number space (0x0001, 0x0002, 0x1000 - 0x1002).
	Interoperability
}

internal sealed partial class MetadataContext
{
	internal readonly Dictionary<string, MetadataCategory> CategoriesMap = new(StringComparer.Ordinal);

	internal void AddTag(string categoryId, string categoryName, bool isSafeToRemove, string name, string value)
	{
		if (!CategoriesMap.TryGetValue(categoryId, out MetadataCategory? category))
		{
			category = new MetadataCategory(categoryId, categoryName, isSafeToRemove);
			CategoriesMap[categoryId] = category;
		}
		// A category is removable when at least one of the items it holds is removable.
		else if (isSafeToRemove)
		{
			category.IsSafeToRemove = true;
		}
		category.Tags.Add(new MetadataTag(name, value));
	}
}

/// <summary>
/// The core Embedded EXIF Scrubber logic.
/// It only removes metadata that won't affect the photo in a negative way whatsoever and maintains 100% visual integrity of the photo.
/// </summary>
internal static class EXIFScrubber
{
	// Tag number for Orientation
	// Source: https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf
	// Page 36 - TIFF 6.0 Specification - 274 (112.H)
	private const int OrientationTag = 0x0112;

	// Source: 4.6.3 Exif-specific IFD - JEITA CP-3451C / CIPA DC-008-2012
	private const int ExifIFD = 0x8769;
	private const int GPSIFD = 0x8825;
	private const int InteroperabilityIFD = 0xA005;

	private static readonly uint[] CrcTable = GenerateCrcTable();

	internal static List<MetadataCategory> Analyze(string inputFilePath)
	{
		MetadataContext ctx = new();
		using FileStream inputStream = new(inputFilePath, FileMode.Open, FileAccess.Read);
		ProcessFile(inputStream, null, null, ctx, inputFilePath);

		List<MetadataCategory> resultList = new(ctx.CategoriesMap.Count);
		foreach (MetadataCategory category in ctx.CategoriesMap.Values)
		{
			resultList.Add(category);
		}
		return resultList;
	}

	internal static void Scrub(string inputFilePath, HashSet<string> categoriesToRemove)
	{
		using MemoryStream memoryStream = new();

		// Enclosing in using to ensure it releases the file lock before we write
		using (FileStream inputStream = new(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
		{
			ProcessFile(inputStream, memoryStream, categoriesToRemove, null, inputFilePath);
		}

		// Overwrite the original file with the in-memory scrubbed data
		using FileStream outputStream = new(inputFilePath, FileMode.Create, FileAccess.Write, FileShare.None);
		memoryStream.Position = 0;
		memoryStream.CopyTo(outputStream);
	}

	private static void ProcessFile(Stream inputStream, Stream? outputStream, HashSet<string>? categoriesToRemove, MetadataContext? ctx, string absoluteInputPath)
	{
		string extension = Path.GetExtension(absoluteInputPath);

		if (ctx != null)
		{
			FileInfo fi = new(absoluteInputPath);
			ctx.AddTag("FileInfo", "File Information", false, "File Name", fi.Name);
			ctx.AddTag("FileInfo", "File Information", false, "Directory", fi.DirectoryName ?? ".");
			ctx.AddTag("FileInfo", "File Information", false, "File Size", $"{Math.Round(fi.Length / 1000.0)} kB");
			ctx.AddTag("FileInfo", "File Information", false, "File Modification Date/Time", fi.LastWriteTime.ToString("yyyy:MM:dd HH:mm:sszzz"));
			ctx.AddTag("FileInfo", "File Information", false, "File Access Date/Time", fi.LastAccessTime.ToString("yyyy:MM:dd HH:mm:sszzz"));
			ctx.AddTag("FileInfo", "File Information", false, "File Creation Date/Time", fi.CreationTime.ToString("yyyy:MM:dd HH:mm:sszzz"));
		}

		if (string.Equals(extension, ".jpg", StringComparison.OrdinalIgnoreCase) || string.Equals(extension, ".jpeg", StringComparison.OrdinalIgnoreCase))
		{
			if (ctx != null)
			{
				ctx.AddTag("FileInfo", "File Information", false, "File Type", "JPEG");
				ctx.AddTag("FileInfo", "File Information", false, "File Type Extension", "jpg");
				ctx.AddTag("FileInfo", "File Information", false, "MIME Type", "image/jpeg");
			}
			ProcessJpeg(inputStream, outputStream, categoriesToRemove, ctx);
		}
		else if (string.Equals(extension, ".png", StringComparison.OrdinalIgnoreCase))
		{
			if (ctx != null)
			{
				ctx.AddTag("FileInfo", "File Information", false, "File Type", "PNG");
				ctx.AddTag("FileInfo", "File Information", false, "File Type Extension", "png");
				ctx.AddTag("FileInfo", "File Information", false, "MIME Type", "image/png");
			}
			ProcessPng(inputStream, outputStream, categoriesToRemove, ctx);
		}
		else
		{
			throw new NotSupportedException("Only JPG/JPEG and PNG files are supported at the moment.");
		}
	}

	private static void ProcessJpeg(Stream inputStream, Stream? outputStream, HashSet<string>? categoriesToRemove, MetadataContext? ctx)
	{
		// Source: ISO/IEC 10918-1 : 1993(E) - B.1.1.2 Marker
		// https://www.w3.org/Graphics/JPEG/itu-t81.pdf
		const byte startOfMarker = 0xFF;
		const byte startOfImage = 0xD8;
		const byte endOfImage = 0xD9;

		// Start of Image marker
		Span<byte> soi = stackalloc byte[2];
		inputStream.ReadExactly(soi);

		// Source: ISO/IEC 10918-1 : 1993(E) - Table B.1 – Marker code assignments
		// https://www.w3.org/Graphics/JPEG/itu-t81.pdf
		if (soi[0] != startOfMarker || soi[1] != startOfImage)
		{
			throw new InvalidDataException("Not a valid JPEG file.");
		}

		outputStream?.Write(soi);

		Span<byte> markerPrefix = stackalloc byte[1];
		Span<byte> markerTypeBuffer = stackalloc byte[1];
		Span<byte> lengthBuffer = stackalloc byte[2];
		Span<byte> replacementLenBytes = stackalloc byte[2];

		// Holds a marker type byte that was already consumed from the stream by the entropy-coded data
		// scanner after an SOS segment, so the next loop iteration processes it without re-reading it.
		int pendingMarkerType = -1;

		while (true)
		{
			byte markerType;

			if (pendingMarkerType >= 0)
			{
				markerType = (byte)pendingMarkerType;
				pendingMarkerType = -1;
			}
			else
			{
				int bytesRead = inputStream.Read(markerPrefix);

				// Shouldn't hit for normal JPEG files. It's defensive here for corrupt image files.
				if (bytesRead == 0)
				{
					break;
				}

				// Source: ISO/IEC 10918-1 : 1993(E) - B.1.1.2 Markers
				// "All markers are assigned two-byte codes: an X'FF' byte followed by a byte which is not equal to 0 or X'FF'."
				// If the byte is not 0xFF, it means we are encountering unexpected garbage data or proprietary padding between segments.
				// We safely write this non-standard byte to the output to avoid corrupting the file and continue scanning for the next true marker.
				if (markerPrefix[0] != startOfMarker)
				{
					outputStream?.Write(markerPrefix);
					continue;
				}

				// Read the second byte of the marker to identify its type
				inputStream.ReadExactly(markerTypeBuffer);
				markerType = markerTypeBuffer[0];

				// Source: ISO/IEC 10918-1 : 1993(E) - B.1.1.2 Markers
				// "Any marker may optionally be preceded by any number of fill bytes, which are bytes assigned code X'FF'."
				// This loop safely consumes any legal 0xFF padding fill bytes until it finds the actual marker type byte.
				while (markerType == startOfMarker)
				{
					outputStream?.WriteByte(startOfMarker);
					inputStream.ReadExactly(markerTypeBuffer);
					markerType = markerTypeBuffer[0];
				}

				// 0x00 is not a valid marker type. It is used exclusively to escape 0xFF in entropy-coded data.
				// If we encounter it here, it means the segment is malformed or contains garbage bytes.
				// We output it safely to prevent stream desynchronization and continue looking for a true marker.
				if (markerType == 0x00)
				{
					outputStream?.WriteByte(startOfMarker);
					outputStream?.WriteByte(markerType);
					continue;
				}
			}

			// RSTm: Restart marker – A conditional marker which is placed between entropy - coded segments only if restart
			// is enabled. There are 8 unique restart markers(m = 0 - 7) which repeat in sequence from 0 to 7, starting with
			// zero for each scan, to provide a modulo 8 restart interval count.
			// Source: ISO/IEC 10918-1 : 1993(E) - B.2.1

			// 0xD8 (SOI): Start of Image - source mentioned at top.
			// 0xD9 (EOI): End of Image - source mentioned at top.

			// 0x01 (TEM): For temporary private use in arithmetic coding
			// Source: ISO/IEC 10918-1 : 1993(E) - Table B.1 – Marker code assignments - Reserved markers

			// Standalone markers (RSTm, SOI, EOI, TEM) do not have a 2-byte length field following them.
			// If we do not intercept them here and `continue` or `break`, the parser would drop down,
			// read the next 2 bytes of actual image data as a "length", and try to skip ahead.
			// This would instantly corrupt the parsing state and break the image.
			// Source: ISO/IEC 10918-1 : 1993(E) - B.1.1.4 Marker segments
			if (markerType == endOfImage)
			{
				outputStream?.WriteByte(startOfMarker);
				outputStream?.WriteByte(markerType);

				// We reached the absolute end of the image datastream. Any bytes that follow the EOI marker are
				// not part of the image and are handled as a removable trailing data category.
				HandleTrailingData(inputStream, outputStream, categoriesToRemove, ctx, "EOI (End of Image) marker");
				break;
			}

			if ((markerType >= 0xD0 && markerType <= startOfImage) || markerType == 0x01)
			{
				outputStream?.WriteByte(startOfMarker);
				outputStream?.WriteByte(markerType);
				continue; // Jumping back to the top of the while(true) loop to read the next byte.
			}

			inputStream.ReadExactly(lengthBuffer);
			int markerLength = BinaryPrimitives.ReadUInt16BigEndian(lengthBuffer);
			int payloadLength = markerLength - 2;

			// Since the length parameter includes itself, a valid length must be at least 2.
			// Anything less indicates file corruption or a completely invalid marker segment.
			if (payloadLength < 0)
			{
				throw new InvalidDataException("Invalid marker length encountered in JPEG.");
			}

			byte[] payload = new byte[payloadLength];
			if (payloadLength > 0)
			{
				inputStream.ReadExactly(payload, 0, payloadLength);
			}

			string chunkType = IdentifyJpegChunk(markerType, payload);

			bool isSafeToRemove = chunkType switch
			{
				"COM" => true,
				"JFXX" => true,
				"EXIF" => true,
				"XMP" => true,
				"ExtendedXMP" => true,
				"Photoshop/IRB" => true,
				"Ducky" => true,
				_ => false
			};

			string categoryName = chunkType switch
			{
				"EXIF" => "EXIF Metadata",
				"XMP" => "XMP Metadata",
				"ExtendedXMP" => "Extended XMP Metadata",
				"Photoshop/IRB" => "Photoshop IRB",
				"COM" => "Comment Data",
				"JFXX" => "JFXX Thumbnail",
				"Ducky" => "Adobe Save-for-Web (Ducky)",
				"ICC_PROFILE" => "ICC Color Profile",
				"JFIF" => "JFIF Header",
				_ => chunkType.StartsWith("APP", StringComparison.OrdinalIgnoreCase) ? $"Application Marker ({chunkType})" : chunkType
			};

			if (outputStream != null)
			{
				bool shouldRemove = isSafeToRemove && categoriesToRemove != null && categoriesToRemove.Contains(chunkType);

				// The standard XMP segment and the ExtendedXMP segments form one logical XMP packet:
				// the standard packet carries an xmpNote:HasExtendedXMP GUID that references the ExtendedXMP segments.
				// Source: https://github.com/adobe/XMP-Toolkit-SDK/blob/main/docs/XMPSpecificationPart3.pdf - 1.1.3.1 Extended XMP in JPEG
				// Removing only one of the two would either leave the ExtendedXMP payload orphaned inside the file
				// (metadata survives the removal) or leave a dangling GUID reference in the standard packet,
				// so a removal request for either category always removes both.
				if (!shouldRemove && categoriesToRemove != null &&
					(string.Equals(chunkType, "XMP", StringComparison.OrdinalIgnoreCase) || string.Equals(chunkType, "ExtendedXMP", StringComparison.OrdinalIgnoreCase)) &&
					(categoriesToRemove.Contains("XMP") || categoriesToRemove.Contains("ExtendedXMP")))
				{
					shouldRemove = true;
				}

				if (shouldRemove)
				{
					byte[]? replacementPayload = null;

					// Defensive: Ensure the EXIF payload is long enough before slicing off the 6-byte "Exif\0\0" header.
					// This prevents ArgumentOutOfRangeException on truncated or malformed EXIF segments.
					if (string.Equals(chunkType, "EXIF", StringComparison.OrdinalIgnoreCase) && payloadLength > 6)
					{
						ReadOnlySpan<byte> tiffData = new(payload, 6, payloadLength - 6);

						// Orientation is SHORT according to the schema: https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf
						ushort? orientation = GetExifOrientation(tiffData);
						if (orientation.HasValue)
						{
							replacementPayload = CreateMinimalExifJpeg(orientation.Value);
						}
					}

					// If replacementPayload is null, we intentionally omit (remove) this marker segment.
					if (replacementPayload != null)
					{
						outputStream.WriteByte(startOfMarker);
						outputStream.WriteByte(markerType);

						BinaryPrimitives.WriteUInt16BigEndian(replacementLenBytes, (ushort)(replacementPayload.Length + 2));
						outputStream.Write(replacementLenBytes);
						outputStream.Write(replacementPayload);
					}
				}
				else
				{
					outputStream.WriteByte(startOfMarker);
					outputStream.WriteByte(markerType);
					outputStream.Write(lengthBuffer);
					if (payloadLength > 0)
					{
						outputStream.Write(payload, 0, payloadLength);
					}
				}
			}
			else if (ctx != null)
			{
				// Analysis Mode
				if (string.Equals(chunkType, "EXIF", StringComparison.OrdinalIgnoreCase))
				{
					// Defensive: prevent slicing exceptions for truncated EXIF segments.
					if (payloadLength > 6)
					{
						ReadOnlySpan<byte> tiffData = new(payload, 6, payloadLength - 6);
						ParseExif(tiffData, chunkType, categoryName, ctx);
					}
					else
					{
						// If the EXIF segment is truncated, it will be marked as safe-to-remove on the UI.
						ctx.AddTag(chunkType, categoryName, true, "Marker Data", $"(Truncated EXIF segment: {payloadLength} bytes)");
					}
				}
				else if (string.Equals(chunkType, "XMP", StringComparison.OrdinalIgnoreCase) ||
						 string.Equals(chunkType, "ExtendedXMP", StringComparison.OrdinalIgnoreCase))
				{
					ParseXmp(payload, chunkType, categoryName, ctx);
				}
				else if (string.Equals(chunkType, "Photoshop/IRB", StringComparison.OrdinalIgnoreCase))
				{
					ParsePhotoshopIrb(payload, chunkType, categoryName, ctx);
				}
				else if (string.Equals(chunkType, "COM", StringComparison.OrdinalIgnoreCase))
				{
					string commentData = Encoding.UTF8.GetString(payload).Trim('\0');
					ctx.AddTag(chunkType, categoryName, true, "Comment", commentData);
				}
				else if (string.Equals(chunkType, "JFXX", StringComparison.OrdinalIgnoreCase))
				{
					ctx.AddTag(chunkType, categoryName, true, "JFXX Thumbnail", "(Binary Data)");
				}
				else if (string.Equals(chunkType, "ICC_PROFILE", StringComparison.OrdinalIgnoreCase))
				{
					ParseIccProfile(payload, chunkType, categoryName, ctx);
				}
				else if (markerType == 0xE0 && payloadLength >= 14 && payload.AsSpan(0, 5).SequenceEqual("JFIF\0"u8))
				{
					ParseJfif(payload, chunkType, categoryName, ctx);
				}
				else if (markerType >= 0xC0 && markerType <= 0xC2)
				{
					ParseSof(markerType, payload, "ImageProperties", "Image Properties", ctx);
				}
				else
				{
					ctx.AddTag(chunkType, categoryName, isSafeToRemove, "Marker Data", $"(Binary Data {payloadLength} bytes)");
				}

				if (isSafeToRemove && !ctx.CategoriesMap.ContainsKey(chunkType))
				{
					ctx.AddTag(chunkType, categoryName, true, "Marker Data", $"(Unparsable {chunkType} segment: {payloadLength} bytes)");
				}
			}

			if (markerType == 0xDA)
			{
				// The entropy-coded scan data follows the SOS header segment. Instead of blindly copying the rest
				// of the file (which would also preserve any metadata segments between progressive scans and any
				// tracking data appended after the EOI marker), scan through the entropy-coded data to find the
				// next true marker and hand it back to this loop for regular processing.
				pendingMarkerType = CopyEntropyCodedData(inputStream, outputStream);
				if (pendingMarkerType < 0)
				{
					break; // The stream ended inside the entropy-coded data (truncated file, no EOI marker). Everything read was copied through.
				}
			}
		}
	}

	/// <summary>
	/// Copies JPEG entropy-coded scan data through to the output until the next true marker is found.
	/// Stuffed bytes (0xFF00), restart markers (RST0-RST7) and fill bytes (0xFF padding) are part of the
	/// entropy-coded data stream and are copied through verbatim.
	/// Source: ISO/IEC 10918-1 : 1993(E) - B.1.1.2 Markers / B.1.1.5 Entropy-coded data segments / B.2.1 High-level syntax.
	/// </summary>
	/// <returns>The marker type byte of the next true marker (its 0xFF prefix and the type byte are consumed but not written), or -1 when the stream ends.</returns>
	private static int CopyEntropyCodedData(Stream inputStream, Stream? outputStream)
	{
		if (inputStream.CanSeek)
		{
			byte[] buffer = new byte[65536];
			int length = 0;
			int pos = 0;

			while (true)
			{
				if (pos >= length)
				{
					length = inputStream.Read(buffer, 0, buffer.Length);
					pos = 0;
					if (length == 0) return -1;
				}

				int ffIndex = Array.IndexOf(buffer, (byte)0xFF, pos, length - pos);
				if (ffIndex < 0)
				{
					// No marker prefix in the remainder of the buffer: it is all entropy-coded data.
					outputStream?.Write(buffer, pos, length - pos);
					pos = length;
					continue;
				}

				// Write the entropy-coded bytes that precede the 0xFF.
				outputStream?.Write(buffer, pos, ffIndex - pos);
				pos = ffIndex;

				// The byte following the 0xFF decides what it is; refill the buffer if the 0xFF was its last byte.
				if (pos + 1 >= length)
				{
					buffer[0] = 0xFF;
					int refilled = inputStream.Read(buffer, 1, buffer.Length - 1);
					if (refilled == 0)
					{
						// The file ends with a dangling 0xFF: copy it through and report end of stream.
						outputStream?.WriteByte(0xFF);
						return -1;
					}
					length = refilled + 1;
					pos = 0;
				}

				byte next = buffer[pos + 1];

				if (next == 0x00 || (next >= 0xD0 && next <= 0xD7))
				{
					// 0xFF00 is a stuffed data byte and RST0-RST7 are restart markers: both stay inside the scan data.
					outputStream?.WriteByte(0xFF);
					outputStream?.WriteByte(next);
					pos += 2;
					continue;
				}

				if (next == 0xFF)
				{
					// A fill byte. Write one 0xFF and re-examine from the second one, which may itself precede a marker.
					outputStream?.WriteByte(0xFF);
					pos += 1;
					continue;
				}

				// A true marker terminates the entropy-coded data. Rewind the stream so its position sits
				// immediately after the marker type byte, then let the caller process the marker.
				pos += 2;
				_ = inputStream.Seek(pos - length, SeekOrigin.Current);
				return next;
			}
		}

		// Byte-by-byte fallback for non-seekable streams where buffered over-reading cannot be rewound.
		// Each read returns the byte value as an int (or -1 at end of stream) so that every byte is
		// evaluated as its own value instead of re-reading the single shared buffer element.
		Span<byte> single = stackalloc byte[1];
		while (true)
		{
			int current = ReadSingleByte(inputStream, single);
			if (current < 0) return -1;

			if (current != 0xFF)
			{
				outputStream?.WriteByte((byte)current);
				continue;
			}

			// Consume any fill bytes: every 0xFF that is followed by another 0xFF is padding.
			int next;
			while (true)
			{
				next = ReadSingleByte(inputStream, single);
				if (next < 0)
				{
					outputStream?.WriteByte(0xFF);
					return -1;
				}
				if (next != 0xFF) break;
				outputStream?.WriteByte(0xFF);
			}

			if (next == 0x00 || (next >= 0xD0 && next <= 0xD7))
			{
				outputStream?.WriteByte(0xFF);
				outputStream?.WriteByte((byte)next);
				continue;
			}

			return next;
		}
	}

	/// <summary>
	/// Reads a single byte from the stream into the supplied one byte scratch buffer.
	/// </summary>
	/// <returns>The value of the byte that was read, or -1 when the stream ended.</returns>
	private static int ReadSingleByte(Stream inputStream, Span<byte> scratch) => inputStream.Read(scratch) == 0 ? -1 : scratch[0];

	/// <summary>
	/// Handles any bytes that remain in the input stream after the logical end of the image datastream
	/// (the EOI marker for JPEG, the IEND chunk for PNG). Decoders stop at the end-of-image structure, so this
	/// appended data never affects how the image renders, yet it is a well known hiding place for tracking
	/// payloads (vendor trailers, appended archives and similar).
	/// In analysis mode the data is reported as a removable category; in scrub mode it is dropped when its
	/// category was selected for removal and copied through verbatim otherwise.
	/// </summary>
	private static void HandleTrailingData(Stream inputStream, Stream? outputStream, HashSet<string>? categoriesToRemove, MetadataContext? ctx, string endMarkerName)
	{
		if (outputStream != null)
		{
			if (categoriesToRemove != null && categoriesToRemove.Contains("TrailingData"))
			{
				return; // Drop everything after the end of the image datastream.
			}

			inputStream.CopyTo(outputStream);
			return;
		}

		if (ctx != null)
		{
			// Count the remaining bytes without loading them all into memory.
			byte[] buffer = new byte[81920];
			long trailingBytes = 0;
			int bytesRead;
			while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
			{
				trailingBytes += bytesRead;
			}

			if (trailingBytes > 0)
			{
				ctx.AddTag("TrailingData", "Trailing Data", true, "Appended Data", $"(Binary Data {trailingBytes} bytes after the {endMarkerName})");
			}
		}
	}

	private static void ProcessPng(Stream inputStream, Stream? outputStream, HashSet<string>? categoriesToRemove, MetadataContext? ctx)
	{
		Span<byte> signature = stackalloc byte[8];
		inputStream.ReadExactly(signature);

		ReadOnlySpan<byte> expectedSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

		if (!signature.SequenceEqual(expectedSignature))
		{
			throw new InvalidDataException("Not a valid PNG file.");
		}

		outputStream?.Write(signature);

		Span<byte> lengthBuffer = stackalloc byte[4];
		Span<byte> typeBuffer = stackalloc byte[4];
		Span<byte> crcBuffer = stackalloc byte[4];
		Span<byte> replacementLenBytes = stackalloc byte[4];
		Span<byte> newCrcBytes = stackalloc byte[4];

		byte[] chunkStreamBuffer = new byte[81920];

		while (true)
		{
			int bytesRead = inputStream.Read(lengthBuffer);
			if (bytesRead == 0)
			{
				break;
			}
			if (bytesRead < 4)
			{
				inputStream.ReadExactly(lengthBuffer[bytesRead..]);
			}

			inputStream.ReadExactly(typeBuffer);

			uint chunkLength = BinaryPrimitives.ReadUInt32BigEndian(lengthBuffer);
			string chunkType = Encoding.ASCII.GetString(typeBuffer);

			if (chunkLength > int.MaxValue)
			{
				throw new InvalidDataException("Invalid PNG chunk length encountered. The PNG specification does not allow a chunk length greater than 2147483647 bytes.");
			}
			bool isSafeToRemove = string.Equals(chunkType, "eXIf", StringComparison.Ordinal) ||
							  string.Equals(chunkType, "tEXt", StringComparison.Ordinal) ||
							  string.Equals(chunkType, "zTXt", StringComparison.Ordinal) ||
							  string.Equals(chunkType, "iTXt", StringComparison.Ordinal) ||
							  string.Equals(chunkType, "tIME", StringComparison.Ordinal);

			string categoryName = chunkType switch
			{
				"eXIf" => "EXIF Metadata",
				"tEXt" => "Text Data",
				"zTXt" => "Compressed Text Data",
				"iTXt" => "International Text Data",
				"tIME" => "Timestamp",
				"iCCP" => "ICC Color Profile",
				"pHYs" => "Physical Dimensions",
				"IHDR" => "Image Header",
				_ => chunkType
			};

			if (outputStream == null)
			{
				if (string.Equals(chunkType, "IDAT", StringComparison.Ordinal))
				{
					_ = inputStream.Seek(chunkLength, SeekOrigin.Current);
					inputStream.ReadExactly(crcBuffer);
					continue;
				}

				byte[] chunkPayload = new byte[chunkLength];
				if (chunkLength > 0)
				{
					inputStream.ReadExactly(chunkPayload, 0, (int)chunkLength);
				}
				inputStream.ReadExactly(crcBuffer);

				if (ctx != null)
				{
					if (string.Equals(chunkType, "eXIf", StringComparison.Ordinal))
					{
						ReadOnlySpan<byte> tiffData = new(chunkPayload);
						ParseExif(tiffData, chunkType, categoryName, ctx);
					}
					else if (string.Equals(chunkType, "tEXt", StringComparison.Ordinal))
					{
						int nullIdx = Array.IndexOf(chunkPayload, (byte)0);
						if (nullIdx >= 0 && nullIdx < chunkLength - 1)
						{
							string keyword = Encoding.ASCII.GetString(chunkPayload, 0, nullIdx);
							string textData = Encoding.UTF8.GetString(chunkPayload, nullIdx + 1, (int)chunkLength - nullIdx - 1);
							ctx.AddTag(chunkType, categoryName, true, keyword, textData);
						}
						else
						{
							ctx.AddTag(chunkType, categoryName, true, "Text Block", "(Binary Data)");
						}
					}
					else if (string.Equals(chunkType, "iTXt", StringComparison.Ordinal) ||
							 string.Equals(chunkType, "zTXt", StringComparison.Ordinal))
					{
						int nullIdx = Array.IndexOf(chunkPayload, (byte)0);
						if (nullIdx >= 0)
						{
							string keyword = Encoding.ASCII.GetString(chunkPayload, 0, nullIdx);
							ctx.AddTag(chunkType, categoryName, true, keyword, "(Compressed Data)");
						}
						else
						{
							ctx.AddTag(chunkType, categoryName, true, "Compressed Block", "(Binary Data)");
						}
					}
					else if (string.Equals(chunkType, "tIME", StringComparison.Ordinal))
					{
						ctx.AddTag(chunkType, categoryName, true, "Timestamp", "(Time Data)");
					}
					else if (string.Equals(chunkType, "iCCP", StringComparison.Ordinal))
					{
						ctx.AddTag(chunkType, categoryName, false, "Profile Data", "[Kept for Visual Fidelity]");
					}
					else if (string.Equals(chunkType, "pHYs", StringComparison.Ordinal))
					{
						ctx.AddTag(chunkType, categoryName, false, "Dimensions", "[Kept for Visual Fidelity]");
					}
					else if (string.Equals(chunkType, "IHDR", StringComparison.Ordinal) && chunkLength >= 13)
					{
						uint width = BinaryPrimitives.ReadUInt32BigEndian(chunkPayload.AsSpan(0, 4));
						uint height = BinaryPrimitives.ReadUInt32BigEndian(chunkPayload.AsSpan(4, 4));
						byte bitDepth = chunkPayload[8];
						byte colorType = chunkPayload[9];

						ctx.AddTag(chunkType, categoryName, false, "Image Width", width.ToString());
						ctx.AddTag(chunkType, categoryName, false, "Image Height", height.ToString());
						ctx.AddTag(chunkType, categoryName, false, "Bits Per Sample", bitDepth.ToString());
						ctx.AddTag(chunkType, categoryName, false, "Color Components", colorType switch { 2 or 6 => "3", 4 or 0 => "1", 3 => "1 (Palette)", _ => "Unknown" });

						long pixels = (long)width * height;
						ctx.AddTag(chunkType, categoryName, false, "Image Size", $"{width}x{height}");
						ctx.AddTag(chunkType, categoryName, false, "Megapixels", (pixels / 1000000.0).ToString("F1"));
					}
					else if (!string.Equals(chunkType, "IEND", StringComparison.Ordinal))
					{
						ctx.AddTag(chunkType, categoryName, isSafeToRemove, "Chunk Data", $"(Binary Data {chunkLength} bytes)");
					}

					if (isSafeToRemove && !ctx.CategoriesMap.ContainsKey(chunkType))
					{
						ctx.AddTag(chunkType, categoryName, true, "Chunk Data", $"(Unparsable {chunkType} chunk: {chunkLength} bytes)");
					}
				}
			}
			else
			{
				bool shouldRemove = isSafeToRemove && categoriesToRemove != null && categoriesToRemove.Contains(chunkType);

				if (shouldRemove)
				{
					byte[] chunkPayload = new byte[chunkLength];
					if (chunkLength > 0)
					{
						inputStream.ReadExactly(chunkPayload, 0, (int)chunkLength);
					}
					inputStream.ReadExactly(crcBuffer);

					byte[]? replacementPayload = null;
					if (string.Equals(chunkType, "eXIf", StringComparison.Ordinal))
					{
						ReadOnlySpan<byte> tiffData = new(chunkPayload);
						ushort? orientation = GetExifOrientation(tiffData);
						if (orientation.HasValue)
						{
							replacementPayload = CreateMinimalExifPng(orientation.Value);
						}
					}

					if (replacementPayload != null)
					{
						BinaryPrimitives.WriteUInt32BigEndian(replacementLenBytes, (uint)replacementPayload.Length);
						outputStream.Write(replacementLenBytes);
						outputStream.Write(typeBuffer);
						outputStream.Write(replacementPayload);

						uint newCrc = CalculateCrc32(typeBuffer, replacementPayload);
						BinaryPrimitives.WriteUInt32BigEndian(newCrcBytes, newCrc);
						outputStream.Write(newCrcBytes);
					}
				}
				else
				{
					outputStream.Write(lengthBuffer);
					outputStream.Write(typeBuffer);

					uint remaining = chunkLength;
					while (remaining > 0)
					{
						int toRead = (int)Math.Min(remaining, (uint)chunkStreamBuffer.Length);
						inputStream.ReadExactly(chunkStreamBuffer, 0, toRead);
						outputStream.Write(chunkStreamBuffer, 0, toRead);
						remaining -= (uint)toRead;
					}

					inputStream.ReadExactly(crcBuffer);
					outputStream.Write(crcBuffer);
				}
			}

			if (string.Equals(chunkType, "IEND", StringComparison.Ordinal))
			{
				// Source: https://www.w3.org/TR/png-3/#5DataRep - "The IEND chunk marks the end of the PNG datastream."
				// Anything that follows it is not part of the image; it is reported and removed as trailing data.
				HandleTrailingData(inputStream, outputStream, categoriesToRemove, ctx, "IEND chunk");
				break;
			}
		}
	}

	private static string IdentifyJpegChunk(byte markerType, byte[] payload)
	{
		// Source: ISO/IEC 10918-1 : 1993(E) - Table B.1 – Marker code assignments - Other markers
		if (markerType == 0xFE)
		{
			return "COM";
		}

		if (markerType >= 0xE0 && markerType <= 0xEF)
		{
			if (markerType == 0xE0)
			{
				// Ensure payload contains at least 5 bytes
				// Source: 10.2 JFIF extension APP0 marker segment
				// ISO/IEC 10918-5:2012 (E)
				// https://www.ijg.org/files/T-REC-T.871-201105-I!!PDF-E.pdf
				if (payload.Length >= 5 && payload.AsSpan(0, 5).SequenceEqual("JFXX\0"u8))
					return "JFXX";
				if (payload.Length >= 5 && payload.AsSpan(0, 5).SequenceEqual("JFIF\0"u8))
					return "JFIF";
			}

			// For APP1 - Application Segment 1 - Exif attribution information
			// Source: https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf - Table 22 - Marker Segments
			if (markerType == 0xE1)
			{
				ReadOnlySpan<byte> pSpan = payload;
				// Read the first 6 bytes
				// 4 bytes for the letters E-x-i-f
				// 1 byte for the null terminator
				// 1 byte for the alignment padding
				// Source: https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf
				// JEITA CP-3451C / CIPA DC-008-2012 - 4.7.2 - interoperability Structure of APP1 in Compressed Data - Figure 30
				if (pSpan.Length >= 6 && pSpan[..6].SequenceEqual("Exif\0\0"u8))
				{
					return "EXIF";
				}
				// 28 characters + the null terminator at the end = 29 bytes
				// https://github.com/adobe/XMP-Toolkit-SDK/blob/main/docs/DynamicMediaXMPPartnerGuide.pdf
				if (pSpan.Length >= 29 && pSpan[..29].SequenceEqual("http://ns.adobe.com/xap/1.0/\0"u8))
				{
					return "XMP";
				}
				// 34 characters + the null terminator at the end = 35 bytes
				if (pSpan.Length >= 35 && pSpan[..35].SequenceEqual("http://ns.adobe.com/xmp/extension/\0"u8))
				{
					return "ExtendedXMP";
				}
			}

			// For APP2 - Application Segment 2 - Exif extended data
			// Source: https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf - Table 22 - Marker Segments
			// 11 characters + the null terminator at the end = 12 bytes
			if (markerType == 0xE2 && payload.Length >= 12 && payload.AsSpan(0, 12).SequenceEqual("ICC_PROFILE\0"u8))
			{
				return "ICC_PROFILE";
			}

			// APP13
			// The APPn designation with the range goes from 0xFFE0 to 0xFFEF means APP0 through APP15.
			// Source: https://www.w3.org/Graphics/JPEG/itu-t81.pdf - Table B.1 – Marker code assignments - Other markers
			// 13 characters + the null terminator at the end = 14 bytes
			if (markerType == 0xED && payload.Length >= 14 && payload.AsSpan(0, 14).SequenceEqual("Photoshop 3.0\0"u8))
			{
				return "Photoshop/IRB";
			}

			// APP12 "Ducky" - written by Adobe Photoshop "Save for Web".
			// It only carries editor metadata (the quality setting plus optional comment and copyright text)
			// and is never used for decoding, so removing it cannot affect how the image renders.
			// Source: https://exiftool.org/TagNames/APP12.html - identified by the ASCII signature "Ducky" at the start of the payload.
			if (markerType == 0xEC && payload.Length >= 5 && payload.AsSpan(0, 5).SequenceEqual("Ducky"u8))
			{
				return "Ducky";
			}

			// Find out the exact application segment number by subtracting the base value (0xE0) from the markerType byte we are currently reading.
			return $"APP{markerType - 0xE0}";
		}

		return markerType switch
		{
			0xDB => "DQT",
			0xC4 => "DHT",
			0xDD => "DRI",
			0xDA => "SOS",
			0xC0 => "SOF0",
			0xC1 => "SOF1",
			0xC2 => "SOF2",
			_ => $"Marker_{markerType:X2}"
		};
	}

	private static void ParseJfif(byte[] payload, string categoryId, string categoryName, MetadataContext ctx)
	{
		byte major = payload[5];
		byte minor = payload[6];
		byte unit = payload[7];
		ushort xRes = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(8, 2));
		ushort yRes = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(10, 2));

		string resUnit = unit switch
		{
			0 => "None",
			1 => "inches",
			2 => "cm",
			_ => "Unknown"
		};

		ctx.AddTag(categoryId, categoryName, false, "JFIF Version", $"{major}.{minor:D2}");
		ctx.AddTag(categoryId, categoryName, false, "Resolution Unit", resUnit);
		ctx.AddTag(categoryId, categoryName, false, "X Resolution", xRes.ToString());
		ctx.AddTag(categoryId, categoryName, false, "Y Resolution", yRes.ToString());
	}

	private static void ParseSof(byte markerType, byte[] payload, string categoryId, string categoryName, MetadataContext ctx)
	{
		if (payload.Length < 6)
		{
			return;
		}

		byte precision = payload[0];
		ushort height = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(1, 2));
		ushort width = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(3, 2));
		byte components = payload[5];

		string process = markerType switch
		{
			0xC0 => "Baseline DCT, Huffman coding",
			0xC1 => "Extended sequential DCT, Huffman coding",
			0xC2 => "Progressive DCT, Huffman coding",
			_ => $"Unknown ({markerType:X2})"
		};

		ctx.AddTag(categoryId, categoryName, false, "Image Width", width.ToString());
		ctx.AddTag(categoryId, categoryName, false, "Image Height", height.ToString());
		ctx.AddTag(categoryId, categoryName, false, "Encoding Process", process);
		ctx.AddTag(categoryId, categoryName, false, "Bits Per Sample", precision.ToString());
		ctx.AddTag(categoryId, categoryName, false, "Color Components", components.ToString());

		if (payload.Length >= 6 + (components * 3) && components == 3)
		{
			byte ySampling = payload[7];
			byte cbSampling = payload[10];
			byte crSampling = payload[13];
			string subsampling = GetSubSampling(ySampling, cbSampling, crSampling);
			ctx.AddTag(categoryId, categoryName, false, "Y Cb Cr Sub Sampling", subsampling);
		}

		long pixels = (long)width * height;
		double megaPixels = pixels / 1000000.0;
		ctx.AddTag(categoryId, categoryName, false, "Image Size", $"{width}x{height}");
		ctx.AddTag(categoryId, categoryName, false, "Megapixels", megaPixels.ToString("F1"));
	}

	private static string GetSubSampling(byte y, byte cb, byte cr)
	{
		int yH = y >> 4;
		int yV = y & 0x0F;
		int cbH = cb >> 4;
		int cbV = cb & 0x0F;
		int crH = cr >> 4;
		int crV = cr & 0x0F;

		if (yH == 2 && yV == 2 && cbH == 1 && cbV == 1 && crH == 1 && crV == 1) return "YCbCr4:2:0 (2 2)";
		if (yH == 2 && yV == 1 && cbH == 1 && cbV == 1 && crH == 1 && crV == 1) return "YCbCr4:2:2 (2 1)";
		if (yH == 1 && yV == 1 && cbH == 1 && cbV == 1 && crH == 1 && crV == 1) return "YCbCr4:4:4 (1 1)";
		if (yH == 1 && yV == 2 && cbH == 1 && cbV == 1 && crH == 1 && crV == 1) return "YCbCr4:4:0 (1 2)";

		return $"Unknown (Y:{yH}x{yV} Cb:{cbH}x{cbV} Cr:{crH}x{crV})";
	}

	private static void ParseIccProfile(byte[] payload, string categoryId, string categoryName, MetadataContext ctx)
	{
		if (payload.Length < 14) return;

		byte seqNum = payload[12];
		if (seqNum != 1) return;

		int iccOffset = 14;
		if (payload.Length < iccOffset + 132) return;

		ReadOnlySpan<byte> header = payload.AsSpan(iccOffset, 128);

		// Source: Spec ICC.1:2001-04 - 6.1 Header description - 4..7 is Preferred CMM type
		string cmmType = Encoding.ASCII.GetString(header.Slice(4, 4)).Trim('\0', ' ');
		ctx.AddTag(categoryId, categoryName, false, "Profile CMM Type", cmmType);

		byte maj = header[8];
		byte min = (byte)(header[9] >> 4);
		byte bug = (byte)(header[9] & 0x0F);
		ctx.AddTag(categoryId, categoryName, false, "Profile Version", $"{maj}.{min}.{bug}");

		string cls = Encoding.ASCII.GetString(header.Slice(12, 4));
		string clsName = cls switch { "scnr" => "Input Device Profile", "mntr" => "Display Device Profile", "prtr" => "Output Device Profile", _ => cls };
		ctx.AddTag(categoryId, categoryName, false, "Profile Class", clsName);

		string colorSpace = Encoding.ASCII.GetString(header.Slice(16, 4)).Trim('\0', ' ');
		ctx.AddTag(categoryId, categoryName, false, "Color Space Data", colorSpace);

		string pcs = Encoding.ASCII.GetString(header.Slice(20, 4)).Trim('\0', ' ');
		ctx.AddTag(categoryId, categoryName, false, "Profile Connection Space", pcs);

		string sig = Encoding.ASCII.GetString(header.Slice(36, 4));
		ctx.AddTag(categoryId, categoryName, false, "Profile File Signature", sig);

		string creator = Encoding.ASCII.GetString(header.Slice(80, 4)).Trim('\0', ' ');
		ctx.AddTag(categoryId, categoryName, false, "Profile Creator", creator);

		uint tagCount = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(iccOffset + 128, 4));
		int tagTableOffset = iccOffset + 132;

		uint maxTags = (uint)(payload.Length - tagTableOffset) / 12;
		uint tagsToRead = Math.Min(tagCount, maxTags);

		for (int i = 0; i < tagsToRead; i++)
		{
			int tagOffset = tagTableOffset + (i * 12);
			string tagSig = Encoding.ASCII.GetString(payload.AsSpan(tagOffset, 4)).Trim('\0', ' ');

			uint tagDataOffset = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(tagOffset + 4, 4));
			uint tagDataSize = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(tagOffset + 8, 4));

			string dataValue = "[Invalid Offset/Truncated]";
			if (iccOffset + tagDataOffset + tagDataSize <= payload.Length)
			{
				ReadOnlySpan<byte> tagData = payload.AsSpan(iccOffset + (int)tagDataOffset, (int)tagDataSize);
				dataValue = FormatIccData(tagData);
			}

			string humanReadableName = GetIccTagName(tagSig);
			ctx.AddTag(categoryId, categoryName, false, humanReadableName, dataValue);
		}
	}

	private static string FormatIccData(ReadOnlySpan<byte> data)
	{
		if (data.Length < 8) return $"(Binary data {data.Length} bytes)";

		string typeSig = Encoding.ASCII.GetString(data[..4]);
		try
		{
			return typeSig switch
			{
				"mluc" => ParseIccMluc(data),
				"XYZ " => ParseIccXyz(data),
				"text" => Encoding.ASCII.GetString(data[8..]).Trim('\0'),
				"desc" => ParseIccDesc(data),
				_ => $"(Binary data {data.Length} bytes)"
			};
		}
		catch { return $"(Binary data {data.Length} bytes)"; }
	}

	private static string ParseIccMluc(ReadOnlySpan<byte> data)
	{
		if (data.Length < 16) return "[Truncated mluc]";
		uint count = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(8, 4));
		if (count == 0) return "[Empty mluc]";

		uint recordSize = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(12, 4));
		if (16 + recordSize > data.Length) return "[Invalid mluc record]";

		uint strLen = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(16 + 4, 4));
		uint strOffset = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(16 + 8, 4));

		if (strOffset + strLen > data.Length) return "[mluc out of bounds]";

		return Encoding.BigEndianUnicode.GetString(data.Slice((int)strOffset, (int)strLen)).Trim('\0');
	}

	// Source: https://www.color.org/specification/ICC.1-2001-04.pdf
	// Page 63: 6.5.26 XYZType - Table 78 - XYZType encoding
	private static string ParseIccXyz(ReadOnlySpan<byte> data)
	{
		if (data.Length < 20) return "(Binary data)";
		double x = BinaryPrimitives.ReadInt32BigEndian(data.Slice(8, 4)) / 65536.0;
		double y = BinaryPrimitives.ReadInt32BigEndian(data.Slice(12, 4)) / 65536.0;
		double z = BinaryPrimitives.ReadInt32BigEndian(data.Slice(16, 4)) / 65536.0;
		return $"{x:0.0####} {y:0.0####} {z:0.0####}";
	}

	// Source: https://www.color.org/specification/ICC.1-2001-04.pdf
	// Page 58: textDescriptionType
	private static string ParseIccDesc(ReadOnlySpan<byte> data)
	{
		// Table 68 dictates the first 12 bytes (offsets 0..11) are mandatory structural headers.
		// If the data is smaller than 12 bytes, it is physically impossible to read the length.
		if (data.Length < 12) return "[Truncated desc]";

		// Section 4.1 mandates Big-Endian. Table 68 offsets 8..11 hold a uInt32Number
		// defining the "ASCII invariant description count" (the length of the string).
		uint strLen = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(8, 4));

		// Safely clamps the declared string length to the actual remaining byte array size.
		// This prevents OutOfRange exceptions if a corrupted file claims an impossible length.
		if (12 + strLen > data.Length) strLen = (uint)(data.Length - 12);

		// Table 68 offsets 12..n-1 mandate reading exactly "7-bit ASCII" text.
		// Trim('\0') explicitly satisfies the "including terminating null" spec requirement.
		return Encoding.ASCII.GetString(data.Slice(12, (int)strLen)).Trim('\0');
	}

	private static void ParsePhotoshopIrb(byte[] payload, string categoryId, string categoryName, MetadataContext ctx)
	{
		int pos = 14;

		while (pos + 12 <= payload.Length)
		{
			if (payload[pos] != '8' || payload[pos + 1] != 'B' || payload[pos + 2] != 'I' || payload[pos + 3] != 'M')
				break;
			pos += 4;

			ushort resId = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(pos, 2));
			pos += 2;

			byte nameLen = payload[pos];
			pos += 1;

			string name = string.Empty;
			if (nameLen > 0 && pos + nameLen <= payload.Length)
			{
				name = Encoding.ASCII.GetString(payload, pos, nameLen);
			}
			pos += nameLen;

			if ((nameLen + 1) % 2 != 0) pos += 1;

			if (pos + 4 > payload.Length) break;

			uint dataSize = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(pos, 4));
			pos += 4;

			// A resource cannot be larger than the bytes remaining in the segment. A corrupted or malicious
			// declared size would otherwise wrap negative in the "pos += (int)dataSize" advance below,
			// moving the cursor backwards and spinning this loop forever on the same resource block.
			if (dataSize > (uint)(payload.Length - pos)) break;

			string resName = $"Photoshop Resource {resId}";
			if (!string.IsNullOrEmpty(name)) resName += $" ({name})";

			if (resId == 1028 && pos + dataSize <= payload.Length)
			{
				byte[] iptcData = new byte[dataSize];
				Array.Copy(payload, pos, iptcData, 0, dataSize);
				ParseIptcStandalone(iptcData, categoryId, categoryName, ctx);
			}
			else
			{
				ctx.AddTag(categoryId, categoryName, true, resName, $"(Binary data {dataSize} bytes)");
			}

			pos += (int)dataSize;
			if (dataSize % 2 != 0) pos += 1;
		}
	}

	// Source: https://www.iptc.org/std/IIM/4.2/specification/IIMV4.2.pdf
	private static void ParseIptcStandalone(byte[] payload, string categoryId, string categoryName, MetadataContext ctx)
	{
		int i = 0;
		while (i + 5 <= payload.Length)
		{
			if (payload[i] == 0x1C && payload[i + 1] == 0x02)
			{
				byte recordId = payload[i + 2];
				ushort size = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(i + 3, 2));

				if (i + 5 + size <= payload.Length)
				{
					string iptcData = Encoding.UTF8.GetString(payload.AsSpan(i + 5, size)).Trim('\0');
					ctx.AddTag(categoryId, categoryName, true, $"IPTC Record 2:{recordId}", iptcData);
					i += 5 + size;
				}
				else break;
			}
			else
			{
				i++;
			}
		}
	}

	// Source: ISO 16684-1:2019 - https://cdn.standards.iteh.ai/samples/75163/2224cf4dffe346d198b11443c6833e89/ISO-16684-1-2019.pdf
	private static void ParseXmp(byte[] payload, string categoryId, string categoryName, MetadataContext ctx)
	{
		string xmpString = Encoding.UTF8.GetString(payload);
		int pos = 0;

		while ((pos = xmpString.IndexOf('<', pos)) != -1)
		{
			if (pos + 1 < xmpString.Length && (xmpString[pos + 1] == '?' || xmpString[pos + 1] == '!' || xmpString[pos + 1] == '/'))
			{
				pos++;
				continue;
			}

			int closeBracket = xmpString.IndexOf('>', pos);
			if (closeBracket == -1) break;

			int space = xmpString.IndexOf(' ', pos);
			int endTag = closeBracket;
			if (space != -1 && space < closeBracket) endTag = space;

			string tagName = xmpString.Substring(pos + 1, endTag - pos - 1);
			if (tagName.Contains(':') && !tagName.StartsWith("rdf:RDF", StringComparison.OrdinalIgnoreCase) && !tagName.StartsWith("x:xmpmeta", StringComparison.OrdinalIgnoreCase) && !tagName.StartsWith("rdf:Description", StringComparison.OrdinalIgnoreCase))
			{
				int nextOpenBracket = xmpString.IndexOf('<', closeBracket);
				string elementValue = string.Empty;

				if (nextOpenBracket != -1 && nextOpenBracket > closeBracket + 1)
				{
					elementValue = xmpString.Substring(closeBracket + 1, nextOpenBracket - closeBracket - 1).Trim();
				}

				if (string.IsNullOrEmpty(elementValue)) elementValue = "[Nested XML / Empty]";

				ctx.AddTag(categoryId, categoryName, true, $"XMP {tagName}", elementValue);
			}
			pos = closeBracket;
		}

		int descPos = 0;
		while ((descPos = xmpString.IndexOf("<rdf:Description", descPos, StringComparison.OrdinalIgnoreCase)) != -1)
		{
			int closeDesc = xmpString.IndexOf('>', descPos);
			if (closeDesc != -1)
			{
				string descTag = xmpString[descPos..closeDesc];
				string[] parts = descTag.Split(' ', StringSplitOptions.RemoveEmptyEntries);
				foreach (string part in parts)
				{
					if (part.Contains('=') && part.Contains(':') && !part.StartsWith("xmlns:", StringComparison.OrdinalIgnoreCase))
					{
						int eqIndex = part.IndexOf('=');
						string attrName = part[..eqIndex];

						if (!string.Equals(attrName, "rdf:about", StringComparison.OrdinalIgnoreCase))
						{
							string attrValue = part[(eqIndex + 1)..].Trim('"', '\'');
							ctx.AddTag(categoryId, categoryName, true, $"XMP Attribute ({attrName})", attrValue);
						}
					}
				}
				descPos = closeDesc;
			}
			else break;
		}
	}

	private static ushort? GetExifOrientation(ReadOnlySpan<byte> tiffData)
	{
		// A TIFF file begins with an 8-byte image file header
		// Source: https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf - Image File Header
		if (tiffData.Length < 8) return null;

		// Detecting byte order: "II" (4949.H) for little-endian and "MM" (4D4D.H) for big-endian
		// Source: https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf - Image File Header
		bool isLittleEndian;
		if (tiffData[0] == 0x49 && tiffData[1] == 0x49)
		{
			isLittleEndian = true;
		}
		else if (tiffData[0] == 0x4D && tiffData[1] == 0x4D)
		{
			isLittleEndian = false;
		}
		else
		{
			return null;
		}

		// Bytes 2-3 contain "An arbitrary but carefully chosen number (42) that further identifies the file as a TIFF file."
		// Source: Page 13 - https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf - Image File Header
		// Without this check any buffer that happens to begin with "II" or "MM" would be accepted as a valid TIFF.
		ushort magic = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(tiffData.Slice(2, 2)) : BinaryPrimitives.ReadUInt16BigEndian(tiffData.Slice(2, 2));
		if (magic != 0x002A) return null;

		// Read bytes 4-7 for IFD (Image File Directory)
		// Source: https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf - Image File Header
		uint ifdOffset = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(tiffData.Slice(4, 4)) : BinaryPrimitives.ReadUInt32BigEndian(tiffData.Slice(4, 4));

		// Validate the IFD data
		// If there isn't enough room left in this buffer to read the mandatory 2-byte Entry Count, abort parsing and return null.
		// The offset is widened to a 64-bit signed integer before the addition because "ifdOffset" is an unmodified
		// 32-bit value taken straight from the file.
		if ((long)ifdOffset + 2 > tiffData.Length) return null;

		// Read the 2-byte count of the number of directory entries (i.e., the number of fields)
		// This tells the for loop below exactly how many tags to look for.
		// Source: https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf - Image File Directory
		ushort entryCount = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(tiffData.Slice((int)ifdOffset, 2)) : BinaryPrimitives.ReadUInt16BigEndian(tiffData.Slice((int)ifdOffset, 2));
		long currentOffset = (long)ifdOffset + 2;

		for (int i = 0; i < entryCount; i++)
		{
			// The TIFF spec mandates 12-byte entries; this bounds check prevents crashes from truncated data or malicious entry counts.
			if (currentOffset + 12 > tiffData.Length) break;

			// Grab 12 bytes of data because every single piece of metadata (like the camera model, the date, or the orientation) is stored in a fixed-size block called a "Directory Entry" or "Field Entry."
			ReadOnlySpan<byte> entry = tiffData.Slice((int)currentOffset, 12);
			ushort tagId = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(entry[..2]) : BinaryPrimitives.ReadUInt16BigEndian(entry[..2]);

			if (tagId == OrientationTag)
			{
				// Bytes 2-3 are the field Type and bytes 4-7 are the Count. Both of them are mandatory to locate and to decode the value.
				// Source: https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf - Image File Directory - IFD Entry
				ushort dataType = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(entry.Slice(2, 2)) : BinaryPrimitives.ReadUInt16BigEndian(entry.Slice(2, 2));
				uint dataCount = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(4, 4)) : BinaryPrimitives.ReadUInt32BigEndian(entry.Slice(4, 4));

				// Isolates Bytes 8, 9, 10, and 11, the exact location where the metadata value is.
				// The specification mandates that this field is always exactly 4 bytes wide, regardless of how small the actual data is.
				ReadOnlySpan<byte> valueField = entry.Slice(8, 4);

				// Source: Page 15 - https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf - Image File Directory
				ulong totalBytes = (ulong)dataCount * (uint)GetExifComponentSize(dataType);
				if (totalBytes == 0) return null;

				ReadOnlySpan<byte> valueData;
				if (totalBytes <= 4)
				{
					valueData = valueField[..(int)totalBytes];
				}
				else
				{
					uint dataOffset = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(valueField) : BinaryPrimitives.ReadUInt32BigEndian(valueField);
					if (dataOffset + totalBytes > (ulong)tiffData.Length) return null;
					valueData = tiffData.Slice((int)dataOffset, (int)totalBytes);
				}

				uint rawValue;
				if (dataType == 1 && valueData.Length >= 1)
				{
					// BYTE. A single byte has no byte order, so it is read directly.
					rawValue = valueData[0];
				}
				else if (dataType == 3 && valueData.Length >= 2)
				{
					rawValue = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(valueData[..2]) : BinaryPrimitives.ReadUInt16BigEndian(valueData[..2]);
				}
				else if (dataType == 4 && valueData.Length >= 4)
				{
					rawValue = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(valueData[..4]) : BinaryPrimitives.ReadUInt32BigEndian(valueData[..4]);
				}
				else
				{
					return null;
				}

				// The specification enumerates exactly 8 legal orientations (1 through 8) and states "Default is 1".
				// Source: Pages 36-37 - https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf - Orientation
				// Source: Table 4 - https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf - JEITA CP-3451C / CIPA DC-008-2012
				return rawValue is >= 1 and <= 8 ? (ushort)rawValue : null;
			}
			currentOffset += 12;
		}
		return null;
	}

	private static byte[] CreateMinimalExifJpeg(ushort orientation)
	{
		// Source: https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf - Section 4.7.2
		// APP1 Structure
		byte[] payload = new byte[32];
		"Exif\0\0"u8.CopyTo(payload);
		CreateMinimalTiff(orientation).CopyTo(payload.AsSpan(6));
		return payload;
	}

	private static byte[] CreateMinimalExifPng(ushort orientation)
	{
		byte[] payload = new byte[26];
		CreateMinimalTiff(orientation).CopyTo(payload);
		return payload;
	}

	private static ReadOnlySpan<byte> CreateMinimalTiff(ushort orientation)
	{
		byte[] tiff = new byte[26];

		// Set the Byte Order as Little-Endian
		tiff[0] = 0x49; // I
		tiff[1] = 0x49; // I

		// Source: Page 13 - https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf
		// An arbitrary but carefully chosen number (42) that further identifies the file as a TIFF file.
		tiff[2] = 0x2A;
		tiff[3] = 0x00;

		// The offset (in bytes) of the first IFD.
		// Source: Page 13 - https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf
		tiff[4] = 0x08;
		tiff[5] = 0x00;
		tiff[6] = 0x00;
		tiff[7] = 0x00;

		// There must be at least 1 IFD in a TIFF file and each IFD must have at least one entry.
		// Source: Page 14 - Image File Directory - https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf
		// We are creating a minimal Exif profile that strips everything except the Orientation tag. Therefore, there is exactly 1 directory entry in this IFD.
		tiff[8] = 0x01;
		tiff[9] = 0x00;

		// IFD Entry: Each 12 - byte IFD entry has the following format.
		tiff[10] = 0x12; tiff[11] = 0x01; // The Tag that identifies the field.
		tiff[12] = 0x03; tiff[13] = 0x00; // The field Type
										  // The number of values, Count of the indicated Type
		tiff[14] = 0x01; tiff[15] = 0x00; tiff[16] = 0x00; tiff[17] = 0x00;

		// Writes the 2-byte orientation directly into the 4-byte Value/Offset field (bytes 18-21).
		// Bytes 22-25 implicitly remain 0x00000000, which correctly terminates the IFD chain.
		// Source: Page 15 - https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf
		BinaryPrimitives.WriteUInt16LittleEndian(tiff.AsSpan(18, 2), orientation);

		return tiff;
	}

	private static void ParseExif(ReadOnlySpan<byte> tiffData, string categoryId, string categoryName, MetadataContext ctx)
	{
		if (tiffData.Length < 8) return;

		bool isLittleEndian;
		if (tiffData[0] == 0x49 && tiffData[1] == 0x49) isLittleEndian = true;
		else if (tiffData[0] == 0x4D && tiffData[1] == 0x4D) isLittleEndian = false;
		else return;

		ushort magic = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(tiffData.Slice(2, 2)) : BinaryPrimitives.ReadUInt16BigEndian(tiffData.Slice(2, 2));
		if (magic != 0x002A) return;

		uint ifdOffset = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(tiffData.Slice(4, 4)) : BinaryPrimitives.ReadUInt32BigEndian(tiffData.Slice(4, 4));

		HashSet<uint> visitedOffsets = new();

		// Source: https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf - 4.5.2 - "the 0th IFD ... records the attribute information of the compressed image data"
		ParseIfd(tiffData, ifdOffset, isLittleEndian, visitedOffsets, categoryId, categoryName, ctx, ExifIfdKind.Primary);
	}

	private static void ParseIfd(ReadOnlySpan<byte> tiffData, uint offset, bool isLittleEndian, HashSet<uint> visitedOffsets, string categoryId, string categoryName, MetadataContext ctx, ExifIfdKind kind)
	{
		if ((long)offset + 2 > tiffData.Length || !visitedOffsets.Add(offset)) return;

		ushort entryCount = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(tiffData.Slice((int)offset, 2)) : BinaryPrimitives.ReadUInt16BigEndian(tiffData.Slice((int)offset, 2));
		long currentOffset = (long)offset + 2;

		for (int i = 0; i < entryCount; i++)
		{
			if (currentOffset + 12 > tiffData.Length) break;

			ReadOnlySpan<byte> entry = tiffData.Slice((int)currentOffset, 12);
			ushort tagId = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(entry[..2]) : BinaryPrimitives.ReadUInt16BigEndian(entry[..2]);
			ushort dataType = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(entry.Slice(2, 2)) : BinaryPrimitives.ReadUInt16BigEndian(entry.Slice(2, 2));
			uint dataCount = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(4, 4)) : BinaryPrimitives.ReadUInt32BigEndian(entry.Slice(4, 4));
			ReadOnlySpan<byte> valueField = entry.Slice(8, 4);

			// Every kind of IFD has its own independent tag number space, so the same numeric tag ID means completely
			// different things depending on which IFD it was found in.
			// https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf - Table 15 (GPS Attribute Information) and Table 16 (Interoperability IFD Attribute Information)
			string tagName = GetTagName(tagId, kind);
			int componentSize = GetExifComponentSize(dataType);

			// Source: https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf - Image File Directory - Count/Value Offset
			ulong totalBytes = (ulong)dataCount * (uint)componentSize;

			ReadOnlySpan<byte> actualData;
			if (totalBytes <= 4)
			{
				actualData = valueField[..(int)totalBytes];
			}
			else
			{
				uint dataOffset = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(valueField) : BinaryPrimitives.ReadUInt32BigEndian(valueField);
				actualData = dataOffset + totalBytes <= (ulong)tiffData.Length ? tiffData.Slice((int)dataOffset, (int)totalBytes) : default;
			}

			string dataValueStr = FormatExifData(actualData, dataType, dataCount, isLittleEndian);

			// Only the 0th IFD's Orientation is preserved, because GetExifOrientation reads the Orientation exclusively
			// from the 0th IFD when it rebuilds the minimal replacement block.
			// Source: https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf - 4.6.4 Table 4 - Orientation is recorded in both the 0th and the 1st IFD, where the 1st IFD value applies to the thumbnail
			if (tagId == OrientationTag && kind == ExifIfdKind.Primary)
			{
				ctx.AddTag(categoryId, categoryName, false, tagName, $"{dataValueStr} [Kept for Visual Fidelity]");
			}
			else
			{
				ctx.AddTag(categoryId, categoryName, true, tagName, dataValueStr);
			}

			// Source: https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf - Table 3 (0th IFD), Table 7 (Exif IFD)
			if (kind is ExifIfdKind.Primary or ExifIfdKind.Thumbnail or ExifIfdKind.ExifPrivate)
			{
				ExifIfdKind? subIfdKind = tagId switch
				{
					ExifIFD => ExifIfdKind.ExifPrivate,
					GPSIFD => ExifIfdKind.Gps,
					InteroperabilityIFD => ExifIfdKind.Interoperability,
					_ => null
				};

				if (subIfdKind.HasValue)
				{
					uint subIfdOffset = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(valueField) : BinaryPrimitives.ReadUInt32BigEndian(valueField);
					ParseIfd(tiffData, subIfdOffset, isLittleEndian, visitedOffsets, categoryId, categoryName, ctx, subIfdKind.Value);
				}
			}

			currentOffset += 12;
		}


		// https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf - 4.5.2
		if (kind is ExifIfdKind.Primary or ExifIfdKind.Thumbnail)
		{
			// Source: https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf - Page 14 - an IFD is a 2-byte entry count, followed by a sequence of 12-byte entries, followed by a 4-byte offset of the next IFD
			long nextIfdFieldOffset = (long)offset + 2 + ((long)entryCount * 12);

			if (nextIfdFieldOffset + 4 <= tiffData.Length)
			{
				uint nextIfdOffset = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(tiffData.Slice((int)nextIfdFieldOffset, 4)) : BinaryPrimitives.ReadUInt32BigEndian(tiffData.Slice((int)nextIfdFieldOffset, 4));
				if (nextIfdOffset != 0)
				{
					// The IFD that follows the 0th IFD is the 1st IFD, which describes the thumbnail.
					ParseIfd(tiffData, nextIfdOffset, isLittleEndian, visitedOffsets, categoryId, categoryName, ctx, ExifIfdKind.Thumbnail);
				}
			}
		}
	}

	// Sources:
	// 4.6.2 IFD Structure - JEITA CP-3451C / CIPA DC-008-2012
	// TIFF 6.0 Specification - Pages 15/16 - Types
	private static int GetExifComponentSize(ushort dataType) => dataType switch
	{
		// 1 = BYTE (8-bit unsigned integer),
		// 2 = ASCII (8-bit byte containing a 7-bit ASCII code)
		// 6 = SBYTE (8-bit signed integer),
		// 7 = UNDEFINED (8-bit byte that may contain anything)
		1 or 2 or 6 or 7 => 1,

		// 3 = SHORT (16-bit / 2-byte unsigned integer)
		// 8 = SSHORT (16-bit / 2-byte signed integer)
		3 or 8 => 2,

		// 4 = LONG (32-bit / 4-byte unsigned integer)
		// 9 = SLONG (32-bit / 4-byte signed integer)
		// 11 = FLOAT (Single precision 4-byte IEEE format)
		4 or 9 or 11 => 4,

		// 5 = RATIONAL (Two 4-byte LONGs = 8 bytes total)
		// 10 = SRATIONAL (Two 4-byte SLONGs = 8 bytes total)
		// 12 = DOUBLE (Double precision 8-byte IEEE format)
		5 or 10 or 12 => 8,

		// Fallback size for any unknown or future TIFF field types.
		// Readers should skip over fields containing an unexpected field type safely.
		_ => 1,
	};

	private static string FormatExifData(ReadOnlySpan<byte> data, ushort type, uint count, bool isLittleEndian)
	{
		if (data.IsEmpty) return "[Truncated/Invalid Data Offset]";
		try
		{
			return type switch
			{
				2 => Encoding.UTF8.GetString(data).Trim('\0', ' '),
				3 => FormatShortArray(data, count, isLittleEndian),
				4 => FormatLongArray(data, count, isLittleEndian),
				5 => FormatRationalArray(data, count, isLittleEndian),
				8 => FormatSShortArray(data, count, isLittleEndian),
				9 => FormatSLongArray(data, count, isLittleEndian),
				10 => FormatSRationalArray(data, count, isLittleEndian),
				1 or 7 => $"(Binary data {data.Length} bytes)",
				_ => $"(Unhandled Type {type})"
			};
		}
		catch { return "[Parse Error]"; }
	}

	/// <summary>
	/// Formats a TIFF/EXIF SSHORT data type array into a human-readable string.
	/// Source: TIFF 6.0 Specification - Page 15: 8 = SSHORT 16-bit (2-byte) signed integer.
	/// </summary>
	private static string FormatSShortArray(ReadOnlySpan<byte> data, uint count, bool isLittleEndian)
	{
		uint maxDisplay = Math.Min(count, 4);
		List<string> values = new((int)maxDisplay);

		for (int i = 0; i < maxDisplay && (i * 2) + 2 <= data.Length; i++)
		{
			short val = isLittleEndian ?
				BinaryPrimitives.ReadInt16LittleEndian(data.Slice(i * 2, 2)) :
				BinaryPrimitives.ReadInt16BigEndian(data.Slice(i * 2, 2));

			values.Add(val.ToString());
		}

		string result = string.Join(", ", values);
		if (count > 4) result += " ...";

		return result;
	}

	/// <summary>
	/// Formats a TIFF/EXIF SLONG data type array into a human-readable string.
	/// Source: TIFF 6.0 Specification - Page 15: 9 = SLONG: 32-bit (4-byte) signed integer.
	/// </summary>
	private static string FormatSLongArray(ReadOnlySpan<byte> data, uint count, bool isLittleEndian)
	{
		uint maxDisplay = Math.Min(count, 4);
		List<string> values = new((int)maxDisplay);

		for (int i = 0; i < maxDisplay && (i * 4) + 4 <= data.Length; i++)
		{
			int val = isLittleEndian ?
				BinaryPrimitives.ReadInt32LittleEndian(data.Slice(i * 4, 4)) :
				BinaryPrimitives.ReadInt32BigEndian(data.Slice(i * 4, 4));

			values.Add(val.ToString());
		}

		string result = string.Join(", ", values);
		if (count > 4) result += " ...";

		return result;
	}

	/// <summary>
	/// Formats a TIFF/EXIF SRATIONAL data type array into a human-readable string.
	/// Source: TIFF 6.0 Specification (Page 15) - A SRATIONAL is Two SLONGs.
	/// </summary>
	private static string FormatSRationalArray(ReadOnlySpan<byte> data, uint count, bool isLittleEndian)
	{
		uint maxDisplay = Math.Min(count, 2);
		List<string> values = new((int)maxDisplay);

		for (int i = 0; i < maxDisplay && (i * 8) + 8 <= data.Length; i++)
		{
			int num = isLittleEndian ?
				BinaryPrimitives.ReadInt32LittleEndian(data.Slice(i * 8, 4)) :
				BinaryPrimitives.ReadInt32BigEndian(data.Slice(i * 8, 4));

			int den = isLittleEndian ?
				BinaryPrimitives.ReadInt32LittleEndian(data.Slice((i * 8) + 4, 4)) :
				BinaryPrimitives.ReadInt32BigEndian(data.Slice((i * 8) + 4, 4));

			values.Add($"{num}/{den}");
		}

		string result = string.Join(", ", values);
		if (count > 2) result += " ...";

		return result;
	}

	/// <summary>
	/// Formats a TIFF/EXIF SHORT or SSHORT data type array into a human-readable string.
	/// Source: TIFF 6.0 Specification - Page 15: 3 = SHORT 16-bit (2-byte) unsigned integer.
	/// </summary>
	internal static string FormatShortArray(ReadOnlySpan<byte> data, uint count, bool isLittleEndian)
	{
		// Limit the display to a maximum of 4 integers to keep the UI clean
		// and prevent lag when encountering tags with large arrays of SHORTs.
		uint maxDisplay = Math.Min(count, 4);
		List<string> values = new((int)maxDisplay);

		// A SHORT takes exactly 2 bytes. We jump forward by 2 bytes per iteration.
		// The condition '(i * 2) + 2 <= data.Length' is a strict bounds check ensuring
		// we never read past the end of the byte array if the file is truncated or corrupted.
		for (int i = 0; i < maxDisplay && (i * 2) + 2 <= data.Length; i++)
		{
			// Slice exactly 2 bytes and parse them as a 16-bit unsigned integer (ushort).
			ushort val = isLittleEndian ?
				BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(i * 2, 2)) :
				BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i * 2, 2));

			values.Add(val.ToString());
		}

		// Join the processed 16-bit integers with a comma for presentation.
		string result = string.Join(", ", values);

		// If the original array contained more than 4 integers, append an ellipsis
		// to visually indicate to the user that the displayed data was truncated.
		if (count > 4) result += " ...";

		return result;
	}

	/// <summary>
	/// Formats a TIFF/EXIF LONG or SLONG data type array into a human-readable string.
	/// Source: TIFF 6.0 Specification - Page 15: 4 = LONG: 32-bit (4-byte) unsigned integer.
	/// </summary>
	internal static string FormatLongArray(ReadOnlySpan<byte> data, uint count, bool isLittleEndian)
	{
		// Limit the display to a maximum of 4 integers to prevent UI lag or massive text blocks
		// for tags that contain huge arrays (like StripOffsets or TileOffsets).
		uint maxDisplay = Math.Min(count, 4);
		List<string> values = new((int)maxDisplay);

		// A LONG takes exactly 4 bytes. We jump forward by 4 bytes per iteration.
		// The condition '(i * 4) + 4 <= data.Length' ensures we never read past the end
		// of the byte array, protecting against corrupted or maliciously crafted EXIF data.
		for (int i = 0; i < maxDisplay && (i * 4) + 4 <= data.Length; i++)
		{
			// Slice exactly 4 bytes and parse them as a 32-bit unsigned integer.
			uint val = isLittleEndian ?
				BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(i * 4, 4)) :
				BinaryPrimitives.ReadUInt32BigEndian(data.Slice(i * 4, 4));

			values.Add(val.ToString());
		}

		// Join the processed integers with a comma for clean UI presentation.
		string result = string.Join(", ", values);

		// If the original tag contained more than 4 integers, append an ellipsis
		// to visually indicate to the user that the data array was truncated.
		if (count > 4) result += " ...";

		return result;
	}

	/// <summary>
	/// Formats a TIFF/EXIF RATIONAL data type array into a human-readable string.
	/// Source: TIFF 6.0 Specification (Page 15)
	/// </summary>
	private static string FormatRationalArray(ReadOnlySpan<byte> data, uint count, bool isLittleEndian)
	{
		// Limit the display to a maximum of 2 fractions to prevent UI lag or clutter
		// from massive arrays (e.g., custom camera calibration tables).
		uint maxDisplay = Math.Min(count, 2);
		List<string> values = new((int)maxDisplay);

		// A RATIONAL takes exactly 8 bytes. We jump forward by 8 bytes per iteration.
		// The condition '(i * 8) + 8 <= data.Length' is a rigorous safety check to prevent
		// IndexOutOfRange exceptions if the image file is truncated or corrupted.
		for (int i = 0; i < maxDisplay && (i * 8) + 8 <= data.Length; i++)
		{
			// Grab the first 4 bytes of the 8-byte block for the numerator.
			uint num = isLittleEndian ?
				BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(i * 8, 4)) :
				BinaryPrimitives.ReadUInt32BigEndian(data.Slice(i * 8, 4));

			// Grab the next 4 byte for the denominator.
			uint den = isLittleEndian ?
				BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((i * 8) + 4, 4)) :
				BinaryPrimitives.ReadUInt32BigEndian(data.Slice((i * 8) + 4, 4));

			// Combine the two numbers into a standard fraction string (e.g., "1/1000" or "28/10").
			values.Add($"{num}/{den}");
		}

		string result = string.Join(", ", values);

		// If the file actually contained more than 2 fractions (like a GPS coordinate tag with 3),
		// append an ellipsis to visually indicate that the data was truncated for display.
		if (count > 2) result += " ...";

		return result;
	}

	// Source: Annex D - Sample CRC implementation - https://www.w3.org/TR/png/#samplecrc
	private static uint CalculateCrc32(ReadOnlySpan<byte> typeBuffer, ReadOnlySpan<byte> data)
	{
		uint[] table = CrcTable;
		uint crc = 0xFFFFFFFFu;

		// Update the running CRC with the 4-byte Chunk Type
		for (int i = 0; i < typeBuffer.Length; i++)
		{
			byte index = (byte)((crc & 0xFF) ^ typeBuffer[i]);
			crc = (crc >> 8) ^ table[index];
		}

		// Continue updating the running CRC with the variable-length Chunk Data
		for (int i = 0; i < data.Length; i++)
		{
			byte index = (byte)((crc & 0xFF) ^ data[i]);
			crc = (crc >> 8) ^ table[index];
		}

		return ~crc;
	}

	// Source: Annex D - Sample CRC implementation - https://www.w3.org/TR/png/#samplecrc
	// https://www.w3.org/TR/png/#5Chunk-layout
	private static uint[] GenerateCrcTable()
	{
		uint[] table = new uint[256];
		for (uint i = 0; i < 256; i++)
		{
			uint c = i;
			for (int j = 0; j < 8; j++)
			{
				if ((c & 1) != 0)
				{
					// matches the 'L' suffix behavior from the ISO C specification.
					c = 0xEDB88320u ^ (c >> 1);
				}
				else
				{
					c >>= 1;
				}
			}
			table[i] = c;
		}
		return table;
	}

	// Resolves a tag ID against the tag number space of the IFD it was found in.
	// Every IFD kind defines its own independent set of tag numbers, so the IFD must be known before a tag ID can be named.
	// Source: https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf - Table 15 (GPS Attribute Information) and Table 16 (Interoperability IFD Attribute Information)
	private static string GetTagName(ushort tag, ExifIfdKind kind) => kind switch
	{
		ExifIfdKind.Gps => GetGpsTagName(tag),
		ExifIfdKind.Interoperability => GetInteroperabilityTagName(tag),
		_ => GetTiffAndExifTagName(tag)
	};

	// The GPS Info IFD tag number space.
	// Source: https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf - Table 15 - 4.6.6 GPS Attribute Information
	private static string GetGpsTagName(ushort tag) => tag switch
	{
		// Source: JEITA CP-3451C / CIPA DC-008-2012: https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf
		// Table 15 - 4.6.6 GPS Attribute Information
		0x0000 => "GPS tag version",
		0x0001 => "North or South Latitude",
		0x0002 => "Latitude",
		0x0003 => "East or West Longitude",
		0x0004 => "Longitude",
		0x0005 => "Altitude reference",
		0x0006 => "Altitude",
		0x0007 => "GPS time (atomic clock)",
		0x0008 => "GPS satellites used for measurement",
		0x0009 => "GPS receiver status",
		0x000A => "GPS measurement mode",
		0x000B => "Measurement precision",
		0x000C => "Speed unit",
		0x000D => "Speed of GPS receiver",
		0x000E => "Reference for direction of movement",
		0x000F => "Direction of movement",
		0x0010 => "Reference for direction of image",
		0x0011 => "Direction of image",
		0x0012 => "Geodetic survey data used",
		0x0013 => "Reference for latitude of destination",
		0x0014 => "Latitude of destination",
		0x0015 => "Reference for longitude of destination",
		0x0016 => "Longitude of destination",
		0x0017 => "Reference for bearing of destination",
		0x0018 => "Bearing of destination",
		0x0019 => "Reference for distance to destination",
		0x001A => "Distance to destination",
		0x001B => "Name of GPS processing method",
		0x001C => "Name of GPS area",
		0x001D => "GPS date",
		0x001E => "GPS differential correction",
		0x001F => "Horizontal positioning error",

		_ => $"Unknown GPS Tag (0x{tag:X4})",
	};

	// Source: https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf - Table 16 - Interoperability IFD Attribute Information
	private static string GetInteroperabilityTagName(ushort tag) => tag switch
	{
		0x0001 => "Interoperability Index",
		0x0002 => "Interoperability Version",
		0x1000 => "Related Image File Format",
		0x1001 => "Related Image Width",
		0x1002 => "Related Image Length",
		_ => $"Unknown Interoperability Tag (0x{tag:X4})",
	};

	// Source: https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf - Table 3 (0th IFD) and Table 7 (Exif IFD)
	private static string GetTiffAndExifTagName(ushort tag) => tag switch
	{
		// TIFF 6.0 Standard Tags
		// Source: Page 117 - Appendix A: TIFF Tags Sorted by Number - https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf
		// https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf
		0x00FE => "New Subfile Type", // (254)
		0x00FF => "Subfile Type", // (255)
		0x0100 => "Image Width", // (256)
		0x0101 => "Image Length", // (257)
		0x0102 => "Bits Per Sample", // (258)
		0x0103 => "Compression", // (259)
		0x0106 => "Photometric Interpretation", // (262)
		0x0107 => "Threshholding", // (263)
		0x0108 => "Cell Width", // (264)
		0x0109 => "Cell Length", // (265)
		0x010A => "Fill Order", // (266)
		0x010D => "Document Name", // (269)
		0x010E => "Image Description", // (270)
		0x010F => "Make", // (271)
		0x0110 => "Model", // (272)
		0x0111 => "Strip Offsets", // (273)
		OrientationTag => "Orientation", // (274)
		0x0115 => "Samples Per Pixel", // (277)
		0x0116 => "Rows Per Strip", // (278)
		0x0117 => "Strip Byte Counts", // (279)
		0x0118 => "Min Sample Value", // (280)
		0x0119 => "Max Sample Value", // (281)
		0x011A => "X Resolution", // (282)
		0x011B => "Y Resolution", // (283)
		0x011C => "Planar Configuration", // (284)
		0x011D => "Page Name", // (285)
		0x011E => "X Position", // (286)
		0x011F => "Y Position", // (287)
		0x0120 => "Free Offsets", // (288)
		0x0121 => "Free Byte Counts", // (289)
		0x0122 => "Gray Response Unit", // (290)
		0x0123 => "Gray Response Curve", // (291)
		0x0124 => "T4 Options", // (292)
		0x0125 => "T6 Options", // (293)
		0x0128 => "Resolution Unit", // (296)
		0x0129 => "Page Number", // (297)
		0x012D => "Transfer Function", // (301)
		0x0131 => "Software", // (305)
		0x0132 => "Date Time", // (306)
		0x013B => "Artist", // (315)
		0x013C => "Host Computer", // (316)
		0x013D => "Predictor", // (317)
		0x013E => "White Point", // (318)
		0x013F => "Primary Chromaticities", // (319)
		0x0140 => "Color Map", // (320)
		0x0141 => "Halftone Hints", // (321)
		0x0142 => "Tile Width", // (322)
		0x0143 => "Tile Length", // (323)
		0x0144 => "Tile Offsets", // (324)
		0x0145 => "Tile Byte Counts", // (325)
		0x014C => "Ink Set", // (332)
		0x014D => "Ink Names", // (333)
		0x014E => "Number Of Inks", // (334)
		0x0150 => "Dot Range", // (336)
		0x0151 => "Target Printer", // (337)
		0x0152 => "Extra Samples", // (338)
		0x0153 => "Sample Format", // (339)
		0x0154 => "S Min Sample Value", // (340)
		0x0155 => "S Max Sample Value", // (341)
		0x0156 => "Transfer Range", // (342)
		0x0200 => "JPEG Proc", // (512)
		0x0201 => "JPEG Interchange Format", // (513)
		0x0202 => "JPEG Interchange Format Length", // (514)
		0x0203 => "JPEG Restart Interval", // (515)
		0x0205 => "JPEG Lossless Predictors", // (517)
		0x0206 => "JPEG Point Transforms", // (518)
		0x0207 => "JPEG Q Tables", // (519)
		0x0208 => "JPEG DC Tables", // (520)
		0x0209 => "JPEG AC Tables", // (521)
		0x0211 => "Y Cb Cr Coefficients", // (529)
		0x0212 => "Y Cb Cr Sub Sampling", // (530)
		0x0213 => "Y Cb Cr Positioning", // (531)
		0x0214 => "Reference Black White", // (532)
		0x8298 => "Copyright", // (33432)

		// Source: JEITA CP-3451C / CIPA DC-008-2012: https://home.jeita.or.jp/tsc/std-pdf/CP3451C.pdf
		// Table 18 Tag Support Levels (2) - 0th IFD Exif Private Tags
		0x829A => "Exposure time",
		0x829D => "F number",
		0x8822 => "Exposure program",
		0x8824 => "Spectral sensitivity",
		0x8827 => "Photographic Sensitivity",
		0x8828 => "Optoelectric coefficient",
		0x8830 => "Sensitivity Type",
		0x8831 => "Standard Output Sensitivity",
		0x8832 => "Recommended Exposure Index",
		0x8833 => "ISOSpeed",
		0x8834 => "ISOSpeed Latitude yyy",
		0x8835 => "ISOSpeed Latitude zzz",
		0x9000 => "Exif Version",
		0x9003 => "Date and time original image was generated",
		0x9004 => "Date and time image was made digital data",
		0x9101 => "Meaning of each component",
		0x9102 => "Image compression mode",
		0x9201 => "Shutter speed",
		0x9202 => "Aperture",
		0x9203 => "Brightness",
		0x9204 => "Exposure bias",
		0x9205 => "Maximum lens aperture",
		0x9206 => "Subject distance",
		0x9207 => "Metering mode",
		0x9208 => "Light source",
		0x9209 => "Flash",
		0x920A => "Lens focal length",
		0x9214 => "Subject area",
		0x927C => "Manufacturer notes",
		0x9286 => "User comments",
		0x9290 => "DateTime subseconds",
		0x9291 => "DateTimeOriginal subseconds",
		0x9292 => "DateTimeDigitized subseconds",
		0xA000 => "Supported Flashpix version",
		0xA001 => "Color space information",
		0xA002 => "Valid image width",
		0xA003 => "Valid image height",
		0xA004 => "Related audio file",
		ExifIFD => "Exif IFD Pointer",
		GPSIFD => "GPS Info IFD Pointer",
		InteroperabilityIFD => "Interoperability tag",
		0xA20B => "Flash energy",
		0xA20C => "Spatial frequency response",
		0xA20E => "Focal plane X resolution",
		0xA20F => "Focal plane Y resolution",
		0xA210 => "Focal plane resolution unit",
		0xA214 => "Subject location",
		0xA215 => "Exposure index",
		0xA217 => "Sensing method",
		0xA300 => "File source",
		0xA301 => "Scene type",
		0xA302 => "CFA pattern",
		0xA401 => "Custom image processing",
		0xA402 => "Exposure mode",
		0xA403 => "White balance",
		0xA404 => "Digital zoom ratio",
		0xA405 => "Focal length in 35 mm film",
		0xA406 => "Scene capture type",
		0xA407 => "Gain control",
		0xA408 => "Contrast",
		0xA409 => "Saturation",
		0xA40A => "Sharpness",
		0xA40B => "Device settings description",
		0xA40C => "Subject distance range",
		0xA420 => "Unique image ID",
		0xA430 => "Camera Owner Name",
		0xA431 => "Body Serial Number",
		0xA432 => "Lens Specification",
		0xA433 => "Lens Make",
		0xA434 => "Lens Model",
		0xA435 => "Lens Serial Number",
		0xA500 => "Gamma",

		// https://exiftool.org/TagNames/EXIF.html
		0x9010 => "OffsetTime",
		0x9011 => "OffsetTimeOriginal",
		0x9012 => "OffsetTimeDigitized",


		_ => $"Unknown Tag (0x{tag:X4})",
	};

	private static string GetIccTagName(string tag) => tag switch
	{
		"desc" => "Profile Description",
		"cprt" => "Profile Copyright",
		"wtpt" => "Media White Point",
		"rXYZ" => "Red Matrix Column",
		"gXYZ" => "Green Matrix Column",
		"bXYZ" => "Blue Matrix Column",
		"rTRC" => "Red Tone Reproduction Curve",
		"gTRC" => "Green Tone Reproduction Curve",
		"bTRC" => "Blue Tone Reproduction Curve",
		"chad" => "Chromatic Adaptation Matrix",
		"dmnd" => "Device Manufacturer",
		"dmdd" => "Device Model",
		"vued" => "Viewing Conditions",
		"tech" => "Technology Signature",
		"A2B0" => "A To B0 Intent",
		"B2A0" => "B To A0 Intent",
		_ => tag
	};
}

/// <summary>
/// Detailed JSON report of a whole bulk metadata removal operation.
/// </summary>
internal sealed class ExifBulkRemovalReport(
	string format,
	DateTimeOffset generatedAt,
	DateTimeOffset operationStartedAt,
	long durationMilliseconds,
	List<string> selectedFolders,
	List<string> supportedExtensions,
	int totalFilesFound,
	int filesCleaned,
	int filesWithNothingToRemove,
	int filesFailed,
	long totalSizeBeforeBytes,
	long totalSizeAfterBytes,
	long totalBytesReclaimed,
	List<ExifBulkFileResult> results)
{
	[JsonInclude]
	[JsonPropertyOrder(0)]
	internal string Format => format;

	[JsonInclude]
	[JsonPropertyOrder(1)]
	internal DateTimeOffset GeneratedAt => generatedAt;

	[JsonInclude]
	[JsonPropertyOrder(2)]
	internal DateTimeOffset OperationStartedAt => operationStartedAt;

	[JsonInclude]
	[JsonPropertyOrder(3)]
	internal long DurationMilliseconds => durationMilliseconds;

	[JsonInclude]
	[JsonPropertyOrder(4)]
	internal List<string> SelectedFolders => selectedFolders;

	[JsonInclude]
	[JsonPropertyOrder(5)]
	internal List<string> SupportedExtensions => supportedExtensions;

	[JsonInclude]
	[JsonPropertyOrder(6)]
	internal int TotalFilesFound => totalFilesFound;

	[JsonInclude]
	[JsonPropertyOrder(7)]
	internal int FilesCleaned => filesCleaned;

	[JsonInclude]
	[JsonPropertyOrder(8)]
	internal int FilesWithNothingToRemove => filesWithNothingToRemove;

	[JsonInclude]
	[JsonPropertyOrder(9)]
	internal int FilesFailed => filesFailed;

	[JsonInclude]
	[JsonPropertyOrder(10)]
	internal long TotalSizeBeforeBytes => totalSizeBeforeBytes;

	[JsonInclude]
	[JsonPropertyOrder(11)]
	internal long TotalSizeAfterBytes => totalSizeAfterBytes;

	[JsonInclude]
	[JsonPropertyOrder(12)]
	internal long TotalBytesReclaimed => totalBytesReclaimed;

	[JsonInclude]
	[JsonPropertyOrder(13)]
	internal List<ExifBulkFileResult> Results => results;
}

/// <summary>
/// Per-file entry of the bulk metadata removal JSON report.
/// </summary>
internal sealed class ExifBulkFileResult(
	string filePath,
	string fileName,
	string directory,
	string status,
	List<string> removedCategories,
	int removedCategoryCount,
	long sizeBeforeBytes,
	long sizeAfterBytes,
	long sizeDifferenceBytes,
	string? errorMessage)
{
	[JsonInclude]
	[JsonPropertyOrder(0)]
	internal string FilePath => filePath;

	[JsonInclude]
	[JsonPropertyOrder(1)]
	internal string FileName => fileName;

	[JsonInclude]
	[JsonPropertyOrder(2)]
	internal string Directory => directory;

	[JsonInclude]
	[JsonPropertyOrder(3)]
	internal string Status => status;

	[JsonInclude]
	[JsonPropertyOrder(4)]
	internal List<string> RemovedCategories => removedCategories;

	[JsonInclude]
	[JsonPropertyOrder(5)]
	internal int RemovedCategoryCount => removedCategoryCount;

	[JsonInclude]
	[JsonPropertyOrder(6)]
	internal long SizeBeforeBytes => sizeBeforeBytes;

	[JsonInclude]
	[JsonPropertyOrder(7)]
	internal long SizeAfterBytes => sizeAfterBytes;

	[JsonInclude]
	[JsonPropertyOrder(8)]
	internal long SizeDifferenceBytes => sizeDifferenceBytes;

	[JsonInclude]
	[JsonPropertyOrder(9)]
	internal string? ErrorMessage => errorMessage;
}

[JsonSerializable(typeof(ExifBulkRemovalReport))]
[JsonSerializable(typeof(ExifBulkFileResult))]
[JsonSerializable(typeof(List<ExifBulkFileResult>))]
[JsonSerializable(typeof(List<string>))]
[JsonSourceGenerationOptions(
	WriteIndented = true,
	PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified,
	PropertyNameCaseInsensitive = true,
	DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class ExifBulkRemovalJsonContext : JsonSerializerContext
{
}
