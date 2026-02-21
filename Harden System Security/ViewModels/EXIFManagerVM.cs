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
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.ViewModels;
using CommonCore.IncrementalCollection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class EXIFManagerVM : ViewModelBase
{
	internal EXIFManagerVM() =>
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

	internal readonly InfoBarSettings MainInfoBar;
	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

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

		try
		{
			AreElementsEnabled = false;
			HashSet<string> toRemove = new(StringComparer.OrdinalIgnoreCase);

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

	private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

	internal string CategoryId => categoryId;
	internal string DisplayName => displayName;
	internal bool IsSafeToRemove => isSafeToRemove;
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

	internal ObservableCollection<MetadataTag> Tags { get; } = [];
}

internal sealed partial class MetadataContext
{
	internal Dictionary<string, MetadataCategory> CategoriesMap = new(StringComparer.OrdinalIgnoreCase);

	internal void AddTag(string categoryId, string categoryName, bool isSafeToRemove, string name, string value)
	{
		if (!CategoriesMap.TryGetValue(categoryId, out MetadataCategory? category))
		{
			category = new MetadataCategory(categoryId, categoryName, isSafeToRemove);
			CategoriesMap[categoryId] = category;
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

		List<MetadataCategory> resultList = [];
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

		while (true)
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
			byte markerType = markerTypeBuffer[0];

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
			if ((markerType >= 0xD0 && markerType <= endOfImage) || markerType == 0x01)
			{
				outputStream?.WriteByte(startOfMarker);
				outputStream?.WriteByte(markerType);

				if (markerType == endOfImage)
				{
					break; // We reached the absolute end of the image datastream, stop parsing.
				}
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
				"ICC_PROFILE" => "ICC Color Profile",
				"JFIF" => "JFIF Header",
				_ => chunkType.StartsWith("APP", StringComparison.OrdinalIgnoreCase) ? $"Application Marker ({chunkType})" : chunkType
			};

			if (outputStream != null)
			{
				bool shouldRemove = isSafeToRemove && categoriesToRemove != null && categoriesToRemove.Contains(chunkType);

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
			}

			if (markerType == 0xDA)
			{
				if (outputStream != null)
				{
					inputStream.CopyTo(outputStream);
				}
				break;
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

			bool isSafeToRemove = string.Equals(chunkType, "eXIf", StringComparison.OrdinalIgnoreCase) ||
								  string.Equals(chunkType, "tEXt", StringComparison.OrdinalIgnoreCase) ||
								  string.Equals(chunkType, "zTXt", StringComparison.OrdinalIgnoreCase) ||
								  string.Equals(chunkType, "iTXt", StringComparison.OrdinalIgnoreCase) ||
								  string.Equals(chunkType, "tIME", StringComparison.OrdinalIgnoreCase);

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
				if (string.Equals(chunkType, "IDAT", StringComparison.OrdinalIgnoreCase))
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
					if (string.Equals(chunkType, "eXIf", StringComparison.OrdinalIgnoreCase))
					{
						ReadOnlySpan<byte> tiffData = new(chunkPayload);
						ParseExif(tiffData, chunkType, categoryName, ctx);
					}
					else if (string.Equals(chunkType, "tEXt", StringComparison.OrdinalIgnoreCase))
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
					else if (string.Equals(chunkType, "iTXt", StringComparison.OrdinalIgnoreCase) ||
							 string.Equals(chunkType, "zTXt", StringComparison.OrdinalIgnoreCase))
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
					else if (string.Equals(chunkType, "tIME", StringComparison.OrdinalIgnoreCase))
					{
						ctx.AddTag(chunkType, categoryName, true, "Timestamp", "(Time Data)");
					}
					else if (string.Equals(chunkType, "iCCP", StringComparison.OrdinalIgnoreCase))
					{
						ctx.AddTag(chunkType, categoryName, false, "Profile Data", "[Kept for Visual Fidelity]");
					}
					else if (string.Equals(chunkType, "pHYs", StringComparison.OrdinalIgnoreCase))
					{
						ctx.AddTag(chunkType, categoryName, false, "Dimensions", "[Kept for Visual Fidelity]");
					}
					else if (string.Equals(chunkType, "IHDR", StringComparison.OrdinalIgnoreCase) && chunkLength >= 13)
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
					else if (!string.Equals(chunkType, "IEND", StringComparison.OrdinalIgnoreCase))
					{
						ctx.AddTag(chunkType, categoryName, isSafeToRemove, "Chunk Data", $"(Binary Data {chunkLength} bytes)");
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
					if (string.Equals(chunkType, "eXIf", StringComparison.OrdinalIgnoreCase))
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

			if (string.Equals(chunkType, "IEND", StringComparison.OrdinalIgnoreCase))
			{
				break;
			}
		}
	}

	private static string IdentifyJpegChunk(byte markerType, byte[] payload)
	{
		// Comment
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
			if (markerType == 0xE2)
			{
				// 11 characters + the null terminator at the end = 12 bytes
				if (payload.Length >= 12 && payload.AsSpan(0, 12).SequenceEqual("ICC_PROFILE\0"u8))
				{
					return "ICC_PROFILE";
				}
			}

			// APP13
			// The APPn designation with the range goes from 0xFFE0 to 0xFFEF means APP0 through APP15.
			// Source: https://www.w3.org/Graphics/JPEG/itu-t81.pdf - Table B.1 – Marker code assignments - Other markers
			if (markerType == 0xED)
			{
				// 13 characters + the null terminator at the end = 14 bytes
				if (payload.Length >= 14 && payload.AsSpan(0, 14).SequenceEqual("Photoshop 3.0\0"u8))
				{
					return "Photoshop/IRB";
				}
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

		if (payload.Length >= 6 + (components * 3))
		{
			if (components == 3)
			{
				byte ySampling = payload[7];
				byte cbSampling = payload[10];
				byte crSampling = payload[13];
				string subsampling = GetSubSampling(ySampling, cbSampling, crSampling);
				ctx.AddTag(categoryId, categoryName, false, "Y Cb Cr Sub Sampling", subsampling);
			}
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
	// Page 63: 6.5.26 XYZType - Table 78 — XYZType encoding
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
		bool isLittleEndian = tiffData[0] == 0x49 && tiffData[1] == 0x49;

		// Read bytes 4-7 for IFD (Image File Directory)
		// Source: https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf - Image File Header
		uint ifdOffset = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(tiffData.Slice(4, 4)) : BinaryPrimitives.ReadUInt32BigEndian(tiffData.Slice(4, 4));

		// Validate the IDF data
		// If there isn't enough room left in this buffer to read the mandatory 2-byte Entry Count, abort parsing and return null.
		if (ifdOffset + 2 > tiffData.Length) return null;

		// Read the 2-byte count of the number of directory entries (i.e., the number of fields)
		// This tells the for loop below exactly how many tags to look for.
		// Source: https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf - Image File Directory
		ushort entryCount = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(tiffData.Slice((int)ifdOffset, 2)) : BinaryPrimitives.ReadUInt16BigEndian(tiffData.Slice((int)ifdOffset, 2));
		uint currentOffset = ifdOffset + 2;

		for (int i = 0; i < entryCount; i++)
		{
			// The TIFF spec mandates 12-byte entries; this bounds check prevents crashes from truncated data or malicious entry counts.
			if (currentOffset + 12 > tiffData.Length) break;

			// Grab 12 bytes of data because every single piece of metadata (like the camera model, the date, or the orientation) is stored in a fixed-size block called a "Directory Entry" or "Field Entry."
			ReadOnlySpan<byte> entry = tiffData.Slice((int)currentOffset, 12);
			ushort tagId = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(entry[..2]) : BinaryPrimitives.ReadUInt16BigEndian(entry[..2]);

			if (tagId == OrientationTag)
			{
				// Isolates Bytes 8, 9, 10, and 11, the exact location where the metadata value is.
				// The specification mandates that this field is always exactly 4 bytes wide, regardless of how small the actual data is.
				ReadOnlySpan<byte> valueField = entry.Slice(8, 4);

				// So, out of the 4 bytes in valueField:
				// Byte 0 and Byte 1 contain the actual Orientation number(the 2 - byte SHORT).
				// Byte 2 and Byte 3 are just empty padding(zeros).
				return isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(valueField[..2]) : BinaryPrimitives.ReadUInt16BigEndian(valueField[..2]);
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
		if (magic != 42 && magic != 0x002A) return;

		uint ifdOffset = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(tiffData.Slice(4, 4)) : BinaryPrimitives.ReadUInt32BigEndian(tiffData.Slice(4, 4));

		HashSet<uint> visitedOffsets = new();
		ParseIfd(tiffData, ifdOffset, isLittleEndian, visitedOffsets, categoryId, categoryName, ctx);
	}

	private static void ParseIfd(ReadOnlySpan<byte> tiffData, uint offset, bool isLittleEndian, HashSet<uint> visitedOffsets, string categoryId, string categoryName, MetadataContext ctx)
	{
		if (offset + 2 > tiffData.Length || !visitedOffsets.Add(offset)) return;

		ushort entryCount = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(tiffData.Slice((int)offset, 2)) : BinaryPrimitives.ReadUInt16BigEndian(tiffData.Slice((int)offset, 2));
		uint currentOffset = offset + 2;

		for (int i = 0; i < entryCount; i++)
		{
			if (currentOffset + 12 > tiffData.Length) break;

			ReadOnlySpan<byte> entry = tiffData.Slice((int)currentOffset, 12);
			ushort tagId = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(entry[..2]) : BinaryPrimitives.ReadUInt16BigEndian(entry[..2]);
			ushort dataType = isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(entry.Slice(2, 2)) : BinaryPrimitives.ReadUInt16BigEndian(entry.Slice(2, 2));
			uint dataCount = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(4, 4)) : BinaryPrimitives.ReadUInt32BigEndian(entry.Slice(4, 4));
			ReadOnlySpan<byte> valueField = entry.Slice(8, 4);

			string tagName = GetTagName(tagId);
			int componentSize = GetExifComponentSize(dataType);
			uint totalBytes = dataCount * (uint)componentSize;

			ReadOnlySpan<byte> actualData;
			if (totalBytes <= 4)
			{
				actualData = valueField[..(int)totalBytes];
			}
			else
			{
				uint dataOffset = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(valueField) : BinaryPrimitives.ReadUInt32BigEndian(valueField);
				actualData = dataOffset + totalBytes <= tiffData.Length ? tiffData.Slice((int)dataOffset, (int)totalBytes) : default;
			}

			string dataValueStr = FormatExifData(actualData, dataType, dataCount, isLittleEndian);

			if (tagId == OrientationTag)
			{
				ctx.AddTag(categoryId, categoryName, false, tagName, $"{dataValueStr} [Kept for Visual Fidelity]");
			}
			else
			{
				ctx.AddTag(categoryId, categoryName, true, tagName, dataValueStr);
			}

			if (tagId == ExifIFD || tagId == GPSIFD || tagId == InteroperabilityIFD)
			{
				uint subIfdOffset = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(valueField) : BinaryPrimitives.ReadUInt32BigEndian(valueField);
				ParseIfd(tiffData, subIfdOffset, isLittleEndian, visitedOffsets, categoryId, categoryName, ctx);
			}

			currentOffset += 12;
		}

		if (currentOffset + 4 <= tiffData.Length)
		{
			uint nextIfdOffset = isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(tiffData.Slice((int)currentOffset, 4)) : BinaryPrimitives.ReadUInt32BigEndian(tiffData.Slice((int)currentOffset, 4));
			if (nextIfdOffset != 0)
			{
				ParseIfd(tiffData, nextIfdOffset, isLittleEndian, visitedOffsets, categoryId, categoryName, ctx);
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
	/// Source: TIFF 6.0 Specification (Page 15) - A RATIONAL is Two LONGs:
	/// the first represents the numerator of a fraction; the second, the denominator.
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

	private static string GetTagName(ushort tag) => tag switch
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
