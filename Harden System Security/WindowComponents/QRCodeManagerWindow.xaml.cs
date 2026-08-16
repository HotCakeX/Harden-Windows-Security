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
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HardenSystemSecurity.Pages.Extras;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.ApplicationModel.DataTransfer;
using Windows.Devices.Enumeration;
using Windows.Graphics.Capture;
using Windows.Graphics.Imaging;
using Windows.Media.Capture;
using Windows.Media.Capture.Frames;
using Windows.Media.Core;
using Windows.Media.Devices;
using Windows.Media.MediaProperties;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.Storage.Streams;
using Windows.System;

namespace HardenSystemSecurity.WindowComponents;

internal sealed partial class QRCodeManagerWindow : Window, IDisposable
{
	private static QRCodeManagerWindow? currentWindow;
	internal readonly InfoBarSettings MainInfoBar = new();
	private bool isBusy;
	private MediaCapture? mediaCapture;
	private MediaFrameReader? mediaFrameReader;
	private SoftwareBitmap? createdQrBitmap;
	private SoftwareBitmapSource? createdQrSource;
	private SoftwareBitmapSource? detectedQrSource;
	private StorageFile? createdQrDragFile;
	private bool isDisposed;
	private readonly bool isUiInitialized;
	private int creatorGenerationVersion;
	private int isCameraFrameProcessing;
	private int isCameraResultFound;
	private long lastCameraAnalysisTimestamp;
	private const double CameraScanFraction = 0.70D;
	private const uint CameraFrameWidth = 960U;
	private const uint CameraFrameHeight = 540U;
	private static readonly TimeSpan CameraAnalysisInterval = TimeSpan.FromMilliseconds(300D);

	private QRCodeManagerWindow()
	{
		InitializeComponent();
		isUiInitialized = true;
		Title = "QR Code Manager";
		AppWindow.SetIcon(@"Assets\AppIcon.ico");
		AppWindow.SetTaskbarIcon(@"Assets\AppIcon.ico");
		AppWindow.SetTitleBarIcon(@"Assets\AppIcon.ico");
		AppWindow.Resize(new Windows.Graphics.SizeInt32(800, 720));
		ExtendsContentIntoTitleBar = true;
		AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
		OverlappedPresenter presenter = OverlappedPresenter.Create();
		presenter.PreferredMinimumWidth = 700;
		presenter.PreferredMinimumHeight = 620;
		AppWindow.SetPresenter(presenter);

		// Get the current system color mode
		ElementTheme currentColorMode = Application.Current.RequestedTheme == ApplicationTheme.Dark
			? ElementTheme.Dark
			: ElementTheme.Light;

		// Set the title bar theme
		AppWindow.TitleBar.PreferredTheme = currentColorMode == ElementTheme.Light ? TitleBarTheme.Light : currentColorMode == ElementTheme.Dark ? TitleBarTheme.Dark : TitleBarTheme.UseDefaultAppMode;

		RootGrid.RequestedTheme = currentColorMode;
	}

	internal static void Show()
	{
		currentWindow ??= new();
		currentWindow.Activate();
	}

	private void ModeSelector_SelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
	{
		bool showCreator = ReferenceEquals(sender.SelectedItem, CreatorSelectorItem);
		ReaderView.Visibility = showCreator ? Visibility.Collapsed : Visibility.Visible;
		CreatorView.Visibility = showCreator ? Visibility.Visible : Visibility.Collapsed;
	}

	private async void CreatorTextBox_TextChanged()
	{
		if (isUiInitialized) await RegenerateCreatedQrAsync();
	}

	private async void ErrorCorrectionComboBox_SelectionChanged()
	{
		if (isUiInitialized) await RegenerateCreatedQrAsync();
	}

	private char GetSelectedErrorCorrectionLevel() => ErrorCorrectionComboBox.SelectedIndex switch
	{
		0 => 'L',
		1 => 'M',
		2 => 'Q',
		3 => 'H',
		_ => 'M'
	};

	private async Task RegenerateCreatedQrAsync()
	{
		int generationVersion = Interlocked.Increment(ref creatorGenerationVersion);
		string text = CreatorTextBox.Text;
		if (string.IsNullOrEmpty(text))
		{
			createdQrBitmap?.Dispose();
			createdQrBitmap = null;
			ClearCreatedQrSource();
			CreatorPlaceholder.Visibility = Visibility.Visible;
			DownloadQrButton.IsEnabled = false;
			ClearCreatorStatistics();
			await DeleteCreatedQrDragFileAsync();
			return;
		}
		try
		{
			using QR.Manage.GeneratedQr generatedQr = QR.Manage.GenerateWithStatistics(text, GetSelectedErrorCorrectionLevel());
			SoftwareBitmap? generatedBitmap = null;
			SoftwareBitmapSource? source = null;
			try
			{
				generatedBitmap = generatedQr.TakeBitmap();
				source = new SoftwareBitmapSource();
				await source.SetBitmapAsync(generatedBitmap);
				if (generationVersion != creatorGenerationVersion)
				{
					return;
				}
				createdQrBitmap?.Dispose();
				createdQrBitmap = generatedBitmap;
				generatedBitmap = null;
				ClearCreatedQrSource();
				createdQrSource = source;
				source = null;
				CreatedQrImage.Source = createdQrSource;
				CreatorPlaceholder.Visibility = Visibility.Collapsed;
				DownloadQrButton.IsEnabled = true;
				CreatorVersionValue.Text = generatedQr.Version.ToString(System.Globalization.CultureInfo.InvariantCulture);
				CreatorDimensionsValue.Text = string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{generatedQr.ModuleCount} × {generatedQr.ModuleCount} modules");
				CreatorByteCountValue.Text = generatedQr.Utf8ByteCount.ToString(System.Globalization.CultureInfo.InvariantCulture);
				CreatorErrorCorrectionValue.Text = generatedQr.ErrorCorrectionLevel.ToString();
				CreatorMaskValue.Text = generatedQr.Mask.ToString(System.Globalization.CultureInfo.InvariantCulture);
				CreatorRemainingCapacityValue.Text = string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{generatedQr.MaximumPayloadBytes} UTF-8 bytes");
				await RefreshCreatedQrDragFileAsync(createdQrBitmap, generationVersion);
			}
			finally
			{
				source?.Dispose();
				generatedBitmap?.Dispose();
			}
		}
		catch (Exception ex)
		{
			if (generationVersion != creatorGenerationVersion) return;
			ClearCreatedQrSource();
			CreatorPlaceholder.Visibility = Visibility.Visible;
			DownloadQrButton.IsEnabled = false;
			ClearCreatorStatistics();
			await DeleteCreatedQrDragFileAsync();
			MainInfoBar.WriteWarning(ex.Message);
		}
	}

	private void ClearCreatedQrSource()
	{
		CreatedQrImage.Source = null;
		createdQrSource?.Dispose();
		createdQrSource = null;
	}

	private void ClearDetectedQrSource()
	{
		DetectedQrImage.Source = null;
		detectedQrSource?.Dispose();
		detectedQrSource = null;
	}

	private void ClearCreatorStatistics()
	{
		CreatorVersionValue.Text = "-";
		CreatorDimensionsValue.Text = "-";
		CreatorByteCountValue.Text = "-";
		CreatorErrorCorrectionValue.Text = "-";
		CreatorMaskValue.Text = "-";
		CreatorRemainingCapacityValue.Text = "-";
	}

	private readonly record struct QrImageFormat(string Name, ReadOnlyMemory<string> Extensions, Guid EncoderId);

	private static QrImageFormat GetQrImageFormat(int formatIndex) => formatIndex switch
	{
		0 => new QrImageFormat("PNG image", new ReadOnlyMemory<string>([".png"]), BitmapEncoder.PngEncoderId),
		1 => new QrImageFormat("Bitmap image", new ReadOnlyMemory<string>([".bmp"]), BitmapEncoder.BmpEncoderId),
		2 => new QrImageFormat("JPEG image", new ReadOnlyMemory<string>([".jpg", ".jpeg"]), BitmapEncoder.JpegEncoderId),
		3 => new QrImageFormat("TIFF image", new ReadOnlyMemory<string>([".tif", ".tiff"]), BitmapEncoder.TiffEncoderId),
		4 => new QrImageFormat("JPEG XR image", new ReadOnlyMemory<string>([".jxr"]), BitmapEncoder.JpegXREncoderId),
		5 => new QrImageFormat("HEIF image", new ReadOnlyMemory<string>([".heif", ".heic"]), BitmapEncoder.HeifEncoderId),
		_ => throw new ArgumentOutOfRangeException(nameof(formatIndex))
	};

	private async void SaveCreatedQr_Click(object sender, RoutedEventArgs args)
	{
		if (createdQrBitmap is null || sender is not MenuFlyoutItem { Tag: string formatTag } || !int.TryParse(formatTag, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int formatIndex)) return;
		try
		{
			QrImageFormat format = GetQrImageFormat(formatIndex);
			FileSavePicker picker = new()
			{
				SuggestedStartLocation = PickerLocationId.PicturesLibrary,
				SuggestedFileName = "QR Code"
			};
			string[] fileExtensions = format.Extensions.ToArray();
			picker.FileTypeChoices.Add(format.Name, fileExtensions);
			IntPtr windowHandle = WinRT.Interop.WindowNative.GetWindowHandle(this);
			WinRT.Interop.InitializeWithWindow.Initialize(picker, windowHandle);
			StorageFile? file = await picker.PickSaveFileAsync();
			if (file is null) return;
			using IRandomAccessStream stream = await file.OpenAsync(FileAccessMode.ReadWrite);
			stream.Size = 0;
			await EncodeCreatedQrAsync(stream, format.EncoderId);
			MainInfoBar.WriteSuccess(string.Concat("The QR code was saved as a ", format.Name, "."));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private async void CopyCreatedQrAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		// Preserve the focused TextBox's built-in Ctrl+C behavior whenever text is selected.
		if (CreatorView.Visibility is not Visibility.Visible || CreatorTextBox.SelectionLength > 0 || createdQrBitmap is null) return;
		args.Handled = true;
		try
		{
			using InMemoryRandomAccessStream stream = new();
			await EncodeCreatedQrAsync(stream, BitmapEncoder.PngEncoderId);
			stream.Seek(0);
			DataPackage package = new();
			package.SetBitmap(RandomAccessStreamReference.CreateFromStream(stream));
			Clipboard.SetContent(package);
			Clipboard.Flush();
			MainInfoBar.WriteSuccess("The generated QR image was copied to the clipboard.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private async Task EncodeCreatedQrAsync(IRandomAccessStream stream, Guid encoderId)
	{
		if (createdQrBitmap is null) throw new InvalidOperationException("No generated QR image is available.");
		await EncodeSoftwareBitmapAsync(stream, encoderId, createdQrBitmap);
	}

	private static async Task EncodeSoftwareBitmapAsync(IRandomAccessStream stream, Guid encoderId, SoftwareBitmap bitmap)
	{
		BitmapEncoder encoder = await BitmapEncoder.CreateAsync(encoderId, stream);
		encoder.SetSoftwareBitmap(bitmap);
		await encoder.FlushAsync();
	}

	private void ReaderView_DragOver(object sender, DragEventArgs args)
	{
		if (!isBusy && args.DataView.Contains(StandardDataFormats.StorageItems))
		{
			args.AcceptedOperation = DataPackageOperation.Copy;
			args.Handled = true;
			args.DragUIOverride.Caption = "Decode QR images";
			args.DragUIOverride.IsCaptionVisible = true;
		}
	}

	private async void ReaderView_Drop(object sender, DragEventArgs args)
	{
		if (isBusy) return;
		args.Handled = true;
		try
		{
			List<string> imagePaths = await GetStorageFilePathsAsync(args.DataView);
			if (imagePaths.Count == 0)
			{
				MainInfoBar.WriteWarning("No image files were included in the dropped content.");
				return;
			}
			await DecodePathsAsync(imagePaths);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteWarning("Failed to decode the dropped image files. See logs for details.");
			Logger.Write(ex);
		}
	}

	private static async Task<List<string>> GetStorageFilePathsAsync(DataPackageView dataView)
	{
		if (!dataView.Contains(StandardDataFormats.StorageItems)) return [];
		IReadOnlyList<IStorageItem> storageItems = await dataView.GetStorageItemsAsync();
		List<string> paths = new(storageItems.Count);
		foreach (IStorageItem storageItem in storageItems)
		{
			if (storageItem is StorageFile { Path.Length: > 0 } file)
			{
				paths.Add(file.Path);
			}
		}
		return paths;
	}

	private async Task DeleteCreatedQrDragFileAsync()
	{
		StorageFile? dragFile = createdQrDragFile;
		createdQrDragFile = null;
		if (dragFile is null) return;
		try
		{
			await dragFile.DeleteAsync(StorageDeleteOption.PermanentDelete);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	private void CreatedQrImage_DragStarting(UIElement sender, DragStartingEventArgs args)
	{
		if (createdQrDragFile is null)
		{
			args.Cancel = true;
			return;
		}
		args.AllowedOperations = DataPackageOperation.Copy;
		args.Data.RequestedOperation = DataPackageOperation.Copy;
		args.Data.Properties.Title = "Generated QR code";
		IStorageItem[] dragItems = [createdQrDragFile];
		args.Data.SetStorageItems(dragItems);
	}

	private async Task RefreshCreatedQrDragFileAsync(SoftwareBitmap bitmap, int generationVersion)
	{
		using SoftwareBitmap dragBitmap = SoftwareBitmap.Copy(bitmap);
		StorageFile? newDragFile = null;
		try
		{
			newDragFile = await ApplicationData.Current.TemporaryFolder.CreateFileAsync("QR Code.png", CreationCollisionOption.GenerateUniqueName);
			using IRandomAccessStream stream = await newDragFile.OpenAsync(FileAccessMode.ReadWrite);
			await EncodeSoftwareBitmapAsync(stream, BitmapEncoder.PngEncoderId, dragBitmap);
			if (generationVersion != creatorGenerationVersion)
			{
				await newDragFile.DeleteAsync(StorageDeleteOption.PermanentDelete);
				return;
			}
			StorageFile? previousDragFile = createdQrDragFile;
			createdQrDragFile = newDragFile;
			newDragFile = null;
			if (previousDragFile is not null)
			{
				try
				{
					await previousDragFile.DeleteAsync(StorageDeleteOption.PermanentDelete);
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
				}
			}
		}
		catch (Exception ex)
		{
			if (newDragFile is not null)
			{
				try
				{
					await newDragFile.DeleteAsync(StorageDeleteOption.PermanentDelete);
				}
				catch (Exception cleanupException)
				{
					Logger.Write(cleanupException);
				}
			}
			Logger.Write(ex);
		}
	}

	private async void PasteReaderImagesAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		if (ReaderView.Visibility is not Visibility.Visible || isBusy) return;
		args.Handled = true;
		try
		{
			DataPackageView clipboardContent = Clipboard.GetContent();
			if (clipboardContent.Contains(StandardDataFormats.StorageItems))
			{
				List<string> imagePaths = await GetStorageFilePathsAsync(clipboardContent);
				if (imagePaths.Count > 0)
				{
					await DecodePathsAsync(imagePaths);
					return;
				}
			}
			if (clipboardContent.Contains(StandardDataFormats.Bitmap))
			{
				RandomAccessStreamReference bitmapReference = await clipboardContent.GetBitmapAsync();
				using IRandomAccessStreamWithContentType stream = await bitmapReference.OpenReadAsync();
				BitmapDecoder decoder = await BitmapDecoder.CreateAsync(stream);
				using SoftwareBitmap bitmap = await decoder.GetSoftwareBitmapAsync(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied);
				SetBusyInfo("Decoding the pasted QR image, please wait.");
				QR.QrResult result = await QR.Manage.DecodeAsync(bitmap, "Pasted clipboard image");
				WriteDecodedText(result.Text, "pasted clipboard image");
				return;
			}
			MainInfoBar.WriteWarning("The clipboard does not contain image files or an image.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteWarning("Failed to decode the pasted image content. See logs for details.");
			Logger.Write(ex);
		}
		finally
		{
			isBusy = false;
		}
	}

	private async void SelectImage_Click()
	{
		if (isBusy) return;
		List<string> selectedPaths = FileDialogHelper.ShowMultipleFilePickerDialog(SecureVault.TotpQrImagePickerFilter);
		if (selectedPaths.Count == 0) return;
		await DecodePathsAsync(selectedPaths);
	}

	private async Task DecodePathsAsync(List<string> paths)
	{
		try
		{
			SetBusyInfo(paths.Count == 1 ? "Decoding the QR code, please wait." : "Decoding the selected QR code images, please wait.");
			List<QR.QrResult> results = await QR.Manage.DecodeAsync(paths);
			if (results.Count == 1)
			{
				QR.QrResult result = results[0];
				if (result.Error is not null)
				{
					Logger.Write(result.Error);
					DecodedTextBox.Text = "1. " + Path.GetFileName(result.FilePath) + " - " + FormatElapsed(result.Elapsed) + " - There was an error. Check logs for details.";
					CopyButton.IsEnabled = true;
					MainInfoBar.WriteWarning("Failed to decode the QR code from the selected image. See logs for details.");
					return;
				}
				WriteDecodedText(result.Text, "selected image");
				return;
			}
			StringBuilder output = new(results.Count * 96);
			int successfulResults = 0;
			for (int index = 0; index < results.Count; index++)
			{
				QR.QrResult result = results[index];
				if (index > 0)
				{
					_ = output.AppendLine();
				}
				_ = output.Append(index + 1)
					.Append(". ")
					.Append(Path.GetFileName(result.FilePath))
					.Append(" - ")
					.Append(FormatElapsed(result.Elapsed))
					.Append(" - ");
				if (result.Error is not null)
				{
					Logger.Write(result.Error);
					_ = output.Append("There was an error. Check logs for details.");
				}
				else if (string.IsNullOrWhiteSpace(result.Text))
				{
					_ = output.Append("No readable QR result was found.");
				}
				else
				{
					_ = output.Append(result.Text);
					successfulResults++;
				}
			}
			DecodedTextBox.Text = output.ToString();
			CopyButton.IsEnabled = true;
			if (successfulResults == results.Count)
			{
				MainInfoBar.WriteSuccess("All selected QR code images were decoded successfully.");
			}
			else if (successfulResults > 0)
			{
				MainInfoBar.WriteWarning("Some selected images could not be decoded. Check the results and logs for details.");
			}
			else
			{
				MainInfoBar.WriteWarning("None of the selected images could be decoded. Check the results and logs for details.");
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteWarning("Failed to decode the selected image files. See logs for details.");
			Logger.Write(ex);
		}
		finally
		{
			isBusy = false;
		}
	}

	private static string FormatElapsed(TimeSpan elapsed) => elapsed.TotalMilliseconds < 1000D
		? string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{elapsed.TotalMilliseconds:F2} ms")
		: string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{elapsed.TotalSeconds:F2} s");

	private async void SelectScreenContent_Click()
	{
		if (isBusy) return;
		if (!GraphicsCaptureSession.IsSupported())
		{
			MainInfoBar.WriteWarning("Screen capture is not supported on this device.");
			return;
		}
		try
		{
			GraphicsCapturePicker picker = new();
			IntPtr windowHandle = WinRT.Interop.WindowNative.GetWindowHandle(this);
			WinRT.Interop.InitializeWithWindow.Initialize(picker, windowHandle);
			GraphicsCaptureItem? captureItem = await picker.PickSingleItemAsync();
			if (captureItem is null) return;
			SetBusyInfo("Capturing and decoding the selected screen content, please wait.");
			using SoftwareBitmap screenshot = await QR.Manage.CaptureSingleFrameAsync(captureItem);
			QR.QrResult result = await QR.Manage.DecodeAsync(screenshot, "Screen capture");
			WriteDecodedText(result.Text, "selected screen content");
		}
		catch (TimeoutException)
		{
			MainInfoBar.WriteWarning("No screen capture frame became available.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			isBusy = false;
		}
	}

	private async void UseSnippingTool_Click()
	{
		if (isBusy) return;
		try
		{
			string correlationId = Guid.CreateVersion7().ToString("D");
			Uri requestUri = new($"ms-screenclip://capture/image?redirect-uri=harden-system-security-snipping://capture-response&user-agent=HardenSystemSecurity&api-version=1.2&x-request-correlation-id={correlationId}&auto-save&rectangle");
			App.SnippingToolResponseHandler = HandleSnippingToolResponse;
			SetBusyInfo("Select the QR code area on your screen and wait for it to be processed.");
			if (!await Launcher.LaunchUriAsync(requestUri))
			{
				isBusy = false;
				MainInfoBar.WriteWarning("Snipping Tool could not be launched.");
			}
		}
		catch (Exception ex)
		{
			isBusy = false;
			MainInfoBar.WriteError(ex);
		}
	}

	private async void HandleSnippingToolResponse(Uri? responseUri)
	{
		if (currentWindow is null) return;
		try
		{
			if (!SecureVault.TryGetQueryValue(responseUri, "file-access-token", out string fileAccessToken))
			{
				if (SecureVault.TryGetQueryValue(responseUri, "status", out string status))
				{
					MainInfoBar.WriteWarning(string.Concat("Snipping Tool returned status ", status, " without an image."));
				}
				else
				{
					MainInfoBar.WriteWarning("The Snipping Tool response did not contain an image.");
				}
				return;
			}
			StorageFile captureFile = await SharedStorageAccessManager.RedeemTokenForFileAsync(fileAccessToken);
			using IRandomAccessStream stream = await captureFile.OpenAsync(FileAccessMode.Read);
			BitmapDecoder decoder = await BitmapDecoder.CreateAsync(stream);
			using SoftwareBitmap screenshot = await decoder.GetSoftwareBitmapAsync(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied);
			QR.QrResult result = await QR.Manage.DecodeAsync(screenshot, "Snipping Tool capture");
			WriteDecodedText(result.Text, "Snipping Tool capture");
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			MainInfoBar.WriteWarning("Failed to decode the QR code from the Snipping Tool capture. See logs for details.");
		}
		finally
		{
			isBusy = false;
		}
	}

	private async void ScanWithCamera_Click()
	{
		if (isBusy) return;
		try
		{
			ClearDetectedQrSource();
			DetectedQrBorder.Visibility = Visibility.Collapsed;
			SetBusyInfo("Starting the camera, please wait.");
			DeviceInformationCollection cameras = await DeviceInformation.FindAllAsync(DeviceClass.VideoCapture);
			if (cameras.Count == 0)
			{
				MainInfoBar.WriteWarning("No camera was found on this device.");
				isBusy = false;
				return;
			}

			MediaCaptureInitializationSettings settings = new()
			{
				VideoDeviceId = cameras[0].Id,
				StreamingCaptureMode = StreamingCaptureMode.Video,
				MemoryPreference = MediaCaptureMemoryPreference.Auto
			};
			_ = Interlocked.Exchange(ref isCameraResultFound, 0);
			lastCameraAnalysisTimestamp = 0;
			mediaCapture = new MediaCapture();
			await mediaCapture.InitializeAsync(settings);

			MediaFrameSource? colorSource = mediaCapture.FrameSources.Values.FirstOrDefault(
				static source => source.Info.SourceKind is MediaFrameSourceKind.Color) ?? throw new InvalidOperationException("The selected camera does not provide a color video stream.");
			CameraPreviewElement.Source = MediaSource.CreateFromMediaFrameSource(colorSource);
			CameraPreviewBorder.Visibility = Visibility.Visible;
			StopCameraButton.IsEnabled = true;
			BitmapSize cameraFrameSize = new()
			{
				Width = CameraFrameWidth,
				Height = CameraFrameHeight
			};
			mediaFrameReader = await mediaCapture.CreateFrameReaderAsync(colorSource, MediaEncodingSubtypes.Bgra8, cameraFrameSize);
			mediaFrameReader.AcquisitionMode = MediaFrameReaderAcquisitionMode.Realtime;
			mediaFrameReader.FrameArrived += CameraFrameReader_FrameArrived;
			MediaFrameReaderStartStatus startStatus = await mediaFrameReader.StartAsync();
			if (startStatus is not MediaFrameReaderStartStatus.Success)
			{
				throw new InvalidOperationException(string.Concat("The camera frame reader could not start. Status: ", startStatus.ToString()));
			}
			FocusControl focusControl = mediaCapture.VideoDeviceController.FocusControl;
			if (focusControl.Supported)
			{
				FocusSettings focusSettings = new()
				{
					Mode = FocusMode.Continuous,
					AutoFocusRange = AutoFocusRange.FullRange,
					DisableDriverFallback = false,
					WaitForFocus = false
				};
				focusControl.Configure(focusSettings);
			}
			MainInfoBar.WriteInfo("Align the entire QR code inside the dotted square and hold it steady.");
		}
		catch (UnauthorizedAccessException)
		{
			await StopCameraAsync();
			isBusy = false;
			MainInfoBar.WriteWarning("Camera access was denied. Enable camera access in Windows Settings and try again.");
		}
		catch (Exception ex)
		{
			await StopCameraAsync();
			isBusy = false;
			MainInfoBar.WriteError(ex);
		}
	}

	private async void StopCamera_Click()
	{
		await StopCameraAsync();
		isBusy = false;
		MainInfoBar.WriteInfo("Camera scanning stopped.");
	}

	private async void CameraFrameReader_FrameArrived(MediaFrameReader sender, MediaFrameArrivedEventArgs args)
	{
		long now = Stopwatch.GetTimestamp();
		if (lastCameraAnalysisTimestamp != 0 && Stopwatch.GetElapsedTime(lastCameraAnalysisTimestamp, now) < CameraAnalysisInterval) return;
		if (Interlocked.Exchange(ref isCameraFrameProcessing, 1) != 0) return;
		lastCameraAnalysisTimestamp = now;
		try
		{
			using MediaFrameReference? frame = sender.TryAcquireLatestFrame();
			if (frame?.VideoMediaFrame is not VideoMediaFrame videoFrame) return;
			SoftwareBitmap? ownedSurfaceBitmap = null;
			try
			{
				SoftwareBitmap? acquiredBitmap = videoFrame.SoftwareBitmap;
				if (acquiredBitmap is null && videoFrame.Direct3DSurface is not null)
				{
					ownedSurfaceBitmap = await SoftwareBitmap.CreateCopyFromSurfaceAsync(videoFrame.Direct3DSurface);
					acquiredBitmap = ownedSurfaceBitmap;
				}
				if (acquiredBitmap is null) return;
				using SoftwareBitmap normalizedBitmap = acquiredBitmap.BitmapPixelFormat is BitmapPixelFormat.Bgra8
					? SoftwareBitmap.Copy(acquiredBitmap)
					: SoftwareBitmap.Convert(acquiredBitmap, BitmapPixelFormat.Bgra8, BitmapAlphaMode.Ignore);
				using SoftwareBitmap scanRegion = CropCameraScanRegion(normalizedBitmap);
				QR.Manage.CameraQrCandidate? cameraCandidate = await QR.Manage.TryExtractCameraQrAsync(scanRegion);
				if (cameraCandidate is null || Interlocked.Exchange(ref isCameraResultFound, 1) != 0)
				{
					cameraCandidate?.Dispose();
					return;
				}
				if (!DispatcherQueue.TryEnqueue(async () =>
				{
					try
					{
						MainInfoBar.WriteInfo("QR code detected. Camera stopped. Preparing the verified result.");
						await StopCameraAsync();
						SoftwareBitmapSource? newDetectedQrSource = null;
						try
						{
							newDetectedQrSource = new SoftwareBitmapSource();
							await newDetectedQrSource.SetBitmapAsync(cameraCandidate.Bitmap);
							ClearDetectedQrSource();
							detectedQrSource = newDetectedQrSource;
							newDetectedQrSource = null;
							DetectedQrImage.Source = detectedQrSource;
						}
						finally
						{
							newDetectedQrSource?.Dispose();
						}
						DetectedQrBorder.Visibility = Visibility.Visible;
						WriteDecodedText(cameraCandidate.Result.Text, "camera detected QR code");
					}
					catch (Exception ex)
					{
						MainInfoBar.WriteError(ex);
					}
					finally
					{
						cameraCandidate.Dispose();
						isBusy = false;
					}
				}))
				{
					cameraCandidate.Dispose();
					_ = Interlocked.Exchange(ref isCameraResultFound, 0);
				}
			}
			finally
			{
				ownedSurfaceBitmap?.Dispose();
			}
		}
		finally
		{
			_ = Interlocked.Exchange(ref isCameraFrameProcessing, 0);
		}
	}

	private void CameraPreviewBorder_SizeChanged(object sender, SizeChangedEventArgs args)
	{
		double availableWidth = args.NewSize.Width;
		double availableHeight = args.NewSize.Height;
		if (availableWidth <= 0D || availableHeight <= 0D)
		{
			return;
		}
		double frameAspectRatio = CameraFrameWidth / (double)CameraFrameHeight;
		double previewAspectRatio = availableWidth / availableHeight;
		double renderedWidth = previewAspectRatio > frameAspectRatio ? availableHeight * frameAspectRatio : availableWidth;
		double renderedHeight = previewAspectRatio > frameAspectRatio ? availableHeight : availableWidth / frameAspectRatio;
		double guideSide = Math.Floor(Math.Min(renderedWidth, renderedHeight) * CameraScanFraction);
		CameraScanGuide.Width = guideSide;
		CameraScanGuide.Height = guideSide;
	}

	private static SoftwareBitmap CropCameraScanRegion(SoftwareBitmap bitmap)
	{
		int side = Math.Max(64, (int)Math.Floor(Math.Min(bitmap.PixelWidth, bitmap.PixelHeight) * CameraScanFraction));
		int left = (bitmap.PixelWidth - side) / 2;
		int top = (bitmap.PixelHeight - side) / 2;
		byte[] sourcePixels = GC.AllocateUninitializedArray<byte>(checked(bitmap.PixelWidth * bitmap.PixelHeight * 4));
		bitmap.CopyToBuffer(sourcePixels.AsBuffer());
		byte[] regionPixels = GC.AllocateUninitializedArray<byte>(checked(side * side * 4));
		int sourceStride = bitmap.PixelWidth * 4;
		int regionStride = side * 4;
		for (int row = 0; row < side; row++)
		{
			System.Buffer.BlockCopy(sourcePixels, ((top + row) * sourceStride) + (left * 4), regionPixels, row * regionStride, regionStride);
		}
		return SoftwareBitmap.CreateCopyFromBuffer(regionPixels.AsBuffer(), BitmapPixelFormat.Bgra8, side, side, BitmapAlphaMode.Ignore);
	}

	private async Task StopCameraAsync()
	{
		MediaFrameReader? reader = mediaFrameReader;
		mediaFrameReader = null;
		if (reader is not null)
		{
			reader.FrameArrived -= CameraFrameReader_FrameArrived;
			try
			{
				await reader.StopAsync();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
			reader.Dispose();
		}
		CameraPreviewElement.Source = null;
		CameraPreviewBorder.Visibility = Visibility.Collapsed;
		StopCameraButton.IsEnabled = false;
		mediaCapture?.Dispose();
		mediaCapture = null;
		_ = Interlocked.Exchange(ref isCameraFrameProcessing, 0);
		_ = Interlocked.Exchange(ref isCameraResultFound, 0);
	}

	private void WriteDecodedText(string? text, string sourceName)
	{
		if (string.IsNullOrWhiteSpace(text))
		{
			DecodedTextBox.Text = string.Empty;
			CopyButton.IsEnabled = false;
			MainInfoBar.WriteWarning(string.Concat("No readable QR code was found in the ", sourceName, "."));
			return;
		}
		DecodedTextBox.Text = text;
		CopyButton.IsEnabled = true;
		MainInfoBar.WriteSuccess("The QR code was decoded successfully.");
	}

	private void CopyButton_Click()
	{
		if (string.IsNullOrWhiteSpace(DecodedTextBox.Text))
		{
			MainInfoBar.WriteWarning("There is no decoded text to copy.");
			return;
		}
		ClipboardManagement.CopyText(DecodedTextBox.Text);
		MainInfoBar.WriteSuccess("The decoded text was copied to the clipboard.");
	}

	private void SetBusyInfo(string message)
	{
		isBusy = true;
		MainInfoBar.WriteInfo(message);
	}

	public void Dispose()
	{
		if (isDisposed) return;
		isDisposed = true;
		MediaFrameReader? reader = mediaFrameReader;
		mediaFrameReader = null;
		if (reader is not null)
		{
			reader.FrameArrived -= CameraFrameReader_FrameArrived;
			reader.Dispose();
		}
		mediaCapture?.Dispose();
		mediaCapture = null;
		createdQrBitmap?.Dispose();
		createdQrBitmap = null;
		ClearCreatedQrSource();
		ClearDetectedQrSource();
		GC.SuppressFinalize(this);
	}

	private async void OnClosed()
	{
		await DeleteCreatedQrDragFileAsync();
		App.SnippingToolResponseHandler = null;
		currentWindow = null;
		await StopCameraAsync();
		Dispose();
	}
}
