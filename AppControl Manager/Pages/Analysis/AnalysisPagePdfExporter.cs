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
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Storage.Streams;
using Windows.UI;
using WinRT;

namespace AppControlManager.Pages.Analysis;

/// <summary>
/// Implements the Analysis page PDF export pipeline for AppControl Manager.
/// The exporter captures visible WinUI content with RenderTargetBitmap at a high render scale,
/// flattens BGRA premultiplied-alpha pixels onto the resolved page background, crops horizontal
/// background-only margins, and writes the captured content as RGB image XObjects into a single-page
/// PDF 2.0 with PDF/A-4 document.
/// </summary>
internal static class AnalysisPagePdfExporter
{
	private const double PreferredRenderScale = 10.0;
	private const int PagePaddingDips = 72;
	private const int BackgroundTolerance = 10;
	private const int RgbComponentCount = 3;
	private const double PointsPerDip = 72.0 / 96.0;
	private const CompressionLevel PdfCompressionLevel = CompressionLevel.Optimal;
	private const string SRgbIccProfileBase64 = "AAACTGxjbXMEQAAAbW50clJHQiBYWVogB+oABgAVABEAAAAcYWNzcEFQUEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPbWAAEAAAAA0y1sY21zAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALZGVzYwAAAQgAAAA2Y3BydAAAAUAAAABMd3RwdAAAAYwAAAAUY2hhZAAAAaAAAAAsclhZWgAAAcwAAAAUYlhZWgAAAeAAAAAUZ1hZWgAAAfQAAAAUclRSQwAAAggAAAAgZ1RSQwAAAggAAAAgYlRSQwAAAggAAAAgY2hybQAAAigAAAAkbWx1YwAAAAAAAAABAAAADGVuVVMAAAAaAAAAHABzAFIARwBCACAAYgB1AGkAbAB0AC0AaQBuAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAADAAAAAcAE4AbwAgAGMAbwBwAHkAcgBpAGcAaAB0ACwAIAB1AHMAZQAgAGYAcgBlAGUAbAB5WFlaIAAAAAAAAPbWAAEAAAAA0y1zZjMyAAAAAAABDEIAAAXe///zJQAAB5MAAP2Q///7of///aIAAAPcAADAblhZWiAAAAAAAABvoAAAOPUAAAOQWFlaIAAAAAAAACSfAAAPhAAAtsNYWVogAAAAAAAAYpcAALeHAAAY2XBhcmEAAAAAAAMAAAACZmYAAPKnAAANWQAAE9AAAApbY2hybQAAAAAAAwAAAACj1wAAVHsAAEzNAACZmgAAJmYAAA9c";

	[DynamicWindowsRuntimeCast(typeof(SolidColorBrush))]
	[DynamicWindowsRuntimeCast(typeof(StackPanel))]
	internal static async Task ExportAsync(FrameworkElement contentElement, string defaultFileName)
	{
		string? savePath = FileDialogHelper.ShowSaveFileDialog("PDF Document (*.pdf)|*.pdf", defaultFileName);
		if (string.IsNullOrWhiteSpace(savePath))
		{
			return;
		}
		if (!savePath.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase))
		{
			savePath += ".pdf";
		}

		Color backgroundColor = Colors.White;
		if (Application.Current.Resources.TryGetValue("ApplicationPageBackgroundThemeBrush", out object value) && value is SolidColorBrush brush)
		{
			backgroundColor = brush.Color;
		}

		PdfMetadata metadata = CreateMetadata(defaultFileName);
		List<CapturedImage> images = await CaptureExportImagesAsync(contentElement, backgroundColor);
		if (images.Count == 0)
		{
			CapturedImage fallbackImage = await CaptureElementAsync(contentElement, backgroundColor);
			images.Add(CropHorizontalBackground(fallbackImage, backgroundColor));
		}

		double spacingDips = contentElement is StackPanel stackPanel ? stackPanel.Spacing : 0;
		using MemoryStream pdfStream = CreatePdf(images, spacingDips, backgroundColor, metadata);
		await using FileStream outputStream = new(savePath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize: 1024 * 1024, useAsync: true);
		await outputStream.WriteAsync(pdfStream.GetBuffer().AsMemory(0, checked((int)pdfStream.Length)));
	}

	[DynamicWindowsRuntimeCast(typeof(Panel))]
	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	private static async Task<List<CapturedImage>> CaptureExportImagesAsync(FrameworkElement contentElement, Color backgroundColor)
	{
		List<CapturedImage> images = [];
		if (contentElement is not Panel panel)
		{
			return images;
		}

		foreach (UIElement child in panel.Children)
		{
			if (child is not FrameworkElement childElement || childElement.Visibility != Visibility.Visible)
			{
				continue;
			}
			childElement.UpdateLayout();
			if (childElement.ActualWidth <= 0 || childElement.ActualHeight <= 0)
			{
				continue;
			}
			CapturedImage capturedImage = await CaptureElementAsync(childElement, backgroundColor);
			images.Add(CropHorizontalBackground(capturedImage, backgroundColor));
		}
		return images;
	}

	private static async Task<CapturedImage> CaptureElementAsync(FrameworkElement element, Color backgroundColor)
	{
		element.UpdateLayout();
		double logicalWidth = Math.Max(1, element.ActualWidth);
		double logicalHeight = Math.Max(1, element.ActualHeight);
		int requestedPixelWidth = Math.Max(1, (int)Math.Ceiling(logicalWidth * PreferredRenderScale));
		int requestedPixelHeight = Math.Max(1, (int)Math.Ceiling(logicalHeight * PreferredRenderScale));
		RenderTargetBitmap renderTargetBitmap = new();
		await renderTargetBitmap.RenderAsync(element, requestedPixelWidth, requestedPixelHeight);
		int pixelWidth = Math.Max(1, renderTargetBitmap.PixelWidth);
		int pixelHeight = Math.Max(1, renderTargetBitmap.PixelHeight);
		double actualScale = pixelWidth / logicalWidth;
		IBuffer pixelBuffer = await renderTargetBitmap.GetPixelsAsync();
		byte[] bgraPixels = new byte[(int)pixelBuffer.Length];
		using DataReader dataReader = DataReader.FromBuffer(pixelBuffer);
		dataReader.ReadBytes(bgraPixels);
		byte[] rgbPixels = new byte[checked(pixelWidth * pixelHeight * RgbComponentCount)];
		for (int index = 0; index < rgbPixels.Length; index += RgbComponentCount)
		{
			rgbPixels[index] = backgroundColor.R;
			rgbPixels[index + 1] = backgroundColor.G;
			rgbPixels[index + 2] = backgroundColor.B;
		}
		Span<int> redBackgroundByAlpha = stackalloc int[256];
		Span<int> greenBackgroundByAlpha = stackalloc int[256];
		Span<int> blueBackgroundByAlpha = stackalloc int[256];
		PopulatePremultipliedAlphaBackgroundTables(backgroundColor, redBackgroundByAlpha, greenBackgroundByAlpha, blueBackgroundByAlpha);
		int pixelCount = Math.Min(pixelWidth * pixelHeight, bgraPixels.Length / 4);
		for (int pixelIndex = 0; pixelIndex < pixelCount; pixelIndex++)
		{
			int sourceIndex = pixelIndex * 4;
			int targetIndex = pixelIndex * RgbComponentCount;
			byte blue = bgraPixels[sourceIndex];
			byte green = bgraPixels[sourceIndex + 1];
			byte red = bgraPixels[sourceIndex + 2];
			byte alpha = bgraPixels[sourceIndex + 3];
			if (alpha == 255)
			{
				rgbPixels[targetIndex] = red;
				rgbPixels[targetIndex + 1] = green;
				rgbPixels[targetIndex + 2] = blue;
				continue;
			}
			rgbPixels[targetIndex] = (byte)(red + redBackgroundByAlpha[alpha]);
			rgbPixels[targetIndex + 1] = (byte)(green + greenBackgroundByAlpha[alpha]);
			rgbPixels[targetIndex + 2] = (byte)(blue + blueBackgroundByAlpha[alpha]);
		}
		return new CapturedImage(pixelWidth, pixelHeight, actualScale, rgbPixels);
	}

	private static CapturedImage CropHorizontalBackground(CapturedImage image, Color backgroundColor)
	{
		ReadOnlySpan<byte> imagePixels = image.RgbPixels.Span;
		int left = image.PixelWidth;
		int right = -1;
		for (int y = 0; y < image.PixelHeight; y++)
		{
			int rowOffset = y * image.PixelWidth * RgbComponentCount;
			for (int x = 0; x < image.PixelWidth; x++)
			{
				int pixelOffset = rowOffset + (x * RgbComponentCount);
				bool isBackgroundPixel = Math.Abs(imagePixels[pixelOffset] - backgroundColor.R) <= BackgroundTolerance &&
					Math.Abs(imagePixels[pixelOffset + 1] - backgroundColor.G) <= BackgroundTolerance &&
					Math.Abs(imagePixels[pixelOffset + 2] - backgroundColor.B) <= BackgroundTolerance;
				if (!isBackgroundPixel)
				{
					left = Math.Min(left, x);
					right = Math.Max(right, x);
				}
			}
		}
		if (right < left)
		{
			return image;
		}
		int croppedWidth = right - left + 1;
		if (croppedWidth >= image.PixelWidth)
		{
			return image;
		}
		byte[] croppedPixels = new byte[checked(croppedWidth * image.PixelHeight * RgbComponentCount)];
		int croppedRowByteCount = croppedWidth * RgbComponentCount;
		for (int y = 0; y < image.PixelHeight; y++)
		{
			int sourceOffset = ((y * image.PixelWidth) + left) * RgbComponentCount;
			int targetOffset = y * croppedRowByteCount;
			imagePixels.Slice(sourceOffset, croppedRowByteCount).CopyTo(croppedPixels.AsSpan(targetOffset, croppedRowByteCount));
		}
		return new CapturedImage(croppedWidth, image.PixelHeight, image.PixelsPerDip, croppedPixels);
	}

	private static MemoryStream CreatePdf(IReadOnlyList<CapturedImage> images, double spacingDips, Color backgroundColor, PdfMetadata metadata)
	{
		double pagePaddingPoints = PagePaddingDips * PointsPerDip;
		double spacingPoints = spacingDips * PointsPerDip;
		double contentWidthPoints = 1;
		double contentHeightPoints = 0;
		for (int index = 0; index < images.Count; index++)
		{
			CapturedImage image = images[index];
			contentWidthPoints = Math.Max(contentWidthPoints, image.WidthPoints);
			contentHeightPoints += image.HeightPoints;
			if (index < images.Count - 1)
			{
				contentHeightPoints += spacingPoints;
			}
		}
		double pageWidth = contentWidthPoints + (pagePaddingPoints * 2);
		double pageHeight = contentHeightPoints + (pagePaddingPoints * 2);
		List<ReadOnlyMemory<byte>> compressedImages = new(images.Count);
		for (int index = 0; index < images.Count; index++)
		{
			CapturedImage image = images[index];
			byte[] predictorBytes = ApplyBestPngPredictor(image.RgbPixels.Span, image.PixelWidth, image.PixelHeight);
			compressedImages.Add(Compress(predictorBytes));
		}
		StringBuilder contentBuilder = new(1024 + (images.Count * 96));
		string backgroundRed = (backgroundColor.R / 255.0).ToString("0.###", CultureInfo.InvariantCulture);
		string backgroundGreen = (backgroundColor.G / 255.0).ToString("0.###", CultureInfo.InvariantCulture);
		string backgroundBlue = (backgroundColor.B / 255.0).ToString("0.###", CultureInfo.InvariantCulture);
		_ = contentBuilder.Append(CultureInfo.InvariantCulture, $"q {backgroundRed} {backgroundGreen} {backgroundBlue} rg 0 0 {FormatPdfNumber(pageWidth)} {FormatPdfNumber(pageHeight)} re f Q\n");
		double currentY = pageHeight - pagePaddingPoints;
		for (int index = 0; index < images.Count; index++)
		{
			CapturedImage image = images[index];
			currentY -= image.HeightPoints;
			double x = (pageWidth - image.WidthPoints) / 2;
			_ = contentBuilder.Append(CultureInfo.InvariantCulture, $"q {FormatPdfNumber(image.WidthPoints)} 0 0 {FormatPdfNumber(image.HeightPoints)} {FormatPdfNumber(x)} {FormatPdfNumber(currentY)} cm /Im{index} Do Q\n");
			currentY -= spacingPoints;
		}
		byte[] contentBytes = Encoding.ASCII.GetBytes(contentBuilder.ToString());
		byte[] xmpBytes = Encoding.UTF8.GetBytes(BuildXmpMetadata(metadata));
		byte[] iccProfileBytes = Convert.FromBase64String(SRgbIccProfileBase64);
		int estimatedPdfLength = EstimatePdfLength(compressedImages, contentBytes.Length, xmpBytes.Length, iccProfileBytes.Length, images.Count);
		MemoryStream pdfStream = new(estimatedPdfLength);
		List<long> objectOffsets = new(images.Count + 8);
		WriteAscii(pdfStream, "%PDF-2.0\n");
		pdfStream.Write([0x25, 0xE2, 0xE3, 0xCF, 0xD3, 0x0A]);
		WriteAscii(pdfStream, "% Generated by AppControl Manager\n");
		WriteObject(pdfStream, objectOffsets, 1, "<< /Type /Catalog /Version /2.0 /Pages 2 0 R /Metadata 4 0 R /OutputIntents [6 0 R] >>\n");
		WriteObject(pdfStream, objectOffsets, 2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n");
		StringBuilder pageBuilder = new(256 + (images.Count * 24));
		_ = pageBuilder.Append(CultureInfo.InvariantCulture, $"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {FormatPdfNumber(pageWidth)} {FormatPdfNumber(pageHeight)}] /Resources << /ColorSpace << /DefaultRGB 7 0 R >> /XObject << ");
		for (int index = 0; index < images.Count; index++)
		{
			_ = pageBuilder.Append(CultureInfo.InvariantCulture, $"/Im{index} {8 + index} 0 R ");
		}
		_ = pageBuilder.Append(CultureInfo.InvariantCulture, $">> >> /Contents {8 + images.Count} 0 R >>\n");
		WriteObject(pdfStream, objectOffsets, 3, pageBuilder.ToString());
		WriteStreamObject(pdfStream, objectOffsets, 4, "<< /Type /Metadata /Subtype /XML /Length " + xmpBytes.Length.ToString(CultureInfo.InvariantCulture) + " >>\n", xmpBytes);
		WriteStreamObject(pdfStream, objectOffsets, 5, "<< /N 3 /Alternate /DeviceRGB /Length " + iccProfileBytes.Length.ToString(CultureInfo.InvariantCulture) + " >>\n", iccProfileBytes);
		WriteObject(pdfStream, objectOffsets, 6, "<< /Type /OutputIntent /S /GTS_PDFA1 /OutputConditionIdentifier (sRGB IEC61966-2.1) /RegistryName (http://www.color.org) /Info (sRGB IEC61966-2.1) /DestOutputProfile 5 0 R >>\n");
		WriteObject(pdfStream, objectOffsets, 7, "[/ICCBased 5 0 R]\n");
		for (int index = 0; index < images.Count; index++)
		{
			CapturedImage image = images[index];
			ReadOnlyMemory<byte> compressedImage = compressedImages[index];
			int imageObjectNumber = 8 + index;
			string imageDictionary = string.Create(CultureInfo.InvariantCulture, $"<< /Type /XObject /Subtype /Image /Width {image.PixelWidth} /Height {image.PixelHeight} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Interpolate false /Filter /FlateDecode /DecodeParms << /Predictor 15 /Colors 3 /BitsPerComponent 8 /Columns {image.PixelWidth} >> /Length {compressedImage.Length} >>\n");
			WriteStreamObject(pdfStream, objectOffsets, imageObjectNumber, imageDictionary, compressedImage);
		}
		int contentObjectNumber = 8 + images.Count;
		WriteStreamObject(pdfStream, objectOffsets, contentObjectNumber, string.Create(CultureInfo.InvariantCulture, $"<< /Length {contentBytes.Length} >>\n"), contentBytes);
		long xrefOffset = pdfStream.Position;
		WriteAscii(pdfStream, string.Create(CultureInfo.InvariantCulture, $"xref\n0 {objectOffsets.Count + 1}\n"));
		WriteAscii(pdfStream, "0000000000 65535 f \n");
		foreach (long offset in objectOffsets)
		{
			WriteAscii(pdfStream, offset.ToString("D10", CultureInfo.InvariantCulture) + " 00000 n \n");
		}
		string documentId = CreateDocumentId(metadata, xrefOffset, objectOffsets.Count);
		WriteAscii(pdfStream, string.Create(CultureInfo.InvariantCulture, $"trailer\n<< /Size {objectOffsets.Count + 1} /Root 1 0 R /ID [<{documentId}> <{documentId}>] >>\nstartxref\n{xrefOffset}\n%%EOF\n"));
		pdfStream.Position = 0;
		return pdfStream;
	}

	private static byte[] ApplyBestPngPredictor(ReadOnlySpan<byte> rgbPixels, int pixelWidth, int pixelHeight)
	{
		int rowByteCount = checked(pixelWidth * RgbComponentCount);
		byte[] predictedPixels = new byte[checked((rowByteCount + 1) * pixelHeight)];
		for (int row = 0; row < pixelHeight; row++)
		{
			ReadOnlySpan<byte> currentRow = rgbPixels.Slice(row * rowByteCount, rowByteCount);
			ReadOnlySpan<byte> previousRow = row == 0 ? [] : rgbPixels.Slice((row - 1) * rowByteCount, rowByteCount);
			long bestScore = long.MaxValue;
			byte bestFilter = 0;
			for (byte filter = 0; filter <= 4; filter++)
			{
				long score = CalculatePngFilterScore(currentRow, previousRow, rowByteCount, filter, bestScore);
				if (score < bestScore)
				{
					bestScore = score;
					bestFilter = filter;
				}
			}
			int targetOffset = row * (rowByteCount + 1);
			predictedPixels[targetOffset] = bestFilter;
			Span<byte> targetRow = predictedPixels.AsSpan(targetOffset + 1, rowByteCount);
			WritePngFilteredRow(currentRow, previousRow, targetRow, bestFilter);
		}
		return predictedPixels;
	}

	private static long CalculatePngFilterScore(ReadOnlySpan<byte> currentRow, ReadOnlySpan<byte> previousRow, int rowByteCount, byte filter, long bestScore)
	{
		long score = 0;
		if (filter == 0)
		{
			for (int column = 0; column < rowByteCount; column++)
			{
				int filtered = currentRow[column];
				int signed = filtered < 128 ? filtered : filtered - 256;
				score += signed < 0 ? -signed : signed;
				if (score >= bestScore)
				{
					break;
				}
			}
			return score;
		}
		if (filter == 1)
		{
			for (int column = 0; column < rowByteCount; column++)
			{
				int left = column >= RgbComponentCount ? currentRow[column - RgbComponentCount] : 0;
				int filtered = (currentRow[column] - left) & 0xFF;
				int signed = filtered < 128 ? filtered : filtered - 256;
				score += signed < 0 ? -signed : signed;
				if (score >= bestScore)
				{
					break;
				}
			}
			return score;
		}
		if (filter == 2)
		{
			bool hasPreviousRow = !previousRow.IsEmpty;
			for (int column = 0; column < rowByteCount; column++)
			{
				int up = hasPreviousRow ? previousRow[column] : 0;
				int filtered = (currentRow[column] - up) & 0xFF;
				int signed = filtered < 128 ? filtered : filtered - 256;
				score += signed < 0 ? -signed : signed;
				if (score >= bestScore)
				{
					break;
				}
			}
			return score;
		}
		if (filter == 3)
		{
			bool hasPreviousRow = !previousRow.IsEmpty;
			for (int column = 0; column < rowByteCount; column++)
			{
				int left = column >= RgbComponentCount ? currentRow[column - RgbComponentCount] : 0;
				int up = hasPreviousRow ? previousRow[column] : 0;
				int filtered = (currentRow[column] - ((left + up) / 2)) & 0xFF;
				int signed = filtered < 128 ? filtered : filtered - 256;
				score += signed < 0 ? -signed : signed;
				if (score >= bestScore)
				{
					break;
				}
			}
			return score;
		}
		bool previousRowAvailable = !previousRow.IsEmpty;
		for (int column = 0; column < rowByteCount; column++)
		{
			int left = column >= RgbComponentCount ? currentRow[column - RgbComponentCount] : 0;
			int up = previousRowAvailable ? previousRow[column] : 0;
			int upperLeft = previousRowAvailable && column >= RgbComponentCount ? previousRow[column - RgbComponentCount] : 0;
			int initial = left + up - upperLeft;
			int leftDistance = Math.Abs(initial - left);
			int upDistance = Math.Abs(initial - up);
			int upperLeftDistance = Math.Abs(initial - upperLeft);
			int predictor = leftDistance <= upDistance && leftDistance <= upperLeftDistance ? left : upDistance <= upperLeftDistance ? up : upperLeft;
			int filtered = (currentRow[column] - predictor) & 0xFF;
			int signed = filtered < 128 ? filtered : filtered - 256;
			score += signed < 0 ? -signed : signed;
			if (score >= bestScore)
			{
				break;
			}
		}
		return score;
	}

	private static void WritePngFilteredRow(ReadOnlySpan<byte> currentRow, ReadOnlySpan<byte> previousRow, Span<byte> targetRow, byte filter)
	{
		if (filter == 0)
		{
			currentRow.CopyTo(targetRow);
			return;
		}
		if (filter == 1)
		{
			for (int column = 0; column < currentRow.Length; column++)
			{
				int left = column >= RgbComponentCount ? currentRow[column - RgbComponentCount] : 0;
				targetRow[column] = (byte)((currentRow[column] - left) & 0xFF);
			}
			return;
		}
		if (filter == 2)
		{
			bool hasPreviousRow = !previousRow.IsEmpty;
			for (int column = 0; column < currentRow.Length; column++)
			{
				int up = hasPreviousRow ? previousRow[column] : 0;
				targetRow[column] = (byte)((currentRow[column] - up) & 0xFF);
			}
			return;
		}
		if (filter == 3)
		{
			bool hasPreviousRow = !previousRow.IsEmpty;
			for (int column = 0; column < currentRow.Length; column++)
			{
				int left = column >= RgbComponentCount ? currentRow[column - RgbComponentCount] : 0;
				int up = hasPreviousRow ? previousRow[column] : 0;
				targetRow[column] = (byte)((currentRow[column] - ((left + up) / 2)) & 0xFF);
			}
			return;
		}
		bool previousRowAvailable = !previousRow.IsEmpty;
		for (int column = 0; column < currentRow.Length; column++)
		{
			int left = column >= RgbComponentCount ? currentRow[column - RgbComponentCount] : 0;
			int up = previousRowAvailable ? previousRow[column] : 0;
			int upperLeft = previousRowAvailable && column >= RgbComponentCount ? previousRow[column - RgbComponentCount] : 0;
			int initial = left + up - upperLeft;
			int leftDistance = Math.Abs(initial - left);
			int upDistance = Math.Abs(initial - up);
			int upperLeftDistance = Math.Abs(initial - upperLeft);
			int predictor = leftDistance <= upDistance && leftDistance <= upperLeftDistance ? left : upDistance <= upperLeftDistance ? up : upperLeft;
			targetRow[column] = (byte)((currentRow[column] - predictor) & 0xFF);
		}
	}

	private static void PopulatePremultipliedAlphaBackgroundTables(Color backgroundColor, Span<int> redBackgroundByAlpha, Span<int> greenBackgroundByAlpha, Span<int> blueBackgroundByAlpha)
	{
		for (int alpha = 0; alpha < 256; alpha++)
		{
			int inverseAlpha = 255 - alpha;
			redBackgroundByAlpha[alpha] = (backgroundColor.R * inverseAlpha + 127) / 255;
			greenBackgroundByAlpha[alpha] = (backgroundColor.G * inverseAlpha + 127) / 255;
			blueBackgroundByAlpha[alpha] = (backgroundColor.B * inverseAlpha + 127) / 255;
		}
	}

	private static int EstimatePdfLength(List<ReadOnlyMemory<byte>> compressedImages, int contentLength, int xmpLength, int iccProfileLength, int imageCount)
	{
		long estimatedLength = 8192L + contentLength + xmpLength + iccProfileLength + (imageCount * 768L);
		for (int index = 0; index < compressedImages.Count; index++)
		{
			estimatedLength += compressedImages[index].Length;
		}
		return estimatedLength > int.MaxValue ? int.MaxValue : (int)estimatedLength;
	}

	private static PdfMetadata CreateMetadata(string defaultFileName)
	{
		string title = Path.GetFileNameWithoutExtension(defaultFileName).Replace('_', ' ');
		DateTimeOffset now = DateTimeOffset.UtcNow;
		string subject = "AppControl Manager PDF/A-4 analysis page export";
		string keywords = title + ", AppControl Manager, analysis, PDF export, PDF/A-4";
		return new PdfMetadata(
			title: title,
			author: "AppControl Manager",
			subject: subject,
			keywords: keywords,
			creator: "AppControl Manager",
			producer: "AppControl Manager PDF 2.0 Exporter",
			pdfVersion: "2.0",
			pdfDate: now.ToUniversalTime().ToString("'D:'yyyyMMddHHmmss'+00''00'", CultureInfo.InvariantCulture),
			xmpDate: now.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture));
	}

	private static string BuildXmpMetadata(PdfMetadata metadata)
	{
		StringBuilder builder = new(2300);
		_ = builder.Append("<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n");
		_ = builder.Append("<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"AppControl Manager PDF 2.0 Exporter\">\n");
		_ = builder.Append("<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n");
		_ = builder.Append("<rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\" xmlns:pdfaid=\"http://www.aiim.org/pdfa/ns/id/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\">\n");
		_ = builder.Append("<dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">");
		_ = builder.Append(EscapeXml(metadata.Title));
		_ = builder.Append("</rdf:li></rdf:Alt></dc:title>\n");
		_ = builder.Append("<dc:creator><rdf:Seq><rdf:li>");
		_ = builder.Append(EscapeXml(metadata.Author));
		_ = builder.Append("</rdf:li></rdf:Seq></dc:creator>\n");
		_ = builder.Append("<dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\">");
		_ = builder.Append(EscapeXml(metadata.Subject));
		_ = builder.Append("</rdf:li></rdf:Alt></dc:description>\n");
		_ = builder.Append("<pdf:Keywords>");
		_ = builder.Append(EscapeXml(metadata.Keywords));
		_ = builder.Append("</pdf:Keywords>\n");
		_ = builder.Append("<pdf:Producer>");
		_ = builder.Append(EscapeXml(metadata.Producer));
		_ = builder.Append("</pdf:Producer>\n");
		_ = builder.Append("<pdf:PDFVersion>");
		_ = builder.Append(EscapeXml(metadata.PdfVersion));
		_ = builder.Append("</pdf:PDFVersion>\n");
		_ = builder.Append("<pdfaid:part>4</pdfaid:part>\n");
		_ = builder.Append("<pdfaid:rev>2020</pdfaid:rev>\n");
		_ = builder.Append("<xmp:CreatorTool>");
		_ = builder.Append(EscapeXml(metadata.Creator));
		_ = builder.Append("</xmp:CreatorTool>\n");
		_ = builder.Append("<xmp:CreateDate>");
		_ = builder.Append(metadata.XmpDate);
		_ = builder.Append("</xmp:CreateDate>\n");
		_ = builder.Append("<xmp:ModifyDate>");
		_ = builder.Append(metadata.XmpDate);
		_ = builder.Append("</xmp:ModifyDate>\n");
		_ = builder.Append("<xmp:MetadataDate>");
		_ = builder.Append(metadata.XmpDate);
		_ = builder.Append("</xmp:MetadataDate>\n");
		_ = builder.Append("</rdf:Description>\n</rdf:RDF>\n</x:xmpmeta>\n<?xpacket end=\"w\"?>\n");
		return builder.ToString();
	}

	private static string CreateDocumentId(PdfMetadata metadata, long xrefOffset, int objectCount)
	{
		byte[] sourceBytes = Encoding.UTF8.GetBytes(metadata.Title + "|" + metadata.Author + "|" + metadata.Subject + "|" + metadata.Keywords + "|" + metadata.PdfDate + "|" + xrefOffset.ToString(CultureInfo.InvariantCulture) + "|" + objectCount.ToString(CultureInfo.InvariantCulture));
		byte[] hashBytes = SHA256.HashData(sourceBytes);
		return Convert.ToHexString(hashBytes.AsSpan(0, 16));
	}

	private static string EscapeXml(string value) => value.Replace("&", "&amp;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal).Replace(">", "&gt;", StringComparison.Ordinal).Replace("\"", "&quot;", StringComparison.Ordinal).Replace("'", "&apos;", StringComparison.Ordinal);

	private static string FormatPdfNumber(double value) => value.ToString("0.###", CultureInfo.InvariantCulture);

	private static void WriteObject(Stream stream, List<long> objectOffsets, int objectNumber, string value)
	{
		objectOffsets.Add(stream.Position);
		WriteAscii(stream, objectNumber.ToString(CultureInfo.InvariantCulture) + " 0 obj\n");
		WriteAscii(stream, value);
		WriteAscii(stream, "endobj\n");
	}

	private static void WriteStreamObject(Stream stream, List<long> objectOffsets, int objectNumber, string dictionary, ReadOnlyMemory<byte> data)
	{
		objectOffsets.Add(stream.Position);
		WriteAscii(stream, objectNumber.ToString(CultureInfo.InvariantCulture) + " 0 obj\n");
		WriteAscii(stream, dictionary);
		WriteAscii(stream, "stream\n");
		stream.Write(data.Span);
		WriteAscii(stream, "\nendstream\nendobj\n");
	}

	private static byte[] Compress(ReadOnlyMemory<byte> data)
	{
		using MemoryStream compressedStream = new(data.Length);
		using (ZLibStream zLibStream = new(compressedStream, PdfCompressionLevel, leaveOpen: true))
		{
			zLibStream.Write(data.Span);
		}
		return compressedStream.ToArray();
	}

	private static void WriteAscii(Stream stream, string value)
	{
		byte[] bytes = Encoding.ASCII.GetBytes(value);
		stream.Write(bytes, 0, bytes.Length);
	}

	private readonly struct CapturedImage(int pixelWidth, int pixelHeight, double pixelsPerDip, byte[] rgbPixels)
	{
		internal int PixelWidth => pixelWidth;
		internal int PixelHeight => pixelHeight;
		internal double PixelsPerDip => pixelsPerDip;
		internal ReadOnlyMemory<byte> RgbPixels => rgbPixels;
		internal double WidthPoints => pixelWidth / pixelsPerDip * PointsPerDip;
		internal double HeightPoints => pixelHeight / pixelsPerDip * PointsPerDip;
	}

	private readonly struct PdfMetadata(string title, string author, string subject, string keywords, string creator, string producer, string pdfVersion, string pdfDate, string xmpDate)
	{
		internal string Title => title;
		internal string Author => author;
		internal string Subject => subject;
		internal string Keywords => keywords;
		internal string Creator => creator;
		internal string Producer => producer;
		internal string PdfVersion => pdfVersion;
		internal string PdfDate => pdfDate;
		internal string XmpDate => xmpDate;
	}
}
