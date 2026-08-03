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

using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Threading;
using Microsoft.Windows.Widgets;
using Windows.UI;
using Windows.UI.ViewManagement;

namespace HardenSystemSecurity.Widgets;

/// <summary>
/// Loads the Adaptive Card template of the Performance widget and builds its matching data payload.
///
/// The template itself lives in the "Resources\Widgets\PerformanceWidgetCard.json" file that ships with the app.
///
/// The Widgets Board draws the widget header (icon, display name and the "..." menu) by itself from the package manifest,
/// leaving a content area that is 268 epx wide and only 82 epx tall on a small widget, 240 epx on a medium one and
/// 398 epx on a large one. Anything taller than that is silently clipped, so the layout is kept tight and every
/// size dependent value (text size, bar height and the spacings) is supplied through the data payload.
/// https://learn.microsoft.com/windows/apps/design/widgets/widgets-design-fundamentals
///
/// The Adaptive Cards schema has no progress bar element and it does not allow arbitrary colors on any element either,
/// therefore each bar is a two column "ColumnSet" where the column widths are relative weights that encode the percentage,
/// and the exact colors come from tiny solid color PNG images that are used as the background image of those columns.
/// Relative weights are used instead of pixel widths because the widget content width differs per host.
/// PNG is used because it is one of the image formats that the Adaptive Cards background image explicitly supports,
/// unlike SVG which the WinUI renderer of the Widgets Board fails to scale correctly.
/// https://adaptivecards.io/explorer/BackgroundImage.html
///
/// Each metric is a "Container" that holds the label with its value and the bar below them, and every one of those
/// containers stretches, which spreads the metrics evenly over the whole height of the widget no matter which
/// size it is pinned at. The fourth metric, which is the disk temperature, carries a "$when" that drops its entire
/// container on the small size where there is no room left for it.
/// https://learn.microsoft.com/adaptive-cards/templating/language
///
/// Widget manifest version: https://learn.microsoft.com/en-us/adaptive-cards/resources/partners
/// </summary>
internal static class PerformanceWidgetCard
{
	// Temperatures are mapped onto this range when the bar length is calculated.
	private const double MaximumDisplayedTemperatureCelsius = 100.0;

	// The bars are built from two relative column weights that always add up to this value.
	private const int TotalBarWeight = 1000;

	// The bars would degenerate if a weight of exactly zero was used, so the weights are always kept inside of this range.
	private const int MinimumBarWeight = 1;
	private const int MaximumBarWeight = TotalBarWeight - MinimumBarWeight;

	// The default Windows accent color, only used if the real accent color cannot be read from the system.
	// https://learn.microsoft.com/windows/apps/design/style/color
	private const byte FallbackAccentRed = 0x00;
	private const byte FallbackAccentGreen = 0x78;
	private const byte FallbackAccentBlue = 0xD4;

	// The unfilled part of every bar. A translucent mid gray stays visible on both the light and the dark Widgets Board.
	private const byte TrackGray = 0x80;
	private const byte TrackAlpha = 0x66;

	// The bar images are solid colors that get stretched over the whole bar, so a tiny image is enough.
	private const int BarImageWidth = 8;
	private const int BarImageHeight = 8;

	private static string? _barFillImage;
	private static string? _barTrackImage;
	private static readonly Lock _imagesLock = new();

	private static readonly uint[] Crc32Table = BuildCrc32Table();

	// The 8 byte signature that every PNG file starts with.
	// https://www.w3.org/TR/png-3/#5PNG-file-signature
	private static ReadOnlySpan<byte> PngSignature => [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

	/// <summary>
	/// The full path of the Adaptive Card template file that ships next to the app.
	/// </summary>
	private static readonly string TemplateFilePath = Path.Join(AppContext.BaseDirectory, "Resources", "Widgets", "PerformanceWidgetCard.json");
	private static readonly Lock _templateLock = new();

	/// <summary>
	/// The Adaptive Card template, which is read from the JSON file only once per process because the file never changes
	/// while the app is running and because only the data payload differs between the updates.
	/// It is an empty string when the file cannot be read, in which case no update is sent to the Widgets Board at all.
	/// </summary>
	internal static string Template
	{
		get
		{
			lock (_templateLock)
			{
				string? cachedTemplate = field;

				if (cachedTemplate is null)
				{
					try
					{
						cachedTemplate = File.ReadAllText(TemplateFilePath);
					}
					catch (Exception ex)
					{
						Logger.Write(ex);
						cachedTemplate = string.Empty;
					}

					field = cachedTemplate;
				}

				return cachedTemplate;
			}
		}
	}

	/// <summary>
	/// Produces the data payload that the Widgets Board merges into <see cref="Template"/>.
	/// </summary>
	/// <param name="snapshot">The metrics that the card displays.</param>
	/// <param name="size">The size that the widget is currently pinned at, which the layout adapts to.</param>
	internal static string BuildData(PerformanceSnapshot snapshot, WidgetSize size)
	{
		bool temperatureAvailable = !double.IsNaN(snapshot.CpuTemperatureCelsius) && !double.IsInfinity(snapshot.CpuTemperatureCelsius);
		bool cpuUsageAvailable = !double.IsNaN(snapshot.CpuUsagePercent) && !double.IsInfinity(snapshot.CpuUsagePercent);
		bool memoryAvailable = snapshot.TotalPhysicalBytes > 0UL;
		bool storageTemperatureAvailable = !double.IsNaN(snapshot.StorageTemperatureCelsius) && !double.IsInfinity(snapshot.StorageTemperatureCelsius);

		// The content area of a small widget is only 82 epx tall, which fits 3 metrics at most, so the disk temperature
		// is the only metric that is dropped there, and the "$when" of its container in the template does exactly that.
		bool storageTemperatureVisible = size is not WidgetSize.Small;

		double temperaturePercentage = temperatureAvailable
			? Math.Clamp(snapshot.CpuTemperatureCelsius / MaximumDisplayedTemperatureCelsius * 100.0, 0.0, 100.0)
			: 0.0;

		double cpuUsagePercentage = cpuUsageAvailable ? Math.Clamp(snapshot.CpuUsagePercent, 0.0, 100.0) : 0.0;

		double memoryPercentage = memoryAvailable
			? Math.Clamp((double)snapshot.UsedPhysicalBytes / snapshot.TotalPhysicalBytes * 100.0, 0.0, 100.0)
			: 0.0;

		double storageTemperaturePercentage = storageTemperatureAvailable
			? Math.Clamp(snapshot.StorageTemperatureCelsius / MaximumDisplayedTemperatureCelsius * 100.0, 0.0, 100.0)
			: 0.0;

		string temperatureText = temperatureAvailable
			? string.Concat(snapshot.CpuTemperatureCelsius.ToString("F0", CultureInfo.InvariantCulture), " °C")
			: "N/A";

		string cpuUsageText = cpuUsageAvailable
			? string.Concat(cpuUsagePercentage.ToString("F0", CultureInfo.InvariantCulture), " %")
			: "N/A";

		string memoryText = memoryAvailable
			? string.Create(
				CultureInfo.InvariantCulture,
				$"{BytesToGigabytes(snapshot.UsedPhysicalBytes):F1} / {BytesToGigabytes(snapshot.TotalPhysicalBytes):F1} GB")
			: "N/A";

		string storageTemperatureText = storageTemperatureAvailable
			? string.Concat(snapshot.StorageTemperatureCelsius.ToString("F0", CultureInfo.InvariantCulture), " °C")
			: "N/A";

		// The metrics have to fit into the content area of the pinned size without being clipped, which is why the
		// smaller the widget is, the smaller its text and the tighter its spacings get.
		string textSize;
		string groupSpacing;
		string barSpacing;
		string barHeight;

		switch (size)
		{
			case WidgetSize.Small:
				{
					textSize = "small";
					groupSpacing = "small";
					barSpacing = "none";
					barHeight = "4px";
					break;
				}
			case WidgetSize.Large:
				{
					textSize = "large";
					groupSpacing = "medium";
					barSpacing = "small";
					barHeight = "8px";
					break;
				}
			case WidgetSize.Medium:
			default:
				{
					textSize = "medium";
					groupSpacing = "small";
					barSpacing = "small";
					barHeight = "6px";
					break;
				}
		}

		GetBarImages(out string barFillImage, out string barTrackImage);

		ArrayBufferWriter<byte> buffer = new(2048);

		using (Utf8JsonWriter writer = new(buffer))
		{
			writer.WriteStartObject();

			writer.WriteString("textSize", textSize);
			writer.WriteString("groupSpacing", groupSpacing);
			writer.WriteString("barSpacing", barSpacing);
			writer.WriteString("barHeight", barHeight);

			writer.WriteString("cpuTemperatureValue", temperatureText);
			WriteBarWeights(writer, "cpuTemperatureFill", "cpuTemperatureRemainder", temperaturePercentage);

			writer.WriteString("cpuUsageValue", cpuUsageText);
			WriteBarWeights(writer, "cpuUsageFill", "cpuUsageRemainder", cpuUsagePercentage);

			writer.WriteString("memoryValue", memoryText);
			WriteBarWeights(writer, "memoryFill", "memoryRemainder", memoryPercentage);

			writer.WriteBoolean("storageTemperatureVisible", storageTemperatureVisible);
			writer.WriteString("storageTemperatureValue", storageTemperatureText);
			WriteBarWeights(writer, "storageTemperatureFill", "storageTemperatureRemainder", storageTemperaturePercentage);

			writer.WriteString("barFillImage", barFillImage);
			writer.WriteString("barTrackImage", barTrackImage);

			writer.WriteEndObject();
		}

		return Encoding.UTF8.GetString(buffer.WrittenSpan);
	}

	/// <summary>
	/// Writes the two relative column weights that make up a single bar.
	/// </summary>
	private static void WriteBarWeights(Utf8JsonWriter writer, string fillPropertyName, string remainderPropertyName, double percentage)
	{
		int fillWeight = Math.Clamp((int)Math.Round(percentage * (TotalBarWeight / 100.0)), MinimumBarWeight, MaximumBarWeight);

		writer.WriteString(fillPropertyName, fillWeight.ToString(CultureInfo.InvariantCulture));
		writer.WriteString(remainderPropertyName, (TotalBarWeight - fillWeight).ToString(CultureInfo.InvariantCulture));
	}

	private static double BytesToGigabytes(ulong bytes) => bytes / 1073741824.0;

	/// <summary>
	/// Builds the two solid color images of the bars once per process, because they never change while the app is running.
	/// </summary>
	private static void GetBarImages(out string barFillImage, out string barTrackImage)
	{
		lock (_imagesLock)
		{
			string? cachedBarFillImage = _barFillImage;
			string? cachedBarTrackImage = _barTrackImage;

			if (cachedBarFillImage is null || cachedBarTrackImage is null)
			{
				byte accentRed = FallbackAccentRed;
				byte accentGreen = FallbackAccentGreen;
				byte accentBlue = FallbackAccentBlue;

				try
				{
					UISettings uiSettings = new();

					// The base accent color is the same shade that Windows itself uses on both the light and the dark theme.
					Color accentColor = uiSettings.GetColorValue(UIColorType.Accent);

					accentRed = accentColor.R;
					accentGreen = accentColor.G;
					accentBlue = accentColor.B;
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
				}

				cachedBarFillImage = BuildSolidColorPngDataUri(accentRed, accentGreen, accentBlue, 0xFF);
				cachedBarTrackImage = BuildSolidColorPngDataUri(TrackGray, TrackGray, TrackGray, TrackAlpha);

				_barFillImage = cachedBarFillImage;
				_barTrackImage = cachedBarTrackImage;
			}

			barFillImage = cachedBarFillImage;
			barTrackImage = cachedBarTrackImage;
		}
	}

	/// <summary>
	/// Creates a tiny solid color PNG image encoded as a Base64 data URI, which is the only way of getting an arbitrary
	/// color onto an Adaptive Card because the card can neither reference the assets of this package nor use raw colors.
	/// https://www.w3.org/TR/png-3/
	/// </summary>
	private static string BuildSolidColorPngDataUri(byte red, byte green, byte blue, byte alpha)
	{
		// Every scanline of the image is preceded by its filter type byte, which is zero here because no filtering is used.
		byte[] rawScanlines = new byte[BarImageHeight * (1 + (BarImageWidth * 4))];

		int rawOffset = 0;

		for (int row = 0; row < BarImageHeight; row++)
		{
			rawScanlines[rawOffset++] = 0;

			for (int column = 0; column < BarImageWidth; column++)
			{
				rawScanlines[rawOffset++] = red;
				rawScanlines[rawOffset++] = green;
				rawScanlines[rawOffset++] = blue;
				rawScanlines[rawOffset++] = alpha;
			}
		}

		byte[] compressedScanlines;

		using (MemoryStream compressedStream = new(rawScanlines.Length))
		{
			using (ZLibStream compressor = new(compressedStream, CompressionLevel.Optimal, true))
			{
				compressor.Write(rawScanlines, 0, rawScanlines.Length);
			}

			compressedScanlines = compressedStream.ToArray();
		}

		// The image header chunk: width, height, bit depth, color type, compression method, filter method and interlace method.
		byte[] imageHeader = new byte[13];
		BinaryPrimitives.WriteUInt32BigEndian(imageHeader.AsSpan(0), BarImageWidth);
		BinaryPrimitives.WriteUInt32BigEndian(imageHeader.AsSpan(4), BarImageHeight);
		imageHeader[8] = 8;
		imageHeader[9] = 6;
		imageHeader[10] = 0;
		imageHeader[11] = 0;
		imageHeader[12] = 0;

		// Signature, then the three chunks, each of which is a 4 byte length, a 4 byte type, the data and a 4 byte CRC.
		int totalLength = PngSignature.Length + (12 * 3) + imageHeader.Length + compressedScanlines.Length;

		using MemoryStream pngStream = new(totalLength);

		pngStream.Write(PngSignature);
		WriteChunk(pngStream, "IHDR"u8, imageHeader);
		WriteChunk(pngStream, "IDAT"u8, compressedScanlines);
		WriteChunk(pngStream, "IEND"u8, []);

		return string.Concat("data:image/png;base64,", Convert.ToBase64String(pngStream.ToArray()));
	}

	/// <summary>
	/// Writes a single PNG chunk, which is a big endian length, the chunk type, the chunk data and the CRC of both.
	/// </summary>
	private static void WriteChunk(Stream stream, ReadOnlySpan<byte> chunkType, ReadOnlySpan<byte> chunkData)
	{
		Span<byte> lengthBuffer = stackalloc byte[4];
		BinaryPrimitives.WriteUInt32BigEndian(lengthBuffer, (uint)chunkData.Length);
		stream.Write(lengthBuffer);

		stream.Write(chunkType);
		stream.Write(chunkData);

		uint crc = UpdateCrc32(UpdateCrc32(0xFFFFFFFFU, chunkType), chunkData) ^ 0xFFFFFFFFU;

		Span<byte> crcBuffer = stackalloc byte[4];
		BinaryPrimitives.WriteUInt32BigEndian(crcBuffer, crc);
		stream.Write(crcBuffer);
	}

	/// <summary>
	/// The CRC-32 that PNG uses for its chunks.
	/// https://www.w3.org/TR/png-3/#5CRC-algorithm
	/// </summary>
	private static uint UpdateCrc32(uint crc, ReadOnlySpan<byte> data)
	{
		uint currentCrc = crc;

		for (int index = 0; index < data.Length; index++)
		{
			currentCrc = Crc32Table[(currentCrc ^ data[index]) & 0xFFU] ^ (currentCrc >> 8);
		}

		return currentCrc;
	}

	private static uint[] BuildCrc32Table()
	{
		uint[] table = new uint[256];

		for (uint index = 0; index < 256U; index++)
		{
			uint value = index;

			for (int bit = 0; bit < 8; bit++)
			{
				value = (value & 1U) != 0U ? 0xEDB88320U ^ (value >> 1) : value >> 1;
			}

			table[index] = value;
		}

		return table;
	}
}
