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

	// The longest text that a single column weight can produce, which is the total weight itself.
	private const int MaximumWeightLength = 8;
	private static readonly JsonEncodedText CpuTemperatureFillProperty = JsonEncodedText.Encode("cpuTemperatureFill"),
	CpuTemperatureRemainderProperty = JsonEncodedText.Encode("cpuTemperatureRemainder"),
	CpuUsageFillProperty = JsonEncodedText.Encode("cpuUsageFill"),
	CpuUsageRemainderProperty = JsonEncodedText.Encode("cpuUsageRemainder"),
	MemoryFillProperty = JsonEncodedText.Encode("memoryFill"),
	MemoryRemainderProperty = JsonEncodedText.Encode("memoryRemainder"),
	StorageTemperatureFillProperty = JsonEncodedText.Encode("storageTemperatureFill"),
	StorageTemperatureRemainderProperty = JsonEncodedText.Encode("storageTemperatureRemainder");

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

	private static readonly Lazy<(string Fill, string Track)> BarImages = new(CreateBarImages);

	private static readonly uint[] Crc32Table = BuildCrc32Table();

	// The 8 byte signature that every PNG file starts with.
	// https://www.w3.org/TR/png-3/#5PNG-file-signature
	private static ReadOnlySpan<byte> PngSignature => [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

	/// <summary>
	/// The payload of every visible Performance widget is rebuilt on every tick of the sampling timer for as long as
	/// the Widgets Board shows it, and the provider process stays alive in the background the whole time, so the buffer
	/// and the writer that produce that payload are created once and then reused instead of being allocated over and
	/// over again. They are guarded by a lock of their own because the payloads can be built from the sampling timer
	/// and from a Widgets Board callback at the same time.
	/// </summary>
	private static readonly Lock _writerLock = new();
	private static readonly ArrayBufferWriter<byte> _buffer = new(2048);
	private static readonly Utf8JsonWriter _writer = new(_buffer);

	/// <summary>
	/// The Adaptive Card template, which is read from the JSON file (that ships with the app) only once per process because the file never changes
	/// while the app is running and because only the data payload differs between the updates.
	/// </summary>
	internal static readonly Lazy<string> Template = new(static () => File.ReadAllText(Path.Join(AppContext.BaseDirectory, "Resources", "Widgets", "PerformanceWidgetCard.json")));

	/// <summary>
	/// Produces the data payload that the Widgets Board merges into <see cref="Template"/>.
	/// </summary>
	/// <param name="snapshot">The metrics that the card displays.</param>
	/// <param name="size">The size that the widget is currently pinned at, which the layout adapts to.</param>
	internal static string BuildData(PerformanceSnapshot snapshot, WidgetSize size)
	{
		bool temperatureAvailable = double.IsFinite(snapshot.CpuTemperatureCelsius);
		bool cpuUsageAvailable = double.IsFinite(snapshot.CpuUsagePercent);
		bool memoryAvailable = snapshot.TotalPhysicalBytes > 0UL;
		bool storageTemperatureAvailable = double.IsFinite(snapshot.StorageTemperatureCelsius);

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
		string textSize, groupSpacing, barSpacing, barHeight;

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

		(string barFillImage, string barTrackImage) = BarImages.Value;

		lock (_writerLock)
		{
			// Everything that the previous payload left behind is dropped while both of the underlying buffers are kept.
			_buffer.ResetWrittenCount();
			_writer.Reset();

			_writer.WriteStartObject();

			_writer.WriteString("textSize", textSize);
			_writer.WriteString("groupSpacing", groupSpacing);
			_writer.WriteString("barSpacing", barSpacing);
			_writer.WriteString("barHeight", barHeight);

			_writer.WriteString("cpuTemperatureValue", temperatureText);
			WriteBarWeights(CpuTemperatureFillProperty, CpuTemperatureRemainderProperty, temperaturePercentage);

			_writer.WriteString("cpuUsageValue", cpuUsageText);
			WriteBarWeights(CpuUsageFillProperty, CpuUsageRemainderProperty, cpuUsagePercentage);

			_writer.WriteString("memoryValue", memoryText);
			WriteBarWeights(MemoryFillProperty, MemoryRemainderProperty, memoryPercentage);

			_writer.WriteBoolean("storageTemperatureVisible", storageTemperatureVisible);
			_writer.WriteString("storageTemperatureValue", storageTemperatureText);
			WriteBarWeights(StorageTemperatureFillProperty, StorageTemperatureRemainderProperty, storageTemperaturePercentage);

			_writer.WriteString("barFillImage", barFillImage);
			_writer.WriteString("barTrackImage", barTrackImage);

			_writer.WriteEndObject();
			_writer.Flush();

			return Encoding.UTF8.GetString(_buffer.WrittenSpan);
		}
	}

	/// <summary>
	/// Writes the two relative column weights that make up a single bar. It must only be called while
	/// <see cref="_writerLock"/> is held.
	/// </summary>
	private static void WriteBarWeights(JsonEncodedText fillPropertyName, JsonEncodedText remainderPropertyName, double percentage)
	{
		int fillWeight = Math.Clamp((int)Math.Round(percentage * (TotalBarWeight / 100.0)), MinimumBarWeight, MaximumBarWeight);

		// The weights are written through a stack buffer so that the numbers of a card that is rebuilt for as long as
		// the widget stays pinned never turn into garbage of their own.
		Span<char> destination = stackalloc char[MaximumWeightLength];

		_ = fillWeight.TryFormat(destination, out int length, default, CultureInfo.InvariantCulture);
		_writer.WriteString(fillPropertyName, destination[..length]);

		_ = (TotalBarWeight - fillWeight).TryFormat(destination, out length, default, CultureInfo.InvariantCulture);
		_writer.WriteString(remainderPropertyName, destination[..length]);
	}

	private static double BytesToGigabytes(ulong bytes) => bytes / 1073741824.0;

	/// <summary>
	/// Builds the two solid color images of the bars once per process, because they never change while the app is running.
	/// </summary>
	private static (string Fill, string Track) CreateBarImages()
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

		return (BuildSolidColorPngDataUri(accentRed, accentGreen, accentBlue, 0xFF), BuildSolidColorPngDataUri(TrackGray, TrackGray, TrackGray, TrackAlpha));
	}

	/// <summary>
	/// Creates a tiny solid color PNG image encoded as a Base64 data URI, which is the only way of getting an arbitrary
	/// color onto an Adaptive Card because the card can neither reference the assets of this package nor use raw colors.
	/// https://www.w3.org/TR/png-3/
	/// </summary>
	private static string BuildSolidColorPngDataUri(byte red, byte green, byte blue, byte alpha)
	{
		// Every scanline of the image is preceded by its filter type byte, which is zero here because no filtering is used.
		Span<byte> rawScanlines = stackalloc byte[BarImageHeight * (1 + (BarImageWidth * 4))];

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

		using MemoryStream compressedStream = new(rawScanlines.Length);

		using (ZLibStream compressor = new(compressedStream, CompressionLevel.Optimal, leaveOpen: true))
		{
			compressor.Write(rawScanlines);
		}

		ReadOnlySpan<byte> compressedScanlines = compressedStream.GetBuffer().AsSpan(0, checked((int)compressedStream.Length));

		// The image header chunk: width, height, bit depth, color type, compression method, filter method and interlace method.
		Span<byte> imageHeader = stackalloc byte[13];
		BinaryPrimitives.WriteUInt32BigEndian(imageHeader, BarImageWidth);
		BinaryPrimitives.WriteUInt32BigEndian(imageHeader[4..], BarImageHeight);
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

		return string.Concat("data:image/png;base64,", Convert.ToBase64String(pngStream.GetBuffer(), 0, checked((int)pngStream.Length)));
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
