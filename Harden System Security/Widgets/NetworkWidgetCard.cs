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
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using Microsoft.Windows.Widgets;

namespace HardenSystemSecurity.Widgets;

/// <summary>
/// Everything that a single carousel panel of the Network widget displays. A panel whose <see cref="Position"/> is zero
/// has no adapter to show at all, which is what makes the template drop it.
/// </summary>
internal readonly struct NetworkPanelData(
		string name,
		int position,
		int adapterCount,
		bool isConnected,
		NetworkAdapterSample sample)
{
	/// <summary>
	/// The connection name of the adapter that the panel currently shows.
	/// </summary>
	internal string Name => name;

	/// <summary>
	/// The one based position of that adapter inside of the carousel, or zero when the panel shows nothing.
	/// </summary>
	internal int Position => position;

	/// <summary>
	/// How many adapters the carousel of the panel can cycle through.
	/// </summary>
	internal int AdapterCount => adapterCount;

	/// <summary>
	/// Whether the adapter is operationally up.
	/// </summary>
	internal bool IsConnected => isConnected;

	/// <summary>
	/// The live throughput and the cumulative traffic of the adapter.
	/// </summary>
	internal NetworkAdapterSample Sample => sample;

	/// <summary>
	/// Whether the panel has an adapter to show.
	/// </summary>
	internal bool IsPresent => position > 0;
}

/// <summary>
/// Loads the Adaptive Card template of the Network widget and builds its matching data payload.
///
/// The template itself lives in the "Resources\Widgets\NetworkWidgetCard.json" file that ships with the app.
///
/// The Widgets Board draws the widget header (icon, display name and the "..." menu) by itself from the package manifest,
/// leaving a content area that is 268 epx wide on every size and 240 epx tall on a medium widget and 398 epx on a large
/// one. Anything taller than that is silently clipped, which is why the medium size holds a single adapter panel while
/// the large one stacks two of them, and why every size dependent value is supplied through the data payload. The small
/// size is not offered by the widget at all, because its 82 epx tall content area cannot hold the name of an adapter,
/// its two speeds and its two totals.
/// https://learn.microsoft.com/windows/apps/design/widgets/widgets-design-fundamentals
///
/// The carousel of each panel is driven by the provider rather than by the host, which is what keeps the promise that
/// only the adapters that are actually on screen are ever measured. The two arrow buttons are "Action.Execute" actions,
/// the only action type that calls the provider back through
/// <see cref="Microsoft.Windows.Widgets.Providers.IWidgetProvider.OnActionInvoked"/>, and they are identified there by
/// their verbs. A host driven element that carries every adapter of the machine would instead force the provider to
/// measure all of them on every single update.
/// https://learn.microsoft.com/windows/apps/develop/widgets/widgets-create-a-template
///
/// Each button lives in an "ActionSet" of its own inside an "auto" sized column of the header row, so a carousel that
/// has nothing to cycle through simply drops both of its columns and leaves the whole width to the adapter name.
/// https://adaptivecards.io/explorer/ActionSet.html
///
/// Widget manifest version: https://learn.microsoft.com/en-us/adaptive-cards/resources/partners
/// </summary>
internal static class NetworkWidgetCard
{
	/// <summary>
	/// The factor between two neighbouring units. Windows reports network traffic in decimal units, which is what makes
	/// the totals of the card read exactly like the byte counters of the status dialog of an adapter and like the
	/// amounts that the Settings app shows, instead of being about seven percent lower than either of them.
	/// </summary>
	private const double UnitFactor = 1000.0;

	/// <summary>
	/// The longest text that any single value of the card can produce, which is a scaled number with one decimal, a
	/// space and a unit for the speeds and the totals, and the position of the carousel with the disconnected note for
	/// the subtle line below the name of an adapter.
	/// </summary>
	private const int MaximumValueLength = 64;

	private static readonly JsonEncodedText NameSizeProperty = JsonEncodedText.Encode("nameSize"),
	 TextSizeProperty = JsonEncodedText.Encode("textSize"),
	 RowSpacingProperty = JsonEncodedText.Encode("rowSpacing"),
	 PanelSpacingProperty = JsonEncodedText.Encode("panelSpacing"),
	 HasAdaptersProperty = JsonEncodedText.Encode("hasAdapters"),
	 NoAdaptersProperty = JsonEncodedText.Encode("noAdapters"),
	 EmptyMessageProperty = JsonEncodedText.Encode("emptyMessage"),
	 FirstNameProperty = JsonEncodedText.Encode("firstName"),
	 FirstMetaProperty = JsonEncodedText.Encode("firstMeta"),
	 FirstNavigationVisibleProperty = JsonEncodedText.Encode("firstNavigationVisible"),
	 FirstUploadProperty = JsonEncodedText.Encode("firstUpload"),
	 FirstDownloadProperty = JsonEncodedText.Encode("firstDownload"),
	 FirstSentProperty = JsonEncodedText.Encode("firstSent"),
	 FirstReceivedProperty = JsonEncodedText.Encode("firstReceived"),
	 SecondPanelVisibleProperty = JsonEncodedText.Encode("secondPanelVisible"),
	 SecondNameProperty = JsonEncodedText.Encode("secondName"),
	 SecondMetaProperty = JsonEncodedText.Encode("secondMeta"),
	 SecondNavigationVisibleProperty = JsonEncodedText.Encode("secondNavigationVisible"),
	 SecondUploadProperty = JsonEncodedText.Encode("secondUpload"),
	 SecondDownloadProperty = JsonEncodedText.Encode("secondDownload"),
	 SecondSentProperty = JsonEncodedText.Encode("secondSent"),
	 SecondReceivedProperty = JsonEncodedText.Encode("secondReceived"),
	 DefaultValue = JsonEncodedText.Encode("default"),
	 MediumValue = JsonEncodedText.Encode("medium"),
	 LargeValue = JsonEncodedText.Encode("large"),
	 SmallValue = JsonEncodedText.Encode("small"),
	 NoneValue = JsonEncodedText.Encode("none"),
	 EmptyMessageValue = JsonEncodedText.Encode("No network adapter was found on this device.");

	/// <summary>
	/// The payload of every visible Network widget is rebuilt once per second for as long as the Widgets Board shows
	/// it, and the provider process stays alive in the background the whole time, so the buffer and the writer that
	/// produce that payload are created once and then reused instead of being allocated on every single tick. They are
	/// guarded by a lock of their own because the payloads can be built from the sampling timer and from a Widgets
	/// Board callback at the same time.
	/// </summary>
	private static readonly Lock _writerLock = new();
	private static readonly ArrayBufferWriter<byte> _buffer = new(1024);
	private static readonly Utf8JsonWriter _writer = new(_buffer);

	/// <summary>
	/// The Adaptive Card template, which is read from the JSON file (that ships with the app) only once per process because the file never changes
	/// while the app is running and because only the data payload differs between the updates.
	/// </summary>
	internal static readonly Lazy<string> Template = new(() => File.ReadAllText(Path.Join(AppContext.BaseDirectory, "Resources", "Widgets", "NetworkWidgetCard.json")));

	/// <summary>
	/// Produces the data payload that the Widgets Board merges into <see cref="Template"/>.
	/// </summary>
	/// <param name="first">The adapter of the upper panel, which every offered size shows.</param>
	/// <param name="second">The adapter of the lower panel, which only the large size has room for.</param>
	/// <param name="size">The size that the widget is currently pinned at, which the layout adapts to.</param>
	internal static string BuildData(in NetworkPanelData first, in NetworkPanelData second, WidgetSize size)
	{
		// Both offered sizes are equally wide and only differ in height, so the layout only has to tighten its vertical
		// rhythm and shrink its text once a second panel has to fit below the first one.
		bool isLarge = size is WidgetSize.Large;

		JsonEncodedText nameSize = isLarge ? DefaultValue : MediumValue;
		JsonEncodedText textSize = isLarge ? MediumValue : LargeValue;
		JsonEncodedText rowSpacing = isLarge ? SmallValue : MediumValue;
		JsonEncodedText panelSpacing = isLarge ? MediumValue : NoneValue;

		bool hasAdapters = first.IsPresent;
		bool secondPanelVisible = isLarge && second.IsPresent;

		lock (_writerLock)
		{
			// Everything that the previous payload left behind is dropped while both of the underlying buffers are kept.
			_buffer.ResetWrittenCount();
			_writer.Reset();

			_writer.WriteStartObject();

			_writer.WriteString(NameSizeProperty, nameSize);
			_writer.WriteString(TextSizeProperty, textSize);
			_writer.WriteString(RowSpacingProperty, rowSpacing);
			_writer.WriteString(PanelSpacingProperty, panelSpacing);

			_writer.WriteBoolean(HasAdaptersProperty, hasAdapters);
			_writer.WriteBoolean(NoAdaptersProperty, !hasAdapters);
			_writer.WriteString(EmptyMessageProperty, EmptyMessageValue);

			_writer.WriteString(FirstNameProperty, first.Name);
			WriteMeta(FirstMetaProperty, first);
			_writer.WriteBoolean(FirstNavigationVisibleProperty, first.AdapterCount > 1);
			WriteValue(FirstUploadProperty, first.Sample.SendBytesPerSecond, Atlas.RateUnits);
			WriteValue(FirstDownloadProperty, first.Sample.ReceiveBytesPerSecond, Atlas.RateUnits);
			WriteValue(FirstSentProperty, first.Sample.TotalSentBytes, Atlas.SizeUnits);
			WriteValue(FirstReceivedProperty, first.Sample.TotalReceivedBytes, Atlas.SizeUnits);

			_writer.WriteBoolean(SecondPanelVisibleProperty, secondPanelVisible);
			_writer.WriteString(SecondNameProperty, second.Name);
			WriteMeta(SecondMetaProperty, second);
			_writer.WriteBoolean(SecondNavigationVisibleProperty, second.AdapterCount > 1);
			WriteValue(SecondUploadProperty, second.Sample.SendBytesPerSecond, Atlas.RateUnits);
			WriteValue(SecondDownloadProperty, second.Sample.ReceiveBytesPerSecond, Atlas.RateUnits);
			WriteValue(SecondSentProperty, second.Sample.TotalSentBytes, Atlas.SizeUnits);
			WriteValue(SecondReceivedProperty, second.Sample.TotalReceivedBytes, Atlas.SizeUnits);

			_writer.WriteEndObject();
			_writer.Flush();

			return Encoding.UTF8.GetString(_buffer.WrittenSpan);
		}
	}

	/// <summary>
	/// Writes the subtle line below the name of an adapter, which tells the user where in the carousel they are and
	/// whether the adapter they are looking at is up at all. It must only be called while <see cref="_writerLock"/> is
	/// held.
	/// </summary>
	private static void WriteMeta(JsonEncodedText propertyName, in NetworkPanelData panel)
	{
		if (!panel.IsPresent)
		{
			_writer.WriteString(propertyName, ReadOnlySpan<char>.Empty);
			return;
		}

		Span<char> destination = stackalloc char[MaximumValueLength];
		int length = 0;

		_ = panel.Position.TryFormat(destination, out int written, default, CultureInfo.InvariantCulture);
		length += written;

		length += Append(destination[length..], " of ");

		_ = panel.AdapterCount.TryFormat(destination[length..], out written, default, CultureInfo.InvariantCulture);
		length += written;

		if (!panel.IsConnected)
		{
			length += Append(destination[length..], " \u2022 Disconnected");
		}

		_writer.WriteString(propertyName, destination[..length]);
	}

	/// <summary>
	/// Scales a byte count into the largest unit that keeps it above one, which is how Windows itself presents both the
	/// throughput and the traffic of an adapter, and writes it out. It must only be called while
	/// <see cref="_writerLock"/> is held.
	/// </summary>
	private static void WriteValue(JsonEncodedText propertyName, double value, string[] units)
	{
		double scaled = double.IsFinite(value) && value > 0.0 ? value : 0.0;
		int unitIndex = 0;

		while (scaled >= UnitFactor && unitIndex < units.Length - 1)
		{
			scaled /= UnitFactor;
			unitIndex++;
		}

		// Rounding must never be allowed to print a value at the very top of a unit as if it still belonged to that
		// unit, which is what would otherwise turn 999.9 bytes into "1000 B" and 999950 bytes into "1000.0 KB". The
		// threshold follows the number of decimals that the unit is printed with.
		if (unitIndex < units.Length - 1 && scaled >= (unitIndex is 0 ? UnitFactor - 0.5 : UnitFactor - 0.05))
		{
			scaled /= UnitFactor;
			unitIndex++;
		}

		Span<char> destination = stackalloc char[MaximumValueLength];

		_ = scaled.TryFormat(destination, out int length, unitIndex is 0 ? "0" : "0.0", CultureInfo.InvariantCulture);

		destination[length++] = ' ';
		length += Append(destination[length..], units[unitIndex]);

		_writer.WriteString(propertyName, destination[..length]);
	}

	/// <summary>
	/// Copies a piece of text into the buffer that a value is being built in and reports how much of it was consumed.
	/// </summary>
	private static int Append(Span<char> destination, ReadOnlySpan<char> text)
	{
		text.CopyTo(destination);
		return text.Length;
	}
}
