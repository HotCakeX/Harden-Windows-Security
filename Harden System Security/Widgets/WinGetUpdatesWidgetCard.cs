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
using HardenSystemSecurity.WinGet;
using Microsoft.Windows.Widgets;

namespace HardenSystemSecurity.Widgets;

/// <summary>
/// Loads the Adaptive Card template of the App Updates widget and builds its matching data payload.
///
/// The template itself lives in the "Resources\Widgets\WinGetUpdatesWidgetCard.json" file that ships with the app.
///
/// The Widgets Board draws the widget header (icon, display name and the "..." menu) by itself from the package manifest,
/// leaving a content area that is 268 epx wide and 240 epx tall on a medium widget and 398 epx on a large one, out of
/// which the two buttons at the bottom claim roughly 40 epx. Anything taller than that is silently clipped, which is why
/// the number of package rows and every size dependent value is supplied through the data payload. The small size is not
/// offered by the widget at all, because neither the headline row nor a single table row would fit next to the buttons
/// in the 82 epx that its content area is tall.
/// https://learn.microsoft.com/windows/apps/design/widgets/widgets-design-fundamentals
///
/// The package rows are produced by a single "TableRow" that carries a "$data" binding, so the template describes one
/// row and the Adaptive Cards templating engine repeats it once per entry of the payload array, right below the static
/// header row of the table. Inside of a "$data" scope the bindings resolve against the array entry rather than against
/// the root of the payload, which is why every entry also carries its own size dependent text size.
/// https://learn.microsoft.com/adaptive-cards/templating/language
///
/// The "Table" element exists since version 1.5 of the Adaptive Cards schema and its grid lines are turned off so that
/// the rows only get the "cellSpacing" of the host between them, which keeps the three columns as compact as the narrow
/// content area of a widget requires.
/// https://adaptivecards.io/explorer/Table.html
///
/// The two buttons are "Action.Execute" actions, which is the only action type that calls the provider back through
/// <see cref="Microsoft.Windows.Widgets.Providers.IWidgetProvider.OnActionInvoked"/>, and they are identified there by
/// their verbs.
/// https://learn.microsoft.com/windows/apps/develop/widgets/widget-providers
///
/// Every button lives in an "ActionSet" of its own inside a "ColumnSet" at the end of the body instead of in the card
/// level "actions" collection, because the alignment of the action bar of a card belongs to the host configuration of
/// the Widgets Board, which a widget cannot override, while an "ActionSet" is an ordinary body element that can be
/// placed anywhere. The column of the first button stretches and the column of the second one is only as wide as that
/// button needs to be, so the row always consumes exactly the width of the content area. Both buttons of a single
/// "ActionSet" placed in one "auto" sized column would instead be measured at their natural width, which overflows the
/// 268 epx of a medium widget and makes the Widgets Board cut the trailing button off at the edge of the card.
/// https://adaptivecards.io/explorer/ActionSet.html
/// </summary>
internal static class WinGetUpdatesWidgetCard
{
	/// <summary>
	/// What a version column of a package row shows when WinGet did not report that version at all, because an empty
	/// cell would make the row look like it lost its alignment.
	/// </summary>
	private const string UnknownVersion = "-";

	/// <summary>
	/// The Adaptive Card template, which is read from the JSON file (that ships with the app) only once per process because the file never changes
	/// while the app is running and because only the data payload differs between the updates.
	/// </summary>
	internal static readonly Lazy<string> Template = new(() => File.ReadAllText(Path.Join(AppContext.BaseDirectory, "Resources", "Widgets", "WinGetUpdatesWidgetCard.json")));

	/// <summary>
	/// The image of the card, encoded as a "data:" URI, which is read from the PNG file of the app package only once per process.
	///
	/// The Widgets Board renders the card in its own process and therefore cannot resolve an "ms-appx:///" URI of this
	/// package, while the Adaptive Cards schema does support a "data:" URI on an image since version 1.2, so the bytes
	/// of the image travel to the host inside of the data payload.
	/// https://adaptivecards.io/explorer/Image.html
	/// </summary>
	internal static readonly Lazy<string> Icon = new(static () => string.Concat("data:image/png;base64,", Convert.ToBase64String(File.ReadAllBytes(Path.Join(AppContext.BaseDirectory, "Assets", "Others", "WinGetWidgetIcon.png")))));

	/// <summary>
	/// Produces the data payload that the Widgets Board merges into <see cref="Template"/>.
	/// </summary>
	/// <param name="snapshot">The result of the latest update check that the card displays.</param>
	/// <param name="size">The size that the widget is currently pinned at, which the layout adapts to.</param>
	internal static string BuildData(WinGetUpdatesSnapshot snapshot, WidgetSize size)
	{
		// The large widget has room for both a bigger headline and considerably more package rows than the medium one.
		bool isLarge = size is WidgetSize.Large;
		int maximumRows = isLarge ? 8 : 3;
		string rowTextSize = isLarge ? "default" : "small";
		string headlineSize = isLarge ? "large" : "medium";

		// The image only takes the room that it needs to stay proportional to the headline next to it, and its width is
		// a multiple of four so that it stays pixel perfect on every scaling factor of the Widgets Board.
		// https://learn.microsoft.com/windows/apps/design/widgets/widgets-design-fundamentals
		string icon = Icon.Value;
		bool hasIcon = icon.Length > 0;
		string iconWidth = isLarge ? "40px" : "32px";

		int updateCount = snapshot.Updates.Count;
		bool completed = snapshot.State is WinGetUpdatesState.Completed;

		// The count is only a meaningful number once an update check actually produced a result.
		string count = completed ? updateCount.ToString(CultureInfo.InvariantCulture) : string.Empty;
		string countColor = updateCount > 0 ? "accent" : "good";

		string headline;
		string subtitle;

		switch (snapshot.State)
		{
			case WinGetUpdatesState.Checking:
				{
					headline = "Checking for updates";
					subtitle = "Asking WinGet about every installed app.";
					break;
				}
			case WinGetUpdatesState.Completed:
				{
					headline = updateCount switch
					{
						0 => "Everything is up to date",
						1 => "Update Available",
						_ => "Updates Available"
					};

					subtitle = string.Create(CultureInfo.CurrentCulture, $"Last Checked At {snapshot.CompletedAt:t}");
					break;
				}
			case WinGetUpdatesState.Failed:
				{
					headline = "Update check failed";
					subtitle = string.Empty;
					break;
				}
			case WinGetUpdatesState.Idle:
			default:
				{
					headline = "App updates";
					subtitle = "See which of your installed apps have a newer version.";
					break;
				}
		}

		bool hasPackages = completed && updateCount > 0;
		int displayedRows = hasPackages ? Math.Min(updateCount, maximumRows) : 0;
		int hiddenRows = updateCount - displayedRows;
		bool hasMore = hasPackages && hiddenRows > 0;

		bool hasMessage = snapshot.State is WinGetUpdatesState.Failed;

		// The encoded image is by far the largest part of the payload, so the buffer starts out big enough to hold it.
		ArrayBufferWriter<byte> buffer = new(2048 + icon.Length);

		using (Utf8JsonWriter writer = new(buffer))
		{
			writer.WriteStartObject();

			writer.WriteBoolean("hasIcon", hasIcon);
			writer.WriteString("icon", icon);
			writer.WriteString("iconWidth", iconWidth);

			writer.WriteBoolean("countVisible", completed);
			writer.WriteString("count", count);
			writer.WriteString("countColor", countColor);

			// The count only moves away from the image when both of them are actually rendered, otherwise the collapsed
			// count column would keep a gap that has nothing in front of it.
			writer.WriteString("countSpacing", hasIcon && completed ? "small" : "none");

			// The headline follows whichever element ends up in front of it, and it starts at the very left edge of the
			// card when neither the image nor the count is rendered.
			writer.WriteString("headlineSpacing", completed ? "medium" : hasIcon ? "small" : "none");
			writer.WriteString("headlineSize", headlineSize);
			writer.WriteString("headline", headline);
			writer.WriteBoolean("hasSubtitle", subtitle.Length > 0);
			writer.WriteString("subtitle", subtitle);

			writer.WriteBoolean("hasPackages", hasPackages);

			// The header row of the table lives outside of the "$data" scope of the package rows, so it needs the size
			// dependent text size at the root of the payload as well.
			writer.WriteString("textSize", rowTextSize);

			writer.WriteStartArray("packages");

			if (hasPackages)
			{
				for (int index = 0; index < displayedRows; index++)
				{
					WinGetAvailableUpdate update = snapshot.Updates[index];

					writer.WriteStartObject();
					writer.WriteString("name", update.Name);
					writer.WriteString("installedVersion", update.InstalledVersion.Length > 0 ? update.InstalledVersion : UnknownVersion);
					writer.WriteString("availableVersion", update.AvailableVersion.Length > 0 ? update.AvailableVersion : UnknownVersion);

					// Bindings inside of a "$data" scope resolve against the entry, so the size dependent values have
					// to travel with every single entry.
					writer.WriteString("textSize", rowTextSize);
					writer.WriteEndObject();
				}
			}

			writer.WriteEndArray();

			writer.WriteBoolean("hasMore", hasMore);
			writer.WriteString("moreText", hasMore ? string.Concat("and ", hiddenRows.ToString(CultureInfo.InvariantCulture), " more") : string.Empty);

			writer.WriteBoolean("hasMessage", hasMessage);
			writer.WriteString("message", hasMessage ? snapshot.ErrorMessage : string.Empty);

			// The button of a running update check tells the user that their press was received, since the Adaptive
			// Cards schema offers no progress indicator of any kind.
			writer.WriteString("checkButtonTitle", snapshot.State is WinGetUpdatesState.Checking ? "Checking..." : "Check for updates");

			writer.WriteEndObject();
		}

		return Encoding.UTF8.GetString(buffer.WrittenSpan);
	}
}
