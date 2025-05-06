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

using System.Threading;
using Windows.Data.Xml.Dom;
using Windows.UI.Notifications;

namespace AppControlManager.Taskbar;

/// <summary>
/// Manages the badging system.
/// https://learn.microsoft.com/windows/apps/design/shell/tiles-and-notifications/badges
/// </summary>
internal static class Badge
{

	private const string badgeGlyphValue = "activity";

	private static readonly Lock SyncLock = new();

	internal static void SetBadgeAsActive()
	{
		lock (SyncLock)
		{
			// Get the blank badge XML payload for a badge glyph
			XmlDocument badgeXml = BadgeUpdateManager.GetTemplateContent(BadgeTemplateType.BadgeGlyph);

			// Set the value of the badge in the XML to our glyph value
			if (badgeXml.SelectSingleNode("/badge") is not XmlElement badgeElement) return;

			badgeElement.SetAttribute("value", badgeGlyphValue);

			// Create the badge notification
			BadgeNotification badge = new(badgeXml);

			// Create the badge updater for the application
			BadgeUpdater badgeUpdater = BadgeUpdateManager.CreateBadgeUpdaterForApplication();

			// And update the badge
			badgeUpdater.Update(badge);
		}
	}

	/// <summary>
	/// Clears any badge on the taskbar icon.
	/// </summary>
	internal static void ClearBadge()
	{
		lock (SyncLock)
		{
			BadgeUpdateManager.CreateBadgeUpdaterForApplication().Clear();
		}
	}
}
