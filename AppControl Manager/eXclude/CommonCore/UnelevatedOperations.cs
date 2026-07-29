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
using System.Text;
using System.Threading.Tasks;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;
using Microsoft.Windows.BadgeNotifications;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Core;
using Windows.UI.Shell;
using Windows.UI.StartScreen;

namespace CommonCore;

/// <summary>
/// This class offers functionalities that cannot normally be performed under any of these conditions:
/// 1. When the process is elevated.
/// 2. When the app is installed for a Standard user account and user elevates via an Admin user's credentials. (This means the functionalities would normally be available for elevated processes, but not when in-place elevation happens between 2 user accounts.)
/// 3. When Administrator Protection is enabled on the system.
/// The non-Startup_ methods launch the App Alias executable unelevated and are used by the main app.
/// The Startup_ methods execute inside the relaunched unelevated process.
/// The Startup_ methods cannot use Logger.Write at the moment.
/// </summary>
internal static class UnelevatedOperations
{
	private const char ToastFieldSeparator = '\u001F';

#if HARDEN_SYSTEM_SECURITY
	internal const string AppAliasExecutableName = "HSS.exe";
#else
	internal const string AppAliasExecutableName = "AppControl.exe";
#endif

	internal static class ToastNotifications
	{
		/// <summary>
		/// Displays a toast notification.
		/// The argument texts are packed into a single Base64 token so spaces, quotes, Unicode and empty values
		/// all survive the command line without any splitting or quoting issues.
		/// </summary>
		/// <param name="title">First line (title) of the notification.</param>
		/// <param name="body">Second line (body) of the notification.</param>
		/// <param name="attributionText">Attribution text shown at the bottom of the notification.</param>
		/// <param name="group">Group identifier for the notification (SetGroup).</param>
		/// <param name="soundEvent">System sound played for the notification.</param>
		/// <param name="inlineImage">Optional URI of the inline image displayed at the top of the notification.</param>
		/// <param name="arguments">Optional key/value activation argument pairs (AddArgument), in order.</param>
		internal static void ShowToastNotification(
			string title,
			string body,
			string attributionText,
			string group,
			AppNotificationSoundEvent soundEvent,
			Uri? inlineImage = null,
			params (string Key, string Value)[] arguments)
		{
			try
			{
				if (!Atlas.Settings.ToastNotificationsAreEnabled) return;

				string soundEventValue = ((int)soundEvent).ToString(System.Globalization.CultureInfo.InvariantCulture);
				string inlineImageValue = inlineImage?.OriginalString ?? string.Empty;
				// Layout: title - body - attribution - group - sound event - inline image - [ key - value ] ...
				// Compute the exact final length in a single pass so string.Create allocates only once.
				int length = title.Length + body.Length + attributionText.Length + group.Length + soundEventValue.Length + inlineImageValue.Length + 5;
				for (int i = 0; i < arguments.Length; i++)
				{
					length += 2 + arguments[i].Key.Length + arguments[i].Value.Length;
				}

				// The buffer is written directly with no intermediate growth.
				string payload = string.Create(
					length,
					(title, body, attributionText, group, soundEventValue, inlineImageValue, arguments),
					static (chars, state) =>
					{
						int pos = 0;

						state.title.CopyTo(chars);
						pos += state.title.Length;
						chars[pos++] = ToastFieldSeparator;

						state.body.CopyTo(chars[pos..]);
						pos += state.body.Length;
						chars[pos++] = ToastFieldSeparator;

						state.attributionText.CopyTo(chars[pos..]);
						pos += state.attributionText.Length;
						chars[pos++] = ToastFieldSeparator;

						state.group.CopyTo(chars[pos..]);
						pos += state.group.Length;
						chars[pos++] = ToastFieldSeparator;

						state.soundEventValue.CopyTo(chars[pos..]);
						pos += state.soundEventValue.Length;
						chars[pos++] = ToastFieldSeparator;

						state.inlineImageValue.CopyTo(chars[pos..]);
						pos += state.inlineImageValue.Length;

						for (int i = 0; i < state.arguments.Length; i++)
						{
							chars[pos++] = ToastFieldSeparator;
							state.arguments[i].Key.CopyTo(chars[pos..]);
							pos += state.arguments[i].Key.Length;
							chars[pos++] = ToastFieldSeparator;
							state.arguments[i].Value.CopyTo(chars[pos..]);
							pos += state.arguments[i].Value.Length;
						}
					});

				string encodedPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));
				string launchArguments = string.Concat("STARTUPREDIRECT TOAST", " ", encodedPayload);
				_ = NativeMethods.launch_unelevated(AppAliasExecutableName, launchArguments, null);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		}

		/// <summary>
		/// Relaunches the App Alias executable unelevated to remove all app notifications from Notification Center.
		/// </summary>
		internal static void ClearAllToastNotifications() => _ = NativeMethods.launch_unelevated(AppAliasExecutableName, "STARTUPREDIRECT TOASTCLEARALL", null);

		/// <summary>
		/// Removes all app notifications from Notification Center.
		/// </summary>
		internal static async Task Startup_ClearAllToastNotifications() => await AppNotificationManager.Default.RemoveAllAsync();

		/// <summary>
		/// Decodes the Base64 payload into its text fields, group and key/value argument pairs,
		/// then displays the app notification.
		/// </summary>
		/// <param name="encodedPayload">
		/// Base64-encoded UTF-8 payload containing U+001F-separated fields in this order:
		/// title, body, attribution text, group, sound event, optional inline image URI, followed by zero or more key/value activation argument pairs.
		/// </param>
		internal static void Startup_ShowToastNotification(string encodedPayload)
		{
			try
			{
				if (!AppNotificationManager.IsSupported())
					return;

				string payload = Encoding.UTF8.GetString(Convert.FromBase64String(encodedPayload));
				string[] parts = payload.Split(ToastFieldSeparator);
				string title = parts.Length > 0 ? parts[0] : string.Empty;
				string body = parts.Length > 1 ? parts[1] : string.Empty;
				string attributionText = parts.Length > 2 ? parts[2] : string.Empty;
				string group = parts.Length > 3 ? parts[3] : string.Empty;
				AppNotificationSoundEvent soundEvent = (AppNotificationSoundEvent)int.Parse(
					parts[4],
					System.Globalization.NumberStyles.Integer,
					System.Globalization.CultureInfo.InvariantCulture);
				string inlineImageValue = parts.Length > 5 ? parts[5] : string.Empty;
				Uri? inlineImage = string.IsNullOrWhiteSpace(inlineImageValue) ? null : new Uri(inlineImageValue, UriKind.Absolute);

				ShowAToastNotification(title: title, body: body, attributionText: attributionText, group: group, soundEvent: soundEvent, parts: parts, inlineImage: inlineImage);
			}
			catch { }
		}

		private static void ShowAToastNotification(string title, string body, string attributionText, string group, AppNotificationSoundEvent soundEvent, string[] parts, Uri? inlineImage = null)
		{
			AppNotificationBuilder builder = new AppNotificationBuilder()
					.AddText(title)
					.AddText(body)
					.SetAudioEvent(soundEvent)
					.SetTimeStamp(DateTime.Now)
					.SetGroup(group)
					.SetScenario(AppNotificationScenario.Default)
					.SetAttributionText(attributionText);

			if (inlineImage is not null)
			{
				builder = builder.SetInlineImage(inlineImage);
			}

			// Key/value argument pairs start at index 6 as consecutive (key, value) entries.
			for (int i = 6; i + 1 < parts.Length; i += 2)
			{
				builder = builder.AddArgument(parts[i], parts[i + 1]);
			}

			AppNotificationManager.Default.Show(builder.BuildNotification());
		}
	}

	internal static class TaskbarBadge
	{
		/// <summary>
		/// Relaunches the App Alias executable unelevated to set the taskbar badge glyph.
		/// The glyph enum is a simple integer so it is passed directly with no encoding needed.
		/// </summary>
		/// <param name="glyph">The badge glyph to display on the taskbar icon.</param>
		internal static void SetTaskbarBadge(BadgeNotificationGlyph glyph)
		{
			try
			{
				string arguments = string.Concat("STARTUPREDIRECT BADGE", " ", (int)glyph);
				_ = NativeMethods.launch_unelevated(AppAliasExecutableName, arguments, null);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		}

		/// <summary>
		/// Relaunches the App Alias executable unelevated to clear the active taskbar badge.
		/// </summary>
		internal static void ClearTaskbarBadge() => _ = NativeMethods.launch_unelevated(AppAliasExecutableName, "STARTUPREDIRECT BADGECLEAR", null);

		/// <summary>
		/// Parses the integer glyph value and applies it as the taskbar badge.
		/// </summary>
		/// <param name="encodedValue">Integer value of the <see cref="BadgeNotificationGlyph"/> enum.</param>
		internal static void Startup_SetTaskbarBadge(string encodedValue)
		{
			if (int.TryParse(encodedValue, out int glyphValue))
				BadgeNotificationManager.Current.SetBadgeAsGlyph((BadgeNotificationGlyph)glyphValue);
		}

		/// <summary>
		/// Clears the active taskbar badge.
		/// </summary>
		internal static void Startup_ClearTaskbarBadge() => BadgeNotificationManager.Current.ClearBadge();
	}

	internal static class AppShortcuts
	{
		/// <summary>
		/// Relaunches the App Alias executable unelevated to request taskbar pinning.
		/// </summary>
		internal static void PinToTaskbar() => _ = NativeMethods.launch_unelevated(AppAliasExecutableName, "STARTUPREDIRECT TASKBARPIN", null);

		/// <summary>
		/// Relaunches the App Alias executable unelevated to request Start menu pinning.
		/// </summary>
		internal static void PinToStartMenu() => _ = NativeMethods.launch_unelevated(AppAliasExecutableName, "STARTUPREDIRECT STARTPIN", null);

		/// <summary>
		/// Asks Windows to pin the current app to the taskbar after the user confirms the system prompt.
		/// </summary>
		internal static async Task Startup_PinToTaskbar()
		{
			TaskbarManager taskbarManager = TaskbarManager.GetDefault();
			if (!taskbarManager.IsSupported || !taskbarManager.IsPinningAllowed || await taskbarManager.IsCurrentAppPinnedAsync())
			{
				return;
			}
			_ = await taskbarManager.RequestPinCurrentAppAsync();
		}

		/// <summary>
		/// Asks Windows to pin the app to Start after the user confirms the system prompt.
		/// </summary>
		internal static async Task Startup_PinToStartMenu()
		{
			IReadOnlyList<AppListEntry> entries = await Package.Current.GetAppListEntriesAsync();
			AppListEntry? entry = entries.Count > 0 ? entries[0] : null;
			if (entry is null)
			{
				return;
			}

			StartScreenManager startScreenManager = StartScreenManager.GetDefault();
			if (!startScreenManager.SupportsAppListEntry(entry))
			{
				return;
			}

			bool isPinned = await startScreenManager.ContainsAppListEntryAsync(entry);
			if (isPinned)
			{
				return;
			}

			_ = await startScreenManager.RequestAddAppListEntryAsync(entry);
		}
	}
}
