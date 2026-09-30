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
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Windows.Storage;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

/// <summary>
/// The view of the top bar that is currently on display.
/// </summary>
internal enum TopBarView
{
	Apps = 0,
	Folders = 1,
	Performance = 2,
	Clocks = 3,
	NetworkQuality = 4,
	Sentry = 5,
	Websites = 6
}

/// <summary>
/// Backdrops used by the TopBar.
/// </summary>
internal enum TopBarBackdrop
{
	Solid = 0,
	Mica = 1,
	MicaAlt = 2,
	DesktopAcrylic = 3
}

/// <summary>
/// The companion animation displayed beside the active Top Bar view.
/// </summary>
internal enum TopBarCompanion
{
	None = 0,
	PrisMatrix = 1,
	NullCat = 2,
	Bunny = 3,
	Squirrel = 4,
	PopForge = 5
}

/// <summary>
/// A single launchable application of the top bar.
/// </summary>
internal sealed class TopBarAppEntry
{
	/// <summary>
	/// The name that is displayed underneath the icon of the entry.
	/// </summary>
	public string DisplayName { get; set; } = string.Empty;

	/// <summary>
	/// The Segoe Fluent Icons glyph of the entry.
	/// </summary>
	public string Glyph { get; set; } = "\uE737";

	/// <summary>
	/// Whatever the shell has to launch when the entry is invoked. It is either the path of an executable
	/// or a shell command such as a protocol activation.
	/// </summary>
	public string LaunchTarget { get; set; } = string.Empty;
}

/// <summary>
/// A single folder of the system that is pinned to the top bar for quick access.
/// </summary>
internal sealed class TopBarFolderEntry
{
	/// <summary>
	/// The name that is displayed underneath the icon of the entry.
	/// </summary>
	public string DisplayName { get; set; } = string.Empty;

	/// <summary>
	/// The full path of the folder that is opened when the entry is invoked.
	/// </summary>
	public string FolderPath { get; set; } = string.Empty;

	/// <summary>
	/// The optional ARGB color of the folder glyph. A missing value preserves the theme-provided default.
	/// </summary>
	public uint? GlyphColor { get; set; }
}

/// <summary>
/// A single website pinned to the Websites view.
/// </summary>
internal sealed class TopBarWebsiteEntry
{
	public string DisplayName { get; set; } = string.Empty;
	public string Url { get; set; } = string.Empty;
}

/// <summary>
/// A single world clock of the top bar.
/// </summary>
internal sealed class TopBarClockEntry
{
	/// <summary>
	/// The name that the user gave to the clock.
	/// </summary>
	public string DisplayName { get; set; } = string.Empty;

	/// <summary>
	/// The identifier of the time zone that the clock displays.
	/// An empty identifier means the local time zone of the machine.
	/// </summary>
	public string TimeZoneId { get; set; } = string.Empty;

	/// <summary>
	/// Whether this clock is displayed in the standard collapsed notch.
	/// </summary>
	public bool DisplayOnNotch { get; set; }
}

/// <summary>
/// Everything about the top bar that survives a restart of the app.
/// </summary>
internal sealed class TopBarConfiguration
{
	public List<TopBarAppEntry> Apps { get; set; } =
	[
		new TopBarAppEntry { DisplayName = "Settings", Glyph = "\uE713", LaunchTarget = "ms-settings:" },
		new TopBarAppEntry { DisplayName = "Explorer", Glyph = "\uEC50", LaunchTarget = "explorer.exe" },
		new TopBarAppEntry { DisplayName = "Notepad", Glyph = "\uE70F", LaunchTarget = "notepad.exe" },
		new TopBarAppEntry { DisplayName = "Calculator", Glyph = "\uE8EF", LaunchTarget = "calc.exe" },
		new TopBarAppEntry { DisplayName = "Task Manager", Glyph = "\uE9D9", LaunchTarget = "taskmgr.exe" }
	];
	public List<TopBarFolderEntry> Folders { get; set; } =
	[
		new TopBarFolderEntry { DisplayName = "Downloads", FolderPath = "shell:Downloads", GlyphColor = 0xFF89CFF0U },
		new TopBarFolderEntry { DisplayName = "Documents", FolderPath = "shell:Personal", GlyphColor = 0xFFCDB4DBU },
		new TopBarFolderEntry { DisplayName = "Desktop", FolderPath = "shell:Desktop", GlyphColor = 0xFFA8D5BAU },
		new TopBarFolderEntry { DisplayName = "Pictures", FolderPath = "shell:My Pictures", GlyphColor = 0xFFFFAFCCU },
		new TopBarFolderEntry { DisplayName = "OneDrive", FolderPath = "shell:OneDrive", GlyphColor = 0xFFA2D2FFU },
		new TopBarFolderEntry { DisplayName = "This PC", FolderPath = "shell:MyComputerFolder", GlyphColor = 0xFFFFD6A5U }
	];
	public List<TopBarWebsiteEntry> Websites { get; set; } =
	[
		new TopBarWebsiteEntry { DisplayName = "Microsoft", Url = "https://microsoft.com/" },
		new TopBarWebsiteEntry { DisplayName = "GitHub", Url = "https://github.com/" },
		new TopBarWebsiteEntry { DisplayName = "Grokipedia", Url = "https://grokipedia.com/" },
		new TopBarWebsiteEntry { DisplayName = "Bing", Url = "https://bing.com/" },
		new TopBarWebsiteEntry { DisplayName = "Spotify", Url = "https://open.spotify.com/" },
		new TopBarWebsiteEntry { DisplayName = "YouTube", Url = "https://YouTube.com/" },
		new TopBarWebsiteEntry { DisplayName = "X", Url = "https://X.com/" },
		new TopBarWebsiteEntry { DisplayName = "Instagram", Url = "https://instagram.com/" }
	];
	public List<TopBarClockEntry> Clocks { get; set; } =
	[
		new TopBarClockEntry { DisplayName = "Local", TimeZoneId = string.Empty, DisplayOnNotch = true },
		new TopBarClockEntry { DisplayName = "UTC", TimeZoneId = "UTC", DisplayOnNotch = true },
		new TopBarClockEntry { DisplayName = "Washington, D.C.", TimeZoneId = "Eastern Standard Time" },
		new TopBarClockEntry { DisplayName = "Central", TimeZoneId = "Central Standard Time" },
		new TopBarClockEntry { DisplayName = "Pacific", TimeZoneId = "Pacific Standard Time" },
		new TopBarClockEntry { DisplayName = "Israel", TimeZoneId = "Israel Standard Time" }
	];
	public TopBarCompanion Companion { get; set; } = TopBarCompanion.PrisMatrix;
	public TopBarBackdrop Backdrop { get; set; } = TopBarBackdrop.MicaAlt;
}

/// <summary>
/// Source generation context so that the configuration can be read and written.
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(TopBarConfiguration))]
[JsonSerializable(typeof(TopBarCompanion))]
internal sealed partial class TopBarConfigurationJsonContext : JsonSerializerContext
{
}

/// <summary>
/// The shape that the bar takes while it is collapsed into its notch.
/// </summary>
internal enum TopBarNotchStyle
{
	/// <summary>
	/// The roomy notch that carries the glyph of the active view, its name and the chevron.
	/// </summary>
	Standard = 0,

	/// <summary>
	/// The much smaller and lower profile notch that only carries the glyph of the active view and its name.
	/// </summary>
	Compact = 1
}

/// <summary>
/// Reads and writes the configuration of the top bar. Everything that the user adds to the bar or removes from it
/// is persisted here so that the bar looks the same the next time that it is opened.
/// The configuration lives in a JSON file in the local app data folder.
/// </summary>
internal static class TopBarConfigurationManager
{
	private const string ConfigurationFileName = "WindowsTopBarConfiguration.json";
	private const string TemporaryConfigurationFileName = "WindowsTopBarConfiguration.json.tmp";

	/// <summary>
	/// Loads the configuration from the app's local data folder, falling back to the default configuration when the
	/// file does not exist or cannot be read.
	/// </summary>
	internal static TopBarConfiguration Load()
	{
		try
		{
			string configurationFilePath = GetConfigurationFilePath();
			if (!File.Exists(configurationFilePath))
			{
				return new TopBarConfiguration();
			}

			string content = File.ReadAllText(configurationFilePath);
			return JsonSerializer.Deserialize(content, TopBarConfigurationJsonContext.Default.TopBarConfiguration) ?? new TopBarConfiguration();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);

			return new TopBarConfiguration();
		}
	}

	/// <summary>
	/// Writes the configuration atomically to the app's local data folder so an interrupted write cannot replace the
	/// last complete configuration with a partial JSON document.
	/// </summary>
	internal static void Save(TopBarConfiguration configuration)
	{
		string temporaryFilePath = GetTemporaryConfigurationFilePath();
		try
		{
			string content = JsonSerializer.Serialize(configuration, TopBarConfigurationJsonContext.Default.TopBarConfiguration);
			File.WriteAllText(temporaryFilePath, content);
			File.Move(temporaryFilePath, GetConfigurationFilePath(), true);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			TryDeleteTemporaryConfigurationFile(temporaryFilePath);
		}
	}

	private static string GetConfigurationFilePath()
	{
		using ApplicationData applicationData = ApplicationData.GetDefault();
		return Path.Join(applicationData.LocalPath, ConfigurationFileName);
	}

	private static string GetTemporaryConfigurationFilePath()
	{
		using ApplicationData applicationData = ApplicationData.GetDefault();
		return Path.Join(applicationData.LocalPath, TemporaryConfigurationFileName);
	}

	private static void TryDeleteTemporaryConfigurationFile(string temporaryFilePath)
	{
		try
		{
			File.Delete(temporaryFilePath);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// The notch style that the bar was last left with.
	/// </summary>
	internal static TopBarNotchStyle LoadNotchStyle() =>
		Atlas.Settings.WindowsTopBarNotchStyle == (int)TopBarNotchStyle.Compact ? TopBarNotchStyle.Compact : TopBarNotchStyle.Standard;

	/// <summary>
	/// Remembers the notch style that the bar is being switched to.
	/// </summary>
	internal static void SaveNotchStyle(TopBarNotchStyle style) => Atlas.Settings.WindowsTopBarNotchStyle = (int)style;
}
