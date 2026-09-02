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
	NetworkQuality = 4
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
}

/// <summary>
/// Everything about the top bar that survives a restart of the app.
/// </summary>
internal sealed class TopBarConfiguration
{
	public List<TopBarAppEntry> Apps { get; set; } = [];

	public List<TopBarFolderEntry> Folders { get; set; } = [];

	public List<TopBarClockEntry> Clocks { get; set; } = [];
}

/// <summary>
/// Source generation context so that the configuration can be read and written.
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(TopBarConfiguration))]
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
	/// <summary>
	/// The entries that a brand new configuration starts out with.
	/// </summary>
	private static TopBarConfiguration CreateDefaultConfiguration() => new()
	{
		Apps =
		[
			new TopBarAppEntry { DisplayName = "Settings", Glyph = "\uE713", LaunchTarget = "ms-settings:" },
			new TopBarAppEntry { DisplayName = "Explorer", Glyph = "\uEC50", LaunchTarget = "explorer.exe" },
			new TopBarAppEntry { DisplayName = "Notepad", Glyph = "\uE70F", LaunchTarget = "notepad.exe" },
			new TopBarAppEntry { DisplayName = "Calculator", Glyph = "\uE8EF", LaunchTarget = "calc.exe" },
			new TopBarAppEntry { DisplayName = "Task Manager", Glyph = "\uE9D9", LaunchTarget = "taskmgr.exe" }
		],
		Folders =
		[
			new TopBarFolderEntry { DisplayName = "Downloads", FolderPath = "shell:Downloads" },
			new TopBarFolderEntry { DisplayName = "Documents", FolderPath = "shell:Personal" },
			new TopBarFolderEntry { DisplayName = "Desktop", FolderPath = "shell:Desktop" }
		],
		Clocks =
		[
			new TopBarClockEntry { DisplayName = "Local", TimeZoneId = string.Empty },
			new TopBarClockEntry { DisplayName = "UTC", TimeZoneId = "UTC" },
			new TopBarClockEntry { DisplayName = "Washington, D.C.", TimeZoneId = "Eastern Standard Time" },
			new TopBarClockEntry { DisplayName = "Central", TimeZoneId = "Central Standard Time" },
			new TopBarClockEntry { DisplayName = "Pacific", TimeZoneId = "Pacific Standard Time" },
			new TopBarClockEntry { DisplayName = "Israel", TimeZoneId = "Israel Standard Time" }
		]
	};

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
				return CreateDefaultConfiguration();
			}

			string content = File.ReadAllText(configurationFilePath);
			TopBarConfiguration? configuration = JsonSerializer.Deserialize(content, TopBarConfigurationJsonContext.Default.TopBarConfiguration);

			return configuration ?? CreateDefaultConfiguration();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);

			return CreateDefaultConfiguration();
		}
	}

	/// <summary>
	/// Writes the configuration atomically to the app's local data folder so an interrupted write cannot replace the
	/// last complete configuration with a partial JSON document.
	/// </summary>
	internal static void Save(TopBarConfiguration configuration) => _ = TrySave(configuration);

	private static bool TrySave(TopBarConfiguration configuration)
	{
		string temporaryFilePath = GetTemporaryConfigurationFilePath();
		try
		{
			string content = JsonSerializer.Serialize(configuration, TopBarConfigurationJsonContext.Default.TopBarConfiguration);
			File.WriteAllText(temporaryFilePath, content);
			File.Move(temporaryFilePath, GetConfigurationFilePath(), true);
			return true;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			TryDeleteTemporaryConfigurationFile(temporaryFilePath);
			return false;
		}
	}

	private static string GetConfigurationFilePath()
	{
		using ApplicationData applicationData = ApplicationData.GetDefault();
		return Path.Combine(applicationData.LocalPath, ConfigurationFileName);
	}

	private static string GetTemporaryConfigurationFilePath()
	{
		using ApplicationData applicationData = ApplicationData.GetDefault();
		return Path.Combine(applicationData.LocalPath, TemporaryConfigurationFileName);
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
