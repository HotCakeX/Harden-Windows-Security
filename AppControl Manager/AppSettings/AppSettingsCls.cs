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

using Windows.Storage;

namespace AppControlManager.AppSettings;

// https://learn.microsoft.com/en-us/uwp/api/windows.storage.applicationdata.localsettings

internal static class AppSettingsCls
{
	/// <summary>
	/// Save setting to local storage with a specific key and value
	/// </summary>
	/// <param name="key"></param>
	/// <param name="value"></param>
	internal static void SaveSetting(SettingKeys key, object? value)
	{
		ApplicationDataContainer localSettings = ApplicationData.Current.LocalSettings;
		localSettings.Values[key.ToString()] = value;
	}

	/// <summary>
	/// Retrieve setting from local storage with a specific key
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="key"></param>
	/// <returns></returns>
	internal static T? GetSetting<T>(SettingKeys key)
	{
		ApplicationDataContainer localSettings = ApplicationData.Current.LocalSettings;

		// Check if the key exists and get the value
		if (localSettings.Values.TryGetValue(key.ToString(), out object? value))
		{
			// Return value cast to T (for value types, this works with nullable types as well)
			return value is T result ? result : default;
		}

		// Return default value (null for reference types, or default(T) for value types)
		return default;
	}


	/// <summary>
	/// Retrieve setting from local storage with a specific key and returns null if the value doesn't exist.
	/// Used by settings that need to set a default app configuration to true/on unless there is a user-defined configuration.
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="key"></param>
	/// <returns></returns>
	internal static T? TryGetSetting<T>(SettingKeys key)
	{
		ApplicationDataContainer localSettings = ApplicationData.Current.LocalSettings;

		// Check if the key exists and get the value
		if (localSettings.Values.TryGetValue(key.ToString(), out object? value))
		{
			// Return value cast to T (for value types, this works with nullable types as well)
			return value is T result ? result : default;
		}

		// Return null explicitly when the key does not exist
		// If T is a reference type, return null directly.
		// If T is a value type, check if it supports nullable by comparing default(T?) to null.
		// If T is not nullable (e.g., int), cast null to T? and return it, effectively providing a null result.
		// in other words:
		// calling it like this: AppSettings.GetSetting<bool>(AppSettings.SettingKeys.AutomaticAssignmentSidebar); and if the key doesn't exist, returns default value for bool which is false.
		// Calling it like this: AppSettings.GetSetting<bool?>(AppSettings.SettingKeys.AutomaticAssignmentSidebar); and if the key doesn't exist, returns null.
		return default(T?) == null ? default : (T?)(object?)null;
	}

	// Enum for the setting keys
	// Used when saving and retrieving settings
	internal enum SettingKeys
	{
		SoundSetting,
		NavViewBackground,
		NavViewPaneDisplayMode,
		AppTheme,
		BackDropBackground,
		IconsStyle,
		MainWindowWidth,
		MainWindowHeight,
		MainWindowIsMaximized,
		AutomaticAssignmentSidebar,
		AutoCheckForUpdateAtStartup,
		ListViewsVerticalCentering,
		CacheSecurityCatalogsScanResults
	}
}
