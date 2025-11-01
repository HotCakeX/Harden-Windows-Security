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

using System.IO;
using Microsoft.Windows.ApplicationModel.Resources;

namespace CommonCore.Others;

internal static partial class GlobalVars
{
	// Instantiate the ResourceLoader object to access the strings in the Resource.resw file
	internal static ResourceLoader Rizz = new();

#if HARDEN_SYSTEM_SECURITY

	internal static Windows.ApplicationModel.Resources.ResourceLoader SecurityMeasuresRizzLoader = Windows.ApplicationModel.Resources.ResourceLoader.GetForViewIndependentUse("SecurityMeasures");

	/// <summary>
	/// This method is responsible for retrieving localized strings from the SecurityMeasures for Security measures' friendly name field based on a key.
	/// </summary>
	/// <param name="key"></param>
	/// <returns></returns>
	internal static string GetSecurityStr(string key)
	{
		try
		{
			return SecurityMeasuresRizzLoader.GetString(key);
		}
		catch (Exception ex)
		{
			Logger.Write($"Error retrieving localized string for key: {key}: {ex.Message}");
			return key;
		}
	}
#endif

	/// <summary>
	/// This method is responsible for retrieving localized strings from the resource files based on a key.
	/// </summary>
	/// <param name="key"></param>
	/// <returns></returns>
	internal static string GetStr(string key)
	{
		try
		{
			return Rizz.GetString(key);
		}
		catch (Exception ex)
		{
			Logger.Write($"Error retrieving localized string for key: {key}: {ex.Message}");
			return key;
		}
	}

	// Handle of the main Window - acquired in the MainWindow.xaml.cs
	internal static nint hWnd;

#if HARDEN_SYSTEM_SECURITY
	// Storing the path to the app's folder in the Program Files
	internal static readonly string UserConfigDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Harden System Security");
#endif
#if APP_CONTROL_MANAGER
	// Storing the path to the app's folder in the Program Files
	internal static readonly string UserConfigDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AppControl Manager");
#endif

	// Storing the path to User Config JSON file in the app's folder in the Program Files
	internal static readonly string UserConfigJson = Path.Combine(UserConfigDir, "UserConfigurations", "UserConfigurations.json");

	// Storing the path to the StagingArea folder in the AppControl Manager folder in the Program Files
	// Each instance of the App (in case there are more than one at a time) has a unique staging area
	internal static readonly string StagingArea = Path.Combine(UserConfigDir, $"StagingArea-{DateTime.UtcNow:yyyyMMddHHmmssfffffff}");

}
