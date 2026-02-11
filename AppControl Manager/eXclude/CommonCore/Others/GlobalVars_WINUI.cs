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
using System.Threading;
using AppControlManager.ViewModels;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.ApplicationModel.Resources;
using Windows.ApplicationModel;
using Windows.Storage;

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
	// Not actually used by the Harden System Security app. Only here to satisfy the BuildAppControlCertificate's method requirement.
	internal static readonly string UserConfigDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Harden System Security");
#endif
#if APP_CONTROL_MANAGER
	// Storing the path to the app's folder in the Program Files
	internal static readonly string UserConfigDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AppControl Manager");
#endif

	// Storing the path to User Config JSON file in the app's folder in the Program Files
	internal static readonly string UserConfigJson = Path.Combine(UserConfigDir, "UserConfigurations", "UserConfigurations.json");

#if HARDEN_SYSTEM_SECURITY
	internal const string AppName = "HardenSystemSecurity";
#endif
#if APP_CONTROL_MANAGER
	internal const string AppName = "AppControlManager";
#endif

	/// <summary>
	/// Package Family Name of the application
	/// </summary>
	internal static readonly string PFN = Package.Current.Id.FamilyName;

	/// <summary>
	/// The App User Model ID which is in the format of PackageFamilyName!App
	/// The "App" is what's defined in the Package.appxmanifest file for ID in Application Id="App"
	/// </summary>
	internal static readonly string AUMID = AppInfo.Current.AppUserModelId;

	/// <summary>
	/// To determine whether the app has Administrator privileges
	/// </summary>
	internal static readonly bool IsElevated = Environment.IsPrivilegedProcess;

	/// <summary>
	/// Detects the source of the application.
	/// GitHub => 0
	/// Microsoft Store => 1
	/// Unknown => 2
	/// </summary>
	internal static readonly int PackageSource = string.Equals(PFN, "AppControlManager_sadt7br7jpt02", StringComparison.OrdinalIgnoreCase) ?
		0 :
		(string.Equals(PFN, "VioletHansen.AppControlManager_ea7andspwdn10", StringComparison.OrdinalIgnoreCase) || string.Equals(PFN, "VioletHansen.HardenSystemSecurity_ea7andspwdn10", StringComparison.OrdinalIgnoreCase)
		? 1 : 2);

	/// <summary>
	/// Initializes the app settings class.
	/// </summary>
	private static readonly Lazy<AppSettings.Main> _appSettings = new(() =>
		new AppSettings.Main(ApplicationData.Current.LocalSettings), LazyThreadSafetyMode.PublicationOnly);

	/// <summary>
	/// The application settings. Any references (instance or static) throughout the app to App settings use this property.
	/// </summary>
	internal static AppSettings.Main Settings => _appSettings.Value;

	/// <summary>
	/// Global dispatcher queue for the application that can be accessed from anywhere.
	/// </summary>
	internal static DispatcherQueue AppDispatcher { get; set; } = null!;

	/// <summary>
	/// Convert it to a normal Version object
	/// </summary>
	internal static readonly Version currentAppVersion = new(Package.Current.Id.Version.Major, Package.Current.Id.Version.Minor, Package.Current.Id.Version.Build, Package.Current.Id.Version.Revision);

#if APP_CONTROL_MANAGER
	/// <summary>
	/// The directory where the logs will be stored
	/// </summary>
	internal static readonly string LogsDirectory = IsElevated ?
		Path.Combine(UserConfigDir, "Logs") :
		Path.Combine(Path.GetTempPath(), $"{AppName}Logs");
#endif

#if HARDEN_SYSTEM_SECURITY
	/// <summary>
	/// The directory where the logs will be stored
	/// </summary>
	internal static readonly string LogsDirectory = Path.Combine(Path.GetTempPath(), $"{AppName}Logs");
#endif

	// To track the currently open Content Dialog across the app. Every piece of code that tries to display a content dialog, whether custom or generic, must assign it first
	// to this variable before using ShowAsync() method to display it.
	internal static ContentDialog? CurrentlyOpenContentDialog;

}
