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

using System;
using System.Threading;
using AppControlManager.AppSettings;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;
using Windows.Storage;

#if HARDEN_WINDOWS_SECURITY
namespace HardenWindowsSecurity.AppSettings;
#endif
#if APP_CONTROL_MANAGER
namespace AppControlManager.AppSettings;
#endif

/// <summary>
/// A thread-safe, unified settings manager for the application.
/// Properties are strongly typed and any change is immediately persisted to local storage.
/// </summary>
internal sealed partial class Main : ViewModelBase
{
	// Single shared lock for all property setters
	private readonly Lock SettingsLock = new();

	private readonly ApplicationDataContainer _localSettings;

	internal Main(ApplicationDataContainer LocalSettings)
	{
		_localSettings = LocalSettings;

		// Load each setting from App storage (if present) or use the default value.
		SoundSetting = ReadValue(nameof(SoundSetting), SoundSetting);
		NavViewBackground = ReadValue(nameof(NavViewBackground), NavViewBackground);
		NavViewPaneDisplayMode = ReadValue(nameof(NavViewPaneDisplayMode), NavViewPaneDisplayMode);
		AppTheme = ReadValue(nameof(AppTheme), AppTheme);
		BackDropBackground = ReadValue(nameof(BackDropBackground), BackDropBackground);
		IconsStyle = ReadValue(nameof(IconsStyle), IconsStyle);
		MainWindowWidth = ReadValue(nameof(MainWindowWidth), MainWindowWidth);
		MainWindowHeight = ReadValue(nameof(MainWindowHeight), MainWindowHeight);
		MainWindowIsMaximized = ReadValue(nameof(MainWindowIsMaximized), MainWindowIsMaximized);
		ListViewsVerticalCentering = ReadValue(nameof(ListViewsVerticalCentering), ListViewsVerticalCentering);
		CacheSecurityCatalogsScanResults = ReadValue(nameof(CacheSecurityCatalogsScanResults), CacheSecurityCatalogsScanResults);
		PromptForElevationOnStartup = ReadValue(nameof(PromptForElevationOnStartup), PromptForElevationOnStartup);
		AutomaticAssignmentSidebar = ReadValue(nameof(AutomaticAssignmentSidebar), AutomaticAssignmentSidebar);
		AutoCheckForUpdateAtStartup = ReadValue(nameof(AutoCheckForUpdateAtStartup), AutoCheckForUpdateAtStartup);
		ApplicationGlobalLanguage = ReadValue(nameof(ApplicationGlobalLanguage), ApplicationGlobalLanguage);
		ApplicationGlobalFlowDirection = ReadValue(nameof(ApplicationGlobalFlowDirection), ApplicationGlobalFlowDirection);
		FileActivatedLaunchArg = ReadValue(nameof(FileActivatedLaunchArg), FileActivatedLaunchArg);
		CiPolicySchemaPath = ReadValue(nameof(CiPolicySchemaPath), CiPolicySchemaPath);
		LaunchActivationFilePath = ReadValue(nameof(LaunchActivationFilePath), LaunchActivationFilePath);
		LaunchActivationAction = ReadValue(nameof(LaunchActivationAction), LaunchActivationAction);
		ScreenShield = ReadValue(nameof(ScreenShield), ScreenShield);
		PublishUserActivityInTheOS = ReadValue(nameof(PublishUserActivityInTheOS), PublishUserActivityInTheOS);
	}

	/// <summary>
	/// Generic helper method to read a value from local storage.
	/// If T is an enum type, expects the stored value to be its string name.
	/// </summary>
	private T ReadValue<T>(string key, T defaultValue)
	{
		if (_localSettings.Values.TryGetValue(key, out object? value))
		{
			// Handle enums stored as strings
			if (typeof(T).IsEnum)
			{
				if (value is string stringValue
					&& Enum.TryParse(typeof(T), stringValue, ignoreCase: true, out object? enumParsed))
				{
					return (T)enumParsed;
				}
			}
			// Handle direct-typed values
			else if (value is T typedValue)
			{
				return typedValue;
			}
		}
		return defaultValue;
	}

	/// <summary>
	/// Helper method to immediately persist the new value to local storage.
	/// TODO: Add logic for Enums that will be added in the future.
	/// </summary>
	private void SaveValue(string key, object value)
	{
		// Use the lock when setting values to the Settings Container
		lock (SettingsLock)
			_localSettings.Values[key] = value;
	}

	/// <summary>
	/// Whether the app emits sounds during navigation or not
	/// </summary>
	internal bool SoundSetting
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(SoundSetting), field);

				// Set the sound settings
				ElementSoundPlayer.State = field ? ElementSoundPlayerState.On : ElementSoundPlayerState.Off;
				ElementSoundPlayer.SpatialAudioMode = field ? ElementSpatialAudioMode.On : ElementSpatialAudioMode.Off;
			}
		}
	}

	/// <summary>
	/// If on, the extra layer is removed from the NavigationView's background, giving the entire app a darker look.
	/// </summary>
	internal bool NavViewBackground
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(NavViewBackground), field);

				// Notify NavigationBackgroundManager
				NavigationBackgroundManager.OnNavigationBackgroundChanged(field);
			}
		}
	}

	/// <summary>
	/// The display mode of the main NavigationView, whether it's on top or on the left side
	/// </summary>
	internal string NavViewPaneDisplayMode
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(NavViewPaneDisplayMode), field);
			}
		}
	} = "Left";

	/// <summary>
	/// Light, Dark or System
	/// </summary>
	internal string AppTheme
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(AppTheme), field);
			}
		}
	} = "Use System Setting";

	/// <summary>
	/// Mica, MicaAlt or Acrylic
	/// </summary>
	internal string BackDropBackground
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(BackDropBackground), field);
			}
		}
	} = "MicaAlt";

	/// <summary>
	/// MonoChrome, Animated or accent based
	/// </summary>
	internal string IconsStyle
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(IconsStyle), field);
			}
		}
	} = "Monochromatic";

	/// <summary>
	/// Width of the main window
	/// </summary>
	internal int MainWindowWidth
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(MainWindowWidth), field);
			}
		}
	} = 700;

	/// <summary>
	/// Height of the main window
	/// </summary>
	internal int MainWindowHeight
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(MainWindowHeight), field);
			}
		}
	} = 700;

	/// <summary>
	/// Whether the main window is maximized prior to closing the app.
	/// </summary>
	internal bool MainWindowIsMaximized
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(MainWindowIsMaximized), field);
			}
		}
	}

	/// <summary>
	/// Whether clicks/taps on ListView items will cause the selected row to be vertically centered.
	/// </summary>
	internal bool ListViewsVerticalCentering
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(ListViewsVerticalCentering), field);
			}
		}
	}

	/// <summary>
	/// Cache the security catalog scan results to speed up various components of the app that use them.
	/// </summary>
	internal bool CacheSecurityCatalogsScanResults
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(CacheSecurityCatalogsScanResults), field);
			}
		}
	} = true;

	/// <summary>
	/// Whether the app will prompt for elevation and display a UAC on startup.
	/// </summary>
	internal bool PromptForElevationOnStartup
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(PromptForElevationOnStartup), field);
			}
		}
	}

	/// <summary>
	/// Automatically assign the generated base policies to the Sidebar's selected policy field for easy usage in pages that support the augmentation.
	/// </summary>
	internal bool AutomaticAssignmentSidebar
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(AutomaticAssignmentSidebar), field);
			}
		}
	} = true;

	/// <summary>
	/// Automatically check for updates on app startup.
	/// </summary>
	internal bool AutoCheckForUpdateAtStartup
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(AutoCheckForUpdateAtStartup), field);
			}
		}
	} = true;

	/// <summary>
	/// Selected language for the application
	/// </summary>
	internal string ApplicationGlobalLanguage
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(ApplicationGlobalLanguage), field);
			}
		}
	} = "en-US";

	/// <summary>
	/// Whether the User Interface flow direction is Left-to-Right or Right-to-Left
	/// </summary>
	internal string ApplicationGlobalFlowDirection
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(ApplicationGlobalFlowDirection), field);
			}
		}
	} = "LeftToRight";

	/// <summary>
	/// The argument received if the app is launched via file activation.
	/// This allows us to have access to this after app has been relaunched with Admin privileges.
	/// </summary>
	internal string FileActivatedLaunchArg
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(FileActivatedLaunchArg), field);
			}
		}
	} = string.Empty;

	/// <summary>
	/// The path to the Code Integrity Schema XSD file.
	/// User can optionally provide a custom path to it. E.g., on Home edition where this file doesn't exist by default.
	/// </summary>
	internal string CiPolicySchemaPath
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(CiPolicySchemaPath), field);
			}
		}
	} = string.Empty;

	/// <summary>
	/// File path retrieved from the Launch args received from Context Menu activation.
	/// </summary>
	internal string LaunchActivationFilePath
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(LaunchActivationFilePath), field);
			}
		}
	} = string.Empty;

	/// <summary>
	/// Action retrieved from the Launch args received from Context Menu activation.
	/// </summary>
	internal string LaunchActivationAction
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(LaunchActivationAction), field);
			}
		}
	} = string.Empty;


	/// <summary>
	/// Prevent screen recorders and other apps from recording or taking screenshot of the app's window.
	/// </summary>
	internal bool ScreenShield
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				WindowDisplayAffinity.SetWindowDisplayAffinity(GlobalVars.hWnd, field ? WindowDisplayAffinity.DisplayAffinity.WDA_EXCLUDEFROMCAPTURE : WindowDisplayAffinity.DisplayAffinity.WDA_NONE);

				SaveValue(nameof(ScreenShield), field);
			}
		}
	}

	/// <summary>
	/// Whether the application can publish user activity in the OS so that user can then re-trace their steps in features such as Recall.
	/// </summary>
	internal bool PublishUserActivityInTheOS
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SaveValue(nameof(PublishUserActivityInTheOS), field);
			}
		}
	} = true;
}
