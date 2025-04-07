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

using System.ComponentModel;
using System.Threading;
using Windows.Storage;

namespace AppControlManager.AppSettings;

#pragma warning disable CA1812

/// <summary>
/// A thread-safe, unified settings manager for the application.
/// Properties are strongly typed and any change is immediately persisted to local storage.
/// </summary>
internal sealed partial class Main : INotifyPropertyChanged
{

	public event PropertyChangedEventHandler? PropertyChanged;

	private readonly Lock _syncRoot = new();

	private readonly ApplicationDataContainer _localSettings;

	// Backing fields for settings with default values.
	private bool _soundSetting;
	private bool _navViewBackground;
	private string _navViewPaneDisplayMode = "Left";
	private string _appTheme = "Use System Setting";
	private string _backDropBackground = "MicaAlt";
	private string _iconsStyle = "Monochromatic";
	private int _mainWindowWidth = 100; // Setting it to this value initially so that it will be determined naturally in MainWindow class
	private int _mainWindowHeight = 100; // Setting it to this value initially so that it will be determined naturally in MainWindow class
	private bool _mainWindowIsMaximized;
	private bool _listViewsVerticalCentering;
	private bool _cacheSecurityCatalogsScanResults = true;
	private bool _promptForElevationOnStartup;
	private bool _automaticAssignmentSidebar = true;
	private bool _autoCheckForUpdateAtStartup = true;
	private string _ApplicationGlobalLanguage = "en-US";
	private string _ApplicationGlobalFlowDirection = "LeftToRight";

	internal Main(ApplicationDataContainer LocalSettings)
	{
		_localSettings = LocalSettings;

		// Load each setting from App storage (if present) or use the default value.
		_soundSetting = ReadValue(nameof(SoundSetting), _soundSetting);
		_navViewBackground = ReadValue(nameof(NavViewBackground), _navViewBackground);
		_navViewPaneDisplayMode = ReadValue(nameof(NavViewPaneDisplayMode), _navViewPaneDisplayMode);
		_appTheme = ReadValue(nameof(AppTheme), _appTheme);
		_backDropBackground = ReadValue(nameof(BackDropBackground), _backDropBackground);
		_iconsStyle = ReadValue(nameof(IconsStyle), _iconsStyle);
		_mainWindowWidth = ReadValue(nameof(MainWindowWidth), _mainWindowWidth);
		_mainWindowHeight = ReadValue(nameof(MainWindowHeight), _mainWindowHeight);
		_mainWindowIsMaximized = ReadValue(nameof(MainWindowIsMaximized), _mainWindowIsMaximized);
		_listViewsVerticalCentering = ReadValue(nameof(ListViewsVerticalCentering), _listViewsVerticalCentering);
		_cacheSecurityCatalogsScanResults = ReadValue(nameof(CacheSecurityCatalogsScanResults), _cacheSecurityCatalogsScanResults);
		_promptForElevationOnStartup = ReadValue(nameof(PromptForElevationOnStartup), _promptForElevationOnStartup);
		_automaticAssignmentSidebar = ReadValue(nameof(AutomaticAssignmentSidebar), _automaticAssignmentSidebar);
		_autoCheckForUpdateAtStartup = ReadValue(nameof(AutoCheckForUpdateAtStartup), _autoCheckForUpdateAtStartup);
		_ApplicationGlobalLanguage = ReadValue(nameof(ApplicationGlobalLanguage), _ApplicationGlobalLanguage);
		_ApplicationGlobalFlowDirection = ReadValue(nameof(ApplicationGlobalFlowDirection), _ApplicationGlobalFlowDirection);
	}


	/// <summary>
	/// Generic helper method to read a value from local storage.
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="key"></param>
	/// <param name="defaultValue"></param>
	/// <returns></returns>
	private T ReadValue<T>(string key, T defaultValue)
	{
		if (_localSettings.Values.TryGetValue(key, out object? value) && value is T typedValue)
		{
			return typedValue;
		}
		return defaultValue;
	}


	/// <summary>
	/// Helper method to immediately persist the new value to local storage.
	/// </summary>
	/// <param name="key"></param>
	/// <param name="value"></param>
	private void SaveValue(string key, object value) => _localSettings.Values[key] = value;


	/// <summary>
	/// Whether the app emits sounds during navigation or not
	/// </summary>
	internal bool SoundSetting
	{
		get
		{
			lock (_syncRoot)
			{
				return _soundSetting;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_soundSetting != value)
				{
					_soundSetting = value;
					SaveValue(nameof(SoundSetting), value);
					OnPropertyChanged(nameof(SoundSetting));
				}
			}
		}
	}


	/// <summary>
	/// If on, the extra layer is removed from the NavigationView's background, giving the entire app a darker look.
	/// </summary>
	internal bool NavViewBackground
	{
		get
		{
			lock (_syncRoot)
			{
				return _navViewBackground;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_navViewBackground != value)
				{
					_navViewBackground = value;
					SaveValue(nameof(NavViewBackground), value);
					OnPropertyChanged(nameof(NavViewBackground));
				}
			}
		}
	}


	/// <summary>
	/// The display mode of the main NavigationView, whether it's on top or on the left side
	/// </summary>
	internal string NavViewPaneDisplayMode
	{
		get
		{
			lock (_syncRoot)
			{
				return _navViewPaneDisplayMode;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_navViewPaneDisplayMode != value)
				{
					_navViewPaneDisplayMode = value;
					SaveValue(nameof(NavViewPaneDisplayMode), value);
					OnPropertyChanged(nameof(NavViewPaneDisplayMode));
				}
			}
		}
	}


	/// <summary>
	/// Light, Dark or System
	/// </summary>
	internal string AppTheme
	{
		get
		{
			lock (_syncRoot)
			{
				return _appTheme;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_appTheme != value)
				{
					_appTheme = value;
					SaveValue(nameof(AppTheme), value);
					OnPropertyChanged(nameof(AppTheme));
				}
			}
		}
	}


	/// <summary>
	/// Mica, MicaAlt or Acrylic
	/// </summary>
	internal string BackDropBackground
	{
		get
		{
			lock (_syncRoot)
			{
				return _backDropBackground;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_backDropBackground != value)
				{
					_backDropBackground = value;
					SaveValue(nameof(BackDropBackground), value);
					OnPropertyChanged(nameof(BackDropBackground));
				}
			}
		}
	}


	/// <summary>
	/// MonoChrome, Animated or accent based
	/// </summary>
	internal string IconsStyle
	{
		get
		{
			lock (_syncRoot)
			{
				return _iconsStyle;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_iconsStyle != value)
				{
					_iconsStyle = value;
					SaveValue(nameof(IconsStyle), value);
					OnPropertyChanged(nameof(IconsStyle));
				}
			}
		}
	}


	/// <summary>
	/// Width of the main window
	/// </summary>
	internal int MainWindowWidth
	{
		get
		{
			lock (_syncRoot)
			{
				return _mainWindowWidth;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_mainWindowWidth != value)
				{
					_mainWindowWidth = value;
					SaveValue(nameof(MainWindowWidth), value);
					OnPropertyChanged(nameof(MainWindowWidth));
				}
			}
		}
	}


	/// <summary>
	/// Height of the main window
	/// </summary>
	internal int MainWindowHeight
	{
		get
		{
			lock (_syncRoot)
			{
				return _mainWindowHeight;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_mainWindowHeight != value)
				{
					_mainWindowHeight = value;
					SaveValue(nameof(MainWindowHeight), value);
					OnPropertyChanged(nameof(MainWindowHeight));
				}
			}
		}
	}


	/// <summary>
	/// Whether the main window is maximized prior to closing the app.
	/// </summary>
	internal bool MainWindowIsMaximized
	{
		get
		{
			lock (_syncRoot)
			{
				return _mainWindowIsMaximized;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_mainWindowIsMaximized != value)
				{
					_mainWindowIsMaximized = value;
					SaveValue(nameof(MainWindowIsMaximized), value);
					OnPropertyChanged(nameof(MainWindowIsMaximized));
				}
			}
		}
	}


	/// <summary>
	/// Whether clicks/taps on ListView items will cause the selected row to be vertically centered.
	/// </summary>
	internal bool ListViewsVerticalCentering
	{
		get
		{
			lock (_syncRoot)
			{
				return _listViewsVerticalCentering;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_listViewsVerticalCentering != value)
				{
					_listViewsVerticalCentering = value;
					SaveValue(nameof(ListViewsVerticalCentering), value);
					OnPropertyChanged(nameof(ListViewsVerticalCentering));
				}
			}
		}
	}


	/// <summary>
	/// Cache the security catalog scan results to speed up various components of the app that use them.
	/// </summary>
	internal bool CacheSecurityCatalogsScanResults
	{
		get
		{
			lock (_syncRoot)
			{
				return _cacheSecurityCatalogsScanResults;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_cacheSecurityCatalogsScanResults != value)
				{
					_cacheSecurityCatalogsScanResults = value;
					SaveValue(nameof(CacheSecurityCatalogsScanResults), value);
					OnPropertyChanged(nameof(CacheSecurityCatalogsScanResults));
				}
			}
		}
	}


	/// <summary>
	/// Whether the app will prompt for elevation and display a UAC on startup.
	/// </summary>
	internal bool PromptForElevationOnStartup
	{
		get
		{
			lock (_syncRoot)
			{
				return _promptForElevationOnStartup;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_promptForElevationOnStartup != value)
				{
					_promptForElevationOnStartup = value;
					SaveValue(nameof(PromptForElevationOnStartup), value);
					OnPropertyChanged(nameof(PromptForElevationOnStartup));
				}
			}
		}
	}


	/// <summary>
	/// Automatically assign the generated base policies to the Sidebar's selected policy field for easy usage in pages that support the augmentation.
	/// </summary>
	internal bool AutomaticAssignmentSidebar
	{
		get
		{
			lock (_syncRoot)
			{
				return _automaticAssignmentSidebar;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_automaticAssignmentSidebar != value)
				{
					_automaticAssignmentSidebar = value;
					SaveValue(nameof(AutomaticAssignmentSidebar), value);
					OnPropertyChanged(nameof(AutomaticAssignmentSidebar));
				}
			}
		}
	}


	/// <summary>
	/// Automatically check for updates on app startup.
	/// </summary>
	internal bool AutoCheckForUpdateAtStartup
	{
		get
		{
			lock (_syncRoot)
			{
				return _autoCheckForUpdateAtStartup;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_autoCheckForUpdateAtStartup != value)
				{
					_autoCheckForUpdateAtStartup = value;
					SaveValue(nameof(AutoCheckForUpdateAtStartup), value);
					OnPropertyChanged(nameof(AutoCheckForUpdateAtStartup));
				}
			}
		}
	}


	/// <summary>
	/// Selected language for the application
	/// </summary>	
	internal string ApplicationGlobalLanguage
	{
		get
		{
			lock (_syncRoot)
			{
				return _ApplicationGlobalLanguage;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_ApplicationGlobalLanguage != value)
				{
					_ApplicationGlobalLanguage = value;
					SaveValue(nameof(ApplicationGlobalLanguage), value);
					OnPropertyChanged(nameof(ApplicationGlobalLanguage));
				}
			}
		}
	}


	/// <summary>
	/// Whether the User Interface flow direction is Left-to-Right or Right-to-Left
	/// </summary>
	internal string ApplicationGlobalFlowDirection
	{
		get
		{
			lock (_syncRoot)
			{
				return _ApplicationGlobalFlowDirection;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_ApplicationGlobalFlowDirection != value)
				{
					_ApplicationGlobalFlowDirection = value;
					SaveValue(nameof(ApplicationGlobalFlowDirection), value);
					OnPropertyChanged(nameof(ApplicationGlobalFlowDirection));
				}
			}
		}
	}


	private void OnPropertyChanged(string propertyName) =>
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

