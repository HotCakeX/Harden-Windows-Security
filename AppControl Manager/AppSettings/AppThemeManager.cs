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

namespace AppControlManager.AppSettings;

// Custom EventArgs class for app theme changes
internal sealed class AppThemeChangedEventArgs(string? newTheme) : EventArgs
{
	internal string? NewTheme => newTheme;
}

internal static class AppThemeManager
{
	// The static event for App theme dark/light changes
	// MainWindow listens to this
	internal static event EventHandler<AppThemeChangedEventArgs>? AppThemeChanged;

	// Method to raise the event
	internal static void OnAppThemeChanged(string newTheme)
	{
		// Trigger the AppThemeChanged event with the new theme
		AppThemeChanged?.Invoke(null, new AppThemeChangedEventArgs(newTheme));
	}
}
