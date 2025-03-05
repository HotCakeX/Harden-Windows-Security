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

namespace AppControlManager.AppSettings;

// Custom EventArgs class for the event
internal sealed class BackgroundChangedEventArgs(string? newBackground) : EventArgs
{
	internal string? NewBackground { get; } = newBackground;
}

internal static class ThemeManager
{
	// The static event for background changes
	// MainWindow listens to this to set the app theme
	internal static event EventHandler<BackgroundChangedEventArgs>? BackDropChanged;

	// Method to raise the event when the background is changed
	internal static void OnBackgroundChanged(string newBackground)
	{
		BackDropChanged?.Invoke(null, new BackgroundChangedEventArgs(newBackground));
	}
}
