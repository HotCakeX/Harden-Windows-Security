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

// Custom EventArgs class for navigation background changes
internal sealed class NavigationBackgroundChangedEventArgs(bool isBackgroundOn) : EventArgs
{
	internal bool IsBackgroundOn => isBackgroundOn;
}

internal static class NavigationBackgroundManager
{
	// Event for when the NavigationView background changes
	internal static event EventHandler<NavigationBackgroundChangedEventArgs>? NavViewBackgroundChange;

	// Method to invoke the event
	internal static void OnNavigationBackgroundChanged(bool isBackgroundOn)
	{
		// Raise the NavViewBackgroundChange event with the new background status
		NavViewBackgroundChange?.Invoke(
			null,
			new NavigationBackgroundChangedEventArgs(isBackgroundOn)
		);
	}
}
