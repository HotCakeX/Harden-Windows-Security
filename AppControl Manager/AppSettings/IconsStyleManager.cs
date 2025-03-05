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

// Custom EventArgs class for Icons Style changes
internal sealed class IconsStyleChangedEventArgs(string? newIconsStyle) : EventArgs
{
	internal string? NewIconsStyle { get; } = newIconsStyle;
}

internal static class IconsStyleManager
{
	// The static event for Icons Style changes
	// MainWindow listens to this to set the icons style
	internal static event EventHandler<IconsStyleChangedEventArgs>? IconsStyleChanged;

	// Method to raise the event when the icons styles change
	internal static void OnIconsStylesChanged(string newIconsStyle)
	{
		// Raise the IconsStyleChanged event with the new style
		IconsStyleChanged?.Invoke(
			null,
			new IconsStyleChangedEventArgs(newIconsStyle)
		);
	}
}
