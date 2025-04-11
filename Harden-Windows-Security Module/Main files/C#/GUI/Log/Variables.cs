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

using System.Windows.Controls;

namespace HardenWindowsSecurity;

public static class GUILogs
{
	internal static UserControl? View;

	internal static Grid? ParentGrid;

	internal static TextBox? MainLoggerTextBox;

	internal static ScrollViewer? scrollerForOutputTextBox;

	// The Logger class refers to this variable before scrolling down the ScrollViewer
	// Setting this to true initially because the toggle button is set to "Checked" when the GUI logger view is loaded but that is visual only and does not trigger the Checked event that would set this variable to true.
	// without this initial assignment, switching to Logs page wouldn't have auto-scrolling capability until the toggle button is set to off and on again.
	internal static bool AutoScroll = true;
}
