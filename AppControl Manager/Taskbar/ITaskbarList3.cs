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

namespace AppControlManager.Taskbar;

/// <summary>
/// Defining the COM interface, since we're manually wrapping we don't need [GeneratedComInterface]
/// </summary>
internal interface ITaskbarList3
{
	/// <summary>
	/// Initializes the taskbar list.
	/// </summary>
	int HrInit();

	/// <summary>
	/// Sets the progress value on the taskbar for a specified window handle.
	/// </summary>
	/// <param name="hwnd">the handle (HWND) to the window whose taskbar icon should display progress.</param>
	/// <param name="completed">the current progress value.</param>
	/// <param name="total">the total or maximum progress value.</param>
	/// <returns></returns>
	int SetProgressValue(IntPtr hwnd, ulong completed, ulong total);
}
