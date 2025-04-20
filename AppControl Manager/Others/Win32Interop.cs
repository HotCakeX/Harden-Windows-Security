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
using System.Runtime.InteropServices;

namespace AppControlManager.Others;

internal sealed partial class Win32InteropInternal
{
	// https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-getwindowplacement
	[LibraryImport("user32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool GetWindowPlacement(IntPtr hWnd, ref WINDOWPLACEMENT lpwndpl);

	[StructLayout(LayoutKind.Sequential)]
	internal struct WINDOWPLACEMENT
	{
		internal int length;
		internal int flags;
		internal ShowWindowCommands showCmd;
		internal POINT ptMinPosition;
		internal POINT ptMaxPosition;
		internal RECT rcNormalPosition;
	}

	internal enum ShowWindowCommands
	{
		SW_HIDE = 0,
		SW_SHOWNORMAL = 1,
		SW_SHOWMINIMIZED = 2,
		SW_SHOWMAXIMIZED = 3,
		SW_SHOWNOACTIVATE = 4,
		SW_SHOW = 5,
		SW_MINIMIZE = 6,
		SW_SHOWMINNOACTIVE = 7,
		SW_SHOWNA = 8,
		SW_RESTORE = 9,
		SW_SHOWDEFAULT = 10,
		SW_FORCEMINIMIZE = 11
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct POINT
	{
		internal int x;
		internal int y;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct RECT
	{
		internal int left;
		internal int top;
		internal int right;
		internal int bottom;
	}
}
