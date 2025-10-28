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

using System.Runtime.InteropServices;

namespace AppControlManager.Taskbar;

internal static class TaskBarProgress
{
	/// <summary>
	/// Updates the taskbar progress for the specified window
	/// </summary>
	/// <param name="hwnd">Window handle</param>
	/// <param name="completed">Amount of work completed</param>
	/// <param name="total">Total amount of work</param>
	/// <exception cref="COMException">Thrown when the operation fails</exception>
	internal static void UpdateTaskbarProgress(IntPtr hwnd, ulong completed, ulong total)
	{
		int result = NativeMethods.update_taskbar_progress(hwnd, completed, total, out int lastError);

		if (lastError != 0 && result != 0)
			Logger.Write($"Taskbar progress update failed with HRESULT: 0x{lastError:X8}");
	}
}
