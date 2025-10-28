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
using System.Runtime.InteropServices;

namespace CommonCore.Others;

/// <summary>
/// Provides methods to control window display affinity for screen protection
/// </summary>
internal static class WindowDisplayAffinity
{
	/// <summary>
	/// Display affinity constants for SetWindowDisplayAffinity
	/// </summary>
	internal enum DisplayAffinity : uint
	{
		/// <summary>
		/// Imposes no restrictions on where the window can be displayed
		/// </summary>
		WDA_NONE = 0x00000000,

		/// <summary>
		/// The window content is displayed only on a monitor.
		/// Everywhere else, the window appears with no content.
		/// </summary>
		WDA_MONITOR = 0x00000001,

		/// <summary>
		/// The window is excluded from capture by other applications.
		/// This prevents screenshots and screen recording of the window.
		/// Available on Windows 10 version 2004 and later.
		/// </summary>
		WDA_EXCLUDEFROMCAPTURE = 0x00000011
	}

	/// <summary>
	/// Sets the display affinity for the specified window
	/// </summary>
	/// <param name="windowHandle">Handle to the window</param>
	/// <param name="affinity">The display affinity to set</param>
	/// <returns></returns>
	/// <exception cref="ArgumentException">Thrown when windowHandle is IntPtr.Zero</exception>
	/// <exception cref="Win32Exception">Thrown when the Windows API call fails</exception>
	internal static void SetWindowDisplayAffinity(IntPtr windowHandle, DisplayAffinity affinity)
	{
		if (windowHandle == IntPtr.Zero)
		{
			return;
		}

		try
		{
			if (!NativeMethods.SetWindowDisplayAffinity(windowHandle, (uint)affinity))
			{
				int errorCode = Marshal.GetLastPInvokeError();
				throw new Win32Exception(errorCode, $"SetWindowDisplayAffinity failed with error code: {errorCode}");
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}
}
