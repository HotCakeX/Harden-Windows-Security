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

namespace CommonCore.Others;

internal static class FileAccessCheck
{

	// Constants from the Windows API.
	private const uint GENERIC_READ = 0x80000000;
	private const uint GENERIC_WRITE = 0x40000000;
	private const uint FILE_SHARE_READ = 0x00000001;
	private const uint FILE_SHARE_WRITE = 0x00000002;
	private const uint OPEN_EXISTING = 3;

	/// <summary>
	/// Checks if the file can be opened with both read and write permissions using native API.
	/// </summary>
	/// <param name="filePath">The full path to the file.</param>
	/// <returns>True if the file is accessible for modification; otherwise, false.</returns>
	internal static bool IsFileAccessibleForWrite(string filePath)
	{
		// Open with read + write access, sharing read & write.
		IntPtr handle = NativeMethods.CreateFileW(
			filePath,
			GENERIC_READ | GENERIC_WRITE,          // Desired access
			FILE_SHARE_READ | FILE_SHARE_WRITE,    // Share mode
			IntPtr.Zero,                           // Security attributes
			OPEN_EXISTING,                         // Creation disposition
			0,                                     // Flags & attributes (none special)
			IntPtr.Zero);                          // Template

		if (handle == NativeMethods.INVALID_HANDLE_VALUE)
		{
			Logger.Write(
				string.Format(
					GlobalVars.GetStr("FileRequiresElevatedPermissionsMessage"),
					filePath
				)
			);
			return false;
		}

		// We do not need the handle beyond this point so closing it immediately.
		if (!NativeMethods.CloseHandle(handle))
		{
			int closeErr = Marshal.GetLastPInvokeError();
			Logger.Write($"CloseHandle failed for {filePath} with error {closeErr}");
		}

		return true;
	}
}
