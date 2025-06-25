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
using Microsoft.Win32.SafeHandles;

namespace AppControlManager.Others;

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
		SafeFileHandle? handle = null;

		try
		{
			handle = NativeMethods.CreateFile(
				filePath,
				GENERIC_READ | GENERIC_WRITE,                   // Desired access.
				FILE_SHARE_READ | FILE_SHARE_WRITE,             // Share mode.
				IntPtr.Zero,                                    // Default security attributes.
				OPEN_EXISTING,                                  // Open only if the file exists.
				0,                                              // No special flags or attributes.
				IntPtr.Zero);                                   // No template file.

			if (handle.IsInvalid)
			{
				Logger.Write(
					string.Format(
						GlobalVars.GetStr("FileRequiresElevatedPermissionsMessage"),
						filePath
					)
				);

				return false;
			}
			else
			{
				return true;
			}
		}
		finally
		{
			handle?.Close();
		}
	}
}
