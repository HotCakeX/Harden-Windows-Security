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
using System.Collections.Generic;
using System.Runtime.InteropServices;
using AppControlManager.Others;

namespace AppControlManager.IntelGathering;

internal static partial class DriveLetterMapper
{
	/// <summary>
	/// Class to store drive mapping information
	/// </summary>
	/// <param name="driveLetter">Property to store drive letter</param>
	/// <param name="volumeName">Property to store volume name</param>
	/// <param name="devicePath">Property to store device path</param>
	internal sealed class DriveMapping(string? driveLetter, string? volumeName, string? devicePath)
	{
		internal string? DriveLetter => driveLetter;
		internal string? DevicePath => devicePath;
		internal string? VolumeName => volumeName;
	}

	/// <summary>
	/// A method that gets the DriveLetter mappings in the global root namespace
	/// And fixes these: \Device\Harddiskvolume
	/// </summary>
	/// <returns>A list of DriveMapping objects containing drive information</returns>
	/// <exception cref="System.ComponentModel.Win32Exception"></exception>
	internal static List<DriveMapping> GetGlobalRootDrives()
	{
		// List to store drive mappings
		List<DriveMapping> drives = [];

		// Maximum buffer size for volume names, paths, and mount points
		const uint max = 65535;
		// char[] for storing volume names
		char[] volumeNameBuffer = new char[max];
		// char[] for storing path names
		char[] pathNameBuffer = new char[max];
		// char[] for storing mount points
		char[] mountPointBuffer = new char[max];
		// Variable to store the length of the return string
		uint lpcchReturnLength = 0;

		// Get the first volume handle
		IntPtr volumeHandle = NativeMethods.FindFirstVolume(volumeNameBuffer, max);

		// Check if the volume handle is valid
		if (volumeHandle == IntPtr.Zero)
		{
			throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
		}

		// Loop through all the volumes
		do
		{
			// Convert the volume name to a string, trimming any leftover null characters
			string volume = new string(volumeNameBuffer).TrimEnd('\0');
			// Get the mount point for the volume
			_ = NativeMethods.GetVolumePathNamesForVolumeNameW(volume, mountPointBuffer, max, ref lpcchReturnLength);
			// Get the device path for the volume
			uint returnLength = NativeMethods.QueryDosDevice(volume[4..^1], pathNameBuffer, (int)max);

			// Check if the device path is found
			if (returnLength > 0)
			{
				// Add a new drive mapping to the list with valid details
				drives.Add(new DriveMapping(
					// Extract the drive letter (mount point) from the buffer
					// Use Array.IndexOf to locate the first null character ('\0')
					// If null is not found, use the entire length of the buffer
					// Replace ":\" with ":" for consistent formatting
					driveLetter: new string(mountPointBuffer, 0, Array.IndexOf(mountPointBuffer, '\0') >= 0
						? Array.IndexOf(mountPointBuffer, '\0')
						: mountPointBuffer.Length)
						.Replace(@":\", ":", StringComparison.OrdinalIgnoreCase),

					// Assign the current volume name
					volumeName: volume,

					// Extract the device path from the buffer
					// Use Array.IndexOf to locate the first null character ('\0')
					// If null is not found, use the entire length of the buffer
					devicePath: new string(pathNameBuffer, 0, Array.IndexOf(pathNameBuffer, '\0') >= 0
						? Array.IndexOf(pathNameBuffer, '\0')
						: pathNameBuffer.Length)
				));
			}
			else
			{
				// Add a new drive mapping with a localized message when the path is invalid
				drives.Add(new DriveMapping(
					// No drive letter since the mount point is unavailable
					driveLetter: null,

					// Assign the current volume name
					volumeName: volume,

					// Use resource for the "No mountpoint found" message
					devicePath: GlobalVars.GetStr("NoMountpointFoundMessage")
				));
			}

		} while (NativeMethods.FindNextVolume(volumeHandle, volumeNameBuffer, max)); // Continue until there are no more volumes

		// Return the list of drive mappings
		return drives;
	}
}
