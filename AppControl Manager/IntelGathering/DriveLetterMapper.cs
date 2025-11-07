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

using System.Collections.Generic;
using System.Runtime.InteropServices;

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
	/// Returns the root path of the EFI System Partition (ESP) as a Volume GUID path,
	/// for example: "\\?\Volume{GUID}\".
	/// The returned path can be used directly with Directory APIs.
	/// </summary>
	/// <returns>null if no EFI partition is found or accessible, otherwise the EFI partition root.</returns>
	internal static string? GetEfiPartitionRootPath()
	{
		// Get all volume names (Volume GUID paths).
		List<DriveMapping> drives = GetGlobalRootDrives();

		// Scan volumes and pick the first one that contains an "EFI" directory at its root.
		// This works even when the partition has no drive letter.
		for (int i = 0; i < drives.Count; i++)
		{
			string? volume = drives[i].VolumeName;
			if (string.IsNullOrEmpty(volume))
			{
				continue;
			}

			// Volume names returned by FindFirst/NextVolume usually include a trailing backslash.
			// Build the path to the well-known "EFI" directory.
			string efiDirPath = string.Concat(volume, "EFI");

			try
			{
				// Directory.Exists will return false on inaccessible or non-existent paths.
				if (System.IO.Directory.Exists(efiDirPath))
				{
					// Found the ESP. Return its root Volume GUID path.
					return volume;
				}
			}
			catch
			{
				// Ignore any exceptional volumes and continue scanning the rest.
			}
		}

		// Not found
		return null;
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
		IntPtr volumeHandle = NativeMethods.FindFirstVolumeW(volumeNameBuffer, max);

		// Check if the volume handle is valid
		if (volumeHandle == NativeMethods.INVALID_HANDLE_VALUE)
		{
			int error = Marshal.GetLastPInvokeError(); // capture error immediately
			throw new System.ComponentModel.Win32Exception(error);
		}

		try
		{

			// Loop through all the volumes
			do
			{
				// Convert the volume name to a string, trimming any leftover null characters
				string volume = new string(volumeNameBuffer).TrimEnd('\0');
				// Get the mount point for the volume
				_ = NativeMethods.GetVolumePathNamesForVolumeNameW(volume, mountPointBuffer, max, ref lpcchReturnLength);
				// Get the device path for the volume
				uint returnLength = NativeMethods.QueryDosDeviceW(volume[4..^1], pathNameBuffer, (int)max);

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

			} while (NativeMethods.FindNextVolumeW(volumeHandle, volumeNameBuffer, max)); // Continue until there are no more volumes

		}
		finally
		{
			if (volumeHandle != NativeMethods.INVALID_HANDLE_VALUE)
			{
				_ = NativeMethods.FindVolumeClose(volumeHandle);
			}
		}

		// Return the list of drive mappings
		return drives;
	}
}
