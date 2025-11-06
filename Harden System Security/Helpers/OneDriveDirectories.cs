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
using System.IO;
using System.Linq;

namespace HardenSystemSecurity.Helpers;

internal static class OneDriveDirectories
{
	/// <summary>
	/// Retrieves the paths to all OneDrive directories on the system.
	/// These paths are under each user directory, they can start with OneDrive such as "OneDrive", "OneDrive Personal", "OneDrive Business" etc.
	/// </summary>
	/// <returns></returns>
	internal static string[] Get()
	{
		// List to store the OneDrive directories found
		List<string> directoriesList = [];

		// Combine system drive with "Users" to get the path to the Users directory
		string usersPath = Path.Combine(GlobalVars.SystemDrive, "Users");

		// catch to prevent unnecessary exception
		if (!Directory.Exists(usersPath))
			return [];

		try
		{
			// Enumerate all top-level directories under the Users directory
			IEnumerable<string> userDirectories = Directory.EnumerateDirectories(usersPath);

			foreach (string userDirectory in userDirectories)
			{
				try
				{
					// Enumerate directories within each user directory that start with "OneDrive"
					IEnumerable<string> directories = Directory.EnumerateDirectories(userDirectory, "OneDrive*", SearchOption.TopDirectoryOnly)
											   .Where(dir => dir.StartsWith(Path.Combine(userDirectory, "OneDrive"), StringComparison.OrdinalIgnoreCase));

					// Add each found directory to the list
					directoriesList.AddRange(directories);
				}
				catch (UnauthorizedAccessException)
				{
					// If access is denied to a directory, skip it
					continue;
				}
				catch (DirectoryNotFoundException)
				{
					// If a directory is not found (e.g., it was deleted), skip it
					continue;
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"An error occurred: {ex.Message}", LogTypeIntel.Error);
		}

		return directoriesList.ToArray();
	}
}
