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

namespace HardenWindowsSecurity;

internal static class GitExesFinder
{
	/// <summary>
	/// This method searches for .exe files in the specified path for Standalone Git program and returns a list of FileInfo objects
	/// </summary>
	/// <returns></returns>
	internal static List<FileInfo>? Find()
	{
		// Define the base path to search
		string basePath = Path.Combine(GlobalVars.SystemDrive, "Program Files", "Git");

		// Check if the base path exists
		if (!Directory.Exists(basePath))
		{
			return null;
		}

		// Get all directories under the base path
		string[] directories = Directory.GetDirectories(basePath, "*", SearchOption.AllDirectories);

		// Initialize a list to store the found FileInfo objects
		List<FileInfo> fileList = [];

		// Iterate through each directory
		foreach (string dir in directories)
		{
			// Get all .exe files in the current directory
			string[] files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
			// Add each FileInfo object to the list
			fileList.AddRange(files.Select(file => new FileInfo(file)));
		}

		// Return null if no files were found
		if (fileList.Count is 0)
		{
			return null;
		}

		// Return the list of FileInfo objects
		return fileList;
	}
}
