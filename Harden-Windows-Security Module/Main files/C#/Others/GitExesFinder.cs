using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace HardenWindowsSecurity;

internal static class GitExesFinder
{
	// This method searches for .exe files in the specified path for Standalone Git program and returns a list of FileInfo objects
	internal static List<FileInfo>? Find()
	{
		// Define the base path to search
		string basePath = @"C:\Program Files\Git";

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
		if (fileList.Count == 0)
		{
			return null;
		}

		// Return the list of FileInfo objects
		return fileList;
	}
}
