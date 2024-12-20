using System;
using System.IO;

namespace AppControlManager;

internal static class StagingArea
{
	/// <summary>
	/// Creating a directory as a staging area for a job and returns the path to that directory
	/// </summary>
	/// <param name="name"></param>
	/// <returns></returns>
	/// <exception cref="ArgumentException"></exception>
	internal static DirectoryInfo NewStagingArea(string name)
	{
		if (string.IsNullOrWhiteSpace(name))
		{
			throw new ArgumentException("CmdletName cannot be null or whitespace", nameof(name));
		}

		// Define a staging area for the cmdlet
		string stagingArea = Path.Combine(GlobalVars.StagingArea, name);

		// Delete it if it already exists with possible content from previous runs
		if (Directory.Exists(stagingArea))
		{
			Directory.Delete(stagingArea, true);
		}

		// Create the staging area for the cmdlet
		DirectoryInfo stagingAreaInfo = Directory.CreateDirectory(stagingArea);

		return stagingAreaInfo;
	}
}
