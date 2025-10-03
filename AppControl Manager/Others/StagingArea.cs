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

using System.IO;

namespace AppControlManager.Others;

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

		// Define a staging area
		string stagingArea = Path.Combine(GlobalVars.StagingArea, name);

		// Delete it if it already exists with possible content from previous runs
		if (Directory.Exists(stagingArea))
		{
			Directory.Delete(stagingArea, true);
		}

		// Create the staging area
		DirectoryInfo stagingAreaInfo = Directory.CreateDirectory(stagingArea);

		return stagingAreaInfo;
	}
}
