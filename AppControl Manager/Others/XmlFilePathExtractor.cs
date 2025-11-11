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
using AppControlManager.SiPolicy;

namespace AppControlManager.Others;

internal static class XmlFilePathExtractor
{
	/// <summary>
	/// Extracts all the file paths from the Allow rules in an App Control policy
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <returns></returns>
	internal static HashSet<string> GetFilePaths(string xmlFilePath)
	{
		// Initialize HashSet with StringComparer.OrdinalIgnoreCase to ensure case-insensitive, ordinal comparison
		HashSet<string> filePaths = new(StringComparer.OrdinalIgnoreCase);

		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = Management.Initialize(xmlFilePath, null);

		// Select all Allow FileRules
		if (policyObj.FileRules is not null)
		{
			foreach (object item in policyObj.FileRules)
			{
				if (item is Allow allowItem && !string.IsNullOrEmpty(allowItem.FilePath))
				{
					// Add the file path to the HashSet
					_ = filePaths.Add(allowItem.FilePath);
				}
			}
		}
		return filePaths;
	}
}
