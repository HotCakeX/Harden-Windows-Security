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
using System.Text.RegularExpressions;

namespace AppControlManager.XMLOps;

internal static partial class CheckForAllowAll
{
	/// <summary>
	/// Takes a XML file path and checks whether it has an allow all rule
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <returns></returns>
	internal static bool Check(string xmlFilePath)
	{
		// Read the content of the XML file into a string
		string xmlContent = File.ReadAllText(xmlFilePath);

		Regex allowAllRegex = MyRegex();

		// Check if the pattern matches the XML content
		return allowAllRegex.IsMatch(xmlContent);
	}

	[GeneratedRegex(@"<Allow ID=""ID_ALLOW_.*"" FriendlyName="".*"" FileName=""\*"".*/>", RegexOptions.Compiled)]
	private static partial Regex MyRegex();
}
