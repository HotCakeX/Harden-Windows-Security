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
using System.IO;
using System.Text.RegularExpressions;

namespace HardenWindowsSecurity;

internal static class IniFileConverter
{
	/// <summary>
	/// A helper method to parse the ini file from the output of the "Secedit /export /cfg .\security_policy.inf"
	/// </summary>
	/// <param name="iniFilePath"></param>
	/// <returns></returns>
	internal static Dictionary<string, Dictionary<string, string>> ConvertFromIniFile(string iniFilePath)
	{
		var iniObject = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
		string[] lines = File.ReadAllLines(iniFilePath);
		string sectionName = string.Empty;

		foreach (string line in lines)
		{
			// Match section headers
			Match sectionMatch = Regex.Match(line, @"^\[(.+)\]$");
			if (sectionMatch.Success)
			{
				sectionName = sectionMatch.Groups[1].Value;
				iniObject[sectionName] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
				continue;
			}

			// Match key-value pairs
			Match keyValueMatch = Regex.Match(line, @"^(.+?)\s*=\s*(.*)$");
			if (keyValueMatch.Success)
			{
				string keyName = keyValueMatch.Groups[1].Value;
				string keyValue = keyValueMatch.Groups[2].Value;

				if (!string.IsNullOrEmpty(sectionName))
				{
					iniObject[sectionName][keyName] = keyValue;
				}
				continue;
			}

			// Ignore blank lines or comments
			if (string.IsNullOrWhiteSpace(line) || line.StartsWith(';') || line.StartsWith('#'))
			{
				continue;
			}
		}

		return iniObject;
	}
}
