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
using System.Text.RegularExpressions;

namespace HardenSystemSecurity.SecurityPolicy;

internal static partial class SecurityPolicyManager
{

	[GeneratedRegex(@"^([^=]+?)\s*=\s*(.+)$")]
	private static partial Regex SystemAccessFindingRegex();

	/// <summary>
	/// Core method that extracts [System Access] settings from lines of text.
	/// </summary>
	/// <param name="lines">Lines of text from the INF file</param>
	/// <returns>Dictionary of System Access settings</returns>
	private static Dictionary<string, string> ExtractSystemAccessSettingsCore(IEnumerable<string> lines)
	{
		Dictionary<string, string> settings = new(StringComparer.Ordinal);
		bool inSystemAccessSection = false;

		foreach (string line in lines)
		{
			string trimmedLine = line.Trim();

			// Check if we're entering the [System Access] section
			if (string.Equals(trimmedLine, "[System Access]", StringComparison.OrdinalIgnoreCase))
			{
				inSystemAccessSection = true;
				continue;
			}

			// Check if we're entering a different section
			if (trimmedLine.StartsWith('[') && trimmedLine.EndsWith(']') && !string.Equals(trimmedLine, "[System Access]", StringComparison.OrdinalIgnoreCase))
			{
				inSystemAccessSection = false;
				continue;
			}

			// If we're in the System Access section and the line contains a setting
			if (inSystemAccessSection && !string.IsNullOrEmpty(trimmedLine) && !trimmedLine.StartsWith(';'))
			{
				// Match both "key = value" and "key=value" formats just in case the format is different!
				Match match = SystemAccessFindingRegex().Match(trimmedLine);

				if (match.Success)
				{
					string key = match.Groups[1].Value.Trim();
					string value = match.Groups[2].Value.Trim();

					// Remove quotes if present, again just in case.
					if (value.StartsWith('"') && value.EndsWith('"'))
					{
						value = value[1..^1];
					}

					settings[key] = value;
				}
			}
		}

		return settings;
	}

	/// <summary>
	/// Extracts [System Access] settings from a StreamReader.
	/// </summary>
	/// <param name="reader">StreamReader for the INF content</param>
	/// <returns>Dictionary of System Access settings</returns>
	internal static Dictionary<string, string> ExtractSystemAccessSettingsFromReader(StreamReader reader)
	{
		// Lazy enumerable that reads lines from the StreamReader
		static IEnumerable<string> ReadAllLines(StreamReader reader)
		{
			string? line;
			while ((line = reader.ReadLine()) is not null)
			{
				yield return line;
			}
		}

		return ExtractSystemAccessSettingsCore(ReadAllLines(reader));
	}

}
