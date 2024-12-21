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
