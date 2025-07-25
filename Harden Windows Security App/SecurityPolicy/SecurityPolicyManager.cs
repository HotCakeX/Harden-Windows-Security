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
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using AppControlManager;
using AppControlManager.Others;

namespace HardenWindowsSecurity.SecurityPolicy;

internal static partial class SecurityPolicyManager
{

	/// <summary>
	/// Sets security policy values in the [System Access] section using secedit by accepting a dictionary of settings.
	/// </summary>
	/// <param name="systemAccessSettings">Dictionary where key is the setting name (e.g., "PasswordComplexity") and value is the setting value (e.g., "1")</param>
	/// <returns></returns>
	internal static void SetSystemAccessPolicy(Dictionary<string, string> systemAccessSettings)
	{
		if (systemAccessSettings.Count is 0)
		{
			throw new InvalidOperationException("No settings provided");
		}

		try
		{
			Logger.Write("Setting system access policy via secedit...");

			string tempSecurityTemplate = Path.GetTempFileName() + ".inf";
			string tempSecurityDatabase = Path.GetTempFileName() + ".sdb";

			try
			{
				// Build the [System Access] section
				StringBuilder systemAccessSection = new();

				foreach (KeyValuePair<string, string> setting in systemAccessSettings)
				{
					_ = systemAccessSection.AppendLine(CultureInfo.InvariantCulture, $"{setting.Key} = {setting.Value}");
				}

				// Create a security template with the system access settings
				string securityTemplate = $@"[Unicode]
Unicode=yes
[System Access]
{systemAccessSection}[Version]
signature=""$CHICAGO$""
Revision=1
";

				File.WriteAllText(tempSecurityTemplate, securityTemplate);
				Logger.Write($"Created security template: {tempSecurityTemplate}");
				Logger.Write($"Template content:\n{securityTemplate}");

				// Apply the security template using secedit
				ProcessStartInfo startInfo = new()
				{
					FileName = "secedit.exe",
					Arguments = $"/configure /db \"{tempSecurityDatabase}\" /cfg \"{tempSecurityTemplate}\" /areas SECURITYPOLICY",
					UseShellExecute = false,
					RedirectStandardOutput = true,
					RedirectStandardError = true,
					CreateNoWindow = true
				};

				using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start secedit process");

				_ = process.WaitForExit(30000); // 30 second timeout

				string output = process.StandardOutput.ReadToEnd();
				string error = process.StandardError.ReadToEnd();

				Logger.Write($"Secedit exit code: {process.ExitCode}");

				if (!string.IsNullOrEmpty(output))
					Logger.Write($"Secedit output: {output}");

				if (!string.IsNullOrEmpty(error))
					Logger.Write($"Secedit error: {error}");

				if (process.ExitCode == 0)
				{
					Logger.Write("Secedit completed successfully");

					// Force a policy refresh
					RefreshGroupPolicy();
				}
				else
				{
					throw new InvalidOperationException($"Secedit failed with exit code: {process.ExitCode}");
				}
			}
			finally
			{
				// Clean up temporary files
				try
				{
					if (File.Exists(tempSecurityTemplate))
						File.Delete(tempSecurityTemplate);

					if (File.Exists(tempSecurityDatabase))
						File.Delete(tempSecurityDatabase);
				}
				catch (Exception ex)
				{
					Logger.Write("Warning: Could not delete temporary files.");
					Logger.Write(ErrorWriter.FormatException(ex));
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write("Secedit method failed.");
			Logger.Write(ErrorWriter.FormatException(ex));
		}
	}

	/// <summary>
	/// Sets security policy values by reading [System Access] section from a file using secedit.
	/// </summary>
	/// <param name="filePath">Path to the .inf or .txt file containing security template with [System Access] section</param>
	internal static void SetSystemAccessPolicy(string filePath)
	{
		if (!File.Exists(filePath))
		{
			throw new FileNotFoundException($"File not found: {filePath}");
		}

		Dictionary<string, string> systemAccessSettings = ExtractSystemAccessSettings(filePath);

		if (systemAccessSettings.Count == 0)
		{
			throw new InvalidOperationException("No [System Access] settings found in the specified file");
		}

		Logger.Write($"Extracted {systemAccessSettings.Count} System Access settings from file: {filePath}");

		foreach (KeyValuePair<string, string> setting in systemAccessSettings)
		{
			Logger.Write($"  {setting.Key} = {setting.Value}");
		}

		SetSystemAccessPolicy(systemAccessSettings);
	}

	/// <summary>
	/// Extracts [System Access] settings from a security template file.
	/// </summary>
	/// <param name="filePath">Path to the file containing the security template</param>
	/// <returns>Dictionary of System Access settings</returns>
	private static Dictionary<string, string> ExtractSystemAccessSettings(string filePath)
	{
		Dictionary<string, string> settings = new(StringComparer.Ordinal);

		string[] lines = File.ReadAllLines(filePath);

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
				// Use regex to match both "key = value" and "key=value" formats just in case the format is different!
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
	/// Refreshes system policies.
	/// </summary>
	private static void RefreshGroupPolicy()
	{
		try
		{
			Logger.Write("Refreshing group policy with force option...");

			// true = machine policy, RP_FORCE = force refresh
			bool result = NativeMethods.RefreshPolicyEx(true, NativeMethods.RP_FORCE);

			Logger.Write($"Group policy refresh result: {result}");

			if (!result)
			{
				int error = Marshal.GetLastWin32Error();
				Logger.Write($"RefreshPolicyEx failed with error code: {error}");
			}
		}
		catch (Exception ex)
		{
			Logger.Write("Warning: Could not refresh group policy.");
			Logger.Write(ErrorWriter.FormatException(ex));
		}
	}


	[GeneratedRegex(@"^([^=]+?)\s*=\s*(.+)$")]
	private static partial Regex SystemAccessFindingRegex();

}
