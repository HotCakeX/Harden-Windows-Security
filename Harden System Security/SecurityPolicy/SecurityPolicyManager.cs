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
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using HardenSystemSecurity.GroupPolicy;

namespace HardenSystemSecurity.SecurityPolicy;

internal static partial class SecurityPolicyManager
{
	/*
	 E.g.,
	 Dictionary<string, string> settings = new()
        {
            { "PasswordComplexity", "0" },
            { "MinimumPasswordLength", "10" },
            { "PasswordHistorySize", "26" },
            { "MaximumPasswordAge", "24" },
            { "MinimumPasswordAge", "22" }
        };

        SecurityPolicyManager.SetSystemAccessPolicy(settings);
	 */

	/// <summary>
	/// Sets security policy values in the [System Access] section using secedit by accepting a dictionary of settings.
	/// </summary>
	/// <param name="systemAccessSettings">Dictionary where key is the setting name (e.g., "PasswordComplexity") and value is the setting value (e.g., "1")</param>
	/// <returns></returns>
	internal static void SetSystemAccessPolicy(Dictionary<string, string> systemAccessSettings)
	{
		if (systemAccessSettings.Count is 0)
		{
			throw new InvalidOperationException(GlobalVars.GetStr("NoSettingsProvided"));
		}

		string programDataPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		string secureWorkDir = Path.Combine(programDataPath, "HardenSystemSecurity");

		string uniqueSuffix = Guid.NewGuid().ToString("N");
		string tempSecurityTemplate = Path.Combine(secureWorkDir, $"policy_{uniqueSuffix}.inf");
		string tempSecurityDatabase = Path.Combine(secureWorkDir, $"policy_{uniqueSuffix}.sdb");

		try
		{
			Logger.Write(GlobalVars.GetStr("SettingSystemAccessPolicyViaSecedit"));

			// Ensure secure directory exists with proper ACLs
			EnsureSecureDirectory(secureWorkDir);

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
			Logger.Write(string.Format(GlobalVars.GetStr("CreatedSecurityTemplate"), tempSecurityTemplate));
			Logger.Write(string.Format(GlobalVars.GetStr("TemplateContent"), securityTemplate));

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

			using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException(GlobalVars.GetStr("FailedToStartSeceditProcess"));

			_ = process.WaitForExit(30000); // 30 second timeout

			string output = process.StandardOutput.ReadToEnd();
			string error = process.StandardError.ReadToEnd();

			Logger.Write(string.Format(GlobalVars.GetStr("SeceditExitCode"), process.ExitCode));

			if (!string.IsNullOrEmpty(output))
			{
				Logger.Write(string.Format(GlobalVars.GetStr("SeceditOutput"), output));
			}

			if (!string.IsNullOrEmpty(error))
			{
				Logger.Write(string.Format(GlobalVars.GetStr("SeceditError"), error));
			}

			if (process.ExitCode == 0)
			{
				Logger.Write(GlobalVars.GetStr("SeceditCompletedSuccessfully"));

				// Force a policy refresh
				RefreshPolicies.Refresh();
			}
			else
			{
				throw new InvalidOperationException(string.Format(GlobalVars.GetStr("SeceditFailedWithExitCode"), process.ExitCode));
			}
		}
		finally
		{
			if (Directory.Exists(secureWorkDir))
			{
				try
				{
					Directory.Delete(secureWorkDir, true);
				}
				catch (Exception dirDelEx)
				{
					Logger.Write(dirDelEx);
				}
			}
		}
	}

	/// <summary>
	/// Ensures the secure directory exists with required ACLs:
	/// - Administrators: Full Control
	/// - SYSTEM: Full Control
	/// - Users (Built-in Users group): Read & Execute (no write / delete)
	/// Inheritance is enabled for child objects.
	/// </summary>
	/// <param name="directoryPath">Target directory path</param>
	private static void EnsureSecureDirectory(string directoryPath)
	{
		if (Directory.Exists(directoryPath))
		{
			Directory.Delete(directoryPath, true);
		}

		DirectoryInfo directoryInfo = Directory.CreateDirectory(directoryPath);

		DirectorySecurity security = new();

		SecurityIdentifier adminsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
		SecurityIdentifier systemSid = new(WellKnownSidType.LocalSystemSid, null);
		SecurityIdentifier usersSid = new(WellKnownSidType.BuiltinUsersSid, null);

		const InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
		const PropagationFlags propagation = PropagationFlags.None;

		// Administrators - Full Control
		FileSystemAccessRule adminsRule = new(
			adminsSid,
			FileSystemRights.FullControl,
			inheritance,
			propagation,
			AccessControlType.Allow);

		// SYSTEM - Full Control
		FileSystemAccessRule systemRule = new(
			systemSid,
			FileSystemRights.FullControl,
			inheritance,
			propagation,
			AccessControlType.Allow);

		// Users - Read & Execute only
		FileSystemRights usersRights =
			FileSystemRights.ReadAndExecute |
			FileSystemRights.ListDirectory |
			FileSystemRights.ReadAttributes |
			FileSystemRights.ReadExtendedAttributes |
			FileSystemRights.ReadPermissions;

		FileSystemAccessRule usersRule = new(
			usersSid,
			usersRights,
			inheritance,
			propagation,
			AccessControlType.Allow);

		// Protect (disable inheritance) and clear existing ACLs first
		// Then set hardened rules
		security.SetAccessRuleProtection(true, false);
		security.SetAccessRule(adminsRule);
		security.SetAccessRule(systemRule);
		security.SetAccessRule(usersRule);

		directoryInfo.SetAccessControl(security);
	}

	/// <summary>
	/// Sets security policy values by reading [System Access] section from a file using secedit.
	/// </summary>
	/// <param name="filePath">Path to the .inf or .txt file containing security template with [System Access] section</param>
	internal static void SetSystemAccessPolicy(string filePath)
	{
		if (!File.Exists(filePath))
		{
			throw new FileNotFoundException(string.Format(GlobalVars.GetStr("FileNotFoundPath"), filePath));
		}

		Dictionary<string, string> systemAccessSettings = ExtractSystemAccessSettings(filePath);

		if (systemAccessSettings.Count == 0)
		{
			throw new InvalidOperationException(GlobalVars.GetStr("NoSystemAccessSettingsFoundInFile"));
		}

		Logger.Write(string.Format(GlobalVars.GetStr("ExtractedSystemAccessSettingsFromFile"), systemAccessSettings.Count, filePath));

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
		string[] lines = File.ReadAllLines(filePath);
		return ExtractSystemAccessSettingsCore(lines);
	}

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
