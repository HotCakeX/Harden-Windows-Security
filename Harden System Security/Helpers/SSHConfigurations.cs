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

namespace HardenSystemSecurity.Helpers;

internal static class SSHConfigurations
{

	private static readonly string UserDirectory = Path.Combine(GlobalVars.SystemDrive, "Users", Environment.UserName);
	private static readonly string SSHClientUserConfigDirectory = Path.Combine(UserDirectory, ".ssh");
	private static readonly string SSHClientUserConfigFile = Path.Combine(SSHClientUserConfigDirectory, "config");

	// Secure MACs configurations for SSH
	private const string sshConfigContent = "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com";

	internal static void SecureMACs()
	{

		Logger.Write(GlobalVars.GetStr("CheckingSSHClientUserConfiguration"), LogTypeIntel.Information);

		// First ensure the detected username is valid so we don't create a directory in non-existent user directory
		if (!Path.Exists(UserDirectory))
		{
			Logger.Write(string.Format(GlobalVars.GetStr("UserDirectoryNotFoundSkippingSSHClientConfigurationCheck"), UserDirectory, Environment.UserName), LogTypeIntel.Warning);
			return;
		}

		// Ensure the SSH client directory exists
		_ = Directory.CreateDirectory(SSHClientUserConfigDirectory);

		// Check if the configuration file exists
		if (!File.Exists(SSHClientUserConfigFile))
		{
			// If the file does not exist, create it with the required content
			File.WriteAllText(SSHClientUserConfigFile, sshConfigContent);
			Logger.Write(string.Format(GlobalVars.GetStr("SSHClientConfigFileCreatedBecauseDidNotExist"), sshConfigContent), LogTypeIntel.Information);
		}
		else
		{
			// If the file exists, read all lines into a list
			List<string> configLines = [.. File.ReadAllLines(SSHClientUserConfigFile)];

			// Check if any line starts with "MACs "
			bool lineExists = false;

			for (int i = 0; i < configLines.Count; i++)
			{
				if (configLines[i].StartsWith("MACs ", StringComparison.OrdinalIgnoreCase))
				{
					// If a line starts with "MACs ", replace it with the new one
					configLines[i] = sshConfigContent;
					lineExists = true;
					Logger.Write(GlobalVars.GetStr("ExistingMACsConfigurationFoundAndReplaced"), LogTypeIntel.Information);
					break;
				}
			}

			if (!lineExists)
			{
				// If no line starts with "MACs ", append the new line to the file
				configLines.Add(sshConfigContent);
				Logger.Write(GlobalVars.GetStr("MACsConfigurationNotFoundAddedNew"), LogTypeIntel.Information);
			}

			// Writing the modified content back to the file
			File.WriteAllLines(SSHClientUserConfigFile, configLines);
		}
	}


	/// <summary>
	/// First checks user configurations and then system-wide configurations for secure MACs configurations of the SSH client
	/// </summary>
	/// <returns>Returns bool</returns>
	internal static bool TestSecureMACs()
	{
		Logger.Write(GlobalVars.GetStr("CheckingSecureMACsInSSHClientUserConfiguration"), LogTypeIntel.Information);

		// Check if the user configurations directory exists in user directory
		// Check if the configuration file exists
		if (Directory.Exists(SSHClientUserConfigDirectory) && File.Exists(SSHClientUserConfigFile))
		{
			// Read all lines into a list
			List<string> configLines = [.. File.ReadAllLines(SSHClientUserConfigFile)];

			// Check if any line starts with "MACs "
			for (int i = 0; i < configLines.Count; i++)
			{
				if (configLines[i].StartsWith("MACs ", StringComparison.OrdinalIgnoreCase))
				{
					if (string.Equals(configLines[i], sshConfigContent, StringComparison.OrdinalIgnoreCase))
					{
						Logger.Write(GlobalVars.GetStr("ExistingMACsFoundInUserDirectoryMatchesSecure"), LogTypeIntel.Information);
						return true;
					}
					else
					{
						// Log when the MACs value does not match the secure configuration
						Logger.Write(string.Format(GlobalVars.GetStr("MACsConfigurationInUserDirectoryIsDifferent"), configLines[i]), LogTypeIntel.Information);
						return false;
					}
				}
			}
		}


		Logger.Write(GlobalVars.GetStr("CheckingSecureMACsInSSHClientSystemWideConfiguration"), LogTypeIntel.Information);

		// Check for secure MACs in the system-wide SSH configuration in %programdata%\ssh\ssh_config
		string programDataSSHConfigFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ssh", "ssh_config");

		// Check if the system-wide SSH configuration file exists
		if (File.Exists(programDataSSHConfigFile))
		{
			// Read all lines into a list
			List<string> configLines = [.. File.ReadAllLines(programDataSSHConfigFile)];

			// Check if any line starts with "MACs "
			for (int i = 0; i < configLines.Count; i++)
			{
				if (configLines[i].StartsWith("MACs ", StringComparison.OrdinalIgnoreCase))
				{
					if (string.Equals(configLines[i], sshConfigContent, StringComparison.OrdinalIgnoreCase))
					{
						Logger.Write(GlobalVars.GetStr("ExistingMACsFoundInSystemWideConfigurationMatchesSecure"), LogTypeIntel.Information);
						return true;
					}
					else
					{
						// Log when the MACs value does not match the secure configuration
						Logger.Write(string.Format(GlobalVars.GetStr("MACsConfigurationInSystemWideConfigurationIsDifferent"), configLines[i]), LogTypeIntel.Information);
						return false;
					}
				}
			}
		}

		// Log when returning false (no matching or secure MACs found)
		Logger.Write(GlobalVars.GetStr("NoSecureMACsFoundInUserAndSystemWideConfigurations"), LogTypeIntel.Information);
		return false;
	}

	internal static void RemoveSecureMACs()
	{
		// Remove the 'MACs' configuration line from the SSH client user config if the file exists.
		Logger.Write(GlobalVars.GetStr("AttemptingToRemoveMACsFromSSHClientUserConfiguration"), LogTypeIntel.Information);

		// Ensure the detected username is valid so we don't touch a non-existent user directory
		if (!Path.Exists(UserDirectory))
		{
			Logger.Write(string.Format(GlobalVars.GetStr("UserDirectoryNotFoundSkippingRemoval"), UserDirectory, Environment.UserName), LogTypeIntel.Warning);
			return;
		}

		// Proceed only if the SSH client configuration file exists
		if (!File.Exists(SSHClientUserConfigFile))
		{
			Logger.Write(GlobalVars.GetStr("SSHClientConfigurationFileNotFoundNothingToRemove"), LogTypeIntel.Information);
			return;
		}

		List<string> configLines = [.. File.ReadAllLines(SSHClientUserConfigFile)];
		int initialCount = configLines.Count;

		// Remove all lines that start with "MACs ", keeping the rest intact
		_ = configLines.RemoveAll(line => line.StartsWith("MACs ", StringComparison.OrdinalIgnoreCase));

		if (configLines.Count != initialCount)
		{
			// Ensure the file is writable in case it's read-only
			try
			{
				FileAttributes attributes = File.GetAttributes(SSHClientUserConfigFile);
				if ((attributes & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
				{
					File.SetAttributes(SSHClientUserConfigFile, attributes & ~FileAttributes.ReadOnly);
				}
			}
			catch
			{
				// If we can't read/set attributes, continue and attempt to write anyway.
			}

			File.WriteAllLines(SSHClientUserConfigFile, configLines);
			Logger.Write(GlobalVars.GetStr("RemovedMACsFromSSHClientUserConfigurationFile"), LogTypeIntel.Information);
		}
		else
		{
			Logger.Write(GlobalVars.GetStr("NoMACsConfigurationFoundToRemoveInSSHClientUserConfigurationFile"), LogTypeIntel.Information);
		}
	}
}
