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
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Management.Automation;
using Microsoft.Win32;

namespace HardenWindowsSecurity;

internal static class ProcessMitigationsApplication
{
	internal static void Apply()
	{

		// Group the data by ProgramName
		IGrouping<string?, ProcessMitigationsParser.ProcessMitigationsRecords>[] groupedMitigations = [.. GlobalVars.ProcessMitigations.GroupBy(pm => pm.ProgramName)];

		// Get the current process mitigations from the registry
		string[] allAvailableMitigations = (Registry.LocalMachine
			.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
			?.GetSubKeyNames()) ?? throw new InvalidOperationException("Failed to read registry keys.");

		// Create a PowerShell instance
		using PowerShell ps = PowerShell.Create();

		// Loop through each group to remove the mitigations, this way we apply clean set of mitigations in the next step
		Logger.LogMessage("Removing the existing process mitigations", LogTypeIntel.Information);
		foreach (IGrouping<string?, ProcessMitigationsParser.ProcessMitigationsRecords> group in groupedMitigations)
		{
			string? fileName = Path.GetFileName(group.Key);

			if (allAvailableMitigations.Contains(fileName))
			{
				try
				{
					Registry.LocalMachine.DeleteSubKeyTree(
						$@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{fileName}",
						false);
				}
				catch (Exception ex)
				{
					Logger.LogMessage($"Failed to remove {fileName}, it's probably protected by the system. {ex.Message}", LogTypeIntel.Error);
				}
			}
		}

		// Adding the process mitigations
		Logger.LogMessage("Adding the process mitigations", LogTypeIntel.Information);
		foreach (IGrouping<string?, ProcessMitigationsParser.ProcessMitigationsRecords> group in groupedMitigations)
		{
			// Clear previous commands
			ps.Commands.Clear();

			string? programName = group.Key;
			Logger.LogMessage($"Adding process mitigations for {programName}", LogTypeIntel.Information);

			string?[] enableMitigations = [.. group.Where(g => string.Equals(g.Action, "Enable", StringComparison.OrdinalIgnoreCase)).Select(g => g.Mitigation)];

			string?[] disableMitigations = [.. group.Where(g => string.Equals(g.Action, "Disable", StringComparison.OrdinalIgnoreCase)).Select(g => g.Mitigation)];

			// Create the command and add parameters
			PSCommand command = new();
			_ = command.AddCommand("Set-ProcessMitigation");
			_ = command.AddParameter("Name", programName);

			if (enableMitigations.Length > 0)
			{
				_ = command.AddParameter("Enable", enableMitigations);
			}

			if (disableMitigations.Length > 0)
			{
				_ = command.AddParameter("Disable", disableMitigations);
			}

			// Add the command to the PowerShell instance
			ps.Commands = command;
			_ = ps.Invoke();

			// Check for errors
			if (ps.HadErrors)
			{
				Collection<ErrorRecord> errors = ps.Streams.Error.ReadAll();
				foreach (ErrorRecord error in errors)
				{
					Logger.LogMessage($"Error: {error}", LogTypeIntel.Error);
				}
			}
		}
	}
}
