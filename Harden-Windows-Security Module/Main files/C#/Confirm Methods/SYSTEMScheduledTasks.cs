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
using System.IO;

namespace HardenWindowsSecurity;

internal static class SYSTEMScheduledTasks
{
	internal static void Invoke()
	{
		Logger.LogMessage("Collecting Intune applied policy details from the System", LogTypeIntel.Information);

		// Path to the PowerShell script
		string scriptPath = Path.Combine(GlobalVars.path, "Shared", "SYSTEMInfoGathering.ps1");

		// Load the PowerShell script into a string
		string script = File.ReadAllText(scriptPath);

		// Replace the BaseDirectory placeholder with the actual value
		script = script.Replace("[System.String]$BaseDirectory = [HardenWindowsSecurity.GlobalVars]::WorkingDir", $"[System.String]$BaseDirectory = '{GlobalVars.WorkingDir}'", StringComparison.OrdinalIgnoreCase);

		// Run the PowerShell script
		_ = PowerShellExecutor.ExecuteScript(script);
	}
}
