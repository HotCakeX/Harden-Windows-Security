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

public static class Microsoft365AppsSecurityBaselines
{
	/// <summary>
	/// Runs the Microsoft 365 Apps Security Baseline category
	/// </summary>
	public static void Invoke()
	{

		if (GlobalVars.Microsoft365SecurityBaselinePath is null)
		{
			throw new InvalidOperationException("The path to the Microsoft 365 Apps Security Baseline has not been set.");
		}

		ChangePSConsoleTitle.Set("🧁 M365 Apps Security'");

		Logger.LogMessage("Applying the Microsoft 365 Apps Security Baseline", LogTypeIntel.Information);
		Logger.LogMessage("Running the official PowerShell script included in the Microsoft 365 Apps Security Baseline file downloaded from Microsoft servers", LogTypeIntel.Information);

		string M365AppsBaselineScriptPath = Path.Combine(
		   GlobalVars.Microsoft365SecurityBaselinePath,
		   "Scripts",
		   "Baseline-LocalInstall.ps1"
	   );

		// Get the directory of the script
		string scriptDirectory = Path.GetDirectoryName(M365AppsBaselineScriptPath)!;

		// Set up the PowerShell command to be executed
		string Command = $"""
Set-Location -Path "{scriptDirectory}"; .\Baseline-LocalInstall.ps1 4>&1
""";

		_ = PowerShellExecutor.ExecuteScript(Command, false, true);

	}
}
