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

public static partial class MicrosoftSecurityBaselines
{
	/// <summary>
	/// Runs the Microsoft Security Baseline category
	/// </summary>
	/// <exception cref="Exception"></exception>
	public static void Invoke()
	{
		if (GlobalVars.MicrosoftSecurityBaselinePath is null)
		{
			throw new InvalidOperationException("The path to the Microsoft Security Baselines has not been set.");
		}

		ChangePSConsoleTitle.Set("🔐 Security Baselines");

		Logger.LogMessage("Applying the Microsoft Security Baselines", LogTypeIntel.Information);
		Logger.LogMessage("Running the official PowerShell script included in the Microsoft Security Baseline file downloaded from Microsoft servers", LogTypeIntel.Information);

		// Define the path to the script
		string baselineScriptPath = Path.Combine(
			GlobalVars.MicrosoftSecurityBaselinePath,
			"Scripts",
			"Baseline-LocalInstall.ps1"
		);

		// Get the directory of the script
		string scriptDirectory = Path.GetDirectoryName(baselineScriptPath)!;

		// Set up the PowerShell command to be executed
		string Command = $"""
Set-Location -Path "{scriptDirectory}"; .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined 4>&1
""";

		_ = PowerShellExecutor.ExecuteScript(Command, false, true);
	}
}
