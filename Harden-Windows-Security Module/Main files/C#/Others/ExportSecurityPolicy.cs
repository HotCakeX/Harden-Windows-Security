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
using System.Diagnostics;
using System.IO;

namespace HardenWindowsSecurity;

public partial class ConfirmSystemComplianceMethods
{
	/// <summary>
	/// Get the security group policies by utilizing the Secedit.exe
	/// </summary>
	internal static void ExportSecurityPolicy()
	{
		// Create the process start info
		ProcessStartInfo processStartInfo = new()
		{
			FileName = Path.Combine(GlobalVars.SystemDrive, "Windows", "System32", "Secedit.exe"),
			Arguments = $"/export /cfg \"{GlobalVars.securityPolicyInfPath}\"",
			// RedirectStandardOutput = false,
			RedirectStandardError = true,
			UseShellExecute = false,
			CreateNoWindow = true
		};

		// Start the process
		using Process? process = Process.Start(processStartInfo) ?? throw new InvalidOperationException("Failed to start Secedit.exe process.");

		// Read the output
		// string output = process.StandardOutput.ReadToEnd();
		string error = process.StandardError.ReadToEnd();

		process.WaitForExit();

		if (!string.IsNullOrEmpty(error))
		{
			Logger.LogMessage("Error: " + error, LogTypeIntel.Error);
		}
	}
}
