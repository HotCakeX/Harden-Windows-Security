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

namespace HardenWindowsSecurity;

internal static class ProcessStarter
{
	/// <summary>
	/// Executes an executable with arguments
	/// </summary>
	/// <param name="command"></param>
	/// <param name="arguments"></param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void RunCommand(string command, string? arguments = null, bool suppressError = false)
	{

		ProcessStartInfo processInfo;

		if (arguments is not null)
		{
			processInfo = new()
			{
				FileName = command,
				Arguments = arguments,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true
			};
		}
		else
		{
			processInfo = new()
			{
				FileName = command,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true
			};
		}

		using Process process = new();
		process.StartInfo = processInfo;
		_ = process.Start();

		// Capture output and errors
		string output = process.StandardOutput.ReadToEnd();
		string error = process.StandardError.ReadToEnd();

		process.WaitForExit();

		if (process.ExitCode != 0 && !suppressError)
		{
			throw new InvalidOperationException($"Command '{command} {arguments}' failed with exit code {process.ExitCode}. Error: {error}");
		}

	}
}
