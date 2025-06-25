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

namespace AppControlManager.Others;

internal static class ProcessStarter
{
	/// <summary>
	/// Executes an executable with arguments
	/// </summary>
	/// <param name="command">The name of full path of the executable to run.</param>
	/// <param name="arguments">Optional arguments.</param>
	/// <exception cref="InvalidOperationException"></exception>
	/// <returns>The string output of the command</returns>
	internal static string RunCommand(string command, string? arguments = null)
	{

		ProcessStartInfo processInfo = new()
		{
			FileName = command,
			RedirectStandardOutput = true,
			RedirectStandardError = true,
			UseShellExecute = false,
			CreateNoWindow = true
		};

		if (arguments is not null)
		{
			processInfo.Arguments = arguments;
		}

		using Process process = new();
		process.StartInfo = processInfo;
		_ = process.Start();

		// Capture output and errors
		string output = process.StandardOutput.ReadToEnd();
		string error = process.StandardError.ReadToEnd();

		process.WaitForExit();

		if (process.ExitCode is not 0)
		{
			throw new InvalidOperationException(
				string.Format(
					GlobalVars.GetStr("CommandFailedWithExitCodeErrorMessage"),
					command,
					arguments,
					process.ExitCode,
					error
				)
			);
		}

		return output;
	}
}
