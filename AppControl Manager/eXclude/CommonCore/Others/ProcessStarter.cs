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

using System.Diagnostics;
using System.Threading.Tasks;

namespace CommonCore.Others;

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

	/// <summary>
	/// Executes an executable with arguments, writing Standard Output lines in real time
	/// and throwing immediately on the first line received from the Error stream.
	/// </summary>
	/// <param name="command">The name or full path of the executable to run.</param>
	/// <param name="arguments">Optional arguments.</param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException">Thrown immediately upon receiving any Error line.</exception>
	internal static void RunCommandInRealTime(InfoBarSettings infoBar, string command, string? arguments = null)
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

		// Task for Standard Output
		Task stdoutTask = Task.Run(() =>
		{
			while (true)
			{
				string? line = process.StandardOutput.ReadLine();
				if (line is null)
				{
					break;
				}

				// Real-time logging of each stdout line
				infoBar.WriteInfo(line);
			}
		});

		// Task for Standard Error
		Task stderrTask = Task.Run(() =>
		{
			while (true)
			{
				string? line = process.StandardError.ReadLine();
				if (line is null)
				{
					break;
				}

				// On first error line, attempt to terminate the process (if still running) to obtain an exit code,
				// then construct and store the exception to be thrown by the main thread.
				int exitCode = -1;

				try
				{
					if (!process.HasExited)
					{
						// Kill the process tree to ensure fast termination and access to ExitCode.
						try
						{
							process.Kill(true);
						}
						catch
						{
							// Ignored - process might have exited naturally in the meantime.
						}
					}

					// Ensure we wait for the process to exit so ExitCode becomes available.
					try
					{
						process.WaitForExit();
					}
					catch { }

					if (process.HasExited)
					{
						exitCode = process.ExitCode;
					}
				}
				catch
				{
					// If anything goes wrong determining exit code, we retain the default -1.
				}

#if DEBUG
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("CommandFailedWithExitCodeErrorMessage"),
						command,
						arguments,
						exitCode,
						line
					)
				);
#else
				// In release builds, omit command and arguments from error message for security.
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("CommandFailedWithExitCodeErrorMessage"),
						string.Empty,
						string.Empty,
						exitCode,
						line
					)
				);

#endif
			}
		});

		// Wait for both reading tasks to complete (or an early error).
		Task.WaitAll(stdoutTask, stderrTask);

		// Ensure process has exited
		process.WaitForExit();

		// throw if process exited with a non-zero exit code even if nothing was written to stderr.
		if (process.ExitCode != 0)
		{
#if DEBUG
			throw new InvalidOperationException(
				string.Format(
					GlobalVars.GetStr("CommandFailedWithExitCodeErrorMessage"),
					command,
					arguments,
					process.ExitCode,
					string.Empty
				)
			);
#else
			// In release builds, omit command and arguments from error message for security.
			throw new InvalidOperationException(
							string.Format(
								GlobalVars.GetStr("CommandFailedWithExitCodeErrorMessage"),
								string.Empty,
								string.Empty,
								process.ExitCode,
								string.Empty
							)
						);

#endif
		}
	}
}
