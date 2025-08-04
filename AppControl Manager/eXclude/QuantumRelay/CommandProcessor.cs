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
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CommonCore.QuantumRelay;

#pragma warning disable CA1812

namespace QuantumRelay;

internal sealed class CommandProcessor
{
	private static readonly string CiToolPath = Path.Combine(
			Environment.GetFolderPath(Environment.SpecialFolder.System),
			"CiTool.exe");

	private const int CommandTimeoutMs = 300000;

	internal async Task<CommandResponse> ProcessCommandAsync(CommandRequest request, ClientSessionContext sessionContext, CancellationToken cancellationToken)
	{
		Stopwatch stopwatch = Stopwatch.StartNew();
		List<LogEntry> logs = [];

		try
		{
			LogEntry startLog = new(DateTime.UtcNow, LogLevel.Information, $"Processing command: {request.CommandType}");
			logs.Add(startLog);
			sessionContext.SendLog(startLog);

			return request.CommandType switch
			{
				QCommandType.CiTool => await ExecuteCiToolAsync(request, logs, sessionContext, cancellationToken),
				_ => await HandleUnsupportedCommandAsync(request, logs, sessionContext)
			};
		}
		catch (Exception ex)
		{
			LogEntry errorLog = new(DateTime.UtcNow, LogLevel.Error, $"Error processing command: {request.CommandType}", ex.ToString());
			logs.Add(errorLog);
			sessionContext.SendLog(errorLog);

			return new CommandResponse(
				success: false,
				output: string.Empty,
				errorOutput: string.Empty,
				exitCode: -1,
				errorMessage: $"Command processing failed: {ex.Message}",
				executionTimeMs: stopwatch.ElapsedMilliseconds,
				logs: logs);
		}
		finally
		{
			stopwatch.Stop();
		}
	}

	private async Task<CommandResponse> ExecuteCiToolAsync(CommandRequest request, List<LogEntry> logs, ClientSessionContext sessionContext, CancellationToken cancellationToken)
	{
		Stopwatch stopwatch = Stopwatch.StartNew();

		try
		{
			// Check if CiTool.exe exists
			if (!File.Exists(CiToolPath))
			{
				LogEntry errorLog = new(DateTime.UtcNow, LogLevel.Error, "CiTool.exe not found");
				logs.Add(errorLog);
				sessionContext.SendLog(errorLog);

				return new CommandResponse(
					success: false,
					output: string.Empty,
					errorOutput: string.Empty,
					exitCode: -1,
					errorMessage: $"CiTool.exe not found at expected location: {CiToolPath}",
					executionTimeMs: stopwatch.ElapsedMilliseconds,
					logs: logs);
			}

			ProcessStartInfo startInfo = new()
			{
				FileName = CiToolPath,
				Arguments = string.Join(" ", request.Arguments),
				UseShellExecute = false,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				CreateNoWindow = true,
				WindowStyle = ProcessWindowStyle.Hidden
			};

			using Process process = new() { StartInfo = startInfo };

			StringBuilder outputBuilder = new();
			StringBuilder errorBuilder = new();

			// Real-time output processing with immediate log sending
			process.OutputDataReceived += (sender, e) =>
			{
				if (!string.IsNullOrEmpty(e.Data))
				{
					_ = outputBuilder.AppendLine(e.Data);

					// Send output data immediately to client as log
					LogEntry outputLog = new(DateTime.UtcNow, LogLevel.Information, $"CiTool Output: {e.Data}");
					logs.Add(outputLog);
					sessionContext.SendLog(outputLog);
				}
			};

			process.ErrorDataReceived += (sender, e) =>
			{
				if (!string.IsNullOrEmpty(e.Data))
				{
					_ = errorBuilder.AppendLine(e.Data);

					// Send error data immediately to client as log
					LogEntry errorLog = new(DateTime.UtcNow, LogLevel.Warning, $"CiTool Error: {e.Data}");
					logs.Add(errorLog);
					sessionContext.SendLog(errorLog);
				}
			};

			bool started = process.Start();
			if (!started)
			{
				LogEntry errorLog = new(DateTime.UtcNow, LogLevel.Error, "Failed to start CiTool.exe process");
				logs.Add(errorLog);
				sessionContext.SendLog(errorLog);

				return new CommandResponse(
					success: false,
					output: string.Empty,
					errorOutput: string.Empty,
					exitCode: -1,
					errorMessage: "Failed to start CiTool.exe process",
					executionTimeMs: stopwatch.ElapsedMilliseconds,
					logs: logs);
			}

			LogEntry startedLog = new(DateTime.UtcNow, LogLevel.Information, $"CiTool.exe started with PID: {process.Id}");
			logs.Add(startedLog);
			sessionContext.SendLog(startedLog);

			process.BeginOutputReadLine();
			process.BeginErrorReadLine();

			using CancellationTokenSource timeoutCts = new(CommandTimeoutMs);
			using CancellationTokenSource combinedCts = CancellationTokenSource.CreateLinkedTokenSource(
				cancellationToken, timeoutCts.Token);

			try
			{
				await process.WaitForExitAsync(combinedCts.Token);
			}
			catch (OperationCanceledException)
			{
				if (!process.HasExited)
				{
					try
					{
						process.Kill(true);
						await process.WaitForExitAsync(CancellationToken.None);

						LogEntry killedLog = new(DateTime.UtcNow, LogLevel.Warning, "Process killed due to timeout/cancellation");
						logs.Add(killedLog);
						sessionContext.SendLog(killedLog);
					}
					catch (Exception killEx)
					{
						LogEntry killErrorLog = new(DateTime.UtcNow, LogLevel.Error, "Error killing timed-out process", killEx.ToString());
						logs.Add(killErrorLog);
						sessionContext.SendLog(killErrorLog);
					}
				}

				string timeoutMessage = cancellationToken.IsCancellationRequested
					? "Command execution was cancelled"
					: $"Command execution timed out after {CommandTimeoutMs}ms";

				LogEntry timeoutLog = new(DateTime.UtcNow, LogLevel.Error, timeoutMessage);
				logs.Add(timeoutLog);
				sessionContext.SendLog(timeoutLog);

				return new CommandResponse(
					success: false,
					output: string.Empty,
					errorOutput: string.Empty,
					exitCode: -1,
					errorMessage: timeoutMessage,
					executionTimeMs: stopwatch.ElapsedMilliseconds,
					logs: logs);
			}

			string standardOutput = outputBuilder.ToString().Trim();
			string standardError = errorBuilder.ToString().Trim();
			int exitCode = process.ExitCode;

			stopwatch.Stop();

			bool success = exitCode == 0;
			LogEntry completedLog = new(DateTime.UtcNow, LogLevel.Information,
				$"CiTool command completed: Exit Code {exitCode}, Duration: {stopwatch.ElapsedMilliseconds}ms");
			logs.Add(completedLog);
			sessionContext.SendLog(completedLog);

			CommandResponse response = new(
				success: success,
				output: standardOutput,
				errorOutput: standardError,
				exitCode: exitCode,
				errorMessage: success ? string.Empty : $"CiTool.exe exited with code {exitCode}",
				executionTimeMs: stopwatch.ElapsedMilliseconds,
				logs: logs);

			return response;
		}
		catch (Exception ex)
		{
			LogEntry exceptionLog = new(DateTime.UtcNow, LogLevel.Error, "Error executing CiTool command", ex.ToString());
			logs.Add(exceptionLog);
			sessionContext.SendLog(exceptionLog);

			return new CommandResponse(
				success: false,
				output: string.Empty,
				errorOutput: string.Empty,
				exitCode: -1,
				errorMessage: $"CiTool execution failed: {ex.Message}",
				executionTimeMs: stopwatch.ElapsedMilliseconds,
				logs: logs);
		}
	}

	private async Task<CommandResponse> HandleUnsupportedCommandAsync(CommandRequest request, List<LogEntry> logs, ClientSessionContext sessionContext)
	{
		await Task.CompletedTask;

		LogEntry unsupportedLog = new(DateTime.UtcNow, LogLevel.Error, $"Unsupported command type: {request.CommandType}");
		logs.Add(unsupportedLog);
		sessionContext.SendLog(unsupportedLog);

		return new CommandResponse(
			success: false,
			output: string.Empty,
			errorOutput: string.Empty,
			exitCode: -1,
			errorMessage: $"Unsupported command type: {request.CommandType}. Currently supported commands: {QCommandType.CiTool}",
			executionTimeMs: 0,
			logs: logs);
	}
}
