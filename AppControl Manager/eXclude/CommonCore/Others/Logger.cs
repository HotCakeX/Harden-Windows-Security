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
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace CommonCore.Others;

/// <summary>
/// Determines the type of log that was received and if it needs additional actions taken.
/// </summary>
internal enum LogTypeIntel
{
	Information,
	Error,
	Warning,
	InformationInteractionRequired, // Same as "Information" but also displays DialogBox to the user
	WarningInteractionRequired, // Same as "Warning" but also displays DialogBox to the user
	ErrorInteractionRequired, // Same as "Error" but also displays DialogBox to the user
}

internal static class Logger
{
	private static string LogsDirectory = null!;
	private static string AppName = null!;

#pragma warning disable CS0649
	/// <summary>
	/// Used to determine if the app is running in CLI mode.
	/// </summary>
	internal static bool CliRequested;
#pragma warning restore CS0649

	/// <summary>
	/// Called from the App class during app initialization to set up the logging system.
	/// </summary>
	/// <param name="logsDirectory"></param>
	/// <param name="appName"></param>
	internal static void Configure(string logsDirectory, string appName)
	{
		LogsDirectory = logsDirectory;
		AppName = appName;

		// Create the Logs directory if it doesn't exist, won't do anything if it exists
		_ = Directory.CreateDirectory(LogsDirectory);

		// Check the size of the directory and clear it if it exceeds 1000 MB
		// To ensure the logs directory doesn't get too big
		if (GetDirectorySize(LogsDirectory) > 1000 * 1024 * 1024) // 1000 MB in bytes
		{
			// Empty the directory while retaining the most recent file
			EmptyDirectory(LogsDirectory);
		}

		LogFileName = Path.Combine(LogsDirectory, $"{AppName}_Logs_{DateTime.Now:yyyy-MM-dd HH-mm-ss}.txt");

		_streamWriter = new(
			new FileStream(
				path: LogFileName,
				mode: FileMode.Append,
				access: FileAccess.Write,
				share: FileShare.Read,
				bufferSize: 4096,
				useAsync: true))
		{
			// Ensures log messages are written to disk right away, reducing the risk of data loss in case of a crash or unexpected termination.
			AutoFlush = true
		};

		// Start the background log processing task
		// allowing the log processing to run concurrently without blocking the main thread.
		_ = Task.Run(async () =>
		{
			// Asynchronously enumerates all available log messages from the channel.
			// The ReadAllAsync method ensures that the loop waits for new entries if none are available.
			await foreach (string log in _logChannel.Reader.ReadAllAsync())
			{
				await _streamWriter.WriteLineAsync(log);
			}
		});
	}

	/// <summary>
	/// The Logs file path
	/// </summary>
	internal static string LogFileName { get; private set; } = null!;

	/// <summary>
	/// The log channel for high-performance asynchronous logging
	/// </summary>
	private static readonly Channel<string> _logChannel = Channel.CreateUnbounded<string>(new UnboundedChannelOptions
	{
		SingleReader = true,
		AllowSynchronousContinuations = false
	});

	/// <summary>
	/// The StreamWriter used for writing to the log file
	/// </summary>
	private static StreamWriter _streamWriter = null!;

	/// <summary>
	/// Write the log to the file
	/// </summary>
	/// <param name="message"></param>
	internal static void Write(string message, LogTypeIntel logType = LogTypeIntel.Information)
	{
		string logEntry = $"{DateTime.Now}: {message}";

		if (CliRequested)
			Console.WriteLine(logEntry);

		// Enqueue the log message for asynchronous writing
		if (!_logChannel.Writer.TryWrite(logEntry))
		{
			//  If TryWrite returns false, falls back to writing directly to the log file asynchronously so no log messages are lost, even if the channel cannot accept new entries.
			_ = _streamWriter.WriteLineAsync(logEntry);
		}
	}

	// Overload that takes in Exceptions
	internal static void Write(Exception ex, LogTypeIntel logType = LogTypeIntel.Error)
	{
		string logEntry = $"{DateTime.Now}: {FormatException(ex)}";

		if (CliRequested)
			Console.Error.WriteLine(logEntry);

		// Enqueue the log message for asynchronous writing
		if (!_logChannel.Writer.TryWrite(logEntry))
		{
			//  If TryWrite returns false, falls back to writing directly to the log file asynchronously so no log messages are lost, even if the channel cannot accept new entries.
			_ = _streamWriter.WriteLineAsync(logEntry);
		}
	}

	private static long GetDirectorySize(string directoryPath)
	{
		long size = 0;

		// Get all files in the directory and its subdirectories
		FileInfo[] files = new DirectoryInfo(directoryPath).GetFiles("*", SearchOption.AllDirectories);

		foreach (FileInfo file in files)
		{
			// Add the size of each file to the total size
			size += file.Length;
		}

		// Return the total size in bytes
		return size;
	}

	private static void EmptyDirectory(string directoryPath)
	{
		// Get all files in the directory
		FileInfo[] files = new DirectoryInfo(directoryPath).GetFiles();

		// Sort files by last write time in descending order
		Array.Sort(files, (x, y) => y.LastWriteTime.CompareTo(x.LastWriteTime));

		// Retain the most recent file, delete others
		// Start from 1 to skip the most recent file
		for (int i = 1; i < files.Length; i++)
		{
			try
			{
				// Delete the file
				files[i].Delete();
			}
			catch
			{ }
		}
	}

	/// <summary>
	/// When an exception is raised by the app, writes the full details to the log file for review.
	/// Handles all types of exception hierarchies including AggregateExceptions and deeply nested scenarios.
	/// </summary>
	/// <param name="ex">The exception to format</param>
	/// <returns>Formatted string containing complete exception details</returns>
	private static string FormatException(Exception ex)
	{
		StringBuilder sb = new();
		HashSet<Exception> visited = new(ReferenceEqualityComparer.Instance);

		_ = sb.AppendLine("==== Exception Details ====");
		FormatExceptionRecursive(ex, sb, visited, 0, "Main");
		_ = sb.AppendLine("==============================");

		return sb.ToString();
	}

	/// <summary>
	/// Recursive helper method to format exception details in any exception hierarchy.
	/// Handles:
	/// - Direct exception formatting
	/// - AggregateException.InnerExceptions collections
	/// - Regular Exception.InnerException chains
	/// - Any combination and nesting of the above
	/// </summary>
	/// <param name="exception">Current exception to format</param>
	/// <param name="sb">StringBuilder to append formatted text to</param>
	/// <param name="visited">Set of already visited exceptions to prevent cycles</param>
	/// <param name="depth">Current nesting depth for indentation</param>
	/// <param name="label">Label to identify this exception (e.g., "Main", "Inner", "Aggregate Item 1")</param>
	private static void FormatExceptionRecursive(Exception exception, StringBuilder sb, HashSet<Exception> visited, int depth, string label)
	{
		// Prevent infinite loops from circular exception references
		if (!visited.Add(exception))
		{
			string circularIndent = new(' ', depth * 2);
			_ = sb.AppendLine($"{circularIndent}-- {label} Exception (Already Processed - Circular Reference) --");
			return;
		}

		// Format current exception details
		string indentString = new(' ', depth * 2);
		_ = sb.AppendLine($"{indentString}-- {label} Exception --");
		_ = sb.AppendLine($"{indentString}Message: {exception.Message}");
		_ = sb.AppendLine($"{indentString}Type: {exception.GetType().FullName}");
		_ = sb.AppendLine($"{indentString}Source: {exception.Source}");
		_ = sb.AppendLine($"{indentString}Stack Trace:");

		// Handle stack trace with proper indentation
		if (!string.IsNullOrEmpty(exception.StackTrace))
		{
			string[] stackLines = exception.StackTrace.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
			foreach (string line in stackLines)
			{
				_ = sb.AppendLine($"{indentString}{line}");
			}
		}
		else
		{
			_ = sb.AppendLine($"{indentString}(No stack trace available)");
		}

		// Handle AggregateException's inner exceptions collection
		if (exception is AggregateException aggregateEx)
		{
			if (aggregateEx.InnerExceptions.Count > 0)
			{
				_ = sb.AppendLine($"{indentString}Aggregate Inner Exceptions ({aggregateEx.InnerExceptions.Count} total):");

				for (int i = 0; i < aggregateEx.InnerExceptions.Count; i++)
				{
					Exception innerEx = aggregateEx.InnerExceptions[i];
					string aggregateLabel = $"Aggregate Item {i + 1}";
					_ = sb.AppendLine();
					FormatExceptionRecursive(innerEx, sb, visited, depth + 1, aggregateLabel);
				}
			}
		}

		// Handle regular InnerException chain (applies to ALL exception types)
		// This is crucial for formatting nested exceptions in non-AggregateException hierarchies
		if (exception.InnerException != null)
		{
			_ = sb.AppendLine();
			FormatExceptionRecursive(exception.InnerException, sb, visited, depth + 1, "Inner");
		}
	}
}
