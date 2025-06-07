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
using System.Threading.Channels;
using System.Threading.Tasks;

namespace AppControlManager.Others;

internal static class Logger
{
	// The Logs file path
	internal static readonly string LogFileName = Path.Combine(App.LogsDirectory, $"AppControlManager_Logs_{DateTime.Now:yyyy-MM-dd HH-mm-ss}.txt");

	// The log channel for high-performance asynchronous logging
	private static readonly Channel<string> _logChannel = Channel.CreateUnbounded<string>(new UnboundedChannelOptions
	{
		SingleReader = true,
		AllowSynchronousContinuations = false
	});

	// The StreamWriter used for writing to the log file
	private static readonly StreamWriter _streamWriter = new(
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

	static Logger()
	{
		// Check the size of the directory and clear it if it exceeds 1000 MB
		// To ensure the logs directory doesn't get too big
		if (GetDirectorySize(App.LogsDirectory) > 1000 * 1024 * 1024) // 1000 MB in bytes
		{
			// Empty the directory while retaining the most recent file
			EmptyDirectory(App.LogsDirectory);
		}

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
	/// Write the log to the file
	/// </summary>
	/// <param name="message"></param>
	internal static void Write(string message)
	{
		string logEntry = $"{DateTime.Now}: {message}";

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
}
