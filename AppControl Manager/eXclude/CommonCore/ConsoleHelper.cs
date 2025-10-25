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

using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace CommonCore;

internal static partial class ConsoleHelper
{

	/// <summary>
	/// https://learn.microsoft.com/windows/console/attachconsole
	/// </summary>
	private const int ATTACH_PARENT_PROCESS = -1;

	private const int ERROR_ACCESS_DENIED = 5;

	// Single lifetime owner for console bindings; disposed at process exit.
	private static ConsoleLifetime? s_lifetime;
	private static bool s_cleanupRegistered;

	// Attaches to parent console if present; otherwise allocates a new console.
	internal static void AttachOrAllocate()
	{
		int attachResult = NativeMethods.AttachConsole(ATTACH_PARENT_PROCESS);
		if (attachResult == 0)
		{
			int attachError = Marshal.GetLastPInvokeError();

			// ERROR_ACCESS_DENIED means the process already has a console; treat as success.
			if (attachError != ERROR_ACCESS_DENIED)
			{
				int allocResult = NativeMethods.AllocConsole();
				if (allocResult == 0)
				{
					int allocError = Marshal.GetLastPInvokeError();
					throw new InvalidOperationException($"Failed to attach or allocate console. LastError={allocError}");
				}
			}
		}

		if (s_lifetime is null)
		{
			Encoding utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
			s_lifetime = new ConsoleLifetime(utf8NoBom);

			if (!s_cleanupRegistered)
			{
				AppDomain.CurrentDomain.ProcessExit += static (_, __) =>
				{
					try
					{
						ConsoleLifetime? lifetime = s_lifetime;
						lifetime?.Dispose();
					}
					catch
					{
						// Swallow exceptions on process exit cleanup.
					}
				};
				s_cleanupRegistered = true;
			}
		}
	}

	/// <summary>
	/// Owns console streams and writers/readers and resets Console on dispose.
	/// </summary>
	private sealed partial class ConsoleLifetime : IDisposable
	{
		private readonly Stream _stdoutStream;
		private readonly Stream _stderrStream;
		private readonly Stream _stdinStream;

		private readonly StreamWriter _outWriter;
		private readonly StreamWriter _errWriter;
		private readonly StreamReader _inReader;

		private bool _disposed;

		internal ConsoleLifetime(Encoding encoding)
		{
			// Open managed streams bound to the current console.
			_stdoutStream = Console.OpenStandardOutput();
			_stderrStream = Console.OpenStandardError();
			_stdinStream = Console.OpenStandardInput();

			if (!_stdoutStream.CanWrite)
			{
				throw new InvalidOperationException("Standard output is not writable after console initialization.");
			}
			if (!_stderrStream.CanWrite)
			{
				throw new InvalidOperationException("Standard error is not writable after console initialization.");
			}
			if (!_stdinStream.CanRead)
			{
				throw new InvalidOperationException("Standard input is not readable after console initialization.");
			}

			// Writers/readers do not own the underlying streams (leaveOpen: true).
			_outWriter = new StreamWriter(_stdoutStream, encoding, bufferSize: 4096, leaveOpen: true)
			{
				AutoFlush = true
			};
			_errWriter = new StreamWriter(_stderrStream, encoding, bufferSize: 4096, leaveOpen: true)
			{
				AutoFlush = true
			};
			_inReader = new StreamReader(_stdinStream, encoding, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);

			// Bind to Console and set encodings.
			Console.SetOut(_outWriter);
			Console.SetError(_errWriter);
			Console.SetIn(_inReader);
			Console.OutputEncoding = encoding;
			Console.InputEncoding = encoding;
		}

		public void Dispose()
		{
			if (_disposed)
			{
				return;
			}
			_disposed = true;

			try
			{
				try
				{
					_outWriter.Flush();
					_errWriter.Flush();
				}
				catch
				{
				}

				// Reset Console to safe sinks before disposing our writers/readers.
				Console.SetOut(TextWriter.Synchronized(TextWriter.Null));
				Console.SetError(TextWriter.Synchronized(TextWriter.Null));
				Console.SetIn(TextReader.Null);

				// Dispose readers/writers first, then the underlying streams.
				_inReader.Dispose();
				_outWriter.Dispose();
				_errWriter.Dispose();

				_stdinStream.Dispose();
				_stdoutStream.Dispose();
				_stderrStream.Dispose();
			}
			catch
			{
				// Do not throw during cleanup.
			}
		}
	}
}
