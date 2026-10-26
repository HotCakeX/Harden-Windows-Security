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
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.UI.Dispatching;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

// Search metadata is resolved on the pipe worker.
internal sealed record TopBarSearchResult(string Name, string Path, string Size, string DateModified, bool IsDirectory = false);

internal sealed partial class TopBarSearchClient : IAsyncDisposable
{
	private readonly DispatcherQueue _dispatcher;
	private readonly Action<string> _status;
	private readonly Action<string, List<TopBarSearchResult>, long> _results;
	// Signaled when the query or the drive indexing setting changes.
	private readonly Channel<bool> _changed = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
	{
		FullMode = BoundedChannelFullMode.DropWrite,
		SingleReader = true,
		SingleWriter = true
	});
	private readonly CancellationTokenSource _shutdown = new();
	private readonly Task _worker;
	private NamedPipeClientStream? _pipe;
	private string _query = string.Empty;
	// The service's kind (0 files and folders, 1 files only, 2 folders only) and file type bits.
	private byte _kind;
	private byte _fileTypes;
	private int _limit = Atlas.GlobalSearchDefaultResultLimit;
	// Incremented after each query change, so a session searches only when the query changed, not when only the
	// drive indexing setting changed.
	private int _queryVersion;
	// Whether the service indexes the drives connected while it runs. Sent after every handshake and whenever it changes.
	private volatile bool _indexConnectedDrives = Atlas.Settings.WindowsTopBarSearchIndexConnectedDrives;
	private bool _disposed;
	private bool _receivedResponse;
	// Service readiness belongs to the current pipe handshake, not the index lifetime.
	private volatile bool _serviceReady;
	internal bool IsServiceReady => _serviceReady;

	internal TopBarSearchClient(DispatcherQueue dispatcher, Action<string> status, Action<string, List<TopBarSearchResult>, long> results)
	{
		_dispatcher = dispatcher;
		_status = status;
		_results = results;
		_worker = RunAsync();
	}

	internal void SetQuery(string query, byte kind = 0, byte fileTypes = 0, int limit = Atlas.GlobalSearchDefaultResultLimit)
	{
		if (_disposed) return;
		_kind = kind;
		_fileTypes = fileTypes;
		_limit = limit;
		_query = query;
		_ = Interlocked.Increment(ref _queryVersion);
		_ = _changed.Writer.TryWrite(true);
	}

	// Sent to the running service at once, or after the next handshake.
	internal void SetIndexConnectedDrives(bool enabled)
	{
		if (_disposed) return;
		_indexConnectedDrives = enabled;
		_ = _changed.Writer.TryWrite(true);
	}

	private async Task RunAsync()
	{
		CancellationToken token = _shutdown.Token;
		bool failureReported = false;
		_status("Connecting to the Global Search, please wait...");
		try
		{
			while (!token.IsCancellationRequested)
			{
				NamedPipeClientStream? pipe = null;
				try
				{
					// The manual service stops itself when idle, so start it first if it is not running.
					await Task.Run(() => QuantumRelayHSS.ServiceStarter.StartServiceAsync(Atlas.GlobalSearchServiceName, TimeSpan.FromSeconds(30), cancellationToken: token), token);
					// Match the service's 0x00100083 client grant without requesting server-instance creation.
					pipe = new NamedPipeClientStream(".", Atlas.GlobalSearchPipeName,
						PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes | PipeAccessRights.Synchronize,
						PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation, HandleInheritability.None);
					_pipe = pipe;
					_receivedResponse = false;
					await pipe.ConnectAsync(30000, token);
					// Reissue current text after reconnecting; explicit rejection clears it before the next attempt.
					if (!string.IsNullOrWhiteSpace(_query)) _ = _changed.Writer.TryWrite(true);
					NamedPipeClientStream connectedPipe = pipe;
					string? rejectedQuery = await Task.Run(() => Exchange(connectedPipe));
					// The idle service closed this session; reconnect at once, which starts it and reissues the query.
					if (rejectedQuery is null) continue;
					// Use the existing result callback on the UI thread; -1 identifies an explicit rejection.
					if (!_disposed) _results(rejectedQuery, [], -1);
				}
				catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
				catch (ObjectDisposedException) when (token.IsCancellationRequested) { break; }
				catch (Exception exception) when (!token.IsCancellationRequested)
				{
					// A completed response ends the previous failure episode.
					if (_receivedResponse) failureReported = false;
					if (!failureReported)
					{
						Logger.Write(exception);
						_ = _dispatcher.TryEnqueue(() => { if (!_disposed) _status("The Global Search is unavailable: " + exception.Message); });
						failureReported = true;
					}
				}
				finally
				{
					_serviceReady = false;
					try { if (pipe is not null) await pipe.DisposeAsync(); }
					catch (Exception exception) when (!token.IsCancellationRequested) { Logger.Write(exception); }
					if (ReferenceEquals(_pipe, pipe)) _pipe = null;
				}
				if (!token.IsCancellationRequested) await Task.Delay(TimeSpan.FromSeconds(2), token);
			}
		}
		catch (OperationCanceledException) when (token.IsCancellationRequested) { }
	}

	private string? Exchange(NamedPipeClientStream pipe)
	{
		// Send a byte before server impersonation and PFN validation.
		pipe.WriteByte(1);
		using BinaryReader input = new(pipe, Encoding.UTF8, leaveOpen: true);
		// Each frame is built here and sent with one write. A writer on the pipe itself flushes the pipe when it is disposed,
		// which throws once the service has closed the session, and so turns a reconnect into an error.
		using MemoryStream frame = new();
		using BinaryWriter output = new(frame, Encoding.UTF8, leaveOpen: true);
		if (input.ReadByte() != 1 || !string.Equals(input.ReadString(), "Search service ready.", StringComparison.OrdinalIgnoreCase))
			throw new InvalidDataException("The Global Search rejected the connection.");
		_serviceReady = true;
		_ = _dispatcher.TryEnqueue(() => { if (!_disposed) _status("Search service ready."); });
		// A new service process starts with the setting off, so it is sent at once.
		bool indexConnectedDrives = _indexConnectedDrives;
		try { SendIndexConnectedDrives(pipe, frame, output, indexConnectedDrives); }
		// The service stopped itself while this connection was idle.
		catch (IOException) { return null; }
		int searchedVersion = -1;
		while (_changed.Reader.WaitToReadAsync().AsTask().GetAwaiter().GetResult())
		{
			_ = _changed.Reader.TryRead(out _);
			if (_disposed) break;
			if (indexConnectedDrives != _indexConnectedDrives)
			{
				indexConnectedDrives = !indexConnectedDrives;
				try { SendIndexConnectedDrives(pipe, frame, output, indexConnectedDrives); }
				catch (IOException) { return null; }
			}
			int version = Volatile.Read(ref _queryVersion);
			if (version == searchedVersion) continue;
			searchedVersion = version;
			string query = _query;
			if (string.IsNullOrWhiteSpace(query)) continue;
			byte kind = _kind;
			byte fileTypes = _fileTypes;
			int limit = _limit;
			_receivedResponse = false;
			QueueSearchStatus(query, "Searching, please wait...");
			// Only the service decides whether the declared UTF-8 length is acceptable.
			byte admission;
			try
			{
				// The filter and the result limit precede the length.
				output.Write(kind);
				output.Write(fileTypes);
				output.Write7BitEncodedInt(limit);
				output.Write7BitEncodedInt(Encoding.UTF8.GetByteCount(query));
				Send(pipe, frame);
				admission = input.ReadByte();
			}
			// The service stopped itself while this connection was idle.
			catch (IOException) { return null; }
			if (admission == 3) return query;
			if (admission != 4) throw new InvalidDataException("Unexpected search admission response.");
			output.Write(query.AsSpan()); // Raw payload; its length has already been sent.
			Send(pipe, frame);
			// Status frames precede, but never replace, the existing result frame.
			byte response = input.ReadByte();
			while (response == 5)
			{
				QueueSearchStatus(query, "Please wait, indexing...");
				response = input.ReadByte();
			}
			if (response != 2) throw new InvalidDataException("Unexpected search response.");
			int count = input.ReadInt32();
			if (count < 0 || count > limit) throw new InvalidDataException("Invalid search result count.");
			// The service writes this snapshot immediately after the result count.
			long indexedItems = input.ReadInt64();
			if (indexedItems < 0) throw new InvalidDataException("Invalid indexed item count.");
			List<TopBarSearchResult> results = new(count);
			// Once a newer query, filter or limit is pending, the rest of the frame is read without file lookups.
			bool superseded = false;
			for (int i = 0; i < count; i++)
			{
				string path = input.ReadString();
				superseded = superseded || Volatile.Read(ref _queryVersion) != version;
				if (!superseded) results.Add(CreateResult(path));
			}
			_receivedResponse = true;
			// The pending search follows at once and shows its own results.
			if (superseded) continue;
			// Results of an older filter or limit for the same text are dropped; the newer search follows.
			_ = _dispatcher.TryEnqueue(() => { if (!_disposed && _kind == kind && _fileTypes == fileTypes && _limit == limit) _results(query, results, indexedItems); });
		}
		return null;
	}

	// The service applies the setting frame in place of a query and sends no response.
	private static void SendIndexConnectedDrives(NamedPipeClientStream pipe, MemoryStream frame, BinaryWriter output, bool enabled)
	{
		output.Write(Atlas.GlobalSearchIndexConnectedDrivesFrame);
		output.Write(enabled);
		Send(pipe, frame);
	}

	// Sends the frame that the writer built and empties it for the next one. The writer has no buffer of its own.
	private static void Send(NamedPipeClientStream pipe, MemoryStream frame)
	{
		pipe.Write(frame.GetBuffer(), 0, (int)frame.Length);
		frame.SetLength(0);
	}

	// Ignore queued status updates after the user changes or clears the query, or closes the bar.
	private void QueueSearchStatus(string query, string message) => _ = _dispatcher.TryEnqueue(() =>
	{
		if (!_disposed && string.Equals(_query, query, StringComparison.OrdinalIgnoreCase)) _status(message);
	});

	private static TopBarSearchResult CreateResult(string path)
	{
		string name = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
		if (string.IsNullOrEmpty(name)) name = path;
		try
		{
			FileAttributes attributes = File.GetAttributes(path);
			bool isDirectory = (attributes & FileAttributes.Directory) != 0;
			FileSystemInfo info = isDirectory ? new DirectoryInfo(path) : new FileInfo(path);
			string size = isDirectory ? string.Empty : FormatFileSize(((FileInfo)info).Length);
			return new(name, path, size, info.LastWriteTime.ToString("g", CultureInfo.CurrentCulture), isDirectory);
		}
		catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
		{
			// Keep indexed paths visible when their metadata is unavailable.
			return new(name, path, string.Empty, string.Empty);
		}
	}

	internal static string FormatFileSize(long bytes)
	{
		double size = bytes;
		int unit = 0;
		while (size >= 1024.0 && unit < Atlas.SizeUnits.Length - 1)
		{
			size /= 1024.0;
			unit++;
		}
		return size.ToString(unit == 0 ? "N0" : "N1", CultureInfo.CurrentCulture) + " " + Atlas.SizeUnits[unit];
	}

	public async ValueTask DisposeAsync()
	{
		if (_disposed) return;
		_disposed = true;
		try
		{
			await _shutdown.CancelAsync();
			_ = _changed.Writer.TryComplete();
			if (_pipe is not null) await _pipe.DisposeAsync().ConfigureAwait(false);
			await _worker.ConfigureAwait(false);
		}
		finally { _shutdown.Dispose(); }
	}
}
