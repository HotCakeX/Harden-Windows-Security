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
using Microsoft.UI.Xaml.Media.Imaging;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

// Search metadata is resolved on the pipe worker.
internal sealed record TopBarSearchResult(string Name, string Path, string Size, string DateModified, bool IsDirectory = false)
{
	// UI-thread-only cache lives with this result set, not with recycled ListView containers.
	internal BitmapImage? Thumbnail;
	internal bool ThumbnailAttempted;
}

internal sealed partial class TopBarSearchClient : IAsyncDisposable
{
	private readonly DispatcherQueue _dispatcher;
	private readonly Action<string> _status;
	private readonly Action<string, List<TopBarSearchResult>, long> _results;
	private readonly Channel<bool> _queryChanged = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
	{
		FullMode = BoundedChannelFullMode.DropWrite,
		SingleReader = true,
		SingleWriter = true
	});
	private readonly CancellationTokenSource _shutdown = new();
	private readonly Task _worker;
	private NamedPipeClientStream? _pipe;
	private string _query = string.Empty;
	private bool _disposed;
	private bool _receivedResponse;
	// Readiness belongs to the current pipe handshake.
	private volatile bool _indexReady;
	internal bool IsIndexReady => _indexReady;

	internal TopBarSearchClient(DispatcherQueue dispatcher, Action<string> status, Action<string, List<TopBarSearchResult>, long> results)
	{
		_dispatcher = dispatcher;
		_status = status;
		_results = results;
		_worker = RunAsync();
	}

	internal void SetQuery(string query)
	{
		if (_disposed) return;
		_query = query;
		_ = _queryChanged.Writer.TryWrite(true);
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
					// Match the service's 0x00100083 client grant without requesting server-instance creation.
					pipe = new NamedPipeClientStream(".", Atlas.GlobalSearchPipeName,
						PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes | PipeAccessRights.Synchronize,
						PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation, HandleInheritability.None);
					_pipe = pipe;
					_receivedResponse = false;
					await pipe.ConnectAsync(30000, token);
					// Reissue current text after reconnecting; explicit rejection clears it before the next attempt.
					if (!string.IsNullOrWhiteSpace(_query)) _ = _queryChanged.Writer.TryWrite(true);
					NamedPipeClientStream connectedPipe = pipe;
					string? rejectedQuery = await Task.Run(() => Exchange(connectedPipe));
					// Use the existing result callback on the UI thread; -1 identifies an explicit rejection.
					if (!_disposed && rejectedQuery is not null) _results(rejectedQuery, [], -1);
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
					_indexReady = false;
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
		using BinaryWriter output = new(pipe, Encoding.UTF8, leaveOpen: true);
		if (input.ReadByte() != 1 || !string.Equals(input.ReadString(), "Search index ready.", StringComparison.OrdinalIgnoreCase))
			throw new InvalidDataException("The Global Search rejected the connection.");
		_indexReady = true;
		_ = _dispatcher.TryEnqueue(() => { if (!_disposed) _status("Search index ready."); });
		while (_queryChanged.Reader.WaitToReadAsync().AsTask().GetAwaiter().GetResult())
		{
			_ = _queryChanged.Reader.TryRead(out _);
			if (_disposed) break;
			string query = _query;
			if (string.IsNullOrWhiteSpace(query)) continue;
			_receivedResponse = false;
			// Only the service decides whether the declared UTF-8 length is acceptable.
			output.Write7BitEncodedInt(Encoding.UTF8.GetByteCount(query));
			output.Flush();
			byte admission = input.ReadByte();
			if (admission == 3) return query;
			if (admission != 4) throw new InvalidDataException("Unexpected search admission response.");
			output.Write(query.AsSpan()); // Raw payload; its length has already been sent.
			output.Flush();
			if (input.ReadByte() != 2) throw new InvalidDataException("Unexpected search response.");
			int count = input.ReadInt32();
			if (count is < 0 or > 100) throw new InvalidDataException("Invalid search result count.");
			// The service writes this snapshot immediately after the result count.
			long indexedItems = input.ReadInt64();
			if (indexedItems < 0) throw new InvalidDataException("Invalid indexed item count.");
			List<TopBarSearchResult> results = new(count);
			for (int i = 0; i < count; i++) results.Add(CreateResult(input.ReadString()));
			_receivedResponse = true;
			_ = _dispatcher.TryEnqueue(() => { if (!_disposed) _results(query, results, indexedItems); });
		}
		return null;
	}

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

	private static string FormatFileSize(long bytes)
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
			_ = _queryChanged.Writer.TryComplete();
			if (_pipe is not null) await _pipe.DisposeAsync().ConfigureAwait(false);
			await _worker.ConfigureAwait(false);
		}
		finally { _shutdown.Dispose(); }
	}
}
