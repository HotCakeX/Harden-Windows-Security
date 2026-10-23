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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace GlobalSearchService;

internal sealed partial class VolumeIndex
{
	/// <summary>
	/// Statistics classify names only on a privately owned index.
	/// Category IDs are fixed by protocol version 1 and match the Top Bar labels.
	/// </summary>
	private static readonly string[][] StatisticsExtensions =
	[
		[".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic", ".heif", ".avif", ".svg", ".ico", ".raw", ".dng"],
		[".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".opus", ".wma", ".aiff", ".mid", ".midi"],
		[".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".m4v", ".mpeg", ".mpg"],
		[".dll"], [".exe"],
		[".pdf", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt", ".csv"],
		[".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".cab"],
		[".cs", ".cpp", ".c", ".h", ".hpp", ".rs", ".js", ".ts", ".py", ".html", ".css", ".xaml", ".json", ".xml", ".yaml", ".yml"]
	];

	internal long[] CountFileCategories(CancellationToken token)
	{
		long[] counts = new long[10];
		// Built per request so the lookup is reclaimed together with the private index.
		FrozenDictionary<string, int>.AlternateLookup<ReadOnlySpan<char>> categories = CreateStatisticsCategories();
		// ASCII names are stored as bytes; widen them here to classify the original UTF-16 name.
		Span<char> scratch = stackalloc char[256];
		if (wideEntries is not null)
		{
			WideEntryTable.Enumerator entries = wideEntries.GetEnumerator();
			while (entries.MoveNext())
			{
				token.ThrowIfCancellationRequested();
				NameRef name = entries.Name;
				if (!name.IsDirectory) counts[GetStatisticsCategory(categories, nameArena.GetChars(name, scratch))]++;
			}
		}
		else
		{
			NtfsEntryTable.Enumerator entries = ntfsEntries!.GetEnumerator();
			while (entries.MoveNext())
			{
				token.ThrowIfCancellationRequested();
				NameRef name = entries.Name;
				if (!name.IsDirectory) counts[GetStatisticsCategory(categories, nameArena.GetChars(name, scratch))]++;
			}
		}
		return counts;
	}

	// Maps each extension to its category, keeping the first category in StatisticsExtensions order.
	private static FrozenDictionary<string, int>.AlternateLookup<ReadOnlySpan<char>> CreateStatisticsCategories()
	{
		Dictionary<string, int> categories = new(StringComparer.OrdinalIgnoreCase);
		for (int category = 0; category < StatisticsExtensions.Length; category++)
			foreach (string extension in StatisticsExtensions[category])
				_ = categories.TryAdd(extension, category);
		return categories.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase).GetAlternateLookup<ReadOnlySpan<char>>();
	}

	private static int GetStatisticsCategory(FrozenDictionary<string, int>.AlternateLookup<ReadOnlySpan<char>> categories, ReadOnlySpan<char> name)
	{
		ReadOnlySpan<char> extension = Path.GetExtension(name);
		if (extension.IsEmpty) return 8;
		return categories.TryGetValue(extension, out int category) ? category : 9;
	}
}

internal static partial class SearchServiceHost
{
	private const string StatisticsPipeName = "GlobalSearchHSS_FileStatisticsPipe";

	private static async Task ServeWithStatisticsAsync(bool indexAtStartup, CancellationToken token)
	{
		using IndexState state = new();
		using CancellationTokenSource lifetime = CancellationTokenSource.CreateLinkedTokenSource(token);
		// Await inside the delegate so the disposable index lifetime is explicit.
		Task statistics = Task.Run(async () => await ServeStatisticsAsync(state, lifetime.Token).ConfigureAwait(false), token);
		try { await ServeAsync(state, indexAtStartup, token).ConfigureAwait(false); }
		finally
		{
			// Always join the worker before disposing its state, even if a cancellation callback fails.
			try { await lifetime.CancelAsync().ConfigureAwait(false); }
			finally { await statistics.ConfigureAwait(false); }
		}
	}

	// Keep the private index out of the listener's async state and the collection frame.
	// NoInlining ensures its local is no longer a GC root when reclamation starts.
	[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
	private static (long[] Counts, int Skipped) CalculateDriveStatistics(IndexState state, char drive, CancellationToken token)
	{
		// Count from the shared search index when it covers this drive, so a second
		// index of the same volume is never built. Holding Sync blocks the idle stop,
		// searches and refreshes while the entries are enumerated.
		lock (state.Sync)
		{
			foreach (VolumeIndex shared in state.Indexes)
			{
				if (shared.Drive != drive) continue;
				try
				{
					// Brings the shared index up to date with the change journal first.
					shared.Refresh();
					return (shared.CountFileCategories(token), shared.InaccessibleDirectoryCount);
				}
				catch (Exception exception) when (exception is Win32Exception or IOException or NotSupportedException)
				{
					// The next search reports and removes the unusable shared index.
					SearchLog.ReportWarning($"Shared index for {drive}:\\ could not be refreshed for statistics: {Describe(exception)}");
				}
				break;
			}
		}
		// The drive is outside the indexed scope or its shared index failed, so a
		// private index with its own handle, arena and dictionaries is built instead.
		using VolumeIndex index = new(drive);
		index.Build();
		return (index.CountFileCategories(token), index.InaccessibleDirectoryCount);
	}

	// Idle cost is one independent listener. After shared index activation, the
	// statistics snapshot reuses that index and only builds its own when needed.
	private static async Task ServeStatisticsAsync(IndexState state, CancellationToken token)
	{
		try
		{
			PipeSecurity security = new();
			security.SetSecurityDescriptorSddlForm(SDDLFORM, AccessControlSections.All);
			while (!token.IsCancellationRequested)
			{
				using NamedPipeServerStream pipe = CreatePipeWithMandatoryLabel(security, StatisticsPipeName);
				using CancellationTokenRegistration registration = token.Register(pipe.Dispose);
				try
				{
					await pipe.WaitForConnectionAsync(token).ConfigureAwait(false);
					using CancellationTokenSource admission = CancellationTokenSource.CreateLinkedTokenSource(token);
					admission.CancelAfter(TimeSpan.FromSeconds(15));
					byte[] request = new byte[3];
					await pipe.ReadExactlyAsync(request.AsMemory(0, 1), admission.Token).ConfigureAwait(false);
					if (request[0] != 1 || !IsClientAuthorized(pipe)) continue;
					await pipe.ReadExactlyAsync(request.AsMemory(1, 2), admission.Token).ConfigureAwait(false);
					if (request[1] != 1 || request[2] is < (byte)'A' or > (byte)'Z') continue;
					long[] counts;
					int skipped;
					try
					{
						// Build is synchronous and observes shutdown only before and after
						// its existing enumeration, rather than altering normal indexing.
						token.ThrowIfCancellationRequested();
						// A valid statistics request also activates the shared search index.
						state.EnsureIndexes(token);
						// Statistics are activity too, so the idle timeout cannot stop the service while they are calculated.
						lock (state.Sync) state.StopIdleTimer();
						try
						{
							(counts, skipped) = CalculateDriveStatistics(state, (char)request[2], token);
						}
						finally
						{
							// The calculation frame has unwound and disposed any private index.
							// Reclaim after success, failure or cancellation, before the next drive.
							ReclaimReleasedIndexMemory();
							if (!token.IsCancellationRequested) lock (state.Sync) state.ResetIdleTimer();
						}
					}
					catch (Exception exception) when (!token.IsCancellationRequested)
					{
						SearchLog.ReportWarning("Drive statistics failed: " + Describe(exception));
						pipe.Write([1, 1]); // Version, failure.
						continue;
					}
					using BinaryWriter writer = new(pipe, Encoding.UTF8, leaveOpen: true);
					writer.Write((byte)1); // Version.
					writer.Write((byte)0); // Success.
					writer.Write(skipped);
					foreach (long count in counts) writer.Write(count);
					writer.Flush();
				}
				catch (Exception) when (token.IsCancellationRequested) { break; }
				catch (Exception exception) when (exception is IOException or OperationCanceledException or ObjectDisposedException)
				{
					// Disconnects and admission timeouts affect this endpoint only.
				}
			}
		}
		catch (Exception exception) when (!token.IsCancellationRequested)
		{
			// An endpoint failure must never terminate normal search.
			SearchLog.ReportError(exception);
		}
		catch (Exception) when (token.IsCancellationRequested) { }
	}
}
