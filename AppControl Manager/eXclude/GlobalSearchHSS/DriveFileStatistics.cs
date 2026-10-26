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
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace GlobalSearchService;

internal sealed partial class VolumeIndex
{
	/// <summary>
	/// Statistics classify the file names of a drive's search index.
	/// Category IDs are fixed by protocol version 1 and match the Top Bar labels.
	/// The search file type filter uses the same IDs as its bits.
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
		// Built per request, so the lookup is not kept in memory between requests.
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

	// True when the name's extension is in a category whose bit is set in fileTypes.
	// Only the selected categories are scanned, so search keeps no lookup in memory and allocates nothing.
	private static bool HasFileType(ReadOnlySpan<char> name, byte fileTypes)
	{
		ReadOnlySpan<char> extension = Path.GetExtension(name);
		if (extension.IsEmpty) return false;
		for (int category = 0; category < StatisticsExtensions.Length; category++)
		{
			if ((fileTypes & (1 << category)) == 0) continue;
			foreach (string candidate in StatisticsExtensions[category])
			{
				if (extension.Equals(candidate, StringComparison.OrdinalIgnoreCase)) return true;
			}
		}
		return false;
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

	// Counts from the volume's shared search index, so a second index of the same volume is never built. A volume without
	// a usable one, such as a drive that could not be indexed when it was connected, is indexed first and its index is
	// kept, so the volume becomes searchable too.
	private static (long[] Counts, int Skipped) CalculateDriveStatistics(IndexState state, char drive, CancellationToken token)
	{
		// The indexes are kept by volume, so the drive letter is mapped to the volume it currently refers to.
		char[] name = new char[50];
		if (!NativeMethods.GetVolumeNameForVolumeMountPointW($"{drive}:\\", name, (uint)name.Length))
			throw new Win32Exception(Marshal.GetLastPInvokeError(), $"GetVolumeNameForVolumeMountPointW failed for {drive}:\\");
		string volume = new(name.AsSpan(0, Array.IndexOf(name, '\0')));
		// Held until the end, so the volume is not indexed meanwhile by a drive arrival.
		using Lock.Scope adding = state.AddSync.EnterScope();
		// Holding Sync blocks the idle stop, searches and refreshes while the entries are enumerated.
		lock (state.Sync)
		{
			foreach (VolumeIndex shared in state.Indexes)
			{
				if (!string.Equals(shared.Root, volume, StringComparison.OrdinalIgnoreCase)) continue;
				try
				{
					// Brings the shared index up to date with the change journal first.
					shared.Refresh();
					return (shared.CountFileCategories(token), shared.InaccessibleDirectoryCount);
				}
				catch (Exception exception) when (exception is Win32Exception or IOException or UnauthorizedAccessException or NotSupportedException)
				{
					// Removed as a search would remove it, then the volume is indexed again below.
					SearchLog.ReportWarning($"Index for {volume} is no longer usable: {Describe(exception)}");
					shared.Dispose();
					_ = state.Indexes.Remove(shared);
				}
				break;
			}
		}
		// Indexed outside Sync, so searches of the other volumes continue meanwhile. AddSync keeps anything else from
		// indexing this volume meanwhile.
		VolumeIndex added = OpenIndex(volume, out _);
		lock (state.Sync)
		{
			state.Indexes.Add(added);
			return (added.CountFileCategories(token), added.InaccessibleDirectoryCount);
		}
	}

	// Idle cost is one independent listener. Statistics are counted from the shared search indexes,
	// and a drive without one is indexed first. The same listener answers the requests that manage the saved indexes.
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
					byte operation = request[1];
					if (operation == Atlas.GlobalSearchStatisticsRequest ? request[2] is < (byte)'A' or > (byte)'Z' :
						(operation is < Atlas.GlobalSearchSavedIndexSizeRequest or > Atlas.GlobalSearchIndexNewDrivesRequest || request[2] != 0)) continue;
					using MemoryStream response = new();
					using BinaryWriter writer = new(response, Encoding.UTF8, leaveOpen: true);
					writer.Write((byte)1); // Version.
					writer.Write((byte)0); // Success.
					try
					{
						// Build is synchronous and observes shutdown only before and after
						// its existing enumeration, rather than altering normal indexing.
						token.ThrowIfCancellationRequested();
						// Every request except the size also activates the shared search index. Deleting unused saved
						// indexes then keeps those of the connected drives, which are in use.
						if (operation != Atlas.GlobalSearchSavedIndexSizeRequest) state.EnsureIndexes(token);
						// Requests are activity too, so the idle timeout cannot stop the service while they are answered.
						lock (state.Sync) state.StopIdleTimer();
						try
						{
							switch (operation)
							{
								case Atlas.GlobalSearchStatisticsRequest:
									(long[] counts, int skipped) = CalculateDriveStatistics(state, (char)request[2], token);
									writer.Write(skipped);
									foreach (long count in counts) writer.Write(count);
									break;
								case Atlas.GlobalSearchSavedIndexSizeRequest:
									writer.Write(GetSavedIndexesSize());
									break;
								case Atlas.GlobalSearchDeleteUnusedIndexesRequest:
									state.DeleteUnusedSavedIndexes();
									// The size left, so the client shows it without another request.
									writer.Write(GetSavedIndexesSize());
									break;
								default:
									// Indexes the drives connected or unlocked since the indexes were built.
									writer.Write(state.IndexVolumes(null));
									lock (state.Sync) writer.Write(state.Indexes.Count);
									break;
							}
						}
						finally
						{
							// Indexing a drive leaves its build buffers behind, and counting leaves its lookup.
							// Reclaim after success, failure or cancellation, before the next drive.
							if (operation == Atlas.GlobalSearchStatisticsRequest) ReclaimReleasedIndexMemory();
							if (!token.IsCancellationRequested) lock (state.Sync) state.ResetIdleTimer();
						}
					}
					catch (Exception exception) when (!token.IsCancellationRequested)
					{
						// The client reports a drive that cannot be indexed.
						if (exception is not UnindexableVolumeException)
							SearchLog.ReportWarning($"Global Search request {operation} failed: " + Describe(exception));
						pipe.Write([1, 1]); // Version, failure.
						continue;
					}
					writer.Flush();
					// Buffered until the request succeeds, so a failure is answered with the failure frame alone.
					response.WriteTo(pipe);
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
