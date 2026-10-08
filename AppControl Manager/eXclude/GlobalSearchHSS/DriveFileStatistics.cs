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
		if (wideEntries is not null)
		{
			foreach (Entry entry in wideEntries.Values)
			{
				token.ThrowIfCancellationRequested();
				if (!entry.Name.IsDirectory) counts[GetStatisticsCategory(nameArena.GetSpan(entry.Name))]++;
			}
		}
		else
		{
			foreach (NtfsEntry entry in ntfsEntries!.Values)
			{
				token.ThrowIfCancellationRequested();
				if (!entry.Name.IsDirectory) counts[GetStatisticsCategory(nameArena.GetSpan(entry.Name))]++;
			}
		}
		return counts;
	}

	private static int GetStatisticsCategory(ReadOnlySpan<char> name)
	{
		ReadOnlySpan<char> extension = Path.GetExtension(name);
		if (extension.IsEmpty) return 8;
		for (int category = 0; category < StatisticsExtensions.Length; category++)
			foreach (string candidate in StatisticsExtensions[category])
				if (extension.Equals(candidate, StringComparison.OrdinalIgnoreCase)) return category;
		return 9;
	}
}

internal static partial class SearchServiceHost
{
	private const string StatisticsPipeName = "GlobalSearchHSS_FileStatisticsPipe";

	private static async Task ServeWithStatisticsAsync(CancellationToken token)
	{
		using IndexState state = new();
		using CancellationTokenSource lifetime = CancellationTokenSource.CreateLinkedTokenSource(token);
		// Await inside the delegate so the disposable index lifetime is explicit.
		Task statistics = Task.Run(async () => await ServeStatisticsAsync(state, lifetime.Token).ConfigureAwait(false), token);
		try { await ServeAsync(state, token).ConfigureAwait(false); }
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
	private static (long[] Counts, int Skipped) CalculateDriveStatistics(char drive, CancellationToken token)
	{
		using VolumeIndex index = new(drive);
		index.Build();
		return (index.CountFileCategories(token), index.InaccessibleDirectoryCount);
	}

	// Idle cost is one independent listener. After shared index activation, the
	// statistics snapshot still uses its own handle, arena and dictionaries.
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
						// A separate handle, arena and dictionaries isolate this request.
						// Build is synchronous and observes shutdown only before and after
						// its existing enumeration, rather than altering normal indexing.
						token.ThrowIfCancellationRequested();
						// A valid statistics request also activates the shared search index.
						state.EnsureIndexes(token);
						try
						{
							(counts, skipped) = CalculateDriveStatistics((char)request[2], token);
						}
						finally
						{
							// The calculation frame has unwound and disposed its private index.
							// Reclaim after success, failure or cancellation, before the next drive.
							ReclaimReleasedIndexMemory();
						}
					}
					catch (Exception exception) when (!token.IsCancellationRequested)
					{
						SearchLog.ReportWarning("Drive statistics failed: " + Describe(exception));
						using BinaryWriter failure = new(pipe, Encoding.UTF8, leaveOpen: true);
						failure.Write((byte)1);
						failure.Write((byte)1);
						failure.Flush();
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
