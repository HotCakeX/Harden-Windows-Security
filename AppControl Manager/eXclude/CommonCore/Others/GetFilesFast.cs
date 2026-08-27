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

using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Enumeration;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace CommonCore.Others;

internal static class FileUtility
{
	/// <summary>
	/// Method that takes 2 collections, one containing file paths and the other containing folder paths.
	/// It checks them and returns the unique file paths that are not in any of the folder paths.
	/// Performs this check recursively, so it works if a file path is in a sub-directory of a folder path.
	/// It works even if the file paths or folder paths are non-existent/deleted, but they still need to be valid file/folder paths.
	/// </summary>
	private static HashSet<string> TestFilePath(
		IReadOnlyCollection<string> directoryPaths,
		IReadOnlyCollection<string> filePaths)
	{
		// Normalize each directory-path into an absolute path ending with a single separator.
		HashSet<string> normalizedDirs = new(StringComparer.OrdinalIgnoreCase);

		foreach (string dir in directoryPaths)
		{
			if (string.IsNullOrWhiteSpace(dir))
				continue;

			// Get full absolute path, trim any trailing separator, then add exactly one.
			string fullDir = Path.GetFullPath(dir)
								 .TrimEnd(Path.DirectorySeparatorChar)
								 + Path.DirectorySeparatorChar;

			_ = normalizedDirs.Add(fullDir);
		}

		// Walk through each file. Normalize its full path, then climb its parent chain.
		// If we ever match one of the normalizedDirs, skip it. Otherwise, add the original file string.
		HashSet<string> output = new(StringComparer.OrdinalIgnoreCase);

		foreach (string file in filePaths)
		{
			if (string.IsNullOrWhiteSpace(file))
				continue;

			// Normalize file into an absolute path
			string fullFilePath;
			try
			{
				fullFilePath = Path.GetFullPath(file);
			}
			catch (Exception)
			{
				// If the file-string is not a valid path, skip it
				continue;
			}

			// Start checking from the file's parent directory upwards
			string? currentDir = Path.GetDirectoryName(fullFilePath);
			bool residesUnderExcluded = false;

			while (currentDir is not null)
			{
				// Normalize this ancestor folder (absolute, trailing separator)
				string normalizedAncestor = Path.GetFullPath(currentDir)
											 .TrimEnd(Path.DirectorySeparatorChar)
											 + Path.DirectorySeparatorChar;

				if (normalizedDirs.Contains(normalizedAncestor))
				{
					residesUnderExcluded = true;
					break;
				}

				currentDir = Path.GetDirectoryName(currentDir);
			}

			if (!residesUnderExcluded)
			{
				// Use the original file-string (not the full-path) in the output set
				_ = output.Add(file);
			}
		}

		// Return the set of files that do NOT reside under any of the provided directories.
		return output;
	}

	// Used to enumerate all files, recursively inside each sub-directory of each user-selected directory
	private static readonly EnumerationOptions RecursiveEnumeration = new()
	{
		IgnoreInaccessible = true,
		RecurseSubdirectories = true,
		AttributesToSkip = FileAttributes.None,
		MatchCasing = MatchCasing.CaseInsensitive,
		ReturnSpecialDirectories = false,
		MaxRecursionDepth = int.MaxValue,
		BufferSize = 65536
	};

	// Used to only enumerate the files in each user-selected directories
	private static readonly EnumerationOptions NonRecurseEnumeration = new()
	{
		IgnoreInaccessible = true,
		RecurseSubdirectories = false,
		AttributesToSkip = FileAttributes.None,
		MatchCasing = MatchCasing.CaseInsensitive,
		ReturnSpecialDirectories = false,
		MaxRecursionDepth = int.MaxValue,
		BufferSize = 65536
	};

	// Used to enumerate the immediate sub-directories of each user-selected directory
	private static readonly EnumerationOptions ImmediateDirectoriesEnumeration = new()
	{
		IgnoreInaccessible = true,
		RecurseSubdirectories = false,
		AttributesToSkip = FileAttributes.None,
		MatchCasing = MatchCasing.CaseInsensitive,
		ReturnSpecialDirectories = false,
		MaxRecursionDepth = int.MaxValue,
		BufferSize = 65536
	};

	// The Default App Control supported extensions, case-insensitive
	private static readonly FrozenSet<string> AppControlExtensions = new string[]
	{
		".sys", ".exe", ".com", ".dll", ".rll", ".ocx", ".msp", ".mst", ".msi",
		".js", ".vbs", ".ps1", ".appx", ".bin", ".bat", ".hxs", ".mui", ".lex", ".mof"
	}.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

	// Extensions that are known to never be Portable Executable images, case-insensitive.
	// Only consulted when the default App Control extensions are used (no explicit extensions were provided to filter by).
	// Files whose extension is in this set are skipped from the content-based PE inspection so that a file handle is never opened for them,
	// which avoids the expensive per-file on-access antimalware scan for obviously non-PE files such as images, text, media, documents, archives and fonts.
	private static readonly FrozenSet<string> NonPortableExecutableExtensions = new string[]
	{
		// Images
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".ico", ".webp", ".svg", ".heic", ".heif", ".raw", ".psd",
		// Text, configuration and documents
		".txt", ".log", ".md", ".csv", ".json", ".xml", ".yaml", ".yml", ".ini", ".pdf",
		".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		// Archives
		".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso",
		// Audio and video
		".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav", ".flac", ".wma", ".wmv", ".m4a", ".aac", ".ogg", ".webm", ".flv",
		// Fonts
		".ttf", ".otf", ".woff", ".woff2", ".eot",
		// Web and shortcuts
		".html", ".htm", ".css", ".lnk", ".url"
	}.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

	private static bool IsPortableExecutable(string filePath)
	{
		try
		{
			using SafeFileHandle fileHandle = File.OpenHandle(
				filePath,
				FileMode.Open,
				FileAccess.Read,
				FileShare.ReadWrite | FileShare.Delete,
				FileOptions.RandomAccess);

			long fileLength = RandomAccess.GetLength(fileHandle);
			if (fileLength < 90)
			{
				return false;
			}

			return IsPortableExecutableCore(filePath, fileHandle, fileLength);
		}
		catch
		{
			return false;
		}
	}

	private static bool IsPortableExecutable(string filePath, long length)
	{
		try
		{
			long fileLength = length;
			if (fileLength < 90)
			{
				return false;
			}

			using SafeFileHandle fileHandle = File.OpenHandle(
				filePath,
				FileMode.Open,
				FileAccess.Read,
				FileShare.ReadWrite | FileShare.Delete,
				FileOptions.RandomAccess);

			return IsPortableExecutableCore(filePath, fileHandle, fileLength);
		}
		catch
		{
			return false;
		}
	}

	/// <summary>
	/// Determines whether a file with an unrecognized extension has the minimum structural requirements of a PE image.
	/// Only the DOS header and the fixed part of the NT headers are read to keep this fallback path fast.
	/// It does not inspect or restrict the COFF Machine field so it will return true for valid PE images of any architecture (x86, x64, ARM, etc.).
	/// </summary>
	private static bool IsPortableExecutableCore(string filePath, SafeFileHandle fileHandle, long fileLength)
	{
		Span<byte> dosHeader = stackalloc byte[64];
		if (RandomAccess.Read(fileHandle, dosHeader, 0) != dosHeader.Length ||
			BinaryPrimitives.ReadUInt16LittleEndian(dosHeader) != 0x5A4D)
		{
			return false;
		}

		int ntHeaderOffset = BinaryPrimitives.ReadInt32LittleEndian(dosHeader[0x3C..]);
		if (ntHeaderOffset < dosHeader.Length || ntHeaderOffset > fileLength - 26)
		{
			return false;
		}

		Span<byte> ntHeaders = stackalloc byte[26];
		if (RandomAccess.Read(fileHandle, ntHeaders, ntHeaderOffset) != ntHeaders.Length ||
			BinaryPrimitives.ReadUInt32LittleEndian(ntHeaders) != 0x00004550)
		{
			return false;
		}

		ushort numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(ntHeaders[6..]);
		ushort sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(ntHeaders[20..]);
		ushort characteristics = BinaryPrimitives.ReadUInt16LittleEndian(ntHeaders[22..]);
		ushort optionalHeaderMagic = BinaryPrimitives.ReadUInt16LittleEndian(ntHeaders[24..]);

		// The Windows loader supports PE images with 1 through 96 sections.
		// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
		if (numberOfSections is 0 or > 96 ||
			sizeOfOptionalHeader < 2 ||
			(characteristics & 0x0002) is 0 ||
			optionalHeaderMagic is not (0x010B or 0x020B))
		{
			return false;
		}

		long sectionTableEnd = ntHeaderOffset + 24L + sizeOfOptionalHeader + (numberOfSections * 40L);
		bool result = sectionTableEnd <= fileLength;
#if DEBUG
		if (result)
		{
			Logger.Write($"File '{filePath}' has an unrecognized extension but is a valid PE image.");
		}
#endif
		return result;
	}

	// Number of unanimous non-PE samples a (folder + extension) pairing must accumulate during a single scan before its content inspection is skipped for the rest of that scan.
	private const int LearnedSkipThreshold = 5;

	// Per-scan learning record for a single (inner folder + extension) pairing.
	// Total: how many files matching this pairing have been content-inspected so far in the current scan.
	// NonPeCount: how many of those inspections returned "not a PE".
	// Locked: once true, files matching this pairing skip content inspection (and thus the file open) for the remainder of the scan.
	private sealed class LearnedVerdict
	{
		internal int Total;
		internal int NonPeCount;
		internal volatile bool Locked;
	}

	// Returns the innermost folder together with its immediate parent from a directory path, so learning is scoped to a specific location rather than a whole extension across the drive.
	// For "C:\\Windows\\System32\\FolderX\\FolderY" it returns "FolderX\\FolderY". When fewer than two segments are available (for example "C:\\FolderY") it returns whatever is present.
	// This is a zero-allocation slice of the input span, no new string is created here.
	private static ReadOnlySpan<char> GetInnerFolderSegment(ReadOnlySpan<char> directory)
	{
		// Trim a single trailing separator so the innermost segment is detected correctly.
		if (directory.Length > 0 && (directory[^1] == '\\' || directory[^1] == '/'))
		{
			directory = directory[..^1];
		}

		// Separator immediately before the innermost folder (FolderY).
		int innerSeparator = directory.LastIndexOfAny('\\', '/');
		if (innerSeparator <= 0)
		{
			return directory;
		}

		// Separator before the immediate parent (FolderX); the slice after it is "FolderX\\FolderY".
		int parentSeparator = directory[..innerSeparator].LastIndexOfAny('\\', '/');
		return parentSeparator < 0 ? directory : directory[(parentSeparator + 1)..];
	}

	// Resolves (or creates) the per-scan verdict for a (folder segment + extension) pairing using a zero-allocation span lookup on the hot path.
	// The composite key is "folderSegment|extension"; the '|' character is invalid in Windows paths and extensions, so it can never collide with real content.
	// A string is only allocated the first time a given pairing is encountered, when the entry has to be inserted.
	private static LearnedVerdict GetVerdict(
		ConcurrentDictionary<string, LearnedVerdict> learned,
		ConcurrentDictionary<string, LearnedVerdict>.AlternateLookup<ReadOnlySpan<char>> learnedLookup,
		ReadOnlySpan<char> folderSegment,
		ReadOnlySpan<char> extension)
	{
		int keyLength = folderSegment.Length + 1 + extension.Length;
		Span<char> keyBuffer = keyLength <= 512 ? stackalloc char[512] : new char[keyLength];
		folderSegment.CopyTo(keyBuffer);
		keyBuffer[folderSegment.Length] = '|';
		extension.CopyTo(keyBuffer[(folderSegment.Length + 1)..]);
		ReadOnlySpan<char> key = keyBuffer[..keyLength];

		if (learnedLookup.TryGetValue(key, out LearnedVerdict? verdict))
		{
			return verdict;
		}

		// First encounter of this pairing in the current scan, materialize the key once and add it (GetOrAdd resolves add races atomically).
		return learned.GetOrAdd(key.ToString(), static _ => new LearnedVerdict());
	}

	// Records the outcome of a single content inspection and decides whether the pairing can be locked as "skip".
	// Locking happens only when at least LearnedSkipThreshold samples were collected AND every one of them was a non-PE.
	// A single PE sample makes Total permanently greater than NonPeCount, so a mixed pairing is never locked and keeps being inspected.
	private static void RecordLearnedSample(LearnedVerdict verdict, bool isPortableExecutable)
	{
		// Fast, lock-free bail-out once the pairing is already locked.
		if (verdict.Locked)
		{
			return;
		}

		// The warm-up window is tiny and bounded (at most LearnedSkipThreshold samples for a non-PE pairing before it locks),
		// so a per-verdict lock here keeps the Total/NonPeCount pair perfectly consistent without measurable cost.
		lock (verdict)
		{
			if (verdict.Locked)
			{
				return;
			}

			verdict.Total++;
			if (!isPortableExecutable)
			{
				verdict.NonPeCount++;
			}

			if (verdict.Total >= LearnedSkipThreshold && verdict.Total == verdict.NonPeCount)
			{
				verdict.Locked = true;
			}
		}
	}

	// Content-inspects a file for PE structure, but first consults the per-scan folder-scoped learning cache so that a (folder + extension) pairing
	// proven to never be a PE (after LearnedSkipThreshold samples) skips the inspection (and the file open) entirely for the rest of the scan.
	private static bool IsPortableExecutableLearned(
		ConcurrentDictionary<string, LearnedVerdict> learned,
		ConcurrentDictionary<string, LearnedVerdict>.AlternateLookup<ReadOnlySpan<char>> learnedLookup,
		ReadOnlySpan<char> directory,
		ReadOnlySpan<char> extension,
		string filePath,
		long length)
	{
		LearnedVerdict verdict = GetVerdict(learned, learnedLookup, GetInnerFolderSegment(directory), extension);
		if (verdict.Locked)
		{
			return false;
		}

		bool isPortableExecutable = IsPortableExecutable(filePath, length);
		RecordLearnedSample(verdict, isPortableExecutable);
		return isPortableExecutable;
	}

	// Overload used by the explicit files path, where the length is not known ahead of time and is obtained from the opened handle.
	private static bool IsPortableExecutableLearned(
		ConcurrentDictionary<string, LearnedVerdict> learned,
		ConcurrentDictionary<string, LearnedVerdict>.AlternateLookup<ReadOnlySpan<char>> learnedLookup,
		ReadOnlySpan<char> directory,
		ReadOnlySpan<char> extension,
		string filePath)
	{
		LearnedVerdict verdict = GetVerdict(learned, learnedLookup, GetInnerFolderSegment(directory), extension);
		if (verdict.Locked)
		{
			return false;
		}

		bool isPortableExecutable = IsPortableExecutable(filePath);
		RecordLearnedSample(verdict, isPortableExecutable);
		return isPortableExecutable;
	}

	/// <summary>
	/// A flexible and fast method that can accept directory paths and file paths as input and return file paths that are compliant with App Control policies.
	/// It supports custom extensions to filter by as well.
	/// </summary>
	/// <param name="directories">Directories to process.</param>
	/// <param name="files">Files to process.</param>
	/// <param name="extensionsToFilterBy">Extensions to filter by. If null or empty, default App Control supported extensions are used.</param>
	/// <returns>A Tuple containing the IEnumerable and count of the data</returns>
	internal static (IEnumerable<string>, int) GetFilesFast(
		IReadOnlyCollection<string>? directories,
		IReadOnlyCollection<string>? files,
		string[]? extensionsToFilterBy,
		CancellationToken? cToken = null)
	{
		// Create a Stopwatch instance and start measuring time
		Stopwatch stopwatch = Stopwatch.StartNew();

		// A FrozenSet used to store extensions to filter files
		FrozenSet<string> extensions = extensionsToFilterBy is { Length: > 0 }
			? extensionsToFilterBy.ToFrozenSet(StringComparer.OrdinalIgnoreCase)
			: AppControlExtensions;

		// Only inspect file contents for PE images when using the default App Control extensions.
		// Don't want to waste time inspecting file contents when the user/caller has provided their own specific custom extensions to filter by.
		bool usePeValidation = extensionsToFilterBy is null or { Length: 0 };

		// If custom extensions are provided, use them and make them case-insensitive

		// Using this improves performance by ~40% and creates 0 allocations where it's used.
		FrozenSet<string>.AlternateLookup<ReadOnlySpan<char>> lookup = extensions.GetAlternateLookup<ReadOnlySpan<char>>();

		// Zero-allocation lookup for extensions that should never be treated as PE images.
		// Only consulted on the default App Control extensions path to skip content inspection (and thus the file open) of obviously non-PE files.
		FrozenSet<string>.AlternateLookup<ReadOnlySpan<char>> skipLookup = NonPortableExecutableExtensions.GetAlternateLookup<ReadOnlySpan<char>>();

		// Per-scan folder-scoped learning cache: a (inner folder + unknown extension) pairing that repeatedly proves to be non-PE gets locked and skipped for the rest of THIS scan.
		// Scoping to the innermost folder and its parent means the same extension is learned independently per location, which is valuable on large trees such as an entire drive.
		// It is intentionally local to each call so verdicts never leak across scans, where the files on disk may have changed between runs.
		ConcurrentDictionary<string, LearnedVerdict> learned = new(StringComparer.OrdinalIgnoreCase);

		// Zero-allocation span lookup into the learning cache; a string key is only allocated the first time a pairing is inserted.
		ConcurrentDictionary<string, LearnedVerdict>.AlternateLookup<ReadOnlySpan<char>> learnedLookup = learned.GetAlternateLookup<ReadOnlySpan<char>>();

		// https://learn.microsoft.com/dotnet/api/system.collections.concurrent.blockingcollection-1
		// https://learn.microsoft.com/dotnet/standard/collections/thread-safe/when-to-use-a-thread-safe-collection
		// https://learn.microsoft.com/dotnet/standard/collections/thread-safe/blockingcollection-overview
		// We could use "Using" statement here but then we wouldn't be able to pass the collection's enumerable as the return object and instead would have to materialize it into an Array/List which would degrade performance.
		BlockingCollection<string> bc = [];

		// To store all of the tasks
		List<Task> tasks = [];

		#region Directories

		// Process directories if provided
		if (directories is { Count: > 0 })
		{
			foreach (string directory in directories)
			{
				// Process files in the current directory - non-recursive
				tasks.Add(Task.Run(() =>
				{

					FileSystemEnumerable<string> enumeration = new(
							directory,
							(ref entry) => entry.ToFullPath(),
							NonRecurseEnumeration)
					{
						ShouldIncludePredicate = (ref entry) =>
						{
							// Skip directories.
							if (entry.IsDirectory)
							{
								return false;
							}

							// Find valid PE files that are candidate for Windows image loading and App Control evaluation.
							// First use the zero-allocation file extension checking fast path, only inspect file contents when the extension is unknown
							// This solves valid PEs with custom file extensions: https://github.com/HotCakeX/Harden-Windows-Security/issues/1196
							ReadOnlySpan<char> extension = Path.GetExtension(entry.FileName);
							return lookup.Contains(extension) || (usePeValidation && !skipLookup.Contains(extension) && IsPortableExecutableLearned(learned, learnedLookup, entry.Directory, extension, entry.ToFullPath(), entry.Length));
						}
					};

					using IEnumerator<string> enumerator = enumeration.GetEnumerator();
					while (true)
					{
						cToken?.ThrowIfCancellationRequested();

						try
						{
							// Move to the next file
							// The reason we use MoveNext() instead of foreach loop is that protected/inaccessible files
							// Would throw errors and this way we can catch them and move to the next file without terminating the entire loop
							if (!enumerator.MoveNext())
							{
								// If we reach the end of the enumeration, we break out of the loop
								break;
							}
							bc.Add(enumerator.Current);
						}
						catch { }
					}
				}));

				// Check for immediate sub-directories and process them if present
				FileSystemEnumerable<FileSystemInfo> subDirectoryEnumeration = new(
					directory,
					(ref entry) => entry.ToFileSystemInfo(),
					ImmediateDirectoriesEnumeration)
				{
					ShouldIncludePredicate = (ref entry) => entry.IsDirectory
				};

				using IEnumerator<FileSystemInfo> subDirectoryEnumerator = subDirectoryEnumeration.GetEnumerator();
				while (true)
				{
					cToken?.ThrowIfCancellationRequested();

					try
					{
						if (!subDirectoryEnumerator.MoveNext())
						{
							break;
						}
					}
					catch
					{
						break;
					}

					FileSystemInfo subDirectory = subDirectoryEnumerator.Current;

					// Process files in each sub-directory concurrently
					tasks.Add(Task.Run(() =>
					{

						FileSystemEnumerable<string> enumeration = new(
							subDirectory.FullName,
							(ref entry) => entry.ToFullPath(),
							RecursiveEnumeration)
						{
							ShouldIncludePredicate = (ref entry) =>
							{
								// Skip directories.
								if (entry.IsDirectory)
								{
									return false;
								}

								// Find valid PE files that are candidate for Windows image loading and App Control evaluation.
								// First use the zero-allocation file extension checking fast path, only inspect file contents when the extension is unknown
								// This solves valid PEs with custom file extensions: https://github.com/HotCakeX/Harden-Windows-Security/issues/1196
								ReadOnlySpan<char> extension = Path.GetExtension(entry.FileName);
								return lookup.Contains(extension) || (usePeValidation && !skipLookup.Contains(extension) && IsPortableExecutableLearned(learned, learnedLookup, entry.Directory, extension, entry.ToFullPath(), entry.Length));
							}
						};

						using IEnumerator<string> subEnumerator = enumeration.GetEnumerator();
						while (true)
						{
							cToken?.ThrowIfCancellationRequested();

							try
							{
								if (!subEnumerator.MoveNext())
								{
									break;
								}
								bc.Add(subEnumerator.Current);
							}
							catch { }
						}
					}));
				}
			}
		}

		#endregion

		#region Files

		// If files are provided, process them
		if (files is { Count: > 0 })
		{
			// Ensure the files aren't already in the directories that were scanned
			IReadOnlyCollection<string> filesToUse = directories is not null && directories.Count > 0 ?
				TestFilePath(directories, files) :
				files;

			// Make sure the files have the correct extension
			foreach (string file in filesToUse)
			{
				cToken?.ThrowIfCancellationRequested();

				ReadOnlySpan<char> extension = Path.GetExtension(file.AsSpan());
				if (lookup.Contains(extension) || (usePeValidation && !skipLookup.Contains(extension) && IsPortableExecutableLearned(learned, learnedLookup, Path.GetDirectoryName(file.AsSpan()), extension, file)))
				{
					bc.Add(file);
				}
			}
		}

		#endregion

		// Wait for all tasks to be completed
		Task.WaitAll(tasks);

		// Stop adding items to the collection
		bc.CompleteAdding();

		// Stop measuring time
		stopwatch.Stop();

		// Get the elapsed time
		TimeSpan elapsedTime = stopwatch.Elapsed;

		Logger.Write(
			string.Format(
				Atlas.GetStr("FileEnumerationDurationMessage"),
				elapsedTime.Hours,
				elapsedTime.Minutes,
				elapsedTime.Seconds
			)
		);

		return (bc.GetConsumingEnumerable(), bc.Count);
	}
}
