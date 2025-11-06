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

using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Enumeration;
using System.Threading;
using System.Threading.Tasks;

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
		// Normalize each directory‐path into an absolute path ending with a single separator.
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
				// If the file‐string is not a valid path, skip it
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
				// Use the original file‐string (not the full‐path) in the output set
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


	// The Default App Control supported extensions, case-insensitive
	private static readonly FrozenSet<string> AppControlExtensions = new string[]
	{
		".sys", ".exe", ".com", ".dll", ".rll", ".ocx", ".msp", ".mst", ".msi",
		".js", ".vbs", ".ps1", ".appx", ".bin", ".bat", ".hxs", ".mui", ".lex", ".mof"
	}.ToFrozenSet(StringComparer.OrdinalIgnoreCase);


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
		FrozenSet<string> extensions;

		// If custom extensions are provided, use them and make them case-insensitive
		if (extensionsToFilterBy is { Length: > 0 })
		{
			extensions = extensionsToFilterBy.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
		}
		else
		{
			extensions = AppControlExtensions;
		}

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

					FileSystemEnumerable<FileSystemInfo> enumeration = new(
							directory,
							(ref entry) => entry.ToFileSystemInfo(),
							NonRecurseEnumeration)
					{
						ShouldIncludePredicate = (ref entry) =>
						{
							// Skip directories.
							if (entry.IsDirectory)
							{
								return false;
							}

							// If the file has the correct extension or wildcard was used
							if (extensions.Contains("*") || extensions.Contains(Path.GetExtension(entry.ToFullPath())))
							{
								return true;
							}

							return false;
						}
					};

					IEnumerator<FileSystemInfo> enumerator = enumeration.GetEnumerator();

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
							bc.Add(enumerator.Current.FullName);
						}
						catch { }
					}
				}));


				// Check for immediate sub-directories and process them if present
				DirectoryInfo[] subDirectories = new DirectoryInfo(directory).GetDirectories();

				if (subDirectories.Length > 0)
				{
					foreach (DirectoryInfo subDirectory in subDirectories)
					{
						// Process files in each sub-directory concurrently
						tasks.Add(Task.Run(() =>
						{

							FileSystemEnumerable<FileSystemInfo> enumeration = new(
								subDirectory.FullName,
								(ref entry) => entry.ToFileSystemInfo(),
								RecursiveEnumeration)
							{
								ShouldIncludePredicate = (ref entry) =>
								{
									// Skip directories.
									if (entry.IsDirectory)
									{
										return false;
									}

									// If the file has the correct extension or wildcard was used
									if (extensions.Contains("*") || extensions.Contains(Path.GetExtension(entry.ToFullPath())))
									{
										return true;
									}

									return false;
								}
							};

							IEnumerator<FileSystemInfo> subEnumerator = enumeration.GetEnumerator();
							while (true)
							{
								cToken?.ThrowIfCancellationRequested();

								try
								{
									if (!subEnumerator.MoveNext())
									{
										break;
									}
									bc.Add(subEnumerator.Current.FullName);
								}
								catch { }
							}
						}));
					}
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

			// If user provided wildcard then add all files without checking their extensions
			if (extensions.Contains("*"))
			{
				foreach (string file in filesToUse)
				{
					cToken?.ThrowIfCancellationRequested();

					bc.Add(file);
				}
			}
			// If user provided no extensions to filter by or provided extensions that are not wildcard
			else
			{
				foreach (string file in filesToUse)
				{
					cToken?.ThrowIfCancellationRequested();

					if (extensions.Contains(Path.GetExtension(file)))
					{
						bc.Add(file);
					}
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
				GlobalVars.GetStr("FileEnumerationDurationMessage"),
				elapsedTime.Hours,
				elapsedTime.Minutes,
				elapsedTime.Seconds
			)
		);

		return (bc.GetConsumingEnumerable(), bc.Count);
	}
}
