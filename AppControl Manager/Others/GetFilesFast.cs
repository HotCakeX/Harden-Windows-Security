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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

namespace AppControlManager.Others;

internal static class FileUtility
{
	// Used to enumerate all files, recursively inside each sub-directory of each user-selected directory
	private static readonly EnumerationOptions options = new()
	{
		IgnoreInaccessible = true,
		RecurseSubdirectories = true,
		AttributesToSkip = FileAttributes.None
	};

	// Used to only enumerate the files in each user-selected directories
	private static readonly EnumerationOptions options2 = new()
	{
		IgnoreInaccessible = true,
		RecurseSubdirectories = false,
		AttributesToSkip = FileAttributes.None
	};


	// The Default App Control supported extensions, case-insensitive
	private static readonly HashSet<string> appControlExtensions = new(StringComparer.OrdinalIgnoreCase)
		{
			".sys", ".exe", ".com", ".dll", ".rll", ".ocx", ".msp", ".mst", ".msi",
			".js", ".vbs", ".ps1", ".appx", ".bin", ".bat", ".hxs", ".mui", ".lex", ".mof"
		};


	/// <summary>
	/// Custom HashSet comparer to compare two FileInfo objects based on their FullName (full path of file)
	/// </summary>
	private sealed class FileInfoComparer : IEqualityComparer<FileInfo>
	{
		public bool Equals(FileInfo? x, FileInfo? y)
		{
			if (x is null || y is null)
				return x == y;

			// Compare by file path
			return x.FullName.Equals(y.FullName, StringComparison.OrdinalIgnoreCase);
		}

		public int GetHashCode(FileInfo obj)
		{
			// Hash based on the file path
			return obj.FullName.ToLowerInvariant().GetHashCode(StringComparison.OrdinalIgnoreCase);
		}
	}


	/// <summary>
	/// A flexible and fast method that can accept directory paths and file paths as input and return a list of FileInfo objects that are compliant with the App Control policy.
	/// It supports custom extensions to filter by as well.
	/// </summary>
	/// <param name="directories">Directories to process.</param>
	/// <param name="files">Files to process.</param>
	/// <param name="extensionsToFilterBy">Extensions to filter by. If null or empty, default App Control supported extensions are used.</param>
	/// <returns>List of FileInfo objects.</returns>
	internal static List<FileInfo> GetFilesFast(
		DirectoryInfo[]? directories,
		FileInfo[]? files,
		string[]? extensionsToFilterBy)
	{
		// Create a Stopwatch instance and start measuring time
		Stopwatch stopwatch = Stopwatch.StartNew();

		// A HashSet used to store extensions to filter files
		HashSet<string> extensions = new(StringComparer.OrdinalIgnoreCase);

		// If custom extensions are provided, use them and make them case-insensitive
		if (extensionsToFilterBy is { Length: > 0 })
		{
			extensions = new HashSet<string>(extensionsToFilterBy, StringComparer.OrdinalIgnoreCase);
		}
		else
		{
			extensions = appControlExtensions;
		}

		// Define a HashSet to store the final output
		HashSet<FileInfo> output = new(new FileInfoComparer());

		// https://learn.microsoft.com/en-us/dotnet/api/system.collections.concurrent.blockingcollection-1
		// https://learn.microsoft.com/en-us/dotnet/standard/collections/thread-safe/when-to-use-a-thread-safe-collection
		// https://learn.microsoft.com/en-us/dotnet/standard/collections/thread-safe/blockingcollection-overview
		using BlockingCollection<FileInfo> bc = [];

		// To store all of the tasks
		List<Task> tasks = [];


		#region Directories

		// Process directories if provided
		if (directories is { Length: > 0 })
		{
			foreach (DirectoryInfo directory in directories)
			{
				// Process files in the current directory
				tasks.Add(Task.Run(() =>
				{
					IEnumerator<FileInfo> enumerator = directory.EnumerateFiles("*", options2).GetEnumerator();

					// If there is wildcard in extensions to filter by, then add all files without performing extension check
					if (extensions.Contains("*"))
					{
						while (true)
						{
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
					}
					// Filter files by extensions if there is no wildcard character for filtering
					else
					{
						while (true)
						{
							try
							{
								// Move to the next file
								if (!enumerator.MoveNext())
								{
									// If we reach the end of the enumeration, we break out of the loop
									break;
								}

								// Check if the file extension is in the Extensions HashSet or Wildcard was used
								if (extensions.Contains(enumerator.Current.Extension))
								{
									bc.Add(enumerator.Current);
								}
							}
							catch { }
						}
					}
				}));


				// Check for immediate sub-directories and process them if present
				DirectoryInfo[] subDirectories = directory.GetDirectories();

				if (subDirectories.Length > 0)
				{
					foreach (DirectoryInfo subDirectory in subDirectories)
					{
						// Process files in each sub-directory concurrently
						tasks.Add(Task.Run(() =>
						{
							IEnumerator<FileInfo> subEnumerator = subDirectory.EnumerateFiles("*", options).GetEnumerator();

							if (extensions.Contains("*"))
							{
								while (true)
								{
									try
									{
										// Move to the next file
										if (!subEnumerator.MoveNext())
										{
											// If we reach the end of the enumeration, we break out of the loop
											break;
										}
										bc.Add(subEnumerator.Current);
									}
									catch { }
								}
							}
							else
							{
								while (true)
								{
									try
									{
										// Move to the next file
										if (!subEnumerator.MoveNext())
										{
											// If we reach the end of the enumeration, we break out of the loop
											break;
										}

										// Check if the file extension is in the Extensions HashSet or Wildcard was used
										if (extensions.Contains(subEnumerator.Current.Extension))
										{
											bc.Add(subEnumerator.Current);
										}
									}
									catch { }
								}
							}
						}));
					}
				}

			}
		}

		#endregion


		#region Files

		// If files are provided, process them
		if (files is { Length: > 0 })
		{
			// If user provided wildcard then add all files without checking their extensions
			if (extensions.Contains("*"))
			{
				foreach (FileInfo file in files)
				{
					bc.Add(file);
				}
			}
			// If user provided no extensions to filter by or provided extensions that are not wildcard
			else
			{
				foreach (FileInfo file in files)
				{
					if (extensions.Contains(file.Extension))
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

		// Add each item to the HashSet from the Blocking Collection
		foreach (FileInfo item in bc.GetConsumingEnumerable())
		{
			_ = output.Add(item);
		}

		// Stop measuring time
		stopwatch.Stop();

		// Get the elapsed time
		TimeSpan elapsedTime = stopwatch.Elapsed;

		Logger.Write($"File enumeration took {elapsedTime.Hours} hours and {elapsedTime.Minutes} minutes and {elapsedTime.Seconds} seconds to complete.");

		return [.. output];
	}
}
