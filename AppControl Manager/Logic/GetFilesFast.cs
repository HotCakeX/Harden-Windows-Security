using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using AppControlManager.Logging;

namespace AppControlManager;

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

		// Use the Default App Control supported extensions and make them case-insensitive
		HashSet<string> extensions = new(StringComparer.OrdinalIgnoreCase)
		{
			".sys", ".exe", ".com", ".dll", ".rll", ".ocx", ".msp", ".mst", ".msi",
			".js", ".vbs", ".ps1", ".appx", ".bin", ".bat", ".hxs", ".mui", ".lex", ".mof"
		};

		// If custom extensions are provided, use them and make them case-insensitive
		if (extensionsToFilterBy is { Length: > 0 })
		{
			extensions = new HashSet<string>(extensionsToFilterBy, StringComparer.OrdinalIgnoreCase);
		}

		// Define a HashSet to store the final output
		HashSet<FileInfo> output = new(new FileInfoComparer());

		// https://learn.microsoft.com/en-us/dotnet/api/system.collections.concurrent.blockingcollection-1
		// https://learn.microsoft.com/en-us/dotnet/standard/collections/thread-safe/when-to-use-a-thread-safe-collection
		// https://learn.microsoft.com/en-us/dotnet/standard/collections/thread-safe/blockingcollection-overview
		using BlockingCollection<FileInfo> bc = [];

		// To store all of the tasks
		List<Task> tasks = [];

		// Process directories if provided
		if (directories is { Length: > 0 })
		{
			foreach (DirectoryInfo directory in directories)
			{
				// Process files in the current directory
				tasks.Add(Task.Run(() =>
				{
					IEnumerator<FileInfo> enumerator = directory.EnumerateFiles("*", options2).GetEnumerator();
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
							if (extensions.Contains(enumerator.Current.Extension) || extensions.Contains("*"))
							{
								bc.Add(enumerator.Current);
							}
						}
						catch { }
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
									if (extensions.Contains(subEnumerator.Current.Extension) || extensions.Contains("*"))
									{
										bc.Add(subEnumerator.Current);
									}
								}
								catch { }
							}
						}));
					}
				}

			}
		}

		// If files are provided, process them
		if (files is { Length: > 0 })
		{
			foreach (FileInfo file in files)
			{
				if (extensions.Contains(file.Extension))
				{
					bc.Add(file);
				}
			}
		}

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
