using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using AppControlManager.Others;
using static AppControlManager.AppSettings.AppSettingsCls;

namespace AppControlManager.IntelGathering;

internal static class CatRootScanner
{
	// Cache variables to store the last scan result and the time it was updated
	private static DateTime _lastScanTime = DateTime.MinValue;
	private static ConcurrentDictionary<string, string> _cachedResult = [];

	/// <summary>
	/// Scans the CatRoot directory for security catalogs and returns a dictionary with the hashes of the security catalogs and their file paths
	/// </summary>
	/// <param name="paths">Directories to scan for .cat files. if not provided, "C:\Windows\System32\CatRoot" will be used.</param>
	/// <param name="scalability">How many concurrent threads will be used to scan the files in parallel. If not provided, 4 will be used.</param>
	/// <returns></returns>
	internal static ConcurrentDictionary<string, string> Scan(List<string>? paths, ushort scalability)
	{
		// If caching is enabled
		if (GetSetting<bool>(SettingKeys.CacheSecurityCatalogsScanResults))
		{
			// Check if the cached result is still valid (within 5 minutes) and return it if so
			if ((DateTime.Now - _lastScanTime) < TimeSpan.FromMinutes(5))
			{
				Logger.Write("Returning cached security catalog scan result");
				return _cachedResult;
			}
		}

		// The output dictionary that will contain the hashes of the security catalogs and their file paths
		ConcurrentDictionary<string, string> output = [];

		List<DirectoryInfo> DirectoriesToScan = [];

		if (paths is { Count: > 0 })
		{
			foreach (string item in paths)
			{
				DirectoriesToScan.Add(new DirectoryInfo(item));
			}
		}
		else
		{
			// Use the default directory in the OS if no other paths were provided
			DirectoriesToScan.Add(new(@"C:\Windows\System32\CatRoot"));
		}

		// Get the .cat files in the CatRoot directories
		List<FileInfo> detectedCatFiles = FileUtility.GetFilesFast([.. DirectoriesToScan], null, [".cat"]);

		Logger.Write($"Including {detectedCatFiles.Count} Security Catalogs in the scan process");

		// Make sure the degree of parallelism is always at least 4
		ParallelOptions options = new() { MaxDegreeOfParallelism = scalability is > 4 ? scalability : 4 };

		_ = Parallel.ForEach(detectedCatFiles, options, file =>
		{
			// Get the hashes of the security catalog file
			HashSet<string> catHashes = MeowParser.GetHashes(file.FullName);

			// If the security catalog file has hashes, then add them to the dictionary
			if (catHashes.Count > 0)
			{
				foreach (string hash in catHashes)
				{
					_ = output.TryAdd(hash, file.FullName);
				}
			}
		});

		// If caching is enabled
		if (GetSetting<bool>(SettingKeys.CacheSecurityCatalogsScanResults))
		{
			// Update the cache with the new results and set the cache timestamp
			_cachedResult = output;
			_lastScanTime = DateTime.Now;
		}

		return output;
	}
}
