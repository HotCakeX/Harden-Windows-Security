using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;

namespace HardenWindowsSecurity;

public static class SneakAndPeek
{
	/// <summary>
	/// Takes a peek into a zip file and returns bool based on whether a file based on the query is found or not
	/// </summary>
	/// <param name="query"></param>
	/// <param name="zipFile"></param>
	/// <returns></returns>
	public static bool Search(string query, string zipFile)
	{
		// Convert the query to a regular expression
		string regexPattern = "^" + Regex.Escape(query).Replace("\\*", ".*", StringComparison.OrdinalIgnoreCase) + "$";
		Regex regex = new(regexPattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

		// Open the zip file in read mode
		using ZipArchive zipArchive = ZipFile.OpenRead(zipFile);

		// Make sure the selected zip has the required file
		List<ZipArchiveEntry> content = [.. zipArchive.Entries.Where(entry => regex.IsMatch(entry.FullName))];

		// Return true if the number of files found is greater than 0
		return content.Count > 0;
	}
}
