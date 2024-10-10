using System;
using System.Collections.Generic;
using System.IO;

#nullable enable

namespace WDACConfig
{
    public class FileUtility
    {
        /// <summary>
        /// A flexible and fast method that can accept directory paths and file paths as input and return a list of FileInfo objects that are compliant with the WDAC policy.
        /// It supports custom extensions to filter by as well.
        /// </summary>
        /// <param name="directories">Directories to process.</param>
        /// <param name="files">Files to process.</param>
        /// <param name="extensionsToFilterBy">Extensions to filter by. If null or empty, default WDAC supported extensions are used.</param>
        /// <returns>List of FileInfo objects.</returns>
        public static List<FileInfo> GetFilesFast(
            DirectoryInfo[] directories,
            FileInfo[]? files,
            string[] extensionsToFilterBy)
        {

            // Use the Default WDAC supported extensions and make them case-insensitive
            HashSet<string> extensions = new(StringComparer.InvariantCultureIgnoreCase)
            {
            ".sys", ".exe", ".com", ".dll", ".rll", ".ocx", ".msp", ".mst", ".msi",
            ".js", ".vbs", ".ps1", ".appx", ".bin", ".bat", ".hxs", ".mui", ".lex", ".mof"
            };

            // If custom extensions are provided, use them and make them case-insensitive
            if (extensionsToFilterBy != null && extensionsToFilterBy.Length > 0)
            {
                extensions = new HashSet<string>(extensionsToFilterBy, StringComparer.InvariantCultureIgnoreCase);
            }

            // Define a HashSet to store the final output
            HashSet<FileInfo> output = [];

            EnumerationOptions options = new()
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                AttributesToSkip = FileAttributes.None
            };

            // Process directories if provided
            if (directories != null && directories.Length > 0)
            {
                foreach (DirectoryInfo directory in directories)
                {
                    IEnumerator<FileInfo> enumerator = directory.EnumerateFiles("*", options).GetEnumerator();
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
                                _ = output.Add(enumerator.Current);
                            }
                        }
                        catch { }
                    }
                }
            }

            // If files are provided, process them
            if (files != null && files.Length > 0)
            {
                foreach (FileInfo file in files)
                {
                    if (extensions.Contains(file.Extension))
                    {
                        _ = output.Add(file);
                    }
                }
            }

            return new List<FileInfo>(output);
        }
    }
}
