using System;
using System.Collections.Generic;

#nullable enable

namespace WDACConfig
{
    public class FileDirectoryPathComparer
    {
        /// <summary>
        /// Method that takes 2 arrays, one containing file paths and the other containing folder paths.
        /// It checks them and returns the unique file paths that are not in any of the folder paths.
        /// Performs this check recursively, so it works if a filepath is in a sub-directory of a folder path.
        /// It works even if the file paths or folder paths are non-existent/deleted, but they still need to be valid file/folder paths.
        /// </summary>
        /// <param name="directoryPaths">Array of directory paths</param>
        /// <param name="filePaths">Array of file paths</param>
        /// <returns>List of unique file paths that don't reside in any of the directory paths (or their sub-directory paths)</returns>
        public static List<string> TestFilePath(string[] directoryPaths, string[] filePaths)
        {
            HashSet<string> output = new(StringComparer.OrdinalIgnoreCase);

            // Loop through each file path
            foreach (string file in filePaths)
            {
                bool isInDirectory = false;

                // Loop through each directory path
                foreach (string directory in directoryPaths)
                {
                    // Check if the file path starts with the directory path
                    if (file.StartsWith(directory, StringComparison.OrdinalIgnoreCase))
                    {
                        // The file is inside the directory or its sub-directories
                        isInDirectory = true;
                        break;
                    }
                }

                // Output the file path if it is not inside any of the directory paths
                if (!isInDirectory)
                {
                    _ = output.Add(file);
                }
            }

            // Return the unique file paths that don't reside in any of the directory paths (or their sub-directory paths)
            return new List<string>(output);
        }
    }
}
