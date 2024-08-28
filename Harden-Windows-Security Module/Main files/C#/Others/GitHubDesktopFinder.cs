using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class GitHubDesktopFinder
    {
        // This method searches for .exe files in the specified path and returns a list of FileInfo objects
        public static List<FileInfo>? Find()
        {
            // Get the current user's name
            string userName = Environment.UserName;
            // Define the base path to search
            string basePath = $@"C:\Users\{userName}\AppData\Local\GitHubDesktop";

            // Check if the base path exists
            if (!Directory.Exists(basePath))
            {
                return null;
            }

            // Get all directories under the base path that contain "resources\app\git"
            var directories = Directory.GetDirectories(basePath, "*", SearchOption.AllDirectories)
                                       .Where(d => d.Contains(@"resources\app\git", StringComparison.OrdinalIgnoreCase));

            // Initialize a list to store the found FileInfo objects
            List<FileInfo> fileList = new List<FileInfo>();

            // Iterate through each directory
            foreach (var dir in directories)
            {
                // Get all .exe files in the current directory
                var files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
                // Add each FileInfo object to the list
                fileList.AddRange(files.Select(file => new FileInfo(file)));
            }

            // Return null if no files were found
            if (fileList.Count == 0)
            {
                return null;
            }

            // Return the list of FileInfo objects
            return fileList;
        }
    }
}
