using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

#nullable enable

namespace WDACConfig
{
    public static class DirectorySelector
    {
        /// <summary>
        /// Keeps asking for directories until the user cancels the selection
        /// returns unique DirectoryInfo[] of selected directories if user actually selected directories
        /// returns null if user did not select any categories
        /// </summary>
        /// <returns></returns>
        public static DirectoryInfo[]? SelectDirectories()
        {
            // HashSet to store unique selected directories
            HashSet<DirectoryInfo> programsPaths = new(new DirectoryInfoComparer());

            do
            {
                string? SelectedFolderPath = FileSystemPicker.ShowDirectoryPicker("Select a folder | To stop selecting folders, press ESC or select Cancel.");

                if (SelectedFolderPath is not null)
                {
                    _ = programsPaths.Add(new DirectoryInfo(SelectedFolderPath));
                }
                else
                {
                    break;
                }
            } while (true);

            // return null if no directories were selected or the array of selected directories if there are any
            return programsPaths.Count > 0 ? programsPaths.ToArray() : null;
        }

        // Comparer for DirectoryInfo to ensure uniqueness and do it in a case-insensitive way
        private class DirectoryInfoComparer : IEqualityComparer<DirectoryInfo>
        {
            public bool Equals(DirectoryInfo? x, DirectoryInfo? y)
            {
                // If both are null, they are considered equal
                if (x == null && y == null)
                {
                    return true;
                }

                // If one is null but not the other, they are not equal
                if (x == null || y == null)
                {
                    return false;
                }

                // Compare full path in a case-insensitive way
                return string.Equals(x.FullName, y.FullName, StringComparison.OrdinalIgnoreCase);
            }

            // Get hash code of the full path in a case-insensitive way using StringComparer.OrdinalIgnoreCase
            public int GetHashCode(DirectoryInfo obj)
            {
                return StringComparer.OrdinalIgnoreCase.GetHashCode(obj.FullName);
            }
        }
    }
}
