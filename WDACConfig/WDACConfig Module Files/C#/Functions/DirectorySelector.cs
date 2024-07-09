using System;
using System.Collections.Generic;
using System.IO;
using System.Windows.Forms;
using System.Linq;

namespace WDACConfig
{
    public static class DirectorySelector
    {
        // Keeps asking for directories until the user cancels the selection
        // returns unique DirectoryInfo[] of selected directories
        public static DirectoryInfo[] SelectDirectories()
        {
            // HashSet to store unique selected directories
            HashSet<DirectoryInfo> programsPaths = new HashSet<DirectoryInfo>(new DirectoryInfoComparer());

            do
            {
                using (FolderBrowserDialog dialog = new FolderBrowserDialog())
                {
                    dialog.Description = "To stop selecting directories, press ESC or select Cancel.";
                    dialog.ShowNewFolderButton = false;
                    dialog.RootFolder = Environment.SpecialFolder.MyComputer;

                    using (Form form = new Form { TopMost = true })
                    {
                        DialogResult result = dialog.ShowDialog(form);
                        if (result == DialogResult.OK)
                        {
                            programsPaths.Add(new DirectoryInfo(dialog.SelectedPath));
                        }
                        else
                        {
                            break;
                        }
                    }
                }
            } while (true);

            // return null if no directories were selected or the array of selected directories if there are any
            return programsPaths.Count > 0 ? programsPaths.ToArray() : null;
        }

        // Comparer for DirectoryInfo to ensure uniqueness and do it in a case-insensitive way
        private class DirectoryInfoComparer : IEqualityComparer<DirectoryInfo>
        {
            public bool Equals(DirectoryInfo x, DirectoryInfo y)
            {
                // Compare full path in a case-insensitive way
                return x.FullName.Equals(y.FullName, StringComparison.OrdinalIgnoreCase);
            }

            // Get hash code of the full path in a case-insensitive way
            public int GetHashCode(DirectoryInfo obj)
            {
                return obj.FullName.ToLowerInvariant().GetHashCode();
            }
        }
    }
}
