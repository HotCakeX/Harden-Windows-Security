using System;
using System.Collections.Generic;
using System.IO;
using System.Windows.Forms;
using System.Linq;
using System.Runtime.InteropServices;

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

                    // Use ShowDialog and set top most by using Win32 API
                    IntPtr hwnd = GetForegroundWindow();
                    DialogResult result = dialog.ShowDialog(new WindowWrapper(hwnd));
                    if (result == DialogResult.OK)
                    {
                        programsPaths.Add(new DirectoryInfo(dialog.SelectedPath));
                    }
                    else
                    {
                        break;
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

        // P/Invoke declarations
        [DllImport("user32.dll")]
        // Get the handle of the foreground window
        // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getforegroundwindow
        private static extern IntPtr GetForegroundWindow();

        // Wrapper class to satisfy IWin32Window interface
        public class WindowWrapper : IWin32Window
        {
            private IntPtr _hwnd;
            public WindowWrapper(IntPtr handle)
            {
                _hwnd = handle;
            }

            // Property to satisfy IWin32Window interface
            public IntPtr Handle
            {
                get { return _hwnd; }
            }
        }
    }
}
