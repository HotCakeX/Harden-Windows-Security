using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;

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
            HashSet<DirectoryInfo> programsPaths = new HashSet<DirectoryInfo>(new DirectoryInfoComparer());

            do
            {
                using (FolderBrowserDialog dialog = new FolderBrowserDialog())
                {
                    dialog.Description = "To stop selecting directories, press ESC or select Cancel.";
                    dialog.ShowNewFolderButton = false;
                    dialog.RootFolder = Environment.SpecialFolder.MyComputer;

                    // Use ShowDialog and set top most by using Win32 API
                    // This method is much better than the ShowDialog overload that takes a parent form
                    // This makes the opened File/Folder picker top most without the ability to go behind the window that initiated it
                    // Which is the experience that other native Windows applications have
                    // Also after picking a directory, the next time the picker GUI opens up will be in the same directory as the last time instead of opening at C drive or some other default location
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
            public IntPtr Handle => _hwnd;
        }
    }
}
