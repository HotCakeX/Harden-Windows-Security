using System;
using System.Runtime.InteropServices;

#nullable enable

namespace WDACConfig
{
    public class FileSystemPicker
    {


        /// <summary>
        /// Usage example
        /// All params are optional
        /// FileSystemPicker.ShowFilePicker(
        /// "Choose a Configuration File",
        /// ("XML Files", "*.xml"),
        /// ("All Files", "*.*")
        /// </summary>
        /// <param name="title"></param>
        /// <param name="filters"></param>
        /// <returns></returns>
        public static string? ShowFilePicker(string title = "Select a file", params (string Description, string Extension)[] filters)
        {
            IFileOpenDialog dialog = (IFileOpenDialog)new FileOpenDialog();

            try
            {
                // Set the dialog title
                dialog.SetTitle(title);

                // Create the file type filters based on the passed parameters
                if (filters != null && filters.Length > 0)
                {
                    COMDLG_FILTERSPEC[] filterSpecs = new COMDLG_FILTERSPEC[filters.Length];
                    for (int i = 0; i < filters.Length; i++)
                    {
                        filterSpecs[i] = new COMDLG_FILTERSPEC
                        {
                            pszName = filters[i].Description,
                            pszSpec = filters[i].Extension
                        };
                    }

                    // Set the file type filters for the dialog
                    dialog.SetFileTypes((uint)filters.Length, filterSpecs);
                }

                // Show the File Open Dialog and check the return value
                int hr = dialog.Show(IntPtr.Zero);

                // Check if the user canceled the dialog
                if (hr != 0)
                {
                    // If canceled, return null
                    return null;
                }

                // Retrieve the selected item
                dialog.GetResult(out IShellItem result);

                // Get the file path from the selected item
                result.GetDisplayName(SIGDN.SIGDN_FILESYSPATH, out IntPtr ppszFilePath);

                // Convert the file path to a string
                string? filePath = Marshal.PtrToStringAuto(ppszFilePath);

                // Free the memory allocated for the file path
                Marshal.FreeCoTaskMem(ppszFilePath);

                return filePath;
            }
            catch (COMException)
            {
                // cancellation or errors
                return null;
            }
            finally
            {
                // Release COM objects
                _ = Marshal.ReleaseComObject(dialog);
            }
        }


        /// <summary>
        /// Opens file picker allowing multiple files to be selected
        /// </summary>
        /// <param name="title"></param>
        /// <param name="filters"></param>
        /// <returns></returns>
        public static string[]? ShowMultiFilePicker(string title = "Select files", params (string Description, string Extension)[] filters)
        {
            IFileOpenDialog dialog = (IFileOpenDialog)new FileOpenDialog();

            try
            {
                dialog.SetTitle(title);

                if (filters != null && filters.Length > 0)
                {
                    COMDLG_FILTERSPEC[] filterSpecs = new COMDLG_FILTERSPEC[filters.Length];
                    for (int i = 0; i < filters.Length; i++)
                    {
                        filterSpecs[i] = new COMDLG_FILTERSPEC
                        {
                            pszName = filters[i].Description,
                            pszSpec = filters[i].Extension
                        };
                    }
                    dialog.SetFileTypes((uint)filters.Length, filterSpecs);
                }

                // Enable multiple file selection
                dialog.SetOptions(FOS.FOS_FORCEFILESYSTEM | FOS.FOS_ALLOWMULTISELECT);

                int hr = dialog.Show(IntPtr.Zero);
                if (hr != 0) return null;

                // Retrieve the results (multiple selected items)
                dialog.GetResults(out IntPtr ppenum);
                IShellItemArray shellItemArray = (IShellItemArray)Marshal.GetObjectForIUnknown(ppenum);

                shellItemArray.GetCount(out uint itemCount);
                string[] filePaths = new string[itemCount];

                for (uint i = 0; i < itemCount; i++)
                {
                    shellItemArray.GetItemAt(i, out IShellItem item);
                    item.GetDisplayName(SIGDN.SIGDN_FILESYSPATH, out IntPtr ppszFilePath);
                    filePaths[i] = Marshal.PtrToStringAuto(ppszFilePath)!;
                    Marshal.FreeCoTaskMem(ppszFilePath);
                }

                return filePaths;
            }
            catch (COMException)
            {
                return null;
            }
            finally
            {
                _ = Marshal.ReleaseComObject(dialog);
            }
        }



        /// <summary>
        /// Opens a directory picker allowing a single folder to be selected.
        /// </summary>
        /// <param name="title"></param>
        /// <returns></returns>
        public static string? ShowDirectoryPicker(string title = "Select a folder")
        {
            IFileOpenDialog dialog = (IFileOpenDialog)new FileOpenDialog();

            try
            {
                // Set the dialog title
                dialog.SetTitle(title);

                // Set options to pick folders only
                dialog.SetOptions(FOS.FOS_FORCEFILESYSTEM | FOS.FOS_PICKFOLDERS);

                // Show the Folder Open Dialog
                int hr = dialog.Show(IntPtr.Zero);
                if (hr != 0) return null;

                // Retrieve the selected item
                dialog.GetResult(out IShellItem result);

                // Get the folder path from the selected item
                result.GetDisplayName(SIGDN.SIGDN_FILESYSPATH, out IntPtr ppszFolderPath);

                // Convert the folder path to a string
                string? folderPath = Marshal.PtrToStringAuto(ppszFolderPath);

                // Free the memory allocated for the folder path
                Marshal.FreeCoTaskMem(ppszFolderPath);

                return folderPath;
            }
            catch (COMException)
            {
                return null;
            }
            finally
            {
                // Release COM objects
                _ = Marshal.ReleaseComObject(dialog);
            }
        }



        // COM interfaces and classes
        [ComImport]
        [Guid("d57c7288-d4ad-4768-be02-9d969532d960")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IFileOpenDialog
        {
            [PreserveSig] int Show(IntPtr hwndParent); // Displays the dialog box
            void SetFileTypes(uint cFileTypes, [MarshalAs(UnmanagedType.LPArray)] COMDLG_FILTERSPEC[] rgFilterSpec);
            void SetFileTypeIndex(uint iFileType);
            void GetFileTypeIndex(out uint piFileType);
            void Advise(IntPtr pfde, out uint pdwCookie);
            void Unadvise(uint dwCookie);
            void SetOptions(FOS fos);
            void GetOptions(out FOS pfos);
            void SetDefaultFolder(IShellItem psi);
            void SetFolder(IShellItem psi);
            void GetFolder(out IShellItem ppsi);
            void GetCurrentSelection(out IShellItem ppsi);
            void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string pszName);
            void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string pszName);
            void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string pszTitle);
            void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string pszText);
            void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string pszLabel);
            void GetResult(out IShellItem ppsi); // Gets the result of the user's file/folder selection
            void AddPlace(IShellItem psi, FDAP fdap);
            void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string pszDefaultExtension);
            void Close(int hr);
            void SetClientGuid(ref Guid guid);
            void ClearClientData();
            void SetFilter(IntPtr pFilter);
            void GetResults(out IntPtr ppenum);
            void GetSelectedItems(out IntPtr ppsai);
        }

        [ComImport]
        [Guid("DC1C5A9C-E88A-4dde-A5A1-60F82A20AEF7")]
        private class FileOpenDialog { }

        [ComImport]
        [Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IShellItem
        {
            void BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);
            void GetParent(out IShellItem ppsi);
            void GetDisplayName(SIGDN sigdnName, out IntPtr ppszName);
            void GetAttributes(uint sfgaoMask, out uint psfgaoAttribs);
            void Compare(IShellItem psi, uint hint, out int piOrder);
        }


        [ComImport]
        [Guid("b63ea76d-1f85-456f-a19c-48159efa858b")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IShellItemArray
        {
            void BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppvOut);
            void GetPropertyStore(int flags, ref Guid riid, out IntPtr ppv);
            void GetPropertyDescriptionList(ref Guid keyType, ref Guid riid, out IntPtr ppv);
            void GetAttributes(uint dwAttribFlags, uint sfgaoMask, out uint psfgaoAttribs);
            void GetCount(out uint pdwNumItems);
            void GetItemAt(uint dwIndex, out IShellItem ppsi);
            void EnumItems(out IntPtr ppenumShellItems);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct COMDLG_FILTERSPEC
        {
            public string pszName;
            public string pszSpec;
        }

        private enum SIGDN : uint
        {
            SIGDN_FILESYSPATH = 0x80058000,
        }

        private enum FOS : uint
        {
            FOS_FORCEFILESYSTEM = 0x00000040,
            FOS_ALLOWMULTISELECT = 0x00000200, // Enable multi-select
            FOS_PICKFOLDERS = 0x00000020,      // Allows folder selection
        }

        private enum FDAP
        {
            FDAP_BOTTOM = 0x00000000,
            FDAP_TOP = 0x00000001,
        }
    }
}
