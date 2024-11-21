using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Com;
using Windows.Win32.UI.Shell;
using Windows.Win32.UI.Shell.Common;

namespace WDACConfig
{
    /// <summary>
    /// https://learn.microsoft.com/en-us/uwp/api/windows.storage.pickers.filesavepicker?view=winrt-26100
    /// This one currently has problems
    /// </summary>
    internal static class FileDialogHelper
    {
        /// <summary>
        /// Opens a file picker dialog to select a single file.
        /// </summary>
        /// <param name="filter"></param>
        /// <returns></returns>
        internal unsafe static string? ShowFilePickerDialog(string filter)
        {
            // Create an instance of the file open dialog
            int hr = PInvoke.CoCreateInstance(
                typeof(FileOpenDialog).GUID, // CLSID for FileOpenDialog
                null, // No outer object for aggregation
                CLSCTX.CLSCTX_INPROC_SERVER, // In-process server context
                out IFileOpenDialog* fileOpenDialog // Explicitly specify the output type
            );

            // If creation fails, throw an exception with the corresponding HRESULT code.
            if (hr < 0)
            {
                Marshal.ThrowExceptionForHR(hr);
            }

            // Prepare the list of file type filters based on the input string.
            List<COMDLG_FILTERSPEC> extensions = [];

            if (!string.IsNullOrEmpty(filter)) // Check if filter is provided.
            {
                // Split the filter into name and pattern pairs (e.g., "Text Files|*.txt").
                string[] tokens = filter.Split('|');

                // Ensure the pairs are valid.
                if (tokens.Length % 2 == 0)
                {
                    for (int i = 0; i < tokens.Length; i += 2)
                    {
                        COMDLG_FILTERSPEC extension;
                        extension.pszName = (char*)Marshal.StringToHGlobalUni(tokens[i]);
                        extension.pszSpec = (char*)Marshal.StringToHGlobalUni(tokens[i + 1]);
                        extensions.Add(extension);
                    }
                }
            }

            // Apply the filters to the file open dialog.
            fileOpenDialog->SetFileTypes(extensions.ToArray());

            // Set the default folder to "My Documents".
            hr = PInvoke.SHCreateItemFromParsingName(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                null,
                typeof(IShellItem).GUID,
                out void* pDirectoryShellItem
            );

            if (hr >= 0) // Proceed only if the default folder creation succeeds.
            {
                IShellItem* directoryShellItem = (IShellItem*)pDirectoryShellItem;
                fileOpenDialog->SetFolder(directoryShellItem);
                fileOpenDialog->SetDefaultFolder(directoryShellItem);

                // Release the IShellItem after use
                _ = directoryShellItem->Release();
            }

            try
            {

                try
                {
                    // Display the dialog to the user.
                    fileOpenDialog->Show(new HWND(GlobalVars.hWnd)); // Pass the parent window handle.
                }
                catch (Exception e)
                {
                    if (e.HResult == -2147023673) // Specific HRESULT for "Operation Canceled".
                    {
                        return null;
                    }

                    throw; // Re-throw unexpected exceptions.
                }
                finally
                {
                    if (fileOpenDialog != null)
                    {
                        _ = fileOpenDialog->Release();
                    }
                }

                // Retrieve the result of the dialog (selected file).
                IShellItem* ppsi = null;
                fileOpenDialog->GetResult(&ppsi);

                // Retrieve the file path
                PWSTR filename;
                ppsi->GetDisplayName(SIGDN.SIGDN_FILESYSPATH, &filename);

                // Convert to managed string
                string selectedFilePath = new(filename);

                // Free the allocated memory for filename
                if (filename.Value != null)
                {
                    Marshal.FreeCoTaskMem((IntPtr)filename.Value);
                }

                // Release COM objects
                _ = ppsi->Release();

                return selectedFilePath;
            }

            finally
            {
                if (fileOpenDialog != null)
                {
                    _ = fileOpenDialog->Release();
                }

                // Clean up extensions memory
                foreach (var extension in extensions)
                {
                    if (extension.pszName.Value != null)
                    {
                        Marshal.FreeHGlobal((IntPtr)extension.pszName.Value);
                    }
                    if (extension.pszSpec.Value != null)
                    {
                        Marshal.FreeHGlobal((IntPtr)extension.pszSpec.Value);
                    }
                }
            }
        }



        /// <summary>
        /// Opens a file picker dialog to select multiple files.
        /// </summary>
        /// <param name="filter">A file filter string in the format "Description|Extension" pairs
        /// (e.g., "Text Files|*.txt|All Files|*.*").</param>
        /// <returns>A list of selected file paths or null if the operation is cancelled.</returns>
        internal unsafe static List<string>? ShowMultipleFilePickerDialog(string filter)
        {
            // Create the file open dialog
            int hr = PInvoke.CoCreateInstance(
                typeof(FileOpenDialog).GUID, // CLSID for FileOpenDialog
                null,                        // No aggregation
                CLSCTX.CLSCTX_INPROC_SERVER, // In-process COM server
                out IFileOpenDialog* fileOpenDialog // Interface for the dialog
            );

            // If the HRESULT indicates failure, throw a corresponding .NET exception.
            if (hr < 0)
            {
                Marshal.ThrowExceptionForHR(hr);
            }

            // Initialize a list to store file type filters for the dialog.
            List<COMDLG_FILTERSPEC> extensions = [];

            if (!string.IsNullOrEmpty(filter))
            {
                // Split the filter string by '|' and process description-extension pairs.
                string[] tokens = filter.Split('|');

                // Ensure there is a valid description-extension pair for every two tokens.
                if (tokens.Length % 2 == 0)
                {
                    for (int i = 1; i < tokens.Length; i += 2)
                    {
                        COMDLG_FILTERSPEC extension;
                        extension.pszName = (char*)Marshal.StringToHGlobalUni(tokens[i - 1]);
                        extension.pszSpec = (char*)Marshal.StringToHGlobalUni(tokens[i]);
                        extensions.Add(extension);
                    }
                }
            }

            // Apply the file type filters to the dialog.
            fileOpenDialog->SetFileTypes(extensions.ToArray());

            // Set default folder to My Documents
            hr = PInvoke.SHCreateItemFromParsingName(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                null,
                typeof(IShellItem).GUID,
                out var directoryShellItem
            );

            // If the "My Documents" folder is successfully retrieved, set it as the default.
            if (hr >= 0)
            {
                fileOpenDialog->SetFolder((IShellItem*)directoryShellItem);
                fileOpenDialog->SetDefaultFolder((IShellItem*)directoryShellItem);
            }

            // Configure dialog options for multiple selection
            FILEOPENDIALOGOPTIONS options = FILEOPENDIALOGOPTIONS.FOS_ALLOWMULTISELECT;
            fileOpenDialog->SetOptions(options);

            try
            {
                // Show the dialog
                fileOpenDialog->Show(new HWND(GlobalVars.hWnd));
            }
            catch (Exception e)
            {
                if (e.HResult == -2147023673) // Operation Canceled HRESULT
                {
                    return null;
                }

                throw;
            }
            finally
            {
                if (fileOpenDialog != null)
                {
                    _ = fileOpenDialog->Release();
                }
            }

            // Retrieve the collection of selected items
            IShellItemArray* ppsiCollection = null;

            try
            {

                fileOpenDialog->GetResults(&ppsiCollection);

                // Get the number of selected files
                uint fileCount = 0;
                ppsiCollection->GetCount(&fileCount);

                // Initialize the list to store file paths
                List<string> selectedFiles = [];

                // Iterate through selected items
                for (uint i = 0; i < fileCount; i++)
                {
                    IShellItem* ppsi = null;
                    ppsiCollection->GetItemAt(i, &ppsi);

                    // Retrieve the file path
                    PWSTR filename;
                    ppsi->GetDisplayName(SIGDN.SIGDN_FILESYSPATH, &filename);

                    // Convert to managed string and add to the list
                    string filePath = new(filename.Value);
                    selectedFiles.Add(filePath);

                    // Free the unmanaged memory allocated for the file path
                    if (filename.Value != null)
                    {
                        Marshal.FreeCoTaskMem((IntPtr)filename.Value);
                    }


                    // Release the IShellItem COM object

                    _ = ppsi->Release();

                }

                return selectedFiles;
            }
            finally
            {
                // Clean up extensions memory
                foreach (var extension in extensions)
                {
                    if (extension.pszName.Value != null)
                    {
                        Marshal.FreeHGlobal((IntPtr)extension.pszName.Value);
                    }
                    if (extension.pszSpec.Value != null)
                    {
                        Marshal.FreeHGlobal((IntPtr)extension.pszSpec.Value);
                    }
                }

                // Release COM objects
                _ = ppsiCollection->Release();
                if (fileOpenDialog != null)
                {
                    _ = fileOpenDialog->Release();
                }
            }
        }





        /// <summary>
        /// Opens a folder picker dialog to select a single folder.
        /// </summary>
        /// <returns>The selected directory path as a string, or null if the operation is cancelled.</returns>
        internal unsafe static string? ShowDirectoryPickerDialog()
        {
            // Create the file open dialog
            int hr = PInvoke.CoCreateInstance(
                typeof(FileOpenDialog).GUID, // CLSID for FileOpenDialog
                null,                        // No aggregation
                CLSCTX.CLSCTX_INPROC_SERVER, // In-process COM server
                out IFileOpenDialog* fileOpenDialog // Interface for the dialog
            );

            if (hr < 0)
            {
                Marshal.ThrowExceptionForHR(hr);
            }

            // Configure dialog options to enable folder selection
            FILEOPENDIALOGOPTIONS options = FILEOPENDIALOGOPTIONS.FOS_PICKFOLDERS;
            fileOpenDialog->SetOptions(options);

            // Set default folder to "My Documents"
            hr = PInvoke.SHCreateItemFromParsingName(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                null,
                typeof(IShellItem).GUID,
                out var directoryShellItem
            );

            // If the "My Documents" folder is successfully retrieved, set it as the default.
            if (hr >= 0)
            {
                fileOpenDialog->SetFolder((IShellItem*)directoryShellItem);
                fileOpenDialog->SetDefaultFolder((IShellItem*)directoryShellItem);
            }

            try
            {
                // Show the dialog
                fileOpenDialog->Show(new HWND(GlobalVars.hWnd));
            }
            catch (Exception e)
            {
                if (e.HResult == -2147023673) // Operation Canceled HRESULT
                {
                    return null;
                }

                throw;
            }
            finally
            {
                // Release the IFileOpenDialog COM object
                if (fileOpenDialog != null)
                {
                    _ = fileOpenDialog->Release();
                }
            }

            // Retrieve the selected folder
            IShellItem* ppsi = null;

            try
            {

                fileOpenDialog->GetResult(&ppsi);

                // Get the file system path of the folder
                PWSTR folderPath;
                ppsi->GetDisplayName(SIGDN.SIGDN_FILESYSPATH, &folderPath);

                // Convert to managed string
                string selectedFolderPath = new(folderPath.Value);

                // Free unmanaged memory for the folder path
                Marshal.FreeCoTaskMem((IntPtr)folderPath.Value);

                return selectedFolderPath;

            }
            finally
            {
                // Clean up the IShellItem COM object
                _ = ppsi->Release();


                // Release the IFileOpenDialog COM object
                if (fileOpenDialog != null)
                {
                    _ = fileOpenDialog->Release();
                }
            }
        }





        /// <summary>
        /// Opens a folder picker dialog to select multiple folders.
        /// </summary>
        /// <returns>A list of selected directory paths or null if cancelled.</returns>
        internal unsafe static List<string>? ShowMultipleDirectoryPickerDialog()
        {
            // Create the file open dialog
            int hr = PInvoke.CoCreateInstance(
                typeof(FileOpenDialog).GUID, // CLSID for FileOpenDialog
                null,                        // No aggregation
                CLSCTX.CLSCTX_INPROC_SERVER, // In-process COM server
                out IFileOpenDialog* fileOpenDialog // Interface for the dialog
            );

            if (hr < 0)
            {
                Marshal.ThrowExceptionForHR(hr);
            }

            // Configure dialog options to enable folder picking and multiple selection
            FILEOPENDIALOGOPTIONS options = FILEOPENDIALOGOPTIONS.FOS_PICKFOLDERS | FILEOPENDIALOGOPTIONS.FOS_ALLOWMULTISELECT;
            fileOpenDialog->SetOptions(options);

            // Set default folder to "My Documents"
            hr = PInvoke.SHCreateItemFromParsingName(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                null,
                typeof(IShellItem).GUID,
                out var directoryShellItem
            );

            if (hr >= 0)
            {
                fileOpenDialog->SetFolder((IShellItem*)directoryShellItem);
                fileOpenDialog->SetDefaultFolder((IShellItem*)directoryShellItem);
            }



            try
            {
                // Show the dialog
                fileOpenDialog->Show(new HWND(GlobalVars.hWnd));
            }
            catch (Exception e)
            {
                if (e.HResult == -2147023673) // Operation Canceled HRESULT
                {
                    return null;
                }

                throw;
            }
            finally
            {
                // Release the IFileOpenDialog COM object
                if (fileOpenDialog != null)
                {
                    _ = fileOpenDialog->Release();
                }
            }

            // Retrieve the collection of selected items
            IShellItemArray* ppsiCollection = null;

            try
            {

                fileOpenDialog->GetResults(&ppsiCollection);

                // Get the number of selected folders
                uint folderCount;
                ppsiCollection->GetCount(&folderCount);

                // Initialize the list to store selected folder paths
                List<string> selectedFolders = [];

                // Iterate through each selected folder
                for (uint i = 0; i < folderCount; i++)
                {
                    IShellItem* ppsi = null;
                    ppsiCollection->GetItemAt(i, &ppsi); // Retrieve IShellItem for the folder

                    // Get the file system path of the folder
                    PWSTR folderPath;
                    ppsi->GetDisplayName(SIGDN.SIGDN_FILESYSPATH, &folderPath);

                    // Convert the unmanaged string (PWSTR) to a managed string and add to the list
                    string selectedFolderPath = new(folderPath.Value);
                    selectedFolders.Add(selectedFolderPath);

                    // Free unmanaged memory for the folder path
                    Marshal.FreeCoTaskMem((IntPtr)folderPath.Value);

                    // Clean up the IShellItem COM object

                    _ = ppsi->Release();

                }

                return selectedFolders;
            }
            finally
            {

                // Clean up the IShellItemArray COM object
                _ = ppsiCollection->Release();

                // Release the IFileOpenDialog COM object
                if (fileOpenDialog != null)
                {
                    _ = fileOpenDialog->Release();
                }

            }
        }



    }
}
