using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Com;
using Windows.Win32.UI.Shell;
using Windows.Win32.UI.Shell.Common;

namespace AppControlManager
{
    /// <summary>
    /// https://learn.microsoft.com/en-us/uwp/api/windows.storage.pickers.filesavepicker?view=winrt-26100
    /// This class uses managed code, "allowMarshaling" should be "true" for CsWin32 JSON settings.
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
            // Create an instance of the file open dialog using COM interface.
            int hr = PInvoke.CoCreateInstance(
                typeof(FileOpenDialog).GUID, // GUID for FileOpenDialog COM object
                null, // No outer object for aggregation
                CLSCTX.CLSCTX_INPROC_SERVER, // Context specifies in-process server execution
                out IFileOpenDialog fileOpenDialog // Output reference to the created IFileOpenDialog instance
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
                if (tokens.Length % 2 == 0) // Ensure the pairs are valid.
                {
                    for (int i = 1; i < tokens.Length; i += 2)
                    {
                        // Populate the filter specification structure for each pair.
                        COMDLG_FILTERSPEC extension;
                        extension.pszName = (char*)Marshal.StringToHGlobalUni(tokens[i - 1]); // Filter name.
                        extension.pszSpec = (char*)Marshal.StringToHGlobalUni(tokens[i]);     // Filter pattern.
                        extensions.Add(extension);
                    }
                }
            }

            // Apply the filters to the file open dialog.
            fileOpenDialog.SetFileTypes(extensions.ToArray());

            // Set the default folder to "My Documents".
            hr = PInvoke.SHCreateItemFromParsingName(
                GlobalVars.UserConfigDir, // Path to the folder.
                null, // No binding context needed.
                typeof(IShellItem).GUID, // GUID for the IShellItem interface.
                out var directoryShellItem // Output reference to the IShellItem instance.
            );

            if (hr >= 0) // Proceed only if the default folder creation succeeds.
            {
                // Set the initial and default folder for the dialog.
                fileOpenDialog.SetFolder((IShellItem)directoryShellItem);
                fileOpenDialog.SetDefaultFolder((IShellItem)directoryShellItem);
            }

            try
            {
                // Display the dialog to the user.
                fileOpenDialog.Show(new HWND(GlobalVars.hWnd)); // Pass the parent window handle.
            }
            catch (Exception e)
            {
                // Handle exceptions, such as when the user cancels the dialog.
                if (e.HResult != -2147023673) // Specific HRESULT for "Operation Canceled".
                {
                    throw; // Re-throw unexpected exceptions.
                }
                else
                {
                    return null; // Return null when the dialog is canceled.
                }
            }

            // Retrieve the result of the dialog (selected file).
            fileOpenDialog.GetResult(out IShellItem ppsi); // Get the IShellItem representing the selected file.

            // Get the file path as a PWSTR.
            PWSTR filename;
            ppsi.GetDisplayName(SIGDN.SIGDN_FILESYSPATH, &filename); // Retrieve the file's full path.

            // Convert the unmanaged PWSTR to a managed string and return it.
            string selectedFilePath = filename.ToString();
            return selectedFilePath;
        }


        /// <summary>
        /// Opens a file picker dialog to select multiple files.
        /// </summary>
        /// <param name="filter">A file filter string in the format "Description|Extension" pairs
        /// (e.g., "Text Files|*.txt|All Files|*.*").</param>
        /// <returns>A list of selected file paths or null if the operation is cancelled.</returns>
        internal unsafe static List<string>? ShowMultipleFilePickerDialog(string filter)
        {
            // Create the file open dialog using COM's CoCreateInstance method.
            // CLSCTX.CLSCTX_INPROC_SERVER ensures the dialog runs in the same process.
            int hr = PInvoke.CoCreateInstance(
                typeof(FileOpenDialog).GUID, // GUID of the FileOpenDialog class.
                null,                        // No aggregation.
                CLSCTX.CLSCTX_INPROC_SERVER, // In-process COM server.
                out IFileOpenDialog fileOpenDialog // Interface for the dialog.
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

                        // Marshal the description and extension strings to unmanaged memory.
                        extension.pszName = (char*)Marshal.StringToHGlobalUni(tokens[i - 1]); // Filter description.
                        extension.pszSpec = (char*)Marshal.StringToHGlobalUni(tokens[i]);     // File extension(s).

                        // Add the filter specification to the list.
                        extensions.Add(extension);
                    }
                }
            }

            // Apply the file type filters to the dialog.
            fileOpenDialog.SetFileTypes(extensions.ToArray());

            // Optionally set a default folder and starting directory.
            // Retrieves a shell item representing the "My Documents" directory.
            hr = PInvoke.SHCreateItemFromParsingName(
                GlobalVars.UserConfigDir, // Path to the folder.
                null,  // No binding context.
                typeof(IShellItem).GUID, // GUID for IShellItem interface.
                out var directoryShellItem // Output shell item.
            );

            // If the "My Documents" folder is successfully retrieved, set it as the default.
            if (hr >= 0)
            {
                fileOpenDialog.SetFolder((IShellItem)directoryShellItem);        // Set starting folder.
                fileOpenDialog.SetDefaultFolder((IShellItem)directoryShellItem); // Set default folder.
            }

            // Configure dialog options to allow multiple file selection.
            FILEOPENDIALOGOPTIONS options = FILEOPENDIALOGOPTIONS.FOS_ALLOWMULTISELECT;
            fileOpenDialog.SetOptions(options);

            try
            {
                // Display the file picker dialog to the user.
                fileOpenDialog.Show(new HWND(GlobalVars.hWnd)); // Owner window handle.
            }
            catch (Exception e)
            {
                // Handle user cancellation of the dialog (specific HRESULT -2147023673).
                if (e.HResult != -2147023673)
                {
                    throw; // Rethrow for unexpected errors.
                }
                else
                {
                    return null; // User cancelled; return null.
                }
            }

            // Retrieve the collection of selected items from the dialog.
            fileOpenDialog.GetResults(out IShellItemArray ppsiCollection);

            // Get the number of selected files in the collection.
            ppsiCollection.GetCount(out uint fileCount);

            // Initialize the list to store the paths of the selected files.
            List<string> selectedFiles = [];

            // Iterate through each selected file.
            for (uint i = 0; i < fileCount; i++)
            {
                ppsiCollection.GetItemAt(i, out IShellItem ppsi); // Get the IShellItem for the file.

                // Get the file system path of the file.
                PWSTR filename;
                ppsi.GetDisplayName(SIGDN.SIGDN_FILESYSPATH, &filename); // Retrieve the full filesystem path.

                // Convert the unmanaged string (PWSTR) to a managed string and add it to the list.
                string selectedFilePath = filename.ToString();
                selectedFiles.Add(selectedFilePath);
            }

            // Return the list of selected file paths.
            return selectedFiles;
        }


        /// <summary>
        /// Opens a folder picker dialog to select a single folder.
        /// </summary>
        /// <returns>The selected directory path as a string, or null if the operation is cancelled.</returns>
        internal unsafe static string? ShowDirectoryPickerDialog()
        {
            // Create the file open dialog using COM's CoCreateInstance method.
            // CLSCTX.CLSCTX_INPROC_SERVER ensures the dialog runs in the same process.
            int hr = PInvoke.CoCreateInstance(
                typeof(FileOpenDialog).GUID, // GUID of the FileOpenDialog class.
                null,                        // No aggregation.
                CLSCTX.CLSCTX_INPROC_SERVER, // In-process COM server.
                out IFileOpenDialog fileOpenDialog // Interface for the dialog.
            );

            // If the HRESULT indicates failure, throw a corresponding .NET exception.
            if (hr < 0)
            {
                Marshal.ThrowExceptionForHR(hr);
            }

            // Configure dialog options to enable folder selection.
            FILEOPENDIALOGOPTIONS options = FILEOPENDIALOGOPTIONS.FOS_PICKFOLDERS;
            fileOpenDialog.SetOptions(options);

            // Optionally set a default folder and starting directory.
            // Retrieves a shell item representing the "My Documents" directory.
            hr = PInvoke.SHCreateItemFromParsingName(
                GlobalVars.UserConfigDir, // Path to the folder.
                null,  // No binding context.
                typeof(IShellItem).GUID, // GUID for IShellItem interface.
                out var directoryShellItem // Output shell item.
            );

            // If the "My Documents" folder is successfully retrieved, set it as the default.
            if (hr >= 0)
            {
                fileOpenDialog.SetFolder((IShellItem)directoryShellItem);        // Set starting folder.
                fileOpenDialog.SetDefaultFolder((IShellItem)directoryShellItem); // Set default folder.
            }

            try
            {
                // Display the folder picker dialog to the user.
                fileOpenDialog.Show(new HWND(GlobalVars.hWnd)); // Owner window handle.
            }
            catch (Exception e)
            {
                // Handle user cancellation of the dialog (specific HRESULT -2147023673).
                if (e.HResult != -2147023673)
                {
                    throw; // Rethrow for unexpected errors.
                }
                else
                {
                    return null; // User cancelled; return null.
                }
            }

            // Retrieve the selected folder from the dialog.
            fileOpenDialog.GetResult(out IShellItem ppsi);

            // Get the file system path of the selected folder.
            PWSTR folderPath;
            ppsi.GetDisplayName(SIGDN.SIGDN_FILESYSPATH, &folderPath); // Retrieve the full filesystem path.

            // Convert the unmanaged string (PWSTR) to a managed string.
            string selectedFolderPath = folderPath.ToString();

            // Return the selected folder path as a managed string.
            return selectedFolderPath;
        }


        /// <summary>
        /// Opens a folder picker dialog to select multiple folders.
        /// </summary>
        /// <returns>A list of selected directory paths or null if cancelled.</returns>
        internal unsafe static List<string>? ShowMultipleDirectoryPickerDialog()
        {
            // Create the file open dialog using COM's CoCreateInstance method.
            // CLSCTX.CLSCTX_INPROC_SERVER ensures the dialog runs in the same process.
            int hr = PInvoke.CoCreateInstance(
                typeof(FileOpenDialog).GUID, // GUID of the FileOpenDialog class.
                null,                        // No aggregation.
                CLSCTX.CLSCTX_INPROC_SERVER, // In-process COM server.
                out IFileOpenDialog fileOpenDialog // Interface for the dialog.
            );

            // If the HRESULT indicates failure, throw a corresponding .NET exception.
            if (hr < 0)
            {
                Marshal.ThrowExceptionForHR(hr);
            }

            // Configure dialog options to enable folder picking and multiple selection.
            FILEOPENDIALOGOPTIONS options = FILEOPENDIALOGOPTIONS.FOS_PICKFOLDERS | FILEOPENDIALOGOPTIONS.FOS_ALLOWMULTISELECT;
            fileOpenDialog.SetOptions(options);

            // Optionally set a default folder and starting directory.
            // Retrieves a shell item representing the "My Documents" directory.
            hr = PInvoke.SHCreateItemFromParsingName(
                GlobalVars.UserConfigDir, // Path to the folder.
                null,  // No binding context.
                typeof(IShellItem).GUID, // GUID for IShellItem interface.
                out var directoryShellItem // Output shell item.
            );

            // If the "My Documents" folder is successfully retrieved, set it as the default.
            if (hr >= 0)
            {
                fileOpenDialog.SetFolder((IShellItem)directoryShellItem);        // Set starting folder.
                fileOpenDialog.SetDefaultFolder((IShellItem)directoryShellItem); // Set default folder.
            }

            try
            {
                // Display the folder picker dialog to the user.
                fileOpenDialog.Show(new HWND(GlobalVars.hWnd)); // Owner window handle.
            }
            catch (Exception e)
            {
                // Handle user cancellation of the dialog (specific HRESULT -2147023673).
                if (e.HResult != -2147023673)
                {
                    throw; // Rethrow for unexpected errors.
                }
                else
                {
                    return null; // User cancelled; return null.
                }
            }

            // Retrieve the collection of selected items from the dialog.
            fileOpenDialog.GetResults(out IShellItemArray ppsiCollection);

            // Get the number of selected folders in the collection.
            ppsiCollection.GetCount(out uint folderCount);

            // Initialize the list to store the paths of the selected folders.
            List<string> selectedFolders = [];

            // Iterate through each selected folder.
            for (uint i = 0; i < folderCount; i++)
            {
                ppsiCollection.GetItemAt(i, out IShellItem ppsi); // Get the IShellItem for the folder.

                // Get the file system path of the folder.
                PWSTR folderPath;
                ppsi.GetDisplayName(SIGDN.SIGDN_FILESYSPATH, &folderPath); // Retrieve the full filesystem path.

                // Convert the unmanaged string (PWSTR) to a managed string and add it to the list.
                string selectedFolderPath = folderPath.ToString();
                selectedFolders.Add(selectedFolderPath);
            }

            // Return the list of selected folder paths.
            return selectedFolders;
        }

    }
}
