// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace CommonCore.Others;

internal static class FileDialogHelper
{
	// Location where File/Folder picker dialog will be opened
	// It is only the directory where the first dialog will be opened in, it will then be replaced by the directory
	// That user browses to to pick a single file/directory
	internal static string DirectoryToOpen = null!;

	/// <summary>
	/// Shows a single file picker dialog with filter.
	/// </summary>
	/// <param name="filter">Filter string in format "Description|*.ext|Description2|*.ext2"</param>
	/// <returns>Selected file path, or null if cancelled</returns>
	/// <exception cref="COMException">Thrown when the operation fails</exception>
	internal static string? ShowFilePickerDialog(string filter)
	{
		IntPtr result = NativeMethods.show_file_picker(filter, DirectoryToOpen, out int lastError);

		if (result == IntPtr.Zero)
		{
			if (lastError != 0)
				throw Marshal.GetExceptionForHR(lastError)!;
			return null; // User cancelled
		}

		try
		{
			string? selectedFilePath = Marshal.PtrToStringUTF8(result);

			// Assign the directory where user last browsed for a file to the directory where file picker will be opened from next time
			string? _selectedFilePath = Path.GetDirectoryName(selectedFilePath);
			if (!string.IsNullOrEmpty(_selectedFilePath))
				DirectoryToOpen = _selectedFilePath;

			return selectedFilePath;
		}
		finally
		{
			NativeMethods.free_string(result);
		}
	}

	/// <summary>
	/// Shows a multiple files picker dialog with filter.
	/// </summary>
	/// <param name="filter">Filter string in format "Description|*.ext|Description2|*.ext2"</param>
	/// <returns>List of selected file paths, or empty list if cancelled</returns>
	/// <exception cref="COMException">Thrown when the operation fails</exception>
	internal static List<string> ShowMultipleFilePickerDialog(string filter)
	{
		StringArrayForFileDialogHelper result = NativeMethods.show_files_picker(filter, DirectoryToOpen, out int lastError);

		if (lastError != 0)
			throw Marshal.GetExceptionForHR(lastError)!;

		// build our result list and treat nullptr/zero count as cancellation
		List<string> paths = [];
		if (result.Strings == IntPtr.Zero || result.Count <= 0)
			return paths; // User cancelled

		try
		{
			for (int i = 0; i < result.Count; i++)
			{
				IntPtr stringPtr = Marshal.ReadIntPtr(result.Strings, i * IntPtr.Size);
				if (stringPtr != IntPtr.Zero)
				{
					string? path = Marshal.PtrToStringUTF8(stringPtr);
					if (path != null)
						paths.Add(path);
				}
			}
		}
		finally
		{
			NativeMethods.free_string_array(result);
		}

		// If the user picked exactly one file, update the initial directory:
		if (paths.Count == 1)
		{
			string? dir = Path.GetDirectoryName(paths[0]);
			if (!string.IsNullOrEmpty(dir))
				DirectoryToOpen = dir;
		}

		return paths;
	}

	/// <summary>
	/// Shows a single folder picker dialog
	/// </summary>
	/// <returns>Selected folder path, or null if cancelled</returns>
	/// <exception cref="COMException">Thrown when the operation fails</exception>
	internal static string? ShowDirectoryPickerDialog()
	{
		IntPtr result = NativeMethods.show_folder_picker(DirectoryToOpen, out int lastError);

		if (result == IntPtr.Zero)
		{
			if (lastError != 0)
				throw Marshal.GetExceptionForHR(lastError)!;
			return null; // User cancelled
		}

		try
		{
			string? selectedFolderPath = Marshal.PtrToStringUTF8(result);
			if (!string.IsNullOrEmpty(selectedFolderPath))
				DirectoryToOpen = selectedFolderPath;
			return selectedFolderPath;
		}
		finally
		{
			NativeMethods.free_string(result);
		}
	}

	/// <summary>
	/// Shows a multiple folders picker dialog
	/// </summary>
	/// <returns>List of selected folder paths, or empty list if cancelled</returns>
	/// <exception cref="COMException">Thrown when the operation fails</exception>
	internal static List<string> ShowMultipleDirectoryPickerDialog()
	{
		StringArrayForFileDialogHelper result = NativeMethods.show_folders_picker(DirectoryToOpen, out int lastError);

		if (lastError != 0)
			throw Marshal.GetExceptionForHR(lastError)!;

		List<string> paths = [];
		if (result.Strings == IntPtr.Zero || result.Count <= 0)
			return paths; // User cancelled

		try
		{
			for (int i = 0; i < result.Count; i++)
			{
				IntPtr stringPtr = Marshal.ReadIntPtr(result.Strings, i * IntPtr.Size);
				if (stringPtr != IntPtr.Zero)
				{
					string? path = Marshal.PtrToStringUTF8(stringPtr);
					if (path != null)
						paths.Add(path);
				}
			}
		}
		finally
		{
			NativeMethods.free_string_array(result);
		}

		if (paths.Count == 1)
		{
			string? dir = paths[0];
			if (!string.IsNullOrEmpty(dir))
				DirectoryToOpen = dir;
		}

		return paths;
	}

	/// <summary>
	/// Shows a save file dialog with filter and optional default filename.
	/// </summary>
	/// <param name="filter">Filter string in format "Description|*.ext|Description2|*.ext2"</param>
	/// <param name="defaultFilename">Optional default filename to pre-fill in the dialog</param>
	/// <returns>Selected save file path, or null if cancelled</returns>
	/// <exception cref="COMException">Thrown when the operation fails</exception>
	internal static string? ShowSaveFileDialog(string filter, string? defaultFilename = null)
	{
		IntPtr result = NativeMethods.show_save_file_dialog(filter, DirectoryToOpen, defaultFilename, out int lastError);

		if (result == IntPtr.Zero)
		{
			if (lastError != 0)
				throw Marshal.GetExceptionForHR(lastError)!;
			return null; // User cancelled
		}

		try
		{
			string? selectedFilePath = Marshal.PtrToStringUTF8(result);

			// Update the directory where user last browsed for future dialogs
			string? selectedDirectory = Path.GetDirectoryName(selectedFilePath);
			if (!string.IsNullOrEmpty(selectedDirectory))
				DirectoryToOpen = selectedDirectory;

			return selectedFilePath;
		}
		finally
		{
			NativeMethods.free_string(result);
		}
	}
}
