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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using AppControlManager.SiPolicyIntel;

#pragma warning disable CS0649

namespace AppControlManager.IntelGathering;

internal static class KernelModeDrivers
{
	private static readonly Guid CRYPT_SUBJTYPE_CABINET_IMAGE = new("C689AABA-8E78-11d0-8C47-00C04FC295EE");
	private static readonly Guid CRYPT_SUBJTYPE_CATALOG_IMAGE = new("DE351A43-8E59-11d0-8C47-00C04FC295EE");
	private static readonly Guid CRYPT_SUBJTYPE_CTL_IMAGE = new("9BA61D3F-E73A-11d0-8CD2-00C04FC295EE");

	private static readonly unsafe int ImportDescriptorSize = sizeof(IMAGE_IMPORT_DESCRIPTOR);

	private const string KernelModeFileExtension = ".sys";

	// If any of these DLLs are found in the imports list, the file is (likely) a user-mode PE.
	// When a binary (such as a .exe or .dll) imports any of these user-mode libraries, it indicates that the binary relies on user-space functions, which are designed for normal applications.
	// E.g., functions like CreateFile, MessageBox, or CreateWindow etc. are provided by kernel32.dll and user32.dll for user-mode applications, not for code running in kernel mode.
	// Kernel-mode components do not interact with these user-mode DLLs. Instead, they access the kernel directly through SysCalls and low-level APIs.

	private static readonly FrozenSet<string> UserModeDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
	{
		"kernel32.dll", "kernelbase.dll", "mscoree.dll", "ntdll.dll", "user32.dll"
	}.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

	[StructLayout(LayoutKind.Sequential)]
	private struct IMAGE_IMPORT_DESCRIPTOR
	{
		internal uint CharacteristicsOrOriginalFirstThunk;
		internal uint TimeDateStamp;
		internal uint ForwarderChain;
		internal uint Name;
		internal uint FirstThunk;
	}


	private static IntPtr OpenFile(string path, out int error)
	{
		error = 0;
		IntPtr fileHandle = NativeMethods.CreateFileW(path, 2147483648U, 1U, IntPtr.Zero, 3U, 33554432U, IntPtr.Zero);
		IntPtr invalidHandleValue = NativeMethods.INVALID_HANDLE_VALUE;

		if (fileHandle != invalidHandleValue)
		{
			return fileHandle;
		}

		error = Marshal.GetLastPInvokeError();
		return fileHandle;
	}


	internal static KernelUserVerdict CheckKernelUserModeStatus(string filePath)
	{

		// To store the import names - Pre-allocate with an average capacity for better performance
		List<string> importNames = new(8);

		uint localPointerFileSizeHigh = 0;
		IntPtr fileMappingView = IntPtr.Zero;
		IntPtr fileHandle = IntPtr.Zero;
		IntPtr fileMappingHandle = IntPtr.Zero;
		IntPtr foundHeader = IntPtr.Zero;
		uint size = 0;

		// Output variables
		bool hasSIP = false;
		bool isPE = false;
		SSType Verdict = SSType.UserMode;

		// If the file is a .sys file then it's a kernel-mode driver, do not proceed further
		if (string.Equals(Path.GetExtension(filePath), KernelModeFileExtension, StringComparison.OrdinalIgnoreCase))
		{
			return new KernelUserVerdict
			(
				verdict: SSType.KernelMode,
				isPE: true,
				hasSIP: false,
				imports: importNames
			);
		}


		try
		{
			fileHandle = OpenFile(filePath, out int OpenFileError);

			if (fileHandle == NativeMethods.INVALID_HANDLE_VALUE)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("CouldNotOpenFileMessage"), filePath, OpenFileError));

				return new KernelUserVerdict
				(
					verdict: Verdict,
					isPE: isPE,
					hasSIP: hasSIP,
					imports: importNames
				);
			}

			hasSIP = NativeMethods.CryptSIPRetrieveSubjectGuid(filePath, fileHandle, out Guid pgActionID);

			if (!hasSIP)
			{
				return new KernelUserVerdict
				(
					verdict: Verdict,
					isPE: isPE,
					hasSIP: hasSIP,
					imports: importNames
				);
			}

			if (pgActionID.Equals(CRYPT_SUBJTYPE_CATALOG_IMAGE))
			{
				hasSIP = false;

				return new KernelUserVerdict
				(
					verdict: Verdict,
					isPE: isPE,
					hasSIP: hasSIP,
					imports: importNames
				);
			}

			if (pgActionID.Equals(CRYPT_SUBJTYPE_CTL_IMAGE) || pgActionID.Equals(CRYPT_SUBJTYPE_CABINET_IMAGE))
			{
				hasSIP = false;

				return new KernelUserVerdict
				(
					verdict: Verdict,
					isPE: isPE,
					hasSIP: hasSIP,
					imports: importNames
				);
			}

			uint fileSize = NativeMethods.GetFileSize(fileHandle, ref localPointerFileSizeHigh);

			// This is because the PE image size limit is 4GB.
			if (fileSize == uint.MaxValue || localPointerFileSizeHigh != 0U)
			{
				int fileSizeError = Marshal.GetLastPInvokeError();

				Logger.Write(string.Format(GlobalVars.GetStr("GetFileSizeFailedMessage"), filePath, fileSizeError));

				return new KernelUserVerdict
				(
					verdict: Verdict,
					isPE: isPE,
					hasSIP: hasSIP,
					imports: importNames
				);
			}

			if (fileSize == 0U)
			{
				return new KernelUserVerdict
				(
					verdict: Verdict,
					isPE: isPE,
					hasSIP: hasSIP,
					imports: importNames
				);
			}

			// Generate a new GUID and convert it to a string to ensure a unique name for the file mapping
			string localPointerName = Guid.CreateVersion7().ToString();

			// Create a file mapping object, associating the file with a memory region.
			// - fileHandle: File handle to map.
			// - IntPtr.Zero: No security attributes specified.
			// - 2U: Map as read-write (PAGE_READWRITE).
			// - lpFileSizeHigh, fileSize: High and low 32-bit file size for large files.
			// - localPointerName: Unique name derived from the GUID to prevent name collisions in the global namespace.
			fileMappingHandle = NativeMethods.CreateFileMappingW(fileHandle,
				IntPtr.Zero,
				2U,
				localPointerFileSizeHigh,
				fileSize,
				localPointerName
				);

			int fileMappingHandleError = Marshal.GetLastPInvokeError();

			if (fileMappingHandle == IntPtr.Zero)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("CreateFileMappingFailedMessage"), filePath, fileMappingHandleError));

				return new KernelUserVerdict
				(
					verdict: Verdict,
					isPE: isPE,
					hasSIP: hasSIP,
					imports: importNames
				);

			}

			// https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-
			if (fileMappingHandleError == 183)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("CreateFileMappingAlreadyExistsMessage"), filePath, fileMappingHandleError));

				return new KernelUserVerdict
				(
					verdict: Verdict,
					isPE: isPE,
					hasSIP: hasSIP,
					imports: importNames
				);
			}

			// Map a view of the file into the process's address space using the file mapping handle.
			// - fileMappingHandle: Handle to the file mapping object created earlier.
			// - 4U: Map the view with read-only access (PAGE_READONLY).
			// - 0U, 0U: Offsets within the file to map the view from (start at the beginning of the file).
			// - IntPtr.Zero: Specifies the desired view size; passing IntPtr.Zero means the entire file is mapped.
			fileMappingView = NativeMethods.MapViewOfFile(fileMappingHandle,
				4U,
				0U,
				0U,
				IntPtr.Zero
				);

			if (fileMappingView == IntPtr.Zero)
			{
				int fileMappingViewError = Marshal.GetLastPInvokeError();

				Logger.Write(string.Format(GlobalVars.GetStr("MapViewOfFileFailedMessage"), filePath, fileMappingViewError));

				return new KernelUserVerdict
				(
					verdict: Verdict,
					isPE: isPE,
					hasSIP: hasSIP,
					imports: importNames
				);
			}

			IntPtr ntHeaders = NativeMethods.ImageNtHeader(fileMappingView);

			if (ntHeaders == IntPtr.Zero)
			{
				int ImageNtHeaderError = Marshal.GetLastPInvokeError();

				if (ImageNtHeaderError == 193)
				{
					return new KernelUserVerdict
					(
						verdict: Verdict,
						isPE: isPE,
						hasSIP: hasSIP,
						imports: importNames
					);
				}

				Logger.Write(string.Format(GlobalVars.GetStr("ImageNtHeaderFailedMessage"), filePath, ImageNtHeaderError));

				return new KernelUserVerdict
				(
					verdict: Verdict,
					isPE: isPE,
					hasSIP: hasSIP,
					imports: importNames
				);
			}

			isPE = true;

			// Retrieve a pointer to the specified directory entry data in the mapped file image.
			// - fileMappingView: A pointer to the mapped view of the file (memory-mapped region).
			// - 0: The index of the directory entry to access (0 refers to the Export Table in PE headers).
			// - 1: The type of data being accessed (1 indicates the Data Directory in PE format).
			// - ref size: A reference to the variable that will hold the size of the retrieved data.
			// - ref foundHeader: A reference to the variable that will store the header information of the directory entry.
			IntPtr dataEx = NativeMethods.ImageDirectoryEntryToDataEx(fileMappingView, 0, 1, ref size, ref foundHeader);

			if (dataEx == IntPtr.Zero)
			{
				int dataExError = Marshal.GetLastPInvokeError();

				if (dataExError == 0)
				{
					return new KernelUserVerdict
					(
						verdict: Verdict,
						isPE: isPE,
						hasSIP: hasSIP,
						imports: importNames
					);
				}

				Logger.Write(string.Format(GlobalVars.GetStr("ImageDirectoryEntryToDataExFailedMessage"), filePath, dataExError));

				return new KernelUserVerdict
				(
					verdict: Verdict,
					isPE: isPE,
					hasSIP: hasSIP,
					imports: importNames
				);
			}

			// Collect all of the file's imports - using cached ImportDescriptorSize for performance
			for (int offset = 0; ; offset += ImportDescriptorSize)
			{
				// Get the pointer to the current IMAGE_IMPORT_DESCRIPTOR in unmanaged memory
				IntPtr currentImportDescriptorPtr = (IntPtr)((long)dataEx + offset);

				unsafe
				{
					IMAGE_IMPORT_DESCRIPTOR importDescriptor = *(IMAGE_IMPORT_DESCRIPTOR*)currentImportDescriptorPtr;

					// Check if the CharacteristicsOrOriginalFirstThunk is 0, indicating the end of the list
					if (importDescriptor.CharacteristicsOrOriginalFirstThunk == 0)
					{
						break;
					}

					// Get the RVA for the import name
					IntPtr importNamePtr = NativeMethods.ImageRvaToVa(ntHeaders, fileMappingView, importDescriptor.Name, IntPtr.Zero);

					// Marshal the string from the unmanaged memory
					string? importName = Marshal.PtrToStringAnsi(importNamePtr);

					if (importName is not null)
					{
						importNames.Add(importName);
					}
				}
			}

			// if any import name is found in UserModeDlls, or there are no imports, it's UserMode, otherwise KernelMode
			bool IsUserMode = importNames.Count == 0;
			for (int i = 0; i < importNames.Count; i++)
			{
				if (UserModeDlls.Contains(importNames[i]))
				{
					IsUserMode = true;
					break;
				}
			}

			Verdict = IsUserMode ? SSType.UserMode : SSType.KernelMode;

			// Return the actual output which happens when no errors occurred before
			return new KernelUserVerdict
			(
				verdict: Verdict,
				isPE: isPE,
				hasSIP: hasSIP,
				imports: importNames
			);
		}

		catch (AccessViolationException)
		{
			return new KernelUserVerdict
			(
				verdict: Verdict,
				isPE: isPE,
				hasSIP: hasSIP,
				imports: importNames
			);
		}

		finally
		{
			if (fileMappingView != IntPtr.Zero)
			{
				if (NativeMethods.UnmapViewOfFile(fileMappingView) == 0)
				{
					int UnmapViewOfFileError = Marshal.GetLastPInvokeError();

					Logger.Write(string.Format(GlobalVars.GetStr("UnmapViewOfFileFailedMessage"), filePath, UnmapViewOfFileError));
				}
			}
			if (fileMappingHandle != IntPtr.Zero && fileMappingHandle != NativeMethods.INVALID_HANDLE_VALUE)
			{
				if (!NativeMethods.CloseHandle(fileMappingHandle))
				{
					int error = Marshal.GetLastPInvokeError();

					Logger.Write(string.Format(GlobalVars.GetStr("CouldNotCloseMapHandleMessage"), filePath, error));

				}
			}
			if (fileHandle != IntPtr.Zero && fileHandle != NativeMethods.INVALID_HANDLE_VALUE)
			{
				if (!NativeMethods.CloseHandle(fileHandle))
				{
					int error = Marshal.GetLastPInvokeError();

					Logger.Write(string.Format(GlobalVars.GetStr("CouldNotCloseFileHandleMessage"), filePath, error));
				}
			}
		}
	}
}
