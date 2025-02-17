using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using AppControlManager.Others;
using AppControlManager.SiPolicyIntel;

#pragma warning disable CS0649

namespace AppControlManager.IntelGathering;

internal static class KernelModeDrivers
{
	private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);
	private static readonly Guid CRYPT_SUBJTYPE_CABINET_IMAGE = new("C689AABA-8E78-11d0-8C47-00C04FC295EE");
	private static readonly Guid CRYPT_SUBJTYPE_CATALOG_IMAGE = new("DE351A43-8E59-11d0-8C47-00C04FC295EE");
	private static readonly Guid CRYPT_SUBJTYPE_CTL_IMAGE = new("9BA61D3F-E73A-11d0-8CD2-00C04FC295EE");

	// If any of these DLLs are found in the imports list, the file is (likely) a user-mode PE.
	// When a binary (such as a .exe or .dll) imports any of these user-mode libraries, it indicates that the binary relies on user-space functions, which are designed for normal applications.
	// E.g., functions like CreateFile, MessageBox, or CreateWindow etc. are provided by kernel32.dll and user32.dll for user-mode applications, not for code running in kernel mode.
	// Kernel-mode components do not interact with these user-mode DLLs. Instead, they access the kernel directly through SysCalls and low-level APIs.

	private static readonly HashSet<string> UserModeDlls = ["kernel32.dll", "kernelbase.dll", "mscoree.dll", "ntdll.dll", "user32.dll"];

	public struct IMAGE_IMPORT_DESCRIPTOR
	{
		public uint CharacteristicsOrOriginalFirstThunk;
		public uint TimeDateStamp;
		public uint ForwarderChain;
		public uint Name;
		public uint FirstThunk;
	}


	private static IntPtr OpenFile(string path, out int error)
	{
		error = 0;
		IntPtr fileHandle = PlatformInvocations.CreateFileW(path, 2147483648U, 1U, IntPtr.Zero, 3U, 33554432U, IntPtr.Zero);
		IntPtr invalidHandleValue = INVALID_HANDLE_VALUE;

		if (fileHandle != invalidHandleValue)
		{
			return fileHandle;
		}

		error = Marshal.GetLastWin32Error();
		return fileHandle;
	}



	internal static KernelUserVerdict CheckKernelUserModeStatus(string filePath)
	{

		// To store the import names
		List<string> importNames = [];

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
		if (string.Equals(Path.GetExtension(filePath), ".sys", StringComparison.OrdinalIgnoreCase))
		{
			return new KernelUserVerdict
			{
				Verdict = SSType.KernelMode,
				IsPE = true,
				HasSIP = false,
				Imports = importNames
			};
		}


		try
		{
			fileHandle = OpenFile(filePath, out int error);

			if (fileHandle == INVALID_HANDLE_VALUE)
			{
				Logger.Write($"CouldNotOpenFile {filePath}. Error: {error}");

				return new KernelUserVerdict
				{
					Verdict = Verdict,
					IsPE = isPE,
					HasSIP = hasSIP,
					Imports = importNames
				};
			}

			hasSIP = PlatformInvocations.CryptSIPRetrieveSubjectGuid(filePath, fileHandle, out Guid pgActionID);

			if (!hasSIP)
			{
				return new KernelUserVerdict
				{
					Verdict = Verdict,
					IsPE = isPE,
					HasSIP = hasSIP,
					Imports = importNames
				};
			}

			if (pgActionID.Equals(CRYPT_SUBJTYPE_CATALOG_IMAGE))
			{
				hasSIP = false;

				return new KernelUserVerdict
				{
					Verdict = Verdict,
					IsPE = isPE,
					HasSIP = hasSIP,
					Imports = importNames
				};
			}

			if (pgActionID.Equals(CRYPT_SUBJTYPE_CTL_IMAGE) || pgActionID.Equals(CRYPT_SUBJTYPE_CABINET_IMAGE))
			{
				hasSIP = false;

				return new KernelUserVerdict
				{
					Verdict = Verdict,
					IsPE = isPE,
					HasSIP = hasSIP,
					Imports = importNames
				};
			}

			uint fileSize = PlatformInvocations.GetFileSize(fileHandle, ref localPointerFileSizeHigh);

			if (fileSize == uint.MaxValue || localPointerFileSizeHigh != 0U)
			{
				error = Marshal.GetLastWin32Error();

				Logger.Write($"GetFileSizeFailed for file {filePath} with error {error}");

				return new KernelUserVerdict
				{
					Verdict = Verdict,
					IsPE = isPE,
					HasSIP = hasSIP,
					Imports = importNames
				};
			}

			if (fileSize == 0U)
			{
				return new KernelUserVerdict
				{
					Verdict = Verdict,
					IsPE = isPE,
					HasSIP = hasSIP,
					Imports = importNames
				};
			}

			// Generate a new GUID and convert it to a string to ensure a unique name for the file mapping
			string localPointerName = Guid.CreateVersion7().ToString();

			// Create a file mapping object, associating the file with a memory region.
			// - fileHandle: File handle to map.
			// - IntPtr.Zero: No security attributes specified.
			// - 2U: Map as read-write (PAGE_READWRITE).
			// - lpFileSizeHigh, fileSize: High and low 32-bit file size for large files.
			// - localPointerName: Unique name derived from the GUID to prevent name collisions in the global namespace.
			fileMappingHandle = PlatformInvocations.CreateFileMapping(fileHandle,
				IntPtr.Zero,
				2U,
				localPointerFileSizeHigh,
				fileSize,
				localPointerName
				);

			error = Marshal.GetLastWin32Error();

			if (fileMappingHandle == IntPtr.Zero)
			{
				Logger.Write($"CreateFileMappingFailed for the file {filePath} with error {error}");

				return new KernelUserVerdict
				{
					Verdict = Verdict,
					IsPE = isPE,
					HasSIP = hasSIP,
					Imports = importNames
				};

			}

			if (error == 183)
			{
				Logger.Write($"CreateFileMappingAlreadyExists for the file {filePath} with error {error}");

				return new KernelUserVerdict
				{
					Verdict = Verdict,
					IsPE = isPE,
					HasSIP = hasSIP,
					Imports = importNames
				};
			}

			// Map a view of the file into the process's address space using the file mapping handle.
			// - fileMappingHandle: Handle to the file mapping object created earlier.
			// - 4U: Map the view with read-only access (PAGE_READONLY).
			// - 0U, 0U: Offsets within the file to map the view from (start at the beginning of the file).
			// - IntPtr.Zero: Specifies the desired view size; passing IntPtr.Zero means the entire file is mapped.
			fileMappingView = PlatformInvocations.MapViewOfFile(fileMappingHandle,
				4U,
				0U,
				0U,
				IntPtr.Zero
				);


			if (fileMappingView == IntPtr.Zero)
			{
				error = Marshal.GetLastWin32Error();

				Logger.Write($"MapViewOfFileFailed for the file {filePath} with error {error}");

				return new KernelUserVerdict
				{
					Verdict = Verdict,
					IsPE = isPE,
					HasSIP = hasSIP,
					Imports = importNames
				};
			}

			IntPtr ntHeaders = PlatformInvocations.ImageNtHeader(fileMappingView);

			if (ntHeaders == IntPtr.Zero)
			{
				error = Marshal.GetLastWin32Error();

				if (error == 193)
				{
					return new KernelUserVerdict
					{
						Verdict = Verdict,
						IsPE = isPE,
						HasSIP = hasSIP,
						Imports = importNames
					};
				}


				Logger.Write($"ImageNtHeaderFailed for the file {filePath} with error {error}");

				return new KernelUserVerdict
				{
					Verdict = Verdict,
					IsPE = isPE,
					HasSIP = hasSIP,
					Imports = importNames
				};
			}

			isPE = true;

			// Retrieve a pointer to the specified directory entry data in the mapped file image.
			// - fileMappingView: A pointer to the mapped view of the file (memory-mapped region).
			// - 0: The index of the directory entry to access (0 refers to the Export Table in PE headers).
			// - 1: The type of data being accessed (1 indicates the Data Directory in PE format).
			// - ref size: A reference to the variable that will hold the size of the retrieved data.
			// - ref foundHeader: A reference to the variable that will store the header information of the directory entry.
			IntPtr dataEx = PlatformInvocations.ImageDirectoryEntryToDataEx(fileMappingView, 0, 1, ref size, ref foundHeader);

			if (dataEx == IntPtr.Zero)
			{
				error = Marshal.GetLastWin32Error();

				if (error == 0)
				{
					return new KernelUserVerdict
					{
						Verdict = Verdict,
						IsPE = isPE,
						HasSIP = hasSIP,
						Imports = importNames
					};
				}


				Logger.Write($"ImageDirectoryEntryToDataExFailed for the file {filePath} with error {error}");

				return new KernelUserVerdict
				{
					Verdict = Verdict,
					IsPE = isPE,
					HasSIP = hasSIP,
					Imports = importNames
				};
			}

			// Collect all of the file's imports
			for (int offset = 0; ; offset += Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>())
			{
				// Get the pointer to the current IMAGE_IMPORT_DESCRIPTOR in unmanaged memory
				IntPtr currentImportDescriptorPtr = (IntPtr)((long)dataEx + offset);

				// Marshal the IMAGE_IMPORT_DESCRIPTOR from unmanaged memory
				IMAGE_IMPORT_DESCRIPTOR importDescriptor = Marshal.PtrToStructure<IMAGE_IMPORT_DESCRIPTOR>(currentImportDescriptorPtr);

				// Check if the CharacteristicsOrOriginalFirstThunk is 0, indicating the end of the list
				if (importDescriptor.CharacteristicsOrOriginalFirstThunk == 0)
				{
					break;
				}

				// Get the RVA for the import name
				IntPtr importNamePtr = PlatformInvocations.ImageRvaToVa(ntHeaders, fileMappingView, importDescriptor.Name, IntPtr.Zero);

				// Marshal the string from the unmanaged memory
				string? importName = Marshal.PtrToStringAnsi(importNamePtr);

				if (importName is not null)
				{
					importNames.Add(importName);
				}
			}


			Verdict = importNames.Any(import => UserModeDlls.Any(dll => string.Equals(import, dll, StringComparison.OrdinalIgnoreCase))) ? SSType.UserMode : SSType.KernelMode;

			// Return the actual output which happens when no errors occurred before
			return new KernelUserVerdict
			{
				Verdict = Verdict,
				IsPE = isPE,
				HasSIP = hasSIP,
				Imports = importNames
			};
		}

		catch (AccessViolationException)
		{
			return new KernelUserVerdict
			{
				Verdict = Verdict,
				IsPE = isPE,
				HasSIP = hasSIP,
				Imports = importNames
			};
		}

		finally
		{
			if (fileMappingView != IntPtr.Zero)
			{
				if (PlatformInvocations.UnmapViewOfFile(fileMappingView) == 0)
				{
					int lastWin32Error = Marshal.GetLastWin32Error();

					Logger.Write($"UnmapViewOfFileFailed for the file {filePath} with error {lastWin32Error}");
				}
			}
			if (fileMappingHandle != IntPtr.Zero && fileMappingHandle != INVALID_HANDLE_VALUE)
			{
				if (!PlatformInvocations.CloseHandle(fileMappingHandle))
				{
					int lastWin32Error = Marshal.GetLastWin32Error();

					Logger.Write($"CouldNotCloseMapHandle for the file {filePath} with error {lastWin32Error}");

				}
			}
			if (fileHandle != IntPtr.Zero && fileHandle != INVALID_HANDLE_VALUE)
			{
				if (!PlatformInvocations.CloseHandle(fileHandle))
				{
					int lastWin32Error = Marshal.GetLastWin32Error();

					Logger.Write($"CouldNotCloseFileHandle for the file {filePath} with error {lastWin32Error}");
				}
			}
		}
	}
}
