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

using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.IO;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;

#pragma warning disable CS0649

namespace CommonCore.IntelGathering;

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

	private const int ExportDirectorySize = 40;

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

	/// <summary>
	/// Reads the PE export directory and returns both named and ordinal-only exports.
	/// </summary>
	/// <exception cref="InvalidDataException">Thrown when the export table is malformed.</exception>
	internal static IReadOnlyList<PortableExecutableExport> GetExportedFunctions(string filePath)
	{
		// Some files use a .dll extension without being real PE images, so filter them out
		// before invoking PEReader to avoid exception-heavy scans and noisy log output.
		if (!LooksLikePortableExecutable(filePath))
		{
			return [];
		}

		using FileStream fileStream = new(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 4096, FileOptions.SequentialScan);

		long fileLengthLong = fileStream.Length;

		if (fileLengthLong <= 0 || fileLengthLong > int.MaxValue)
		{
			return [];
		}

		int fileLength = checked((int)fileLengthLong);

		// Rent the buffer to avoid allocating a brand-new byte[] for every scanned file.
		byte[] rentedBuffer = ArrayPool<byte>.Shared.Rent(fileLength);

		try
		{
			fileStream.ReadExactly(rentedBuffer.AsSpan(0, fileLength));

			using MemoryStream memoryStream = new(rentedBuffer, 0, fileLength, writable: false, publiclyVisible: true);
			using PEReader peReader = new(memoryStream, PEStreamOptions.LeaveOpen);

			PEHeaders peHeaders = peReader.PEHeaders;
			PEHeader? peHeader = peHeaders.PEHeader;

			if (peHeader is null)
			{
				return [];
			}

			ReadOnlySpan<byte> imageBytes = rentedBuffer.AsSpan(0, fileLength);
			DirectoryEntry exportDirectory = peHeader.ExportTableDirectory;
			if (exportDirectory.RelativeVirtualAddress is 0 || exportDirectory.Size < ExportDirectorySize)
			{
				return [];
			}

			int exportDirectoryOffset = TranslateRvaToOffset(peHeaders, exportDirectory.RelativeVirtualAddress, imageBytes.Length);
			ReadOnlySpan<byte> exportDirectoryData = imageBytes.Slice(exportDirectoryOffset, ExportDirectorySize);

			uint ordinalBase = BinaryPrimitives.ReadUInt32LittleEndian(exportDirectoryData[16..20]);
			uint addressTableEntries = BinaryPrimitives.ReadUInt32LittleEndian(exportDirectoryData[20..24]);
			uint numberOfNamePointers = BinaryPrimitives.ReadUInt32LittleEndian(exportDirectoryData[24..28]);
			uint exportAddressTableRva = BinaryPrimitives.ReadUInt32LittleEndian(exportDirectoryData[28..32]);
			uint namePointerRva = BinaryPrimitives.ReadUInt32LittleEndian(exportDirectoryData[32..36]);
			uint ordinalTableRva = BinaryPrimitives.ReadUInt32LittleEndian(exportDirectoryData[36..40]);

			if (addressTableEntries is 0)
			{
				return [];
			}

			Dictionary<int, string> exportNamesByIndex = new((int)numberOfNamePointers);

			for (int i = 0; i < numberOfNamePointers; i++)
			{
				int currentNamePointerOffset = TranslateRvaToOffset(peHeaders, checked((int)namePointerRva + (i * sizeof(uint))), imageBytes.Length);
				uint currentNameRva = BinaryPrimitives.ReadUInt32LittleEndian(imageBytes.Slice(currentNamePointerOffset, sizeof(uint)));
				int currentOrdinalOffset = TranslateRvaToOffset(peHeaders, checked((int)ordinalTableRva + (i * sizeof(ushort))), imageBytes.Length);
				ushort exportIndex = BinaryPrimitives.ReadUInt16LittleEndian(imageBytes.Slice(currentOrdinalOffset, sizeof(ushort)));

				if (exportIndex >= addressTableEntries)
				{
					throw new InvalidDataException("The PE export table contains an out-of-range ordinal index.");
				}

				int currentNameOffset = TranslateRvaToOffset(peHeaders, checked((int)currentNameRva), imageBytes.Length);
				exportNamesByIndex[exportIndex] = ReadAnsiString(imageBytes, currentNameOffset);
			}

			List<PortableExecutableExport> exportedFunctions = new((int)addressTableEntries);

			for (int i = 0; i < addressTableEntries; i++)
			{
				int currentAddressOffset = TranslateRvaToOffset(peHeaders, checked((int)exportAddressTableRva + (i * sizeof(uint))), imageBytes.Length);
				uint exportTargetRva = BinaryPrimitives.ReadUInt32LittleEndian(imageBytes.Slice(currentAddressOffset, sizeof(uint)));
				uint ordinal = ordinalBase + (uint)i;
				string exportName = exportNamesByIndex.TryGetValue(i, out string? namedExport) ? namedExport : $"#{ordinal}";

				string? forwarderName = null;
				int exportDirectoryEnd = checked(exportDirectory.RelativeVirtualAddress + exportDirectory.Size);

				if (exportTargetRva >= exportDirectory.RelativeVirtualAddress && exportTargetRva < exportDirectoryEnd)
				{
					int forwarderOffset = TranslateRvaToOffset(peHeaders, checked((int)exportTargetRva), imageBytes.Length);
					forwarderName = ReadAnsiString(imageBytes, forwarderOffset);
				}

				exportedFunctions.Add(new PortableExecutableExport(exportName, ordinal, forwarderName));
			}

			return exportedFunctions;
		}
		catch (BadImageFormatException)
		{
			return [];
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(rentedBuffer, clearArray: false);
		}
	}

	private static bool LooksLikePortableExecutable(string filePath)
	{
		Span<byte> header = stackalloc byte[64];

		using FileStream fileStream = new(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 1, FileOptions.SequentialScan);

		if (fileStream.Read(header) < header.Length)
		{
			return false;
		}

		if (header[0] != (byte)'M' || header[1] != (byte)'Z')
		{
			return false;
		}

		int peHeaderOffset = BinaryPrimitives.ReadInt32LittleEndian(header[0x3C..0x40]);

		if (peHeaderOffset < 0 || peHeaderOffset + 4 > fileStream.Length)
		{
			return false;
		}

		fileStream.Position = peHeaderOffset;

		Span<byte> peSignature = stackalloc byte[4];

		return fileStream.Read(peSignature) == peSignature.Length &&
			peSignature[0] == (byte)'P' &&
			peSignature[1] == (byte)'E' &&
			peSignature[2] == 0 &&
			peSignature[3] == 0;
	}

	private static int TranslateRvaToOffset(PEHeaders peHeaders, int relativeVirtualAddress, int imageLength)
	{
		foreach (SectionHeader sectionHeader in peHeaders.SectionHeaders)
		{
			int sectionStart = sectionHeader.VirtualAddress;
			int sectionLength = Math.Max(sectionHeader.VirtualSize, sectionHeader.SizeOfRawData);
			int relativeOffset = relativeVirtualAddress - sectionStart;

			if (relativeOffset < 0 || relativeOffset >= sectionLength)
			{
				continue;
			}

			long rawOffset = (long)sectionHeader.PointerToRawData + relativeOffset;
			if (rawOffset < 0 || rawOffset > imageLength - 1L)
			{
				break;
			}

			return (int)rawOffset;
		}

		if (relativeVirtualAddress >= 0 && relativeVirtualAddress < imageLength)
		{
			return relativeVirtualAddress;
		}

		throw new InvalidDataException("The PE export table contains an RVA outside of the image.");
	}

	private static string ReadAnsiString(ReadOnlySpan<byte> imageBytes, int offset)
	{
		if (offset < 0 || offset >= imageBytes.Length)
		{
			throw new InvalidDataException("The PE export table contains an invalid string offset.");
		}

		int end = offset;
		while (end < imageBytes.Length && imageBytes[end] != 0)
		{
			end++;
		}

		return Encoding.ASCII.GetString(imageBytes[offset..end]);
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
				Logger.Write(string.Format(Atlas.GetStr("CouldNotOpenFileMessage"), filePath, OpenFileError));

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

				Logger.Write(string.Format(Atlas.GetStr("GetFileSizeFailedMessage"), filePath, fileSizeError));

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
				Logger.Write(string.Format(Atlas.GetStr("CreateFileMappingFailedMessage"), filePath, fileMappingHandleError));

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
				Logger.Write(string.Format(Atlas.GetStr("CreateFileMappingAlreadyExistsMessage"), filePath, fileMappingHandleError));

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

				Logger.Write(string.Format(Atlas.GetStr("MapViewOfFileFailedMessage"), filePath, fileMappingViewError));

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

				Logger.Write(string.Format(Atlas.GetStr("ImageNtHeaderFailedMessage"), filePath, ImageNtHeaderError));

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

				Logger.Write(string.Format(Atlas.GetStr("ImageDirectoryEntryToDataExFailedMessage"), filePath, dataExError));

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

					Logger.Write(string.Format(Atlas.GetStr("UnmapViewOfFileFailedMessage"), filePath, UnmapViewOfFileError));
				}
			}
			if (fileMappingHandle != IntPtr.Zero && fileMappingHandle != NativeMethods.INVALID_HANDLE_VALUE)
			{
				if (!NativeMethods.CloseHandle(fileMappingHandle))
				{
					int error = Marshal.GetLastPInvokeError();

					Logger.Write(string.Format(Atlas.GetStr("CouldNotCloseMapHandleMessage"), filePath, error));

				}
			}
			if (fileHandle != IntPtr.Zero && fileHandle != NativeMethods.INVALID_HANDLE_VALUE)
			{
				if (!NativeMethods.CloseHandle(fileHandle))
				{
					int error = Marshal.GetLastPInvokeError();

					Logger.Write(string.Format(Atlas.GetStr("CouldNotCloseFileHandleMessage"), filePath, error));
				}
			}
		}
	}
}

internal sealed class PortableExecutableExport(string name, uint ordinal, string? forwarderName)
{
	internal string Name => name;
	internal uint Ordinal => ordinal;
	internal string? ForwarderName => forwarderName;
}
