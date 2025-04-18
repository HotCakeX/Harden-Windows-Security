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

using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using Microsoft.Win32.SafeHandles;

namespace AppControlManager;

internal static partial class NativeMethods
{

	// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontextw
	[LibraryImport("advapi32.dll", EntryPoint = "CryptAcquireContextW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptAcquireContext(
			out IntPtr hProv,
			string? pszContainer,
			string? pszProvider,
			uint dwProvType,
			uint dwFlags);


	// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash
	[LibraryImport("advapi32.dll", EntryPoint = "CryptCreateHash", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptCreateHash(
		 IntPtr hProv,
		 uint Algid,
		 IntPtr hKey,
		 uint dwFlags,
		 out IntPtr phHash);


	// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-crypthashdata
	[LibraryImport("advapi32.dll", EntryPoint = "CryptHashData", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptHashData(
		 IntPtr hHash,
		 [In] byte[] pbData,
		 uint dataLen,
		 uint dwFlags);


	// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgethashparam
	[LibraryImport("advapi32.dll", EntryPoint = "CryptGetHashParam", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptGetHashParam(
		 IntPtr hHash,
		 uint dwParam,
		 [Out] byte[]? pbData,
		 ref uint pdwDataLen,
		 uint dwFlags);


	// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdestroyhash
	[LibraryImport("advapi32.dll", EntryPoint = "CryptDestroyHash", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptDestroyHash(IntPtr hHash);


	// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptreleasecontext
	[LibraryImport("advapi32.dll", EntryPoint = "CryptReleaseContext", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptReleaseContext(IntPtr hProv, uint dwFlags);


	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstvolumew
	[LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16, EntryPoint = "FindFirstVolumeW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr FindFirstVolume(
		[MarshalUsing(CountElementName = "cchBufferLength")][Out] char[] lpszVolumeName,
		uint cchBufferLength);


	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextvolumew
	[LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16, EntryPoint = "FindNextVolumeW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool FindNextVolume(
		IntPtr hFindVolume,
		[MarshalUsing(CountElementName = "cchBufferLength")][Out] char[] lpszVolumeName,
		uint cchBufferLength);


	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-querydosdevicew
	[LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16, EntryPoint = "QueryDosDeviceW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint QueryDosDevice(
		string lpDeviceName,
		[MarshalUsing(CountElementName = "ucchMax")][Out] char[] lpTargetPath,
		int ucchMax);


	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamesforvolumenamew
	[LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16, EntryPoint = "GetVolumePathNamesForVolumeNameW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool GetVolumePathNamesForVolumeNameW(
		[MarshalAs(UnmanagedType.LPWStr)] string lpszVolumeName,
		[MarshalUsing(CountElementName = "cchBuferLength")][Out] char[] lpszVolumeNamePaths,
		uint cchBuferLength,
		ref uint lpcchReturnLength);


	// https://learn.microsoft.com/en-us/windows/win32/api/mssip/nf-mssip-cryptsipretrievesubjectguid
	[LibraryImport("crypt32.dll", EntryPoint = "CryptSIPRetrieveSubjectGuid", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptSIPRetrieveSubjectGuid(
		string FileName,
		IntPtr hFileIn,
		out Guid pgActionID);


	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
	[LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CreateFileW(
		string lpFileName,
		uint dwDesiredAccess,
		uint dwShareMode,
		IntPtr lpSecurityAttributes,
		uint dwCreationDisposition,
		uint dwFlagsAndAttributes,
		IntPtr hTemplateFile);


	// https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CloseHandle(IntPtr hObject);


	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga
	[LibraryImport("kernel32.dll", EntryPoint = "CreateFileMappingW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CreateFileMapping(
		IntPtr hFile,
		IntPtr pFileMappingAttributes,
		uint flProtect,
		uint dwMaximumSizeHigh,
		uint dwMaximumSizeLow,
		string lpName);


	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesize
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint GetFileSize(IntPtr hFile, ref uint lpFileSizeHigh);


	// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr MapViewOfFile(
		IntPtr hFileMappingObject,
		uint dwDesiredAccess,
		uint dwFileOffsetHigh,
		uint dwFileOffsetLow,
		IntPtr dwNumberOfBytesToMap);


	// https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagedirectoryentrytodataex
	[LibraryImport("DbgHelp.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr ImageDirectoryEntryToDataEx(
		IntPtr Base,
		int MappedAsImage,
		ushort DirectoryEntry,
		ref uint Size,
		ref IntPtr FoundHeader);


	// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int UnmapViewOfFile(IntPtr lpBaseAddress);


	// https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagentheader
	[LibraryImport("DbgHelp.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr ImageNtHeader(IntPtr ImageBase);


	// https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagervatova
	[LibraryImport("DbgHelp.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr ImageRvaToVa(
		IntPtr NtHeaders,
		IntPtr Base,
		uint Rva,
		IntPtr LastRvaSection);


	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#system_codeintegrity_information
	[LibraryImport("ntdll.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int NtQuerySystemInformation(
	int SystemInformationClass,
	IntPtr SystemInformation,
	int SystemInformationLength,
	ref int ReturnLength
	);


	// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
	[LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial SafeFileHandle CreateFile(
	 string lpFileName,
	 uint dwDesiredAccess,
	 uint dwShareMode,
	 IntPtr lpSecurityAttributes,
	 uint dwCreationDisposition,
	 uint dwFlagsAndAttributes,
	 IntPtr hTemplateFile);

}
