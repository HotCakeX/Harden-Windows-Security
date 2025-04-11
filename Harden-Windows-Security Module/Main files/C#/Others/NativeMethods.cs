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
using static HardenWindowsSecurity.FirmwareChecker;
using static HardenWindowsSecurity.SystemInformationClass;

namespace HardenWindowsSecurity;

internal static class NativeMethods
{
	// Structure to hold parameters for file trust query in Microsoft Defender
	[StructLayout(LayoutKind.Sequential)]
	internal struct Params
	{
		public uint StructSize;         // Size of the structure
		public int TrustScore;          // Trust score of the file
		public ulong ValidityDurationMs; // Validity of the trust score in milliseconds
	}

	[DllImport("TpmCoreProvisioning", CharSet = CharSet.Unicode)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern uint TpmIsEnabled(out byte pfIsEnabled);

	[DllImport("TpmCoreProvisioning", CharSet = CharSet.Unicode)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern uint TpmIsActivated(out byte pfIsActivated);

	// Load a library dynamically
	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern IntPtr LoadLibraryExW(string lpFileName, IntPtr hFile, uint dwFlags);

	// Get the address of a procedure (function) from a loaded library
	// BestFitMapping = false disables the automatic conversion of characters that cannot be represented in the target character set, satisfying the CA2101
	// Windows uses ANSI encoding for exported function names so we cannot use Unicode for GetProcAddress.
	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

	[DllImport("ntdll.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern Int32 NtQuerySystemInformation(
		SYSTEM_DMA_GUARD_POLICY_INFORMATION SystemDmaGuardPolicyInformation,
		IntPtr SystemInformation,
		Int32 SystemInformationLength,
		out Int32 ReturnLength);

	// Delegate for the function signature of 'MpQueryFileTrustByHandle2'
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	internal delegate long MpQueryFileTrustByHandle2Delegate(
		IntPtr hFile, IntPtr a2, IntPtr a3,
		ref Params pParams, ref ulong extraInfoCount, ref IntPtr MpFileTrustExtraInfo);

	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwaretype
	[DllImport(dllName: "kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern bool GetFirmwareType(out FirmwareType firmwareType);

	// Create a file handle to interact with a file
	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern IntPtr CreateFile(
		string lpFileName, uint dwDesiredAccess, uint dwShareMode,
		IntPtr lpSecurityAttributes, uint dwCreationDisposition,
		uint dwFlagsAndAttributes, IntPtr hTemplateFile);

	[DllImport("shell32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern int SHGetKnownFolderPath(
		ref Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);

	// Close an open file handle
	[DllImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern bool CloseHandle(IntPtr hObject);
}
