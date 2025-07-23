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
using HardenWindowsSecurity.SecurityPolicy;
using static HardenWindowsSecurity.ExploitMitigation.Main;

namespace AppControlManager;

internal static partial class NativeMethods
{
	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-refreshpolicyex
	/// </summary>
	internal const uint RP_FORCE = 0x00000001;

	[LibraryImport("userenv.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool RefreshPolicyEx([MarshalAs(UnmanagedType.Bool)] bool bMachine, uint dwOptions);

	[LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint NetUserModalsGet(
		string? servername,
		int level,
		out IntPtr bufptr
	);

	[LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint NetUserModalsSet(
		string? servername,
		int level,
		IntPtr bufptr,
		out uint parm_err
	);

	[LibraryImport("netapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int NetApiBufferFree(IntPtr Buffer);

	[LibraryImport("netapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint NetApiBufferAllocate(
		uint ByteCount,
		out IntPtr Buffer
	);

	[LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint LsaOpenPolicy(
		ref LSA_UNICODE_STRING SystemName,
		ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
		int DesiredAccess,
		out IntPtr PolicyHandle
	);

	[LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint LsaEnumerateAccountsWithUserRight(
		IntPtr PolicyHandle,
		ref LSA_UNICODE_STRING UserRight,
		out IntPtr EnumerationBuffer,
		out int CountReturned
	);

	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int LsaClose(IntPtr PolicyHandle);

	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int LsaFreeMemory(IntPtr Buffer);

	[LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint LsaQueryInformationPolicy(
		IntPtr PolicyHandle,
		int InformationClass,
		out IntPtr Buffer
	);

	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool AuditEnumerateCategories(
		out IntPtr ppAuditCategoriesArray,
		out uint pCountReturned
	);

	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool AuditEnumerateSubCategories(
		IntPtr pAuditCategoryGuid,
		[MarshalAs(UnmanagedType.Bool)] bool bRetrieveAllSubCategories,
		out IntPtr ppAuditSubCategoriesArray,
		out uint pCountReturned
	);

	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool AuditQuerySystemPolicy(
		IntPtr pSubCategoryGuids,
		uint PolicyCount,
		out IntPtr ppAuditPolicy
	);

	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial void AuditFree(IntPtr Buffer);

	[LibraryImport("samlib.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamConnect(
		ref LSA_UNICODE_STRING ServerName,
		out IntPtr ServerHandle,
		uint DesiredAccess,
		IntPtr ObjectAttributes
	);

	[LibraryImport("samlib.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamOpenDomain(
		IntPtr ServerHandle,
		uint DesiredAccess,
		IntPtr DomainId,
		out IntPtr DomainHandle
	);

	[LibraryImport("samlib.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamQueryInformationDomain(
		IntPtr DomainHandle,
		int DomainInformationClass,
		out IntPtr Buffer
	);

	[LibraryImport("samlib.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamCloseHandle(IntPtr SamHandle);

	[LibraryImport("samlib.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamFreeMemory(IntPtr Buffer);

	[LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint NetUserGetInfo(
		string? servername,
		string username,
		uint level,
		out IntPtr bufptr
	);

	[LibraryImport("secur32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint LsaLookupAuthenticationPackage(
		IntPtr LsaHandle,
		ref LSA_STRING PackageName,
		out uint AuthenticationPackage
	);

	[LibraryImport("samlib.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamOpenUser(
	IntPtr DomainHandle,
	uint DesiredAccess,
	uint UserId,
	out IntPtr UserHandle
	);

	[LibraryImport("samlib.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamQueryInformationUser(
		IntPtr UserHandle,
		int UserInformationClass,
		out IntPtr Buffer
	);

	[LibraryImport("bcd.dll", EntryPoint = "BcdOpenSystemStore", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BcdOpenSystemStore(out IntPtr storeHandle);

	[LibraryImport("bcd.dll", EntryPoint = "BcdCloseStore", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BcdCloseStore(IntPtr storeHandle);

	[LibraryImport("bcd.dll", EntryPoint = "BcdOpenObject", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BcdOpenObject(IntPtr storeHandle, ref Guid identifier, out IntPtr objectHandle);

	[LibraryImport("bcd.dll", EntryPoint = "BcdCloseObject", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BcdCloseObject(IntPtr objectHandle);

	[LibraryImport("bcd.dll", EntryPoint = "BcdSetElementDataWithFlags", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BcdSetElementDataWithFlags(
		IntPtr objectHandle,
		uint elementType,
		uint flags,
		IntPtr data,
		uint dataSize);

	[LibraryImport("bcd.dll", EntryPoint = "BcdGetElementDataWithFlags", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BcdGetElementDataWithFlags(
		IntPtr objectHandle,
		uint elementType,
		uint flags,
		IntPtr data,
		ref uint dataSize);

	[LibraryImport("ntdll.dll", EntryPoint = "RtlNtStatusToDosErrorW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RtlNtStatusToDosError(int ntStatus);

	[LibraryImport("ntdll.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RtlQueryImageMitigationPolicy(
	string? imagePath,
	IMAGE_MITIGATION_POLICY policy,
	uint Flags,
	IntPtr buffer,
	uint bufferSize);

	[LibraryImport("ntdll.dll", EntryPoint = "RtlSetImageMitigationPolicy", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RtlSetImageMitigationPolicy(
	  string? imagePath,
	  IMAGE_MITIGATION_POLICY policy,
	  uint Flags,
	  IntPtr buffer,
	  uint bufferSize);

	[LibraryImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CreateProcess(
		string? lpApplicationName,
		string lpCommandLine,
		IntPtr lpProcessAttributes,
		IntPtr lpThreadAttributes,
		[MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
		uint dwCreationFlags,
		IntPtr lpEnvironment,
		string? lpCurrentDirectory,
		ref STARTUPINFO lpStartupInfo,
		out PROCESS_INFORMATION lpProcessInformation);

	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool TerminateProcess(IntPtr hProcess, uint uExitCode);

	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

	[StructLayout(LayoutKind.Sequential)]
	internal struct STARTUPINFO
	{
		internal uint cb;
		internal IntPtr lpReserved;
		internal IntPtr lpDesktop;
		internal IntPtr lpTitle;
		internal uint dwX;
		internal uint dwY;
		internal uint dwXSize;
		internal uint dwYSize;
		internal uint dwXCountChars;
		internal uint dwYCountChars;
		internal uint dwFillAttribute;
		internal uint dwFlags;
		internal ushort wShowWindow;
		internal ushort cbReserved2;
		internal IntPtr lpReserved2;
		internal IntPtr hStdInput;
		internal IntPtr hStdOutput;
		internal IntPtr hStdError;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct PROCESS_INFORMATION
	{
		internal IntPtr hProcess;
		internal IntPtr hThread;
		internal uint dwProcessId;
		internal uint dwThreadId;
	}
}
