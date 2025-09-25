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

namespace QuantumRelayHSS;

internal static partial class NativeMethods
{

	// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process
	internal const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
	internal const uint SERVICE_ACCEPT_STOP = 0x00000001;
	internal const uint SERVICE_ACCEPT_SHUTDOWN = 0x00000004;

	// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-controlservice
	internal const uint SERVICE_CONTROL_STOP = 0x00000001;

	// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Services/constant.SERVICE_CONTROL_SHUTDOWN.html
	internal const uint SERVICE_CONTROL_SHUTDOWN = 0x00000005;

	internal enum SERVICE_STATE : uint
	{
		SERVICE_STOPPED = 0x00000001,
		SERVICE_START_PENDING = 0x00000002,
		SERVICE_STOP_PENDING = 0x00000003,
		SERVICE_RUNNING = 0x00000004
	}

	// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_status_process
	[StructLayout(LayoutKind.Sequential)]
	internal struct SERVICE_STATUS
	{
		internal uint dwServiceType;
		internal uint dwCurrentState;
		internal uint dwControlsAccepted;
		internal uint dwWin32ExitCode;
		internal uint dwServiceSpecificExitCode;
		internal uint dwCheckPoint;
		internal uint dwWaitHint;
	}

	[UnmanagedFunctionPointer(CallingConvention.Winapi)]
	internal delegate void ServiceMainFunction(uint dwNumServicesArgs, IntPtr lpServiceArgVectors); // LPWSTR* marshalled as IntPtr

	[UnmanagedFunctionPointer(CallingConvention.Winapi)]
	internal delegate uint HandlerEx(uint dwControl, uint dwEventType, IntPtr lpEventData, IntPtr lpContext);

	// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_table_entryw
	[StructLayout(LayoutKind.Sequential)]
	internal struct SERVICE_TABLE_ENTRY
	{
		internal IntPtr lpServiceName; // LPWSTR
		internal IntPtr lpServiceProc; // LPSERVICE_MAIN_FUNCTIONW
	}

	[LibraryImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool StartServiceCtrlDispatcherW([In] SERVICE_TABLE_ENTRY[] lpServiceStartTable);

	[LibraryImport("advapi32.dll", EntryPoint = "RegisterServiceCtrlHandlerExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr RegisterServiceCtrlHandlerExW(string lpServiceName, HandlerEx lpHandlerProc, IntPtr lpContext);

	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool SetServiceStatus(IntPtr hServiceStatus, ref SERVICE_STATUS lpServiceStatus);

	[LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr RegisterEventSourceW(string? lpUNCServerName, string lpSourceName);

	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool DeregisterEventSource(IntPtr hEventLog);

	[LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool ReportEventW(
		IntPtr hEventLog,
		ushort wType,
		ushort wCategory,
		uint dwEventID,
		IntPtr lpUserSid,
		ushort wNumStrings,
		uint dwDataSize,
		[In, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[] lpStrings,
		IntPtr lpRawData);

	[LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RegCreateKeyExW(
		IntPtr hKey,
		string lpSubKey,
		uint Reserved,
		string? lpClass,
		uint dwOptions,
		uint samDesired,
		IntPtr lpSecurityAttributes,
		out IntPtr phkResult,
		out uint lpdwDisposition);

	[LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RegSetValueExW(
		IntPtr hKey,
		[MarshalAs(UnmanagedType.LPWStr)] string lpValueName,
		uint Reserved,
		uint dwType,
		[In] byte[] lpData,
		uint cbData);

	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RegCloseKey(IntPtr hKey);


	// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information
	internal const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

	internal enum JOBOBJECTINFOCLASS
	{
		JobObjectBasicAccountingInformation = 1,
		JobObjectBasicLimitInformation = 2,
		JobObjectBasicProcessIdList = 3,
		JobObjectBasicUIRestrictions = 4,
		JobObjectSecurityLimitInformation = 5,
		JobObjectEndOfJobTimeInformation = 6,
		JobObjectAssociateCompletionPortInformation = 7,
		JobObjectBasicAndIoAccountingInformation = 8,
		JobObjectExtendedLimitInformation = 9,
		JobObjectJobSetInformation = 13,
	}

	// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-io_counters
	[StructLayout(LayoutKind.Sequential)]
	internal struct IO_COUNTERS
	{
		internal ulong ReadOperationCount;
		internal ulong WriteOperationCount;
		internal ulong OtherOperationCount;
		internal ulong ReadTransferCount;
		internal ulong WriteTransferCount;
		internal ulong OtherTransferCount;
	}

	// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information
	[StructLayout(LayoutKind.Sequential)]
	internal struct JOBOBJECT_BASIC_LIMIT_INFORMATION
	{
		internal long PerProcessUserTimeLimit;   // LARGE_INTEGER
		internal long PerJobUserTimeLimit;       // LARGE_INTEGER
		internal uint LimitFlags;                // JOB_OBJECT_LIMIT_*
		internal UIntPtr MinimumWorkingSetSize;  // SIZE_T
		internal UIntPtr MaximumWorkingSetSize;  // SIZE_T
		internal uint ActiveProcessLimit;        // DWORD
		internal UIntPtr Affinity;               // ULONG_PTR
		internal uint PriorityClass;             // DWORD
		internal uint SchedulingClass;           // DWORD
	}

	// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information
	[StructLayout(LayoutKind.Sequential)]
	internal struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	{
		internal JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
		internal IO_COUNTERS IoInfo;
		internal UIntPtr ProcessMemoryLimit;       // SIZE_T
		internal UIntPtr JobMemoryLimit;           // SIZE_T
		internal UIntPtr PeakProcessMemoryUsed;    // SIZE_T
		internal UIntPtr PeakJobMemoryUsed;        // SIZE_T
	}

	[LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string? lpName);

	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool SetInformationJobObject(
		IntPtr hJob,
		JOBOBJECTINFOCLASS JobObjectInformationClass,
		ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInformation,
		uint cbJobObjectInformationLength);

	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

	// https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-closehandle
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CloseHandle(IntPtr hObject);

	// https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
	[LibraryImport("kernel32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr GetCurrentProcess();

	// https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CheckTokenMembership(IntPtr TokenHandle, IntPtr SidToCheck, [MarshalAs(UnmanagedType.Bool)] out bool IsMember);
}
