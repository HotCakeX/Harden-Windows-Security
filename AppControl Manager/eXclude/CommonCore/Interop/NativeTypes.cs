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

using System.Runtime.InteropServices;

namespace CommonCore.Interop;


/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-token_privileges
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct TOKEN_PRIVILEGES
{
	internal uint PrivilegeCount;
	internal LUID_AND_ATTRIBUTES Privileges;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-luid
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct LUID
{
	internal uint LowPart;
	internal int HighPart;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-luid_and_attributes
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct LUID_AND_ATTRIBUTES
{
	internal LUID Luid;
	internal uint Attributes;
}


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

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_INFORMATION
{
	internal IntPtr hProcess;
	internal IntPtr hThread;
	internal uint dwProcessId;
	internal uint dwThreadId;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex2
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_MEMORY_COUNTERS_EX2
{
	internal uint cb;
	internal uint PageFaultCount;
	internal nuint PeakWorkingSetSize;
	internal nuint WorkingSetSize;
	internal nuint QuotaPeakPagedPoolUsage;
	internal nuint QuotaPagedPoolUsage;
	internal nuint QuotaPeakNonPagedPoolUsage;
	internal nuint QuotaNonPagedPoolUsage;
	internal nuint PagefileUsage;
	internal nuint PeakPagefileUsage;
	internal nuint PrivateUsage;
	internal nuint PrivateWorkingSetSize;
	internal nuint SharedCommitUsage;
	internal ulong PrivateCommitUsage;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/ntdef/ns-ntdef-_unicode_string
/// Represents a Unicode string with a specified length and a pointer to the string's buffer. It includes fields for the
/// string's current length and maximum length.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct UNICODE_STRING
{
	internal ushort Length;
	internal ushort MaximumLength;
	internal IntPtr Buffer;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/psapi/ns-psapi-performance_information
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct PerformanceInformation
{
	internal uint Size;
	internal nint CommitTotal;
	internal nint CommitLimit;
	internal nint CommitPeak;
	internal nint PhysicalTotal;
	internal nint PhysicalAvailable;
	internal nint SystemCache;
	internal nint KernelTotal;
	internal nint KernelPaged;
	internal nint KernelNonpaged;
	internal nint PageSize;
	internal uint HandleCount;
	internal uint ProcessCount;
	internal uint ThreadCount;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/ifmib/ns-ifmib-mib_ifrow
/// MIB_IFROW: IPv4-era per-interface stats with 32-bit octet counters.
/// Using unsafe fixed buffers to match native layout; only fields we need are read.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct MIB_IFROW
{
	// MAX_INTERFACE_NAME_LEN is 256 WCHARs
	private fixed char wszName[256];

	internal uint dwIndex;
	internal uint dwType;
	internal uint dwMtu;
	internal uint dwSpeed;
	internal uint dwPhysAddrLen;
	private fixed byte bPhysAddr[8];
	internal uint dwAdminStatus;
	internal uint dwOperStatus;
	internal uint dwLastChange;
	internal uint dwInOctets;         // 32-bit byte counters (wrap at 4GB)
	internal uint dwInUcastPkts;
	internal uint dwInNUcastPkts;
	internal uint dwInDiscards;
	internal uint dwInErrors;
	internal uint dwInUnknownProtos;
	internal uint dwOutOctets;        // 32-bit byte counters (wrap at 4GB)
	internal uint dwOutUcastPkts;
	internal uint dwOutNUcastPkts;
	internal uint dwOutDiscards;
	internal uint dwOutErrors;
	internal uint dwOutQLen;
	internal uint dwDescrLen;
	// MAXLEN_IFDESCR is 256 bytes
	private fixed byte bDescr[256];
}

[Flags]
internal enum RegNotifyFilter : uint
{
	Name = 1,
	Attributes = 2,
	LastSet = 4,
	Security = 8
}

/// <summary>
/// Defines different types of secure setting values used in WLDP. Types include Boolean, Integer, None, String, and
/// Flag.
/// </summary>
internal enum WLDP_SECURE_SETTING_VALUE_TYPE
{
	WldpBoolean = 0,
	WldpInteger = 1,
	WldpNone = 2,
	WldpString = 3,
	WldpFlag = 4
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winuser/ns-winuser-windowplacement
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct WINDOWPLACEMENT
{
	internal int length;
	internal int flags;
	internal ShowWindowCommands showCmd;
	internal POINT ptMinPosition;
	internal POINT ptMaxPosition;
	internal RECT rcNormalPosition;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-showwindow#parameters
/// </summary>
internal enum ShowWindowCommands
{
	SW_HIDE = 0,
	SW_SHOWNORMAL = 1,
	SW_SHOWMINIMIZED = 2,
	SW_SHOWMAXIMIZED = 3,
	SW_SHOWNOACTIVATE = 4,
	SW_SHOW = 5,
	SW_MINIMIZE = 6,
	SW_SHOWMINNOACTIVE = 7,
	SW_SHOWNA = 8,
	SW_RESTORE = 9,
	SW_SHOWDEFAULT = 10,
	SW_FORCEMINIMIZE = 11
}

/// <summary>
/// https://learn.microsoft.com/dotnet/api/system.drawing.point?view=net-9.0
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct POINT
{
	internal int x;
	internal int y;
}

[StructLayout(LayoutKind.Sequential)]
internal struct RECT
{
	internal int left;
	internal int top;
	internal int right;
	internal int bottom;
}

/// <summary>
/// Enum defining WinVerifyTrust results
/// </summary>
internal enum WinVerifyTrustResult : uint
{
	Success = 0, // It's Success
	SubjectCertificateRevoked = 2148204812, // Subject's certificate was revoked. (CERT_E_REVOKED)
	SubjectNotTrusted = 2148204548, // Subject failed the specified verification action
	CertExpired = 2148204801, // This is checked for - Signer's certificate was expired. (CERT_E_EXPIRED)
	UntrustedRootCert = 2148204809, // A certification chain processed correctly but terminated in a root certificate that is not trusted by the trust provider. (CERT_E_UNTRUSTEDROOT)
	HashMismatch = 2148098064, // This is checked for (aka: SignatureOrFileCorrupt) - (TRUST_E_BAD_DIGEST)
	ProviderUnknown = 2148204545, // Trust provider is not recognized on this system
	ActionUnknown = 2148204546, // Trust provider does not support the specified action
	SubjectFormUnknown = 2148204547, // Trust provider does not support the subject's form
	FileNotSigned = 2148204800, // File is not signed. (TRUST_E_NOSIGNATURE)
	SubjectExplicitlyDistrusted = 2148204817, // Signer's certificate is in the Untrusted Publishers store
}

/// <summary>
/// https://learn.microsoft.com/openspecs/windows_protocols/ms-samr/d74231bd-81e2-4229-9e82-ce6d3713cc62
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SAM_USER_GENERAL_INFORMATION
{
	internal LSA_UNICODE_STRING UserName;
	internal LSA_UNICODE_STRING FullName;
	internal uint PrimaryGroupId;
	internal LSA_UNICODE_STRING AdminComment;
	internal LSA_UNICODE_STRING UserComment;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_0
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct USER_MODALS_INFO_0
{
	internal uint min_passwd_len;
	internal uint max_passwd_age;
	internal uint min_passwd_age;
	internal uint force_logoff;
	internal uint password_hist_len;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_3
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct USER_MODALS_INFO_3
{
	internal uint lockout_duration;
	internal uint lockout_observation_window;
	internal uint lockout_threshold;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/lmaccess/ns-lmaccess-user_info_1
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct USER_INFO_1
{
	internal IntPtr usri1_name;
	internal IntPtr usri1_password;
	internal uint usri1_password_age;
	internal uint usri1_priv;
	internal IntPtr usri1_home_dir;
	internal IntPtr usri1_comment;
	internal uint usri1_flags;
	internal IntPtr usri1_script_path;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/lsalookup/ns-lsalookup-lsa_unicode_string
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct LSA_UNICODE_STRING
{
	internal ushort Length;
	internal ushort MaximumLength;
	internal IntPtr Buffer;

	internal LSA_UNICODE_STRING(string? s)
	{
		if (s is null)
		{
			Length = MaximumLength = 0;
			Buffer = IntPtr.Zero;
		}
		else
		{
			Length = (ushort)(s.Length * 2);
			MaximumLength = (ushort)(Length + 2);
			Buffer = Marshal.StringToHGlobalUni(s);
		}
	}
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/lsalookup/ns-lsalookup-lsa_string
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct LSA_STRING
{
	internal ushort Length;
	internal ushort MaximumLength;
	internal IntPtr Buffer;

	internal LSA_STRING(string s)
	{
		if (s is null)
		{
			Length = MaximumLength = 0;
			Buffer = IntPtr.Zero;
		}
		else
		{
			Length = (ushort)s.Length;
			MaximumLength = (ushort)(Length + 1);
			Buffer = Marshal.StringToHGlobalAnsi(s);
		}
	}
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/lsalookup/ns-lsalookup-lsa_object_attributes
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct LSA_OBJECT_ATTRIBUTES
{
	internal int Length;
	internal IntPtr RootDirectory;
	internal IntPtr ObjectName;
	internal int Attributes;
	internal IntPtr SecurityDescriptor;
	internal IntPtr SecurityQualityOfService;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/ntsecapi/ns-ntsecapi-lsa_enumeration_information
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct LSA_ENUMERATION_INFORMATION
{
	internal IntPtr PSid;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/ntsecapi/ns-ntsecapi-audit_policy_information
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct AUDIT_POLICY_INFORMATION
{
	internal Guid AuditSubCategoryGuid;
	internal uint AuditingInformation;
	internal Guid AuditCategoryGuid;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/lsalookup/ns-lsalookup-policy_account_domain_info
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct POLICY_ACCOUNT_DOMAIN_INFO
{
	internal LSA_UNICODE_STRING DomainName;
	internal IntPtr DomainSid;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/ntsecapi/ns-ntsecapi-domain_password_information
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct DOMAIN_PASSWORD_INFORMATION
{
	internal ushort MinPasswordLength;
	internal ushort PasswordHistoryLength;
	internal uint PasswordProperties;
	internal long MaxPasswordAge;
	internal long MinPasswordAge;
}

/// <summary>
/// Structure to hold extra info about the file trust
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MpFileTrustExtraInfo
{
	internal uint First;             // First extra info field
	internal uint Second;            // Second extra info field
	internal uint DataSize;          // Size of the data
	internal uint AlignmentPadding;  // Padding for memory alignment
	internal IntPtr Data;            // Pointer to extra data
}

/// <summary>
/// Structure to hold parameters for file trust query in Microsoft Defender
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct Params
{
	public uint StructSize;         // Size of the structure
	public int TrustScore;          // Trust score of the file
	public ulong ValidityDurationMs; // Validity of the trust score in milliseconds
}

/// <summary>
/// Used by the Rust Interop Library.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct StringArrayForFileDialogHelper
{
	internal IntPtr Strings;
	internal int Count;
}

/// <summary>
/// https://learn.microsoft.com/openspecs/office_file_formats/ms-oshared/91755632-4b0d-44ca-89a9-9699afbbd268
/// Rust implementation: https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/WinTrust/struct.SPC_SP_OPUS_INFO.html
/// This is NON-Blittable because of the string inside it, but it is fine because we don't pass it to any Native methods.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct OpusInfoObj
{
	[MarshalAs(UnmanagedType.LPWStr)]
	internal string CertOemID = string.Empty;

	internal IntPtr PublisherInfo = IntPtr.Zero;

	/// <summary>
	/// not always present
	/// </summary>
	internal IntPtr MoreInfo = IntPtr.Zero;

	public OpusInfoObj()
	{
		CertOemID = string.Empty;
		PublisherInfo = IntPtr.Zero;
		MoreInfo = IntPtr.Zero;
	}
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/mscat/ns-mscat-cryptcatmember
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal readonly struct MeowMemberCrypt
{
	public readonly uint StructureSize;
	public readonly IntPtr Hashes;
	public readonly IntPtr FileName;
	public readonly Guid SubjectType;
	public readonly uint MemberFlags;
	public readonly IntPtr IndirectDataStructure;
	public readonly uint CertVersion;
	private readonly uint Reserved1;
	private readonly IntPtr Reserved2;
}

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

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-io_counters
/// </summary>
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

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information
/// </summary>
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

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information
/// </summary>
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

internal enum SERVICE_STATE : uint
{
	SERVICE_STOPPED = 0x00000001,
	SERVICE_START_PENDING = 0x00000002,
	SERVICE_STOP_PENDING = 0x00000003,
	SERVICE_RUNNING = 0x00000004
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_status_process
/// </summary>
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

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_table_entryw
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SERVICE_TABLE_ENTRY
{
	internal IntPtr lpServiceName; // LPWSTR
	internal IntPtr lpServiceProc; // LPSERVICE_MAIN_FUNCTIONW
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-crypt_context_functions
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal readonly struct CRYPT_CONTEXT_FUNCTIONS
{
	internal readonly uint cFunctions;
	internal readonly IntPtr rgpszFunctions;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-crypt_provider_refs
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal readonly struct CRYPT_PROVIDER_REFS
{
	internal readonly uint cProviders;
	internal readonly IntPtr rgpProviders;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-crypt_provider_ref
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal readonly struct CRYPT_PROVIDER_REF
{
	internal readonly uint dwInterface;
	internal readonly IntPtr pszFunction;
	internal readonly IntPtr pszProvider;
	internal readonly uint cProperties;
	internal readonly IntPtr rgpProperties;
	internal readonly IntPtr pUM;
	internal readonly IntPtr pKM;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-crypt_providers
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal readonly struct CRYPT_PROVIDERS
{
	internal readonly uint cProviders;
	internal readonly IntPtr rgpszProviders;
}

/// <summary>
/// SAMPR_USER_INFO_BUFFER union; we only model the member we use (UserControlInformation) at offset 0.
/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9496c26e-490b-4e76-827f-2695fc216f35
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct SAMPR_USER_INFO_BUFFER
{
	[FieldOffset(0)]
	internal SAMPR_USER_CONTROL_INFORMATION UserControlInformation;

	[FieldOffset(0)]
	internal SAMPR_USER_NAME_INFORMATION UserNameInformation;
}

/// <summary>
/// [MS-SAMR] 2.2.6.28/2.2.6.29
/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/eb5f1508-ede1-4ff1-be82-55f3e2ef1633
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SAMPR_USER_CONTROL_INFORMATION
{
	internal uint Control;
}

/// <summary>
/// SAMPR_USER_NAME_INFORMATION structure used with SamSetInformationUser(UserNameInformation).
/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/400d937e-66e5-44af-929d-13dfab550d46
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SAMPR_USER_NAME_INFORMATION
{
	internal LSA_UNICODE_STRING UserName;
	internal LSA_UNICODE_STRING FullName;
}
