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
using System.Runtime.InteropServices.Marshalling;

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

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winbase/ns-winbase-startupinfoexw
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct STARTUPINFOEX
{
	internal STARTUPINFO StartupInfo;
	internal IntPtr lpAttributeList;
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

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_if_row2
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct MIB_IF_ROW2
{
	internal ulong InterfaceLuid; // NET_LUID
	internal uint InterfaceIndex; // NET_IFINDEX
	internal Guid InterfaceGuid;
	private fixed char Alias[257]; // IF_MAX_STRING_SIZE + 1
	private fixed char Description[257]; // IF_MAX_STRING_SIZE + 1
	internal uint PhysicalAddressLength;
	private fixed byte PhysicalAddress[32]; // IF_MAX_PHYS_ADDRESS_LENGTH
	private fixed byte PermanentPhysicalAddress[32]; // IF_MAX_PHYS_ADDRESS_LENGTH
	internal uint Mtu;
	internal uint Type; // IFT_FAMILY
	internal int TunnelType; // TUNNEL_TYPE
	internal int MediaType; // NDIS_MEDIUM
	internal int PhysicalMediumType; // NDIS_PHYSICAL_MEDIUM
	internal int AccessType; // NET_IF_ACCESS_TYPE
	internal int DirectionType; // NET_IF_DIRECTION_TYPE
	internal int InterfaceAndOperStatusFlags; // Bitfields (ULONG)
	internal int OperStatus; // IF_OPER_STATUS
	internal int AdminStatus; // NET_IF_ADMIN_STATUS
	internal int MediaConnectState; // NET_IF_MEDIA_CONNECT_STATE
	internal Guid NetworkGuid;
	internal int ConnectionType; // NET_IF_CONNECTION_TYPE
	internal ulong TransmitLinkSpeed;
	internal ulong ReceiveLinkSpeed;
	internal ulong InOctets;
	internal ulong InUcastPkts;
	internal ulong InNUcastPkts;
	internal ulong InDiscards;
	internal ulong InErrors;
	internal ulong InUnknownProtos;
	internal ulong InUcastOctets;
	internal ulong InMulticastOctets;
	internal ulong InBroadcastOctets;
	internal ulong OutOctets;
	internal ulong OutUcastPkts;
	internal ulong OutNUcastPkts;
	internal ulong OutDiscards;
	internal ulong OutErrors;
	internal ulong OutUcastOctets;
	internal ulong OutMulticastOctets;
	internal ulong OutBroadcastOctets;
	internal ulong OutQLen;
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
internal struct SERVICE_STATUS_PROCESS
{
	internal uint dwServiceType;
	internal uint dwCurrentState;
	internal uint dwControlsAccepted;
	internal uint dwWin32ExitCode;
	internal uint dwServiceSpecificExitCode;
	internal uint dwCheckPoint;
	internal uint dwWaitHint;
	internal uint dwProcessId;
	internal uint dwServiceFlags;
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
/// https://learn.microsoft.com/openspecs/windows_protocols/ms-samr/9496c26e-490b-4e76-827f-2695fc216f35
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
/// https://learn.microsoft.com/openspecs/windows_protocols/ms-samr/eb5f1508-ede1-4ff1-be82-55f3e2ef1633
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SAMPR_USER_CONTROL_INFORMATION
{
	internal uint Control;
}

/// <summary>
/// SAMPR_USER_NAME_INFORMATION structure used with SamSetInformationUser(UserNameInformation).
/// https://learn.microsoft.com/openspecs/windows_protocols/ms-samr/400d937e-66e5-44af-929d-13dfab550d46
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SAMPR_USER_NAME_INFORMATION
{
	internal LSA_UNICODE_STRING UserName;
	internal LSA_UNICODE_STRING FullName;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winnt/ne-winnt-logical_processor_relationship
/// </summary>
internal enum LOGICAL_PROCESSOR_RELATIONSHIP
{
	RelationProcessorCore,
	RelationNumaNode,
	RelationCache,
	RelationProcessorPackage,
	RelationGroup,
	RelationProcessorDie,
	RelationNumaNodeEx,
	RelationProcessorModule,
	RelationAll = 0xffff
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winnt/ne-winnt-processor_cache_type
/// </summary>
internal enum PROCESSOR_CACHE_TYPE
{
	CacheUnified = 0,
	CacheInstruction = 1,
	CacheData = 2,
	CacheTrace = 3,
	CacheUnknown
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-group_affinity
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct GROUP_AFFINITY
{
	internal nuint Mask;
	internal ushort Group;
	internal ushort Reserved1;
	internal ushort Reserved2;
	internal ushort Reserved3;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-cache_relationship
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct CACHE_RELATIONSHIP
{
	internal byte Level;
	internal byte Associativity;
	internal ushort LineSize;
	internal uint CacheSize;
	internal PROCESSOR_CACHE_TYPE Type;
	internal GROUP_AFFINITY GroupMask;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-processor_relationship
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct PROCESSOR_RELATIONSHIP
{
	internal byte Flags;
	internal byte EfficiencyClass;
	[MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
	internal byte[] Reserved;
	internal ushort GroupCount;
}

[StructLayout(LayoutKind.Sequential)]
internal struct PDH_FMT_COUNTERVALUE_DOUBLE
{
	internal uint CStatus;
	internal double Value;
}

[StructLayout(LayoutKind.Sequential)]
internal struct PDH_FMT_COUNTERVALUE_ITEM_DOUBLE
{
	internal IntPtr NamePtr;
	internal PDH_FMT_COUNTERVALUE_DOUBLE Value;
}

[StructLayout(LayoutKind.Sequential)]
internal struct VARIABLE_HEADER
{
	internal uint Size;
	internal uint DataOffset;
	internal uint DataSize;
	internal uint Attributes;
	internal Guid VendorGuid;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/sysinfoapi/ne-sysinfoapi-computer_name_format
/// </summary>
internal enum COMPUTER_NAME_FORMAT
{
	ComputerNameNetBIOS,
	ComputerNameDnsHostname,
	ComputerNameDnsDomain,
	ComputerNameDnsFullyQualified,
	ComputerNamePhysicalNetBIOS,
	ComputerNamePhysicalDnsHostname,
	ComputerNamePhysicalDnsDomain,
	ComputerNamePhysicalDnsFullyQualified,
	ComputerNameMax
}

/// <summary>
/// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_predict_failure
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct STORAGE_PREDICT_FAILURE
{
	internal uint PredictFailure;
	internal fixed byte VendorSpecific[512];
}

/// <summary>
/// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_property_query
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct STORAGE_PROPERTY_QUERY
{
	internal uint PropertyId;
	internal uint QueryType;
	internal fixed byte AdditionalParameters[1];
}

/// <summary>
/// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_temperature_data_descriptor
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct STORAGE_TEMPERATURE_DATA_DESCRIPTOR
{
	internal uint Version;
	internal uint Size;
	internal short CriticalTemperature;
	internal short WarningTemperature;
	internal ushort InfoCount;
	internal fixed byte Reserved0[2];
	internal fixed uint Reserved1[2];
}

/// <summary>
/// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_temperature_info
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct STORAGE_TEMPERATURE_INFO
{
	internal ushort Index;
	internal short Temperature;
	internal short OverThreshold;
	internal short UnderThreshold;
	internal byte OverThresholdChangable;
	internal byte UnderThresholdChangable;
	internal byte EventGenerated;
	internal byte Reserved0;
	internal uint Reserved1;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct VS_FIXEDFILEINFO
{
	internal uint dwSignature;
	internal uint dwStrucVersion;
	internal uint dwFileVersionMS;
	internal uint dwFileVersionLS;
	internal uint dwProductVersionMS;
	internal uint dwProductVersionLS;
	internal uint dwFileFlagsMask;
	internal uint dwFileFlags;
	internal uint dwFileOS;
	internal uint dwFileType;
	internal uint dwFileSubtype;
	internal uint dwFileDateMS;
	internal uint dwFileDateLS;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-crypt_provider_sgnr
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct CryptProviderSigner
{
	private readonly uint cbStruct;   // Size of structure
	private System.Runtime.InteropServices.ComTypes.FILETIME sftVerifyAsOf;   // Verification time
	private readonly uint csCertChain;   // Number of certificates in the chain
	private readonly IntPtr pasCertChain;   // Pointer to certificate chain
	private readonly uint dwSignerType;   // Type of signer
	private readonly IntPtr psSigner;   // Pointer to signer
	private readonly uint dwError;   // Error code
	internal uint csCounterSigners;   // Number of countersigners
	internal IntPtr pasCounterSigners;   // Pointer to countersigners
	internal IntPtr pChainContext;   // Pointer to chain context
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-crypt_provider_data
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct CryptProviderData
{
	internal uint cbStruct;                        // Size of structure
	internal IntPtr pWintrustData;                 // WINTRUST_DATA*
	internal int fOpenedFile;                      // BOOL
	internal IntPtr hWndParent;                    // HWND
	internal IntPtr pgActionId;                    // GUID*
	internal IntPtr hProv;                         // HCRYPTPROV
	internal uint dwError;                         // DWORD
	internal uint dwRegSecuritySettings;           // DWORD
	internal uint dwRegPolicySettings;             // DWORD
	internal IntPtr psPfns;                        // CRYPT_PROVIDER_FUNCTIONS*
	internal uint cdwTrustStepErrors;              // DWORD
	internal IntPtr padwTrustStepErrors;           // DWORD*
	internal uint chStores;                        // DWORD
	internal IntPtr pahStores;                     // HCERTSTORE*
	internal uint dwEncoding;                      // DWORD
	internal IntPtr hMsg;                          // HCRYPTMSG
	internal uint csSigners;                       // DWORD
	internal IntPtr pasSigners;                    // CRYPT_PROVIDER_SGNR*
	internal uint csProvPrivData;                  // DWORD
	internal IntPtr pasProvPrivData;               // CRYPT_PROVIDER_PRIVDATA*
	internal uint dwSubjectChoice;                 // DWORD
	internal IntPtr pPDSip;                        // _PROVDATA_SIP*
	internal IntPtr pszUsageOID;                   // char*
	internal int fRecallWithState;                 // BOOL
	internal System.Runtime.InteropServices.ComTypes.FILETIME sftSystemTime; // FILETIME
	internal IntPtr pszCTLSignerUsageOID;          // char*
	internal uint dwProvFlags;                     // DWORD
	internal uint dwFinalError;                    // DWORD
	internal IntPtr pRequestUsage;                 // PCERT_USAGE_MATCH
	internal uint dwTrustPubSettings;              // DWORD
	internal uint dwUIStateFlags;                  // DWORD
	internal IntPtr pSigState;                     // CRYPT_PROVIDER_SIGSTATE*
	internal IntPtr pSigSettings;                  // WINTRUST_SIGNATURE_SETTINGS*
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_signature_settings
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WINTRUST_SIGNATURE_SETTINGS
{
	internal uint cbStruct;   // Size of structure
	internal uint dwIndex;   // Index of the signature
	internal uint dwFlags;   // Flags for signature verification
	internal uint SecondarySignersCount;   // Number of secondary signatures
	internal uint dwVerifiedSigIndex;   // Index of verified signature
	internal IntPtr pCryptoPolicy;   // Pointer to cryptographic policy

	// Default constructor initializes dwIndex to unsigned integer 0
	public WINTRUST_SIGNATURE_SETTINGS()
	{
		cbStruct = (uint)sizeof(WINTRUST_SIGNATURE_SETTINGS);
		dwIndex = 0U;
		dwFlags = 3;
		SecondarySignersCount = 0;
		dwVerifiedSigIndex = 0;
		pCryptoPolicy = IntPtr.Zero;
	}

	// Constructor initializes with given index
	internal WINTRUST_SIGNATURE_SETTINGS(uint index)
	{
		cbStruct = (uint)sizeof(WINTRUST_SIGNATURE_SETTINGS);
		dwIndex = index;
		dwFlags = 3;
		SecondarySignersCount = 0;
		dwVerifiedSigIndex = 0;
		pCryptoPolicy = IntPtr.Zero;
	}
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WINTRUST_FILE_INFO
{
	internal uint StructSize;   // Size of structure
	internal IntPtr FilePath;   // File path pointer (LPCWSTR)
	internal IntPtr hFile;   // File handle pointer
	internal IntPtr pgKnownSubject;   // Pointer to known subject

	// Default constructor initializes FilePath to null
	public WINTRUST_FILE_INFO()
	{
		StructSize = (uint)sizeof(WINTRUST_FILE_INFO);
		FilePath = IntPtr.Zero;
		hFile = IntPtr.Zero;
		pgKnownSubject = IntPtr.Zero;
	}

	// Constructor initializes FilePath with the given filePath
	internal WINTRUST_FILE_INFO(IntPtr filePathPtr)
	{
		StructSize = (uint)sizeof(WINTRUST_FILE_INFO);
		FilePath = filePathPtr;
		hFile = IntPtr.Zero;
		pgKnownSubject = IntPtr.Zero;
	}
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WINTRUST_DATA
{
	internal uint StructSize;   // Size of structure
	internal IntPtr PolicyCallbackData;   // Pointer to policy callback data
	internal IntPtr SIPClientData;   // Pointer to SIP client data
	internal uint UIChoice;   // UI choice for trust verification
	internal uint RevocationChecks;   // Revocation checks
	internal uint UnionChoice;   // Union choice for trust verification
	internal IntPtr FileInfoPtr;   // Pointer to file information
	internal uint StateAction;   // State action for trust verification
	internal IntPtr StateData;   // Pointer to state data
	internal IntPtr URLReference;   // URL reference for trust verification
	internal uint ProvFlags;   // Provider flags for trust verification
	internal uint UIContext;   // UI context for trust verification
	internal IntPtr pSignatureSettings;   // Pointer to signature settings

	internal WINTRUST_DATA(IntPtr fileInfoPtr, IntPtr signatureSettingsPtr)
	{
		StructSize = (uint)sizeof(WINTRUST_DATA);
		PolicyCallbackData = IntPtr.Zero;
		SIPClientData = IntPtr.Zero;
		UIChoice = 2;
		RevocationChecks = 0;
		UnionChoice = 1;
		FileInfoPtr = fileInfoPtr;
		StateAction = 1;
		StateData = IntPtr.Zero;
		URLReference = IntPtr.Zero;
		ProvFlags = 4112;
		UIContext = 0;
		pSignatureSettings = signatureSettingsPtr;
	}
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/slpublic/ns-slpublic-sl_licensing_status
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SL_LICENSING_STATUS
{
	internal Guid SkuId;
	internal uint eStatus;
	internal uint dwGraceTime;
	internal uint dwTotalGraceTime;
	internal int hrReason;
	internal long qwValidityExpiration;
}

[StructLayout(LayoutKind.Sequential)]
internal struct SubscriptionStatus
{
	internal uint dwEnabled;
	internal uint dwSku;
	internal uint dwState;
}

[GeneratedComInterface]
[Guid("F2DCB80D-0670-44BC-9002-CD18688730AF")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal partial interface IEditionUpgradeManager
{
	void PlaceholderMethod1();
	void PlaceholderMethod2();
	void PlaceholderMethod3();
	void PlaceholderMethod4();

	[PreserveSig]
	int GetWindowsLicense(int uUnk, out int pdwResult);
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RawIUnknown
{
	internal IUnknownVtbl* Vtbl;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/unknwn/nn-unknwn-iunknown
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct IUnknownVtbl
{
	internal delegate* unmanaged[Stdcall]<void*, Guid*, void**, int> QueryInterface;
	internal delegate* unmanaged[Stdcall]<void*, uint> AddRef;
	internal delegate* unmanaged[Stdcall]<void*, uint> Release;
}


[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RawIAppxFactory
{
	internal IAppxFactoryVtbl* Vtbl;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/appxpackaging/nn-appxpackaging-iappxfactory
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct IAppxFactoryVtbl
{
	internal delegate* unmanaged[Stdcall]<void*, Guid*, void**, int> QueryInterface;
	internal delegate* unmanaged[Stdcall]<void*, uint> AddRef;
	internal delegate* unmanaged[Stdcall]<void*, uint> Release;

	internal delegate* unmanaged[Stdcall]<void*, IntPtr, IntPtr, IntPtr*, int> CreatePackageWriter;
	internal delegate* unmanaged[Stdcall]<void*, IntPtr, IntPtr*, int> CreatePackageReader; // Index 4
	internal delegate* unmanaged[Stdcall]<void*, IntPtr, IntPtr*, int> CreateManifestReader;
	internal delegate* unmanaged[Stdcall]<void*, IntPtr, IntPtr*, int> CreateBlockMapReader;
	internal delegate* unmanaged[Stdcall]<void*, IntPtr, ushort*, IntPtr*, int> CreateValidatedBlockMapReader;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RawIAppxPackageReader
{
	internal IAppxPackageReaderVtbl* Vtbl;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/appxpackaging/nn-appxpackaging-iappxpackagereader
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct IAppxPackageReaderVtbl
{
	internal delegate* unmanaged[Stdcall]<void*, Guid*, void**, int> QueryInterface;
	internal delegate* unmanaged[Stdcall]<void*, uint> AddRef;
	internal delegate* unmanaged[Stdcall]<void*, uint> Release;

	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetBlockMap; // Index 3
	internal delegate* unmanaged[Stdcall]<void*, int, IntPtr*, int> GetFootprintFile;
	internal delegate* unmanaged[Stdcall]<void*, ushort*, IntPtr*, int> GetPayloadFile;
	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetPayloadFiles;
	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetManifest; // Index 7
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RawIAppxManifestReader
{
	internal IAppxManifestReaderVtbl* Vtbl;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/appxpackaging/nn-appxpackaging-iappxmanifestreader
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct IAppxManifestReaderVtbl
{
	internal delegate* unmanaged[Stdcall]<void*, Guid*, void**, int> QueryInterface;
	internal delegate* unmanaged[Stdcall]<void*, uint> AddRef;
	internal delegate* unmanaged[Stdcall]<void*, uint> Release;

	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetPackageId; // Index 3
	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetProperties;
	// Methods after GetProperties are omitted as they are not used.
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RawIAppxManifestPackageId
{
	internal IAppxManifestPackageIdVtbl* Vtbl;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/appxpackaging/nn-appxpackaging-iappxmanifestpackageid
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct IAppxManifestPackageIdVtbl
{
	internal delegate* unmanaged[Stdcall]<void*, Guid*, void**, int> QueryInterface;
	internal delegate* unmanaged[Stdcall]<void*, uint> AddRef;
	internal delegate* unmanaged[Stdcall]<void*, uint> Release;

	internal delegate* unmanaged[Stdcall]<void*, ushort**, int> GetName;
	internal delegate* unmanaged[Stdcall]<void*, int*, int> GetArchitecture;
	internal delegate* unmanaged[Stdcall]<void*, ushort**, int> GetPublisher; // Index 5
	internal delegate* unmanaged[Stdcall]<void*, ulong*, int> GetVersion; // Index 6
	internal delegate* unmanaged[Stdcall]<void*, ushort**, int> GetResourceId;
	internal delegate* unmanaged[Stdcall]<void*, ushort*, int*, int> ComparePublisher;
	internal delegate* unmanaged[Stdcall]<void*, ushort**, int> GetPackageFullName;
	internal delegate* unmanaged[Stdcall]<void*, ushort**, int> GetPackageFamilyName; // Index 10
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RawIAppxBlockMapReader
{
	internal IAppxBlockMapReaderVtbl* Vtbl;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/appxpackaging/nn-appxpackaging-iappxblockmapreader
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct IAppxBlockMapReaderVtbl
{
	internal delegate* unmanaged[Stdcall]<void*, Guid*, void**, int> QueryInterface;
	internal delegate* unmanaged[Stdcall]<void*, uint> AddRef;
	internal delegate* unmanaged[Stdcall]<void*, uint> Release;

	internal delegate* unmanaged[Stdcall]<void*, ushort*, IntPtr*, int> GetFile; // Index 3
	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetFiles;
	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetHashMethod; // Index 5
	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetStream;
}

// IUri (Windows/Urlmon)
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RawIUri
{
	internal IUriVtbl* Vtbl;
}

/// <summary>
/// https://learn.microsoft.com/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775038(v=vs.85)
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct IUriVtbl
{
	internal delegate* unmanaged[Stdcall]<void*, Guid*, void**, int> QueryInterface;
	internal delegate* unmanaged[Stdcall]<void*, uint> AddRef;
	internal delegate* unmanaged[Stdcall]<void*, uint> Release;

	internal delegate* unmanaged[Stdcall]<void*, int, ushort**, uint, int> GetPropertyBSTR;
	internal delegate* unmanaged[Stdcall]<void*, int, uint*, uint, int> GetPropertyLength;
	internal delegate* unmanaged[Stdcall]<void*, int, uint*, uint, int> GetPropertyDWORD;
	internal delegate* unmanaged[Stdcall]<void*, int, int*, uint, int> HasProperty;
	internal delegate* unmanaged[Stdcall]<void*, ushort**, int> GetAbsoluteUri; // Index 7
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RawIAppxBundleFactory
{
	internal IAppxBundleFactoryVtbl* Vtbl;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/appxpackaging/nn-appxpackaging-iappxbundlefactory
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct IAppxBundleFactoryVtbl
{
	internal delegate* unmanaged[Stdcall]<void*, Guid*, void**, int> QueryInterface;
	internal delegate* unmanaged[Stdcall]<void*, uint> AddRef;
	internal delegate* unmanaged[Stdcall]<void*, uint> Release;

	internal delegate* unmanaged[Stdcall]<void*, IntPtr, ulong, IntPtr*, int> CreateBundleWriter;
	internal delegate* unmanaged[Stdcall]<void*, IntPtr, IntPtr*, int> CreateBundleReader; // Index 4
	internal delegate* unmanaged[Stdcall]<void*, IntPtr, IntPtr*, int> CreateBundleManifestReader;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RawIAppxBundleReader
{
	internal IAppxBundleReaderVtbl* Vtbl;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/appxpackaging/nn-appxpackaging-iappxbundlereader
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct IAppxBundleReaderVtbl
{
	internal delegate* unmanaged[Stdcall]<void*, Guid*, void**, int> QueryInterface;
	internal delegate* unmanaged[Stdcall]<void*, uint> AddRef;
	internal delegate* unmanaged[Stdcall]<void*, uint> Release;

	internal delegate* unmanaged[Stdcall]<void*, int, IntPtr*, int> GetFootprintFile;
	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetBlockMap; // Index 4
	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetManifest; // Index 5
	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetPayloadPackages;
	internal delegate* unmanaged[Stdcall]<void*, ushort*, IntPtr*, int> GetPayloadPackage;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RawIAppxBundleManifestReader
{
	internal IAppxBundleManifestReaderVtbl* Vtbl;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/appxpackaging/nn-appxpackaging-iappxbundlemanifestreader
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct IAppxBundleManifestReaderVtbl
{
	internal delegate* unmanaged[Stdcall]<void*, Guid*, void**, int> QueryInterface;
	internal delegate* unmanaged[Stdcall]<void*, uint> AddRef;
	internal delegate* unmanaged[Stdcall]<void*, uint> Release;

	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetPackageId; // Index 3
	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetPackageInfoItems;
	internal delegate* unmanaged[Stdcall]<void*, IntPtr*, int> GetStream;
}

/// <summary>
/// 2.2.1 FW_STORE_TYPE.
/// MS-FASP PDF.
/// </summary>
internal enum FW_STORE_TYPE
{
	INVALID = 0,
	GP_RSOP = 1,
	LOCAL = 2, // Persistent Store.
	NOT_USED_VALUE_3 = 3,
	NOT_USED_VALUE_4 = 4,
	DYNAMIC = 5,
	GPO = 6, // Group Policies Store.
	DEFAULTS = 7
}

/// <summary>
/// 2.2.3 FW_POLICY_ACCESS_RIGHT.
/// MS-FASP PDF.
/// </summary>
internal enum FW_POLICY_ACCESS_RIGHT
{
	INVALID = 0,
	READ = 1,
	READ_WRITE = 2
}

/// <summary>
/// typedef enum _tag_FW_POLICY_STORE_FLAGS
/// MS-FASP PDF.
/// </summary>
internal enum FW_POLICY_STORE_FLAGS : uint
{
	NONE = 0x0000,
	DELETE_DYNAMIC_RULES_AFTER_CLOSE = 0x0001,
	OPEN_GP_CACHE = 0x0002,
	USE_GP_CACHE = 0x0004,
	SAVE_GP_CACHE = 0x0008,
	NOT_USED_VALUE_16 = 0x0010,
	MAX = 0x0020
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-enum_service_status_processa
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal unsafe struct ENUM_SERVICE_STATUS_PROCESS
{
	internal char* lpServiceName;
	internal char* lpDisplayName;
	internal SERVICE_STATUS_PROCESS ServiceStatusProcess;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-query_service_configw
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal unsafe struct QUERY_SERVICE_CONFIGW
{
	internal uint dwServiceType;
	internal uint dwStartType;
	internal uint dwErrorControl;
	internal char* lpBinaryPathName;
	internal char* lpLoadOrderGroup;
	internal uint dwTagId;
	internal char* lpDependencies;
	internal char* lpServiceStartName;
	internal char* lpDisplayName;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_descriptionw
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct SERVICE_DESCRIPTIONW { internal char* lpDescription; }

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SERVICE_DELAYED_AUTO_START_INFO { internal int fDelayedAutostart; }

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_sid_info
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SERVICE_SID_INFO { internal uint dwServiceSidType; }

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct SERVICE_REQUIRED_PRIVILEGES_INFOW { internal char* pmszRequiredPrivileges; }

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_launch_protected_info
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SERVICE_LAUNCH_PROTECTED_INFO { internal uint dwLaunchProtected; }

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_preshutdown_info
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SERVICE_PRESHUTDOWN_INFO { internal uint dwPreshutdownTimeout; }

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-sc_action
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SC_ACTION
{
	internal uint Type; // This is an enum.
	internal uint Delay;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal unsafe struct SERVICE_FAILURE_ACTIONSW
{
	internal uint dwResetPeriod;
	internal char* lpRebootMsg;
	internal char* lpCommand;
	internal uint cActions;
	internal SC_ACTION* lpsaActions;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_trigger_info
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct SERVICE_TRIGGER_INFO
{
	internal uint cTriggers;
	internal SERVICE_TRIGGER* pTriggers;
	internal byte* pReserved;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_trigger
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct SERVICE_TRIGGER
{
	internal uint dwTriggerType;
	internal uint dwAction;
	internal Guid* pTriggerSubtype;
	internal uint cDataItems;
	internal IntPtr pDataItems;
}

/// <summary>
/// Defined here: https://learn.microsoft.com/windows/win32/api/winver/nf-winver-verqueryvaluew
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct LANGANDCODEPAGE { internal ushort wLanguage; internal ushort wCodePage; }

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/aclui/ns-aclui-si_object_info
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SI_OBJECT_INFO
{
	internal uint dwFlags;
	internal IntPtr hInstance;  // HINSTANCE
	internal IntPtr pszServerName; // LPWSTR
	internal IntPtr pszObjectName; // LPWSTR
	internal IntPtr pszPageTitle; // LPWSTR
	internal Guid guidObjectType;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/aclui/ns-aclui-si_access
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SI_ACCESS
{
	internal IntPtr pguid; // const GUID*
	internal uint mask;
	internal IntPtr pszName; // LPCWSTR
	internal uint dwFlags;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/aclui/ns-aclui-si_inherit_type
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SI_INHERIT_TYPE
{
	internal IntPtr pguid;
	internal uint dwFlags;
	internal IntPtr pszName;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/accctrl/ns-accctrl-trustee_w
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct TRUSTEE_W
{
	internal IntPtr pMultipleTrustee;
	internal int MultipleTrusteeOperation;
	internal int TrusteeForm;
	internal int TrusteeType;
	internal IntPtr ptstrName;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-object_type_list
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct OBJECT_TYPE_LIST
{
	internal ushort Level;
	internal ushort Sbz;
	internal IntPtr ObjectType;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/aclui/nn-aclui-isecurityinformation
/// </summary>
[GeneratedComInterface]
[Guid("965FC360-16FF-11d0-91CB-00AA00BBB723")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal partial interface ISecurityInformation
{
	[PreserveSig]
	unsafe int GetObjectInformation(SI_OBJECT_INFO* pObjectInfo);

	[PreserveSig]
	unsafe int GetSecurity(uint RequestedInformation, IntPtr* ppSecurityDescriptor, int fDefault);

	[PreserveSig]
	int SetSecurity(uint SecurityInformation, IntPtr pSecurityDescriptor);

	[PreserveSig]
	unsafe int GetAccessRights(Guid* pguidObjectType, uint dwFlags, IntPtr* ppAccess, uint* pcAccesses, uint* piDefaultAccess);

	[PreserveSig]
	unsafe int MapGeneric(Guid* pguidObjectType, byte* pAceFlags, uint* pMask);

	[PreserveSig]
	unsafe int GetInheritTypes(IntPtr* ppInheritTypes, uint* pcInheritTypes);

	[PreserveSig]
	int PropertySheetPageCallback(IntPtr hwnd, uint uMsg, uint uPage);
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/aclui/nn-aclui-isecurityinformation2
/// </summary>
[GeneratedComInterface]
[Guid("c3ccfdb4-6f88-11d2-a3ce-00c04fb1782a")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal partial interface ISecurityInformation2
{
	[PreserveSig]
	int IsDaclCanonical(IntPtr pDacl);

	[PreserveSig]
	int LookupSids(uint cSids, IntPtr rgpSids, out IntPtr ppdo);
}

/// <summary>
/// https://learn.microsoft.com/en-us/windows/win32/api/aclui/nn-aclui-isecurityinformation3
/// </summary>
[GeneratedComInterface]
[Guid("E2CDC9CC-31BD-4f8f-8C8B-B641AF516A1A")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal partial interface ISecurityInformation3
{
	[PreserveSig]
	unsafe int GetFullResourceName(IntPtr* ppszResourceName);

	[PreserveSig]
	int OpenElevatedEditor(IntPtr hWnd, uint uPage);
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/aclui/nn-aclui-ieffectivepermission
/// </summary>
[GeneratedComInterface]
[Guid("3853DC76-9F35-407c-88A1-D19344365FBC")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal partial interface IEffectivePermission
{
	[PreserveSig]
	unsafe int GetEffectivePermission(
		Guid* pguidObjectType, IntPtr pUserSid, IntPtr pszServerName, IntPtr pSD,
		IntPtr* ppObjectTypeList, uint* pcObjectTypeListLength,
		IntPtr* ppGrantedAccessList, uint* pcGrantedAccessListLength);
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/aclui/nn-aclui-isecurityobjecttypeinfo
/// </summary>
[GeneratedComInterface]
[Guid("FC3066EB-79EF-444b-9111-D18A75EBF2FA")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal partial interface ISecurityObjectTypeInfo
{
	[PreserveSig]
	unsafe int GetInheritSource(uint si, IntPtr pACL, IntPtr* ppInheritArray);
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_status
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

#region For WMI and COM usages porting from C++

/// <summary>
/// Raw unmanaged COM VARIANT structure for Native AOT.
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct VARIANT
{
	[FieldOffset(0)] internal ushort vt;
	[FieldOffset(2)] internal ushort wReserved1;
	[FieldOffset(4)] internal ushort wReserved2;
	[FieldOffset(6)] internal ushort wReserved3;
	[FieldOffset(8)] internal IntPtr bstrVal;
	[FieldOffset(8)] internal long llVal;
	[FieldOffset(8)] internal int lVal;
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/wbemcli/nn-wbemcli-iwbemcontext
/// </summary>
[GeneratedComInterface]
[Guid("44aca674-e8fc-11d0-a07c-00c04fb68820")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal partial interface IWbemContext
{
	[PreserveSig] int Clone(out IWbemContext ppNewCopy);
	[PreserveSig] int GetNames(int lFlags, out IntPtr pNames);
	[PreserveSig] int BeginEnumeration(int lFlags);
	[PreserveSig] int Next(int lFlags, out IntPtr pstrName, out VARIANT pValue);
	[PreserveSig] int EndEnumeration();

	[PreserveSig]
	int SetValue(
		[MarshalAs(UnmanagedType.LPWStr)] string strName,
		int lFlags,
		in VARIANT pValue);

	[PreserveSig]
	int GetValue(
		[MarshalAs(UnmanagedType.LPWStr)] string strName,
		int lFlags,
		out VARIANT pValue);

	[PreserveSig] int DeleteValue([MarshalAs(UnmanagedType.LPWStr)] string strName, int lFlags);
	[PreserveSig] int DeleteAll();
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/wbemcli/nn-wbemcli-iwbemlocator
/// </summary>
[GeneratedComInterface]
[Guid("DC12A687-737F-11CF-884D-00AA004B2E24")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal partial interface IWbemLocator
{
	[PreserveSig]
	int ConnectServer(
		[MarshalAs(UnmanagedType.BStr)] string strNetworkResource,
		IntPtr strUser,
		IntPtr strPassword,
		IntPtr strLocale,
		int lSecurityFlags,
		IntPtr strAuthority,
		IntPtr pCtx,
		out IWbemServices ppNamespace);
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/wbemcli/nn-wbemcli-iwbemservices
/// </summary>
[GeneratedComInterface]
[Guid("9556DC99-828C-11CF-A37E-00AA003240C7")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal partial interface IWbemServices
{
	[PreserveSig] int OpenNamespace(IntPtr strNamespace, int lFlags, IntPtr pCtx, out IWbemServices ppWorkingNamespace, IntPtr ppResult);
	[PreserveSig] int CancelAsyncCall(IntPtr pSink);
	[PreserveSig] int QueryObjectSink(int lFlags, out IntPtr ppResponseHandler);
	[PreserveSig] int GetObject([MarshalAs(UnmanagedType.BStr)] string strObjectPath, int lFlags, IntPtr pCtx, out IWbemClassObject ppObject, IntPtr ppCallResult);
	[PreserveSig] int GetObjectAsync(IntPtr strObjectPath, int lFlags, IntPtr pCtx, IntPtr pResponseHandler);
	[PreserveSig] int PutClass(IntPtr pObject, int lFlags, IntPtr pCtx, IntPtr ppCallResult);
	[PreserveSig] int PutClassAsync(IntPtr pObject, int lFlags, IntPtr pCtx, IntPtr pResponseHandler);
	[PreserveSig] int DeleteClass(IntPtr strClass, int lFlags, IntPtr pCtx, IntPtr ppCallResult);
	[PreserveSig] int DeleteClassAsync(IntPtr strClass, int lFlags, IntPtr pCtx, IntPtr pResponseHandler);
	[PreserveSig] int CreateClassEnum(IntPtr strSuperclass, int lFlags, IntPtr pCtx, out IEnumWbemClassObject ppEnum);
	[PreserveSig] int CreateClassEnumAsync(IntPtr strSuperclass, int lFlags, IntPtr pCtx, IntPtr pResponseHandler);
	[PreserveSig] int PutInstance(IntPtr pInst, int lFlags, IntPtr pCtx, IntPtr ppCallResult);
	[PreserveSig] int PutInstanceAsync(IntPtr pInst, int lFlags, IntPtr pCtx, IntPtr pResponseHandler);
	[PreserveSig] int DeleteInstance(IntPtr strObjectPath, int lFlags, IntPtr pCtx, IntPtr ppCallResult);
	[PreserveSig] int DeleteInstanceAsync(IntPtr strObjectPath, int lFlags, IntPtr pCtx, IntPtr pResponseHandler);
	[PreserveSig] int CreateInstanceEnum(IntPtr strFilter, int lFlags, IntPtr pCtx, out IEnumWbemClassObject ppEnum);
	[PreserveSig] int CreateInstanceEnumAsync(IntPtr strFilter, int lFlags, IntPtr pCtx, IntPtr pResponseHandler);

	[PreserveSig]
	int ExecQuery(
		[MarshalAs(UnmanagedType.BStr)] string strQueryLanguage,
		[MarshalAs(UnmanagedType.BStr)] string strQuery,
		int lFlags,
		IWbemContext? pCtx,
		out IEnumWbemClassObject ppEnum);

	[PreserveSig] int ExecQueryAsync(IntPtr strQueryLanguage, IntPtr strQuery, int lFlags, IntPtr pCtx, IntPtr pResponseHandler);
	[PreserveSig] int ExecNotificationQuery(IntPtr strQueryLanguage, IntPtr strQuery, int lFlags, IntPtr pCtx, out IEnumWbemClassObject ppEnum);
	[PreserveSig] int ExecNotificationQueryAsync(IntPtr strQueryLanguage, IntPtr strQuery, int lFlags, IntPtr pCtx, IntPtr pResponseHandler);
	[PreserveSig] int ExecMethod(IntPtr strObjectPath, IntPtr strMethodName, int lFlags, IntPtr pCtx, IntPtr pInParams, out IntPtr ppOutParams, IntPtr ppCallResult);
	[PreserveSig] int ExecMethodAsync(IntPtr strObjectPath, IntPtr strMethodName, int lFlags, IntPtr pCtx, IntPtr pInParams, IntPtr pResponseHandler);
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/wbemcli/nn-wbemcli-ienumwbemclassobject
/// </summary>
[GeneratedComInterface]
[Guid("027947E1-D731-11CE-A357-000000000001")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal partial interface IEnumWbemClassObject
{
	[PreserveSig] int Reset();

	[PreserveSig]
	int Next(
		int lTimeout,
		uint uCount,
		out IWbemClassObject? apObject,
		out uint puReturned);

	[PreserveSig] int NextAsync(uint uCount, IntPtr pSink);
	[PreserveSig] int Clone(out IEnumWbemClassObject ppEnum);
	[PreserveSig] int Skip(int lTimeout, uint nCount);
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/wbemcli/nn-wbemcli-iwbemclassobject
/// </summary>
[GeneratedComInterface]
[Guid("DC12A681-737F-11CF-884D-00AA004B2E24")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal partial interface IWbemClassObject
{
	[PreserveSig] int GetQualifierSet(out IntPtr ppQualSet);

	[PreserveSig]
	int Get(
		[MarshalAs(UnmanagedType.LPWStr)] string wszName,
		int lFlags,
		out VARIANT pVal,
		IntPtr pType,
		IntPtr plFlavor);

	[PreserveSig] int Put(IntPtr wszName, int lFlags, IntPtr pVal, int Type);
	[PreserveSig] int Delete(IntPtr wszName);
	[PreserveSig] int GetNames(IntPtr wszQualifierName, int lFlags, IntPtr pQualifierVal, out IntPtr pNames);
	[PreserveSig] int BeginEnumeration(int lEnumFlags);
	[PreserveSig] int Next(int lFlags, out IntPtr strName, out VARIANT pVal, IntPtr pType, IntPtr plFlavor);
	[PreserveSig] int EndEnumeration();
	[PreserveSig] int GetPropertyQualifierSet(IntPtr wszProperty, out IntPtr ppQualSet);
	[PreserveSig] int Clone(out IWbemClassObject ppCopy);
	[PreserveSig] int GetObjectText(int lFlags, out IntPtr pstrObjectText);
	[PreserveSig] int SpawnDerivedClass(int lFlags, out IWbemClassObject ppNewClass);
	[PreserveSig] int SpawnInstance(int lFlags, out IWbemClassObject ppNewInstance);
	[PreserveSig] int CompareTo(int lFlags, IWbemClassObject pCompareTo);
	[PreserveSig] int GetPropertyOrigin(IntPtr wszName, out IntPtr pstrClassName);
	[PreserveSig] int InheritsFrom(IntPtr strAncestor);
	[PreserveSig] int GetMethod(IntPtr wszName, int lFlags, out IWbemClassObject ppInSignature, out IWbemClassObject ppOutSignature);
	[PreserveSig] int PutMethod(IntPtr wszName, int lFlags, IWbemClassObject pInSignature, IWbemClassObject pOutSignature);
	[PreserveSig] int DeleteMethod(IntPtr wszName);
	[PreserveSig] int BeginMethodEnumeration(int lEnumFlags);
	[PreserveSig] int NextMethod(int lFlags, out IntPtr pstrName, out IWbemClassObject ppInSignature, out IWbemClassObject ppOutSignature);
	[PreserveSig] int EndMethodEnumeration();
	[PreserveSig] int GetMethodQualifierSet(IntPtr wszMethod, out IntPtr ppQualSet);
	[PreserveSig] int GetMethodOrigin(IntPtr wszMethodName, out IntPtr pstrClassName);
}

#endregion
