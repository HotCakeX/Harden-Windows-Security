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
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace HardenSystemSecurity.SecurityPolicy;

internal static class SecurityPolicyReader
{
	/// <summary>
	/// https://learn.microsoft.com/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
	/// </summary>
	internal const uint NERR_Success = 0;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/iads/ne-iads-ads_user_flag_enum
	/// </summary>
	internal const uint UF_ACCOUNTDISABLE = 0x00000002;

	/// <summary>
	/// https://learn.microsoft.com/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
	/// </summary>
	internal const uint STATUS_SUCCESS = 0x00000000;

	/// <summary>
	/// The following are defined in this PDF, they are part of the PasswordProperties (aka PwdProperties),
	/// Which is an unsigned long numeric, is home to several bool policies, bit by bit.
	/// https://learn.microsoft.com/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380
	/// </summary>
	internal const uint DOMAIN_PASSWORD_COMPLEX = 0x00000001;
	internal const uint DOMAIN_PASSWORD_NO_ANON_CHANGE = 0x00000002;
	internal const uint DOMAIN_LOCKOUT_ADMINS = 0x00000008;
	internal const uint DOMAIN_PASSWORD_STORE_CLEARTEXT = 0x00000010;

	/// <summary>
	/// https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask
	/// https://learn.microsoft.com/en-us/windows/win32/secauthz/requesting-access-rights-to-an-object
	/// </summary>
	internal const int MAXIMUM_ALLOWED = 0x02000000;

	/// <summary>
	/// https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/security-information#dacl_security_information
	/// </summary>
	internal const uint DACL_SECURITY_INFORMATION = 0x00000004;

	/// <summary>
	/// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Authentication/Identity/constant.POLICY_LOOKUP_NAMES.html
	/// </summary>
	internal const int POLICY_LOOKUP_NAMES = 0x00000800;

	/// <summary>
	/// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type
	/// </summary>
	internal const int WinAnonymousSid = 13;

	/// <summary>
	/// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl_revision_information
	/// </summary>
	private const byte ACL_REVISION = 2; // Standard ACL revision for new ACLs

	/// <summary>
	/// Source in the PDF => https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc
	/// typedef enum _POLICY_INFORMATION_CLASS { ... }
	/// </summary>
	internal const int PolicyAccountDomainInformation = 5;

	/// <summary>
	/// Source in the PDF => https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380
	/// 2.2.6.28 USER_INFORMATION_CLASS 
	/// typedef  enum _USER_INFORMATION_CLASS 
	/// </summary>
	internal const int UserControlInformation = 16;

	/// <summary>
	/// Source in the PDF => https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380
	/// 2.2.1.3 Server ACCESS_MASK Values
	/// </summary>
	internal const uint SAM_SERVER_LOOKUP_DOMAIN = 0x00000020;

	/// <summary>
	/// Source in the PDF => https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380
	/// 2.2.1.4 Domain ACCESS_MASK Values
	/// </summary>
	internal const uint DOMAIN_LOOKUP = 0x00000200;

	/// <summary>
	/// Source in the PDF => https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380
	/// Built-in Administrator RID
	/// 2.2.1.14 Predefined RIDs
	/// </summary>
	internal const uint DOMAIN_USER_RID_ADMIN = 500;

	/// <summary>
	/// Source in the PDF => https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380
	/// Built-in Guest RID
	/// 2.2.1.14 Predefined RIDs
	/// </summary>
	internal const uint DOMAIN_USER_RID_GUEST = 501;

	/// <summary>
	/// Source in the PDF => https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380
	/// 2.2.1.12 USER_ACCOUNT Codes
	/// </summary>
	internal const uint USER_ACCOUNT_DISABLED = 0x00000001;

	/// <summary>
	/// Gets the Audit info for the [Event Audit] section.
	/// </summary>
	/// <returns></returns>
	private unsafe static EventAuditInfo GetEventAudit()
	{
		EventAuditInfo eventAudit = new();

		Dictionary<string, string> auditMapping = new(StringComparer.OrdinalIgnoreCase)
		{
			{ "0cce923f-69ae-11d9-bed3-505054503030", "AuditSystemEvents" },
			{ "0cce9240-69ae-11d9-bed3-505054503030", "AuditLogonEvents" },
			{ "0cce9241-69ae-11d9-bed3-505054503030", "AuditObjectAccess" },
			{ "0cce9242-69ae-11d9-bed3-505054503030", "AuditPrivilegeUse" },
			{ "0cce9243-69ae-11d9-bed3-505054503030", "AuditPolicyChange" },
			{ "0cce9244-69ae-11d9-bed3-505054503030", "AuditAccountManage" },
			{ "0cce9245-69ae-11d9-bed3-505054503030", "AuditProcessTracking" },
			{ "0cce9246-69ae-11d9-bed3-505054503030", "AuditDSAccess" },
			{ "0cce9247-69ae-11d9-bed3-505054503030", "AuditAccountLogon" }
		};

		if (!NativeMethods.AuditEnumerateCategories(out nint categoriesPtr, out uint categoriesCount))
		{
			return eventAudit;
		}

		try
		{
			int guidSize = sizeof(Guid);
			List<Guid> subCatGuids = [];

			for (uint i = 0; i < categoriesCount; i++)
			{
				Guid catGuid = *(Guid*)IntPtr.Add(categoriesPtr, (int)i * guidSize);
				if (!NativeMethods.AuditEnumerateSubCategories(IntPtr.Add(categoriesPtr, (int)i * guidSize), true, out nint subCatPtr, out uint subCatCount))
				{
					continue;
				}

				try
				{
					for (uint j = 0; j < subCatCount; j++)
					{
						Guid subGuid = *(Guid*)IntPtr.Add(subCatPtr, (int)j * guidSize);
						subCatGuids.Add(subGuid);
					}
				}
				finally
				{
					NativeMethods.AuditFree(subCatPtr);
				}
			}

			if (subCatGuids.Count == 0)
			{
				return eventAudit;
			}

			IntPtr allGuidsPtr = Marshal.AllocHGlobal(subCatGuids.Count * guidSize);
			try
			{
				for (int i = 0; i < subCatGuids.Count; i++)
				{
					*(Guid*)IntPtr.Add(allGuidsPtr, i * guidSize) = subCatGuids[i];
				}

				if (!NativeMethods.AuditQuerySystemPolicy(allGuidsPtr, (uint)subCatGuids.Count, out nint auditPolicyPtr) || auditPolicyPtr == IntPtr.Zero)
				{
					return eventAudit;
				}

				try
				{
					Dictionary<string, uint> found = new(StringComparer.Ordinal);
					for (int i = 0; i < subCatGuids.Count; i++)
					{
						AUDIT_POLICY_INFORMATION info = *(AUDIT_POLICY_INFORMATION*)IntPtr.Add(auditPolicyPtr, i * sizeof(AUDIT_POLICY_INFORMATION));
						string key = info.AuditSubCategoryGuid.ToString();
						if (auditMapping.TryGetValue(key.ToLowerInvariant(), out string? name))
						{
							found[name] = info.AuditingInformation;
						}
					}

					eventAudit.AuditSystemEvents = found.TryGetValue("AuditSystemEvents", out uint value) ? value : 0;
					eventAudit.AuditLogonEvents = found.TryGetValue("AuditLogonEvents", out uint value1) ? value1 : 0;
					eventAudit.AuditObjectAccess = found.TryGetValue("AuditObjectAccess", out uint value2) ? value2 : 0;
					eventAudit.AuditPrivilegeUse = found.TryGetValue("AuditPrivilegeUse", out uint value3) ? value3 : 0;
					eventAudit.AuditPolicyChange = found.TryGetValue("AuditPolicyChange", out uint value4) ? value4 : 0;
					eventAudit.AuditAccountManage = found.TryGetValue("AuditAccountManage", out uint value5) ? value5 : 0;
					eventAudit.AuditProcessTracking = found.TryGetValue("AuditProcessTracking", out uint value7) ? value7 : 0;
					eventAudit.AuditDSAccess = found.TryGetValue("AuditDSAccess", out uint value6) ? value6 : 0;
					eventAudit.AuditAccountLogon = found.TryGetValue("AuditAccountLogon", out uint value8) ? value8 : 0;
				}
				finally
				{
					NativeMethods.AuditFree(auditPolicyPtr);
				}
			}
			finally
			{
				Marshal.FreeHGlobal(allGuidsPtr);
			}
		}
		finally
		{
			NativeMethods.AuditFree(categoriesPtr);
		}

		return eventAudit;
	}

	/// <summary>
	/// All of the items in the [Privilege Rights] section of the secedit export.
	/// They must be update as needed if/when OS updates add/remove any of them.
	/// </summary>
	private static readonly string[] privilegeNames =
	[
		"SeNetworkLogonRight",
		"SeDenyNetworkLogonRight",
		"SeRemoteInteractiveLogonRight",
		"SeDenyRemoteInteractiveLogonRight",
		"SeInteractiveLogonRight",
		"SeDenyInteractiveLogonRight",
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeTakeOwnershipPrivilege",
		"SeSecurityPrivilege",
		"SeSystemEnvironmentPrivilege",
		"SeCreatePagefilePrivilege",
		"SeCreatePermanentPrivilege",
		"SeCreateTokenPrivilege",
		"SeCreateGlobalPrivilege",
		"SeCreateSymbolicLinkPrivilege",
		"SeChangeNotifyPrivilege",
		"SeSystemtimePrivilege",
		"SeDebugPrivilege",
		"SeImpersonatePrivilege",
		"SeLoadDriverPrivilege",
		"SeLockMemoryPrivilege",
		"SeManageVolumePrivilege",
		"SeRemoteShutdownPrivilege",
		"SeProfileSingleProcessPrivilege",
		"SeSystemProfilePrivilege",
		"SeAssignPrimaryTokenPrivilege",
		"SeShutdownPrivilege",
		"SeUndockPrivilege",
		"SeIncreaseQuotaPrivilege",
		"SeIncreaseBasePriorityPrivilege",
		"SeIncreaseWorkingSetPrivilege",
		"SeTimeZonePrivilege",
		"SeAuditPrivilege",
		"SeTrustedCredManAccessPrivilege",
		"SeTcbPrivilege",
		"SeEnableDelegationPrivilege",
		"SeDelegateSessionUserImpersonatePrivilege"
	];

	/// <summary>
	/// Gets the information for the [Privilege Rights] section.
	/// </summary>
	/// <returns></returns>
	internal unsafe static Dictionary<string, string[]> GetPrivilegeRights()
	{
		Dictionary<string, string[]> privilegeRights = new(StringComparer.Ordinal);
		LSA_OBJECT_ATTRIBUTES lsaAttr = new()
		{
			Length = sizeof(LSA_OBJECT_ATTRIBUTES),
			RootDirectory = IntPtr.Zero,
			ObjectName = IntPtr.Zero,
			Attributes = 0,
			SecurityDescriptor = IntPtr.Zero,
			SecurityQualityOfService = IntPtr.Zero
		};
		LSA_UNICODE_STRING system = new(null);

		uint openPolicyStatus = NativeMethods.LsaOpenPolicy(ref system, ref lsaAttr, 0x000F0FFF, out nint policyHandle);
		if (openPolicyStatus != STATUS_SUCCESS)
		{
			return privilegeRights;
		}

		try
		{
			foreach (string privilege in privilegeNames)
			{
				LSA_UNICODE_STRING userRight = new(privilege);
				uint status = NativeMethods.LsaEnumerateAccountsWithUserRight(policyHandle, ref userRight, out nint enumBuffer, out int countReturned);
				List<string> sidList = [];

				if (status == STATUS_SUCCESS && enumBuffer != IntPtr.Zero && countReturned > 0)
				{
					try
					{
						for (int i = 0; i < countReturned; i++)
						{
							LSA_ENUMERATION_INFORMATION info = *(LSA_ENUMERATION_INFORMATION*)IntPtr.Add(enumBuffer, i * sizeof(LSA_ENUMERATION_INFORMATION));
							try
							{
								SecurityIdentifier sid = new(info.PSid);
								sidList.Add("*" + sid.Value);
							}
							catch
							{
								sidList.Add(info.PSid.ToString(CultureInfo.InvariantCulture));
							}
						}
					}
					finally
					{
						_ = NativeMethods.LsaFreeMemory(enumBuffer);
					}
				}

				privilegeRights[privilege] = sidList.ToArray();
			}
		}
		finally
		{
			_ = NativeMethods.LsaClose(policyHandle);
		}

		return privilegeRights;
	}

	/// <summary>
	/// Used by the <see cref="GetRegistryValues"/> method.
	/// It needs to stay up to date if new security policies need to be verified such as new entries added to the exported INF file by Secedit.
	/// </summary>
	private static readonly FrozenDictionary<string, (RegistryKey rootKey, string subKey, string valueName, int type)> registryPaths = new Dictionary<string, (RegistryKey rootKey, string subKey, string valueName, int type)>(StringComparer.Ordinal)
	{
		{ @"MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount", (Registry.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount", 1) },
		{ @"MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon", (Registry.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "ForceUnlockLogon", 4) },
		{ @"MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning", (Registry.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "PasswordExpiryWarning", 4) },
		{ @"MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption", (Registry.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "ScRemoveOption", 1) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorEnhancedAdmin", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorEnhancedAdmin", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorUser", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DontDisplayLastUserName", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLockedUserId", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DontDisplayLockedUserId", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayUserName", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DontDisplayUserName", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "EnableInstallerDetection", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "EnableSecureUIAPaths", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "EnableUIADesktopToggle", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "EnableVirtualization", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "FilterAdministratorToken", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "LegalNoticeCaption", 1) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "LegalNoticeText", 7) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "MaxDevicePasswordFailedAttempts", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "ScForceOption", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "ShutdownWithoutLogon", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\TypeOfAdminApprovalMode", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "TypeOfAdminApprovalMode", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "UndockWithoutLogon", 4) },
		{ @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures", (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "ValidateAdminCodeSignatures", 4) },
		{ @"MACHINE\Software\Policies\Microsoft\Cryptography\ForceKeyProtection", (Registry.LocalMachine, @"Software\Policies\Microsoft\Cryptography", "ForceKeyProtection", 4) },
		{ @"MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled", (Registry.LocalMachine, @"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers", "AuthenticodeEnabled", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "AuditBaseObjects", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "CrashOnAuditFail", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "DisableDomainCreds", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "EveryoneIncludesAnonymous", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy", "Enabled", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "ForceGuest", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "FullPrivilegeAuditing", 3) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa\MSV1_0", "allownullsessionfallback", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa\MSV1_0", "NTLMMinClientSec", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa\MSV1_0", "NTLMMinServerSec", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictReceivingNTLMTraffic", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa\MSV1_0", "RestrictReceivingNTLMTraffic", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa\MSV1_0", "RestrictSendingNTLMTraffic", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "NoLMHash", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "RestrictAnonymous", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "RestrictRemoteSAM", 1) },
		{ @"MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "SCENoApplyLegacyAuditPolicy", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers", "AddPrinterDrivers", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine", (Registry.LocalMachine, @"System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths", "Machine", 7) },
		{ @"MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine", (Registry.LocalMachine, @"System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths", "Machine", 7) },
		{ @"MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Session Manager\Kernel", "ObCaseInsensitive", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Session Manager\Memory Management", "ClearPageFileAtShutdown", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Session Manager", "ProtectionMode", 4) },
		{ @"MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional", (Registry.LocalMachine, @"System\CurrentControlSet\Control\Session Manager\SubSystems", "optional", 7) },
		{ @"MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff", (Registry.LocalMachine, @"System\CurrentControlSet\Services\LanManServer\Parameters", "EnableForcedLogOff", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature", (Registry.LocalMachine, @"System\CurrentControlSet\Services\LanManServer\Parameters", "EnableSecuritySignature", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes", (Registry.LocalMachine, @"System\CurrentControlSet\Services\LanManServer\Parameters", "NullSessionPipes", 7) },
		{ @"MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature", (Registry.LocalMachine, @"System\CurrentControlSet\Services\LanManServer\Parameters", "RequireSecuritySignature", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess", (Registry.LocalMachine, @"System\CurrentControlSet\Services\LanManServer\Parameters", "RestrictNullSessAccess", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword", (Registry.LocalMachine, @"System\CurrentControlSet\Services\LanmanWorkstation\Parameters", "EnablePlainTextPassword", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature", (Registry.LocalMachine, @"System\CurrentControlSet\Services\LanmanWorkstation\Parameters", "EnableSecuritySignature", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature", (Registry.LocalMachine, @"System\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientConfidentiality", (Registry.LocalMachine, @"System\CurrentControlSet\Services\LDAP", "LDAPClientConfidentiality", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity", (Registry.LocalMachine, @"System\CurrentControlSet\Services\LDAP", "LDAPClientIntegrity", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange", (Registry.LocalMachine, @"System\CurrentControlSet\Services\Netlogon\Parameters", "DisablePasswordChange", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge", (Registry.LocalMachine, @"System\CurrentControlSet\Services\Netlogon\Parameters", "MaximumPasswordAge", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal", (Registry.LocalMachine, @"System\CurrentControlSet\Services\Netlogon\Parameters", "RequireSignOrSeal", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey", (Registry.LocalMachine, @"System\CurrentControlSet\Services\Netlogon\Parameters", "RequireStrongKey", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel", (Registry.LocalMachine, @"System\CurrentControlSet\Services\Netlogon\Parameters", "SealSecureChannel", 4) },
		{ @"MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel", (Registry.LocalMachine, @"System\CurrentControlSet\Services\Netlogon\Parameters", "SignSecureChannel", 4) }
	}.ToFrozenDictionary(StringComparer.Ordinal);

	/// <summary>
	/// Gets the Registry data for the [Registry Values] section.
	/// </summary>
	/// <returns></returns>
	internal static List<RegistryValue> GetRegistryValues()
	{
		List<RegistryValue> registryValues = [];

		foreach (KeyValuePair<string, (RegistryKey rootKey, string subKey, string valueName, int type)> item in registryPaths)
		{
			try
			{
				using RegistryKey? key = item.Value.rootKey.OpenSubKey(item.Value.subKey);
				if (key is not null)
				{
					object? value = key.GetValue(item.Value.valueName);
					string formattedValue;

					if (value is null)
					{
						formattedValue = item.Value.type == 7 ? "" : "0";
					}
					else
					{
						switch (item.Value.type)
						{
							case 1: // REG_SZ
								formattedValue = $"\"{value}\"";
								break;
							case 3: // REG_BINARY
								if (value is byte[] bytes)
								{
									formattedValue = string.Join(",", bytes);
								}
								else
								{
									formattedValue = value.ToString() ?? "";
								}
								break;
							case 4: // REG_DWORD
								formattedValue = value.ToString() ?? "0";
								break;
							case 7: // REG_MULTI_SZ
								if (value is string[] strings)
								{
									formattedValue = string.Join("\n", strings);
								}
								else
								{
									formattedValue = value.ToString() ?? "";
								}
								break;
							default:
								formattedValue = value.ToString() ?? "";
								break;
						}
					}

					registryValues.Add(new RegistryValue
					(
						name: item.Key,
						type: item.Value.type,
						value: formattedValue
					));
				}
				else
				{
					registryValues.Add(new RegistryValue
					(
						name: item.Key,
						type: item.Value.type,
						value: item.Value.type == 7 ? "" : "0"
					));
				}
			}
			catch
			{
				registryValues.Add(new RegistryValue
					(
						name: item.Key,
						type: item.Value.type,
						value: item.Value.type == 7 ? "" : "0"
					));
			}
		}

		return registryValues;
	}

	/// <summary>
	/// Reads the [System Access] policies.
	/// </summary>
	/// <returns></returns>
	internal unsafe static SystemAccessInfo GetSystemAccess()
	{
		SystemAccessInfo systemAccess = new();

		// Get password policy using NetUserModalsGet level 0
		uint result0 = NativeMethods.NetUserModalsGet(null, 0, out nint buffer0);
		if (result0 == NERR_Success && buffer0 != IntPtr.Zero)
		{
			try
			{
				USER_MODALS_INFO_0 info0 = *(USER_MODALS_INFO_0*)buffer0;
				systemAccess.MinimumPasswordLength = (int)info0.min_passwd_len;

				// max_passwd_age is in seconds, convert to days by dividing by 86400 (24*60*60)
				systemAccess.MaximumPasswordAge = info0.max_passwd_age == uint.MaxValue ? -1 : (int)(info0.max_passwd_age / 86400);

				// min_passwd_age is in seconds, convert to days by dividing by 86400 (24*60*60)
				systemAccess.MinimumPasswordAge = (int)(info0.min_passwd_age / 86400);

				// force_logoff is in seconds, convert to minutes by dividing by 60, but 0 means disabled
				systemAccess.ForceLogoffWhenHourExpire = info0.force_logoff == uint.MaxValue ? 0 : (int)(info0.force_logoff / 60);

				systemAccess.PasswordHistorySize = (int)info0.password_hist_len;
			}
			finally
			{
				_ = NativeMethods.NetApiBufferFree(buffer0);
			}
		}

		// Get lockout policy using NetUserModalsGet level 3
		uint result3 = NativeMethods.NetUserModalsGet(null, 3, out nint buffer3);
		if (result3 == NERR_Success && buffer3 != IntPtr.Zero)
		{
			try
			{
				CommonCore.Interop.USER_MODALS_INFO_3 info3 = *(USER_MODALS_INFO_3*)buffer3;

				// lockout_duration is in seconds, convert to minutes by dividing by 60
				systemAccess.LockoutDuration = info3.lockout_duration == uint.MaxValue ? -1 : (int)(info3.lockout_duration / 60);

				// lockout_observation_window is in seconds, convert to minutes by dividing by 60
				systemAccess.ResetLockoutCount = info3.lockout_observation_window == uint.MaxValue ? -1 : (int)(info3.lockout_observation_window / 60);

				systemAccess.LockoutBadCount = (int)info3.lockout_threshold;
			}
			finally
			{
				_ = NativeMethods.NetApiBufferFree(buffer3);
			}
		}

		// Get password complexity and other domain settings using SAM
		LSA_OBJECT_ATTRIBUTES lsaAttr = new()
		{
			Length = sizeof(LSA_OBJECT_ATTRIBUTES),
			RootDirectory = IntPtr.Zero,
			ObjectName = IntPtr.Zero,
			Attributes = 0,
			SecurityDescriptor = IntPtr.Zero,
			SecurityQualityOfService = IntPtr.Zero
		};

		LSA_UNICODE_STRING system = new(null);

		uint openStatus = NativeMethods.LsaOpenPolicy(ref system, ref lsaAttr, 0x000F0FFF, out nint policyHandle);
		if (openStatus == STATUS_SUCCESS && policyHandle != IntPtr.Zero)
		{
			try
			{
				// Get domain information
				uint queryResult = NativeMethods.LsaQueryInformationPolicy(policyHandle, PolicyAccountDomainInformation, out nint domainBuffer); // PolicyAccountDomainInformation
				if (queryResult == STATUS_SUCCESS && domainBuffer != IntPtr.Zero)
				{
					try
					{
						POLICY_ACCOUNT_DOMAIN_INFO domainInfo = *(POLICY_ACCOUNT_DOMAIN_INFO*)domainBuffer;

						// Connect to SAM with correct access rights for reading domain password policy
						IntPtr serverHandle = IntPtr.Zero;
						LSA_UNICODE_STRING serverName = new(null);
						uint samStatus = NativeMethods.SamConnect(ref serverName, out serverHandle, 0x00000020, IntPtr.Zero); // SAM_SERVER_LOOKUP_DOMAIN

						if (samStatus == STATUS_SUCCESS && serverHandle != IntPtr.Zero)
						{
							try
							{
								IntPtr domainHandle = IntPtr.Zero;
								uint openDomainStatus = NativeMethods.SamOpenDomain(serverHandle, 0x00000201, domainInfo.DomainSid, out domainHandle); // DOMAIN_READ_PASSWORD_PARAMETERS | DOMAIN_READ_OTHER_PARAMETERS

								if (openDomainStatus == STATUS_SUCCESS && domainHandle != IntPtr.Zero)
								{
									try
									{
										// Get password information - DomainPasswordInformation (1)
										uint queryDomainStatus = NativeMethods.SamQueryInformationDomain(domainHandle, 1, out nint passwordBuffer);

										if (queryDomainStatus == STATUS_SUCCESS && passwordBuffer != IntPtr.Zero)
										{
											try
											{
												DOMAIN_PASSWORD_INFORMATION passwordInfo = *(DOMAIN_PASSWORD_INFORMATION*)passwordBuffer;

												// PasswordComplexity: Check DOMAIN_PASSWORD_COMPLEX (0x1) flag in PasswordProperties
												systemAccess.PasswordComplexity = (passwordInfo.PasswordProperties & DOMAIN_PASSWORD_COMPLEX) != 0 ? 1 : 0;
												systemAccess.RequireLogonToChangePassword = (passwordInfo.PasswordProperties & DOMAIN_PASSWORD_NO_ANON_CHANGE) != 0 ? 1 : 0;
												systemAccess.ClearTextPassword = (passwordInfo.PasswordProperties & DOMAIN_PASSWORD_STORE_CLEARTEXT) != 0 ? 1 : 0;

												// AllowAdministratorLockout: DOMAIN_LOCKOUT_ADMINS (0x8)
												// https://learn.microsoft.com/openspecs/windows_protocols/ms-ada3/88b69937-f8cc-408f-a564-6abd1313cd3a
												systemAccess.AllowAdministratorLockout = (passwordInfo.PasswordProperties & DOMAIN_LOCKOUT_ADMINS) != 0 ? 1 : 0;
											}
											finally
											{
												_ = NativeMethods.SamFreeMemory(passwordBuffer);
											}
										}
									}
									finally
									{
										_ = NativeMethods.SamCloseHandle(domainHandle);
									}
								}
							}
							finally
							{
								_ = NativeMethods.SamCloseHandle(serverHandle);
							}
						}
					}
					finally
					{
						_ = NativeMethods.LsaFreeMemory(domainBuffer);
					}
				}
			}
			finally
			{
				_ = NativeMethods.LsaClose(policyHandle);
			}
		}

		// Get account names and status

		// Get Administrator account info using well-known RID 500
		string adminName = GetAccountNameByRid(500);

		if (!string.IsNullOrEmpty(adminName))
		{
			uint adminResult = NativeMethods.NetUserGetInfo(null, adminName, 1, out nint adminBuffer);
			if (adminResult == NERR_Success && adminBuffer != IntPtr.Zero)
			{
				try
				{
					USER_INFO_1 adminInfo = *(USER_INFO_1*)adminBuffer;
					systemAccess.NewAdministratorName = adminName;
					systemAccess.EnableAdminAccount = (adminInfo.usri1_flags & UF_ACCOUNTDISABLE) == 0 ? 1 : 0;
				}
				finally
				{
					_ = NativeMethods.NetApiBufferFree(adminBuffer);
				}
			}
			else
			{
				systemAccess.NewAdministratorName = adminName;
				systemAccess.EnableAdminAccount = 0;
			}
		}
		else
		{
			systemAccess.NewAdministratorName = "Administrator";
			systemAccess.EnableAdminAccount = 0;
		}

		// Get Guest account info using well-known RID
		string guestName = GetAccountNameByRid(DOMAIN_USER_RID_GUEST);

		if (!string.IsNullOrEmpty(guestName))
		{
			uint guestResult = NativeMethods.NetUserGetInfo(null, guestName, 1, out nint guestBuffer);
			if (guestResult == NERR_Success && guestBuffer != IntPtr.Zero)
			{
				try
				{
					USER_INFO_1 guestInfo = *(USER_INFO_1*)guestBuffer;
					systemAccess.NewGuestName = guestName;
					systemAccess.EnableGuestAccount = (guestInfo.usri1_flags & UF_ACCOUNTDISABLE) == 0 ? 1 : 0;
				}
				finally
				{
					_ = NativeMethods.NetApiBufferFree(guestBuffer);
				}
			}
			else
			{
				systemAccess.NewGuestName = guestName;
				systemAccess.EnableGuestAccount = 0;
			}
		}
		else
		{
			systemAccess.NewGuestName = "Guest";
			systemAccess.EnableGuestAccount = 0;
		}

		systemAccess.LSAAnonymousNameLookup = LsaAnonymousNameLookupManager.GetValue();

		return systemAccess;
	}

	/// <summary>
	/// To get account name by RID using SAM APIs
	/// </summary>
	/// <param name="rid"></param>
	/// <returns></returns>
	private static unsafe string GetAccountNameByRid(uint rid)
	{
		try
		{
			LSA_OBJECT_ATTRIBUTES lsaAttr = new()
			{
				Length = sizeof(LSA_OBJECT_ATTRIBUTES),
				RootDirectory = IntPtr.Zero,
				ObjectName = IntPtr.Zero,
				Attributes = 0,
				SecurityDescriptor = IntPtr.Zero,
				SecurityQualityOfService = IntPtr.Zero
			};

			LSA_UNICODE_STRING system = new(null);
			uint openStatus = NativeMethods.LsaOpenPolicy(ref system, ref lsaAttr, 0x000F0FFF, out nint policyHandle);
			if (openStatus != STATUS_SUCCESS)
				return string.Empty;

			try
			{
				// Get domain information
				uint queryResult = NativeMethods.LsaQueryInformationPolicy(policyHandle, PolicyAccountDomainInformation, out nint domainBuffer); // PolicyAccountDomainInformation
				if (queryResult != STATUS_SUCCESS || domainBuffer == IntPtr.Zero)
					return string.Empty;

				try
				{
					POLICY_ACCOUNT_DOMAIN_INFO domainInfo = *(POLICY_ACCOUNT_DOMAIN_INFO*)domainBuffer;

					// Connect to SAM
					LSA_UNICODE_STRING serverName = new(null);
					uint samStatus = NativeMethods.SamConnect(ref serverName, out nint serverHandle, 0x00000020, IntPtr.Zero);
					if (samStatus != STATUS_SUCCESS)
						return string.Empty;

					try
					{
						// Open domain
						uint openDomainStatus = NativeMethods.SamOpenDomain(serverHandle, 0x00000200, domainInfo.DomainSid, out nint domainHandle);
						if (openDomainStatus != STATUS_SUCCESS)
							return string.Empty;

						try
						{
							// Open user by RID
							uint openUserStatus = NativeMethods.SamOpenUser(domainHandle, 0x00000001, rid, out nint userHandle);
							if (openUserStatus != STATUS_SUCCESS)
								return string.Empty;

							try
							{
								// Query user name information
								uint queryUserStatus = NativeMethods.SamQueryInformationUser(userHandle, 1, out nint userBuffer); // UserGeneralInformation
								if (queryUserStatus != STATUS_SUCCESS || userBuffer == IntPtr.Zero)
									return string.Empty;

								try
								{
									SAM_USER_GENERAL_INFORMATION userInfo = *(SAM_USER_GENERAL_INFORMATION*)userBuffer;
									return Marshal.PtrToStringUni(userInfo.UserName.Buffer, userInfo.UserName.Length / 2) ?? string.Empty;
								}
								finally
								{
									_ = NativeMethods.SamFreeMemory(userBuffer);
								}
							}
							finally
							{
								_ = NativeMethods.SamCloseHandle(userHandle);
							}
						}
						finally
						{
							_ = NativeMethods.SamCloseHandle(domainHandle);
						}
					}
					finally
					{
						_ = NativeMethods.SamCloseHandle(serverHandle);
					}
				}
				finally
				{
					_ = NativeMethods.LsaFreeMemory(domainBuffer);
				}
			}
			finally
			{
				_ = NativeMethods.LsaClose(policyHandle);
			}
		}
		catch
		{
			return string.Empty;
		}
	}

	/// <summary>
	/// Reads the Security Policies of the system and returns the main object that contains all of the information for Security Policies.
	/// </summary>
	/// <returns></returns>
	internal static SecurityPolicyInfo GetSecurityPolicyInfo()
	{
		SecurityPolicyInfo policyInfo = new(
			systemAccess: GetSystemAccess(),
			eventAudit: GetEventAudit(),
			privilegeRights: GetPrivilegeRights(),
			registryValues: GetRegistryValues()
		);

		return policyInfo;
	}


	internal static class LsaAnonymousNameLookupManager
	{
		/// <summary>
		/// Opens the LSA Policy handle with MAXIMUM_ALLOWED access.
		/// </summary>
		/// <returns></returns>
		private unsafe static IntPtr OpenPolicy()
		{
			LSA_OBJECT_ATTRIBUTES objectAttributes = new()
			{
				Length = sizeof(LSA_OBJECT_ATTRIBUTES),
				RootDirectory = IntPtr.Zero,
				ObjectName = IntPtr.Zero,
				Attributes = 0,
				SecurityDescriptor = IntPtr.Zero,
				SecurityQualityOfService = IntPtr.Zero
			};

			LSA_UNICODE_STRING systemName = new(null);
			uint status = NativeMethods.LsaOpenPolicy(ref systemName, ref objectAttributes, MAXIMUM_ALLOWED, out IntPtr policyHandle);
			FreeLsaUnicodeString(ref systemName);

			if (status != 0)
			{
				ThrowIfError(status, "LsaOpenPolicy");
			}
			return policyHandle;
		}

		private static void ClosePolicy(IntPtr handle)
		{
			if (handle != IntPtr.Zero)
			{
				_ = NativeMethods.LsaClose(handle);
			}
		}

		/// <summary>
		/// Retrieves current value.
		/// 1 if DACL includes an ACCESS_ALLOWED ACE for the Anonymous SID whose AccessMask is exactly POLICY_LOOKUP_NAMES.
		/// otherwise 0.
		/// </summary>
		/// <returns></returns>
		/// <exception cref="InvalidOperationException"></exception>
		internal static int GetValue()
		{
			IntPtr policyHandle = IntPtr.Zero;
			IntPtr securityDescriptorPtr = IntPtr.Zero;
			try
			{
				policyHandle = OpenPolicy();

				uint queryStatus = NativeMethods.LsaQuerySecurityObject(
					policyHandle,
					DACL_SECURITY_INFORMATION,
					out securityDescriptorPtr
				);

				if (queryStatus != 0 || securityDescriptorPtr == IntPtr.Zero)
				{
					ThrowIfError(queryStatus, "LsaQuerySecurityObject");
				}

				uint sdLen = NativeMethods.GetSecurityDescriptorLength(securityDescriptorPtr);
				if (sdLen == 0)
				{
					throw new InvalidOperationException("GetSecurityDescriptorLength returned 0.");
				}

				byte[] sdBytes = new byte[sdLen];
				Marshal.Copy(securityDescriptorPtr, sdBytes, 0, (int)sdLen);

				RawSecurityDescriptor raw = new(sdBytes, 0);
				RawAcl? dacl = raw.DiscretionaryAcl;

				if (dacl == null)
				{
					return 0;
				}

				SecurityIdentifier anonymousSid = GetAnonymousSidManaged();

				for (int i = 0; i < dacl.Count; i++)
				{
					GenericAce ace = dacl[i];
					CommonAce? commonAce = ace as CommonAce;
					if (commonAce == null)
					{
						continue;
					}

					if (commonAce.AceQualifier == AceQualifier.AccessAllowed)
					{
						SecurityIdentifier sid = commonAce.SecurityIdentifier;
						if (sid.Equals(anonymousSid))
						{
							int mask = commonAce.AccessMask;
							// Strict check, mask must equal exactly POLICY_LOOKUP_NAMES
							if (mask == POLICY_LOOKUP_NAMES)
							{
								return 1;
							}
						}
					}
				}

				return 0;
			}
			finally
			{
				if (securityDescriptorPtr != IntPtr.Zero)
				{
					_ = NativeMethods.LsaFreeMemory(securityDescriptorPtr);
				}
				ClosePolicy(policyHandle);
			}
		}

		/// <summary>
		/// 1 => add an ACCESS_ALLOWED ACE for Anonymous SID with AccessMask exactly POLICY_LOOKUP_NAMES, without modifying any existing ACEs.
		/// 0 => remove only ACEs for Anonymous SID whose AccessMask is exactly POLICY_LOOKUP_NAMES.
		/// </summary>
		/// <param name="value"></param>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="InvalidOperationException"></exception>
		internal static void SetValue(int value)
		{
			if (value != 0 && value != 1)
			{
				throw new ArgumentOutOfRangeException(nameof(value), "Value must be 0 or 1.");
			}

			IntPtr policyHandle = IntPtr.Zero;
			IntPtr securityDescriptorPtr = IntPtr.Zero;
			try
			{
				policyHandle = OpenPolicy();

				uint queryStatus = NativeMethods.LsaQuerySecurityObject(
					policyHandle,
					DACL_SECURITY_INFORMATION,
					out securityDescriptorPtr
				);

				if (queryStatus != 0 || securityDescriptorPtr == IntPtr.Zero)
				{
					ThrowIfError(queryStatus, "LsaQuerySecurityObject");
				}

				uint sdLen = NativeMethods.GetSecurityDescriptorLength(securityDescriptorPtr);
				if (sdLen == 0)
				{
					throw new InvalidOperationException("GetSecurityDescriptorLength returned 0.");
				}

				byte[] sdBytes = new byte[sdLen];
				Marshal.Copy(securityDescriptorPtr, sdBytes, 0, (int)sdLen);

				// Parse existing SD into managed RawSecurityDescriptor
				RawSecurityDescriptor raw = new(sdBytes, 0);
				RawAcl? dacl = raw.DiscretionaryAcl;

				// If no DACL present, create a new RawAcl
				dacl ??= new RawAcl(ACL_REVISION, 1);

				SecurityIdentifier anonymousSid = GetAnonymousSidManaged();
				bool changed = false;

				if (value == 1)
				{
					// Enabling: add an ACE with EXACT mask if none exists. Do not modify existing ACEs.
					bool existsExactAce = false;

					for (int i = 0; i < dacl.Count; i++)
					{
						CommonAce? commonAce = dacl[i] as CommonAce;
						if (commonAce == null || commonAce.AceQualifier != AceQualifier.AccessAllowed)
						{
							continue;
						}

						SecurityIdentifier sid = commonAce.SecurityIdentifier;
						if (!sid.Equals(anonymousSid))
						{
							continue;
						}

						if (commonAce.AccessMask == POLICY_LOOKUP_NAMES)
						{
							existsExactAce = true;
							break;
						}
					}

					if (!existsExactAce)
					{
						CommonAce aceToAdd = new(
							AceFlags.None,
							AceQualifier.AccessAllowed,
							POLICY_LOOKUP_NAMES,
							anonymousSid,
							false,
							null
						);

						// Insert at the beginning to minimize impact. Windows may canonicalize as needed.
						dacl.InsertAce(0, aceToAdd);
						changed = true;
					}
				}
				else
				{
					// value == 0: remove only ACEs whose mask is exactly POLICY_LOOKUP_NAMES for Anonymous SID.
					// Iterate backwards when removing to avoid index reordering issues.
					for (int i = dacl.Count - 1; i >= 0; i--)
					{
						CommonAce? commonAce = dacl[i] as CommonAce;
						if (commonAce == null || commonAce.AceQualifier != AceQualifier.AccessAllowed)
						{
							continue;
						}

						SecurityIdentifier sid = commonAce.SecurityIdentifier;
						if (!sid.Equals(anonymousSid))
						{
							continue;
						}

						if (commonAce.AccessMask == POLICY_LOOKUP_NAMES)
						{
							dacl.RemoveAce(i);
							changed = true;
						}
					}
				}

				if (!changed)
				{
					// Nothing to write back
					return;
				}

				// Assign updated DACL back to descriptor
				raw.DiscretionaryAcl = dacl;

				// Serialize to self-relative SD bytes (LSAR_SR_SECURITY_DESCRIPTOR)
				int newLen = raw.BinaryLength;
				byte[] newSdBytes = new byte[newLen];
				raw.GetBinaryForm(newSdBytes, 0);

				// Pin and set
				IntPtr newSdPtr = Marshal.AllocHGlobal(newLen);
				try
				{
					Marshal.Copy(newSdBytes, 0, newSdPtr, newLen);

					uint setStatus = NativeMethods.LsaSetSecurityObject(
						policyHandle,
						DACL_SECURITY_INFORMATION,
						newSdPtr
					);

					if (setStatus != 0)
					{
						ThrowIfError(setStatus, "LsaSetSecurityObject");
					}
				}
				finally
				{
					Marshal.FreeHGlobal(newSdPtr);
				}
			}
			finally
			{
				if (securityDescriptorPtr != IntPtr.Zero)
				{
					_ = NativeMethods.LsaFreeMemory(securityDescriptorPtr);
				}
				ClosePolicy(policyHandle);
			}
		}

		/// <summary>
		/// Returns managed Anonymous SID.
		/// </summary>
		/// <returns></returns>
		/// <exception cref="InvalidOperationException"></exception>
		private static SecurityIdentifier GetAnonymousSidManaged()
		{
			uint size = 64;
			byte[] sidBytes = new byte[size];
			bool created = NativeMethods.CreateWellKnownSid(WinAnonymousSid, IntPtr.Zero, sidBytes, ref size);
			if (!created)
			{
				int winErr = Marshal.GetLastPInvokeError();
				throw new InvalidOperationException("CreateWellKnownSid failed. Win32Error=" + winErr.ToString(CultureInfo.InvariantCulture));
			}
			byte[] exact = new byte[size];
			Buffer.BlockCopy(sidBytes, 0, exact, 0, (int)size);
			SecurityIdentifier sid = new(exact, 0);
			return sid;
		}

		private static void FreeLsaUnicodeString(ref LSA_UNICODE_STRING lsa)
		{
			if (lsa.Buffer != IntPtr.Zero)
			{
				Marshal.FreeHGlobal(lsa.Buffer);
				lsa.Buffer = IntPtr.Zero;
			}
		}
	}

	private static void ThrowIfError(uint ntStatus, string api)
	{
		uint winError = NativeMethods.LsaNtStatusToWinError(ntStatus);
		if (winError != 0)
		{
			throw new InvalidOperationException(api + " failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture) + " WinError=" + winError.ToString(CultureInfo.InvariantCulture));
		}
	}

	/// <summary>
	/// For "EnableAdminAccount" and "EnableGuestAccount" settings.
	/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0d94df7c-9752-4b08-84de-bf29e389c074
	/// Implements MS-GPSB behavior for enabling/disabling a local account by RID via SAM:
	/// - Query with SamQueryInformationUser(UserControlInformation) to read Control
	/// - Set with SamSetInformationUser(UserControlInformation) using:
	///   value == 1 => Control AND 0xFFFFFFFE (enable)
	///   value == 0 => Control OR USER_ACCOUNT_DISABLED (disable)
	/// The user is opened via SamOpenUser with DesiredAccess=MAXIMUM_ALLOWED and the specified RID.
	/// DomainHandle is obtained via:
	///   LsaOpenPolicy -> LsaQueryInformationPolicy(PolicyAccountDomainInformation) -> DomainSid -> SamConnect -> SamOpenDomain.
	/// </summary>
	/// <param name="rid">User RID to modify: e.g., 500 for built-in Administrator (DOMAIN_USER_RID_ADMIN), 501 for built-in Guest (DOMAIN_USER_RID_GUEST).</param>
	/// <param name="value">1 to enable, 0 to disable.</param>
	internal static unsafe void SetEnableOrDisableAnAccount(uint rid, int value)
	{
		if (value != 0 && value != 1)
		{
			throw new ArgumentOutOfRangeException(nameof(value), "Value must be 0 or 1.");
		}

		IntPtr policyHandle = IntPtr.Zero;
		IntPtr domainInfoBuffer = IntPtr.Zero;
		IntPtr serverHandle = IntPtr.Zero;
		IntPtr domainHandle = IntPtr.Zero;
		IntPtr userHandle = IntPtr.Zero;
		IntPtr queryBuffer = IntPtr.Zero;
		IntPtr setBuffer = IntPtr.Zero;

		try
		{
			// Open LSA Policy with MAXIMUM_ALLOWED to obtain the local machine's domain SID
			LSA_OBJECT_ATTRIBUTES objectAttributes = new()
			{
				Length = sizeof(LSA_OBJECT_ATTRIBUTES),
				RootDirectory = IntPtr.Zero,
				ObjectName = IntPtr.Zero,
				Attributes = 0,
				SecurityDescriptor = IntPtr.Zero,
				SecurityQualityOfService = IntPtr.Zero
			};
			LSA_UNICODE_STRING systemName = new(null);

			uint nt = NativeMethods.LsaOpenPolicy(ref systemName, ref objectAttributes, MAXIMUM_ALLOWED, out policyHandle);
			ThrowIfError(nt, "LsaOpenPolicy");

			// Query PolicyAccountDomainInformation (class 5) to get DomainSid
			nt = NativeMethods.LsaQueryInformationPolicy(policyHandle, PolicyAccountDomainInformation, out domainInfoBuffer);
			ThrowIfError(nt, "LsaQueryInformationPolicy");

			if (domainInfoBuffer == IntPtr.Zero)
			{
				throw new InvalidOperationException("LsaQueryInformationPolicy returned a null buffer.");
			}

			POLICY_ACCOUNT_DOMAIN_INFO* domainInfo = (POLICY_ACCOUNT_DOMAIN_INFO*)domainInfoBuffer;
			IntPtr domainSid = domainInfo->DomainSid;
			if (domainSid == IntPtr.Zero)
			{
				throw new InvalidOperationException("PolicyAccountDomainInformation does not contain a DomainSid.");
			}

			// Connect to SAM with SAM_SERVER_LOOKUP_DOMAIN
			LSA_UNICODE_STRING server = new(null);
			nt = NativeMethods.SamConnect(ref server, out serverHandle, SAM_SERVER_LOOKUP_DOMAIN, IntPtr.Zero);
			ThrowIfError(nt, "SamConnect");

			// Open the domain with DOMAIN_LOOKUP to allow opening users by RID
			nt = NativeMethods.SamOpenDomain(serverHandle, DOMAIN_LOOKUP, domainSid, out domainHandle);
			ThrowIfError(nt, "SamOpenDomain");

			// Open the target user by RID with DesiredAccess = MAXIMUM_ALLOWED
			nt = NativeMethods.SamOpenUser(domainHandle, MAXIMUM_ALLOWED, rid, out userHandle);
			ThrowIfError(nt, "SamOpenUser");

			// Step 1, Query current Control flags
			nt = NativeMethods.SamQueryInformationUser(userHandle, UserControlInformation, out queryBuffer);
			ThrowIfError(nt, "SamQueryInformationUser(UserControlInformation)");

			if (queryBuffer == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamQueryInformationUser returned a null buffer.");
			}

			SAMPR_USER_INFO_BUFFER* userInfo = (SAMPR_USER_INFO_BUFFER*)queryBuffer;
			uint control = userInfo->UserControlInformation.Control;

			// Compute new Control per spec
			// if enabling, clear disabled bit. If disabling, set disabled bit.
			uint newControl = (value == 1) ? (control & 0xFFFFFFFEu) : (control | USER_ACCOUNT_DISABLED);

			// If no change, we can return early (no-op write)
			if (newControl == control)
			{
				return;
			}

			// Step 2, Set new Control via SamSetInformationUser(UserControlInformation)
			// Prepare a minimal SAMPR_USER_INFO_BUFFER containing only the UserControlInformation member.
			int size = sizeof(SAMPR_USER_INFO_BUFFER);
			setBuffer = Marshal.AllocHGlobal(size);

			// Zero the buffer to be safe, then set the Control value
			Span<byte> zeroSpan = new((void*)setBuffer, size);
			zeroSpan.Clear();

			((SAMPR_USER_INFO_BUFFER*)setBuffer)->UserControlInformation.Control = newControl;

			nt = NativeMethods.SamSetInformationUser(userHandle, UserControlInformation, setBuffer);
			ThrowIfError(nt, "SamSetInformationUser(UserControlInformation)");
		}
		finally
		{
			if (setBuffer != IntPtr.Zero)
			{
				Marshal.FreeHGlobal(setBuffer);
			}
			if (queryBuffer != IntPtr.Zero)
			{
				_ = NativeMethods.SamFreeMemory(queryBuffer);
			}
			if (userHandle != IntPtr.Zero)
			{
				_ = NativeMethods.SamCloseHandle(userHandle);
			}
			if (domainHandle != IntPtr.Zero)
			{
				_ = NativeMethods.SamCloseHandle(domainHandle);
			}
			if (serverHandle != IntPtr.Zero)
			{
				_ = NativeMethods.SamCloseHandle(serverHandle);
			}
			if (domainInfoBuffer != IntPtr.Zero)
			{
				_ = NativeMethods.LsaFreeMemory(domainInfoBuffer);
			}
			if (policyHandle != IntPtr.Zero)
			{
				_ = NativeMethods.LsaClose(policyHandle);
			}
		}
	}
}
