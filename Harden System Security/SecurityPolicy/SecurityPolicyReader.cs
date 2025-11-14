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

using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace HardenSystemSecurity.SecurityPolicy;

internal static class SecurityPolicyReader
{
	/// <summary>
	/// https://learn.microsoft.com/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
	/// </summary>
	internal const uint NERR_Success = 0x00000000;

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
	/// Maximum Access.
	/// https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask
	/// https://learn.microsoft.com/en-us/windows/win32/secauthz/requesting-access-rights-to-an-object
	/// https://learn.microsoft.com/en-us/windows/win32/secmgmt/policy-object-access-rights#standard-access-types
	/// </summary>
	internal const int POLICY_ALL_ACCESS = 0x000F0FFF;

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
	/// Per [MS-SAMR] 2.2.6.28 USER_INFORMATION_CLASS
	/// </summary>
	internal const int UserNameInformation = 6;

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
	/// Source in the PDF => https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380
	/// 2.2.1.4 Domain ACCESS_MASK Values
	/// </summary>
	internal const uint DOMAIN_READ_PASSWORD_PARAMETERS = 0x00000001;

	/// <summary>
	/// Source in the PDF => https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380
	/// 2.2.1.4 Domain ACCESS_MASK Values
	/// </summary>
	internal const uint DOMAIN_WRITE_PASSWORD_PARAMS = 0x00000002;

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

		uint openPolicyStatus = NativeMethods.LsaOpenPolicy(ref system, ref lsaAttr, POLICY_ALL_ACCESS, out nint policyHandle);
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
						FreeLSAMemory(enumBuffer);
					}
				}

				privilegeRights[privilege] = sidList.ToArray();

				FreeLsaUnicodeString(ref userRight);
			}
		}
		finally
		{
			ClosePolicy(policyHandle);
		}

		return privilegeRights;
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

		uint openStatus = NativeMethods.LsaOpenPolicy(ref system, ref lsaAttr, POLICY_ALL_ACCESS, out nint policyHandle);
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
												FreeSAMMemory(passwordBuffer);
											}
										}
									}
									finally
									{
										CloseSAMHandle(domainHandle);
									}
								}
							}
							finally
							{
								CloseSAMHandle(serverHandle);
							}
						}
					}
					finally
					{
						FreeLSAMemory(domainBuffer);
					}
				}
			}
			finally
			{
				ClosePolicy(policyHandle);
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

		systemAccess.LSAAnonymousNameLookup = LsaAnonymousNameLookupGetValue();

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
			uint openStatus = NativeMethods.LsaOpenPolicy(ref system, ref lsaAttr, POLICY_ALL_ACCESS, out nint policyHandle);
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
									FreeSAMMemory(userBuffer);
								}
							}
							finally
							{
								CloseSAMHandle(userHandle);
							}
						}
						finally
						{
							CloseSAMHandle(domainHandle);
						}
					}
					finally
					{
						CloseSAMHandle(serverHandle);
					}
				}
				finally
				{
					FreeLSAMemory(domainBuffer);
				}
			}
			finally
			{
				ClosePolicy(policyHandle);
			}
		}
		catch
		{
			return string.Empty;
		}
	}

	/// <summary>
	/// Opens the LSA Policy handle.
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
		uint status = NativeMethods.LsaOpenPolicy(ref systemName, ref objectAttributes, POLICY_ALL_ACCESS, out IntPtr policyHandle);
		FreeLsaUnicodeString(ref systemName);

		ThrowIfError(status, "LsaOpenPolicy");

		return policyHandle;
	}

	internal static void ClosePolicy(IntPtr handle)
	{
		if (handle != IntPtr.Zero)
			_ = NativeMethods.LsaClose(handle);
	}

	private static void CloseSAMHandle(IntPtr handle)
	{
		if (handle != IntPtr.Zero)
			_ = NativeMethods.SamCloseHandle(handle);
	}

	private static void FreeSAMMemory(IntPtr handle)
	{
		if (handle != IntPtr.Zero)
			_ = NativeMethods.SamFreeMemory(handle);
	}

	internal static void FreeLSAMemory(IntPtr handle)
	{
		if (handle != IntPtr.Zero)
			_ = NativeMethods.LsaFreeMemory(handle);
	}

	internal static void FreeGlobalHandle(IntPtr handle)
	{
		if (handle != IntPtr.Zero)
			Marshal.FreeHGlobal(handle);
	}

	/// <summary>
	/// Retrieves current value.
	/// 1 if DACL includes an ACCESS_ALLOWED ACE for the Anonymous SID whose AccessMask is exactly POLICY_LOOKUP_NAMES.
	/// otherwise 0.
	/// </summary>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static int LsaAnonymousNameLookupGetValue()
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
			FreeLSAMemory(securityDescriptorPtr);
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
	internal static void LsaAnonymousNameLookupSetValue(int value)
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
				FreeGlobalHandle(newSdPtr);
			}
		}
		finally
		{
			FreeLSAMemory(securityDescriptorPtr);
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

	internal static void FreeLsaUnicodeString(ref LSA_UNICODE_STRING lsa)
	{
		if (lsa.Buffer != IntPtr.Zero)
		{
			Marshal.FreeHGlobal(lsa.Buffer);
			lsa.Buffer = IntPtr.Zero;
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
	/// The user is opened via SamOpenUser with DesiredAccess=POLICY_ALL_ACCESS and the specified RID.
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
			policyHandle = OpenPolicy();

			// Query PolicyAccountDomainInformation (class 5) to get DomainSid
			uint nt = NativeMethods.LsaQueryInformationPolicy(policyHandle, PolicyAccountDomainInformation, out domainInfoBuffer);
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

			// Open the target user by RID with DesiredAccess = POLICY_ALL_ACCESS
			nt = NativeMethods.SamOpenUser(domainHandle, POLICY_ALL_ACCESS, rid, out userHandle);
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
			FreeGlobalHandle(setBuffer);
			FreeSAMMemory(queryBuffer);
			CloseSAMHandle(userHandle);
			CloseSAMHandle(domainHandle);
			CloseSAMHandle(serverHandle);
			FreeLSAMemory(domainInfoBuffer);
			ClosePolicy(policyHandle);
		}
	}

	/// <summary>
	/// Implements the behavior described in [MS-GPSB] for "NewAdministratorName".
	/// UserInformationClass MUST be UserNameInformation; buffer MUST be SAMPR_USER_NAME_INFORMATION with UserName set to the provided value.
	/// </summary>
	/// <param name="newName">The new name for the built-in Administrator account.</param>
	internal static void SetNewAdministratorName(string newName) => SetLocalAccountNameByRid(DOMAIN_USER_RID_ADMIN, newName);

	/// <summary>
	/// Implements the behavior described in [MS-GPSB] for "NewGuestName".
	/// UserInformationClass MUST be UserNameInformation; buffer MUST be SAMPR_USER_NAME_INFORMATION with UserName set to the provided value.
	/// </summary>
	/// <param name="newName">The new name for the built-in Guest account.</param>
	internal static void SetNewGuestName(string newName) => SetLocalAccountNameByRid(DOMAIN_USER_RID_GUEST, newName);

	/// <summary>
	/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0d94df7c-9752-4b08-84de-bf29e389c074
	/// Core implementation for renaming a local account by RID using SAM, strictly following [MS-GPSB] and [MS-SAMR].
	/// Steps:
	/// - LsaOpenPolicy(POLICY_ALL_ACCESS) -> LsaQueryInformationPolicy(PolicyAccountDomainInformation) -> DomainSid
	/// - SamConnect(SAM_SERVER_LOOKUP_DOMAIN) -> SamOpenDomain(DOMAIN_LOOKUP)
	/// - SamOpenUser(POLICY_ALL_ACCESS, rid)
	/// - SamSetInformationUser(UserNameInformation, SAMPR_USER_NAME_INFORMATION{UserName = newName})
	/// If SamSetInformationUser returns an error, throw (aligns with "stop processing Local Account policies and log an error").
	/// </summary>
	/// <param name="rid">Target user RID (e.g., 500 Administrator, 501 Guest).</param>
	/// <param name="newName">New account name to set.</param>
	internal static unsafe void SetLocalAccountNameByRid(uint rid, string newName)
	{
		if (string.IsNullOrWhiteSpace(newName))
		{
			throw new ArgumentException("New account name must not be null, empty, or whitespace.", nameof(newName));
		}

		IntPtr policyHandle = IntPtr.Zero;
		IntPtr domainInfoBuffer = IntPtr.Zero;
		IntPtr serverHandle = IntPtr.Zero;
		IntPtr domainHandle = IntPtr.Zero;
		IntPtr userHandle = IntPtr.Zero;

		// We will query current general info to preserve FullNam.
		IntPtr generalInfoBuffer = IntPtr.Zero;

		IntPtr nameInfoBuffer = IntPtr.Zero;

		// UNICODE_STRINGs we own and must free
		LSA_UNICODE_STRING newUserName = default;
		LSA_UNICODE_STRING existingFullNameCopy = default;

		try
		{
			policyHandle = OpenPolicy();

			// Query PolicyAccountDomainInformation to get DomainSid
			uint nt = NativeMethods.LsaQueryInformationPolicy(policyHandle, PolicyAccountDomainInformation, out domainInfoBuffer);
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

			// Open the target user by RID with DesiredAccess = POLICY_ALL_ACCESS
			nt = NativeMethods.SamOpenUser(domainHandle, POLICY_ALL_ACCESS, rid, out userHandle);
			ThrowIfError(nt, "SamOpenUser");

			// Query current general user information to obtain existing FullName (UserGeneralInformation = 1)
			nt = NativeMethods.SamQueryInformationUser(userHandle, 1, out generalInfoBuffer);
			ThrowIfError(nt, "SamQueryInformationUser(UserGeneralInformation)");

			if (generalInfoBuffer == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamQueryInformationUser(UserGeneralInformation) returned a null buffer.");
			}

			SAM_USER_GENERAL_INFORMATION* generalInfo = (SAM_USER_GENERAL_INFORMATION*)generalInfoBuffer;

			// Duplicate existing FullName into a UNICODE_STRING we own or leave empty if none
			if (generalInfo->FullName.Length > 0 && generalInfo->FullName.Buffer != IntPtr.Zero)
			{
				int fullNameChars = generalInfo->FullName.Length / 2;
				string fullName = Marshal.PtrToStringUni(generalInfo->FullName.Buffer, fullNameChars) ?? string.Empty;
				existingFullNameCopy = new LSA_UNICODE_STRING(fullName);
			}
			else
			{
				existingFullNameCopy = new LSA_UNICODE_STRING(null);
			}

			// Prepare the new account name as UNICODE_STRING
			newUserName = new LSA_UNICODE_STRING(newName);

			// Allocate the union buffer and zero it to avoid stray data
			int unionSize = sizeof(SAMPR_USER_INFO_BUFFER);
			nameInfoBuffer = Marshal.AllocHGlobal(unionSize);

			Span<byte> zeroSpan = new((void*)nameInfoBuffer, unionSize);
			zeroSpan.Clear();

			// Populate both fields in the union member for UserNameInformation
			// - UserName set to the new policy value
			// - FullName preserved because ABI expects this structure to include both
			((SAMPR_USER_INFO_BUFFER*)nameInfoBuffer)->UserNameInformation.UserName = newUserName;
			((SAMPR_USER_INFO_BUFFER*)nameInfoBuffer)->UserNameInformation.FullName = existingFullNameCopy;

			// Perform the rename using UserNameInformation (6), per [MS-GPSB].
			nt = NativeMethods.SamSetInformationUser(userHandle, UserNameInformation, nameInfoBuffer);
			ThrowIfError(nt, "SamSetInformationUser(UserNameInformation)");
		}
		finally
		{
			// Free allocations we own		
			FreeGlobalHandle(nameInfoBuffer);
			FreeGlobalHandle(newUserName.Buffer);
			FreeGlobalHandle(existingFullNameCopy.Buffer);
			// Free SAM-returned buffers and close handles	
			FreeSAMMemory(generalInfoBuffer);
			CloseSAMHandle(userHandle);
			CloseSAMHandle(domainHandle);
			CloseSAMHandle(serverHandle);
			FreeLSAMemory(domainInfoBuffer);
			ClosePolicy(policyHandle);
		}
	}

	/// <summary>
	/// Sets the "PasswordComplexity" policy by toggling the DOMAIN_PASSWORD_COMPLEX flag in DOMAIN_PASSWORD_INFORMATION.PasswordProperties.
	/// Uses SAM APIs:
	/// SamQueryInformationDomain (DomainPasswordInformation = 1) -> modify PasswordProperties bit -> SamSetInformationDomain.
	/// </summary>
	/// <param name="enable">1 to enable complexity, 0 to disable.</param>
	/// <exception cref="ArgumentOutOfRangeException">If enable is not 0 or 1.</exception>
	/// <exception cref="InvalidOperationException">On any failure to retrieve or apply the setting.</exception>
	internal unsafe static void SetPasswordComplexity(int enable)
	{
		if (enable != 0 && enable != 1)
		{
			throw new ArgumentOutOfRangeException(nameof(enable), "Value must be 0 or 1.");
		}

		IntPtr policyHandle = IntPtr.Zero;
		IntPtr domainInfoBuffer = IntPtr.Zero;
		IntPtr serverHandle = IntPtr.Zero;
		IntPtr domainHandle = IntPtr.Zero;
		IntPtr passwordInfoBuffer = IntPtr.Zero;
		IntPtr setBuffer = IntPtr.Zero;

		try
		{
			policyHandle = OpenPolicy();

			// Query PolicyAccountDomainInformation for DomainSid.
			uint ntStatus = NativeMethods.LsaQueryInformationPolicy(policyHandle, PolicyAccountDomainInformation, out domainInfoBuffer);
			if (ntStatus != STATUS_SUCCESS || domainInfoBuffer == IntPtr.Zero)
			{
				throw new InvalidOperationException("LsaQueryInformationPolicy(PolicyAccountDomainInformation) failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			POLICY_ACCOUNT_DOMAIN_INFO* domainInfo = (POLICY_ACCOUNT_DOMAIN_INFO*)domainInfoBuffer;
			if (domainInfo->DomainSid == IntPtr.Zero)
			{
				throw new InvalidOperationException("DomainSid is null in POLICY_ACCOUNT_DOMAIN_INFO.");
			}

			// Connect to SAM with lookup rights.
			LSA_UNICODE_STRING server = new(null);
			ntStatus = NativeMethods.SamConnect(ref server, out serverHandle, SAM_SERVER_LOOKUP_DOMAIN, IntPtr.Zero);
			if (ntStatus != STATUS_SUCCESS || serverHandle == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamConnect failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			// Open domain with read + write password parameter rights (least privilege for modification).
			uint desiredDomainAccess = DOMAIN_READ_PASSWORD_PARAMETERS | DOMAIN_WRITE_PASSWORD_PARAMS; // 0x00000003
			ntStatus = NativeMethods.SamOpenDomain(serverHandle, desiredDomainAccess, domainInfo->DomainSid, out domainHandle);
			if (ntStatus != STATUS_SUCCESS || domainHandle == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamOpenDomain failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			// Query current DOMAIN_PASSWORD_INFORMATION
			ntStatus = NativeMethods.SamQueryInformationDomain(domainHandle, 1, out passwordInfoBuffer);
			if (ntStatus != STATUS_SUCCESS || passwordInfoBuffer == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamQueryInformationDomain(DomainPasswordInformation) failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			DOMAIN_PASSWORD_INFORMATION currentInfo = *(DOMAIN_PASSWORD_INFORMATION*)passwordInfoBuffer;

			uint originalProps = currentInfo.PasswordProperties;
			bool currentlyEnabled = (originalProps & DOMAIN_PASSWORD_COMPLEX) != 0;
			bool wantEnable = enable == 1;

			// If already in desired state, nothing to do.
			if (currentlyEnabled == wantEnable)
			{
				return;
			}

			// Toggle only the DOMAIN_PASSWORD_COMPLEX bit, preserve all other flags and numeric fields.
			currentInfo.PasswordProperties = wantEnable ? originalProps | DOMAIN_PASSWORD_COMPLEX
				: originalProps & ~DOMAIN_PASSWORD_COMPLEX;

			int size = sizeof(DOMAIN_PASSWORD_INFORMATION);
			setBuffer = Marshal.AllocHGlobal(size);

			// Zero for safety then copy modified struct.
			Span<byte> zeroSpan = new((void*)setBuffer, size);
			zeroSpan.Clear();
			*(DOMAIN_PASSWORD_INFORMATION*)setBuffer = currentInfo;

			ntStatus = NativeMethods.SamSetInformationDomain(domainHandle, 1, setBuffer);
			if (ntStatus != STATUS_SUCCESS)
			{
				throw new InvalidOperationException("SamSetInformationDomain(DomainPasswordInformation) failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}
		}
		finally
		{
			FreeGlobalHandle(setBuffer);
			FreeSAMMemory(passwordInfoBuffer);
			CloseSAMHandle(domainHandle);
			CloseSAMHandle(serverHandle);
			FreeLSAMemory(domainInfoBuffer);
			ClosePolicy(policyHandle);
		}
	}

	/// <summary>
	/// Sets the "ForceLogoffWhenHourExpire" policy.
	/// Mapping:
	///   enable == 1 => force immediate logoff when hours expire (store force_logoff = 0 seconds).
	///   enable == 0 => do not force logoff (store force_logoff = TIMEQ_FOREVER = uint.MaxValue).
	/// Underlying field: USER_MODALS_INFO_0.force_logoff (seconds; TIMEQ_FOREVER means never).
	/// </summary>
	/// <param name="enable">1 to enable forced logoff at hour expiration; 0 to disable.</param>
	/// <exception cref="ArgumentOutOfRangeException">If enable is not 0 or 1.</exception>
	/// <exception cref="InvalidOperationException">On failure to retrieve or apply the setting.</exception>
	internal unsafe static void SetForceLogoffWhenHourExpire(int enable)
	{
		if (enable != 0 && enable != 1)
		{
			throw new ArgumentOutOfRangeException(nameof(enable), "Value must be 0 or 1.");
		}

		IntPtr currentBuffer = IntPtr.Zero;
		IntPtr newBuffer = IntPtr.Zero;

		try
		{
			// Retrieve current modal info (level 0)
			uint getStatus = NativeMethods.NetUserModalsGet(null, 0, out currentBuffer);
			if (getStatus != NERR_Success || currentBuffer == IntPtr.Zero)
			{
				throw new InvalidOperationException("NetUserModalsGet(level 0) failed. Status=0x" + getStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			USER_MODALS_INFO_0 currentInfo = *(USER_MODALS_INFO_0*)currentBuffer;

			// Determine desired underlying force_logoff value.
			// Enabled => immediate logoff => 0 seconds.
			// Disabled => TIMEQ_FOREVER => uint.MaxValue.
			uint desired = enable == 1 ? 0u : uint.MaxValue;

			// Early exit if already matches desired state.
			bool currentlyEnabled = currentInfo.force_logoff != uint.MaxValue; // any non-FOREVER is treated as enabled
			if ((enable == 1 && currentlyEnabled && currentInfo.force_logoff == 0u) ||
				(enable == 0 && currentInfo.force_logoff == uint.MaxValue))
			{
				return;
			}

			// Allocate new buffer for updated struct
			uint allocStatus = NativeMethods.NetApiBufferAllocate((uint)sizeof(USER_MODALS_INFO_0), out newBuffer);
			if (allocStatus != NERR_Success || newBuffer == IntPtr.Zero)
			{
				throw new InvalidOperationException("NetApiBufferAllocate failed. Status=0x" + allocStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			USER_MODALS_INFO_0 updated = new()
			{
				min_passwd_len = currentInfo.min_passwd_len,
				max_passwd_age = currentInfo.max_passwd_age,
				min_passwd_age = currentInfo.min_passwd_age,
				force_logoff = desired,
				password_hist_len = currentInfo.password_hist_len
			};

			*(USER_MODALS_INFO_0*)newBuffer = updated;

			uint setStatus = NativeMethods.NetUserModalsSet(null, 0, newBuffer, out uint parmErr);
			if (setStatus != NERR_Success)
			{
				throw new InvalidOperationException("NetUserModalsSet(level 0) failed. Status=0x" + setStatus.ToString("X8", CultureInfo.InvariantCulture) +
					" ParmErr=" + parmErr.ToString(CultureInfo.InvariantCulture));
			}
		}
		finally
		{
			if (newBuffer != IntPtr.Zero)
			{
				_ = NativeMethods.NetApiBufferFree(newBuffer);
			}
			if (currentBuffer != IntPtr.Zero)
			{
				_ = NativeMethods.NetApiBufferFree(currentBuffer);
			}
		}
	}

	/// <summary>
	/// Sets the "RequireLogonToChangePassword" policy by toggling the DOMAIN_PASSWORD_NO_ANON_CHANGE flag
	/// inside DOMAIN_PASSWORD_INFORMATION.PasswordProperties.
	/// Mapping:
	///   enable == 1 => set DOMAIN_PASSWORD_NO_ANON_CHANGE (anonymous users cannot change passwords).
	///   enable == 0 => clear DOMAIN_PASSWORD_NO_ANON_CHANGE.
	/// Uses SAM APIs:
	///   LsaOpenPolicy -> LsaQueryInformationPolicy(PolicyAccountDomainInformation) -> SamConnect ->
	///   SamOpenDomain(DOMAIN_READ_PASSWORD_PARAMETERS | DOMAIN_WRITE_PASSWORD_PARAMS) ->
	///   SamQueryInformationDomain(DomainPasswordInformation = 1) -> modify bit -> SamSetInformationDomain.
	/// </summary>
	/// <param name="enable">1 to require logon to change password; 0 to allow anonymous change.</param>
	/// <exception cref="ArgumentOutOfRangeException">If enable is not 0 or 1.</exception>
	/// <exception cref="InvalidOperationException">On any failure to retrieve or apply the setting.</exception>
	internal unsafe static void SetRequireLogonToChangePassword(int enable)
	{
		if (enable != 0 && enable != 1)
		{
			throw new ArgumentOutOfRangeException(nameof(enable), "Value must be 0 or 1.");
		}

		IntPtr policyHandle = IntPtr.Zero;
		IntPtr domainInfoBuffer = IntPtr.Zero;
		IntPtr serverHandle = IntPtr.Zero;
		IntPtr domainHandle = IntPtr.Zero;
		IntPtr passwordInfoBuffer = IntPtr.Zero;
		IntPtr setBuffer = IntPtr.Zero;

		try
		{
			policyHandle = OpenPolicy();

			// Query PolicyAccountDomainInformation for DomainSid.
			uint ntStatus = NativeMethods.LsaQueryInformationPolicy(policyHandle, PolicyAccountDomainInformation, out domainInfoBuffer);
			if (ntStatus != STATUS_SUCCESS || domainInfoBuffer == IntPtr.Zero)
			{
				throw new InvalidOperationException("LsaQueryInformationPolicy(PolicyAccountDomainInformation) failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			POLICY_ACCOUNT_DOMAIN_INFO* domainInfo = (POLICY_ACCOUNT_DOMAIN_INFO*)domainInfoBuffer;
			if (domainInfo->DomainSid == IntPtr.Zero)
			{
				throw new InvalidOperationException("DomainSid is null in POLICY_ACCOUNT_DOMAIN_INFO.");
			}

			// Connect to SAM with lookup rights.
			LSA_UNICODE_STRING server = new(null);
			ntStatus = NativeMethods.SamConnect(ref server, out serverHandle, SAM_SERVER_LOOKUP_DOMAIN, IntPtr.Zero);
			if (ntStatus != STATUS_SUCCESS || serverHandle == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamConnect failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			// Open domain with read + write password parameter rights.
			uint desiredDomainAccess = DOMAIN_READ_PASSWORD_PARAMETERS | DOMAIN_WRITE_PASSWORD_PARAMS; // 0x00000003
			ntStatus = NativeMethods.SamOpenDomain(serverHandle, desiredDomainAccess, domainInfo->DomainSid, out domainHandle);
			if (ntStatus != STATUS_SUCCESS || domainHandle == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamOpenDomain failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			// Query current DOMAIN_PASSWORD_INFORMATION
			ntStatus = NativeMethods.SamQueryInformationDomain(domainHandle, 1, out passwordInfoBuffer);
			if (ntStatus != STATUS_SUCCESS || passwordInfoBuffer == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamQueryInformationDomain(DomainPasswordInformation) failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			DOMAIN_PASSWORD_INFORMATION currentInfo = *(DOMAIN_PASSWORD_INFORMATION*)passwordInfoBuffer;

			uint originalProps = currentInfo.PasswordProperties;
			bool currentlyEnabled = (originalProps & DOMAIN_PASSWORD_NO_ANON_CHANGE) != 0;
			bool wantEnable = enable == 1;

			// If already in desired state, nothing to do.
			if (currentlyEnabled == wantEnable)
			{
				return;
			}

			// Toggle only the DOMAIN_PASSWORD_NO_ANON_CHANGE bit, preserve other flags.
			currentInfo.PasswordProperties = wantEnable ? originalProps | DOMAIN_PASSWORD_NO_ANON_CHANGE : originalProps & ~DOMAIN_PASSWORD_NO_ANON_CHANGE;

			int size = sizeof(DOMAIN_PASSWORD_INFORMATION);
			setBuffer = Marshal.AllocHGlobal(size);

			// Zero for safety then copy modified struct.
			Span<byte> zeroSpan = new((void*)setBuffer, size);
			zeroSpan.Clear();
			*(DOMAIN_PASSWORD_INFORMATION*)setBuffer = currentInfo;

			ntStatus = NativeMethods.SamSetInformationDomain(domainHandle, 1, setBuffer);
			if (ntStatus != STATUS_SUCCESS)
			{
				throw new InvalidOperationException("SamSetInformationDomain(DomainPasswordInformation) failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}
		}
		finally
		{
			FreeGlobalHandle(setBuffer);
			FreeSAMMemory(passwordInfoBuffer);
			CloseSAMHandle(domainHandle);
			CloseSAMHandle(serverHandle);
			FreeLSAMemory(domainInfoBuffer);
			ClosePolicy(policyHandle);
		}
	}

	/// <summary>
	/// Sets the "AllowAdministratorLockout" policy by toggling the DOMAIN_LOCKOUT_ADMINS flag
	/// inside DOMAIN_PASSWORD_INFORMATION.PasswordProperties.
	/// Mapping:
	///   enable == 1 => set DOMAIN_LOCKOUT_ADMINS (built-in Administrator can be locked out).
	///   enable == 0 => clear DOMAIN_LOCKOUT_ADMINS (built-in Administrator cannot be locked out).
	/// Implementation is surgical, only this bit is modified, all other bits and numeric fields are preserved.
	/// </summary>
	/// <param name="enable">1 to allow Administrator lockout; 0 to disallow.</param>
	/// <exception cref="ArgumentOutOfRangeException">If enable is not 0 or 1.</exception>
	/// <exception cref="InvalidOperationException">On any failure to retrieve or apply the setting.</exception>
	internal unsafe static void SetAllowAdministratorLockout(int enable)
	{
		if (enable != 0 && enable != 1)
		{
			throw new ArgumentOutOfRangeException(nameof(enable), "Value must be 0 or 1.");
		}

		IntPtr policyHandle = IntPtr.Zero;
		IntPtr domainInfoBuffer = IntPtr.Zero;
		IntPtr serverHandle = IntPtr.Zero;
		IntPtr domainHandle = IntPtr.Zero;
		IntPtr passwordInfoBuffer = IntPtr.Zero;
		IntPtr setBuffer = IntPtr.Zero;

		try
		{
			policyHandle = OpenPolicy();

			// Query PolicyAccountDomainInformation to get DomainSid.
			uint ntStatus = NativeMethods.LsaQueryInformationPolicy(policyHandle, PolicyAccountDomainInformation, out domainInfoBuffer);
			if (ntStatus != STATUS_SUCCESS || domainInfoBuffer == IntPtr.Zero)
			{
				throw new InvalidOperationException("LsaQueryInformationPolicy(PolicyAccountDomainInformation) failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			POLICY_ACCOUNT_DOMAIN_INFO* domainInfo = (POLICY_ACCOUNT_DOMAIN_INFO*)domainInfoBuffer;
			if (domainInfo->DomainSid == IntPtr.Zero)
			{
				throw new InvalidOperationException("DomainSid is null in POLICY_ACCOUNT_DOMAIN_INFO.");
			}

			// Connect to SAM.
			LSA_UNICODE_STRING server = new(null);
			ntStatus = NativeMethods.SamConnect(ref server, out serverHandle, SAM_SERVER_LOOKUP_DOMAIN, IntPtr.Zero);
			if (ntStatus != STATUS_SUCCESS || serverHandle == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamConnect failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			// Open domain with minimal rights needed to read and write password parameters.
			uint desiredDomainAccess = DOMAIN_READ_PASSWORD_PARAMETERS | DOMAIN_WRITE_PASSWORD_PARAMS;
			ntStatus = NativeMethods.SamOpenDomain(serverHandle, desiredDomainAccess, domainInfo->DomainSid, out domainHandle);
			if (ntStatus != STATUS_SUCCESS || domainHandle == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamOpenDomain failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			// Query current DOMAIN_PASSWORD_INFORMATION (DomainPasswordInformation = 1).
			ntStatus = NativeMethods.SamQueryInformationDomain(domainHandle, 1, out passwordInfoBuffer);
			if (ntStatus != STATUS_SUCCESS || passwordInfoBuffer == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamQueryInformationDomain(DomainPasswordInformation) failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			DOMAIN_PASSWORD_INFORMATION currentInfo = *(DOMAIN_PASSWORD_INFORMATION*)passwordInfoBuffer;

			uint originalProps = currentInfo.PasswordProperties;
			bool currentlyEnabled = (originalProps & DOMAIN_LOCKOUT_ADMINS) != 0;
			bool wantEnable = enable == 1;

			// Early exit if already desired state.
			if (currentlyEnabled == wantEnable)
			{
				return;
			}

			// Toggle only DOMAIN_LOCKOUT_ADMINS bit.
			currentInfo.PasswordProperties = wantEnable ? originalProps | DOMAIN_LOCKOUT_ADMINS : originalProps & ~DOMAIN_LOCKOUT_ADMINS;

			int size = sizeof(DOMAIN_PASSWORD_INFORMATION);
			setBuffer = Marshal.AllocHGlobal(size);

			// Zero buffer then copy updated structure.
			Span<byte> zeroSpan = new((void*)setBuffer, size);
			zeroSpan.Clear();
			*(DOMAIN_PASSWORD_INFORMATION*)setBuffer = currentInfo;

			ntStatus = NativeMethods.SamSetInformationDomain(domainHandle, 1, setBuffer);
			if (ntStatus != STATUS_SUCCESS)
			{
				throw new InvalidOperationException("SamSetInformationDomain(DomainPasswordInformation) failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}
		}
		finally
		{
			FreeGlobalHandle(setBuffer);
			FreeSAMMemory(passwordInfoBuffer);
			CloseSAMHandle(domainHandle);
			CloseSAMHandle(serverHandle);
			FreeLSAMemory(domainInfoBuffer);
			ClosePolicy(policyHandle);
		}
	}

	/// <summary>
	/// Sets the "ClearTextPassword" policy by toggling the DOMAIN_PASSWORD_STORE_CLEARTEXT flag
	/// inside DOMAIN_PASSWORD_INFORMATION.PasswordProperties.
	/// Mapping:
	///   enable == 1 => set DOMAIN_PASSWORD_STORE_CLEARTEXT (store reversible encryption passwords).
	///   enable == 0 => clear DOMAIN_PASSWORD_STORE_CLEARTEXT.
	/// Implementation is surgical, only this bit is changed, all other bits and numeric fields are preserved.
	/// </summary>
	/// <param name="enable">1 to allow storing clear text (reversible) passwords; 0 to disallow.</param>
	/// <exception cref="ArgumentOutOfRangeException">If enable is not 0 or 1.</exception>
	/// <exception cref="InvalidOperationException">On any failure to retrieve or apply the setting.</exception>
	internal unsafe static void SetClearTextPassword(int enable)
	{
		if (enable != 0 && enable != 1)
		{
			throw new ArgumentOutOfRangeException(nameof(enable), "Value must be 0 or 1.");
		}

		IntPtr policyHandle = IntPtr.Zero;
		IntPtr domainInfoBuffer = IntPtr.Zero;
		IntPtr serverHandle = IntPtr.Zero;
		IntPtr domainHandle = IntPtr.Zero;
		IntPtr passwordInfoBuffer = IntPtr.Zero;
		IntPtr setBuffer = IntPtr.Zero;

		try
		{
			policyHandle = OpenPolicy();

			// Get Domain SID.
			uint ntStatus = NativeMethods.LsaQueryInformationPolicy(policyHandle, PolicyAccountDomainInformation, out domainInfoBuffer);
			if (ntStatus != STATUS_SUCCESS || domainInfoBuffer == IntPtr.Zero)
			{
				throw new InvalidOperationException("LsaQueryInformationPolicy(PolicyAccountDomainInformation) failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			POLICY_ACCOUNT_DOMAIN_INFO* domainInfo = (POLICY_ACCOUNT_DOMAIN_INFO*)domainInfoBuffer;
			if (domainInfo->DomainSid == IntPtr.Zero)
			{
				throw new InvalidOperationException("DomainSid is null in POLICY_ACCOUNT_DOMAIN_INFO.");
			}

			// Connect to SAM.
			LSA_UNICODE_STRING server = new(null);
			ntStatus = NativeMethods.SamConnect(ref server, out serverHandle, SAM_SERVER_LOOKUP_DOMAIN, IntPtr.Zero);
			if (ntStatus != STATUS_SUCCESS || serverHandle == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamConnect failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			// Open domain with read + write password parameter rights.
			uint desiredDomainAccess = DOMAIN_READ_PASSWORD_PARAMETERS | DOMAIN_WRITE_PASSWORD_PARAMS;
			ntStatus = NativeMethods.SamOpenDomain(serverHandle, desiredDomainAccess, domainInfo->DomainSid, out domainHandle);
			if (ntStatus != STATUS_SUCCESS || domainHandle == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamOpenDomain failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			// Query current DOMAIN_PASSWORD_INFORMATION (DomainPasswordInformation = 1).
			ntStatus = NativeMethods.SamQueryInformationDomain(domainHandle, 1, out passwordInfoBuffer);
			if (ntStatus != STATUS_SUCCESS || passwordInfoBuffer == IntPtr.Zero)
			{
				throw new InvalidOperationException("SamQueryInformationDomain(DomainPasswordInformation) failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}

			DOMAIN_PASSWORD_INFORMATION currentInfo = *(DOMAIN_PASSWORD_INFORMATION*)passwordInfoBuffer;

			uint originalProps = currentInfo.PasswordProperties;
			bool currentlyEnabled = (originalProps & DOMAIN_PASSWORD_STORE_CLEARTEXT) != 0;
			bool wantEnable = enable == 1;

			// Early exit if already desired state.
			if (currentlyEnabled == wantEnable)
			{
				return;
			}

			// Toggle only DOMAIN_PASSWORD_STORE_CLEARTEXT bit.
			currentInfo.PasswordProperties = wantEnable ? originalProps | DOMAIN_PASSWORD_STORE_CLEARTEXT : originalProps & ~DOMAIN_PASSWORD_STORE_CLEARTEXT;

			int size = sizeof(DOMAIN_PASSWORD_INFORMATION);
			setBuffer = Marshal.AllocHGlobal(size);

			// Zero buffer then copy updated structure.
			Span<byte> zeroSpan = new((void*)setBuffer, size);
			zeroSpan.Clear();
			*(DOMAIN_PASSWORD_INFORMATION*)setBuffer = currentInfo;

			ntStatus = NativeMethods.SamSetInformationDomain(domainHandle, 1, setBuffer);
			if (ntStatus != STATUS_SUCCESS)
			{
				throw new InvalidOperationException("SamSetInformationDomain(DomainPasswordInformation) failed. NTSTATUS=0x" + ntStatus.ToString("X8", CultureInfo.InvariantCulture));
			}
		}
		finally
		{
			FreeGlobalHandle(setBuffer);
			FreeSAMMemory(passwordInfoBuffer);
			CloseSAMHandle(domainHandle);
			CloseSAMHandle(serverHandle);
			FreeLSAMemory(domainInfoBuffer);
			ClosePolicy(policyHandle);
		}
	}
}
