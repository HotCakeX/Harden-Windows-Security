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
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace HardenSystemSecurity.SecurityPolicy;

internal static class SecurityPolicyWriter
{
	/// <summary>
	/// Sets information for the [Registry Values] part.
	/// </summary>
	/// <param name="registryPath"></param>
	/// <param name="valueName"></param>
	/// <param name="value"></param>
	/// <param name="valueType"></param>
	/// <returns></returns>
	internal static bool SetRegistrySecurityValue(string registryPath, string valueName, object value, RegistryValueKind valueType)
	{
		try
		{
			// Parse the registry path to extract root key and subkey
			string[] pathParts = registryPath.Split('\\', 2);
			if (pathParts.Length < 2)
				return false;

			// For "MACHINE\" prefix, use the subkey after "MACHINE\"
			string actualPath;
			RegistryKey? rootKey;

			if (pathParts[0].Equals("MACHINE", StringComparison.OrdinalIgnoreCase))
			{
				rootKey = Registry.LocalMachine;
				actualPath = pathParts[1];
			}
			else
			{
				// Handle direct registry root keys
				rootKey = pathParts[0].ToUpperInvariant() switch
				{
					"HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
					"HKLM" => Registry.LocalMachine,
					"USER" => Registry.CurrentUser,
					"HKEY_CURRENT_USER" => Registry.CurrentUser,
					"HKCU" => Registry.CurrentUser,
					"USERS" => Registry.Users,
					"HKEY_USERS" => Registry.Users,
					"CLASSES_ROOT" => Registry.ClassesRoot,
					"HKEY_CLASSES_ROOT" => Registry.ClassesRoot,
					"CURRENT_CONFIG" => Registry.CurrentConfig,
					"HKEY_CURRENT_CONFIG" => Registry.CurrentConfig,
					_ => null
				};
				actualPath = pathParts[1];
			}

			if (rootKey is null)
				return false;

			using RegistryKey key = rootKey.CreateSubKey(actualPath, true);
			if (key is not null)
			{
				key.SetValue(valueName, value, valueType);
				key.Flush(); // Ensure the value is written immediately
				return true;
			}
			return false;
		}
		catch
		{
			return false;
		}
	}

	/// <summary>
	/// Sets privilege rights (user rights assignments) for specified privileges.
	/// This method configures the [Privilege Rights] section equivalent.
	/// </summary>
	/// <param name="privilegeRights">Dictionary where key is privilege name and value is array of SIDs/account names</param>
	/// <returns></returns>
	internal unsafe static void SetPrivilegeRights(Dictionary<string, string[]> privilegeRights)
	{
		if (privilegeRights.Count == 0)
		{
			throw new InvalidOperationException("No privilege rights provided to set");
		}

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

		// Full access
		uint desiredAccess = 0x000F0FFF;

		uint openPolicyStatus = NativeMethods.LsaOpenPolicy(ref system, ref lsaAttr, (int)desiredAccess, out nint policyHandle);

		if (openPolicyStatus != SecurityPolicyReader.STATUS_SUCCESS)
		{
			throw new InvalidOperationException($"Failed to open LSA policy. Status: 0x{openPolicyStatus:X8} ({GetLsaErrorMessage(openPolicyStatus)})");
		}

		try
		{
			foreach (KeyValuePair<string, string[]> privilege in privilegeRights)
			{
				SetSinglePrivilegeRight(policyHandle, privilege.Key, privilege.Value);

				Logger.Write($"Successfully set privilege right: {privilege.Key} with {privilege.Value.Length} assignments");
			}
		}
		finally
		{
			_ = NativeMethods.LsaClose(policyHandle);
		}
	}

	/// <summary>
	/// Converts LSA error codes to readable messages.
	/// </summary>
	/// <param name="status">LSA status code</param>
	/// <returns>Human-readable error message</returns>
	private static string GetLsaErrorMessage(uint status)
	{
		return status switch
		{
			0xC0000022 => "ACCESS_DENIED - Insufficient privileges or access rights",
			0xC000000D => "INVALID_PARAMETER - One or more parameters are invalid",
			0xC0000034 => "OBJECT_NAME_NOT_FOUND - The specified object was not found",
			0xC00000BB => "NOT_SUPPORTED - The operation is not supported",
			0xC0000001 => "UNSUCCESSFUL - The operation was unsuccessful",
			_ => $"Unknown LSA error code: 0x{status:X8}"
		};
	}

	/// <summary>
	/// Sets a single privilege right surgically by comparing current assignments with desired assignments
	/// and only removing/adding accounts that need to be changed.
	/// </summary>
	/// <param name="policyHandle">Handle to the LSA policy</param>
	/// <param name="privilegeName">Name of the privilege (e.g., "SeServiceLogonRight")</param>
	/// <param name="accountSidsOrNames">Array of SIDs or account names to assign the privilege to</param>
	/// <returns></returns>
	private unsafe static void SetSinglePrivilegeRight(nint policyHandle, string privilegeName, string[] accountSidsOrNames)
	{
		LSA_UNICODE_STRING userRight = new(privilegeName);

		HashSet<string> currentSids = new(StringComparer.OrdinalIgnoreCase);
		HashSet<string> desiredSids = new(StringComparer.OrdinalIgnoreCase);

		// Open a separate policy handle specifically for enumeration with the correct access rights
		LSA_OBJECT_ATTRIBUTES enumLsaAttr = new()
		{
			Length = sizeof(LSA_OBJECT_ATTRIBUTES),
			RootDirectory = IntPtr.Zero,
			ObjectName = IntPtr.Zero,
			Attributes = 0,
			SecurityDescriptor = IntPtr.Zero,
			SecurityQualityOfService = IntPtr.Zero
		};

		LSA_UNICODE_STRING enumSystem = new(null);

		// Specific access rights for enumeration: POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION
		// Using full access wouldn't work.
		uint enumDesiredAccess = 0x00000800 | 0x00000001;

		uint enumOpenStatus = NativeMethods.LsaOpenPolicy(ref enumSystem, ref enumLsaAttr, (int)enumDesiredAccess, out nint enumPolicyHandle);

		if (enumOpenStatus == SecurityPolicyReader.STATUS_SUCCESS)
		{
			try
			{
				// Get all current accounts with this privilege using the enumeration-specific handle
				uint enumStatus = NativeMethods.LsaEnumerateAccountsWithUserRight(enumPolicyHandle, ref userRight, out nint enumBuffer, out int countReturned);

				if (enumStatus == SecurityPolicyReader.STATUS_SUCCESS)
				{
					// Collect current SIDs if any exist
					if (enumBuffer != IntPtr.Zero && countReturned > 0)
					{
						try
						{
							for (int i = 0; i < countReturned; i++)
							{
								LSA_ENUMERATION_INFORMATION info = *(LSA_ENUMERATION_INFORMATION*)IntPtr.Add(enumBuffer, i * sizeof(LSA_ENUMERATION_INFORMATION));

								try
								{
									SecurityIdentifier sid = new(info.PSid);
									_ = currentSids.Add(sid.Value);
								}
								catch
								{
									// Skip if we can't convert to SID
								}
							}
						}
						finally
						{
							_ = NativeMethods.LsaFreeMemory(enumBuffer);
						}
					}
					// If enumBuffer is Zero or countReturned is 0, it means no accounts have this privilege (which is valid)
				}
				// https://learn.microsoft.com/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
				else if (enumStatus == 0xC0000034) // STATUS_OBJECT_NAME_NOT_FOUND - no accounts have this privilege
				{
					Logger.Write($"No accounts currently have privilege {privilegeName}");
				}
				else if (enumStatus == 0x8000001A) // STATUS_NO_MORE_ENTRIES - privilege has no assignments.
				{
					Logger.Write($"Privilege {privilegeName} has no current assignments");
				}
				else
				{
					throw new InvalidOperationException($"Could not enumerate current accounts for privilege {privilegeName}. Status: 0x{enumStatus:X8}.");
				}
			}
			finally
			{
				_ = NativeMethods.LsaClose(enumPolicyHandle);
			}
		}
		else
		{
			throw new InvalidOperationException($"Could not open LSA policy for enumeration of privilege {privilegeName}. Status: 0x{enumOpenStatus:X8}.");
		}

		// Converting desired account names/SIDs to normalized SID strings
		foreach (string accountSidOrName in accountSidsOrNames)
		{
			if (string.IsNullOrWhiteSpace(accountSidOrName))
				continue;

			string normalizedSid = GetNormalizedSidString(accountSidOrName);
			if (!string.IsNullOrEmpty(normalizedSid))
			{
				_ = desiredSids.Add(normalizedSid);
			}
			else
			{
				Logger.Write($"Could not resolve SID for account: {accountSidOrName}", LogTypeIntel.Warning);
			}
		}

		// Remove accounts that shouldn't have the privilege (current - desired)
		HashSet<string> sidsToRemove = new(currentSids.Except(desiredSids, StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase);
		foreach (string sidToRemove in sidsToRemove)
		{
			IntPtr sidPtr = GetSidPtrFromString(sidToRemove);
			if (sidPtr != IntPtr.Zero)
			{
				try
				{
					uint removeStatus = NativeMethods.LsaRemoveAccountRights(policyHandle, sidPtr, false, ref userRight, 1);
					if (removeStatus != SecurityPolicyReader.STATUS_SUCCESS)
					{
						throw new InvalidOperationException($"Could not remove privilege {privilegeName} from SID {sidToRemove}. Status: 0x{removeStatus:X8}");
					}
					else
					{
						Logger.Write($"Removed privilege {privilegeName} from SID {sidToRemove}");
					}
				}
				finally
				{
					Marshal.FreeHGlobal(sidPtr);
				}
			}
		}

		// Add accounts that should have the privilege but don't (desired - current)
		HashSet<string> sidsToAdd = new(desiredSids.Except(currentSids, StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase);
		foreach (string sidToAdd in sidsToAdd)
		{
			IntPtr sidPtr = GetSidPtrFromString(sidToAdd);
			if (sidPtr != IntPtr.Zero)
			{
				try
				{
					uint addStatus = NativeMethods.LsaAddAccountRights(policyHandle, sidPtr, ref userRight, 1);
					if (addStatus != SecurityPolicyReader.STATUS_SUCCESS)
					{
						throw new InvalidOperationException($"Failed to add privilege {privilegeName} to SID {sidToAdd}. Status: 0x{addStatus:X8}");
					}
					else
					{
						Logger.Write($"Added privilege {privilegeName} to SID {sidToAdd}");
					}
				}
				finally
				{
					Marshal.FreeHGlobal(sidPtr);
				}
			}
		}

		Logger.Write($"Privilege {privilegeName}: {sidsToRemove.Count} removed, {sidsToAdd.Count} added, {currentSids.Intersect(desiredSids, StringComparer.OrdinalIgnoreCase).Count()} unchanged");
	}

	/// <summary>
	/// Normalizes a SID or account name to a SID string for comparison purposes.
	/// </summary>
	/// <param name="sidOrAccountName">SID string (with or without *) or account name</param>
	/// <returns>Normalized SID string or empty string if resolution failed</returns>
	private static string GetNormalizedSidString(string sidOrAccountName)
	{
		try
		{
			// Remove * prefix if present (secedit export format)
			string cleanInput = sidOrAccountName.StartsWith('*') ? sidOrAccountName[1..] : sidOrAccountName;

			// Try as SID first
			try
			{
				SecurityIdentifier sid = new(cleanInput);
				return sid.Value;
			}
			catch
			{
				// Try as account name
				NTAccount account = new(cleanInput);
				SecurityIdentifier resolvedSid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
				return resolvedSid.Value;
			}
		}
		catch
		{
			return string.Empty;
		}
	}

	/// <summary>
	/// Converts a SID string to an IntPtr for use with LSA APIs.
	/// </summary>
	/// <param name="sidString">SID string to convert</param>
	/// <returns>Pointer to SID or IntPtr.Zero if conversion failed</returns>
	private static IntPtr GetSidPtrFromString(string sidString)
	{
		try
		{
			SecurityIdentifier sid = new(sidString);
			byte[] sidBytes = new byte[sid.BinaryLength];
			sid.GetBinaryForm(sidBytes, 0);

			IntPtr sidPtr = Marshal.AllocHGlobal(sidBytes.Length);
			Marshal.Copy(sidBytes, 0, sidPtr, sidBytes.Length);
			return sidPtr;
		}
		catch
		{
			return IntPtr.Zero;
		}
	}

	/// <summary>
	/// Configures the [Registry Values] section with recommended values.
	/// </summary>
	/// <returns></returns>
	internal static bool ConfigureSecurityRegistryValues()
	{
		bool allSuccessful = true;

		// Dictionary of security registry values with their recommended secure values
		Dictionary<(string path, string valueName), (object value, RegistryValueKind type)> securityValues = new()
		{
			// UAC Settings
			{ (@"MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin"), (2, RegistryValueKind.DWord) },
			{ (@"MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorUser"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableSecureUIAPaths"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableVirtualization"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "FilterAdministratorToken"), (1, RegistryValueKind.DWord) },

			// LSA Settings
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel"), (5, RegistryValueKind.DWord) },
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "SCENoApplyLegacyAuditPolicy"), (1, RegistryValueKind.DWord) },

			// Network Security
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters", "RequireSecuritySignature"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters", "EnableSecuritySignature"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "EnableSecuritySignature"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "EnablePlainTextPassword"), (0, RegistryValueKind.DWord) },

			// NTLM Settings
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NTLMMinClientSec"), (537395200, RegistryValueKind.DWord) },
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NTLMMinServerSec"), (537395200, RegistryValueKind.DWord) },
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "RestrictSendingNTLMTraffic"), (2, RegistryValueKind.DWord) },
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "RestrictReceivingNTLMTraffic"), (2, RegistryValueKind.DWord) },

			// Logon Settings
			{ (@"MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "PasswordExpiryWarning"), (14, RegistryValueKind.DWord) },
			{ (@"MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount"), (2, RegistryValueKind.DWord) },

			// Session Settings
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "ClearPageFileAtShutdown"), (1, RegistryValueKind.DWord) },
			{ (@"MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager", "ProtectionMode"), (1, RegistryValueKind.DWord) }
		};

		foreach (KeyValuePair<(string path, string valueName), (object value, RegistryValueKind type)> setting in securityValues)
		{
			bool success = SetRegistrySecurityValue(setting.Key.path, setting.Key.valueName, setting.Value.value, setting.Value.type);
			if (!success)
			{
				allSuccessful = false;
				Logger.Write($"Failed to set {setting.Key.path}\\{setting.Key.valueName}");
			}
		}

		return allSuccessful;
	}

	/// <summary>
	/// Sets the minimumPasswordAge and maximumPasswordAge for the [System Access] section.
	/// </summary>
	/// <param name="minimumPasswordAge"></param>
	/// <param name="maximumPasswordAge"></param>
	/// <returns></returns>
	internal unsafe static bool SetPasswordAge(int minimumPasswordAge, int maximumPasswordAge)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 0, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			return false;
		}

		try
		{
			USER_MODALS_INFO_0 currentInfo = *(USER_MODALS_INFO_0*)buffer;

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)sizeof(USER_MODALS_INFO_0), out nint newBuffer);
			if (allocResult != SecurityPolicyReader.NERR_Success)
			{
				return false;
			}

			try
			{
				USER_MODALS_INFO_0 newInfo = new()
				{
					min_passwd_len = currentInfo.min_passwd_len,

					// Convert days to seconds by multiplying by 86400 (24*60*60)
					max_passwd_age = maximumPasswordAge == -1 ? uint.MaxValue : (uint)(maximumPasswordAge * 86400),

					// Convert days to seconds by multiplying by 86400 (24*60*60)
					min_passwd_age = (uint)(minimumPasswordAge * 86400),

					force_logoff = currentInfo.force_logoff,
					password_hist_len = currentInfo.password_hist_len
				};
				*(USER_MODALS_INFO_0*)newBuffer = newInfo;

				uint setResult = NativeMethods.NetUserModalsSet(null, 0, newBuffer, out uint parmErr);
				return setResult == SecurityPolicyReader.NERR_Success;
			}
			finally
			{
				_ = NativeMethods.NetApiBufferFree(newBuffer);
			}
		}
		finally
		{
			_ = NativeMethods.NetApiBufferFree(buffer);
		}
	}

	/// <summary>
	/// Sets the minimum password length for the [System Access] section.
	/// </summary>
	/// <param name="minimumPasswordLength"></param>
	/// <returns></returns>
	internal unsafe static bool SetMinimumPasswordLength(int minimumPasswordLength)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 0, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			return false;
		}

		try
		{
			USER_MODALS_INFO_0 currentInfo = *(USER_MODALS_INFO_0*)buffer;

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)sizeof(USER_MODALS_INFO_0), out nint newBuffer);
			if (allocResult != SecurityPolicyReader.NERR_Success)
			{
				return false;
			}

			try
			{
				USER_MODALS_INFO_0 newInfo = new()
				{
					min_passwd_len = (uint)minimumPasswordLength,
					max_passwd_age = currentInfo.max_passwd_age,
					min_passwd_age = currentInfo.min_passwd_age,
					force_logoff = currentInfo.force_logoff,
					password_hist_len = currentInfo.password_hist_len
				};
				*(USER_MODALS_INFO_0*)newBuffer = newInfo;

				uint setResult = NativeMethods.NetUserModalsSet(null, 0, newBuffer, out uint parmErr);
				return setResult == SecurityPolicyReader.NERR_Success;
			}
			finally
			{
				_ = NativeMethods.NetApiBufferFree(newBuffer);
			}
		}
		finally
		{
			_ = NativeMethods.NetApiBufferFree(buffer);
		}
	}

	/// <summary>
	/// Sets the passwordHistorySize for the [System Access] section.
	/// </summary>
	/// <param name="passwordHistorySize"></param>
	/// <returns></returns>
	internal unsafe static bool SetPasswordHistorySize(int passwordHistorySize)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 0, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			return false;
		}

		try
		{
			USER_MODALS_INFO_0 currentInfo = *(USER_MODALS_INFO_0*)buffer;

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)sizeof(USER_MODALS_INFO_0), out nint newBuffer);
			if (allocResult != SecurityPolicyReader.NERR_Success)
			{
				return false;
			}

			try
			{
				USER_MODALS_INFO_0 newInfo = new()
				{
					min_passwd_len = currentInfo.min_passwd_len,
					max_passwd_age = currentInfo.max_passwd_age,
					min_passwd_age = currentInfo.min_passwd_age,
					force_logoff = currentInfo.force_logoff,
					password_hist_len = (uint)passwordHistorySize
				};
				*(USER_MODALS_INFO_0*)newBuffer = newInfo;

				uint setResult = NativeMethods.NetUserModalsSet(null, 0, newBuffer, out uint parmErr);
				return setResult == SecurityPolicyReader.NERR_Success;
			}
			finally
			{
				_ = NativeMethods.NetApiBufferFree(newBuffer);
			}
		}
		finally
		{
			_ = NativeMethods.NetApiBufferFree(buffer);
		}
	}

	/// <summary>
	/// Sets 3 properties for the [System Access] section at the same time.
	/// </summary>
	/// <param name="lockoutBadCount"></param>
	/// <param name="resetLockoutCount"></param>
	/// <param name="lockoutDuration"></param>
	/// <returns></returns>
	internal unsafe static bool SetLockoutPolicy(int lockoutBadCount, int resetLockoutCount, int lockoutDuration)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 3, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			return false;
		}

		try
		{
			USER_MODALS_INFO_3 currentInfo = *(USER_MODALS_INFO_3*)buffer;

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)sizeof(USER_MODALS_INFO_3), out nint newBuffer);
			if (allocResult != SecurityPolicyReader.NERR_Success)
			{
				return false;
			}

			try
			{
				USER_MODALS_INFO_3 newInfo = new()
				{
					lockout_threshold = (uint)lockoutBadCount,

					// Convert minutes to seconds by multiplying by 60
					lockout_observation_window = resetLockoutCount == -1 ? uint.MaxValue : (uint)(resetLockoutCount * 60),

					// Convert minutes to seconds by multiplying by 60
					lockout_duration = lockoutDuration == -1 ? uint.MaxValue : (uint)(lockoutDuration * 60)
				};
				*(USER_MODALS_INFO_3*)newBuffer = newInfo;

				uint setResult = NativeMethods.NetUserModalsSet(null, 3, newBuffer, out uint parmErr);
				return setResult == SecurityPolicyReader.NERR_Success;
			}
			finally
			{
				_ = NativeMethods.NetApiBufferFree(newBuffer);
			}
		}
		finally
		{
			_ = NativeMethods.NetApiBufferFree(buffer);
		}
	}

	/// <summary>
	/// Sets the lockoutBadCount individually. Use SetLockoutPolicy for setting 3 policies at the same time.
	/// </summary>
	/// <param name="lockoutBadCount"></param>
	/// <returns></returns>
	internal unsafe static void SetLockoutBadCount(int lockoutBadCount)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 3, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			throw new InvalidOperationException("Failed to retrieve current user modals information.");
		}

		try
		{
			USER_MODALS_INFO_3 currentInfo = *(USER_MODALS_INFO_3*)buffer;

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)sizeof(USER_MODALS_INFO_3), out nint newBuffer);
			if (allocResult != SecurityPolicyReader.NERR_Success)
			{
				throw new InvalidOperationException("Failed to allocate memory for new user modals information.");
			}

			try
			{
				USER_MODALS_INFO_3 newInfo = new()
				{
					lockout_threshold = (uint)lockoutBadCount,
					lockout_observation_window = currentInfo.lockout_observation_window,
					lockout_duration = currentInfo.lockout_duration
				};
				*(USER_MODALS_INFO_3*)newBuffer = newInfo;

				uint setResult = NativeMethods.NetUserModalsSet(null, 3, newBuffer, out uint parmErr);
				if (setResult != SecurityPolicyReader.NERR_Success)
				{
					throw new InvalidOperationException("Failed to set user modals information. Error code: " + setResult);
				}
			}
			finally
			{
				_ = NativeMethods.NetApiBufferFree(newBuffer);
			}
		}
		finally
		{
			_ = NativeMethods.NetApiBufferFree(buffer);
		}
	}

	/// <summary>
	/// Sets the resetLockoutCount individually. Use SetLockoutPolicy for setting 3 policies at the same time.
	/// </summary>
	/// <param name="resetLockoutCount"></param>
	/// <returns></returns>
	internal unsafe static void SetResetLockoutCount(int resetLockoutCount)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 3, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			throw new InvalidOperationException("Failed to retrieve current user modals information.");
		}

		try
		{
			USER_MODALS_INFO_3 currentInfo = *(USER_MODALS_INFO_3*)buffer;

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)sizeof(USER_MODALS_INFO_3), out nint newBuffer);
			if (allocResult != SecurityPolicyReader.NERR_Success)
			{
				throw new InvalidOperationException("Failed to allocate memory for new user modals information.");
			}

			try
			{
				USER_MODALS_INFO_3 newInfo = new()
				{
					lockout_threshold = currentInfo.lockout_threshold,

					// Convert minutes to seconds by multiplying by 60
					lockout_observation_window = resetLockoutCount == -1 ? uint.MaxValue : (uint)(resetLockoutCount * 60),

					lockout_duration = currentInfo.lockout_duration
				};
				*(USER_MODALS_INFO_3*)newBuffer = newInfo;

				uint setResult = NativeMethods.NetUserModalsSet(null, 3, newBuffer, out uint parmErr);
				if (setResult != SecurityPolicyReader.NERR_Success)
				{
					throw new InvalidOperationException("Failed to set user modals information. Error code: " + setResult);
				}
			}
			finally
			{
				_ = NativeMethods.NetApiBufferFree(newBuffer);
			}
		}
		finally
		{
			_ = NativeMethods.NetApiBufferFree(buffer);
		}
	}

	/// <summary>
	/// Sets the lockoutDuration individually. Use SetLockoutPolicy for setting 3 policies at the same time.
	/// </summary>
	/// <param name="lockoutDuration"></param>
	/// <returns></returns>
	internal unsafe static void SetLockoutDuration(int lockoutDuration)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 3, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			throw new InvalidOperationException("Failed to retrieve current user modals information.");
		}

		try
		{
			USER_MODALS_INFO_3 currentInfo = *(USER_MODALS_INFO_3*)buffer;

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)sizeof(USER_MODALS_INFO_3), out nint newBuffer);
			if (allocResult != SecurityPolicyReader.NERR_Success)
			{
				throw new InvalidOperationException("Failed to allocate memory for new user modals information.");
			}

			try
			{
				USER_MODALS_INFO_3 newInfo = new()
				{
					lockout_threshold = currentInfo.lockout_threshold,
					lockout_observation_window = currentInfo.lockout_observation_window,

					// Convert minutes to seconds by multiplying by 60
					lockout_duration = lockoutDuration == -1 ? uint.MaxValue : (uint)(lockoutDuration * 60)
				};
				*(USER_MODALS_INFO_3*)newBuffer = newInfo;

				uint setResult = NativeMethods.NetUserModalsSet(null, 3, newBuffer, out uint parmErr);
				if (setResult != SecurityPolicyReader.NERR_Success)
				{
					throw new InvalidOperationException("Failed to set user modals information. Error code: " + setResult);
				}
			}
			finally
			{
				_ = NativeMethods.NetApiBufferFree(newBuffer);
			}
		}
		finally
		{
			_ = NativeMethods.NetApiBufferFree(buffer);
		}
	}
}
