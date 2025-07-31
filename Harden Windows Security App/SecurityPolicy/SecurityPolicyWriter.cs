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
using System.Collections.Generic;
using System.Runtime.InteropServices;
using AppControlManager;
using AppControlManager.Others;
using Microsoft.Win32;

namespace HardenWindowsSecurity.SecurityPolicy;

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
	internal static bool SetPasswordAge(int minimumPasswordAge, int maximumPasswordAge)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 0, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			return false;
		}

		try
		{
			USER_MODALS_INFO_0 currentInfo = Marshal.PtrToStructure<USER_MODALS_INFO_0>(buffer);

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)Marshal.SizeOf<USER_MODALS_INFO_0>(), out nint newBuffer);
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

				Marshal.StructureToPtr(newInfo, newBuffer, false);

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
	internal static bool SetMinimumPasswordLength(int minimumPasswordLength)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 0, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			return false;
		}

		try
		{
			USER_MODALS_INFO_0 currentInfo = Marshal.PtrToStructure<USER_MODALS_INFO_0>(buffer);

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)Marshal.SizeOf<USER_MODALS_INFO_0>(), out nint newBuffer);
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

				Marshal.StructureToPtr(newInfo, newBuffer, false);

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
	internal static bool SetPasswordHistorySize(int passwordHistorySize)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 0, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			return false;
		}

		try
		{
			USER_MODALS_INFO_0 currentInfo = Marshal.PtrToStructure<USER_MODALS_INFO_0>(buffer);

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)Marshal.SizeOf<USER_MODALS_INFO_0>(), out nint newBuffer);
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

				Marshal.StructureToPtr(newInfo, newBuffer, false);

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
	internal static bool SetLockoutPolicy(int lockoutBadCount, int resetLockoutCount, int lockoutDuration)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 3, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			return false;
		}

		try
		{
			USER_MODALS_INFO_3 currentInfo = Marshal.PtrToStructure<USER_MODALS_INFO_3>(buffer);

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)Marshal.SizeOf<USER_MODALS_INFO_3>(), out nint newBuffer);
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

				Marshal.StructureToPtr(newInfo, newBuffer, false);

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
	internal static void SetLockoutBadCount(int lockoutBadCount)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 3, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			throw new InvalidOperationException("Failed to retrieve current user modals information.");
		}

		try
		{
			USER_MODALS_INFO_3 currentInfo = Marshal.PtrToStructure<USER_MODALS_INFO_3>(buffer);

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)Marshal.SizeOf<USER_MODALS_INFO_3>(), out nint newBuffer);
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

				Marshal.StructureToPtr(newInfo, newBuffer, false);

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
	internal static void SetResetLockoutCount(int resetLockoutCount)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 3, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			throw new InvalidOperationException("Failed to retrieve current user modals information.");
		}

		try
		{
			USER_MODALS_INFO_3 currentInfo = Marshal.PtrToStructure<USER_MODALS_INFO_3>(buffer);

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)Marshal.SizeOf<USER_MODALS_INFO_3>(), out nint newBuffer);
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

				Marshal.StructureToPtr(newInfo, newBuffer, false);

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
	internal static void SetLockoutDuration(int lockoutDuration)
	{
		// Get current settings first
		uint result = NativeMethods.NetUserModalsGet(null, 3, out nint buffer);
		if (result != SecurityPolicyReader.NERR_Success || buffer == IntPtr.Zero)
		{
			throw new InvalidOperationException("Failed to retrieve current user modals information.");
		}

		try
		{
			USER_MODALS_INFO_3 currentInfo = Marshal.PtrToStructure<USER_MODALS_INFO_3>(buffer);

			// Allocate new buffer for setting
			uint allocResult = NativeMethods.NetApiBufferAllocate((uint)Marshal.SizeOf<USER_MODALS_INFO_3>(), out nint newBuffer);
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

				Marshal.StructureToPtr(newInfo, newBuffer, false);

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
