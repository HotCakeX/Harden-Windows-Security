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
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace HardenWindowsSecurity;

/// <summary>
/// This class is responsible for querying effective Audit policy information on the system.
/// It uses registry instead of using cmdlets such as: (auditpol /get /subcategory:"Other Logon/Logoff Events" /r | ConvertFrom-Csv).'Inclusion Setting'
/// because they contain culture specific data that make verification hard.
/// </summary>
internal static class AuditPolicyHelper
{
	// Path to the registry key where audit policies are saved
	// They are normally visible only to SYSTEM
	private const string SubKeyPath = "SECURITY";

	// Defining a new access rule that grants the BUILTIN\Administrators group full control and also will be used for removal
	private static readonly RegistryAccessRule rule = new(
		 new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
		 RegistryRights.FullControl,
		 InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
		 PropagationFlags.None,
		 AccessControlType.Allow
	 );

	/// <summary>
	/// Checks if the BUILTIN\Administrators group has full control access to the specified registry key.
	/// </summary>
	/// <returns>True if the BUILTIN\Administrators have full control, otherwise false.</returns>
	private static bool CheckAdministratorsAccess()
	{
		try
		{
			// Attempt to open the registry key with read permissions to check access rights
			using RegistryKey key = Registry.LocalMachine.OpenSubKey(SubKeyPath, RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadPermissions)
				?? throw new InvalidOperationException($"Failed to open registry key: {SubKeyPath}");

			// Retrieve the access control settings for the registry key
			RegistrySecurity security = key.GetAccessControl();

			// Get all the access rules for the registry key
			AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(NTAccount));

			foreach (AuthorizationRule rule in rules)
			{
				// Check if the access rule applies to the BUILTIN\Administrators group
				if (rule is RegistryAccessRule accessRule && accessRule.IdentityReference.Value.Contains(@"BUILTIN\Administrators", StringComparison.OrdinalIgnoreCase))
				{
					// Check if the access rule grants full control permissions
					if ((accessRule.RegistryRights & RegistryRights.FullControl) is RegistryRights.FullControl)
					{
						return true; // Return true if full control is granted
					}
				}
			}
		}
		catch (Exception ex)
		{
			// Log any errors encountered during the access check process
			Logger.LogMessage("Error while checking access: " + ex.Message, LogTypeIntel.Error);
		}

		return false; // Return false if access check fails or full control is not granted
	}

	/// <summary>
	/// Grants the BUILTIN\Administrators group full control access to the registry key.
	/// </summary>
	private static void GrantAdministratorsAccess()
	{
		try
		{
			// Open the registry key with permissions to change its ACL
			using RegistryKey key = Registry.LocalMachine.OpenSubKey(SubKeyPath, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions)
				?? throw new InvalidOperationException($"Failed to open registry key: {SubKeyPath}");

			// Add the new access rule to the registry key
			RegistrySecurity newSecurity = key.GetAccessControl();
			newSecurity.AddAccessRule(rule);
			key.SetAccessControl(newSecurity);

			// Log the successful ACL modification
			Logger.LogMessage("Full control access granted to Administrators group.", LogTypeIntel.Information);
		}
		catch (Exception ex)
		{
			// Log any errors encountered during the access granting process
			Logger.LogMessage("Error while granting access: " + ex.Message, LogTypeIntel.Error);
		}
	}

	/// <summary>
	/// Removes the full control access of the BUILTIN\Administrators group from the registry key.
	/// </summary>
	private static void RemoveAdministratorsAccess()
	{
		try
		{
			// Open the registry key with permissions to change its ACL
			using RegistryKey key = Registry.LocalMachine.OpenSubKey(SubKeyPath, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions)
				?? throw new InvalidOperationException($"Failed to open registry key: {SubKeyPath}");

			// Remove the access rule from the registry key
			RegistrySecurity newSecurity = key.GetAccessControl();
			_ = newSecurity.RemoveAccessRule(rule);
			key.SetAccessControl(newSecurity);

			// Log the successful ACL restoration
			Logger.LogMessage("Administrators group's access removed.", LogTypeIntel.Information);
		}
		catch (Exception ex)
		{
			// Log any errors encountered during the access removal process
			Logger.LogMessage("Error while removing access: " + ex.Message, LogTypeIntel.Error);
		}
	}

	/// <summary>
	/// Reads the default value from the PolAdtEv registry key.
	/// </summary>
	/// <returns>The default value of the key as a byte array, or null if the read operation fails.</returns>
	private static ReadOnlySpan<byte> ReadDefaultValueFromPolAdtEv()
	{
		const string policyKeyPath = @"SECURITY\Policy\PolAdtEv";
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(policyKeyPath, RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadKey)
				?? throw new InvalidOperationException($"Failed to open registry key: HKEY_LOCAL_MACHINE {policyKeyPath}");
			object? value = key.GetValue("");

			if (value is byte[] byteArray)
			{
				// Log the successful read operation
				Logger.LogMessage("Successfully read default value from PolAdtEv.", LogTypeIntel.Information);
				return byteArray; // Return the read value as a byte array
			}
			else
			{
				throw new InvalidOperationException("Default value is not a byte array.");
			}
		}
		catch (Exception ex)
		{
			// Log any errors encountered during the read operation
			Logger.LogMessage("Error while reading default value from PolAdtEv: " + ex.Message, LogTypeIntel.Error);
			return null; // Return null if an error occurs
		}
	}

	/// <summary>
	/// Retrieves the audit policies from the registry, handling access permissions as needed.
	/// </summary>
	/// <returns>An AuditPolicies object containing the retrieved audit policies.</returns>
	internal static AuditPolicies GetAuditPolicies()
	{
		bool AdminHasAccess = CheckAdministratorsAccess();

		ReadOnlySpan<byte> registryValues;
		if (AdminHasAccess)
		{
			registryValues = ReadDefaultValueFromPolAdtEv();
		}
		else
		{
			GrantAdministratorsAccess();
			registryValues = ReadDefaultValueFromPolAdtEv();
			RemoveAdministratorsAccess();
		}

		// Parse raw byte data into an AuditPolicies object and return it
		return new AuditPolicies(registryValues);
	}




	internal enum Status
	{
		NotConfigured = 0,
		Success = 1,
		Failure = 2,
		SuccessAndFailure = 3
	}

	internal sealed class AuditPolicies
	{
		internal AccountLogonCategory AccountLogon { get; private set; }
		internal AccountManagementCategory AccountManagement { get; private set; }
		internal DSAccessCategory DSAccess { get; private set; }
		internal DetailedTrackingCategory DetailedTracking { get; private set; }
		internal LogonLogoffCategory LogonLogoff { get; private set; }
		internal ObjectAccessCategory ObjectAccess { get; private set; }
		internal PrivilegeUseCategory PrivilegeUse { get; private set; }
		internal PolicyChangeCategory PolicyChange { get; private set; }
		internal SystemCategory System { get; private set; }

		internal AuditPolicies(ReadOnlySpan<byte> data)
		{
			AccountLogon = new AccountLogonCategory(data);
			AccountManagement = new AccountManagementCategory(data);
			DSAccess = new DSAccessCategory(data);
			DetailedTracking = new DetailedTrackingCategory(data);
			LogonLogoff = new LogonLogoffCategory(data);
			ObjectAccess = new ObjectAccessCategory(data);
			PrivilegeUse = new PrivilegeUseCategory(data);
			PolicyChange = new PolicyChangeCategory(data);
			System = new SystemCategory(data);
		}
	}

	internal sealed class AccountLogonCategory
	{
		internal Status CredentialValidation { get; private set; }
		internal Status KerberosServiceTicketOperations { get; private set; }
		internal Status OtherAccountLogonEvents { get; private set; }

		internal AccountLogonCategory(ReadOnlySpan<byte> data)
		{
			CredentialValidation = (Status)data[122];
			KerberosServiceTicketOperations = (Status)data[124];
			OtherAccountLogonEvents = (Status)data[126];
		}
	}

	internal sealed class AccountManagementCategory
	{
		internal Status UserAccountManagement { get; private set; }
		internal Status ComputerAccountManagement { get; private set; }
		internal Status SecurityGroupManagement { get; private set; }
		internal Status DistributionGroupManagement { get; private set; }
		internal Status ApplicationGroupManagement { get; private set; }
		internal Status OtherAccountManagementEvents { get; private set; }

		internal AccountManagementCategory(ReadOnlySpan<byte> data)
		{
			UserAccountManagement = (Status)data[102];
			ComputerAccountManagement = (Status)data[104];
			SecurityGroupManagement = (Status)data[106];
			DistributionGroupManagement = (Status)data[108];
			ApplicationGroupManagement = (Status)data[110];
			OtherAccountManagementEvents = (Status)data[112];
		}
	}

	internal sealed class DSAccessCategory
	{
		internal Status DirectoryServiceAccess { get; private set; }
		internal Status DirectoryServiceChanges { get; private set; }
		internal Status DirectoryServiceReplication { get; private set; }
		internal Status DetailedDirectoryServiceReplication { get; private set; }

		internal DSAccessCategory(ReadOnlySpan<byte> data)
		{
			DirectoryServiceAccess = (Status)data[114];
			DirectoryServiceChanges = (Status)data[116];
			DirectoryServiceReplication = (Status)data[118];
			DetailedDirectoryServiceReplication = (Status)data[120];
		}
	}

	internal sealed class DetailedTrackingCategory
	{
		internal Status ProcessCreation { get; private set; }
		internal Status ProcessTermination { get; private set; }
		internal Status DPAPIActivity { get; private set; }
		internal Status RPCEvents { get; private set; }
		internal Status PlugAndPlayEvents { get; private set; }
		internal Status TokenRightAdjustedEvents { get; private set; }

		internal DetailedTrackingCategory(ReadOnlySpan<byte> data)
		{
			ProcessCreation = (Status)data[78];
			ProcessTermination = (Status)data[80];
			DPAPIActivity = (Status)data[82];
			RPCEvents = (Status)data[84];
			PlugAndPlayEvents = (Status)data[86];
			TokenRightAdjustedEvents = (Status)data[88];
		}
	}

	internal sealed class LogonLogoffCategory
	{
		internal Status Logon { get; private set; }
		internal Status Logoff { get; private set; }
		internal Status AccountLockout { get; private set; }
		internal Status IPSecMainMode { get; private set; }
		internal Status SpecialLogon { get; private set; }
		internal Status IPSecQuickMode { get; private set; }
		internal Status IPSecExtendedMode { get; private set; }
		internal Status OtherLogonLogoffEvents { get; private set; }
		internal Status NetworkPolicyServer { get; private set; }
		internal Status UserDeviceClaims { get; private set; }
		internal Status GroupMembership { get; private set; }

		internal LogonLogoffCategory(ReadOnlySpan<byte> data)
		{
			Logon = (Status)data[22];
			Logoff = (Status)data[24];
			AccountLockout = (Status)data[26];
			IPSecMainMode = (Status)data[28];
			SpecialLogon = (Status)data[30];
			IPSecQuickMode = (Status)data[32];
			IPSecExtendedMode = (Status)data[34];
			OtherLogonLogoffEvents = (Status)data[36];
			NetworkPolicyServer = (Status)data[38];
			UserDeviceClaims = (Status)data[40];
			GroupMembership = (Status)data[42];
		}
	}

	internal sealed class ObjectAccessCategory
	{
		internal Status FileSystem { get; private set; }
		internal Status Registry { get; private set; }
		internal Status KernelObject { get; private set; }
		internal Status SAM { get; private set; }
		internal Status OtherObjectAccessEvents { get; private set; }
		internal Status CertificationServices { get; private set; }
		internal Status ApplicationGenerated { get; private set; }
		internal Status HandleManipulation { get; private set; }
		internal Status FileShare { get; private set; }
		internal Status FilteringPlatformPacketDrop { get; private set; }
		internal Status FilteringPlatformConnection { get; private set; }
		internal Status DetailedFileShare { get; private set; }
		internal Status RemovableStorage { get; private set; }
		internal Status CentralPolicyStaging { get; private set; }

		internal ObjectAccessCategory(ReadOnlySpan<byte> data)
		{
			FileSystem = (Status)data[44];
			Registry = (Status)data[46];
			KernelObject = (Status)data[48];
			SAM = (Status)data[50];
			OtherObjectAccessEvents = (Status)data[52];
			CertificationServices = (Status)data[54];
			ApplicationGenerated = (Status)data[56];
			HandleManipulation = (Status)data[58];
			FileShare = (Status)data[60];
			FilteringPlatformPacketDrop = (Status)data[62];
			FilteringPlatformConnection = (Status)data[64];
			DetailedFileShare = (Status)data[66];
			RemovableStorage = (Status)data[68];
			CentralPolicyStaging = (Status)data[70];
		}
	}

	internal sealed class PrivilegeUseCategory
	{
		internal Status SensitivePrivilegeUse { get; private set; }
		internal Status NonSensitivePrivilegeUse { get; private set; }
		internal Status OtherPrivilegeUseEvents { get; private set; }

		internal PrivilegeUseCategory(ReadOnlySpan<byte> data)
		{
			SensitivePrivilegeUse = (Status)data[72];
			NonSensitivePrivilegeUse = (Status)data[74];
			OtherPrivilegeUseEvents = (Status)data[76];
		}
	}

	internal sealed class PolicyChangeCategory
	{
		internal Status AuditPolicyChange { get; private set; }
		internal Status AuthenticationPolicyChange { get; private set; }
		internal Status AuthorizationPolicyChange { get; private set; }
		internal Status MPSSVCRuleLevelPolicyChange { get; private set; }
		internal Status FilteringPlatformPolicyChange { get; private set; }
		internal Status OtherPolicyChangeEvents { get; private set; }

		internal PolicyChangeCategory(ReadOnlySpan<byte> data)
		{
			AuditPolicyChange = (Status)data[90];
			AuthenticationPolicyChange = (Status)data[92];
			AuthorizationPolicyChange = (Status)data[94];
			MPSSVCRuleLevelPolicyChange = (Status)data[96];
			FilteringPlatformPolicyChange = (Status)data[98];
			OtherPolicyChangeEvents = (Status)data[100];
		}
	}

	internal sealed class SystemCategory
	{
		internal Status SecurityStateChange { get; private set; }
		internal Status SecuritySystemExtension { get; private set; }
		internal Status SystemIntegrity { get; private set; }
		internal Status IPSecDriver { get; private set; }
		internal Status OtherSystemEvents { get; private set; }

		internal SystemCategory(ReadOnlySpan<byte> data)
		{
			SecurityStateChange = (Status)data[12];
			SecuritySystemExtension = (Status)data[14];
			SystemIntegrity = (Status)data[16];
			IPSecDriver = (Status)data[18];
			OtherSystemEvents = (Status)data[20];
		}
	}
}
