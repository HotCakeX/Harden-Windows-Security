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
using System.Globalization;
using System.Linq;
using AppControlManager.Others;
using HardenWindowsSecurity.GroupPolicy;
using Microsoft.Win32;

namespace HardenWindowsSecurity.SecurityPolicy;

internal static class SecurityPolicyRegistryManager
{
	/// <summary>
	/// Applies multiple security policy registry entries in bulk.
	/// For source 2 (SecurityPolicyRegistry), applying means setting the registry value to the RegValue.
	/// </summary>
	/// <param name="policies">List of security policy registry entries to apply</param>
	internal static void AddPoliciesToSystem(List<RegistryPolicyEntry> policies)
	{
		List<string> appliedEntries = [];

		foreach (RegistryPolicyEntry policy in policies)
		{
			// Validate that DefaultRegValue is not null for SecurityPolicyRegistry entries
			if (policy.DefaultRegValue is null)
			{
				throw new InvalidOperationException($"SecurityPolicyRegistry entry {policy.KeyName}\\{policy.ValueName} must have a non-null DefaultRegValue");
			}

			// Parse registry path to extract the actual registry path
			string registryPath = ParseRegistryPath(policy.KeyName);

			// Apply the security policy registry value
			bool success = SecurityPolicyWriter.SetRegistrySecurityValue(
				registryPath,
				policy.ValueName,
				ConvertRegValueToObject(policy.RegValue!, policy.Type),
				ConvertToRegistryValueKind(policy.Type)
			);

			if (success)
			{
				appliedEntries.Add($"APPLIED: {policy.KeyName}\\{policy.ValueName}");
			}
			else
			{
				throw new InvalidOperationException($"ERROR applying security policy registry entry {policy.KeyName}\\{policy.ValueName}: SetRegistrySecurityValue returned false");
			}
		}

		foreach (string appliedEntry in appliedEntries)
		{
			Logger.Write(appliedEntry);
		}

		Logger.Write($"Security policy registry application complete: {appliedEntries.Count} of {policies.Count} policies applied successfully");
	}

	/// <summary>
	/// Removes multiple security policy registry entries in bulk.
	/// For source 2 (SecurityPolicyRegistry), removing means setting the registry value to the DefaultRegValue.
	/// Security Group Policies that have Type 4 (DWORD) and appear as (4,) in the INF backup file of Secedit, are actually 0 so the DefaultRegValue in the JSON files are set to 0 for them.
	/// </summary>
	/// <param name="policies">List of security policy registry entries to remove</param>
	internal static void RemovePoliciesFromSystem(List<RegistryPolicyEntry> policies)
	{
		List<string> removedEntries = [];

		foreach (RegistryPolicyEntry policy in policies)
		{
			// Validate that DefaultRegValue is not null for SecurityPolicyRegistry entries
			if (policy.DefaultRegValue is null)
			{
				throw new InvalidOperationException($"SecurityPolicyRegistry entry {policy.KeyName}\\{policy.ValueName} must have a non-null DefaultRegValue");
			}

			// Parse registry path to extract the actual registry path
			string registryPath = ParseRegistryPath(policy.KeyName);

			// Remove (reset to default) the security policy registry value
			bool success = SecurityPolicyWriter.SetRegistrySecurityValue(
				registryPath,
				policy.ValueName,
				ConvertRegValueToObject(policy.DefaultRegValue, policy.Type),
				ConvertToRegistryValueKind(policy.Type)
			);

			if (success)
			{
				removedEntries.Add($"RESET TO DEFAULT: {policy.KeyName}\\{policy.ValueName}");
			}
			else
			{
				throw new InvalidOperationException($"ERROR removing security policy registry entry {policy.KeyName}\\{policy.ValueName}: SetRegistrySecurityValue returned false");
			}
		}

		foreach (string removedEntry in removedEntries)
		{
			Logger.Write(removedEntry);
		}

		Logger.Write($"Security policy registry removal complete: {removedEntries.Count} of {policies.Count} policies removed successfully");
	}

	/// <summary>
	/// Verifies multiple security policy registry entries in bulk.
	/// </summary>
	/// <param name="policies">List of security policy registry entries to verify</param>
	/// <returns>Dictionary with policies as keys and verification results as values</returns>
	internal static Dictionary<RegistryPolicyEntry, bool> VerifyPoliciesInSystem(List<RegistryPolicyEntry> policies)
	{
		Dictionary<RegistryPolicyEntry, bool> verificationResults = [];

		// Get current security policy information
		SecurityPolicyInfo securityPolicy = SecurityPolicyReader.GetSecurityPolicyInfo();
		List<RegistryValue> registryValues = securityPolicy.RegistryValues;

		foreach (RegistryPolicyEntry policy in policies)
		{
			try
			{
				// Find the corresponding registry value in the security policy
				RegistryValue? registryValue = registryValues.FirstOrDefault(rv =>
					string.Equals(rv.Name, policy.KeyName, StringComparison.OrdinalIgnoreCase));

				bool isVerified = false;

				if (registryValue != null && policy.RegValue is not null)
				{
					// Compare the values based on the registry type
					isVerified = CompareSecurityPolicyValues(policy.Type, registryValue.Value, policy.RegValue);
				}

				verificationResults[policy] = isVerified;
				Logger.Write($"VERIFY: {policy.KeyName}\\{policy.ValueName} = {(isVerified ? "MATCH" : "MISMATCH")}");
			}
			catch (Exception ex)
			{
				verificationResults[policy] = false;
				throw new InvalidOperationException($"ERROR verifying security policy registry entry {policy.KeyName}\\{policy.ValueName}: {ex.Message}");
			}
		}

		Logger.Write($"Security policy registry verification complete: {verificationResults.Count(kvp => kvp.Value)} of {policies.Count} policies match");
		return verificationResults;
	}

	/// <summary>
	/// Parses the registry path from the KeyName to extract the actual registry path.
	/// Removes the "MACHINE\" prefix if present.
	/// </summary>
	/// <param name="keyName">The key name from the policy entry</param>
	/// <returns>The parsed registry path</returns>
	private static string ParseRegistryPath(string keyName)
	{
		// If the keyName starts with "MACHINE\", return it as-is for SecurityPolicyWriter
		if (keyName.StartsWith("MACHINE\\", StringComparison.OrdinalIgnoreCase))
		{
			return keyName;
		}

		// Otherwise, prepend "MACHINE\" to make it compatible with SecurityPolicyWriter
		return $"MACHINE\\{keyName}";
	}

	/// <summary>
	/// Converts a string RegValue to the appropriate object type based on the registry type.
	/// </summary>
	/// <param name="regValue">The string value to convert</param>
	/// <param name="type">The registry value type</param>
	/// <returns>The converted object</returns>
	private static object ConvertRegValueToObject(string regValue, RegistryValueType type)
	{
		return type switch
		{
			RegistryValueType.REG_SZ or RegistryValueType.REG_EXPAND_SZ => regValue,
			RegistryValueType.REG_DWORD => int.Parse(regValue, NumberStyles.Integer, CultureInfo.InvariantCulture),
			RegistryValueType.REG_QWORD => long.Parse(regValue, NumberStyles.Integer, CultureInfo.InvariantCulture),
			RegistryValueType.REG_BINARY => Convert.FromBase64String(regValue),
			RegistryValueType.REG_MULTI_SZ => regValue.Split(',', StringSplitOptions.None),
			_ => regValue
		};
	}

	/// <summary>
	/// Converts a RegistryValueType to RegistryValueKind.
	/// </summary>
	/// <param name="type">The registry value type</param>
	/// <returns>The corresponding RegistryValueKind</returns>
	private static RegistryValueKind ConvertToRegistryValueKind(RegistryValueType type)
	{
		return type switch
		{
			RegistryValueType.REG_SZ => RegistryValueKind.String,
			RegistryValueType.REG_EXPAND_SZ => RegistryValueKind.ExpandString,
			RegistryValueType.REG_DWORD => RegistryValueKind.DWord,
			RegistryValueType.REG_QWORD => RegistryValueKind.QWord,
			RegistryValueType.REG_BINARY => RegistryValueKind.Binary,
			RegistryValueType.REG_MULTI_SZ => RegistryValueKind.MultiString,
			_ => RegistryValueKind.String
		};
	}

	/// <summary>
	/// Compares security policy registry values based on their type.
	/// </summary>
	/// <param name="type">Registry value type</param>
	/// <param name="actualValue">Actual value from security policy</param>
	/// <param name="expectedValue">Expected value</param>
	/// <returns>True if values match, false otherwise</returns>
	private static bool CompareSecurityPolicyValues(RegistryValueType type, string actualValue, string expectedValue)
	{
		try
		{
			return type switch
			{
				RegistryValueType.REG_SZ or RegistryValueType.REG_EXPAND_SZ =>
					string.Equals(actualValue.Trim('"'), expectedValue, StringComparison.OrdinalIgnoreCase),

				RegistryValueType.REG_DWORD =>
					int.TryParse(actualValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out int actualDword) &&
					int.TryParse(expectedValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out int expectedDword) &&
					actualDword == expectedDword,

				RegistryValueType.REG_QWORD =>
					long.TryParse(actualValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out long actualQword) &&
					long.TryParse(expectedValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out long expectedQword) &&
					actualQword == expectedQword,

				RegistryValueType.REG_MULTI_SZ =>
					CompareMultiStringSecurityPolicyValues(actualValue, expectedValue),

				RegistryValueType.REG_BINARY =>
					string.Equals(actualValue, expectedValue, StringComparison.OrdinalIgnoreCase),

				_ => string.Equals(actualValue, expectedValue, StringComparison.OrdinalIgnoreCase)
			};
		}
		catch
		{
			return false;
		}
	}

	/// <summary>
	/// Compares multi-string security policy registry values.
	/// </summary>
	/// <param name="actualValue">Actual multi-string value (newline separated from security policy)</param>
	/// <param name="expectedValue">Expected multi-string value (comma separated from JSON)</param>
	/// <returns>True if values match, false otherwise</returns>
	private static bool CompareMultiStringSecurityPolicyValues(string actualValue, string expectedValue)
	{
		// Security policy multi-string values are newline separated
		string[] actualArray = actualValue.Split('\n', StringSplitOptions.RemoveEmptyEntries);
		// Expected values are comma separated
		string[] expectedArray = expectedValue.Split(',', StringSplitOptions.None);

		return actualArray.Length == expectedArray.Length &&
			   actualArray.SequenceEqual(expectedArray, StringComparer.OrdinalIgnoreCase);
	}
}
