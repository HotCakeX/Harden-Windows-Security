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
using System.Linq;
using HardenSystemSecurity.GroupPolicy;
using Microsoft.Win32;

namespace HardenSystemSecurity.SecurityPolicy;

internal static class SecurityPolicyRegistryManager
{
	/// <summary>
	/// Applies multiple security policy registry entries in bulk.
	/// For source 2 (SecurityPolicyRegistry), applying means setting the registry value to the RegValue.
	/// These are items under the "[Registry Values]" section in the Secedit exported INF data.
	/// </summary>
	/// <param name="policies">List of security policy registry entries to apply</param>
	internal static void AddPoliciesToSystem(List<RegistryPolicyEntry> policies)
	{
		List<string> appliedEntries = [];

		foreach (RegistryPolicyEntry policy in policies)
		{

			// Not Checking if policy.DefaultRegValue is null here since the policies from Microsoft Security Baselines don't assign this info!

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
		List<RegistryValue> registryValues = SecurityPolicyReader.GetRegistryValues();

		foreach (RegistryPolicyEntry policy in policies)
		{
			try
			{
				// Build the INF-style full name: "MACHINE\<keyPath>\<valueName>" to match SecurityPolicyReader output
				string expectedName = string.Concat(ParseRegistryPath(policy.KeyName), "\\", policy.ValueName);

				// Find the corresponding registry value using the INF-style identifier
				RegistryValue? registryValue = registryValues.FirstOrDefault(
					rv => string.Equals(rv.Name, expectedName, StringComparison.OrdinalIgnoreCase));

				bool isVerified = false;

				if (registryValue != null && policy.RegValue is not null)
				{
					// Compare the values based on the registry type
					isVerified = CompareSecurityPolicyValues(policy.Type, registryValue.Value, policy.RegValue);
				}

				verificationResults[policy] = isVerified;

				if (isVerified)
				{
					// Match
					Logger.Write($"VERIFY: {policy.KeyName}\\{policy.ValueName} = MATCH");
				}
				else
				{
					// Mismatch
					string actualDisplay = registryValue?.Value ?? "<not found>";
					string expectedDisplay = policy.RegValue ?? "<null>";
					Logger.Write($"VERIFY: {policy.KeyName}\\{policy.ValueName} = MISMATCH (expected: {expectedDisplay}, actual: {actualDisplay})");
				}
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
	/// The reason "MACHINE" is prepended is because the INF file exported by Secedit uses "MACHINE" to denote HKEY_LOCAL_MACHINE and it doesn't write to any other HIVE.
	/// If that changes in the future, we'll have to change this logic accordingly.
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
	/// Robust for both INF (Secedit outputs) and JSON sources (The App's resources):
	/// - REG_BINARY: accepts base64 (from JSON file) or textual INF (Secedit) forms (comma-separated decimal bytes, tokens as hex, contiguous hex pairs, single decimal).
	/// - REG_MULTI_SZ: accepts newline, semicolon, or comma-delimited lists; empty => zero-length array.
	/// </summary>
	/// <param name="regValue">The string value to convert</param>
	/// <param name="type">The registry value type</param>
	/// <returns>The converted object</returns>
	private static object ConvertRegValueToObject(string regValue, RegistryValueType type)
	{
		switch (type)
		{
			case RegistryValueType.REG_SZ:
			case RegistryValueType.REG_EXPAND_SZ:
				{
					return regValue;
				}

			case RegistryValueType.REG_DWORD:
				{
					int parsed = int.Parse(regValue, NumberStyles.Integer, CultureInfo.InvariantCulture);
					return parsed;
				}

			case RegistryValueType.REG_QWORD:
				{
					long parsed = long.Parse(regValue, NumberStyles.Integer, CultureInfo.InvariantCulture);
					return parsed;
				}

			case RegistryValueType.REG_BINARY:
				{
					if (!TryParseBinaryFlexible(regValue, out byte[] bytes))
					{
						throw new InvalidOperationException($"Could not parse REG_BINARY value from \"{regValue}\".");
					}
					return bytes;
				}

			case RegistryValueType.REG_MULTI_SZ:
				{
					string[] items = SplitMultiStringFlexible(regValue);
					return items;
				}

			case RegistryValueType.REG_NONE:
			case RegistryValueType.REG_DWORD_BIG_ENDIAN:
			case RegistryValueType.REG_LINK:
			case RegistryValueType.REG_RESOURCE_LIST:
			case RegistryValueType.REG_FULL_RESOURCE_DESCRIPTOR:
			case RegistryValueType.REG_RESOURCE_REQUIREMENTS_LIST:
				return regValue;
			default:
				{
					return regValue;
				}
		}
	}

	/// <summary>
	/// Attempts to parse a binary string value in multiple formats:
	/// - Comma-separated decimals: "1,2,255"
	/// - Comma-separated hex tokens: "0A,FF" (with optional 0x prefix per token)
	/// - Single decimal: "0"
	/// - Contiguous hex string (even length): "0001FF"
	/// - Base64: From the app's JSON files
	/// Returns true if parsing succeeded.
	/// </summary>
	private static bool TryParseBinaryFlexible(string input, out byte[] bytes)
	{
		string s = input is null ? string.Empty : input.Trim();
		if (s.Length == 0)
		{
			bytes = [];
			return true;
		}

		// Comma-separated tokens (decimal or hex)
		if (s.Contains(',', StringComparison.OrdinalIgnoreCase))
		{
			string[] tokens = s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
			if (tokens.Length == 0)
			{
				bytes = [];
				return true;
			}

			// Detect if any token is hex-like (has A-F or starts with 0x)
			bool anyHex = false;
			for (int i = 0; i < tokens.Length; i++)
			{
				string tk = tokens[i];
				if (tk.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
				{
					anyHex = true;
					break;
				}
				for (int j = 0; j < tk.Length; j++)
				{
					char c = tk[j];
					if ((c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))
					{
						anyHex = true;
						break;
					}
				}
				if (anyHex) break;
			}

			byte[] result = new byte[tokens.Length];
			for (int i = 0; i < tokens.Length; i++)
			{
				string tk = tokens[i];
				if (tk.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
				{
					tk = tk[2..];
				}

				bool ok = anyHex
					? byte.TryParse(tk, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte b)
					: byte.TryParse(tk, NumberStyles.Integer, CultureInfo.InvariantCulture, out b);

				if (!ok)
				{
					bytes = [];
					return false;
				}
				result[i] = b;
			}

			bytes = result;
			return true;
		}

		// Contiguous even-length hex string?
		if (IsHexStringEvenLength(s))
		{
			int len = s.Length / 2;
			byte[] result = new byte[len];
			for (int i = 0; i < len; i++)
			{
				ReadOnlySpan<char> pair = s.AsSpan(i * 2, 2);
				if (!byte.TryParse(pair, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out result[i]))
				{
					bytes = [];
					return false;
				}
			}
			bytes = result;
			return true;
		}

		// Single decimal byte?
		if (byte.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out byte single))
		{
			bytes = [single];
			return true;
		}

		// Base64 (JSON path)
		try
		{
			byte[] b64 = Convert.FromBase64String(s);
			bytes = b64;
			return true;
		}
		catch
		{
			// Fall through
		}

		bytes = [];
		return false;
	}

	/// <summary>
	/// Returns true if s is an even-length string of only hex digits 0-9A-Fa-f.
	/// </summary>
	private static bool IsHexStringEvenLength(string s)
	{
		if ((s.Length & 1) != 0) return false;
		for (int i = 0; i < s.Length; i++)
		{
			char c = s[i];
			bool isDigit = c >= '0' && c <= '9';
			bool isUpper = c >= 'A' && c <= 'F';
			bool isLower = c >= 'a' && c <= 'f';
			if (!isDigit && !isUpper && !isLower) return false;
		}
		return true;
	}

	/// <summary>
	/// Splits a multi-string payload accepting newline, semicolon, or comma as delimiters.
	/// Empty input => zero-length array. Trims entries and drops empties.
	/// </summary>
	private static string[] SplitMultiStringFlexible(string input)
	{
		if (string.IsNullOrEmpty(input))
		{
			return [];
		}

		// Normalize line endings
		string normalized = input.Replace("\r\n", "\n", StringComparison.OrdinalIgnoreCase);

		if (normalized.Contains('\n', StringComparison.OrdinalIgnoreCase))
		{
			return normalized.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
		}
		if (normalized.Contains(';', StringComparison.OrdinalIgnoreCase))
		{
			return normalized.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
		}
		if (normalized.Contains(',', StringComparison.OrdinalIgnoreCase))
		{
			return normalized.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
		}

		return [normalized.Trim()];
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
	/// <param name="actualValue">Actual multi-string value (newline separated from security policy in the System)</param>
	/// <param name="expectedValue">Expected multi-string value (comma separated from JSON in the app resources)</param>
	/// <returns>True if values match, false otherwise</returns>
	private static bool CompareMultiStringSecurityPolicyValues(string actualValue, string expectedValue)
	{
		// Normalize nulls
		string actualNormalized = actualValue ?? string.Empty;
		string expectedNormalized = expectedValue ?? string.Empty;

		// Security policy multi-string values are newline separated; trim entries and drop empties
		string[] actualArray = actualNormalized.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

		// Expected values are comma separated; if empty, treat as zero-length list
		if (expectedNormalized.Length == 0)
		{
			return actualArray.Length == 0;
		}

		// Trim entries and drop empties to avoid whitespace-caused mismatches
		string[] expectedArray = expectedNormalized.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

		// Compare length and sequence (case-insensitive); order-sensitive by design
		return actualArray.Length == expectedArray.Length &&
			   actualArray.SequenceEqual(expectedArray, StringComparer.OrdinalIgnoreCase);
	}
}
