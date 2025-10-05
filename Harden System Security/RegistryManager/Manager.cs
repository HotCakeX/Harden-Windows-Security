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
using AppControlManager.Others;
using HardenSystemSecurity.GroupPolicy;
using Microsoft.Win32;

namespace HardenSystemSecurity.RegistryManager;

internal static class Manager
{
	private const char Separator = ';';

	/// <summary>
	/// Modifies or removes the <see cref="RegistryPolicyEntry"/> items from the JSON files
	/// whose <see cref="RegistryPolicyEntry.Source"/> is <see cref="Source.Registry"/>.
	/// </summary>
	/// <param name="package"></param>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void EditRegistry(RegistryPolicyEntry package)
	{
		using RegistryKey baseKey = GetBaseRegistryKey(package.hive);
		using RegistryKey subKey = baseKey.OpenSubKey(package.KeyName, writable: true)
           ?? baseKey.CreateSubKey(package.KeyName)
           ?? throw new InvalidOperationException($"Failed to open or create registry key: {package.KeyName}");

		if (package.RegValue is null)
			throw new InvalidOperationException(GlobalVars.GetStr("RegistryKeyDidNotHaveRegValue"));

		switch (package.policyAction)
		{
			case PolicyAction.Apply:
				var (kind, value) = ConvertValue(package.Type, package.RegValue);
				if (value is not null) subKey.SetValue(package.ValueName, value, kind);
				break;

			case PolicyAction.Remove:
				if (package.DefaultRegValue is null)
				{
					if (subKey.GetValue(package.ValueName) is not null)
						subKey.DeleteValue(package.ValueName, throwOnMissingValue: true);
				}
				else
				{
					var (defKind, defValue) = ConvertValue(package.Type, package.DefaultRegValue);
					if (defValue is not null) subKey.SetValue(package.ValueName, defValue, defKind);
				}
				break;

			default:
				throw new ArgumentException(string.Format(GlobalVars.GetStr("InvalidActionSpecified"), package.policyAction));
		}
	}

	/// <summary>
	/// Reads the registry value for the given <see cref="RegistryPolicyEntry"/>.
	/// Returns the raw data converted into the same string form used by RegValue,
	/// or null if the key or value does not exist.
	/// </summary>
	/// <param name="package">The policy entry describing hive, key and value.</param>
	/// <returns>
	/// Stringified registry value (for REG_SZ, REG_DWORD, etc.),
	/// Base64 for binary, or joined strings for multi‑sz; null if not present.
	/// </returns>
	internal static string? ReadRegistry(RegistryPolicyEntry package)
	{
		// Determine base hive
		using RegistryKey baseKey = GetBaseRegistryKey(package.hive);
		// Open subkey readonly
		using RegistryKey? subKey = baseKey.OpenSubKey(package.KeyName, writable: false);

		// Try get the raw value
		object? rawValue = subKey?.GetValue(package.ValueName);
		if (rawValue is null)
			return null;

		// Convert according to expected type
		return package.Type switch
		{
			RegistryValueType.REG_SZ
				=> rawValue as string,

			RegistryValueType.REG_EXPAND_SZ
				=> rawValue as string,

			RegistryValueType.REG_DWORD
				=> ((int)rawValue).ToString(CultureInfo.InvariantCulture),

			RegistryValueType.REG_QWORD
				=> ((long)rawValue).ToString(CultureInfo.InvariantCulture),

			RegistryValueType.REG_BINARY
				=> Convert.ToBase64String((byte[])rawValue),

			RegistryValueType.REG_MULTI_SZ
				=> string.Join(Separator, (string[])rawValue),

			_ => throw new ArgumentException(GlobalVars.GetStr("InvalidRegistryValueType"))
		};
	}

	/// <summary>
	/// Applies multiple registry policies in bulk.
	/// </summary>
	/// <param name="policies">List of registry policies to apply</param>
	internal static void AddPoliciesToSystem(List<RegistryPolicyEntry> policies)
	{
		List<string> appliedEntries = [];

		foreach (RegistryPolicyEntry policy in policies)
		{
			try
			{
				EditRegistry(policy);
				appliedEntries.Add(string.Format(GlobalVars.GetStr("AppliedRegistryEntry"), policy.hive, policy.KeyName, policy.ValueName));
			}
			catch (Exception ex)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("ErrorApplyingRegistryPolicy"), policy.hive, policy.KeyName, policy.ValueName, ex.Message));
			}
		}

		foreach (string appliedEntry in appliedEntries)
		{
			Logger.Write(appliedEntry);
		}

		Logger.Write(string.Format(GlobalVars.GetStr("RegistryApplicationComplete"), appliedEntries.Count, policies.Count));
	}

	/// <summary>
	/// Removes multiple registry policies in bulk.
	/// </summary>
	/// <param name="policies">List of registry policies to remove</param>
	internal static void RemovePoliciesFromSystem(List<RegistryPolicyEntry> policies)
	{
		List<string> removedEntries = [];

		foreach (RegistryPolicyEntry policy in policies)
		{
			try
			{
				// Create a copy with Remove action since we use the same EditRegistry for removal too.
				RegistryPolicyEntry removePolicy = new(
					source: policy.Source,
					keyName: policy.KeyName,
					valueName: policy.ValueName,
					type: policy.Type,
					size: policy.Size,
					data: policy.Data)
				{
					RegValue = policy.RegValue,
					hive = policy.hive,
					policyAction = PolicyAction.Remove,
					FriendlyName = policy.FriendlyName,
					URL = policy.URL,
					Category = policy.Category,
					SubCategory = policy.SubCategory,
					DefaultRegValue = policy.DefaultRegValue
				};

				EditRegistry(removePolicy);

				string action = policy.DefaultRegValue is null ? GlobalVars.GetStr("RemovedRegistryEntry") : GlobalVars.GetStr("ResetToDefaultRegistryEntry");
				removedEntries.Add(string.Format(GlobalVars.GetStr("RemovedRegistryEntryFormat"), action, policy.hive, policy.KeyName, policy.ValueName));
			}
			catch (Exception ex)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("ErrorRemovingRegistryPolicy"), policy.hive, policy.KeyName, policy.ValueName, ex.Message));
			}
		}

		foreach (string removedEntry in removedEntries)
		{
			Logger.Write(removedEntry);
		}

		Logger.Write(string.Format(GlobalVars.GetStr("RegistryRemovalComplete"), removedEntries.Count, policies.Count));
	}

	/// <summary>
	/// Verifies multiple registry policies in bulk.
	/// </summary>
	/// <param name="policies">List of registry policies to verify</param>
	/// <returns>Dictionary with policies as keys and verification results as values</returns>
	internal static Dictionary<RegistryPolicyEntry, bool> VerifyPoliciesInSystem(List<RegistryPolicyEntry> policies)
	{
		Dictionary<RegistryPolicyEntry, bool> verificationResults = [];

		foreach (RegistryPolicyEntry policy in policies)
		{
			try
			{
				string? actualValue = ReadRegistry(policy);
				bool isVerified = false;

				if (actualValue is not null && policy.RegValue is not null)
				{
					isVerified = CompareRegistryValues(policy.Type, actualValue, policy.RegValue);
				}

				verificationResults[policy] = isVerified;
				Logger.Write(isVerified ?
					string.Format(GlobalVars.GetStr("VerifyRegistryMatch"), policy.hive, policy.KeyName, policy.ValueName) :
					string.Format(GlobalVars.GetStr("VerifyRegistryMismatch"), policy.hive, policy.KeyName, policy.ValueName));
			}
			catch (Exception ex)
			{
				verificationResults[policy] = false;
				Logger.Write(string.Format(GlobalVars.GetStr("ErrorVerifyingRegistryPolicy"), policy.hive, policy.KeyName, policy.ValueName, ex.Message));
			}
		}

		Logger.Write(string.Format(GlobalVars.GetStr("RegistryVerificationComplete"), verificationResults.Count(kvp => kvp.Value), policies.Count));
		return verificationResults;
	}

	/// <summary>
	/// Compares registry values based on their type.
	/// </summary>
	/// <param name="type">Registry value type</param>
	/// <param name="actualValue">Actual value from registry</param>
	/// <param name="expectedValue">Expected value</param>
	/// <returns>True if values match, false otherwise</returns>
	private static bool CompareRegistryValues(RegistryValueType type, string actualValue, string expectedValue) =>
		type switch
		{
			RegistryValueType.REG_SZ or RegistryValueType.REG_EXPAND_SZ
				=> string.Equals(actualValue, expectedValue, StringComparison.OrdinalIgnoreCase),

			RegistryValueType.REG_DWORD
				=> uint.TryParse(actualValue, out var actD) && uint.TryParse(expectedValue, out var expD) && actD == expD,

			RegistryValueType.REG_QWORD
				=> long.TryParse(actualValue, out var actQ) && long.TryParse(expectedValue, out var expQ) && actQ == expQ,

			RegistryValueType.REG_MULTI_SZ
				=> CompareMultiStringValues(actualValue, expectedValue),

			RegistryValueType.REG_BINARY
				=> string.Equals(actualValue, expectedValue, StringComparison.OrdinalIgnoreCase),

			_ => string.Equals(actualValue, expectedValue, StringComparison.OrdinalIgnoreCase)
		};

	/// <summary>
	/// Compares multi-string registry values.
	/// </summary>
	/// <param name="actualValue">Actual multi-string value (semicolon separated)</param>
	/// <param name="expectedValue">Expected multi-string value (semicolon separated)</param>
	/// <returns>True if values match, false otherwise</returns>
	private static bool CompareMultiStringValues(string actualValue, string expectedValue)
	{
		string[] actualArray = actualValue.Split(Separator);
		string[] expectedArray = expectedValue.Split(Separator);

		return actualArray.Length == expectedArray.Length &&
			   actualArray.SequenceEqual(expectedArray, StringComparer.OrdinalIgnoreCase);
	}

	private static (RegistryValueKind, object?) ConvertValue(RegistryValueType type, string? rawValue) =>
		type switch
		{
			RegistryValueType.REG_SZ
				=> (RegistryValueKind.String, rawValue),
			RegistryValueType.REG_EXPAND_SZ
				=> (RegistryValueKind.ExpandString, rawValue),
			RegistryValueType.REG_DWORD
				=> (RegistryValueKind.DWord, int.Parse(rawValue ?? string.Empty, NumberStyles.Integer, CultureInfo.InvariantCulture)),
			RegistryValueType.REG_QWORD
				=> (RegistryValueKind.QWord, long.Parse(rawValue ?? string.Empty, NumberStyles.Integer, CultureInfo.InvariantCulture)),
			RegistryValueType.REG_BINARY
				=> (RegistryValueKind.Binary, Convert.FromBase64String(rawValue ?? string.Empty)),
			RegistryValueType.REG_MULTI_SZ
				=> (RegistryValueKind.MultiString, rawValue?.Split(Separator) ?? []),
			_ => throw new ArgumentException(GlobalVars.GetStr("InvalidRegistryValueType"))
		};

	private static RegistryKey GetBaseRegistryKey(Hive? hive) =>
		hive switch
		{
			Hive.HKLM => Registry.LocalMachine,
			Hive.HKCU => Registry.CurrentUser,
			Hive.HKCR => Registry.ClassesRoot,
			_ => throw new ArgumentException(string.Format(GlobalVars.GetStr("InvalidRegistryBaseKey"), hive))
		};
}
