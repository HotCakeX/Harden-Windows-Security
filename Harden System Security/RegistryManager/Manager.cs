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
		// Determine base hive
		RegistryKey baseRegistryKey = GetBaseRegistryKey(package.Hive);

		using RegistryKey subKey = baseRegistryKey.OpenSubKey(package.KeyName, true) ?? baseRegistryKey.CreateSubKey(package.KeyName);

		if (package.RegValue is null)
			throw new InvalidOperationException(GlobalVars.GetStr("RegistryKeyDidNotHaveRegValue"));

		if (package.policyAction is PolicyAction.Apply)
		{
			(RegistryValueKind valueType, object convertedValue) = ConvertStringToRegistryData(package.Type, package.RegValue);
			subKey.SetValue(package.ValueName, convertedValue, valueType);
		}
		else if (package.policyAction is PolicyAction.Remove)
		{
			// Check if DefaultRegValue is null - if so, delete the registry value as before
			if (package.DefaultRegValue is null)
			{
				if (subKey.GetValue(package.ValueName) is not null)
				{
					subKey.DeleteValue(package.ValueName, true);
				}
			}
			else
			{
				// DefaultRegValue is not null, so set the registry value to the default value
				(RegistryValueKind valueType, object convertedValue) = ConvertStringToRegistryData(package.Type, package.DefaultRegValue);
				subKey.SetValue(package.ValueName, convertedValue, valueType);
			}
		}
		else
		{
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
		RegistryKey baseRegistryKey = GetBaseRegistryKey(package.Hive);

		// Open subkey readonly
		using RegistryKey? subKey = baseRegistryKey.OpenSubKey(package.KeyName, writable: false);
		if (subKey is null)
			return null;

		// Try get the raw value
		object? rawValue = subKey.GetValue(package.ValueName);
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
				=> rawValue switch
				{
					int i => unchecked((uint)i).ToString(CultureInfo.InvariantCulture),
					uint ui => ui.ToString(CultureInfo.InvariantCulture),
					long l => unchecked((uint)l).ToString(CultureInfo.InvariantCulture),
					byte[] bytes when bytes.Length == 4 => BitConverter.ToUInt32(bytes, 0).ToString(CultureInfo.InvariantCulture),
					string s when uint.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint parsed) => parsed.ToString(CultureInfo.InvariantCulture),
					_ => Convert.ToUInt32(rawValue, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture)
				},

			RegistryValueType.REG_QWORD
				=> rawValue switch
				{
					long l => unchecked((ulong)l).ToString(CultureInfo.InvariantCulture),
					ulong ul => ul.ToString(CultureInfo.InvariantCulture),
					byte[] bytes when bytes.Length == 8 => BitConverter.ToUInt64(bytes, 0).ToString(CultureInfo.InvariantCulture),
					string s when ulong.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out ulong parsed) => parsed.ToString(CultureInfo.InvariantCulture),
					_ => Convert.ToUInt64(rawValue, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture)
				},

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
				appliedEntries.Add(string.Format(GlobalVars.GetStr("AppliedRegistryEntry"), policy.Hive, policy.KeyName, policy.ValueName));
			}
			catch (Exception ex)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("ErrorApplyingRegistryPolicy"), policy.Hive, policy.KeyName, policy.ValueName, ex.Message));
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
					data: policy.Data,
					hive: policy.Hive)
				{
					RegValue = policy.RegValue,
					policyAction = PolicyAction.Remove,
					FriendlyName = policy.FriendlyName,
					URL = policy.URL,
					Category = policy.Category,
					SubCategory = policy.SubCategory,
					DefaultRegValue = policy.DefaultRegValue
				};

				EditRegistry(removePolicy);

				string action = policy.DefaultRegValue is null ? GlobalVars.GetStr("RemovedRegistryEntry") : GlobalVars.GetStr("ResetToDefaultRegistryEntry");
				removedEntries.Add(string.Format(GlobalVars.GetStr("RemovedRegistryEntryFormat"), action, policy.Hive, policy.KeyName, policy.ValueName));
			}
			catch (Exception ex)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("ErrorRemovingRegistryPolicy"), policy.Hive, policy.KeyName, policy.ValueName, ex.Message));
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
					string.Format(GlobalVars.GetStr("VerifyRegistryMatch"), policy.Hive, policy.KeyName, policy.ValueName) :
					string.Format(GlobalVars.GetStr("VerifyRegistryMismatch"), policy.Hive, policy.KeyName, policy.ValueName));
			}
			catch (Exception ex)
			{
				verificationResults[policy] = false;
				Logger.Write(string.Format(GlobalVars.GetStr("ErrorVerifyingRegistryPolicy"), policy.Hive, policy.KeyName, policy.ValueName, ex.Message));
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
	private static bool CompareRegistryValues(RegistryValueType type, string actualValue, string expectedValue)
	{
		try
		{
			return type switch
			{
				RegistryValueType.REG_SZ or RegistryValueType.REG_EXPAND_SZ
					=> string.Equals(actualValue, expectedValue, StringComparison.OrdinalIgnoreCase),

				RegistryValueType.REG_DWORD
					=> uint.TryParse(actualValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint actualDword) &&
					   uint.TryParse(expectedValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint expectedDword) &&
					   actualDword == expectedDword,

				RegistryValueType.REG_QWORD
					=> long.TryParse(actualValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out long actualQword) &&
					   long.TryParse(expectedValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out long expectedQword) &&
					   actualQword == expectedQword,

				RegistryValueType.REG_MULTI_SZ
					=> CompareMultiStringValues(actualValue, expectedValue),

				RegistryValueType.REG_BINARY
					=> string.Equals(actualValue, expectedValue, StringComparison.OrdinalIgnoreCase),

				_ => string.Equals(actualValue, expectedValue, StringComparison.OrdinalIgnoreCase)
			};
		}
		catch
		{
			return false;
		}
	}

	/// <summary>
	/// Compares multi-string registry values.
	/// </summary>
	/// <param name="actualValue">Actual multi-string value (semicolon separated)</param>
	/// <param name="expectedValue">Expected multi-string value (semicolon separated)</param>
	/// <returns>True if values match, false otherwise</returns>
	private static bool CompareMultiStringValues(string actualValue, string expectedValue)
	{
		string[] actualArray = actualValue.Split(Separator, StringSplitOptions.None);
		string[] expectedArray = expectedValue.Split(Separator, StringSplitOptions.None);

		return actualArray.Length == expectedArray.Length &&
			   actualArray.SequenceEqual(expectedArray, StringComparer.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Maps <see cref="Hive"/> to its base <see cref="RegistryKey"/>.
	/// </summary>
	private static RegistryKey GetBaseRegistryKey(Hive hive)
	{
		return hive switch
		{
			Hive.HKLM => Registry.LocalMachine,
			Hive.HKCU => Registry.CurrentUser,
			Hive.HKCR => Registry.ClassesRoot,
			_ => throw new ArgumentException(string.Format(GlobalVars.GetStr("InvalidRegistryBaseKey"), hive))
		};
	}

	/// <summary>
	/// Centralized conversion from string to registry data and kind for SetValue.
	/// </summary>
	/// <param name="type">Registry value type descriptor</param>
	/// <param name="value">String value to convert</param>
	/// <returns>Tuple of (RegistryValueKind, converted object)</returns>
	/// <exception cref="ArgumentException">Thrown for invalid registry value types.</exception>
	private static (RegistryValueKind kind, object converted) ConvertStringToRegistryData(RegistryValueType type, string value)
	{
		switch (type)
		{
			case RegistryValueType.REG_SZ:
				{
					return (RegistryValueKind.String, value);
				}
			case RegistryValueType.REG_DWORD:
				{
					int convertedValue = int.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture);
					return (RegistryValueKind.DWord, convertedValue);
				}
			case RegistryValueType.REG_QWORD:
				{
					long convertedValue = long.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture);
					return (RegistryValueKind.QWord, convertedValue);
				}
			case RegistryValueType.REG_BINARY:
				{
					byte[] convertedValue = Convert.FromBase64String(value);
					return (RegistryValueKind.Binary, convertedValue);
				}
			case RegistryValueType.REG_MULTI_SZ:
				{
					string[] convertedValue = value.Split(Separator, StringSplitOptions.None);
					return (RegistryValueKind.MultiString, convertedValue);
				}
			case RegistryValueType.REG_EXPAND_SZ:
				{
					return (RegistryValueKind.ExpandString, value);
				}
			case RegistryValueType.REG_NONE:
			case RegistryValueType.REG_DWORD_BIG_ENDIAN:
			case RegistryValueType.REG_LINK:
			case RegistryValueType.REG_RESOURCE_LIST:
			case RegistryValueType.REG_FULL_RESOURCE_DESCRIPTOR:
			case RegistryValueType.REG_RESOURCE_REQUIREMENTS_LIST:
			default:
				{
					throw new ArgumentException(GlobalVars.GetStr("InvalidRegistryValueType"));
				}
		}
	}

	/// <summary>
	/// Formats an already-parsed Group Policy value (entry.ParsedValue) into the exact string form
	/// Expected by Registry verification => <see cref="RegistryManager.Manager.VerifyPoliciesInSystem(List{RegistryPolicyEntry})"/>.
	/// This method is used by <see cref="ViewModels.GroupPolicyEditorVM"/> and is run when user loads a JSON or POL file and then saves it to JSON file.
	/// - REG_SZ, REG_EXPAND_SZ: plain string (REG_EXPAND_SZ is environment-expanded)
	/// - REG_DWORD: decimal string
	/// - REG_QWORD: decimal string
	/// - REG_BINARY: Base64
	/// - REG_MULTI_SZ: semicolon-separated
	/// </summary>
	/// <param name="entry"></param>
	/// <returns></returns>
	internal static string? BuildRegValueFromParsedValue(RegistryPolicyEntry entry)
	{
		object? parsed = entry.ParsedValue;
		if (parsed is null)
		{
			// Leave as null when policy carries "no value" (Size == 0).
			// If we want registry-fallback to treat "absent value" as compliant, we should handle that in the verifier.
			return null;
		}

		switch (entry.Type)
		{
			case RegistryValueType.REG_SZ:
				{
					string? s = parsed as string;
					return s ?? parsed.ToString();
				}

			case RegistryValueType.REG_EXPAND_SZ:
				{
					// Expand env vars to match RegistryKey.GetValue default expansion in RegistryManager.Manager.ReadRegistry
					string? s = parsed as string ?? parsed.ToString();
					return Environment.ExpandEnvironmentVariables(s ?? string.Empty);
				}

			case RegistryValueType.REG_DWORD:
				{
					// ParsedValue is UInt32 for DWORD
					if (parsed is uint u) return u.ToString(CultureInfo.InvariantCulture);
					if (parsed is int i && i >= 0) return ((uint)i).ToString(CultureInfo.InvariantCulture);
					if (parsed is long l && l >= 0 && l <= uint.MaxValue) return ((uint)l).ToString(CultureInfo.InvariantCulture);
					return null;
				}

			case RegistryValueType.REG_QWORD:
				{
					// ParsedValue is UInt64 for QWORD
					if (parsed is ulong ul) return ul.ToString(CultureInfo.InvariantCulture);
					if (parsed is long ll && ll >= 0) return ((ulong)ll).ToString(CultureInfo.InvariantCulture);
					if (parsed is uint ui) return ((ulong)ui).ToString(CultureInfo.InvariantCulture);
					if (parsed is int ii && ii >= 0) return ((ulong)ii).ToString(CultureInfo.InvariantCulture);
					return null;
				}

			case RegistryValueType.REG_BINARY:
				{
					return parsed is not byte[] bytes ? null : Convert.ToBase64String(bytes);
				}

			case RegistryValueType.REG_MULTI_SZ:
				{
					if (parsed is not string[] arr) return null;
					return string.Join(";", arr);
				}

			case RegistryValueType.REG_FULL_RESOURCE_DESCRIPTOR:
			case RegistryValueType.REG_NONE:
			case RegistryValueType.REG_DWORD_BIG_ENDIAN:
			case RegistryValueType.REG_LINK:
			case RegistryValueType.REG_RESOURCE_LIST:
			case RegistryValueType.REG_RESOURCE_REQUIREMENTS_LIST:
			default:
				{
					// Fallback stringification
					return parsed.ToString();
				}
		}
	}
}
