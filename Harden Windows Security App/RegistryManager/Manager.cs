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

namespace HardenWindowsSecurity.RegistryManager;

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

		RegistryKey baseRegistryKey = package.hive switch
		{
			Hive.HKLM => Registry.LocalMachine,
			Hive.HKCU => Registry.CurrentUser,
			Hive.HKCR => Registry.ClassesRoot,
			_ => throw new ArgumentException(string.Format(GlobalVars.GetStr("InvalidRegistryBaseKey"), package.hive))
		};

		using RegistryKey subKey = baseRegistryKey.OpenSubKey(package.KeyName, true) ?? baseRegistryKey.CreateSubKey(package.KeyName);

		if (package.RegValue is null)
			throw new InvalidOperationException(GlobalVars.GetStr("RegistryKeyDidNotHaveRegValue"));

		if (package.policyAction is PolicyAction.Apply)
		{
			RegistryValueKind valueType;
			object convertedValue;

			switch (package.Type)
			{
				case RegistryValueType.REG_SZ:
					{
						valueType = RegistryValueKind.String;
						convertedValue = package.RegValue;
						break;
					}
				case RegistryValueType.REG_DWORD:
					{
						valueType = RegistryValueKind.DWord;
						convertedValue = int.Parse(package.RegValue, NumberStyles.Integer, CultureInfo.InvariantCulture);
						break;
					}
				case RegistryValueType.REG_QWORD:
					{
						valueType = RegistryValueKind.QWord;
						convertedValue = long.Parse(package.RegValue, NumberStyles.Integer, CultureInfo.InvariantCulture);
						break;
					}
				case RegistryValueType.REG_BINARY:
					{
						valueType = RegistryValueKind.Binary;
						convertedValue = Convert.FromBase64String(package.RegValue);
						break;
					}
				case RegistryValueType.REG_MULTI_SZ:
					{
						valueType = RegistryValueKind.MultiString;
						convertedValue = package.RegValue.Split(Separator, StringSplitOptions.None);
						break;
					}
				case RegistryValueType.REG_EXPAND_SZ:
					{
						valueType = RegistryValueKind.ExpandString;
						convertedValue = package.RegValue;
						break;
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
				RegistryValueKind valueType;
				object convertedValue;

				switch (package.Type)
				{
					case RegistryValueType.REG_SZ:
						{
							valueType = RegistryValueKind.String;
							convertedValue = package.DefaultRegValue;
							break;
						}
					case RegistryValueType.REG_DWORD:
						{
							valueType = RegistryValueKind.DWord;
							convertedValue = int.Parse(package.DefaultRegValue, NumberStyles.Integer, CultureInfo.InvariantCulture);
							break;
						}
					case RegistryValueType.REG_QWORD:
						{
							valueType = RegistryValueKind.QWord;
							convertedValue = long.Parse(package.DefaultRegValue, NumberStyles.Integer, CultureInfo.InvariantCulture);
							break;
						}
					case RegistryValueType.REG_BINARY:
						{
							valueType = RegistryValueKind.Binary;
							convertedValue = Convert.FromBase64String(package.DefaultRegValue);
							break;
						}
					case RegistryValueType.REG_MULTI_SZ:
						{
							valueType = RegistryValueKind.MultiString;
							convertedValue = package.DefaultRegValue.Split(Separator, StringSplitOptions.None);
							break;
						}
					case RegistryValueType.REG_EXPAND_SZ:
						{
							valueType = RegistryValueKind.ExpandString;
							convertedValue = package.DefaultRegValue;
							break;
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
		RegistryKey baseRegistryKey = package.hive switch
		{
			Hive.HKLM => Registry.LocalMachine,
			Hive.HKCU => Registry.CurrentUser,
			Hive.HKCR => Registry.ClassesRoot,
			_ => throw new ArgumentException(string.Format(GlobalVars.GetStr("InvalidRegistryBaseKey"), package.hive))
		};

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
}
