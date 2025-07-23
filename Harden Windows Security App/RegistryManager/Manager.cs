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
using System.Globalization;
using Microsoft.Win32;
using HardenWindowsSecurity.GroupPolicy;

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
			_ => throw new ArgumentException($"Invalid registry base key: {package.hive}")
		};

		using RegistryKey subKey = baseRegistryKey.OpenSubKey(package.KeyName, true) ?? baseRegistryKey.CreateSubKey(package.KeyName);

		if (package.RegValue is null)
			throw new InvalidOperationException("Registry key did not have any RegValue");

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
						throw new ArgumentException("Invalid registry value type");
					}
			}

			subKey.SetValue(package.ValueName, convertedValue, valueType);
		}
		else if (package.policyAction is PolicyAction.Remove)
		{
			if (subKey.GetValue(package.ValueName) is not null)
			{
				subKey.DeleteValue(package.ValueName, true);
			}
		}
		else
		{
			throw new ArgumentException($"Invalid action specified: {package.policyAction}");
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
			_ => throw new ArgumentException($"Invalid registry base key: {package.hive}")
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

			_ => throw new ArgumentException("Invalid registry value type")
		};
	}
}
