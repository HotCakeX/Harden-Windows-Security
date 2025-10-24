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
using System.IO;
using System.Text;
using HardenSystemSecurity.GroupPolicy;

namespace HardenSystemSecurity.SecurityPolicy;

internal static class SecurityINFParser
{
	/// <summary>
	/// Parses a Security INF file and extracts registry values from the [Registry Values] section,
	/// converting them to <see cref="RegistryPolicyEntry"/> objects.
	/// </summary>
	/// <param name="filePath">Path to the Security INF file</param>
	/// <returns>List of RegistryPolicyEntry objects</returns>
	/// <exception cref="FileNotFoundException">Thrown when the file doesn't exist</exception>
	/// <exception cref="ArgumentException">Thrown when parameters are invalid</exception>
	internal static List<RegistryPolicyEntry> ParseSecurityINFFile(string filePath)
	{
		if (!File.Exists(filePath))
			throw new FileNotFoundException($"Security INF file not found: {filePath}");

		string[] lines = File.ReadAllLines(filePath, Encoding.UTF8);

		List<RegistryPolicyEntry> policies = [];
		bool inRegistryValuesSection = false;

		foreach (string line in lines)
		{
			string trimmedLine = line.Trim();

			// Skip empty lines and comments
			if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith(';'))
				continue;

			// Check if we're entering the [Registry Values] section
			if (string.Equals(trimmedLine, "[Registry Values]", StringComparison.OrdinalIgnoreCase))
			{
				inRegistryValuesSection = true;
				continue;
			}

			// Check if we're entering a different section
			if (trimmedLine.StartsWith('[') && trimmedLine.EndsWith(']') &&
				!string.Equals(trimmedLine, "[Registry Values]", StringComparison.OrdinalIgnoreCase))
			{
				inRegistryValuesSection = false;
				continue;
			}

			// Process registry values if we're in the correct section
			if (inRegistryValuesSection)
			{
				RegistryPolicyEntry? policy = ParseRegistryValueLine(trimmedLine);
				if (policy != null)
				{
					policies.Add(policy);
				}
			}
		}

		return policies;
	}

	/// <summary>
	/// Parses a single registry value line from the [Registry Values] section.
	/// Format: MACHINE\Path\To\Registry\Key\ValueName=Type,Value
	/// </summary>
	/// <param name="line">The line to parse</param>
	/// <returns>RegistryPolicyEntry object or null if parsing fails</returns>
	internal static RegistryPolicyEntry? ParseRegistryValueLine(string line)
	{
		try
		{
			// Find the equals sign that separates the registry path from the type and value
			int equalsIndex = line.IndexOf('=');
			if (equalsIndex == -1)
				return null;

			string registryPath = line[..equalsIndex].Trim();
			string typeAndValue = line[(equalsIndex + 1)..].Trim();

			// Parse the registry path to extract hive, key name, and value name
			if (!ParseRegistryPath(registryPath, out Hive hive, out string keyName, out string valueName))
				return null;

			// Parse the type and value
			if (!ParseTypeAndValue(typeAndValue, out RegistryValueType registryType, out string regValue, out byte[] data, out uint size))
				return null;

			// Create and return the RegistryPolicyEntry
			return new RegistryPolicyEntry(
				source: Source.SecurityPolicyRegistry,
				keyName: keyName,
				valueName: valueName,
				type: registryType,
				size: size,
				data: data,
				hive: hive)
			{
				RegValue = regValue,
				policyAction = PolicyAction.Apply,
				FriendlyName = "",
				URL = "",
				Category = null,
				SubCategory = null,
				DefaultRegValue = null
			};
		}
		catch
		{
			// Return null if any parsing fails
			return null;
		}
	}

	/// <summary>
	/// Parses the registry path to extract hive, key name, and value name.
	/// </summary>
	/// <param name="registryPath">The full registry path</param>
	/// <param name="hive">Output: The registry hive</param>
	/// <param name="keyName">Output: The registry key path</param>
	/// <param name="valueName">Output: The registry value name</param>
	/// <returns>True if parsing succeeds, false otherwise</returns>
	private static bool ParseRegistryPath(string registryPath, out Hive hive, out string keyName, out string valueName)
	{
		// Setting initial values
		hive = Hive.HKLM;
		keyName = "";
		valueName = "";

		// Split the path by backslashes
		string[] pathParts = registryPath.Split('\\');
		if (pathParts.Length < 3) // Need at least hive + one key part + value name
			return false;

		// Determine the hive from the first part
		string hivePart = pathParts[0].ToUpperInvariant();
		switch (hivePart)
		{
			case "MACHINE":
				hive = Hive.HKLM;
				break;
			case "USER":
			case "USERS":
				hive = Hive.HKCU;
				break;
			case "CLASSES_ROOT":
				hive = Hive.HKCR;
				break;
			default:
				return false; // Unknown hive
		}

		// The last part is the value name
		valueName = pathParts[^1];

		// Everything in between (excluding the first and last parts) forms the key name
		if (pathParts.Length == 2)
		{
			// Only hive and value name, no intermediate path
			keyName = "";
		}
		else
		{
			// Join all parts except the first (hive) and last (value name)
			string[] keyParts = new string[pathParts.Length - 2];
			Array.Copy(pathParts, 1, keyParts, 0, pathParts.Length - 2);
			keyName = string.Join("\\", keyParts);
		}

		return true;
	}

	/// <summary>
	/// Parses the type and value portion of a registry value line.
	/// Format: Type,Value (e.g., "4,1" or "1,\"Some String\"")
	/// </summary>
	/// <param name="typeAndValue">The type and value string</param>
	/// <param name="registryType">Output: The registry value type</param>
	/// <param name="regValue">Output: The string representation of the value</param>
	/// <param name="data">Output: The binary data</param>
	/// <param name="size">Output: The size of the data</param>
	/// <returns>True if parsing succeeds, false otherwise</returns>
	private static bool ParseTypeAndValue(string typeAndValue, out RegistryValueType registryType, out string regValue, out byte[] data, out uint size)
	{
		registryType = RegistryValueType.REG_NONE;
		regValue = "";
		data = [];
		size = 0;

		// Find the first comma that separates type from value
		int commaIndex = typeAndValue.IndexOf(',');
		if (commaIndex == -1)
		{
			// No comma found, treat as type only with empty value
			if (uint.TryParse(typeAndValue, CultureInfo.InvariantCulture, out uint typeValue))
			{
				registryType = (RegistryValueType)typeValue;
				regValue = "";
				data = [];
				size = 0;
				return true;
			}
			return false;
		}

		string typeString = typeAndValue[..commaIndex].Trim();
		string valueString = typeAndValue[(commaIndex + 1)..].Trim();

		// Parse the type
		if (!uint.TryParse(typeString, CultureInfo.InvariantCulture, out uint typeNum))
			return false;

		registryType = (RegistryValueType)typeNum;

		// Parse the value based on the type
		switch (registryType)
		{
			case RegistryValueType.REG_SZ:
			case RegistryValueType.REG_EXPAND_SZ:
				// String value - remove quotes if present
				regValue = valueString;
				if (regValue.StartsWith('"') && regValue.EndsWith('"') && regValue.Length >= 2)
				{
					regValue = regValue[1..^1];
				}
				data = Encoding.Unicode.GetBytes(regValue + '\0');
				size = (uint)data.Length;
				break;

			case RegistryValueType.REG_DWORD:
				// DWORD value
				if (uint.TryParse(valueString, CultureInfo.InvariantCulture, out uint dwordValue))
				{
					regValue = dwordValue.ToString(CultureInfo.InvariantCulture);
					data = BitConverter.GetBytes(dwordValue);
					size = 4;
				}
				else
				{
					return false;
				}
				break;

			case RegistryValueType.REG_QWORD:
				// QWORD value
				if (ulong.TryParse(valueString, CultureInfo.InvariantCulture, out ulong qwordValue))
				{
					regValue = qwordValue.ToString(CultureInfo.InvariantCulture);
					data = BitConverter.GetBytes(qwordValue);
					size = 8;
				}
				else
				{
					return false;
				}
				break;

			case RegistryValueType.REG_BINARY:
				// Binary value - parse as comma-separated bytes or hex string
				regValue = valueString;
				data = ParseBinaryData(valueString);
				size = (uint)data.Length;
				break;

			case RegistryValueType.REG_MULTI_SZ:
				// Multi-string value - handle as single string for now
				regValue = valueString;
				if (regValue.StartsWith('"') && regValue.EndsWith('"') && regValue.Length >= 2)
				{
					regValue = regValue[1..^1];
				}
				// For multi-string, we need to add double null terminator
				data = Encoding.Unicode.GetBytes(regValue + "\0\0");
				size = (uint)data.Length;
				break;
			case RegistryValueType.REG_NONE:
				break;
			case RegistryValueType.REG_DWORD_BIG_ENDIAN:
				break;
			case RegistryValueType.REG_LINK:
				break;
			case RegistryValueType.REG_RESOURCE_LIST:
				break;
			case RegistryValueType.REG_FULL_RESOURCE_DESCRIPTOR:
				break;
			case RegistryValueType.REG_RESOURCE_REQUIREMENTS_LIST:
				break;
			default:
				// For unknown types, store as string
				regValue = valueString;
				data = Encoding.UTF8.GetBytes(regValue);
				size = (uint)data.Length;
				break;
		}

		return true;
	}

	/// <summary>
	/// Parses binary data from a string representation.
	/// Supports comma-separated bytes or hex strings.
	/// </summary>
	/// <param name="binaryString">The binary data string</param>
	/// <returns>Byte array representation</returns>
	private static byte[] ParseBinaryData(string binaryString)
	{
		try
		{
			// Try parsing as comma-separated bytes first
			if (binaryString.Contains(','))
			{
				string[] byteStrings = binaryString.Split(',');
				byte[] bytes = new byte[byteStrings.Length];
				for (int i = 0; i < byteStrings.Length; i++)
				{
					if (!byte.TryParse(byteStrings[i].Trim(), CultureInfo.InvariantCulture, out bytes[i]))
					{
						// If parsing fails, return the string as UTF-8 bytes
						return Encoding.UTF8.GetBytes(binaryString);
					}
				}
				return bytes;
			}
			else
			{
				// Try parsing as hex string
				if (binaryString.Length % 2 == 0)
				{
					byte[] bytes = new byte[binaryString.Length / 2];
					for (int i = 0; i < bytes.Length; i++)
					{
						if (!byte.TryParse(binaryString.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bytes[i]))
						{
							// If hex parsing fails, return the string as UTF-8 bytes
							return Encoding.UTF8.GetBytes(binaryString);
						}
					}
					return bytes;
				}
				else
				{
					// Not a valid hex string, return as UTF-8 bytes
					return Encoding.UTF8.GetBytes(binaryString);
				}
			}
		}
		catch
		{
			// If all parsing fails, return the string as UTF-8 bytes
			return Encoding.UTF8.GetBytes(binaryString);
		}
	}
}
