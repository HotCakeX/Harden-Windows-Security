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
using HardenSystemSecurity.RegistryManager;

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

			// Parse the type and value (canonicalize to JSON-like formats)
			if (!ParseTypeAndValue(typeAndValue, out RegistryValueType registryType, out string regValue, out byte[] data, out uint size))
				return null;

			// Create and return the RegistryPolicyEntry
			return new RegistryPolicyEntry(
				source: Source.Registry,
				keyName: keyName,
				valueName: valueName,
				type: registryType,
				size: size,
				data: data,
				hive: hive)
			{
				// Canonical RegValue for verification via RegistryManager:
				// - REG_BINARY: Base64
				// - REG_MULTI_SZ: semicolon-separated
				// - REG_SZ/REG_EXPAND_SZ: plain string (REG_EXPAND_SZ expanded)
				// - REG_DWORD/REG_QWORD: decimal string
				RegValue = regValue,
				policyAction = PolicyAction.Apply,
				FriendlyName = "",
				URL = "",
				Category = null,
				SubCategory = null,
				DefaultRegValue = null
			};
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return null;
		}
	}

	/// <summary>
	/// Parses the registry path to extract hive, key name, and value name.
	/// Accepts the INF "MACHINE\..." and standard "HKLM\..." styles.
	/// </summary>
	internal static bool ParseRegistryPath(string registryPath, out Hive hive, out string keyName, out string valueName)
	{
		hive = Hive.HKLM;
		keyName = "";
		valueName = "";

		string[] pathParts = registryPath.Split('\\');
		if (pathParts.Length < 3) // Need at least hive + one key part + value name
			return false;

		string hivePart = pathParts[0].ToUpperInvariant();
		hive = hivePart switch
		{
			"MACHINE" or "HKLM" or "HKEY_LOCAL_MACHINE" => Hive.HKLM,
			"USER" or "USERS" or "HKCU" or "HKEY_CURRENT_USER" => Hive.HKCU,
			"CLASSES_ROOT" or "HKCR" or "HKEY_CLASSES_ROOT" => Hive.HKCR,
			_ => throw new InvalidOperationException($"Unknown registry hive in path: {hivePart}"),
		};

		// The last part is the value name
		valueName = pathParts[^1];

		// Everything in between (excluding the first and last parts) forms the key name
		if (pathParts.Length == 2)
		{
			keyName = "";
		}
		else
		{
			string[] keyParts = new string[pathParts.Length - 2];
			Array.Copy(pathParts, 1, keyParts, 0, pathParts.Length - 2);
			keyName = string.Join("\\", keyParts);
		}

		return true;
	}

	/// <summary>
	/// Parses "Type,Value" into canonical RegValue + Data/Size.
	/// Canonicalization rules (string form centralized in Manager.BuildRegValueFromParsedValue):
	/// - REG_BINARY: Data = bytes; RegValue = Base64
	/// - REG_MULTI_SZ: Data = UTF-16 with '\0' separators + double null; RegValue semicolon-separated
	/// - REG_SZ/REG_EXPAND_SZ: Data = UTF-16 NUL-terminated; RegValue plain string (REG_EXPAND_SZ expanded)
	/// - REG_DWORD/QWORD: Data = LE bytes; 4/8; RegValue decimal string
	/// </summary>
	internal static bool ParseTypeAndValue(string typeAndValue, out RegistryValueType registryType, out string regValue, out byte[] data, out uint size)
	{
		registryType = RegistryValueType.REG_NONE;
		regValue = "";
		data = [];
		size = 0;

		int commaIndex = typeAndValue.IndexOf(',');
		if (commaIndex == -1)
		{
			// No comma found, treat as type only with empty value
			if (uint.TryParse(typeAndValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint typeValue))
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
		if (!uint.TryParse(typeString, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint typeNum))
			return false;

		registryType = (RegistryValueType)typeNum;

		// Build Data for each supported type
		switch (registryType)
		{
			case RegistryValueType.REG_SZ:
			case RegistryValueType.REG_EXPAND_SZ:
				{
					string s = Unquote(valueString);
					string withNull = string.Concat(s, '\0'); // UTF-16 + single NUL terminator
					data = Encoding.Unicode.GetBytes(withNull);
					break;
				}

			case RegistryValueType.REG_DWORD:
				{
					if (!uint.TryParse(valueString, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint dword))
						return false;
					data = BitConverter.GetBytes(dword); // little-endian
					break;
				}

			case RegistryValueType.REG_QWORD:
				{
					if (!ulong.TryParse(valueString, NumberStyles.Integer, CultureInfo.InvariantCulture, out ulong qword))
						return false;
					data = BitConverter.GetBytes(qword); // little-endian
					break;
				}

			case RegistryValueType.REG_BINARY:
				{
					data = ParseBinaryData(valueString); // single-token and multi-token parsing
					break;
				}

			case RegistryValueType.REG_MULTI_SZ:
				{
					string dequoted = Unquote(valueString);
					string[] items = SplitMultiStringFlexible(dequoted);
					data = BuildMultiSzBytes(items); // MULTI_SZ encoding
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
					// Unknown/unsupported types, preserve original string in Data and RegValue
					regValue = valueString;
					data = Encoding.UTF8.GetBytes(valueString);
					break;
				}
		}

		size = (uint)data.Length;

		// Centralize canonical RegValue string creation
		// This expands REG_EXPAND_SZ and formats all types consistently with RegistryManager expectations.
		if (registryType is RegistryValueType.REG_SZ or
			RegistryValueType.REG_EXPAND_SZ or
			RegistryValueType.REG_DWORD or
			RegistryValueType.REG_QWORD or
			RegistryValueType.REG_BINARY or
			RegistryValueType.REG_MULTI_SZ)
		{
			RegistryPolicyEntry tempEntry = new(
				source: Source.Registry,
				keyName: string.Empty,
				valueName: string.Empty,
				type: registryType,
				size: size,
				data: data,
				hive: Hive.HKLM);

			string? canonical = Manager.BuildRegValueFromParsedValue(tempEntry);
			regValue = canonical ?? string.Empty;
		}
		// else keep regValue from default branch

		return true;
	}

	internal static string Unquote(string s)
	{
		if (s.Length >= 2 && s[0] == '"' && s[^1] == '"')
		{
			return s[1..^1];
		}
		return s;
	}

	/// <summary>
	/// Parses binary data from INF-style representation:
	/// - Comma-separated bytes (decimal), e.g. "1,2,255"
	/// - Comma-separated hex tokens (with or without 0x), e.g. "0x0A,FF"
	/// - Contiguous hex string, e.g. "0A0BFF"
	/// - Single-token decimal or hex (e.g. "0", "255", "0x0A", "A")
	/// Falls back to UTF-8 bytes if parsing fails (rare).
	/// </summary>
	internal static byte[] ParseBinaryData(string binaryString)
	{
		try
		{
			string s = binaryString.Trim();
			if (s.Length == 0)
			{
				return [];
			}

			// Comma-separated tokens (decimal or hex)
			if (s.Contains(',', StringComparison.OrdinalIgnoreCase))
			{
				string[] tokens = s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
				if (tokens.Length == 0) return [];

				// Detect hex usage
				bool anyHex = false;
				for (int i = 0; i < tokens.Length && !anyHex; i++)
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
						? byte.TryParse(tk, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out result[i])
						: byte.TryParse(tk, NumberStyles.Integer, CultureInfo.InvariantCulture, out result[i]);

					if (!ok)
					{
						return Encoding.UTF8.GetBytes(binaryString);
					}
				}
				return result;
			}

			// Hex char check
			static bool IsHexChar(char c)
			{
				return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
			}

			// Single token (no commas)
			string token = s;
			bool hasHexPrefix = token.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
			if (hasHexPrefix)
			{
				token = token[2..];
			}

			// All hex digits
			bool tokenIsHex = token.Length > 0;
			for (int i = 0; i < token.Length && tokenIsHex; i++)
			{
				if (!IsHexChar(token[i]))
				{
					tokenIsHex = false;
				}
			}

			if (tokenIsHex)
			{
				// Even length => contiguous hex string (pairs of bytes)
				if ((token.Length & 1) == 0)
				{
					byte[] result = new byte[token.Length / 2];
					for (int i = 0; i < result.Length; i++)
					{
						if (!byte.TryParse(token.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out result[i]))
						{
							return Encoding.UTF8.GetBytes(binaryString);
						}
					}
					return result;
				}

				// Single nibble => treat as one byte (e.g., "A" => 0x0A)
				if (token.Length == 1)
				{
					if (byte.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte bNibble))
					{
						return [bNibble];
					}
					return Encoding.UTF8.GetBytes(binaryString);
				}

				// Odd length > 1 is ambiguous => fallback
				return Encoding.UTF8.GetBytes(binaryString);
			}

			// Decimal single token (0..255)
			bool allDigits = true;
			for (int i = 0; i < token.Length && allDigits; i++)
			{
				char ch = token[i];
				allDigits = ch >= '0' && ch <= '9';
			}
			if (allDigits)
			{
				if (byte.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out byte b))
				{
					return [b];
				}
				return Encoding.UTF8.GetBytes(binaryString);
			}

			// Fallback, not recognized, treat as UTF-8 bytes
			return Encoding.UTF8.GetBytes(binaryString);
		}
		catch
		{
			return Encoding.UTF8.GetBytes(binaryString);
		}
	}

	/// <summary>
	/// Splits a multi-string value accepting newline, semicolon, or comma as delimiters.
	/// Empty input => [].
	/// </summary>
	internal static string[] SplitMultiStringFlexible(string input)
	{
		if (string.IsNullOrEmpty(input))
		{
			return [];
		}

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

		// Single token
		string single = normalized.Trim();
		if (single.Length == 0) return [];
		return [single];
	}

	/// <summary>
	/// Builds MULTI_SZ bytes (UTF-16): items joined by '\0' and double-null terminated.
	/// </summary>
	internal static byte[] BuildMultiSzBytes(string[] items)
	{
		// Join with single NULs and add final double NUL
		string joined = items.Length == 0 ? string.Empty : string.Join("\0", items);
		string withDoubleNull = string.Concat(joined, "\0\0");
		return Encoding.Unicode.GetBytes(withDoubleNull);
	}
}
