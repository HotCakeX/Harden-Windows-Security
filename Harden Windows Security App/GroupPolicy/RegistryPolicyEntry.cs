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
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AppControlManager.Others;
using HardenWindowsSecurity.Protect;
using HardenWindowsSecurity.ViewModels;

#pragma warning disable CA1819

namespace HardenWindowsSecurity.GroupPolicy;

internal sealed class RegistryPolicyEntry(
	Source source,
	string keyName,
	string valueName,
	RegistryValueType type,
	uint size,
	byte[] data)
{
	[JsonInclude]
	[JsonPropertyOrder(0)]
	[JsonPropertyName("Source")]
	internal Source Source => source;

	[JsonInclude]
	[JsonPropertyOrder(1)]
	[JsonPropertyName("KeyName")]
	internal string KeyName => keyName;

	[JsonInclude]
	[JsonPropertyOrder(2)]
	[JsonPropertyName("ValueName")]
	internal string ValueName => valueName;

	[JsonInclude]
	[JsonPropertyOrder(3)]
	[JsonPropertyName("Type")]
	internal RegistryValueType Type => type;

	[JsonInclude]
	[JsonPropertyOrder(4)]
	[JsonPropertyName("Size")]
	internal uint Size => size;

	[JsonInclude]
	[JsonPropertyOrder(5)]
	[JsonPropertyName("Data")]
	internal byte[] Data { get; set; } = data;

	[JsonInclude]
	[JsonPropertyOrder(6)]
	[JsonPropertyName("RegValue")]
	internal string? RegValue { get; set; }

	[JsonInclude]
	[JsonPropertyOrder(7)]
	[JsonPropertyName("Hive")]
	internal Hive hive { get; init; }

	[JsonInclude]
	[JsonPropertyOrder(8)]
	[JsonPropertyName("PolicyAction")]
	internal PolicyAction policyAction { get; init; }

	[JsonInclude]
	[JsonPropertyOrder(9)]
	[JsonPropertyName("FriendlyName")]
	internal string? FriendlyName { get; set; }

	[JsonInclude]
	[JsonPropertyOrder(10)]
	[JsonPropertyName("URL")]
	internal string? URL { get; init; }

	[JsonInclude]
	[JsonPropertyOrder(11)]
	[JsonPropertyName("Category")]
	internal Categories? Category { get; init; }

	[JsonInclude]
	[JsonPropertyOrder(12)]
	[JsonPropertyName("SubCategory")]
	internal SubCategories? SubCategory { get; init; }

	[JsonInclude]
	[JsonPropertyOrder(13)]
	[JsonPropertyName("DefaultRegValue")]
	internal string? DefaultRegValue { get; set; }

	/// <summary>
	/// Calculated once, returns the parsed value based on the type and data.
	/// </summary>
	[JsonIgnore]
	internal object? ParsedValue { get; } = GetValue(data, type);

	/// <summary>
	/// Used to reference the VM of the ListView displaying this type.
	/// </summary>
	[JsonIgnore]
	internal GroupPolicyEditorVM? ParentVM;

	private static object? GetValue(byte[] data, RegistryValueType type)
	{
		if (data == null || data.Length == 0)
			return null;
		return type switch
		{
			// Unicode string value - decode from UTF-16 and remove null terminator
			RegistryValueType.REG_SZ => Encoding.Unicode.GetString(data).TrimEnd('\0'),

			// Expandable unicode string value - decode from UTF-16 and remove null terminator
			RegistryValueType.REG_EXPAND_SZ => Encoding.Unicode.GetString(data).TrimEnd('\0'),

			// 32-bit unsigned integer value - convert from byte array
			RegistryValueType.REG_DWORD => BitConverter.ToUInt32(data, 0),

			// 64-bit unsigned integer value - convert from byte array
			RegistryValueType.REG_QWORD => BitConverter.ToUInt64(data, 0),

			// Binary data - return raw byte array as-is
			RegistryValueType.REG_BINARY => data,

			// Multi-string value - parse null-separated unicode strings
			RegistryValueType.REG_MULTI_SZ => ParseMultiString(data),

			// Unknown or unsupported registry value type - return raw byte array
			_ => data
		};
	}

	private static string[] ParseMultiString(byte[] data)
	{
		string? unicodeString = Encoding.Unicode.GetString(data);
		string[] strings = unicodeString.Split('\0', StringSplitOptions.RemoveEmptyEntries);
		return strings;
	}

	/// <summary>
	/// Saves a list of RegistryPolicyEntry to a JSON file.
	/// </summary>
	/// <param name="path"></param>
	/// <param name="files"></param>
	internal static void Save(string path, List<RegistryPolicyEntry> files)
	{
		string json = JsonSerializer.Serialize(files, PolicyInputJsonContext.Default.ListRegistryPolicyEntry);
		File.WriteAllText(path, json);
	}

	/// <summary>
	/// Reads a JSON file containing the RegistryPolicyEntry data.
	/// </summary>
	/// <param name="path"></param>
	/// <returns></returns>
	/// <exception cref="FileNotFoundException"></exception>
	internal static List<RegistryPolicyEntry> Load(string path)
	{
		if (!File.Exists(path))
			throw new FileNotFoundException($"JSON file not found: {path}");

		string json = File.ReadAllText(path);

		return JsonSerializer.Deserialize(json, PolicyInputJsonContext.Default.ListRegistryPolicyEntry) ?? throw new InvalidOperationException($"Could not load the JSON file: {path}");
	}

	/// <summary>
	/// Reads a JSON file containing the RegistryPolicyEntry data and resolves the resource keys from the JSON.
	/// </summary>
	/// <param name="path"></param>
	/// <returns></returns>
	/// <exception cref="FileNotFoundException"></exception>
	internal static List<RegistryPolicyEntry> LoadWithFriendlyNameKeyResolve(string path)
	{
		if (!File.Exists(path))
			throw new FileNotFoundException($"JSON file not found: {path}");

		string json = File.ReadAllText(path);

		List<RegistryPolicyEntry> result = JsonSerializer.Deserialize(json, PolicyInputJsonContext.Default.ListRegistryPolicyEntry) ?? throw new InvalidOperationException($"Could not load the JSON file: {path}");

		foreach (RegistryPolicyEntry entry in result)
		{
			if (entry.FriendlyName is not null)
			{
				// Resolve the resource key to the actual string.
				entry.FriendlyName = GlobalVars.GetSecurityStr(entry.FriendlyName);
			}
		}

		return result;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool HasAlternateVerification(RegistryPolicyEntry item, string KeyName, string ValueName)
	{
		return string.Equals(item.KeyName, KeyName, StringComparison.OrdinalIgnoreCase) &&
			string.Equals(item.ValueName, ValueName, StringComparison.OrdinalIgnoreCase);
	}
}
