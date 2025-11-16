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
using System.Text.Json.Serialization;

namespace HardenSystemSecurity.Protect;

/// <summary>
/// Represents a single desired WMI value with its declared type.
/// If any of these values match the result of a WMI call then the security measure must be considered value/true/applied.
/// </summary>
internal sealed class WmiDesiredValue(
	string value,
	string type
)
{
	[JsonInclude]
	internal string Value => value;

	[JsonInclude]
	internal string Type => type;
}

/// <summary>
/// Represents one specialized verification item from the JSON file which is an array of these objects.
/// </summary>
internal sealed class WmiSpecialVerificationItem(
	string category,
	string friendlyName,
	uint registryHive,
	string registryKeyName,
	string registryValueName,
	string wmiNamespace,
	string wmiClass,
	string wmiProperty,
	List<WmiDesiredValue> desiredWmiValues,
	bool isSpecialVerification
)
{
	[JsonInclude]
	internal string Category => category;

	[JsonInclude]
	internal string FriendlyName => friendlyName;

	[JsonInclude]
	internal uint RegistryHive => registryHive;

	[JsonInclude]
	internal string RegistryKeyName => registryKeyName;

	[JsonInclude]
	internal string RegistryValueName => registryValueName;

	[JsonInclude]
	internal string WMINamespace => wmiNamespace;

	[JsonInclude]
	internal string WMIClass => wmiClass;

	[JsonInclude]
	internal string WMIProperty => wmiProperty;

	[JsonInclude]
	internal List<WmiDesiredValue> DesiredWMIValues => desiredWmiValues;

	[JsonInclude]
	internal bool IsSpecialVerification => isSpecialVerification;

	// PolicyKey format must match fallback lookup in MUnit (KeyName|ValueName)
	internal string PolicyKey => string.Concat(RegistryKeyName, "|", RegistryValueName);
}

/// <summary>
/// Source generation context for deserializing the JSON array.
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(List<WmiSpecialVerificationItem>))]
internal sealed partial class WmiSpecialVerificationJsonContext : JsonSerializerContext
{
}
