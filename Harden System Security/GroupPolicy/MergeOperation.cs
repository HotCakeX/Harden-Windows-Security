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

namespace HardenSystemSecurity.GroupPolicy;

/// <summary>
/// A class representing a single merge operation on registry policy entries.
/// </summary>
/// <param name="operationType"></param>
/// <param name="keyName"></param>
/// <param name="valueName"></param>
/// <param name="oldEntry"></param>
/// <param name="newEntry"></param>
internal sealed class MergeOperation(
	OperationType operationType,
	string keyName,
	string valueName,
	RegistryPolicyEntry? oldEntry,
	RegistryPolicyEntry newEntry)
{
	internal OperationType OperationType => operationType;
	internal string KeyName => keyName;
	internal string ValueName => valueName;
	internal RegistryPolicyEntry? OldEntry => oldEntry;
	internal RegistryPolicyEntry NewEntry => newEntry;

	public override string ToString()
	{
		return OperationType switch
		{
			OperationType.Added => $"ADDED: {KeyName}\\{ValueName} = {FormatValue(NewEntry.ParsedValue)} (Type: {NewEntry.Type})",
			OperationType.Replaced => $"REPLACED: {KeyName}\\{ValueName}\n  Old: {FormatValue(OldEntry?.ParsedValue)} (Type: {OldEntry?.Type})\n  New: {FormatValue(NewEntry.ParsedValue)} (Type: {NewEntry.Type})",
			_ => $"UNKNOWN: {KeyName}\\{ValueName}"
		};
	}

	private static string FormatValue(object? value)
	{
		return value switch
		{
			null => "<null>",
			byte[] bytes => $"<binary data, {bytes.Length} bytes>",
			string[] strings => $"[{string.Join(", ", strings)}]",
			_ => value.ToString() ?? "<null>"
		};
	}
}
