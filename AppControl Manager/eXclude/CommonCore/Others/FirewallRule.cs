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

namespace CommonCore.Others;

/// <summary>
/// Defines a Windows Firewall rule.
/// </summary>
/// <param name="name"></param>
/// <param name="direction"></param>
/// <param name="action"></param>
internal sealed class FirewallRule(string name, string direction, string action)
{
	[JsonInclude]
	[JsonPropertyOrder(0)]
	[JsonPropertyName("name")]
	internal string Name = name;

	[JsonInclude]
	[JsonPropertyOrder(1)]
	[JsonPropertyName("direction")]
	internal string Direction = direction;

	[JsonInclude]
	[JsonPropertyOrder(2)]
	[JsonPropertyName("action")]
	internal string Action = action;

	[JsonIgnore]
	internal string DisplayString { get; } = GetDisplayName(name);

	/// <summary>
	/// Extract only the file path from a name shaped like: Prefix-<file path>-Suffix
	/// </summary>
	/// <param name="s"></param>
	/// <returns></returns>
	private static string GetDisplayName(string s)
	{
		if (string.IsNullOrWhiteSpace(s))
		{
			return string.Empty;
		}

		int firstDashIndex = s.IndexOf('-', StringComparison.OrdinalIgnoreCase);
		if (firstDashIndex < 0 || firstDashIndex == s.Length - 1)
		{
			// No delimiter or nothing after it; return the original string.
			return s;
		}

		int lastDashIndex = s.LastIndexOf('-');
		if (lastDashIndex <= firstDashIndex)
		{
			// Only one dash (or invalid positions) -> take everything after the first dash
			return s[(firstDashIndex + 1)..];
		}

		int startIndex = firstDashIndex + 1;
		int length = lastDashIndex - startIndex;
		if (length <= 0)
		{
			return s;
		}

		string middle = s.Substring(startIndex, length);

		return middle.Trim();
	}
}

[JsonSourceGenerationOptions(
	PropertyNameCaseInsensitive = true,
	PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
	WriteIndented = true,
	NumberHandling = JsonNumberHandling.AllowReadingFromString
	)]
[JsonSerializable(typeof(FirewallRule))]
[JsonSerializable(typeof(List<FirewallRule>))]
internal sealed partial class FirewallRuleJSONContext : JsonSerializerContext
{
}
