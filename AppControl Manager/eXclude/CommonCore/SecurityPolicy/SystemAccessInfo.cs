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

using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CommonCore.SecurityPolicy;

/// <summary>
/// Represents the policies defined in the [System Access].
/// Many of them implemented according to the specs defined here: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0d94df7c-9752-4b08-84de-bf29e389c074
/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0b40db09-d95d-40a6-8467-32aedec8140c
/// </summary>
internal sealed class SystemAccessInfo
{
	[JsonInclude]
	internal int MinimumPasswordAge { get; set; }
	[JsonInclude]
	internal int MaximumPasswordAge { get; set; }
	[JsonInclude]
	internal int MinimumPasswordLength { get; set; }
	[JsonInclude]
	internal int PasswordComplexity { get; set; }
	[JsonInclude]
	internal int PasswordHistorySize { get; set; }
	[JsonInclude]
	internal int LockoutBadCount { get; set; }
	[JsonInclude]
	internal int ResetLockoutCount { get; set; }
	[JsonInclude]
	internal int LockoutDuration { get; set; }
	[JsonInclude]
	internal int AllowAdministratorLockout { get; set; }
	[JsonInclude]
	internal int RequireLogonToChangePassword { get; set; }
	[JsonInclude]
	internal int ForceLogoffWhenHourExpire { get; set; }
	[JsonInclude]
	internal string NewAdministratorName { get; set; } = string.Empty;
	[JsonInclude]
	internal string NewGuestName { get; set; } = string.Empty;
	[JsonInclude]
	internal int ClearTextPassword { get; set; }

	/// <summary>
	/// Network access: Allow anonymous SID/name translation
	/// https://learn.microsoft.com/openspecs/windows_protocols/ms-gpsb/0d94df7c-9752-4b08-84de-bf29e389c074
	/// https://learn.microsoft.com/openspecs/windows_protocols/ms-gpsb/d6eaa54a-f609-48e9-8461-b32738d77a47
	/// </summary>
	[JsonInclude]
	internal int LSAAnonymousNameLookup { get; set; }

	[JsonInclude]
	internal int EnableAdminAccount { get; set; }
	[JsonInclude]
	internal int EnableGuestAccount { get; set; }
}

internal static class SystemAccessDefaults
{
	private static readonly string DefaultsFilePath = Path.Combine(AppContext.BaseDirectory, "Resources", "SystemAccessDefaults", "DefaultValues.json");

	/// <summary>
	/// Loads the default System Access settings from the JSON file.
	/// </summary>
	internal static SystemAccessInfo LoadSystemDefaults()
	{
		ReadOnlySpan<byte> json = File.ReadAllBytes(DefaultsFilePath);
		return JsonSerializer.Deserialize(json, SystemAccessJsonContext.Default.SystemAccessInfo)!;
	}

	/// <summary>
	/// Backs up the current System Access policies to a JSON file.
	/// </summary>
	internal static void BackupSystemAccessPolicies(string filePath)
	{
		// Get current system access settings
		SystemAccessInfo currentSettings = SecurityPolicyReader.GetSystemAccess();

		// Serialize to JSON
		string json = JsonSerializer.Serialize(currentSettings, SystemAccessJsonContext.Default.SystemAccessInfo);

		// Write to file
		File.WriteAllText(filePath, json);
	}
}

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(SystemAccessInfo))]
internal sealed partial class SystemAccessJsonContext : JsonSerializerContext
{
}
