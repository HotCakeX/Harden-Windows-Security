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

namespace CommonCore.MicrosoftGraph;

/// <summary>
/// Represents a standard (non-custom OMA-URI) device management configuration policy.
/// https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfigv2-devicemanagementconfigurationpolicy?view=graph-rest-beta
/// </summary>
internal sealed class DeviceManagementConfigurationPolicy(
	string? id,
	string? name,
	string? description,
	string? platforms,
	string? technologies,
	int? settingCount,
	DateTimeOffset? createdDateTime,
	DateTimeOffset? lastModifiedDateTime,
	List<string>? roleScopeTagIds
)
{
	[JsonInclude]
	[JsonPropertyName("id")]
	internal string? Id => id;

	[JsonInclude]
	[JsonPropertyName("name")]
	internal string? Name => name;

	[JsonInclude]
	[JsonPropertyName("description")]
	internal string? Description => description;

	[JsonInclude]
	[JsonPropertyName("platforms")]
	internal string? Platforms => platforms;

	[JsonInclude]
	[JsonPropertyName("technologies")]
	internal string? Technologies => technologies;

	[JsonInclude]
	[JsonPropertyName("settingCount")]
	internal int? SettingCount => settingCount;

	[JsonInclude]
	[JsonPropertyName("createdDateTime")]
	internal DateTimeOffset? CreatedDateTime => createdDateTime;

	[JsonInclude]
	[JsonPropertyName("lastModifiedDateTime")]
	internal DateTimeOffset? LastModifiedDateTime => lastModifiedDateTime;

	[JsonInclude]
	[JsonPropertyName("roleScopeTagIds")]
	internal List<string>? RoleScopeTagIds => roleScopeTagIds;
}

/// <summary>
/// Response container for configuration policies listing (pagination supported).
/// </summary>
internal sealed class DeviceManagementConfigurationPoliciesResponse(
	string? oDataContext,
	List<DeviceManagementConfigurationPolicy>? value
)
{
	[JsonInclude]
	[JsonPropertyName("@odata.context")]
	internal string? ODataContext => oDataContext;

	[JsonInclude]
	[JsonPropertyName("value")]
	internal List<DeviceManagementConfigurationPolicy>? Value => value;
}
