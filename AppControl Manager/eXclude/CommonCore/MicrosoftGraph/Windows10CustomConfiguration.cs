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
/// Define the class structure for the custom policy.
/// https://learn.microsoft.com/graph/api/resources/intune-deviceconfig-windows10customconfiguration?view=graph-rest-beta
/// </summary>
internal sealed class Windows10CustomConfiguration(
	string? oDataType,
	string? displayName,
	string? description,
	string? id,
	DateTimeOffset? lastModifiedDateTime,
	List<string>? roleScopeTagIds,
	bool supportsScopeTags,
	DateTimeOffset? createdDateTime,
	int version,
	List<OmaSettingBase64>? omaSettings
)
{
	/// <summary>
	/// Represents the OData type.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("@odata.type")]
	internal string? ODataType => oDataType;

	/// <summary>
	/// The display name of the custom configuration.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("displayName")]
	internal string? DisplayName => displayName;

	/// <summary>
	/// The description of the custom configuration.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("description")]
	internal string? Description => description;

	/// <summary>
	/// Unique identifier for the policy.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("id")]
	internal string? Id => id;

	/// <summary>
	/// Date and time when the policy was last modified.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("lastModifiedDateTime")]
	internal DateTimeOffset? LastModifiedDateTime => lastModifiedDateTime;

	/// <summary>
	/// List of role scope tag identifiers.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("roleScopeTagIds")]
	internal List<string>? RoleScopeTagIds => roleScopeTagIds;

	/// <summary>
	/// Indicates whether the policy supports scope tags.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("supportsScopeTags")]
	internal bool SupportsScopeTags => supportsScopeTags;

	/// <summary>
	/// Date and time when the policy was created.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("createdDateTime")]
	internal DateTimeOffset? CreatedDateTime => createdDateTime;

	/// <summary>
	/// Version of the policy.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("version")]
	internal int Version => version;

	/// <summary>
	/// The OMA settings associated with the configuration.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("omaSettings")]
	internal List<OmaSettingBase64>? OmaSettings => omaSettings;
}
