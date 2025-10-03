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
namespace AppControlManager.MicrosoftGraph;

/// <summary>
/// Represents a single device configuration policy.
/// </summary>
internal sealed class DeviceConfigurationPolicy(
	string? oDataType,
	string? id,
	DateTimeOffset? lastModifiedDateTime,
	List<string>? roleScopeTagIds,
	bool supportsScopeTags,
	string? deviceManagementApplicabilityRuleOsEdition,
	string? deviceManagementApplicabilityRuleOsVersion,
	string? deviceManagementApplicabilityRuleDeviceMode,
	DateTimeOffset? createdDateTime,
	string? description,
	string? displayName,
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
	/// OS edition rule for device management applicability.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("deviceManagementApplicabilityRuleOsEdition")]
	internal string? DeviceManagementApplicabilityRuleOsEdition => deviceManagementApplicabilityRuleOsEdition;

	/// <summary>
	/// OS version rule for device management applicability.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("deviceManagementApplicabilityRuleOsVersion")]
	internal string? DeviceManagementApplicabilityRuleOsVersion => deviceManagementApplicabilityRuleOsVersion;

	/// <summary>
	/// Device mode rule for device management applicability.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("deviceManagementApplicabilityRuleDeviceMode")]
	internal string? DeviceManagementApplicabilityRuleDeviceMode => deviceManagementApplicabilityRuleDeviceMode;

	/// <summary>
	/// Date and time when the policy was created.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("createdDateTime")]
	internal DateTimeOffset? CreatedDateTime => createdDateTime;

	/// <summary>
	/// Description of the policy.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("description")]
	internal string? Description => description;

	/// <summary>
	/// Display name of the policy.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("displayName")]
	internal string? DisplayName => displayName;

	/// <summary>
	/// Version of the policy.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("version")]
	internal int Version => version;

	/// <summary>
	/// List of OMA settings.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("omaSettings")]
	internal List<OmaSettingBase64>? OmaSettings => omaSettings;
}

/// <summary>
/// Represents the response from the Graph API that contains a list of device configuration policies.
/// </summary>
internal sealed class DeviceConfigurationPoliciesResponse(
	string? oDataContext,
	string? microsoftGraphTips,
	List<DeviceConfigurationPolicy>? value
)
{
	/// <summary>
	/// OData context information.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("@odata.context")]
	internal string? ODataContext => oDataContext;

	/// <summary>
	/// Additional Microsoft Graph tips.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("@microsoft.graph.tips")]
	internal string? MicrosoftGraphTips => microsoftGraphTips;

	/// <summary>
	/// The list of device configuration policies.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("value")]
	internal List<DeviceConfigurationPolicy>? Value => value;
}
