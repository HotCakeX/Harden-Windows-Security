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
/// The Device Health Script object.
/// https://learn.microsoft.com/graph/api/resources/intune-devices-devicehealthscript?view=graph-rest-beta
/// </summary>
internal sealed class DeviceHealthScript
{
	[JsonInclude]
	[JsonPropertyName("id")]
	internal string? Id { get; set; }

	[JsonInclude]
	[JsonPropertyName("publisher")]
	internal string? Publisher { get; set; }

	[JsonInclude]
	[JsonPropertyName("version")]
	internal string? Version { get; set; }

	[JsonInclude]
	[JsonPropertyName("displayName")]
	internal string? DisplayName { get; set; }

	[JsonInclude]
	[JsonPropertyName("description")]
	internal string? Description { get; set; }

	/// <summary>
	/// Binary in the doc, Base64 string in JSON
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("detectionScriptContent")]
	internal string? DetectionScriptContent { get; set; }

	/// <summary>
	/// Binary in the doc, Base64 string in JSON
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("remediationScriptContent")]
	internal string? RemediationScriptContent { get; set; }

	[JsonInclude]
	[JsonPropertyName("createdDateTime")]
	internal DateTimeOffset? CreatedDateTime { get; set; }

	[JsonInclude]
	[JsonPropertyName("lastModifiedDateTime")]
	internal DateTimeOffset? LastModifiedDateTime { get; set; }

	[JsonInclude]
	[JsonPropertyName("runAsAccount")]
	internal string? RunAsAccount { get; set; }

	[JsonInclude]
	[JsonPropertyName("enforceSignatureCheck")]
	internal bool? EnforceSignatureCheck { get; set; }

	[JsonInclude]
	[JsonPropertyName("runAs32Bit")]
	internal bool? RunAs32Bit { get; set; }

	[JsonInclude]
	[JsonPropertyName("roleScopeTagIds")]
	internal List<string>? RoleScopeTagIds { get; set; }

	[JsonInclude]
	[JsonPropertyName("isGlobalScript")]
	internal bool? IsGlobalScript { get; set; }

	[JsonInclude]
	[JsonPropertyName("highestAvailableVersion")]
	internal string? HighestAvailableVersion { get; set; }

	/// <summary>
	/// https://learn.microsoft.com/graph/api/resources/intune-devices-devicehealthscripttype?view=graph-rest-beta
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("deviceHealthScriptType")]
	internal string? DeviceHealthScriptType { get; set; }

	[JsonInclude]
	[JsonPropertyName("detectionScriptParameters")]
	internal List<DeviceHealthScriptStringParameter>? DetectionScriptParameters { get; set; }

	[JsonInclude]
	[JsonPropertyName("remediationScriptParameters")]
	internal List<DeviceHealthScriptStringParameter>? RemediationScriptParameters { get; set; }
}

/// <summary>
/// A string parameter for the Device Health Script.
/// https://learn.microsoft.com/graph/api/resources/intune-devices-devicehealthscriptstringparameter?view=graph-rest-beta
/// </summary>
internal sealed class DeviceHealthScriptStringParameter
{
	[JsonInclude]
	[JsonPropertyName("@odata.type")]
	internal string ODataType { get; set; } = "#microsoft.graph.deviceHealthScriptStringParameter";

	[JsonInclude]
	[JsonPropertyName("name")]
	internal string? Name { get; set; }

	[JsonInclude]
	[JsonPropertyName("description")]
	internal string? Description { get; set; }

	[JsonInclude]
	[JsonPropertyName("isRequired")]
	internal bool IsRequired { get; set; }

	[JsonInclude]
	[JsonPropertyName("applyDefaultValueWhenNotAssigned")]
	internal bool ApplyDefaultValueWhenNotAssigned { get; set; }

	[JsonInclude]
	[JsonPropertyName("defaultValue")]
	internal string? DefaultValue { get; set; }
}

/// <summary>
/// Envelope for listing Device Health Scripts.
/// </summary>
internal sealed class DeviceHealthScriptsResponse
{
	[JsonInclude]
	[JsonPropertyName("@odata.context")]
	internal string? ODataContext { get; set; }

	[JsonInclude]
	[JsonPropertyName("@microsoft.graph.tips")]
	internal string? MicrosoftGraphTips { get; set; }

	[JsonInclude]
	[JsonPropertyName("value")]
	internal List<DeviceHealthScript>? Value { get; set; }
}
