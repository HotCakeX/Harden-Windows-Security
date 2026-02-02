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
using Microsoft.UI.Xaml;

namespace CommonCore.MicrosoftGraph;

/// <summary>
/// Represents the response containing a list of assignments from Graph API.
/// </summary>
internal sealed class PolicyAssignmentResponse(List<PolicyAssignmentObject> value)
{
	[JsonPropertyName("value")]
	[JsonInclude]
	internal List<PolicyAssignmentObject> Value => value;
}

/// <summary>
/// Represents a single assignment object from Graph API.
/// </summary>
internal sealed class PolicyAssignmentObject(string id, PolicyAssignmentTarget target)
{
	[JsonPropertyName("id")]
	[JsonInclude]
	internal string Id => id;

	[JsonPropertyName("target")]
	[JsonInclude]
	internal PolicyAssignmentTarget Target => target;
}

/// <summary>
/// Represents the target of an assignment.
/// </summary>
internal sealed class PolicyAssignmentTarget(string? oDataType, string? groupId)
{
	[JsonPropertyName("@odata.type")]
	[JsonInclude]
	internal string? ODataType => oDataType;

	[JsonPropertyName("groupId")]
	[JsonInclude]
	internal string? GroupId => groupId;
}

/// <summary>
/// Class used to display assignment info in the UI.
/// </summary>
internal sealed class PolicyAssignmentDisplay(string name, string type, string? targetId, string? assignmentId)
{
	internal string Name => name;
	internal string Type => type;

	/// <summary>
	/// The ID of the Group/User/Device (Display purposes)
	/// </summary>
	internal string? TargetId => targetId;

	/// <summary>
	/// The ID of the Assignment Object itself (Required for deletion)
	/// </summary>
	internal string? AssignmentId => assignmentId;

	internal Visibility IdVisibility => string.IsNullOrEmpty(targetId) ? Visibility.Collapsed : Visibility.Visible;
}
