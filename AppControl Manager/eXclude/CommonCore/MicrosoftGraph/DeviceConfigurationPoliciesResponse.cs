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
/// Represents the response from the Graph API that contains a list of device configuration policies.
/// </summary>
internal sealed class DeviceConfigurationPoliciesResponse(
	string? oDataContext,
	string? microsoftGraphTips,
	List<Windows10CustomConfiguration>? value
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
	internal List<Windows10CustomConfiguration>? Value => value;
}
