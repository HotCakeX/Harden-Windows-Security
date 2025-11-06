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
/// https://learn.microsoft.com/graph/api/resources/group?view=graph-rest-beta
/// </summary>
internal sealed class Group(
	string? displayName,
	string? description,
	bool mailEnabled,
	string mailNickname,
	bool securityEnabled,
	List<string> groupTypes
)
{
	[JsonInclude]
	[JsonPropertyName("displayName")]
	internal string? DisplayName => displayName;

	[JsonInclude]
	[JsonPropertyName("description")]
	internal string? Description => description;

	[JsonInclude]
	[JsonPropertyName("mailEnabled")]
	internal bool MailEnabled => mailEnabled;

	[JsonInclude]
	[JsonPropertyName("mailNickname")]
	internal string MailNickname => mailNickname;

	[JsonInclude]
	[JsonPropertyName("securityEnabled")]
	internal bool SecurityEnabled => securityEnabled;

	[JsonInclude]
	[JsonPropertyName("groupTypes")]
	internal List<string> GroupTypes => groupTypes;
}
