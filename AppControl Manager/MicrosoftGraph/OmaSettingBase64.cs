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

using System.Text.Json.Serialization;

namespace AppControlManager.MicrosoftGraph;

/// <summary>
/// Represents a configuration setting with properties for OData type, display name, description, URI, file name, and
/// value.
/// </summary>
internal sealed class OmaSettingBase64
{
	[JsonInclude]
	[JsonPropertyName("@odata.type")]
	internal string? ODataType { get; set; }

	[JsonInclude]
	[JsonPropertyName("displayName")]
	internal string? DisplayName { get; set; }

	[JsonInclude]
	[JsonPropertyName("description")]
	internal string? Description { get; set; }

	[JsonInclude]
	[JsonPropertyName("omaUri")]
	internal string? OmaUri { get; set; }

	[JsonInclude]
	[JsonPropertyName("fileName")]
	internal string? FileName { get; set; }

	[JsonInclude]
	[JsonPropertyName("value")]
	internal string? Value { get; set; }
}
