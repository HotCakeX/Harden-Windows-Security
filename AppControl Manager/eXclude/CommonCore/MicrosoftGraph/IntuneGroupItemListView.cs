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
/// Used to store Intune group Names/ID and is served as a DataType for ListViews that show them
/// </summary>
internal sealed class IntuneGroupItemListView(
	string groupName,
	string groupID,
	string? description,
	string? securityIdentifier,
	DateTime createdDateTime)
{
	[JsonInclude]
	[JsonPropertyName("Name")]
	internal string GroupName => groupName;

	[JsonInclude]
	[JsonPropertyName("ID")]
	internal string GroupID => groupID;

	[JsonInclude]
	[JsonPropertyName("Description")]
	internal string? Description => description;

	[JsonInclude]
	[JsonPropertyName("Security Identifier")]
	internal string? SecurityIdentifier => securityIdentifier;

	[JsonInclude]
	[JsonPropertyName("creation Date")]
	internal DateTime CreatedDateTime => createdDateTime;
}

/// <summary>
/// JSON source generated context for <see cref="IntuneGroupItemListView"/> type.
/// </summary>
[JsonSourceGenerationOptions(
	WriteIndented = true
)]
[JsonSerializable(typeof(IntuneGroupItemListView))]
[JsonSerializable(typeof(List<IntuneGroupItemListView>))]
internal sealed partial class IntuneGroupItemListViewJsonSerializationContext : JsonSerializerContext
{
}
