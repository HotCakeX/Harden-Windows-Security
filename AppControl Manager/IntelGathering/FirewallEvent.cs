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

namespace AppControlManager.IntelGathering;

internal sealed class FirewallEvent
{
	[JsonInclude]
	internal DateTime? TimeCreated { get; init; }

	[JsonInclude]
	internal string? Application { get; init; }

	[JsonInclude]
	internal string? Direction { get; init; }

	[JsonInclude]
	internal string? Protocol { get; init; }

	[JsonInclude]
	internal string? SourceAddress { get; init; }

	[JsonInclude]
	internal string? DestAddress { get; init; }

	[JsonInclude]
	internal string? SourcePort { get; init; }

	[JsonInclude]
	internal string? DestPort { get; init; }

	[JsonInclude]
	internal string? ProcessId { get; init; }

	[JsonInclude]
	internal string? FilterOrigin { get; init; }

	[JsonInclude]
	internal string? LayerName { get; init; }

	[JsonInclude]
	internal string? Interface { get; init; }

	[JsonInclude]
	internal string? UserID { get; init; }
}
