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

namespace CommonCore.QuantumRelay;

/// <summary>
/// Represents a command request from the client application
/// </summary>
public sealed class CommandRequest(
	QCommandType commandType,
	IReadOnlyCollection<string> arguments,
	Dictionary<string, string>? metadata = null)
{
	/// <summary>
	/// The type of command to execute
	/// </summary>
	[JsonPropertyName("commandType")]
	public QCommandType CommandType => commandType;

	/// <summary>
	/// Arguments for the command
	/// </summary>
	[JsonPropertyName("arguments")]
	public IReadOnlyCollection<string> Arguments => arguments;

	/// <summary>
	/// Optional metadata for the command
	/// </summary>
	[JsonPropertyName("metadata")]
	public Dictionary<string, string>? Metadata => metadata;
}
