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

namespace CommonCore.QuantumRelay;

/// <summary>
/// Base message envelope for type discrimination
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "messageType")]
[JsonDerivedType(typeof(LogMessage), "log")]
[JsonDerivedType(typeof(ResponseMessage), "response")]
public abstract class MessageEnvelope
{
	public abstract string MessageType { get; }
}

/// <summary>
/// Message envelope for log entries
/// </summary>
public sealed class LogMessage(LogEntry logEntry) : MessageEnvelope
{
	public override string MessageType => "log";

	[JsonPropertyName("logEntry")]
	public LogEntry LogEntry => logEntry;
}

/// <summary>
/// Message envelope for command responses
/// </summary>
public sealed class ResponseMessage(CommandResponse commandResponse) : MessageEnvelope
{
	public override string MessageType => "response";

	[JsonPropertyName("commandResponse")]
	public CommandResponse CommandResponse => commandResponse;
}
