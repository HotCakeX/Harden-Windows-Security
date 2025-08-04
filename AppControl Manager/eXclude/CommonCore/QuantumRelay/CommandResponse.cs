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
/// Represents a command response sent back to the client application
/// </summary>
public sealed class CommandResponse(
	bool success,
	string output,
	string errorOutput,
	int exitCode,
	string errorMessage,
	long executionTimeMs,
	IReadOnlyCollection<LogEntry> logs,
	Dictionary<string, string>? metadata = null)
{
	/// <summary>
	/// Indicates whether the command executed successfully
	/// </summary>
	[JsonPropertyName("success")]
	public bool Success => success;

	/// <summary>
	/// Standard output from the executed command
	/// </summary>
	[JsonPropertyName("output")]
	public string Output => output;

	/// <summary>
	/// Standard error output from the executed command
	/// </summary>
	[JsonPropertyName("errorOutput")]
	public string ErrorOutput => errorOutput;

	/// <summary>
	/// Exit code from the executed command
	/// </summary>
	[JsonPropertyName("exitCode")]
	public int ExitCode => exitCode;

	/// <summary>
	/// Error message if the command failed
	/// </summary>
	[JsonPropertyName("errorMessage")]
	public string ErrorMessage => errorMessage;

	/// <summary>
	/// Execution time in milliseconds
	/// </summary>
	[JsonPropertyName("executionTimeMs")]
	public long ExecutionTimeMs => executionTimeMs;

	/// <summary>
	/// Log entries generated during command execution
	/// </summary>
	[JsonPropertyName("logs")]
	public IReadOnlyCollection<LogEntry> Logs => logs;

	/// <summary>
	/// Additional response metadata
	/// </summary>
	[JsonPropertyName("metadata")]
	public Dictionary<string, string>? Metadata => metadata;
}
