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

using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Runtime;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using HardenSystemSecurity.Helpers;

namespace HardenSystemSecurity.MCP;

/// <summary>
/// MCP server that exposes Harden System Security operations over standard I/O.
/// </summary>
internal static class McpServer
{
	private const string ProtocolVersion = "2025-06-18";
	private const string DecodeQrToolName = "decode_qr";
	private const string CreateQrToolName = "create_qr";
	private const string MissingPathMessage = "The QR image path does not exist. Provide the absolute path of an existing image. Chat attachment paths must not be guessed.";
	private const string DecodeFailureMessage = "QR code could not be decoded.";
	private const string CreateFailureMessage = "QR code could not be created.";
	private const int MaximumEncodedImageBytes = 16 * 1024 * 1024;

	internal static async Task RunAsync()
	{
		using Stream input = Console.OpenStandardInput();
		using Stream output = Console.OpenStandardOutput();
		using StreamReader reader = new(input, new UTF8Encoding(false), false, 4096, leaveOpen: true);

		while (await reader.ReadLineAsync().ConfigureAwait(false) is string line)
		{
			if (string.IsNullOrWhiteSpace(line))
			{
				continue;
			}

			try
			{
				using JsonDocument request = JsonDocument.Parse(line);
				JsonElement root = request.RootElement;

				if (!IsValidJsonRpcEnvelope(root, out JsonElement methodElement, out bool hasId, out JsonElement id))
				{
					await WriteRequestErrorAsync(output, default, false, -32600, "Invalid Request.").ConfigureAwait(false);
					continue;
				}

				// Notifications deliberately receive no response. The currently supported MCP notifications do not require server-side work.
				if (!hasId)
				{
					continue;
				}

				string method = methodElement.GetString()!;
				ToolExecutionResult? toolResult = string.Equals(method, "tools/call", StringComparison.OrdinalIgnoreCase)
					? await ExecuteToolAsync(root).ConfigureAwait(false)
					: null;
				ArrayBufferWriter<byte> responseBuffer = new(1024);
				using (Utf8JsonWriter writer = new(responseBuffer))
				{
					writer.WriteStartObject();
					writer.WriteString("jsonrpc", "2.0");
					writer.WritePropertyName("id");
					id.WriteTo(writer);
					if (string.Equals(method, "initialize", StringComparison.OrdinalIgnoreCase))
					{
						WriteInitializeResult(writer);
					}
					else if (string.Equals(method, "tools/list", StringComparison.OrdinalIgnoreCase))
					{
						WriteToolsListResult(writer);
					}
					else if (string.Equals(method, "tools/call", StringComparison.OrdinalIgnoreCase))
					{
						WriteToolExecutionResult(writer, toolResult ?? ToolExecutionResult.Error("Unknown tool name."));
					}
					else if (string.Equals(method, "ping", StringComparison.OrdinalIgnoreCase))
					{
						writer.WriteStartObject("result");
						writer.WriteEndObject();
					}
					else
					{
						WriteProtocolError(writer, -32601, "Method not found.");
					}
					writer.WriteEndObject();
				}
				await WriteResponseAsync(output, responseBuffer.WrittenMemory).ConfigureAwait(false);
			}
			catch (JsonException)
			{
				await WriteParseErrorAsync(output).ConfigureAwait(false);
			}
			catch (Exception)
			{
				// Keep the stdio server alive after an unexpected request-processing failure without exposing internal details.
				await WriteRequestErrorAsync(output, default, false, -32603, "Internal error.").ConfigureAwait(false);
			}
		}
	}

	private static bool IsValidJsonRpcEnvelope(JsonElement root, out JsonElement methodElement, out bool hasId, out JsonElement id)
	{
		methodElement = default;
		id = default;
		hasId = false;
		if (root.ValueKind is not JsonValueKind.Object ||
			!root.TryGetProperty("jsonrpc", out JsonElement versionElement) ||
			versionElement.ValueKind is not JsonValueKind.String ||
			!string.Equals(versionElement.GetString(), "2.0", StringComparison.OrdinalIgnoreCase) ||
			!root.TryGetProperty("method", out methodElement) ||
			methodElement.ValueKind is not JsonValueKind.String ||
			string.IsNullOrWhiteSpace(methodElement.GetString()))
		{
			return false;
		}
		hasId = root.TryGetProperty("id", out id);
		return !hasId || id.ValueKind is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.Null;
	}

	private static void WriteInitializeResult(Utf8JsonWriter writer)
	{
		writer.WriteStartObject("result");
		writer.WriteString("protocolVersion", ProtocolVersion);
		writer.WriteStartObject("capabilities");
		writer.WriteStartObject("tools");
		writer.WriteBoolean("listChanged", false);
		writer.WriteEndObject();
		writer.WriteEndObject();
		writer.WriteStartObject("serverInfo");
		writer.WriteString("name", "Harden System Security");
		writer.WriteString("version", "1.0.0");
		writer.WriteEndObject();
		writer.WriteEndObject();
	}

	private static void WriteToolsListResult(Utf8JsonWriter writer)
	{
		writer.WriteStartObject("result");
		writer.WriteStartArray("tools");
		WriteDecodeQrToolDefinition(writer);
		WriteCreateQrToolDefinition(writer);
		WriteCheckFileReputationToolDefinition(writer);
		writer.WriteEndArray();
		writer.WriteEndObject();
	}

	private static void WriteDecodeQrToolDefinition(Utf8JsonWriter writer)
	{
		writer.WriteStartObject();
		writer.WriteString("name", DecodeQrToolName);
		writer.WriteString("description", "Decodes a QR code from an existing local image path or exact base64 image bytes. Never invent, infer, or construct a temporary path for a chat attachment. If a verified existing path or exact base64 bytes are unavailable, do not call this tool and ask the user to provide the original absolute path or save the attachment to disk first.");
		writer.WriteStartObject("inputSchema");
		writer.WriteString("type", "object");
		writer.WriteStartObject("properties");
		WriteStringProperty(writer, "image_path", "Verified absolute path of an image that already exists on disk. Never guess a path for a dragged or pasted chat attachment.");
		WriteStringProperty(writer, "image_base64", "Exact base64-encoded bytes supplied by the host. Never synthesize base64 from visual context.");
		writer.WriteEndObject();
		writer.WriteStartArray("anyOf");
		WriteRequiredProperty(writer, "image_path");
		WriteRequiredProperty(writer, "image_base64");
		writer.WriteEndArray();
		writer.WriteBoolean("additionalProperties", false);
		writer.WriteEndObject();
		writer.WriteEndObject();
	}

	private static void WriteCreateQrToolDefinition(Utf8JsonWriter writer)
	{
		writer.WriteStartObject();
		writer.WriteString("name", CreateQrToolName);
		writer.WriteString("description", "Creates a PNG QR code image from text and returns the generated image.");
		writer.WriteStartObject("inputSchema");
		writer.WriteString("type", "object");
		writer.WriteStartObject("properties");
		WriteStringProperty(writer, "text", "Text to encode in the QR code.");
		writer.WriteStartObject("error_correction_level");
		writer.WriteString("type", "string");
		writer.WriteString("description", "QR error correction level. Defaults to M.");
		writer.WriteStartArray("enum");
		writer.WriteStringValue("L");
		writer.WriteStringValue("M");
		writer.WriteStringValue("Q");
		writer.WriteStringValue("H");
		writer.WriteEndArray();
		writer.WriteString("default", "M");
		writer.WriteEndObject();
		writer.WriteEndObject();
		writer.WriteStartArray("required");
		writer.WriteStringValue("text");
		writer.WriteEndArray();
		writer.WriteBoolean("additionalProperties", false);
		writer.WriteEndObject();
		writer.WriteEndObject();
	}

	private static void WriteStringProperty(Utf8JsonWriter writer, string name, string description)
	{
		writer.WriteStartObject(name);
		writer.WriteString("type", "string");
		writer.WriteString("description", description);
		writer.WriteEndObject();
	}

	private static void WriteRequiredProperty(Utf8JsonWriter writer, string name)
	{
		writer.WriteStartObject();
		writer.WriteStartArray("required");
		writer.WriteStringValue(name);
		writer.WriteEndArray();
		writer.WriteEndObject();
	}

	private static async Task<ToolExecutionResult> ExecuteToolAsync(JsonElement root)
	{
		if (!root.TryGetProperty("params", out JsonElement parameters) || parameters.ValueKind is not JsonValueKind.Object || !parameters.TryGetProperty("name", out JsonElement nameElement) || nameElement.ValueKind is not JsonValueKind.String)
		{
			return ToolExecutionResult.Error("Unknown tool name.");
		}
		string? toolName = nameElement.GetString();
		JsonElement arguments = parameters.TryGetProperty("arguments", out JsonElement suppliedArguments) && suppliedArguments.ValueKind is JsonValueKind.Object ? suppliedArguments : default;
		return string.Equals(toolName, DecodeQrToolName, StringComparison.OrdinalIgnoreCase)
			? await DecodeQrAsync(arguments).ConfigureAwait(false)
			: string.Equals(toolName, CreateQrToolName, StringComparison.OrdinalIgnoreCase)
				? await CreateQrAsync(arguments).ConfigureAwait(false)
				: string.Equals(toolName, CheckFileReputationToolName, StringComparison.OrdinalIgnoreCase)
					? await CheckFileReputationAsync(arguments).ConfigureAwait(false)
					: ToolExecutionResult.Error("Unknown tool name.");
	}

	private static async Task<ToolExecutionResult> DecodeQrAsync(JsonElement arguments)
	{
		try
		{
			QR.QrResult result;
			string? imagePath = GetOptionalString(arguments, "image_path");
			string? imageBase64 = GetOptionalString(arguments, "image_base64");
			if (!string.IsNullOrWhiteSpace(imagePath) && string.IsNullOrWhiteSpace(imageBase64))
			{
				if (!Path.IsPathFullyQualified(imagePath) || !File.Exists(imagePath)) return ToolExecutionResult.Error(MissingPathMessage);
				List<QR.QrResult> results = await QR.Manage.DecodeAsync(new string[] { imagePath }).ConfigureAwait(false);
				result = results[0];
			}
			else if (string.IsNullOrWhiteSpace(imagePath) && !string.IsNullOrWhiteSpace(imageBase64))
			{
				byte[] encodedImage = Convert.FromBase64String(imageBase64);
				if (encodedImage.Length is 0 or > MaximumEncodedImageBytes) return ToolExecutionResult.Error(DecodeFailureMessage);
				result = await QR.Manage.DecodeAsync(encodedImage).ConfigureAwait(false);
			}
			else return ToolExecutionResult.Error(DecodeFailureMessage);
			return result.Error is null && !string.IsNullOrWhiteSpace(result.Text) ? ToolExecutionResult.Text(result.Text) : ToolExecutionResult.Error(DecodeFailureMessage);
		}
		catch (Exception)
		{
			return ToolExecutionResult.Error(DecodeFailureMessage);
		}
		finally
		{
			ReleaseQrWorkingMemory();
		}
	}

	private static async Task<ToolExecutionResult> CreateQrAsync(JsonElement arguments)
	{
		try
		{
			string? text = GetOptionalString(arguments, "text");
			if (string.IsNullOrEmpty(text)) return ToolExecutionResult.Error(CreateFailureMessage);
			char errorCorrectionLevel = ParseErrorCorrectionLevel(GetOptionalString(arguments, "error_correction_level") ?? "M");
			byte[] pngBytes = await QR.Manage.GeneratePngAsync(text, errorCorrectionLevel).ConfigureAwait(false);
			return ToolExecutionResult.Image(pngBytes, "image/png");
		}
		catch (Exception)
		{
			return ToolExecutionResult.Error(CreateFailureMessage);
		}
	}

	private static void ReleaseQrWorkingMemory()
	{
		// QR decoding intentionally allocates large temporary image and detection buffers.
		// The stdio server is idle between calls, so reclaim and compact those buffers immediately after each decode.
		GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
		GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, true, true);
	}

	private static string? GetOptionalString(JsonElement arguments, string propertyName) => arguments.ValueKind is JsonValueKind.Object && arguments.TryGetProperty(propertyName, out JsonElement property) && property.ValueKind is JsonValueKind.String ? property.GetString() : null;

	private static char ParseErrorCorrectionLevel(string value)
	{
		if (string.Equals(value, "L", StringComparison.OrdinalIgnoreCase)) return 'L';
		if (string.Equals(value, "M", StringComparison.OrdinalIgnoreCase)) return 'M';
		if (string.Equals(value, "Q", StringComparison.OrdinalIgnoreCase)) return 'Q';
		if (string.Equals(value, "H", StringComparison.OrdinalIgnoreCase)) return 'H';
		throw new ArgumentOutOfRangeException(nameof(value));
	}

	#region File Reputation MCP Tool

	private const string CheckFileReputationToolName = "check_file_reputation";
	private const string MissingFilePathMessage = "The file path does not exist. Provide the absolute path of an existing file.";
	private const string FileReputationFailureMessage = "File reputation could not be determined.";

	private static void WriteCheckFileReputationToolDefinition(Utf8JsonWriter writer)
	{
		writer.WriteStartObject();
		writer.WriteString("name", CheckFileReputationToolName);
		writer.WriteString("description", "Checks the Microsoft Defender SmartScreen or Smart App Control file reputation verdict for an existing local file path.");
		writer.WriteStartObject("inputSchema");
		writer.WriteString("type", "object");
		writer.WriteStartObject("properties");
		WriteStringProperty(writer, "file_path", "Absolute path of an existing local file whose reputation should be checked.");
		writer.WriteEndObject();
		writer.WriteStartArray("required");
		writer.WriteStringValue("file_path");
		writer.WriteEndArray();
		writer.WriteBoolean("additionalProperties", false);
		writer.WriteEndObject();
		writer.WriteEndObject();
	}

	private static async Task<ToolExecutionResult> CheckFileReputationAsync(JsonElement arguments)
	{
		try
		{
			string? filePath = GetOptionalString(arguments, "file_path");
			if (!File.Exists(filePath) || !Path.IsPathFullyQualified(filePath))
			{
				return ToolExecutionResult.Error(MissingFilePathMessage);
			}
			FileTrustChecker.FileTrustResult result = await Task.Run(() => FileTrustChecker.CheckFileTrust(filePath)).ConfigureAwait(false);
			ArrayBufferWriter<byte> resultBuffer = new(256);
			using (Utf8JsonWriter writer = new(resultBuffer))
			{
				writer.WriteStartObject();
				writer.WriteString("verdict", result.Reputation);
				writer.WriteString("source", result.Source.ToString());
				writer.WriteString("validity_duration", result.Duration);
				writer.WriteEndObject();
			}
			return ToolExecutionResult.Text(Encoding.UTF8.GetString(resultBuffer.WrittenSpan));
		}
		catch (Exception)
		{
			return ToolExecutionResult.Error(FileReputationFailureMessage);
		}
	}

	#endregion

	private static void WriteToolExecutionResult(Utf8JsonWriter writer, ToolExecutionResult executionResult)
	{
		writer.WriteStartObject("result");
		writer.WriteStartArray("content");
		writer.WriteStartObject();
		if (executionResult.ImageBytes is ReadOnlyMemory<byte> imageBytes)
		{
			writer.WriteString("type", "image");
			writer.WriteBase64String("data", imageBytes.Span);
			writer.WriteString("mimeType", executionResult.MimeType);
		}
		else
		{
			writer.WriteString("type", "text"); writer.WriteString("text", executionResult.TextContent ?? string.Empty);
		}
		writer.WriteEndObject();
		writer.WriteEndArray();
		writer.WriteBoolean("isError", executionResult.IsError);
		writer.WriteEndObject();
	}

	private static void WriteProtocolError(Utf8JsonWriter writer, int code, string message)
	{
		writer.WriteStartObject("error");
		writer.WriteNumber("code", code);
		writer.WriteString("message", message);
		writer.WriteEndObject();
	}

	private static async Task WriteResponseAsync(Stream output, ReadOnlyMemory<byte> response)
	{
		await output.WriteAsync(response).ConfigureAwait(false);
		await output.WriteAsync("\n"u8.ToArray()).ConfigureAwait(false);
		await output.FlushAsync().ConfigureAwait(false);
	}

	private static async Task WriteRequestErrorAsync(Stream output, JsonElement id, bool hasId, int code, string message)
	{
		ArrayBufferWriter<byte> responseBuffer = new(160);
		using (Utf8JsonWriter writer = new(responseBuffer))
		{
			writer.WriteStartObject();
			writer.WriteString("jsonrpc", "2.0");
			writer.WritePropertyName("id");
			if (hasId)
			{
				id.WriteTo(writer);
			}
			else
			{
				writer.WriteNullValue();
			}
			WriteProtocolError(writer, code, message);
			writer.WriteEndObject();
		}
		await WriteResponseAsync(output, responseBuffer.WrittenMemory).ConfigureAwait(false);
	}

	private static Task WriteParseErrorAsync(Stream output) => WriteRequestErrorAsync(output, default, false, -32700, "Parse error.");

	private sealed class ToolExecutionResult
	{
		private ToolExecutionResult(string? textContent, ReadOnlyMemory<byte>? imageBytes, string? mimeType, bool isError) { TextContent = textContent; ImageBytes = imageBytes; MimeType = mimeType; IsError = isError; }
		internal string? TextContent { get; }
		internal ReadOnlyMemory<byte>? ImageBytes { get; }
		internal string? MimeType { get; }
		internal bool IsError { get; }
		internal static ToolExecutionResult Text(string text) => new(text, null, null, false);
		internal static ToolExecutionResult Image(byte[] imageBytes, string mimeType) => new(null, imageBytes, mimeType, false);
		internal static ToolExecutionResult Error(string message) => new(message, null, null, true);
	}
}
