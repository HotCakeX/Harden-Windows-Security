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
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using HardenSystemSecurity.ViewModels;

namespace HardenSystemSecurity.MCP;

/// <summary>
/// MCP server that exposes Harden System Security operations over standard I/O.
/// </summary>
internal static class McpServer
{
	private const string ProtocolVersion = "2025-06-18";
	private const string DecodeQrToolName = "decode_qr";
	private const string CreateQrToolName = "create_qr";
	private const string VerifySecurityHardeningToolName = "verify_security_hardening";
	private const string ApplySecurityHardeningToolName = "apply_security_hardening";
	private const string RemoveSecurityHardeningToolName = "remove_security_hardening";
	private const string MissingPathMessage = "The QR image path does not exist. Provide the absolute path of an existing image. Chat attachment paths must not be guessed.";
	private const string DecodeFailureMessage = "QR code could not be decoded.";
	private const string CreateFailureMessage = "QR code could not be created.";
	private const int MaximumEncodedImageBytes = 16 * 1024 * 1024;
	private static readonly byte[] NewLine = "\n"u8.ToArray();

	internal static async Task RunAsync(Stream input, Stream output)
	{
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

				string? method = methodElement.GetString();
				ToolExecutionResult? toolResult = string.Equals(method, "tools/call", StringComparison.OrdinalIgnoreCase)
					? await ExecuteToolAsync(root, output).ConfigureAwait(false)
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
		WriteVerifySecurityHardeningToolDefinition(writer);
		WriteMutationToolDefinition(writer, ApplySecurityHardeningToolName, "Applies the selected Harden System Security preset with administrator privileges.");
		WriteMutationToolDefinition(writer, RemoveSecurityHardeningToolName, "Removes the selected Harden System Security preset with administrator privileges and can reduce protection.");
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

	private static async Task<ToolExecutionResult> ExecuteToolAsync(JsonElement root, Stream output)
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
					: string.Equals(toolName, VerifySecurityHardeningToolName, StringComparison.OrdinalIgnoreCase)
						? await VerifySecurityHardeningAsync(arguments, parameters, output).ConfigureAwait(false)
						: string.Equals(toolName, ApplySecurityHardeningToolName, StringComparison.OrdinalIgnoreCase)
							? await MutateSecurityHardeningAsync(arguments, parameters, output, Helpers.MUnitOperation.Apply).ConfigureAwait(false)
							: string.Equals(toolName, RemoveSecurityHardeningToolName, StringComparison.OrdinalIgnoreCase)
								? await MutateSecurityHardeningAsync(arguments, parameters, output, Helpers.MUnitOperation.Remove).ConfigureAwait(false)
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

	private static int GetPresetIndex(string? preset) =>
		string.Equals(preset, "basic", StringComparison.OrdinalIgnoreCase) ? 0 :
		string.Equals(preset, "recommended", StringComparison.OrdinalIgnoreCase) ? 1 :
		string.Equals(preset, "complete", StringComparison.OrdinalIgnoreCase) ? 2 : -1;

	private static char ParseErrorCorrectionLevel(string value)
	{
		if (string.Equals(value, "L", StringComparison.OrdinalIgnoreCase)) return 'L';
		if (string.Equals(value, "M", StringComparison.OrdinalIgnoreCase)) return 'M';
		if (string.Equals(value, "Q", StringComparison.OrdinalIgnoreCase)) return 'Q';
		if (string.Equals(value, "H", StringComparison.OrdinalIgnoreCase)) return 'H';
		throw new ArgumentOutOfRangeException(nameof(value));
	}

	#region Security Hardening MCP Tools
	private static void WriteVerifySecurityHardeningToolDefinition(Utf8JsonWriter writer)
	{
		writer.WriteStartObject();
		writer.WriteString("name", VerifySecurityHardeningToolName);
		writer.WriteString("description", "Verifies the selected Harden System Security preset with administrator privileges and returns the final compliance score.");
		writer.WriteStartObject("inputSchema");
		writer.WriteString("type", "object");
		writer.WriteStartObject("properties");
		WritePresetProperty(writer, "Security hardening preset to verify.");
		writer.WriteEndObject();
		writer.WriteStartArray("required");
		writer.WriteStringValue("preset");
		writer.WriteEndArray();
		writer.WriteBoolean("additionalProperties", false);
		writer.WriteEndObject();
		writer.WriteEndObject();
	}

	private static void WritePresetProperty(Utf8JsonWriter writer, string? description)
	{
		writer.WriteStartObject("preset");
		writer.WriteString("type", "string");
		if (description is not null) writer.WriteString("description", description);
		writer.WriteStartArray("enum");
		writer.WriteStringValue("basic");
		writer.WriteStringValue("recommended");
		writer.WriteStringValue("complete");
		writer.WriteEndArray();
		writer.WriteEndObject();
	}

	private static void WriteMutationToolDefinition(Utf8JsonWriter writer, string name, string description)
	{
		writer.WriteStartObject();
		writer.WriteString("name", name);
		writer.WriteString("description", description);
		writer.WriteStartObject("inputSchema");
		writer.WriteString("type", "object");
		writer.WriteStartObject("properties");
		WritePresetProperty(writer, null);
		writer.WriteStartObject("confirmed");
		writer.WriteString("type", "boolean");
		writer.WriteString("description", "Must be true only after explicit user approval.");
		writer.WriteEndObject();
		writer.WriteEndObject();
		writer.WriteStartArray("required");
		writer.WriteStringValue("preset");
		writer.WriteStringValue("confirmed");
		writer.WriteEndArray();
		writer.WriteBoolean("additionalProperties", false);
		writer.WriteEndObject();
		writer.WriteStartObject("annotations");
		writer.WriteBoolean("readOnlyHint", false);
		writer.WriteBoolean("destructiveHint", true);
		writer.WriteBoolean("idempotentHint", false);
		writer.WriteBoolean("openWorldHint", false);
		writer.WriteEndObject();
		writer.WriteEndObject();
	}

	private static async Task<ToolExecutionResult> MutateSecurityHardeningAsync(
		JsonElement arguments,
		JsonElement parameters,
		Stream output,
		Helpers.MUnitOperation operation)
	{
		string? preset = GetOptionalString(arguments, "preset");
		int presetIndex = GetPresetIndex(preset);
		if (presetIndex < 0)
		{
			return ToolExecutionResult.Error("The preset must be basic, recommended, or complete.");
		}
		if (arguments.ValueKind is not JsonValueKind.Object ||
			!arguments.TryGetProperty("confirmed", out JsonElement confirmed) ||
			confirmed.ValueKind is not JsonValueKind.True)
		{
			return ToolExecutionResult.Error("Explicit user confirmation is required.");
		}

		Func<int, int, string, Task>? progress = CreateProgressCallback(
			parameters,
			output,
			message => $"{operation} {message}");

		string operationName = operation.ToString().ToLowerInvariant();

		try
		{
			if (Atlas.IsElevated)
			{
				ProtectVM.PresetOperationResult directResult = await ViewModelProvider.ProtectVM.RunPresetFromCliAsync(presetIndex, operation, progress);
				if (!directResult.Succeeded)
				{
					throw new InvalidOperationException($"Security hardening {operationName} did not complete.");
				}
				return CreateMutationSuccessResult(preset!, operationName);
			}
			ProtectVM.PresetOperationResult elevatedResult = await RunElevatedPresetOperationAsync(presetIndex, operation, progress).ConfigureAwait(false);
			return elevatedResult.Succeeded ? CreateMutationSuccessResult(preset!, operationName) : throw new InvalidOperationException($"Security hardening {operationName} did not complete.");
		}
		catch (Exception)
		{
			return ToolExecutionResult.Error($"Security hardening {operationName} failed.");
		}
	}

	private static async Task<ToolExecutionResult> VerifySecurityHardeningAsync(JsonElement arguments, JsonElement parameters, Stream output)
	{
		string? preset = GetOptionalString(arguments, "preset");
		int presetIndex = GetPresetIndex(preset);
		if (presetIndex < 0)
		{
			return ToolExecutionResult.Error("The preset must be basic, recommended, or complete.");
		}

		Func<int, int, string, Task>? progress = CreateProgressCallback(
			parameters,
			output,
			static category => $"Verifying {category}");

		try
		{
			ProtectVM.PresetVerificationResult result;
			if (Atlas.IsElevated)
			{
				ProtectVM.PresetOperationResult operationResult = await ViewModelProvider.ProtectVM.RunPresetFromCliAsync(
					presetIndex,
					Helpers.MUnitOperation.Verify,
					progress).ConfigureAwait(false);
				result = operationResult.Succeeded && operationResult.Verification is ProtectVM.PresetVerificationResult verification
					? verification
					: throw new InvalidOperationException("Security hardening verification did not return a result.");
			}
			else
			{
				ProtectVM.PresetOperationResult elevatedResult = await RunElevatedPresetOperationAsync(presetIndex, Helpers.MUnitOperation.Verify, progress).ConfigureAwait(false);
				result = elevatedResult.Succeeded && elevatedResult.Verification is ProtectVM.PresetVerificationResult verification
					? verification
					: throw new InvalidOperationException("Security hardening verification did not return a result.");
			}
			ArrayBufferWriter<byte> resultBuffer = new(256);
			using (Utf8JsonWriter writer = new(resultBuffer))
			{
				writer.WriteStartObject();
				writer.WriteString("preset", preset);
				writer.WriteNumber("verified_categories", result.Categories);
				writer.WriteNumber("total", result.Total);
				writer.WriteNumber("compliant", result.Compliant);
				writer.WriteNumber("non_compliant", result.NonCompliant);
				writer.WriteNumber("score_percentage", result.Percentage);
				writer.WriteEndObject();
			}
			return ToolExecutionResult.Text(Encoding.UTF8.GetString(resultBuffer.WrittenSpan));
		}
		catch (Exception)
		{
			return ToolExecutionResult.Error("Security hardening verification failed.");
		}
	}

	private const string ProtectOperationPipePrefix = @"LOCAL\HardenSystemSecurity.MCP.ProtectOperation.";

	private static async Task<ProtectVM.PresetOperationResult> RunElevatedPresetOperationAsync(int presetIndex, Helpers.MUnitOperation operation, Func<int, int, string, Task>? progress)
	{
		int operationCode = presetIndex + (operation is Helpers.MUnitOperation.Apply ? 3 : operation is Helpers.MUnitOperation.Remove ? 6 : 0);
		string channelId = Guid.CreateVersion7().ToString("N");
		string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
		await using NamedPipeServerStream pipe = new($"{ProtectOperationPipePrefix}{channelId}", PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
		ProcessStartInfo startInfo = new("HSS.exe") { UseShellExecute = true, Verb = "runas" };
		startInfo.ArgumentList.Add("--mcp-protect-worker");
		startInfo.ArgumentList.Add(channelId);
		startInfo.ArgumentList.Add(nonce);
		startInfo.ArgumentList.Add(operationCode.ToString(System.Globalization.CultureInfo.InvariantCulture));
		using Process worker = Process.Start(startInfo) ?? throw new InvalidOperationException("The elevated Protect operation worker could not be started.");
		using CancellationTokenSource connectionTimeout = new(TimeSpan.FromSeconds(60));
		await pipe.WaitForConnectionAsync(connectionTimeout.Token).ConfigureAwait(false);
		using StreamReader reader = new(pipe, new UTF8Encoding(false), false, 1024, leaveOpen: true);
		StreamWriter writer = new(pipe, new UTF8Encoding(false), 1024, leaveOpen: true) { AutoFlush = true };
		string? authentication = await reader.ReadLineAsync().ConfigureAwait(false);

		// Keep the one-shot elevated worker blocked until this server validates its per-launch nonce.
		bool authenticated = authentication is not null &&
			CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(nonce), Encoding.ASCII.GetBytes(authentication));
		await writer.WriteLineAsync(authenticated ? "A|1" : "A|0").ConfigureAwait(false);
		if (!authenticated)
		{
			DisposePipeWriter(writer);
			throw new InvalidOperationException("The elevated Protect operation worker could not be authenticated.");
		}
		while (await reader.ReadLineAsync().ConfigureAwait(false) is string line)
		{
			string[] parts = line.Split('|', operation is Helpers.MUnitOperation.Verify ? 6 : 4);
			if (parts.Length == 4 && string.Equals(parts[0], "P", StringComparison.OrdinalIgnoreCase))
			{
				if (progress is not null && int.TryParse(parts[1], out int current) && int.TryParse(parts[2], out int total)) await progress(current, total, Encoding.UTF8.GetString(Convert.FromBase64String(parts[3]))).ConfigureAwait(false);
				continue;
			}
			if (operation is Helpers.MUnitOperation.Verify && parts.Length == 6 && string.Equals(parts[0], "R", StringComparison.OrdinalIgnoreCase) && int.TryParse(parts[1], out int categories) && int.TryParse(parts[2], out int totalMeasures) && int.TryParse(parts[3], out int compliant) && int.TryParse(parts[4], out int nonCompliant) && double.TryParse(parts[5], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double percentage)) return new(true, new(categories, totalMeasures, compliant, nonCompliant, percentage));
			if (parts.Length == 2 && string.Equals(parts[0], "O", StringComparison.OrdinalIgnoreCase) && string.Equals(parts[1], operation.ToString(), StringComparison.OrdinalIgnoreCase)) return new(true, null);
		}
		throw new InvalidOperationException("The elevated Protect operation worker did not return a result.");
	}

	private static ToolExecutionResult CreateMutationSuccessResult(string preset, string operationName) => ToolExecutionResult.Text($"{{\"preset\":\"{preset}\",\"operation\":\"{operationName}\",\"completed\":true}}");

	internal static async Task RunProtectWorkerAsync(string channelId, string nonce, int operationCode)
	{
		try
		{
			await RunProtectWorkerCoreAsync(channelId, nonce, operationCode);
		}
		finally
		{
			// This is a one-shot elevated worker entry point. Always terminate the process after success,
			// rejection, pipe failure, cancellation, or operation failure so no hidden WinUI process remains.
			Environment.Exit(0);
		}
	}

	private static async Task RunProtectWorkerCoreAsync(string channelId, string nonce, int operationCode)
	{
		if (!Atlas.IsElevated || !Guid.TryParseExact(channelId, "N", out _) || nonce.Length != 64 || operationCode is < 0 or > 8)
		{
			return;
		}
		_ = Convert.FromHexString(nonce);
		int presetIndex = operationCode % 3;
		Helpers.MUnitOperation operation = operationCode < 3
			? Helpers.MUnitOperation.Verify
			: operationCode < 6
				? Helpers.MUnitOperation.Apply
				: Helpers.MUnitOperation.Remove;
		await using NamedPipeClientStream pipe = new(".", $"{ProtectOperationPipePrefix}{channelId}", PipeDirection.InOut, PipeOptions.Asynchronous);
		await pipe.ConnectAsync(60000);
		using StreamReader reader = new(pipe, new UTF8Encoding(false), false, 1024, leaveOpen: true);
		StreamWriter writer = new(pipe, new UTF8Encoding(false), 1024, leaveOpen: true) { AutoFlush = true };
		try
		{
			await writer.WriteLineAsync(nonce);
			string? acknowledgement = await reader.ReadLineAsync();
			if (!string.Equals(acknowledgement, "A|1", StringComparison.OrdinalIgnoreCase))
			{
				return;
			}
			Task progress(int current, int total, string category) =>
				writer.WriteLineAsync($"P|{current}|{total}|{Convert.ToBase64String(Encoding.UTF8.GetBytes(category))}");
			ProtectVM.PresetOperationResult result = await ViewModelProvider.ProtectVM.RunPresetFromCliAsync(presetIndex, operation, progress);
			if (!result.Succeeded)
			{
				throw new InvalidOperationException($"Security hardening {operation.ToString().ToLowerInvariant()} did not complete.");
			}
			if (operation is Helpers.MUnitOperation.Verify)
			{
				ProtectVM.PresetVerificationResult verification = result.Verification
					?? throw new InvalidOperationException("Security hardening verification did not return a result.");
				await writer.WriteLineAsync($"R|{verification.Categories}|{verification.Total}|{verification.Compliant}|{verification.NonCompliant}|{verification.Percentage.ToString(System.Globalization.CultureInfo.InvariantCulture)}");
				return;
			}
			await writer.WriteLineAsync($"O|{operation}");
		}
		finally
		{
			DisposePipeWriter(writer);
		}
	}

	private static void DisposePipeWriter(StreamWriter writer)
	{
		try { writer.Dispose(); } catch { }
	}

	private static Func<int, int, string, Task>? CreateProgressCallback(
		JsonElement parameters,
		Stream output,
		Func<string, string> formatMessage)
	{
		if (!parameters.TryGetProperty("_meta", out JsonElement metadata) ||
			metadata.ValueKind is not JsonValueKind.Object ||
			!metadata.TryGetProperty("progressToken", out JsonElement progressToken) ||
			progressToken.ValueKind is not (JsonValueKind.String or JsonValueKind.Number))
		{
			return null;
		}
		return (current, total, message) => WriteProgressAsync(output, progressToken, current, total, formatMessage(message));
	}

	private static async Task WriteProgressAsync(Stream output, JsonElement progressToken, int progress, int total, string message)
	{
		ArrayBufferWriter<byte> notificationBuffer = new(192);
		using (Utf8JsonWriter writer = new(notificationBuffer))
		{
			writer.WriteStartObject();
			writer.WriteString("jsonrpc", "2.0");
			writer.WriteString("method", "notifications/progress");
			writer.WriteStartObject("params");
			writer.WritePropertyName("progressToken");
			progressToken.WriteTo(writer);
			writer.WriteNumber("progress", progress);
			writer.WriteNumber("total", total);
			writer.WriteString("message", message);
			writer.WriteEndObject();
			writer.WriteEndObject();
		}
		await WriteResponseAsync(output, notificationBuffer.WrittenMemory).ConfigureAwait(false);
	}
	#endregion

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
			Helpers.FileTrustChecker.FileTrustResult result = await Task.Run(() => Helpers.FileTrustChecker.CheckFileTrust(filePath)).ConfigureAwait(false);
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
		await output.WriteAsync(NewLine).ConfigureAwait(false);
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
