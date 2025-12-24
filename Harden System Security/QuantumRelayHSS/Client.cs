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

using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using CommonCore.QuantumRelay;

namespace HardenSystemSecurity.QuantumRelayHSS;

internal static class Client
{
	/// <summary>
	/// Runs a command via the QuantumRelayHSS service.
	/// Streams all logs in real-time.
	/// Throws if the pipe closes unexpectedly or the service sends a protocol Error frame.
	/// Returns the result when the service sends a Final frame.
	/// </summary>
	/// <param name="command">Executable/command to run.</param>
	/// <param name="arguments">Optional arguments.</param>
	internal static string RunCommand(string command, string? arguments) =>
		ExecuteRequest((writer) =>
		{
			writer.Write((byte)RequestCommand.RunProcess);
			CommonCore.QuantumRelay.Helpers.WriteString(writer, command);
			CommonCore.QuantumRelay.Helpers.WriteString(writer, arguments ?? string.Empty);
		});

	/// <summary>
	/// Copies a file using the QuantumRelayHSS service.
	/// </summary>
	/// <param name="source">Source file path.</param>
	/// <param name="destination">Destination file path.</param>
	/// <param name="overwrite">Whether to overwrite the destination if it exists.</param>
	internal static void CopyFile(string source, string destination, bool overwrite) =>
		ExecuteRequest((writer) =>
		{
			writer.Write((byte)RequestCommand.CopyFile);
			CommonCore.QuantumRelay.Helpers.WriteString(writer, source);
			CommonCore.QuantumRelay.Helpers.WriteString(writer, destination);
			writer.Write(overwrite);
		});

	/// <summary>
	/// Deletes a file using the QuantumRelayHSS service.
	/// </summary>
	/// <param name="path">File path to delete.</param>
	internal static void DeleteFile(string path) =>
		ExecuteRequest((writer) =>
		{
			writer.Write((byte)RequestCommand.DeleteFile);
			CommonCore.QuantumRelay.Helpers.WriteString(writer, path);
		});

	/// <summary>
	/// Helper method to encapsulate connection, request sending, and response loop logic.
	/// </summary>
	private static string ExecuteRequest(Action<BinaryWriter> sendRequest)
	{
		// Ensure the service is running.
		ServiceStarter.StartServiceAsync(Atlas.QuantumRelayHSSServiceName, TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();

		// Set up the client to connect to the server pipe.
		// Uses Impersonation so the service can impersonate to verify elevated admin status.
		using NamedPipeClientStream client = new(
			serverName: ".",
			pipeName: Atlas.QuantumRelayHSSPipeName,
			direction: PipeDirection.InOut,
			options: PipeOptions.Asynchronous | PipeOptions.WriteThrough,
			impersonationLevel: TokenImpersonationLevel.Impersonation);

		// Connect to the SCM-managed service, 20 seconds timeout.
		client.Connect(20000);

		// Binary protocol
		client.ReadMode = PipeTransmissionMode.Byte;

		using BinaryWriter writer = new(client, Encoding.UTF8, leaveOpen: true);
		using BinaryReader reader = new(client, Encoding.UTF8, leaveOpen: true);

		// Send request using the provided action
		sendRequest(writer);
		writer.Flush();

		// Keep receiving data and handle frames until Final or Error is received.
		while (true)
		{
			// Read the response tag
			int tag = client.ReadByte();
			if (tag == -1)
			{
				throw new IOException("The service closed the connection before sending a final response.");
			}

			ResponseType type = (ResponseType)(byte)tag;

			switch (type)
			{
				case ResponseType.Log:
					{
						string message = CommonCore.QuantumRelay.Helpers.ReadString(reader);
						Logger.Write(message, LogTypeIntel.Information);
						continue;
					}

				case ResponseType.Final:
					{
						string output = CommonCore.QuantumRelay.Helpers.ReadString(reader);
						return output;
					}

				case ResponseType.Error:
					{
						int exitCode = CommonCore.QuantumRelay.Helpers.ReadInt32(reader);
						string errorDetails = CommonCore.QuantumRelay.Helpers.ReadString(reader);
						throw new InvalidOperationException($"ExitCode={exitCode}: {errorDetails}");
					}

				default:
					{
						throw new InvalidOperationException("Unknown message type received from the service.");
					}
			}
		}
	}
}
