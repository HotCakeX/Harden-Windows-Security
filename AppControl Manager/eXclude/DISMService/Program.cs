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
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace DISMService;

internal sealed class Program
{
	private static NamedPipeServerStream? _pipeServer;
	private static BinaryWriter? _writer;
	private static BinaryReader? _reader;
	private static string? _currentItemName;

	internal const string OnlineImage = "DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}";

	internal static void SendProgressCallback(uint current, uint total)
	{
		try
		{
			if (_writer != null && _pipeServer?.IsConnected == true)
			{
				// Send item-specific progress if we have a current item
				if (!string.IsNullOrEmpty(_currentItemName))
				{
					SendItemProgress(_currentItemName, current, total);
				}
			}
		}
		catch
		{
			// Ignore errors during progress callback
		}
	}

	private static async Task Main(string[] args)
	{
		string pipeName = args.Length > 0 ? args[0] : "DismService_Default";

		try
		{
			_pipeServer = CreateSecurePipe(pipeName);

			await _pipeServer.WaitForConnectionAsync();

			_writer = new BinaryWriter(_pipeServer);
			_reader = new BinaryReader(_pipeServer);

			// Log handler to send logs to the client
			Logger.SetLogHandler((message, logType) =>
			{
				try
				{
					SendLog(message, logType);
				}
				catch
				{
					// Ignore logging errors during pipe communication
				}
			});

			await ProcessCommands();
		}
		catch
		{
			// Ignore startup errors
		}
		finally
		{
			Cleanup();
		}
	}

	private static NamedPipeServerStream CreateSecurePipe(string pipeName)
	{
		PipeSecurity pipeSecurity = new();

		// Allow SYSTEM full control
		SecurityIdentifier systemSid = new(WellKnownSidType.LocalSystemSid, null);
		pipeSecurity.AddAccessRule(new PipeAccessRule(
			systemSid,
			PipeAccessRights.FullControl,
			AccessControlType.Allow));

		// Allow Administrators full control
		SecurityIdentifier adminSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
		pipeSecurity.AddAccessRule(new PipeAccessRule(
			adminSid,
			PipeAccessRights.FullControl,
			AccessControlType.Allow));

		return NamedPipeServerStreamAcl.Create(
			pipeName,
			PipeDirection.InOut,
			maxNumberOfServerInstances: 1,
			PipeTransmissionMode.Byte,
			PipeOptions.Asynchronous,
			inBufferSize: 10485760, // 10MB in buffer
			outBufferSize: 10485760, // 10MB out buffer
			pipeSecurity);
	}

	private static async Task ProcessCommands()
	{
		try
		{
			while (_pipeServer?.IsConnected == true)
			{
				Command command = (Command)_reader!.ReadByte();

				switch (command)
				{
					case Command.GetAllResults:
						await Task.Run(HandleGetAllResults);
						break;

					case Command.GetSpecificCapabilities:
						await Task.Run(HandleGetSpecificCapabilities);
						break;

					case Command.GetSpecificFeatures:
						await Task.Run(HandleGetSpecificFeatures);
						break;

					case Command.AddCapability:
						await Task.Run(HandleAddCapability);
						break;

					case Command.RemoveCapability:
						await Task.Run(HandleRemoveCapability);
						break;

					case Command.EnableFeature:
						await Task.Run(HandleEnableFeature);
						break;

					case Command.DisableFeature:
						await Task.Run(HandleDisableFeature);
						break;

					case Command.Shutdown:
						await Task.Run(HandleShutdown);
						return;

					case Command.Exit:
						return;
					default:
						break;
				}
			}
		}
		catch (EndOfStreamException)
		{
			// Client disconnected
		}
		catch
		{
			// Ignore command processing errors
		}
	}

	private static void HandleGetAllResults()
	{
		try
		{
			List<CommonCore.DISM.DISMOutput> results = Methods.GetAllAvailableResults();

			// Need to send results in chunks to avoid pipe buffer overflow
			const int chunkSize = 100; // Send 100 items at a time
			int totalChunks = (int)Math.Ceiling((double)results.Count / chunkSize);

			SendResponse(Response.ResultsData);
			_writer!.Write(totalChunks); // Send total number of chunks first
			_writer.Write(results.Count); // Send total result count

			for (int chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++)
			{
				int startIndex = chunkIndex * chunkSize;
				int endIndex = Math.Min(startIndex + chunkSize, results.Count);
				int currentChunkSize = endIndex - startIndex;

				_writer.Write(chunkIndex); // Chunk number
				_writer.Write(currentChunkSize); // Items in this chunk

				// Send chunk data
				for (int i = startIndex; i < endIndex; i++)
				{
					WriteString(results[i].Name);
					_writer.Write((int)results[i].State);
					_writer.Write((int)results[i].Type);
					WriteString(results[i].Description);
				}

				// Flush after each chunk to ensure data is sent
				_writer.Flush();
			}
		}
		catch (Exception ex)
		{
			SendError($"GetAllResults error: {ex.Message}");
		}
	}

	private static void HandleGetSpecificCapabilities()
	{
		try
		{
			int count = _reader!.ReadInt32();
			string[] names = new string[count];
			for (int i = 0; i < count; i++)
			{
				names[i] = ReadString();
			}

			List<CommonCore.DISM.DISMOutput> results = Methods.GetSpecificCapabilities(names);

			SendResponse(Response.ResultsData);
			_writer!.Write(1); // Only one chunk for specific results
			_writer.Write(results.Count);

			// Send single chunk
			_writer.Write(0); // Chunk index 0
			_writer.Write(results.Count); // Items in chunk

			foreach (CommonCore.DISM.DISMOutput result in results)
			{
				WriteString(result.Name);
				_writer.Write((int)result.State);
				_writer.Write((int)result.Type);
				WriteString(result.Description);
			}

			_writer.Flush();
		}
		catch (Exception ex)
		{
			SendError($"GetSpecificCapabilities error: {ex.Message}");
		}
	}

	private static void HandleGetSpecificFeatures()
	{
		try
		{
			int count = _reader!.ReadInt32();
			string[] names = new string[count];
			for (int i = 0; i < count; i++)
			{
				names[i] = ReadString();
			}

			List<CommonCore.DISM.DISMOutput> results = Methods.GetSpecificFeatures(names);

			SendResponse(Response.ResultsData);
			_writer!.Write(1); // Only one chunk for specific results
			_writer.Write(results.Count);

			// Send single chunk
			_writer.Write(0); // Chunk index 0
			_writer.Write(results.Count); // Items in chunk

			foreach (CommonCore.DISM.DISMOutput result in results)
			{
				WriteString(result.Name);
				_writer.Write((int)result.State);
				_writer.Write((int)result.Type);
				WriteString(result.Description);
			}

			_writer.Flush();
		}
		catch (Exception ex)
		{
			SendError($"GetSpecificFeatures error: {ex.Message}");
		}
	}

	private static void HandleAddCapability()
	{
		try
		{
			string name = ReadString();
			_currentItemName = name;
			bool limitAccess = _reader!.ReadBoolean();
			int sourcePathCount = _reader.ReadInt32();
			string[]? sourcePaths = null;

			if (sourcePathCount > 0)
			{
				sourcePaths = new string[sourcePathCount];
				for (int i = 0; i < sourcePathCount; i++)
				{
					sourcePaths[i] = ReadString();
				}
			}

			bool success = Methods.AddCapability(name, limitAccess, sourcePaths);

			SendResponse(Response.OperationComplete);
			_writer!.Write(success);
		}
		catch (Exception ex)
		{
			SendError($"AddCapability error: {ex.Message}");
		}
		finally
		{
			_currentItemName = null;
		}
	}

	private static void HandleRemoveCapability()
	{
		try
		{
			string name = ReadString();
			_currentItemName = name;
			bool success = Methods.RemoveCapability(name);

			SendResponse(Response.OperationComplete);
			_writer!.Write(success);
		}
		catch (Exception ex)
		{
			SendError($"RemoveCapability error: {ex.Message}");
		}
		finally
		{
			_currentItemName = null;
		}
	}

	private static void HandleEnableFeature()
	{
		try
		{
			string name = ReadString();
			_currentItemName = name;
			int sourcePathCount = _reader!.ReadInt32();
			string[]? sourcePaths = null;

			if (sourcePathCount > 0)
			{
				sourcePaths = new string[sourcePathCount];
				for (int i = 0; i < sourcePathCount; i++)
				{
					sourcePaths[i] = ReadString();
				}
			}

			bool success = Methods.EnableFeature(name, sourcePaths);

			SendResponse(Response.OperationComplete);
			_writer!.Write(success);
		}
		catch (Exception ex)
		{
			SendError($"EnableFeature error: {ex.Message}");
		}
		finally
		{
			_currentItemName = null;
		}
	}

	private static void HandleDisableFeature()
	{
		try
		{
			string name = ReadString();
			_currentItemName = name;
			bool success = Methods.DisableFeature(name);

			SendResponse(Response.OperationComplete);
			_writer!.Write(success);
		}
		catch (Exception ex)
		{
			SendError($"DisableFeature error: {ex.Message}");
		}
		finally
		{
			_currentItemName = null;
		}
	}

	private static void HandleShutdown()
	{
		try
		{
			Methods.DestroyDISMSession();
			SendResponse(Response.ShutdownComplete);
		}
		catch (Exception ex)
		{
			SendError($"Shutdown error: {ex.Message}");
		}
	}

	private static void SendResponse(Response response)
	{
		_writer!.Write((byte)response);
		_writer.Flush();
	}

	private static void SendError(string message)
	{
		_writer!.Write((byte)Response.Error);
		WriteString(message);
		_writer.Flush();
	}

	private static void SendItemProgress(string itemName, uint current, uint total)
	{
		try
		{
			if (_writer != null && _pipeServer?.IsConnected == true)
			{
				_writer.Write((byte)Response.ItemProgress);
				WriteString(itemName);
				_writer.Write(current);
				_writer.Write(total);
				_writer.Flush();
			}
		}
		catch
		{
			// Ignore flush errors
		}
	}

	private static void SendLog(string message, LogTypeIntel logType)
	{
		try
		{
			if (_writer != null && _pipeServer?.IsConnected == true)
			{
				_writer.Write((byte)Response.Log);
				WriteString(message);
				_writer.Write((int)logType);
				_writer.Flush();
			}
		}
		catch
		{
			// Ignore flush errors
		}
	}

	private static void WriteString(string value)
	{
		byte[] bytes = Encoding.UTF8.GetBytes(value);
		_writer!.Write(bytes.Length);
		_writer.Write(bytes);
	}

	private static string ReadString()
	{
		int length = _reader!.ReadInt32();
		byte[] bytes = _reader.ReadBytes(length);
		return Encoding.UTF8.GetString(bytes);
	}

	private static void Cleanup()
	{
		try
		{
			Methods.DestroyDISMSession();
		}
		catch
		{
			// Ignore cleanup errors
		}

		try
		{
			_writer?.Dispose();
		}
		catch { }

		try
		{
			_reader?.Dispose();
		}
		catch { }

		try
		{
			_pipeServer?.Dispose();
		}
		catch { }
	}
}

internal enum Command : byte
{
	GetAllResults = 1,
	GetSpecificCapabilities = 2,
	GetSpecificFeatures = 3,
	AddCapability = 4,
	RemoveCapability = 5,
	EnableFeature = 6,
	DisableFeature = 7,
	Shutdown = 8,
	Exit = 9
}

internal enum Response : byte
{
	ResultsData = 1,
	OperationComplete = 2,
	ShutdownComplete = 4,
	Log = 5,
	ItemProgress = 6,
	Error = 255
}
