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

using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using CommonCore.QuantumRelay;

#pragma warning disable CA1812

namespace QuantumRelay;

internal sealed class NamedPipeServer(CommandProcessor commandProcessor) : IDisposable
{
	private const string PipeName = "QuantumRelay_CommandPipe";
	private const int MaxConcurrentConnections = 5;
	private const int BufferSize = 8 * 1024 * 1024;

	private readonly CancellationTokenSource _cancellationTokenSource = new();
	private readonly CommandProcessor _commandProcessor = commandProcessor;
	private volatile bool _isRunning;
	private volatile bool _isDisposed;

	internal async Task StartAsync(CancellationToken cancellationToken)
	{
		_isRunning = true;

		// Linked token source that responds to both external and internal cancellations.
		using CancellationTokenSource linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(
			cancellationToken, _cancellationTokenSource.Token);

		Task[] serverTasks = new Task[MaxConcurrentConnections];
		for (int i = 0; i < MaxConcurrentConnections; i++)
		{
			serverTasks[i] = HandleClientConnectionsAsync(linkedTokenSource.Token);
		}

		try
		{
			await Task.WhenAll(serverTasks).WaitAsync(linkedTokenSource.Token);
		}
		catch (OperationCanceledException) { } // Expected during shutdown
		catch (Exception ex)
		{
			try
			{
				EventLog.WriteEntry(WindowsServiceHost.EventLogSource,
				$"QuantumRelay Named pipe server error: {ex.Message}",
				EventLogEntryType.Error);
			}
			catch { }

			throw;
		}
	}

	internal async Task StopAsync()
	{
		_isRunning = false;

		// Cancel operations if not already disposed
		if (!_isDisposed && !_cancellationTokenSource.IsCancellationRequested)
		{
			try
			{
				await _cancellationTokenSource.CancelAsync();
			}
			catch (ObjectDisposedException) { } // Already disposed so ignore
		}

		await Task.Delay(1000);
		try
		{
			EventLog.WriteEntry(WindowsServiceHost.EventLogSource,
				"QuantumRelay Service stopped",
				EventLogEntryType.Information);
		}
		catch { }
	}

	private async Task HandleClientConnectionsAsync(CancellationToken cancellationToken)
	{
		while (_isRunning && !cancellationToken.IsCancellationRequested)
		{
			NamedPipeServerStream? pipeServer = null;
			bool wasConnected = false;

			try
			{
				pipeServer = CreateSecurePipeServer();

				await pipeServer.WaitForConnectionAsync(cancellationToken);
				wasConnected = true;

				// Small delay to prevent rapid connection cycling issues
				await Task.Delay(10, cancellationToken);

				await HandleClientSessionAsync(pipeServer, cancellationToken);

				// Transfer ownership to HandleClientSessionAsync
				// Have to assign null here to prevent double dispose
				pipeServer = null;
			}
			catch (OperationCanceledException)
			{
				break;
			}
			catch (IOException) when (wasConnected)
			{
				// Client disconnected unexpectedly after connection was established
				// No need to log this as it's common in high-frequency scenarios
				await Task.Delay(100, CancellationToken.None);
			}
			catch (InvalidOperationException) when (wasConnected)
			{
				// Pipe operation attempted on disconnected pipe
				// Again no need to log this as it's common in high-frequency scenarios
				await Task.Delay(100, CancellationToken.None);
			}
			catch (Exception ex)
			{
				try
				{
					EventLog.WriteEntry(WindowsServiceHost.EventLogSource,
						$"QuantumRelay Error handling client connection: {ex.Message}",
						EventLogEntryType.Error);
				}
				catch { } // Ignore event log errors
			}
			finally
			{
				if (pipeServer != null)
					await pipeServer.DisposeAsync();
			}

			// Small delay between connection attempts to prevent resource exhaustion
			if (_isRunning && !cancellationToken.IsCancellationRequested)
			{
				await Task.Delay(50, CancellationToken.None);
			}
		}
	}

	private static NamedPipeServerStream CreateSecurePipeServer()
	{
		PipeSecurity pipeSecurity = new();

		pipeSecurity.AddAccessRule(new PipeAccessRule(
			new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
			PipeAccessRights.FullControl,
			AccessControlType.Allow));

		pipeSecurity.AddAccessRule(new PipeAccessRule(
			new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
			PipeAccessRights.FullControl,
			AccessControlType.Allow));

		return NamedPipeServerStreamAcl.Create(
			PipeName,
			PipeDirection.InOut,
			NamedPipeServerStream.MaxAllowedServerInstances,
			PipeTransmissionMode.Message,
			PipeOptions.Asynchronous | PipeOptions.WriteThrough,
			BufferSize,
			BufferSize,
			pipeSecurity);
	}

	private async Task HandleClientSessionAsync(NamedPipeServerStream pipeServer, CancellationToken cancellationToken)
	{
		ClientSessionContext? sessionContext = null;

		try
		{
			// Take ownership of pipeServer disposal
			await using (pipeServer)
			{
				// Validate pipe state before proceeding
				if (!pipeServer.IsConnected)
				{
					return;
				}

				using StreamReader reader = new(pipeServer, Encoding.UTF8, false, BufferSize, true);
				using StreamWriter writer = new(pipeServer, Encoding.UTF8, BufferSize, true) { AutoFlush = true };

				sessionContext = new ClientSessionContext(writer);

				while (pipeServer.IsConnected && !cancellationToken.IsCancellationRequested)
				{
					try
					{
						string? requestJson = await reader.ReadLineAsync(cancellationToken);
						if (string.IsNullOrEmpty(requestJson))
						{
							break;
						}

						CommandResponse response = await ProcessCommandRequestAsync(requestJson, sessionContext, cancellationToken);

						// Validate pipe is still connected before sending response
						if (!pipeServer.IsConnected)
						{
							break;
						}

						// Send final response using the session context to ensure proper synchronization
						ResponseMessage responseMessage = new(response);
						string responseJson = JsonSerializer.Serialize(responseMessage, SourceGenerationContext.Default.MessageEnvelope);

						// Ensure synchronization with log sender
						await sessionContext.WriteResponseAsync(responseJson, cancellationToken);
					}
					catch (IOException)
					{
						// Client disconnected or pipe broken - this is normal
						break;
					}
					catch (ObjectDisposedException)
					{
						// Stream was disposed - this is normal during shutdown
						break;
					}
					catch (InvalidOperationException) when (!pipeServer.IsConnected)
					{
						// Operation attempted on disconnected pipe
						break;
					}
					catch (OperationCanceledException)
					{
						// Service shutting down
						break;
					}
					catch (Exception ex)
					{
						try
						{
							// Only try to send error response if pipe is still connected
							if (pipeServer.IsConnected)
							{
								CommandResponse errorResponse = new(
									success: false,
									output: string.Empty,
									errorOutput: string.Empty,
									exitCode: -1,
									errorMessage: $"Error processing request: {ex.Message}",
									executionTimeMs: 0,
									logs: [new LogEntry(DateTime.UtcNow, LogLevel.Error, "Request processing failed", ex.ToString())]);

								ResponseMessage errorResponseMessage = new(errorResponse);
								string errorJson = JsonSerializer.Serialize(errorResponseMessage, SourceGenerationContext.Default.MessageEnvelope);
								await sessionContext.WriteResponseAsync(errorJson, cancellationToken);
							}
						}
						catch
						{
							// If we can't send error response, just break the loop
							break;
						}
					}
				}
			}
		}
		catch (IOException) { } // Expected pipe errors during high-frequency usage - don't log as error
		catch (ObjectDisposedException) { } // Expected during disposal - don't log
		catch (InvalidOperationException) { } // Expected when pipe operations fail due to disconnection
		catch (Exception ex)
		{
			try
			{
				EventLog.WriteEntry(WindowsServiceHost.EventLogSource,
					$"QuantumRelay Error in client session: {ex.Message}",
					EventLogEntryType.Error);
			}
			catch { } // Ignore event log errors
		}
		finally
		{
			sessionContext?.Dispose();
		}
	}

	private async Task<CommandResponse> ProcessCommandRequestAsync(string requestJson, ClientSessionContext sessionContext, CancellationToken cancellationToken)
	{
		try
		{
			CommandRequest? request = JsonSerializer.Deserialize(requestJson, SourceGenerationContext.Default.CommandRequest);
			if (request == null)
			{
				return new CommandResponse(
					success: false,
					output: string.Empty,
					errorOutput: string.Empty,
					exitCode: -1,
					errorMessage: "Invalid request format: Unable to deserialize command request",
					executionTimeMs: 0,
					logs: [new LogEntry(DateTime.UtcNow, LogLevel.Error, "Invalid request format")]);
			}

			return await _commandProcessor.ProcessCommandAsync(request, sessionContext, cancellationToken);
		}
		catch (JsonException ex)
		{
			return new CommandResponse(
				success: false,
				output: string.Empty,
				errorOutput: string.Empty,
				exitCode: -1,
				errorMessage: $"JSON parsing error: {ex.Message}",
				executionTimeMs: 0,
				logs: [new LogEntry(DateTime.UtcNow, LogLevel.Error, "JSON parsing error", ex.ToString())]);
		}
		catch (Exception ex)
		{
			return new CommandResponse(
				success: false,
				output: string.Empty,
				errorOutput: string.Empty,
				exitCode: -1,
				errorMessage: $"Unexpected error: {ex.Message}",
				executionTimeMs: 0,
				logs: [new LogEntry(DateTime.UtcNow, LogLevel.Error, "Unexpected error", ex.ToString())]);
		}
	}

	public void Dispose()
	{
		if (_isDisposed)
		{
			return;
		}

		_isRunning = false;
		_isDisposed = true;

		try
		{
			if (!_cancellationTokenSource.IsCancellationRequested)
			{
				_cancellationTokenSource.Cancel();
			}
		}
		catch (ObjectDisposedException) { } // Already disposed

		try
		{
			_cancellationTokenSource.Dispose();
		}
		catch (ObjectDisposedException) { } // Already disposed
	}
}

/// <summary>
/// Context for managing real-time log streaming to client
/// </summary>
internal sealed class ClientSessionContext : IDisposable
{
	private readonly StreamWriter _writer;
	private readonly Channel<LogEntry> _logChannel;
	private readonly Task _logSenderTask;
	private readonly CancellationTokenSource _cancellationTokenSource;

	/// <summary>
	/// We use this to prevent concurrent writes
	/// </summary>
	private readonly SemaphoreSlim _writeSemaphore;

	private volatile bool _isDisposed;

	internal ClientSessionContext(StreamWriter writer)
	{
		_writer = writer;
		_cancellationTokenSource = new CancellationTokenSource();
		_writeSemaphore = new SemaphoreSlim(1, 1); // Only allow one write at a time

		_logChannel = Channel.CreateUnbounded<LogEntry>(new UnboundedChannelOptions
		{
			SingleReader = true,
			AllowSynchronousContinuations = false
		});

		// Start the background task to send logs in real-time
		_logSenderTask = Task.Run(async () =>
		{
			await foreach (LogEntry logEntry in _logChannel.Reader.ReadAllAsync(_cancellationTokenSource.Token))
			{
				try
				{
					// Using semaphore to prevent concurrent writes
					await _writeSemaphore.WaitAsync(_cancellationTokenSource.Token);
					try
					{
						// Send log entry immediately to client
						LogMessage logMessage = new(logEntry);
						string logJson = JsonSerializer.Serialize(logMessage, SourceGenerationContext.Default.MessageEnvelope);
						await _writer.WriteLineAsync(logJson);
						await _writer.FlushAsync(); // Ensure immediate delivery
					}
					finally
					{
						_ = _writeSemaphore.Release();
					}
				}
				catch (IOException)
				{
					// Client disconnected - stop trying to send logs
					break;
				}
				catch (ObjectDisposedException)
				{
					// Writer disposed - stop trying to send logs
					break;
				}
				catch (InvalidOperationException)
				{
					// Writer in invalid state - stop trying to send logs
					break;
				}
				catch (OperationCanceledException)
				{
					// Cancellation requested - stop trying to send logs
					break;
				}
				catch
				{
					// If we can't send to client, write to event log as fallback
					try
					{
						EventLog.WriteEntry(WindowsServiceHost.EventLogSource,
							$"QuantumRelay {logEntry.Level}: {logEntry.Message}",
							logEntry.Level switch
							{
								LogLevel.Error => EventLogEntryType.Error,
								LogLevel.Warning => EventLogEntryType.Warning,
								_ => EventLogEntryType.Information
							});
					}
					catch { } // Ignore event log errors
				}
			}
		}, _cancellationTokenSource.Token);
	}

	internal void SendLog(LogEntry logEntry)
	{
		if (_isDisposed || !_logChannel.Writer.TryWrite(logEntry))
		{
			// If channel is full/closed, fall back to event log
			try
			{
				EventLog.WriteEntry(WindowsServiceHost.EventLogSource,
					$"QuantumRelay {logEntry.Level}: {logEntry.Message}",
					logEntry.Level switch
					{
						LogLevel.Error => EventLogEntryType.Error,
						LogLevel.Warning => EventLogEntryType.Warning,
						_ => EventLogEntryType.Information
					});
			}
			catch { } // Ignore event log errors
		}
	}

	/// <summary>
	/// Writes response data to the client using the same synchronization as log sending
	/// </summary>
	internal async Task WriteResponseAsync(string responseJson, CancellationToken cancellationToken)
	{
		if (_isDisposed)
		{
			return;
		}

		try
		{
			// Using same semaphore to ensure response writing is synchronized with log sending
			await _writeSemaphore.WaitAsync(cancellationToken);
			try
			{
				await _writer.WriteLineAsync(responseJson);
				await _writer.FlushAsync(cancellationToken);
			}
			finally
			{
				_ = _writeSemaphore.Release();
			}
		}
		catch (IOException)
		{
			// Client disconnected - ignore
		}
		catch (ObjectDisposedException)
		{
			// Writer disposed - ignore
		}
		catch (InvalidOperationException)
		{
			// Writer in invalid state - ignore
		}
		catch (OperationCanceledException)
		{
			// Cancellation requested - ignore
		}
	}

	public void Dispose()
	{
		if (_isDisposed)
		{
			return;
		}

		_isDisposed = true;

		try
		{
			_logChannel.Writer.Complete();

			if (!_cancellationTokenSource.IsCancellationRequested)
			{
				_cancellationTokenSource.Cancel();
			}

			_ = _logSenderTask.Wait(1000);
		}
		catch { } // Ignore disposal errors
		finally
		{
			try
			{
				_writeSemaphore.Dispose();
			}
			catch (ObjectDisposedException) { } // Already disposed

			try
			{
				_cancellationTokenSource.Dispose();
			}
			catch (ObjectDisposedException) { } // Already disposed
		}
	}
}
