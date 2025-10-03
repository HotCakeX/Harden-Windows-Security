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

using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CommonCore.QuantumRelay;

namespace QuantumRelayHSS;

internal sealed class NamedPipeServer : IDisposable
{
	/// <summary>
	/// The maximum number of concurrent client connections the server will handle.
	/// </summary>
	private const int MaxConcurrentConnections = 5;

	/// <summary>
	/// 4 MB buffer size for pipe I/O
	/// </summary>
	private const int BufferSize = 4 * 1024 * 1024;

	/// <summary>
	/// If no clients are connected for this duration, stop the service.
	/// </summary>
	private const int IdleTimeoutSeconds = 120;

	private readonly CancellationTokenSource CTS = new();

	/// <summary>
	/// Indicates whether the server is currently running,
	/// </summary>
	private volatile bool IsRunning;

	/// <summary>
	/// Indicates whether Dispose has been called on this instance.
	/// </summary>
	private volatile bool IsDisposed;

	/// <summary>
	/// Tracks the number of active client sessions
	/// </summary>
	private int ActiveSessions;

	/// <summary>
	/// Single-shot timer used to trigger shutdown after idle timeout
	/// </summary>
	private readonly Timer IdleTimer;

	/// <summary>
	/// Debug logging toggle via environment variable "QUANTUMRELAYHSS_DEBUG"
	/// </summary>
	private readonly bool DebugLoggingEnabled;

	internal NamedPipeServer()
	{
		// Create the idle timer in a disabled state
		IdleTimer = new Timer(OnIdleTimerCallback, state: null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
		DebugLoggingEnabled = WindowsServiceHost.IsDebugEnabled();
	}

	internal async Task StartAsync(CancellationToken cancellationToken)
	{
		IsRunning = true;

		// Arm the idle timer immediately; if no clients connect, the service will auto-stop after the timeout.
		ArmIdleTimerIfIdle();

		using CancellationTokenSource linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(
			cancellationToken, CTS.Token);

		Task[] serverTasks = new Task[MaxConcurrentConnections];
		for (int i = 0; i < MaxConcurrentConnections; i++)
		{
			serverTasks[i] = HandleClientConnectionsAsync(linkedTokenSource.Token);
		}

		try
		{
			await Task.WhenAll(serverTasks).ConfigureAwait(false);
		}
		catch (OperationCanceledException) { }
		catch (Exception ex)
		{
			NativeEventLogger.WriteEntry(
				$"{Atlas.QuantumRelayHSSServiceName} Named pipe server error: {ex.Message}",
				NativeEventLogger.EventLogEntryType.Error);

			throw;
		}
	}

	internal async Task StopAsync()
	{
		IsRunning = false;

		if (!IsDisposed && !CTS.IsCancellationRequested)
		{
			try
			{
				await CTS.CancelAsync().ConfigureAwait(false);
			}
			catch (ObjectDisposedException) { }
		}

		// Stop the idle timer
		try { _ = IdleTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan); } catch (ObjectDisposedException) { }

		await Task.Delay(1000).ConfigureAwait(false);

		NativeEventLogger.WriteEntry(
			$"{Atlas.QuantumRelayHSSServiceName} Service stopped",
			NativeEventLogger.EventLogEntryType.Information);
	}

	// Main loop to handle incoming client connections' requests.
	private async Task HandleClientConnectionsAsync(CancellationToken cancellationToken)
	{
		while (IsRunning && !cancellationToken.IsCancellationRequested)
		{
			bool wasConnected = false;
			bool sessionCounted;

			try
			{
				using NamedPipeServerStream pipeServer = CreateSecurePipeServer();

				await pipeServer.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
				wasConnected = true;

				// Count this session as active and stop the idle timer if this is the first connection
				OnClientConnected();
				sessionCounted = true;

				await Task.Delay(10, cancellationToken).ConfigureAwait(false);

				try
				{
					await HandleClientSessionAsync(pipeServer, cancellationToken).ConfigureAwait(false);
				}
				finally
				{
					// Ensure we decrement the active session count even if session handling throws
					if (sessionCounted)
					{
						OnClientDisconnected();
						sessionCounted = false;
					}
				}
			}
			catch (OperationCanceledException)
			{
				break;
			}
			catch (IOException) when (wasConnected)
			{
				await Task.Delay(100, CancellationToken.None).ConfigureAwait(false);
			}
			catch (InvalidOperationException) when (wasConnected)
			{
				await Task.Delay(100, CancellationToken.None).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				NativeEventLogger.WriteEntry(
					$"{Atlas.QuantumRelayHSSServiceName} Error handling client connection: {ex.Message}",
					NativeEventLogger.EventLogEntryType.Error);
			}

			if (IsRunning && !cancellationToken.IsCancellationRequested)
			{
				await Task.Delay(50, CancellationToken.None).ConfigureAwait(false);
			}
		}
	}

	private static NamedPipeServerStream CreateSecurePipeServer()
	{
		PipeSecurity pipeSecurity = new();

		// Deny all remote network tokens, regardless of group membership.
		pipeSecurity.AddAccessRule(new PipeAccessRule(
			new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
			PipeAccessRights.FullControl,
			AccessControlType.Deny));

		// Allow LocalSystem (service account)
		pipeSecurity.AddAccessRule(new PipeAccessRule(
			new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
			PipeAccessRights.FullControl,
			AccessControlType.Allow));

		// Allow local administrators. Remote administrators will be denied by the NETWORK deny ACE above.
		pipeSecurity.AddAccessRule(new PipeAccessRule(
			new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
			PipeAccessRights.FullControl,
			AccessControlType.Allow));

		return NamedPipeServerStreamAcl.Create(
			Atlas.QuantumRelayHSSPipeName,
			PipeDirection.InOut,
			NamedPipeServerStream.MaxAllowedServerInstances,
			PipeTransmissionMode.Byte,
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
			await using (pipeServer.ConfigureAwait(false))
			{
				// Validate pipe is still connected.
				if (!pipeServer.IsConnected)
				{
					return;
				}

				using BinaryReader reader = new(pipeServer, Encoding.UTF8, leaveOpen: true);
				using BinaryWriter writer = new(pipeServer, Encoding.UTF8, leaveOpen: true);

				sessionContext = new ClientSessionContext(writer);

				// Verify the client's elevation status once per session (after the first byte).
				bool adminVerified = false;
				bool adminAllowed = false;

				while (pipeServer.IsConnected && !cancellationToken.IsCancellationRequested)
				{
					try
					{
						int cmdRaw = pipeServer.ReadByte();
						if (cmdRaw == -1)
						{
							break;
						}

						// Ensure the client is an elevated Administrator before processing any request.
						if (!adminVerified)
						{
							adminAllowed = IsClientElevatedAdmin(pipeServer);
							adminVerified = true;

							if (!adminAllowed)
							{
								// Deny and inform client
								try
								{
									await sessionContext.WriteErrorResponseAsync(-1, "Access denied: client is not an elevated administrator.", cancellationToken).ConfigureAwait(false);
								}
								catch { }
								break; // Break out of the loop and disconnect.
							}
						}

						// Determine the type of command sent by the client
						RequestCommand cmd = (RequestCommand)(byte)cmdRaw;

						switch (cmd)
						{
							case RequestCommand.RunProcess:
								{
									// Extract parameters
									string command = Helpers.ReadString(reader);
									string arguments = Helpers.ReadString(reader);

									// Execute the command as SYSTEM
									(int ExitCode, string Output, string ErrorDetails) = await ExecuteRunProcessAsync(
											command,
											string.IsNullOrEmpty(arguments) ? null : arguments,
											sessionContext).ConfigureAwait(false);

									if (ExitCode == 0)
									{
										// Send final output to client if exit code is 0.
										await sessionContext.WriteFinalResponseAsync(Output, cancellationToken).ConfigureAwait(false);
									}
									else
									{
										// Send error details to client if exit code is non-zero.
										await sessionContext.WriteErrorResponseAsync(ExitCode, ErrorDetails, cancellationToken).ConfigureAwait(false);
									}

									break;
								}
							default: break;
						}
					}
					catch (IOException)
					{
						break;
					}
					catch (ObjectDisposedException)
					{
						break;
					}
					catch (InvalidOperationException) when (!pipeServer.IsConnected)
					{
						break;
					}
					catch (OperationCanceledException)
					{
						break;
					}
					catch (Exception ex)
					{
						try
						{
							if (pipeServer.IsConnected)
							{
								await sessionContext!.WriteErrorResponseAsync(-1, $"Error processing request: {ex.Message}{Environment.NewLine}{ex.StackTrace}", cancellationToken).ConfigureAwait(false);
							}
						}
						catch
						{
							break;
						}
					}
				}
			}
		}
		catch (IOException) { }
		catch (ObjectDisposedException) { }
		catch (InvalidOperationException) { }
		catch (Exception ex)
		{
			NativeEventLogger.WriteEntry(
				$"{Atlas.QuantumRelayHSSServiceName} Error in client session: {ex.Message}",
				NativeEventLogger.EventLogEntryType.Error);
		}
		finally
		{
			sessionContext?.Dispose();
		}
	}

	public void Dispose()
	{
		if (IsDisposed)
		{
			return;
		}

		IsDisposed = true;
		IsRunning = false;

		try
		{
			if (!CTS.IsCancellationRequested)
			{
				CTS.Cancel();
			}
		}
		catch (ObjectDisposedException) { }

		try
		{
			IdleTimer.Dispose();
		}
		catch (ObjectDisposedException) { }

		try
		{
			CTS.Dispose();
		}
		catch (ObjectDisposedException) { }
	}


	/// <summary>
	/// Executes a process command using the binary protocol, streams logs in real-time, and returns the final result.
	/// </summary>
	private static async Task<(int ExitCode, string Output, string ErrorDetails)> ExecuteRunProcessAsync(string command, string? arguments, ClientSessionContext sessionContext)
	{
		return await Task.Run(() =>
		{
			try
			{
				sessionContext.SendLog("Processing command");

				ProcessStartInfo processInfo = new()
				{
					FileName = command,
					RedirectStandardOutput = true,
					RedirectStandardError = true,
					UseShellExecute = false,
					CreateNoWindow = true
				};

				if (arguments is not null)
				{
					processInfo.Arguments = arguments;
				}

				using Process process = new();
				process.StartInfo = processInfo;

				if (!process.Start())
				{
					return (-1, string.Empty, $"Failed to start '{command}'");
				}

				sessionContext.SendLog($"{Atlas.QuantumRelayHSSServiceName} service RunProcess started with PID: {process.Id}");

				// Capture output and errors
				string output = process.StandardOutput.ReadToEnd();
				string error = process.StandardError.ReadToEnd();

				process.WaitForExit();

				if (process.ExitCode is not 0)
				{
					return (process.ExitCode, output, error);
				}

				return (process.ExitCode, output, error);
			}
			catch (Exception ex)
			{
				return (-1, string.Empty, ex.ToString());
			}
		});
	}

	// Idle management helpers

	private void OnClientConnected()
	{
		int count = Interlocked.Increment(ref ActiveSessions);
		if (count == 1)
		{
			// First active client: stop the idle timer
			try { _ = IdleTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan); } catch (ObjectDisposedException) { }

			if (DebugLoggingEnabled)
			{
				NativeEventLogger.WriteEntry(
					$"{Atlas.QuantumRelayHSSServiceName} First client connected. ActiveSessions={count}. Idle timer stopped.",
					NativeEventLogger.EventLogEntryType.Information);
			}
		}
	}

	private void OnClientDisconnected()
	{
		int count = Interlocked.Decrement(ref ActiveSessions);
		if (count < 0)
		{
			// guarding against underflow
			_ = Interlocked.Exchange(ref ActiveSessions, 0);
			count = 0;
		}

		if (count == 0 && IsRunning)
		{
			// Last client disconnected: arm idle timer
			ArmIdleTimerIfIdle();
		}
	}

	private void ArmIdleTimerIfIdle()
	{
		if (Volatile.Read(ref ActiveSessions) == 0 && IsRunning)
		{
			try
			{
				TimeSpan dueTime = TimeSpan.FromSeconds(IdleTimeoutSeconds);
				_ = IdleTimer.Change(dueTime, Timeout.InfiniteTimeSpan);

				if (DebugLoggingEnabled)
				{
					NativeEventLogger.WriteEntry(
						$"{Atlas.QuantumRelayHSSServiceName} No active clients. Idle timer armed for {IdleTimeoutSeconds} seconds.",
						NativeEventLogger.EventLogEntryType.Information);
				}
			}
			catch (ObjectDisposedException) { }
		}
	}

	private void OnIdleTimerCallback(object? _)
	{
		try
		{
			// Fire only if still idle
			if (Volatile.Read(ref ActiveSessions) == 0 && IsRunning && !CTS.IsCancellationRequested)
			{
				if (DebugLoggingEnabled)
				{
					NativeEventLogger.WriteEntry(
						$"{Atlas.QuantumRelayHSSServiceName} Idle timeout reached ({IdleTimeoutSeconds}s) with no clients. Initiating shutdown.",
						NativeEventLogger.EventLogEntryType.Information);
				}

				try
				{
					// Stop further timer callbacks
					_ = IdleTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
				}
				catch (ObjectDisposedException) { }

				try
				{
					// Cancel the server to unwind accept/session loops
					CTS.Cancel();
				}
				catch (ObjectDisposedException) { }

				IsRunning = false;
			}
		}
		catch
		{
			// Never throw from timer callback
		}
	}

	// Using RunAsClient to impersonate, then CheckTokenMembership against the Administrators SID.
	// CheckTokenMembership with an impersonated thread returns false for filtered (non-elevated) admin tokens.
	private static bool IsClientElevatedAdmin(NamedPipeServerStream pipeServer)
	{
		bool isAdmin = false;

		try
		{
			pipeServer.RunAsClient(delegate
			{
				// Build the Administrators well-known SID in managed form.
				SecurityIdentifier adminSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);

				int sidLength = adminSid.BinaryLength;
				IntPtr pSid = IntPtr.Zero;

				try
				{
					byte[] sidBytes = new byte[sidLength];
					adminSid.GetBinaryForm(sidBytes, 0);

					pSid = Marshal.AllocHGlobal(sidLength);
					Marshal.Copy(sidBytes, 0, pSid, sidLength);

					// TokenHandle = NULL means evaluate membership for the effective token of the calling thread.
					// Since we are inside RunAsClient, the thread is impersonating the client.
					if (NativeMethods.CheckTokenMembership(IntPtr.Zero, pSid, out bool isMember))
					{
						isAdmin = isMember;
					}
					else
					{
						isAdmin = false;
					}
				}
				catch
				{
					isAdmin = false;
				}
				finally
				{
					if (pSid != IntPtr.Zero)
					{
						Marshal.FreeHGlobal(pSid);
					}
				}
			});
		}
		catch
		{
			isAdmin = false;
		}

		return isAdmin;
	}
}

/// <summary>
/// Context for managing log streaming to client.
/// </summary>
internal sealed class ClientSessionContext : IDisposable
{
	private readonly BinaryWriter _writer;

	/// <summary>
	/// We use this to prevent concurrent writes
	/// </summary>
	private readonly SemaphoreSlim WriteSemaphore;

	private volatile bool IsDisposed;

	internal ClientSessionContext(BinaryWriter writer)
	{
		_writer = writer;
		WriteSemaphore = new SemaphoreSlim(1, 1);
	}

	/// <summary>
	/// Sends a log entry to the client immediately. Uses the same semaphore as responses to avoid interleaving.
	/// Falls back to Windows Event Log if the pipe is disconnected or writer is disposed.
	/// </summary>
	/// <param name="message">The log message text.</param>
	internal void SendLog(string message)
	{
		// Write to Windows Event Logs if we can't write to the pipe.
		if (IsDisposed)
		{
			NativeEventLogger.WriteEntry(
				$"{Atlas.QuantumRelayHSSServiceName}: {message}",
				NativeEventLogger.EventLogEntryType.Information);
			return;
		}

		bool acquired = false;
		try
		{
			WriteSemaphore.Wait();
			acquired = true;

			_writer.Write((byte)ResponseType.Log);
			Helpers.WriteString(_writer, message);
			_writer.Flush();
		}
		catch
		{
			NativeEventLogger.WriteEntry(
				$"{Atlas.QuantumRelayHSSServiceName}: {message}",
				NativeEventLogger.EventLogEntryType.Information);
		}
		finally
		{
			if (acquired)
			{
				try { _ = WriteSemaphore.Release(); } catch { }
			}
		}
	}

	/// <summary>
	/// Writes response data to the client using the same synchronization as log sending
	/// </summary>
	internal async Task WriteFinalResponseAsync(string output, CancellationToken cancellationToken)
	{
		if (IsDisposed)
		{
			return;
		}

		try
		{
			await WriteSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
			try
			{
				_writer.Write((byte)ResponseType.Final);
				Helpers.WriteString(_writer, output);
				_writer.Flush();
			}
			finally
			{
				_ = WriteSemaphore.Release();
			}
		}
		catch (IOException) { }
		catch (ObjectDisposedException) { }
		catch (InvalidOperationException) { }
		catch (OperationCanceledException) { }
	}

	internal async Task WriteErrorResponseAsync(int exitCode, string exceptionDetails, CancellationToken cancellationToken)
	{
		if (IsDisposed)
		{
			return;
		}

		try
		{
			await WriteSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
			try
			{
				_writer.Write((byte)ResponseType.Error);
				_writer.Write(exitCode);
				Helpers.WriteString(_writer, exceptionDetails);
				_writer.Flush();
			}
			finally
			{
				_ = WriteSemaphore.Release();
			}
		}
		catch (IOException) { }
		catch (ObjectDisposedException) { }
		catch (InvalidOperationException) { }
		catch (OperationCanceledException) { }
	}

	public void Dispose()
	{
		if (IsDisposed)
		{
			return;
		}

		IsDisposed = true;

		try
		{
			WriteSemaphore.Dispose();
		}
		catch (ObjectDisposedException) { }
	}
}
