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

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace QuantumRelayHSS;

internal static class WindowsServiceHost
{
	// Service status handle
	private static IntPtr s_statusHandle = IntPtr.Zero;

	// Runtime state
	private static CancellationTokenSource? s_stoppingCts;
	private static Task? s_workerTask;
	private static NamedPipeServer? s_pipeServer;
	private static volatile bool s_stopRequested;
	private static volatile bool s_runningReported;

	// Job object to ensure all child processes are killed when the service stops
	private static IntPtr s_jobHandle = IntPtr.Zero;

	// Debug logging toggle via System environment variable "QUANTUMRELAYHSS_DEBUG"
	private static readonly bool s_debugLoggingEnabled = IsDebugEnabled();

	static WindowsServiceHost()
	{
		// Create the custom event source if it doesn't exist
		NativeEventLogger.EnsureSourceRegistered(Atlas.QuantumRelayHSSServiceName);
	}

	// Entry from Program.Main. Starts the service control dispatcher.
	internal static int Run()
	{
		IntPtr serviceNamePtr = IntPtr.Zero;
		try
		{
			SERVICE_TABLE_ENTRY[] dispatchTable = new SERVICE_TABLE_ENTRY[2];

			// Allocate unmanaged memory for the service name (LPWSTR)
			serviceNamePtr = Marshal.StringToHGlobalUni(Atlas.QuantumRelayHSSServiceName);

			// Get a function pointer for the managed ServiceMain delegate
			IntPtr serviceMainPtr;
			unsafe
			{
				// Use an unmanaged function pointer
				serviceMainPtr = (IntPtr)(delegate* unmanaged[Stdcall]<uint, IntPtr, void>)&ServiceMain_Unmanaged;
			}

			dispatchTable[0] = new SERVICE_TABLE_ENTRY
			{
				lpServiceName = serviceNamePtr,
				lpServiceProc = serviceMainPtr
			};

			// Sentinel terminator entry must be all zeros
			dispatchTable[1] = new SERVICE_TABLE_ENTRY
			{
				lpServiceName = IntPtr.Zero,
				lpServiceProc = IntPtr.Zero
			};

			bool ok = NativeMethods.StartServiceCtrlDispatcherW(dispatchTable);
			if (!ok)
			{
				int error = Marshal.GetLastPInvokeError();

				NativeEventLogger.WriteEntry(
					$"{Atlas.QuantumRelayHSSServiceName} StartServiceCtrlDispatcherW failed with error {error}. The executable must be started by the Service Control Manager.",
					NativeEventLogger.EventLogEntryType.Error);

				return error != 0 ? error : 1;
			}

			return 0;
		}
		catch (Exception ex)
		{
			NativeEventLogger.WriteEntry(
				$"{Atlas.QuantumRelayHSSServiceName} Service dispatcher error: {ex.Message}\n{ex.StackTrace}",
				NativeEventLogger.EventLogEntryType.Error);

			return 1;
		}
		finally
		{
			// Free the unmanaged service name buffer
			if (serviceNamePtr != IntPtr.Zero)
			{
				Marshal.FreeHGlobal(serviceNamePtr);
			}
		}
	}

	// Service entry point called by SCM
	private static void ServiceMain(uint argc, IntPtr argv)
	{
		try
		{
			unsafe
			{
				// Register unmanaged control handler using an unmanaged function pointer
				IntPtr handlerPtr = (IntPtr)(delegate* unmanaged[Stdcall]<uint, uint, IntPtr, IntPtr, uint>)&ServiceControlHandler_Unmanaged;
				s_statusHandle = NativeMethods.RegisterServiceCtrlHandlerExW(Atlas.QuantumRelayHSSServiceName, handlerPtr, IntPtr.Zero);
			}
			if (s_statusHandle == IntPtr.Zero)
			{
				int error = Marshal.GetLastPInvokeError();

				NativeEventLogger.WriteEntry(
					$"{Atlas.QuantumRelayHSSServiceName} RegisterServiceCtrlHandlerExW failed with error {error}",
					NativeEventLogger.EventLogEntryType.Error);

				return;
			}

			// Report start pending
			ReportServiceStatus(SERVICE_STATE.SERVICE_START_PENDING, waitHintMs: 30000);

			// Initialize and start worker
			s_stoppingCts = new CancellationTokenSource();

			// Creating a Job Object so that all child processes are killed when the service stops
			SetupKillOnJobClose();

			// Construct the components
			s_pipeServer = new NamedPipeServer();

			// Start the server work
			s_workerTask = Task.Run(async () =>
			{
				try
				{
					await s_pipeServer!.StartAsync(s_stoppingCts.Token).ConfigureAwait(false);
				}
				catch (OperationCanceledException) { } // Expected during stopping
				catch (Exception ex)
				{
					NativeEventLogger.WriteEntry(
						$"{Atlas.QuantumRelayHSSServiceName} Worker error: {ex.Message}\n{ex.StackTrace}",
						NativeEventLogger.EventLogEntryType.Error);

					// Trigger stop sequence if worker crashes
					RequestStop();
				}
			});

			// Report running
			s_runningReported = true;

			ReportServiceStatus(SERVICE_STATE.SERVICE_RUNNING, controlsAccepted:
				NativeMethods.SERVICE_ACCEPT_STOP | NativeMethods.SERVICE_ACCEPT_SHUTDOWN);

			// Wait for worker to end; stop is requested by SCM or fatal error
			try
			{
				s_workerTask.Wait();
			}
			catch { } // If the task throws, proceed to stop reporting

			// Perform stop finalization and report stopped
			ReportServiceStatus(SERVICE_STATE.SERVICE_STOP_PENDING, waitHintMs: 30000);
			TryStopServerSync();
			ReportServiceStatus(SERVICE_STATE.SERVICE_STOPPED);
		}
		catch (Exception ex)
		{
			NativeEventLogger.WriteEntry(
				$"{Atlas.QuantumRelayHSSServiceName} ServiceMain error: {ex.Message}\n{ex.StackTrace}",
				NativeEventLogger.EventLogEntryType.Error);

			// Best-effort stop report
			try
			{
				ReportServiceStatus(SERVICE_STATE.SERVICE_STOPPED, win32ExitCode: 1);
			}
			catch { }
		}
	}

	// Service control handler for STOP/SHUTDOWN etc.
	private static uint ServiceControlHandler(uint control, uint eventType, IntPtr eventData, IntPtr context)
	{
		switch (control)
		{
			case NativeMethods.SERVICE_CONTROL_STOP:
			case NativeMethods.SERVICE_CONTROL_SHUTDOWN:
				{
					RequestStop();
					return 0;
				}
			default:
				return 0;
		}
	}

	private static void RequestStop()
	{
		if (s_stopRequested)
		{
			return;
		}

		s_stopRequested = true;

		// Report pending stop if we already reported running
		if (s_runningReported)
		{
			try
			{
				ReportServiceStatus(SERVICE_STATE.SERVICE_STOP_PENDING, waitHintMs: 30000);
			}
			catch { }
		}

		try
		{
			s_stoppingCts?.Cancel();
		}
		catch { }
	}

	private static void TryStopServerSync()
	{
		try
		{
			if (s_pipeServer != null)
			{
				// Give the server a chance to shut down cleanly
				Task stopTask = s_pipeServer.StopAsync();
				_ = stopTask.Wait(15000);
			}
		}
		catch { }

		try
		{
			if (s_workerTask != null)
			{
				_ = s_workerTask.Wait(15000);
			}
		}
		catch { }

		try
		{
			s_pipeServer?.Dispose();
		}
		catch { }

		// Close the Job Object handle last to force-terminate any remaining child processes
		try
		{
			if (s_jobHandle != IntPtr.Zero)
			{
				bool closed = NativeMethods.CloseHandle(s_jobHandle);
				s_jobHandle = IntPtr.Zero;

				if (s_debugLoggingEnabled)
				{
					NativeEventLogger.WriteEntry(
						$"{Atlas.QuantumRelayHSSServiceName} Job object closed (kill-on-close). CloseHandle result={closed}.",
						NativeEventLogger.EventLogEntryType.Information);
				}
			}
		}
		catch { }
	}

	private static void ReportServiceStatus(SERVICE_STATE currentState, uint controlsAccepted = 0, uint win32ExitCode = 0, uint waitHintMs = 0)
	{
		SERVICE_STATUS status = new()
		{
			dwServiceType = NativeMethods.SERVICE_WIN32_OWN_PROCESS,
			dwCurrentState = (uint)currentState,
			dwControlsAccepted = controlsAccepted,
			dwWin32ExitCode = win32ExitCode,
			dwServiceSpecificExitCode = 0,
			dwCheckPoint = 0,
			dwWaitHint = waitHintMs
		};

		_ = NativeMethods.SetServiceStatus(s_statusHandle, ref status);
	}

	private unsafe static void SetupKillOnJobClose()
	{
		try
		{
			s_jobHandle = NativeMethods.CreateJobObjectW(IntPtr.Zero, null);
			if (s_jobHandle == IntPtr.Zero)
			{
				int error = Marshal.GetLastPInvokeError();
				if (s_debugLoggingEnabled)
				{
					NativeEventLogger.WriteEntry(
						$"{Atlas.QuantumRelayHSSServiceName} CreateJobObjectW failed with error {error}.",
						NativeEventLogger.EventLogEntryType.Information);
				}
				return;
			}

			JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new()
			{
				BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
				{
					LimitFlags = NativeMethods.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
				}
			};

			uint size = (uint)sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
			bool setOk = NativeMethods.SetInformationJobObject(
				s_jobHandle,
				JOBOBJECTINFOCLASS.JobObjectExtendedLimitInformation,
				ref info,
				size);

			if (!setOk)
			{
				int error = Marshal.GetLastPInvokeError();
				if (s_debugLoggingEnabled)
				{
					NativeEventLogger.WriteEntry(
						$"{Atlas.QuantumRelayHSSServiceName} SetInformationJobObject failed with error {error}.",
						NativeEventLogger.EventLogEntryType.Information);
				}
				// Keep the handle anyway; Assign may still work, but kill-on-close might not be set.
			}

			IntPtr currentProcess = NativeMethods.GetCurrentProcess();
			bool assignOk = NativeMethods.AssignProcessToJobObject(s_jobHandle, currentProcess);
			if (!assignOk)
			{
				int error = Marshal.GetLastPInvokeError();
				if (s_debugLoggingEnabled)
				{
					NativeEventLogger.WriteEntry(
						$"{Atlas.QuantumRelayHSSServiceName} AssignProcessToJobObject failed with error {error}. The service may already be in a job.",
						NativeEventLogger.EventLogEntryType.Information);
				}
			}
			else
			{
				if (s_debugLoggingEnabled)
				{
					NativeEventLogger.WriteEntry(
						$"{Atlas.QuantumRelayHSSServiceName} Job object setup complete. Kill-on-close is enabled.",
						NativeEventLogger.EventLogEntryType.Information);
				}
			}
		}
		catch { } // Do not fail service startup on job setup errors
	}

	internal static bool IsDebugEnabled()
	{
		try
		{
			string? value = Environment.GetEnvironmentVariable("QUANTUMRELAYHSS_DEBUG");
			if (string.IsNullOrEmpty(value))
				return false;

			return value.Equals("1", StringComparison.OrdinalIgnoreCase)
				|| value.Equals("true", StringComparison.OrdinalIgnoreCase)
				|| value.Equals("yes", StringComparison.OrdinalIgnoreCase);
		}
		catch
		{
			return false;
		}
	}

	// Unmanaged entry point for SCM table
	[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
	private static void ServiceMain_Unmanaged(uint argc, IntPtr argv) => ServiceMain(argc, argv);

	// Unmanaged control handler for RegisterServiceCtrlHandlerExW
	[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
	private static uint ServiceControlHandler_Unmanaged(uint control, uint eventType, IntPtr eventData, IntPtr context) =>
		 ServiceControlHandler(control, eventType, eventData, context);

}
