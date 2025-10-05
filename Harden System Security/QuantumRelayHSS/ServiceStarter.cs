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

using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace HardenSystemSecurity.QuantumRelayHSS;

internal static partial class ServiceStarter
{
	/// <summary>
	/// Starts the given service and waits until it reaches "running" status or the timeout/cancellation is hit.
	/// </summary>
	/// <param name="serviceName"></param>
	/// <param name="timeout"></param>
	/// <param name="cancellationToken"></param>
	/// <returns></returns>
	/// <exception cref="ArgumentOutOfRangeException"></exception>
	/// <exception cref="Win32Exception"></exception>
	internal static async Task StartServiceAsync(string serviceName, TimeSpan timeout, CancellationToken cancellationToken = default)
	{
		if (timeout <= TimeSpan.Zero)
		{
			throw new ArgumentOutOfRangeException(nameof(timeout), "Timeout must be greater than zero.");
		}

		IntPtr scmHandle = IntPtr.Zero;
		IntPtr serviceHandle = IntPtr.Zero;

		try
		{
			// Open the Service Control Manager by openning a service handle.
			scmHandle = NativeMethods.OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
			if (scmHandle == IntPtr.Zero)
			{
				int error = Marshal.GetLastPInvokeError();
				throw new Win32Exception(error, $"OpenSCManagerW failed with error {error}.");
			}

			// Open the service with rights to start and query status.
			serviceHandle = NativeMethods.OpenServiceW(scmHandle, serviceName, SERVICE_START | SERVICE_QUERY_STATUS);
			if (serviceHandle == IntPtr.Zero)
			{
				int error = Marshal.GetLastPInvokeError();
				throw new Win32Exception(error, $"OpenServiceW failed for '{serviceName}' with error {error}.");
			}

			DateTime deadlineUtc = DateTime.UtcNow + timeout;

			// If already running, nothing to do.
			SERVICE_STATUS_PROCESS status = QueryServiceStatusProcess(serviceHandle);
			if (status.dwCurrentState == SERVICE_RUNNING)
			{
				return;
			}

			// If stopping, wait until fully stopped before attempting to start.
			if (status.dwCurrentState == SERVICE_STOP_PENDING)
			{
				await WaitForStateAsync(serviceHandle, SERVICE_STOPPED, deadlineUtc, cancellationToken).ConfigureAwait(false);
			}

			// Attempt to start (ignore "already running" error).
			bool startOk = NativeMethods.StartServiceW(serviceHandle, 0, IntPtr.Zero);
			if (!startOk)
			{
				int error = Marshal.GetLastPInvokeError();
				if (error != ERROR_SERVICE_ALREADY_RUNNING)
				{
					throw new Win32Exception(error, $"StartServiceW failed for '{serviceName}' with error {error}.");
				}
			}

			// Wait until the service reports running.
			await WaitForStateAsync(serviceHandle, SERVICE_RUNNING, deadlineUtc, cancellationToken).ConfigureAwait(false);
		}
		finally
		{
			// Close handles in reverse order.
			try
			{
				if (serviceHandle != IntPtr.Zero)
				{
					_ = NativeMethods.CloseServiceHandle(serviceHandle);
				}
			}
			catch { }

			try
			{
				if (scmHandle != IntPtr.Zero)
				{
					_ = NativeMethods.CloseServiceHandle(scmHandle);
				}
			}
			catch { }
		}
	}

	// Poll QueryServiceStatusEx until the service reaches the desired state, times out, or is canceled.
	private static async Task WaitForStateAsync(IntPtr serviceHandle, uint desiredState, DateTime deadlineUtc, CancellationToken cancellationToken)
	{
		while (true)
		{
			cancellationToken.ThrowIfCancellationRequested();

			SERVICE_STATUS_PROCESS status = QueryServiceStatusProcess(serviceHandle);
			if (status.dwCurrentState == desiredState)
			{
				return;
			}

			if (DateTime.UtcNow >= deadlineUtc)
			{
				throw new TimeoutException($"Timed out waiting for the service to reach state {desiredState} (current state {status.dwCurrentState}).");
			}

			// Derive a reasonable polling delay from WaitHint (use 10% of wait hint, bounded).
			int delayMs = 250;
			uint waitHint = status.dwWaitHint;
			if (waitHint > 0)
			{
				long suggested = (long)waitHint / 10;
				if (suggested < 100) suggested = 100;
				if (suggested > 2000) suggested = 2000;
				delayMs = (int)suggested;
			}

			// Ensure we don't sleep past the deadline.
			TimeSpan remaining = deadlineUtc - DateTime.UtcNow;
			if (remaining <= TimeSpan.Zero)
			{
				throw new TimeoutException($"Timed out waiting for the service to reach state {desiredState} (current state {status.dwCurrentState}).");
			}

			int boundedDelay = remaining < TimeSpan.FromMilliseconds(delayMs) ? (int)remaining.TotalMilliseconds : delayMs;
			if (boundedDelay < 50) boundedDelay = 50;

			await Task.Delay(boundedDelay, cancellationToken).ConfigureAwait(false);
		}
	}

	// Query SERVICE_STATUS_PROCESS using QueryServiceStatusEx(SC_STATUS_PROCESS_INFO).
	private unsafe static SERVICE_STATUS_PROCESS QueryServiceStatusProcess(IntPtr serviceHandle)
	{
		int size = sizeof(SERVICE_STATUS_PROCESS);
		IntPtr buffer = Marshal.AllocHGlobal(size);

		try
		{
			bool ok = NativeMethods.QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO, buffer, (uint)size, out uint bytesNeeded);
			if (!ok)
			{
				int error = Marshal.GetLastPInvokeError();
				throw new Win32Exception(error, $"QueryServiceStatusEx failed with error {error}.");
			}

			SERVICE_STATUS_PROCESS status = *(SERVICE_STATUS_PROCESS*)buffer;
			return status;
		}
		finally
		{
			Marshal.FreeHGlobal(buffer);
		}
	}


	// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_status_process
	[StructLayout(LayoutKind.Sequential)]
	private struct SERVICE_STATUS_PROCESS
	{
		internal uint dwServiceType;
		internal uint dwCurrentState;
		internal uint dwControlsAccepted;
		internal uint dwWin32ExitCode;
		internal uint dwServiceSpecificExitCode;
		internal uint dwCheckPoint;
		internal uint dwWaitHint;
		internal uint dwProcessId;
		internal uint dwServiceFlags;
	}

	// https://learn.microsoft.com/windows/win32/services/service-security-and-access-rights
	private const uint SC_MANAGER_CONNECT = 0x0001;
	private const uint SERVICE_QUERY_STATUS = 0x0004;
	private const uint SERVICE_START = 0x0010;

	// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_status_process
	private const uint SERVICE_STOPPED = 0x00000001;
	private const uint SERVICE_STOP_PENDING = 0x00000003;
	private const uint SERVICE_RUNNING = 0x00000004;

	// https://learn.microsoft.com/openspecs/windows_protocols/ms-scmr/a7de3a4b-0b9e-4b9b-8863-b3dbc9bbe02b
	// Info level for QueryServiceStatusEx
	private const int SC_STATUS_PROCESS_INFO = 0;

	// "https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-"
	private const int ERROR_SERVICE_ALREADY_RUNNING = 1056;
}
