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
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Windows.ApplicationModel;

namespace HardenSystemSecurity;

internal static class ClipboardMonitor
{
	private const uint CF_UNICODETEXT = 13;
	private const uint WM_CLIPBOARDUPDATE = 0x031D;
	private const uint WM_CLOSE = 0x0010;
	private const uint WM_DESTROY = 0x0002;
	private const int ClipboardMaximumCharacters = 131_072;
	private const string MonitorMutexName = "Local\\HardenSystemSecurity.ClipboardMonitor";
	private const string MonitorStopEventName = "Local\\HardenSystemSecurity.ClipboardMonitor.Stop";
	private const string MonitorReadyEventName = "Local\\HardenSystemSecurity.ClipboardMonitor.Ready";
	private const string StartupTaskId = "HardenSystemSecurityClipboardMonitor";
	private const int StateTransitionMaximumAttempts = 100;
	private const int StateTransitionDelayMilliseconds = 100;
	private static AutoResetEvent? ClipboardUpdateEvent;

	internal static int Run()
	{
		// Only the named object's lifetime is used, not mutex ownership.
		using Mutex monitorMutex = new(false, MonitorMutexName, out bool createdNew);
		if (!createdNew)
		{
			return 0;
		}

		nint amsiContext = 0;
		try
		{
			using EventWaitHandle stopEvent = new(false, EventResetMode.ManualReset, MonitorStopEventName);
			using EventWaitHandle readyEvent = new(false, EventResetMode.ManualReset, MonitorReadyEventName);
			using AutoResetEvent clipboardUpdateEvent = new(false);
			ClipboardUpdateEvent = clipboardUpdateEvent;

			_ = readyEvent.Reset();
			int hResult = NativeMethods.AmsiInitialize("HSSClipBoardMonitor", out amsiContext);
			if (hResult < 0)
			{
				amsiContext = 0;
				throw new InvalidOperationException($"AmsiInitialize failed with HRESULT 0x{hResult:X8}.");
			}

			RunClipboardMessageLoop(amsiContext, stopEvent, readyEvent, clipboardUpdateEvent);
			return 0;
		}
		catch (Exception exception)
		{
			Logger.Write(exception);
			return 1;
		}
		finally
		{
			ClipboardUpdateEvent = null;
			if (amsiContext != 0)
			{
				NativeMethods.AmsiUninitialize(amsiContext);
			}
		}
	}

	internal static bool IsRunning() => ProcessExists() && IsEventSignaled(MonitorReadyEventName);

	private static bool ProcessExists()
	{
		try
		{
			if (!Mutex.TryOpenExisting(MonitorMutexName, out Mutex? monitorMutex))
			{
				return false;
			}

			monitorMutex.Dispose();
			return true;
		}
		catch (UnauthorizedAccessException)
		{
			return true;
		}
	}

	private static bool IsEventSignaled(string eventName)
	{
		try
		{
			using EventWaitHandle monitorEvent = EventWaitHandle.OpenExisting(eventName);
			return monitorEvent.WaitOne(0);
		}
		catch (WaitHandleCannotBeOpenedException)
		{
			return false;
		}
	}

	internal static async Task<bool> StartAsync()
	{
		if (!ProcessExists())
		{
			string executablePath = Environment.ProcessPath ?? throw new InvalidOperationException("The application executable path is unavailable.");
			using Process process = Process.Start(new ProcessStartInfo(executablePath, "--startClipBoardMonitor")
			{
				UseShellExecute = true
			}) ?? throw new InvalidOperationException("The clipboard monitor process could not be started.");
		}

		for (int attempt = 0; attempt < StateTransitionMaximumAttempts; attempt++)
		{
			if (IsRunning())
			{
				return true;
			}
			await Task.Delay(StateTransitionDelayMilliseconds);
		}
		throw new TimeoutException("The clipboard monitor did not become ready.");
	}

	internal static async Task<bool> StopAsync()
	{
		for (int attempt = 0; attempt < StateTransitionMaximumAttempts; attempt++)
		{
			if (!ProcessExists())
			{
				return false;
			}
			try
			{
				using EventWaitHandle stopEvent = EventWaitHandle.OpenExisting(MonitorStopEventName);
				if (!stopEvent.Set())
				{
					throw new InvalidOperationException("The clipboard monitor stop request could not be signaled.");
				}
			}
			catch (WaitHandleCannotBeOpenedException)
			{
				// Startup may not have created the stop event yet. Retry while the process exists.
			}
			await Task.Delay(StateTransitionDelayMilliseconds);
		}
		throw new TimeoutException("The clipboard monitor has not finished stopping.");
	}

	internal static async Task<StartupTaskState> GetStartupStateAsync()
	{
		StartupTask startupTask = await StartupTask.GetAsync(StartupTaskId);
		return startupTask.State;
	}

	internal static async Task<StartupTaskState> EnableAtStartupAsync()
	{
		StartupTask startupTask = await StartupTask.GetAsync(StartupTaskId);
		return await startupTask.RequestEnableAsync();
	}

	internal static async Task<StartupTaskState> DisableAtStartupAsync()
	{
		StartupTask startupTask = await StartupTask.GetAsync(StartupTaskId);
		startupTask.Disable();
		return startupTask.State;
	}

	private static void RunClipboardMessageLoop(nint amsiContext, EventWaitHandle stopEvent, EventWaitHandle readyEvent, AutoResetEvent clipboardUpdateEvent)
	{
		nint module = NativeMethods.GetModuleHandleW(null);
		string className = $"HSSClipboardMonitor.{Environment.ProcessId}";
		nint classNamePointer = Marshal.StringToHGlobalUni(className);

		try
		{
			WNDCLASSEXW windowClass = new()
			{
				cbSize = (uint)sizeof(WNDCLASSEXW),
				lpfnWndProc = (nint)(delegate* unmanaged[Stdcall]<nint, uint, nuint, nint, nint>)&WindowProc,
				hInstance = module,
				lpszClassName = classNamePointer
			};

			if (NativeMethods.RegisterClassExW(in windowClass) == 0)
			{
				throw new InvalidOperationException("RegisterClassExW failed.");
			}

			bool clipboardFormatListenerAdded = false;
			nint window = 0;
			using CancellationTokenSource cancellation = new();
			Thread? worker = null;
			Thread? stopListener = null;
			try
			{
				window = NativeMethods.CreateWindowExW(
					0,
					className,
					null,
					0,
					0,
					0,
					0,
					0,
					new nint(-3),
					0,
					module,
					0);

				if (window == 0)
				{
					throw new InvalidOperationException("CreateWindowExW failed.");
				}

				if (!NativeMethods.AddClipboardFormatListener(window))
				{
					throw new InvalidOperationException($"AddClipboardFormatListener failed with Win32 error {Marshal.GetLastPInvokeError()}.");
				}
				clipboardFormatListenerAdded = true;

				Thread clipboardWorker = new(() => ClipboardWorkerLoop(amsiContext, clipboardUpdateEvent, cancellation.Token))
				{
					IsBackground = true,
					Name = "HSS Clipboard Monitor"
				};
				clipboardWorker.Start();
				worker = clipboardWorker;
				Thread stopThread = new(() => WaitForStopRequest(window, stopEvent, cancellation.Token))
				{
					IsBackground = true,
					Name = "HSS Clipboard Monitor Stop Listener"
				};
				stopThread.Start();
				stopListener = stopThread;
				_ = readyEvent.Set();
				// Include the current clipboard instead of waiting for the first new copy.
				_ = clipboardUpdateEvent.Set();

				while (true)
				{
					int result = NativeMethods.GetMessageW(out MSG message, 0, 0, 0);
					if (result == -1)
					{
						throw new Win32Exception(Marshal.GetLastPInvokeError(), "GetMessageW failed.");
					}

					if (result == 0)
					{
						break;
					}

					_ = NativeMethods.DispatchMessageW(in message);
				}
			}
			finally
			{
				_ = readyEvent.Reset();
				cancellation.Cancel();
				stopListener?.Join();
				// Never dispose the AMSI context or clipboard window while the worker is using them.
				worker?.Join();
				if (window != 0)
				{
					if (clipboardFormatListenerAdded)
					{
						_ = NativeMethods.RemoveClipboardFormatListener(window);
					}
					_ = NativeMethods.DestroyWindow(window);
				}

				_ = NativeMethods.UnregisterClassW(className, module);
			}
		}
		finally
		{
			Marshal.FreeHGlobal(classNamePointer);
		}
	}

	private static void WaitForStopRequest(nint window, EventWaitHandle stopEvent, CancellationToken cancellation)
	{
		WaitHandle[] waitHandles = [cancellation.WaitHandle, stopEvent];
		if (WaitHandle.WaitAny(waitHandles) != 1)
		{
			return;
		}

		// Marshal shutdown to the window thread so its finally blocks run.
		// If the message queue is full, retry without leaking or abandoning this listener thread.
		while (!NativeMethods.PostMessageW(window, (WinMsg)WM_CLOSE, 0, 0))
		{
			if (cancellation.WaitHandle.WaitOne(100))
			{
				return;
			}
		}
	}

	[UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
	private static nint WindowProc(nint hWnd, uint uMsg, nuint wParam, nint lParam)
	{
		try
		{
			switch (uMsg)
			{
				case WM_CLIPBOARDUPDATE:
					_ = ClipboardUpdateEvent?.Set();
					return 0;
				case WM_CLOSE:
				case WM_DESTROY:
					NativeMethods.PostQuitMessage(0);
					return 0;
				default:
					return NativeMethods.DefWindowProcW(hWnd, uMsg, wParam, lParam);
			}
		}
		catch (Exception exception)
		{
			Logger.Write(exception);
			return NativeMethods.DefWindowProcW(hWnd, uMsg, wParam, lParam);
		}
	}

	private static void ClipboardWorkerLoop(nint amsiContext, AutoResetEvent clipboardUpdateEvent, CancellationToken cancellation)
	{
		// Cancellation takes precedence over queued updates. A failed read/scan is retried even without another copy.
		WaitHandle[] waitHandles = [cancellation.WaitHandle, clipboardUpdateEvent];
		uint? lastSequence = null;
		int retryDelay = Timeout.Infinite;
		bool scanFailed = false;
		while (WaitHandle.WaitAny(waitHandles, retryDelay) != 0)
		{
			try
			{
				cancellation.ThrowIfCancellationRequested();
				ClipboardSnapshot? snapshot = ReadClipboardText(lastSequence, cancellation);
				if (snapshot is ClipboardSnapshot current)
				{
					cancellation.ThrowIfCancellationRequested();
					ScanClipboardText(amsiContext, current);
					if (current.IsIncomplete)
					{
						Logger.Write($"Clipboard scan incomplete: sequence {current.SequenceNumber}, owner PID {current.OwnerProcessId}, character limit {ClipboardMaximumCharacters}. Text exceeded the limit or was not null-terminated.");
					}
					// Zero is not a usable sequence number. Failed scans never advance this marker.
					lastSequence = current.SequenceNumber == 0 ? null : current.SequenceNumber;
				}
				if (scanFailed)
				{
					Logger.Write("Clipboard monitoring resumed processing the current snapshot. Monitoring remains best-effort; replaced clipboard values cannot be recovered.");
				}
				scanFailed = false;
				retryDelay = Timeout.Infinite;
			}
			catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
			{
				return;
			}
			catch (Exception exception)
			{
				if (!scanFailed)
				{
					// Log once per failure episode rather than on every timed retry.
					Logger.Write(exception);
				}
				scanFailed = true;
				retryDelay = 1000;
			}
		}
	}

	private static unsafe void ScanClipboardText(nint amsiContext, ClipboardSnapshot snapshot)
	{
		string? content = snapshot.Text;
		if (string.IsNullOrWhiteSpace(content))
		{
			return;
		}

		int hResult;
		AMSI_RESULT result;
		fixed (char* contentBuffer = content)
		{
			uint contentLength = checked((uint)(content.Length * sizeof(char)));
			hResult = NativeMethods.AmsiScanBuffer(
				amsiContext, contentBuffer, contentLength, "HSSClipboardMonitor/Clipboard", 0, out result);
		}

		if (hResult < 0)
		{
			throw new InvalidOperationException($"AmsiScanBuffer failed with HRESULT 0x{hResult:X8}.");
		}

		// Provider-specific risk scores below DETECTED are not malware verdicts.
		// https://learn.microsoft.com/windows/win32/api/amsi/ne-amsi-amsi_result
		bool malware = result >= AMSI_RESULT.DETECTED;
		bool policyBlocked = result is >= AMSI_RESULT.BLOCKED_BY_ADMIN_START and <= AMSI_RESULT.BLOCKED_BY_ADMIN_END;
		if (!malware && !policyBlocked)
		{
			return;
		}

		DeleteClipboardSnapshot(snapshot.SequenceNumber);
		string sourceProcessName = GetClipboardOwnerProcessName(snapshot.OwnerProcessId, snapshot.CapturedAtUtc);
		UnelevatedOperations.ToastNotifications.ShowToastNotification(
			title: malware ? "Malicious clipboard content detected" : "Clipboard content flagged by administrator policy",
			body: malware
				? $"Detected malware in the text copied from {sourceProcessName}."
				: $"An antimalware provider reported an administrator-policy block in the text copied from {sourceProcessName}.",
			attributionText: "Harden System Security",
			group: "ClipboardMonitor",
			ignoreUserPreferences: true,
			soundEvent: Microsoft.Windows.AppNotifications.Builder.AppNotificationSoundEvent.Default);
	}

	private static void DeleteClipboardSnapshot(uint sequenceNumber)
	{
		int lastError = 0;
		for (int attempt = 0; attempt < 6; attempt++)
		{
			if (NativeMethods.OpenClipboard(0))
			{
				try
				{
					uint currentSequenceNumber = NativeMethods.GetClipboardSequenceNumber();
					if (currentSequenceNumber != sequenceNumber)
					{
						Logger.Write($"Malicious clipboard content was not deleted because the clipboard changed after scanning. Scanned sequence {sequenceNumber}, current sequence {currentSequenceNumber}.");
						return;
					}
					if (!NativeMethods.EmptyClipboard())
					{
						Logger.Write(new Win32Exception(Marshal.GetLastPInvokeError(), "EmptyClipboard failed."));
						return;
					}
					Logger.Write($"Deleted malicious clipboard content from sequence {sequenceNumber}.");
					return;
				}
				finally
				{
					_ = NativeMethods.CloseClipboard();
				}
			}
			lastError = Marshal.GetLastPInvokeError();
			if (attempt < 5)
			{
				Thread.Sleep(10 * (attempt + 1));
			}
		}
		Logger.Write(new Win32Exception(lastError, "OpenClipboard failed after 6 attempts while deleting malicious clipboard content."));
	}

	private static string GetClipboardOwnerProcessName(uint processId, DateTime capturedAtUtc)
	{
		if (processId == 0)
		{
			return "Unknown";
		}

		try
		{
			using Process process = Process.GetProcessById(checked((int)processId));
			// A PID can be reused while an antimalware provider is scanning.
			return process.StartTime.ToUniversalTime() <= capturedAtUtc ? process.ProcessName : "Unknown";
		}
		catch
		{
			return "Unknown";
		}
	}

	private readonly record struct ClipboardSnapshot(string? Text, uint SequenceNumber, uint OwnerProcessId, bool IsIncomplete, DateTime CapturedAtUtc);

	private static ClipboardSnapshot? ReadClipboardText(uint? lastSequence, CancellationToken cancellation)
	{
		int lastError = 0;
		for (int attempt = 0; attempt < 6; attempt++)
		{
			cancellation.ThrowIfCancellationRequested();
			// A null window is supported for read-only access. Ownership, text and sequence are sampled under this lock.
			if (NativeMethods.OpenClipboard(0))
			{
				try
				{
					uint sequence = NativeMethods.GetClipboardSequenceNumber();
					if (!NativeMethods.IsClipboardFormatAvailable(CF_UNICODETEXT))
					{
						return sequence != 0 && sequence == lastSequence
							? null
							: new ClipboardSnapshot(null, sequence, 0, false, DateTime.UtcNow);
					}

					nint handle = NativeMethods.GetClipboardData(CF_UNICODETEXT);
					if (handle == 0)
					{
						throw new Win32Exception(Marshal.GetLastPInvokeError(), "GetClipboardData failed.");
					}

					// Delayed text must be rendered before deduplication because rendering can increment the sequence.
					sequence = NativeMethods.GetClipboardSequenceNumber();
					if (sequence != 0 && sequence == lastSequence)
					{
						return null;
					}
					uint ownerProcessId = 0;
					nint owner = NativeMethods.GetClipboardOwner();
					if (owner != 0)
					{
						_ = NativeMethods.GetWindowThreadProcessId(owner, out ownerProcessId);
					}
					DateTime capturedAtUtc = DateTime.UtcNow;

					nuint size = NativeMethods.GlobalSize(handle);
					if (size < sizeof(char))
					{
						throw new InvalidOperationException($"Invalid clipboard allocation size: {size} bytes.");
					}

					nint pointer = NativeMethods.GlobalLock(handle);
					if (pointer == 0)
					{
						throw new Win32Exception(Marshal.GetLastPInvokeError(), "GlobalLock failed.");
					}

					try
					{
						// Inspect one extra code unit so a terminator exactly at the limit is not reported as truncation.
						int characterCount = checked((int)Math.Min(size / sizeof(char), ClipboardMaximumCharacters + 1));
						// Clipboard text ends at the first null within the bounded allocation.
						ReadOnlySpan<char> characters = new((void*)pointer, characterCount);
						int terminatorIndex = characters.IndexOf('\0');
						bool incomplete = terminatorIndex < 0;
						characters = characters[..(incomplete ? Math.Min(characterCount, ClipboardMaximumCharacters) : terminatorIndex)];
						return new ClipboardSnapshot(new string(characters), sequence, ownerProcessId, incomplete, capturedAtUtc);
					}
					finally
					{
						_ = NativeMethods.GlobalUnlock(handle);
					}
				}
				finally
				{
					_ = NativeMethods.CloseClipboard();
				}
			}

			lastError = Marshal.GetLastPInvokeError();
			if (attempt < 5 && cancellation.WaitHandle.WaitOne(10 * (attempt + 1)))
			{
				cancellation.ThrowIfCancellationRequested();
			}
		}
		throw new Win32Exception(lastError, "OpenClipboard failed after 6 attempts. Monitoring will retry.");
	}
}


