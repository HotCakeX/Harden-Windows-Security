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
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace GlobalSearchService;

internal static class SearchLog
{
	internal static void Report(string message) => NativeEventLogger.WriteEntry(message, NativeEventLogger.EventLogEntryType.Information, SearchServiceHost.ServiceName);
	internal static void ReportWarning(string message) => NativeEventLogger.WriteEntry(message, NativeEventLogger.EventLogEntryType.Warning, SearchServiceHost.ServiceName);
	internal static void ReportError(Exception exception) => NativeEventLogger.WriteEntry(exception.ToString(), NativeEventLogger.EventLogEntryType.Error, SearchServiceHost.ServiceName);
}

internal static class SearchServiceHost
{
	internal const string ServiceName = "GlobalSearchHSS";
	internal const string PipeName = "GlobalSearchHSS_SearchPipe";
	// Application Id="App" in the package manifest; shared by the main app and Top Bar.
	internal const string AuthorizedApplicationUserModelId = "VioletHansen.HardenSystemSecurity_ea7andspwdn10!App";
	private static nint _status;
	private static CancellationTokenSource? _stop;
	private static NamedPipeServerStream? _pipe;

	private static int Main()
	{
		NativeEventLogger.EnsureSourceRegistered(ServiceName);
		nint name = Marshal.StringToHGlobalUni(ServiceName);
		try
		{
			SERVICE_TABLE_ENTRY[] table = new SERVICE_TABLE_ENTRY[2];
			table[0] = new SERVICE_TABLE_ENTRY
			{
				lpServiceName = name,
				lpServiceProc = (nint)(delegate* unmanaged[Stdcall]<uint, nint, void>)&ServiceMainCallback
			};
			if (NativeMethods.StartServiceCtrlDispatcherW(table)) return 0;
			int error = Marshal.GetLastPInvokeError();
			SearchLog.ReportError(new Win32Exception(error, "StartServiceCtrlDispatcherW failed"));
			return error;
		}
		catch (Exception exception)
		{
			SearchLog.ReportError(exception);
			return 1;
		}
		finally { Marshal.FreeHGlobal(name); }
	}

	[UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
	private static void ServiceMainCallback(uint count, nint arguments) => ServiceMain();

	[UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
	private static uint ControlCallback(uint control, uint eventType, nint eventData, nint context)
	{
		if (control is NativeMethods.SERVICE_CONTROL_STOP or NativeMethods.SERVICE_CONTROL_SHUTDOWN)
		{
			_stop?.Cancel();
			_pipe?.Dispose();
		}
		return 0;
	}

	private static void SetStatus(SERVICE_STATE state, uint accepted = 0, uint checkpoint = 0)
	{
		SERVICE_STATUS_PROCESS status = new()
		{
			dwServiceType = NativeMethods.SERVICE_WIN32_OWN_PROCESS,
			dwCurrentState = (uint)state,
			dwControlsAccepted = accepted,
			dwCheckPoint = checkpoint,
			dwWaitHint = state is SERVICE_STATE.SERVICE_START_PENDING ? 30000U : 0U
		};
		if (!NativeMethods.SetServiceStatus(_status, ref status))
			SearchLog.ReportError(new Win32Exception(Marshal.GetLastPInvokeError(), "SetServiceStatus failed"));
	}

	private static void ServiceMain()
	{
		_status = NativeMethods.RegisterServiceCtrlHandlerExW(ServiceName,
			(nint)(delegate* unmanaged[Stdcall]<uint, uint, nint, nint, uint>)&ControlCallback, 0);
		if (_status == 0)
		{
			SearchLog.ReportError(new Win32Exception(Marshal.GetLastPInvokeError(), "RegisterServiceCtrlHandlerExW failed"));
			return;
		}
		using CancellationTokenSource stop = new();
		_stop = stop;
		try
		{
			SetStatus(SERVICE_STATE.SERVICE_START_PENDING);
			// Report RUNNING promptly while the worker builds the startup index.
			Task worker = Task.Run(() => ServeAsync(stop.Token));
			SetStatus(SERVICE_STATE.SERVICE_RUNNING, NativeMethods.SERVICE_ACCEPT_STOP | NativeMethods.SERVICE_ACCEPT_SHUTDOWN);
			worker.GetAwaiter().GetResult();
		}
		catch (OperationCanceledException) { }
		catch (Exception exception) { SearchLog.ReportError(exception); }
		finally
		{
			SetStatus(SERVICE_STATE.SERVICE_STOP_PENDING);
			_pipe?.Dispose();
			_pipe = null;
			_stop = null;
			SetStatus(SERVICE_STATE.SERVICE_STOPPED);
		}
	}

	private static string Describe(Exception exception) => exception is Win32Exception win32
		? $"{win32.Message} (Win32 error {win32.NativeErrorCode}: {new Win32Exception(win32.NativeErrorCode).Message})"
		: exception.Message;

	private static async Task ServeAsync(CancellationToken cancellationToken)
	{
		using IndexState state = new();
		try
		{
			// NETWORK is denied; INTERACTIVE gets data read/write, attribute read and synchronization only.
			// the medium mandatory label allows writes across the SYSTEM integrity boundary.
			PipeSecurity security = new();
			security.SetSecurityDescriptorSddlForm(
				"D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100083;;;IU)S:(ML;;NW;;;ME)",
				AccessControlSections.All);
			// Publish the first pipe before indexing; the client can connect while awaiting readiness.
			using NamedPipeServerStream startupPipe = CreatePipeWithMandatoryLabel(security);
			_pipe = startupPipe;
			bool firstPipe = true;
			// Start indexing without a client; the initial idle window starts when this build finishes.
			try
			{
				BuildIndexes(state.Indexes, cancellationToken);
				state.Unloaded = false;
				state.ResetIdleTimer();
			}
			catch (Exception exception) when (!cancellationToken.IsCancellationRequested) { SearchLog.ReportError(exception); }
			while (!cancellationToken.IsCancellationRequested)
			{
				using NamedPipeServerStream pipe = firstPipe ? startupPipe : CreatePipeWithMandatoryLabel(security);
				firstPipe = false;
				_pipe = pipe;
				bool buildingIndexes = false;
				try
				{
					await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
					// The first byte enables RunAsClient impersonation; no query is processed yet.
					if (pipe.ReadByte() != 1 || !IsClientAuthorized(pipe)) continue;
					// Rebuild after idle unload or a failed startup build, before the ready handshake.
					lock (state.Sync)
					{
						if (state.Unloaded)
						{
							buildingIndexes = true;
							BuildIndexes(state.Indexes, cancellationToken);
							buildingIndexes = false;
							state.Unloaded = false;
							state.ResetIdleTimer();
						}
					}
					HandleSession(pipe, state, cancellationToken);
				}
				catch (IOException) when (!cancellationToken.IsCancellationRequested && !buildingIndexes && !pipe.IsConnected) { }
				catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
				{
					// A failed build or unexpected session error is logged; the next connection can retry.
					SearchLog.ReportError(exception);
				}
				catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested) { }
				finally { _pipe = null; }
			}
		}
		finally { state.StopIdleTimer(); }
	}

	private static void BuildIndexes(List<VolumeIndex> indexes, CancellationToken cancellationToken)
	{
		Stopwatch initialTime = Stopwatch.StartNew();
		string[] driveRoots = Environment.GetLogicalDrives();
		bool osOnly = false;
		try
		{
			// Read the persistent machine value on each build, not the service's process environment.
			osOnly = string.Equals(Environment.GetEnvironmentVariable("HardenSystemSecurity_GlobalSearchScope", EnvironmentVariableTarget.Machine),
				"OS", StringComparison.OrdinalIgnoreCase);
		}
		catch (Exception exception)
		{
			SearchLog.ReportWarning($"Could not read Global Search scope; using all drives: {Describe(exception)}");
		}
		string? osRoot = osOnly ? Path.GetPathRoot(Environment.SystemDirectory) : null;
		_ = indexes.EnsureCapacity(osOnly ? 1 : driveRoots.Length);
		try
		{
			foreach (string driveRoot in driveRoots)
			{
				cancellationToken.ThrowIfCancellationRequested();
				if (osOnly && !string.Equals(driveRoot, osRoot, StringComparison.OrdinalIgnoreCase)) continue;
				char drive = driveRoot[0];
				VolumeIndex? index = null;
				try
				{
					// SearchLog.Report($"Building index for {drive}:\\; please wait...");
					index = new VolumeIndex(drive);
					// SearchLog.Report($"{drive}:\\ filesystem: {index.FileSystem}");
					index.Build();
					// SearchLog.Report($"{drive}:\\ indexed {index.Count:N0} file IDs.");
					if (index.InaccessibleDirectoryCount != 0)
						SearchLog.ReportWarning($"WARNING: {drive}:\\ index is PARTIAL: {index.InaccessibleDirectoryCount:N0} access-denied director{(index.InaccessibleDirectoryCount == 1 ? "y" : "ies")} not traversed.");
					indexes.Add(index);
					index = null; // Ownership transferred to indexes.
				}
				catch (Exception exception) when (exception is Win32Exception or IOException or NotSupportedException)
				{
					SearchLog.ReportWarning($"Skipping {drive}:\\: {Describe(exception)}");
				}
				finally { index?.Dispose(); }
			}
			initialTime.Stop();
			SearchLog.Report($"Completion time: {initialTime.Elapsed.TotalMilliseconds / 1000} seconds ");
			if (indexes.Count == 0)
				SearchLog.ReportWarning("No drives could be indexed. Check that an NTFS or ReFS volume with a USN journal is available.");

		}
		catch
		{
			foreach (VolumeIndex index in indexes) index.Dispose();
			indexes.Clear();
			throw;
		}
	}

	// One service-wide index and one one-shot timer. All index operations use the
	// same lock, so the timer cannot dispose a volume during refresh or search.
	private sealed class IndexState : IDisposable
	{
		internal readonly Lock Sync = new();
		internal readonly List<VolumeIndex> Indexes = new();
		internal readonly Timer IdleTimer;
		internal bool Unloaded = true;
		private bool disposed;
		private long idleDeadline = long.MaxValue;
		// Ten minutes initially; one hour after the first query or initial idle unload.
		internal TimeSpan IdleDelay = TimeSpan.FromMinutes(10);

		internal IndexState() => IdleTimer = new(static value => ((IndexState)value!).OnIdleTimerTick(),
			this, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);

		private void OnIdleTimerTick()
		{
			try { UnloadIfIdle(); }
			catch (Exception exception) { SearchLog.ReportError(exception); }
		}

		// Called under Sync after a response, or before accepting the first client.
		internal void ResetIdleTimer()
		{
			idleDeadline = Stopwatch.GetTimestamp() + (long)(IdleDelay.TotalSeconds * Stopwatch.Frequency);
			_ = IdleTimer.Change(IdleDelay, Timeout.InfiniteTimeSpan);
		}

		internal void StopIdleTimer()
		{
			idleDeadline = long.MaxValue;
			_ = IdleTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
		}

		private void UnloadIfIdle()
		{
			lock (Sync)
			{
				if (disposed || Unloaded || idleDeadline == long.MaxValue) return;
				long now = Stopwatch.GetTimestamp();
				if (now < idleDeadline)
				{
					// An already queued callback must not override a later query's reset.
					_ = IdleTimer.Change(Stopwatch.GetElapsedTime(now, idleDeadline), Timeout.InfiniteTimeSpan);
					return;
				}
				StopIdleTimer();
				ReleaseIndexes();
				Unloaded = true;
				IdleDelay = TimeSpan.FromHours(1);
				// Collect only once per idle unload, after ReleaseIndexes has returned
				// so its last VolumeIndex local cannot keep the final volume alive.
				System.Runtime.GCSettings.LargeObjectHeapCompactionMode =
					System.Runtime.GCLargeObjectHeapCompactionMode.CompactOnce;
				GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
			}
		}

		private void ReleaseIndexes()
		{
			foreach (VolumeIndex index in Indexes) index.Dispose();
			Indexes.Clear();
			Indexes.TrimExcess();
		}

		public void Dispose()
		{
			lock (Sync)
			{
				if (disposed) return;
				disposed = true;
				StopIdleTimer();
				IdleTimer.Dispose();
				ReleaseIndexes();
			}
		}
	}

	// A mandatory integrity label lives in the SACL. LocalSystem normally has
	// SeSecurityPrivilege disabled, so enable it only while creating the pipe.
	private static NamedPipeServerStream CreatePipeWithMandatoryLabel(PipeSecurity security)
	{
		const uint TokenAdjustPrivileges = 0x0020;
		const uint TokenQuery = 0x0008;
		const uint SePrivilegeEnabled = 0x00000002;
		const int ErrorNotAllAssigned = 1300;

		if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
				TokenAdjustPrivileges | TokenQuery, out nint token))
			throw new Win32Exception(Marshal.GetLastPInvokeError(), "OpenProcessToken failed");

		try
		{
			if (!NativeMethods.LookupPrivilegeValueW(null, "SeSecurityPrivilege", out LUID luid))
				throw new Win32Exception(Marshal.GetLastPInvokeError(), "LookupPrivilegeValueW failed");

			TOKEN_PRIVILEGES enabled = new()
			{
				PrivilegeCount = 1,
				Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SePrivilegeEnabled }
			};
			TOKEN_PRIVILEGES previous = default;
			uint previousLength = 0;
			if (!NativeMethods.AdjustTokenPrivileges(token, false, ref enabled,
					(uint)sizeof(TOKEN_PRIVILEGES), (nint)(&previous), (nint)(&previousLength)))
				throw new Win32Exception(Marshal.GetLastPInvokeError(), "Enabling SeSecurityPrivilege failed");
			int privilegeError = Marshal.GetLastPInvokeError();
			if (privilegeError == ErrorNotAllAssigned)
				throw new Win32Exception(privilegeError, "SeSecurityPrivilege is not assigned to the service token");
			if (privilegeError != 0)
				throw new Win32Exception(privilegeError, "Enabling SeSecurityPrivilege failed");

			try
			{
				return NamedPipeServerStreamAcl.Create(
					PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
					PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 0, 0, security);
			}
			finally
			{
				// PreviousState contains only privileges changed by this call.
				if (previous.PrivilegeCount != 0 &&
					!NativeMethods.AdjustTokenPrivileges(token, false, ref previous,
						0, nint.Zero, nint.Zero))
					SearchLog.ReportError(new Win32Exception(Marshal.GetLastPInvokeError(),
						"Restoring SeSecurityPrivilege failed"));
			}
		}
		finally { _ = NativeMethods.CloseHandle(token); }
	}

	private static unsafe bool IsClientAuthorized(NamedPipeServerStream pipe)
	{
		bool allowed = false;
		try
		{
			pipe.RunAsClient(() =>
			{
				using WindowsIdentity identity = WindowsIdentity.GetCurrent();
				if (!Atlas.IsTokenFromAuthorizedPackage(identity.Token)) return;
				// Only the expected identity can fit; missing or longer identities fail closed.
				char* applicationId = stackalloc char[AuthorizedApplicationUserModelId.Length + 1];
				uint length = (uint)(AuthorizedApplicationUserModelId.Length + 1);
				allowed = NativeMethods.GetApplicationUserModelIdFromToken(identity.Token, ref length, applicationId) == 0 &&
					length == AuthorizedApplicationUserModelId.Length + 1 && applicationId[length - 1] == '\0' &&
					MemoryExtensions.Equals(new ReadOnlySpan<char>(applicationId, (int)length - 1),
						AuthorizedApplicationUserModelId.AsSpan(), StringComparison.OrdinalIgnoreCase);
			});
		}
		catch (Exception exception) { SearchLog.ReportError(exception); }
		if (!allowed) SearchLog.ReportWarning("Rejected Global Search pipe client without authorized package and application identity.");
		return allowed;
	}

	// Reject the declared length before reading or allocating the payload. The service owns the limit.
	private static string? ReadQuery(BinaryReader reader, BinaryWriter writer)
	{
		int length = reader.Read7BitEncodedInt();
		if (length < 0) throw new InvalidDataException("Invalid search query length.");
		writer.Write(length > 1000 ? (byte)3 : (byte)4); // 3: rejected; 4: send payload.
		writer.Flush();
		if (length > 1000)
		{
			SearchLog.ReportWarning("Rejected search query exceeding 1,000 UTF-8 bytes.");
			return null;
		}
		byte[] bytes = reader.ReadBytes(length);
		if (bytes.Length != length) throw new EndOfStreamException();
		return Encoding.UTF8.GetString(bytes);
	}

	private static List<string> SearchIndexes(string query, List<VolumeIndex> indexes)
	{
		List<string> results = new(100);
		if (!string.IsNullOrEmpty(query))
		{
			// Refresh each volume separately so one journal failure does not hide other results.
			for (int i = 0; i < indexes.Count;)
			{
				VolumeIndex index = indexes[i];
				try
				{
					index.Refresh();
					foreach (string path in index.Search(query, 100 - results.Count))
						results.Add(path);
					i++;
				}
				catch (Exception exception) when (exception is Win32Exception or IOException or NotSupportedException)
				{
					SearchLog.ReportWarning($"Index for {index.Drive}:\\ is no longer usable: {Describe(exception)}");
					index.Dispose();
					indexes.RemoveAt(i);
				}
				if (results.Count >= 100) break;
			}
		}
		return results;
	}

	private static void HandleSession(NamedPipeServerStream pipe, IndexState state, CancellationToken token)
	{
		using BinaryReader reader = new(pipe, Encoding.UTF8, leaveOpen: true);
		using BinaryWriter writer = new(pipe, Encoding.UTF8, leaveOpen: true);
		writer.Write((byte)1);
		writer.Write("Search index ready.");
		writer.Flush();
		while (!token.IsCancellationRequested)
		{
			string? query;
			try { query = ReadQuery(reader, writer); }
			catch (Exception exception) when (exception is InvalidDataException or FormatException)
			{
				// A malformed request closes only this client session, not the service or its indexes.
				SearchLog.ReportWarning($"Rejected malformed search query: {exception.Message}");
				break;
			}
			catch (EndOfStreamException) { break; }
			catch (IOException) { break; }
			if (query is null) break;
			lock (state.Sync)
			{
				state.IdleDelay = TimeSpan.FromHours(1);
				state.StopIdleTimer();
				try
				{
					if (state.Unloaded && !string.IsNullOrEmpty(query))
					{
						BuildIndexes(state.Indexes, token);
						state.Unloaded = false;
					}
					List<string> results = SearchIndexes(query, state.Indexes);
					// Snapshot the indexes currently held after this query's refresh, without walking their entries.
					long indexedItems = 0;
					foreach (VolumeIndex index in state.Indexes) indexedItems += index.IndexedItemCount;
					writer.Write((byte)2);
					writer.Write(results.Count);
					writer.Write(indexedItems);
					foreach (string path in results) writer.Write(path);
					writer.Flush();
					if (state.Indexes.Count == 0) SearchLog.ReportWarning("No usable indexes remain. Restart the service to rebuild.");
				}
				finally
				{
					// Count inactivity from the completed response, even if the pipe stays connected.
					if (!token.IsCancellationRequested) state.ResetIdleTimer();
				}
			}
		}
	}
}
