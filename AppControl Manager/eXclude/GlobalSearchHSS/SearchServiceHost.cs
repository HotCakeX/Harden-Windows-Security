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

using System.Buffers.Binary;
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
using System.Text.Unicode;
using System.Threading;
using System.Threading.Tasks;

namespace GlobalSearchService;

internal static class SearchLog
{
	internal static void Report(string message) => NativeEventLogger.WriteEntry(message, NativeEventLogger.EventLogEntryType.Information, SearchServiceHost.ServiceName);
	internal static void ReportWarning(string message) => NativeEventLogger.WriteEntry(message, NativeEventLogger.EventLogEntryType.Warning, SearchServiceHost.ServiceName);
	internal static void ReportError(Exception exception) => NativeEventLogger.WriteEntry(exception.ToString(), NativeEventLogger.EventLogEntryType.Error, SearchServiceHost.ServiceName);
}

// The search result frame, built in buffers reused by every query of a session and sent with one pipe write.
// The pipe is asynchronous, so every separate write allocates its own I/O task and wait; writing each field
// separately allocated hundreds of them per search. The bytes are identical to the BinaryWriter output the
// client reads: tag 2, Int32 count, Int64 indexed items, then each path as a 7-bit encoded UTF-8 byte length
// followed by its UTF-8 bytes.
internal sealed class SearchResponse
{
	internal const int MaxResults = 100;
	// Tag, count and indexed items.
	private const int HeaderSize = 13;
	private const int InitialFrameSize = 16 * 1024;
	private const int InitialPathSize = 1024;
	// Buffers grown by unusually long paths are released after the response instead of being kept for the session.
	// 256 KB holds 100 paths averaging over 850 characters, even when each character takes 3 UTF-8 bytes.
	private const int RetainedFrameSize = 256 * 1024;
	private const int RetainedPathSize = 32 * 1024;
	private byte[] frame = new byte[InitialFrameSize];
	private char[] path = new char[InitialPathSize];
	private int length = HeaderSize;

	internal int Count { get; private set; }
	internal bool IsFull => Count >= MaxResults;

	internal void Clear()
	{
		length = HeaderSize;
		Count = 0;
	}

	// Scratch for building one path; valid until the next call.
	internal Span<char> GetPathBuffer(int pathLength)
	{
		if (path.Length < pathLength) path = new char[Math.Max(pathLength, path.Length * 2)];
		return path.AsSpan(0, pathLength);
	}

	// Same bytes as BinaryWriter.Write(string) with Encoding.UTF8, including U+FFFD for each unpaired surrogate.
	// Utf8.FromUtf16 replaces them without the allocations of Encoding.UTF8's replacement fallback, in one pass.
	internal void Add(ReadOnlySpan<char> value)
	{
		// Each UTF-16 code unit takes at most 3 UTF-8 bytes; a surrogate pair takes 4.
		int maxByteCount = value.Length * 3;
		int reservedPrefix = GetPrefixSize(maxByteCount);
		int required = length + reservedPrefix + maxByteCount;
		if (frame.Length < required) Array.Resize(ref frame, Math.Max(required, frame.Length * 2));
		// Encode after room for the longest possible length prefix, then close the gap if the prefix is shorter.
		_ = Utf8.FromUtf16(value, frame.AsSpan(length + reservedPrefix), out _, out int byteCount);
		int prefix = GetPrefixSize(byteCount);
		if (prefix != reservedPrefix)
			frame.AsSpan(length + reservedPrefix, byteCount).CopyTo(frame.AsSpan(length + prefix));
		uint remaining = (uint)byteCount;
		while (remaining > 0x7F)
		{
			frame[length++] = unchecked((byte)(remaining | 0x80));
			remaining >>= 7;
		}
		frame[length++] = (byte)remaining;
		length += byteCount;
		Count++;
	}

	// Size of the 7-bit encoded length prefix.
	private static int GetPrefixSize(int value) => value < 0x80 ? 1 : value < 0x4000 ? 2 : value < 0x20_0000 ? 3 : value < 0x1000_0000 ? 4 : 5;

	internal void WriteTo(Stream stream, long indexedItems)
	{
		frame[0] = 2;
		BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(1, 4), Count);
		BinaryPrimitives.WriteInt64LittleEndian(frame.AsSpan(5, 8), indexedItems);
		stream.Write(frame, 0, length);
		if (frame.Length > RetainedFrameSize) frame = new byte[InitialFrameSize];
		if (path.Length > RetainedPathSize) path = new char[InitialPathSize];
	}
}

internal static partial class SearchServiceHost
{
	internal const string SDDLFORM = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100083;;;IU)S:(ML;;NW;;;ME)";
	internal const string ServiceName = "GlobalSearchHSS";
	internal const string PipeName = "GlobalSearchHSS_SearchPipe";
	// Application Id="App" in the package manifest; shared by the main app and Top Bar.
	internal const string AuthorizedApplicationUserModelId = "VioletHansen.HardenSystemSecurity_ea7andspwdn10!App";
	// Searches answered between two periodic memory reclamations.
	private const int SearchesPerReclaim = 10;
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
			EnableStartupSecurityPrivilege();
			// Report RUNNING promptly while the worker starts the listeners and optional startup index.
			Task worker = Task.Run(() => ServeWithStatisticsAsync(stop.Token));
			SetStatus(SERVICE_STATE.SERVICE_RUNNING, NativeMethods.SERVICE_ACCEPT_STOP | NativeMethods.SERVICE_ACCEPT_SHUTDOWN);
			worker.GetAwaiter().GetResult();
		}
		catch (OperationCanceledException) { }
		catch (Exception exception) { SearchLog.ReportError(exception); }
		finally
		{
			SetStatus(SERVICE_STATE.SERVICE_STOP_PENDING);
			_stop = null;
			SetStatus(SERVICE_STATE.SERVICE_STOPPED);
		}
	}

	private static string Describe(Exception exception) => exception is Win32Exception win32
		? $"{win32.Message} (Win32 error {win32.NativeErrorCode}: {new Win32Exception(win32.NativeErrorCode).Message})"
		: exception.Message;

	private static async Task ServeAsync(IndexState state, CancellationToken cancellationToken)
	{
		try
		{
			// NETWORK is denied; INTERACTIVE gets data read/write, attribute read and synchronization only.
			// the medium mandatory label allows writes across the SYSTEM integrity boundary.
			PipeSecurity security = new();
			security.SetSecurityDescriptorSddlForm(SDDLFORM, AccessControlSections.All);
			// Publish the first pipe before indexing; the client can connect while awaiting readiness.
			using NamedPipeServerStream startupPipe = CreatePipeWithMandatoryLabel(security);
			_pipe = startupPipe;
			bool firstPipe = true;
			// Missing, invalid or unreadable machine values leave indexing request-driven.
			try
			{
				if (string.Equals(Environment.GetEnvironmentVariable("HardenSystemSecurity_GlobalSearchIndexAtStartup",
					EnvironmentVariableTarget.Machine), "STARTUP", StringComparison.OrdinalIgnoreCase))
					state.EnsureIndexes(cancellationToken);
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
					// Authentication alone never starts indexing; wait for an admitted query.
					HandleSession(pipe, state, cancellationToken, ref buildingIndexes);
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
					index = new VolumeIndex(drive);
					index.Build();
					if (index.InaccessibleDirectoryCount != 0)
						SearchLog.ReportWarning($"WARNING: {drive}:\\ index is PARTIAL: {index.InaccessibleDirectoryCount:N0} inaccessible director{(index.InaccessibleDirectoryCount == 1 ? "y" : "ies")} not traversed.");
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
			// Indexing leaves outgrown hash buckets, enumeration buffers and walk state behind. The large ones
			// are only freed by a full collection, which may not happen for a long time, so collect once now.
			ReclaimReleasedIndexMemory();

		}
		catch
		{
			foreach (VolumeIndex index in indexes) index.Dispose();
			indexes.Clear();
			throw;
		}
	}

	// Call only after releasing an index and returning from its owning frame, after a build completes,
	// or after every SearchesPerReclaim searches.
	// This is process-wide collection, not a working-set trim: live search indexes remain intact.
	internal static void ReclaimReleasedIndexMemory()
	{
		System.Runtime.GCSettings.LargeObjectHeapCompactionMode =
			System.Runtime.GCLargeObjectHeapCompactionMode.CompactOnce;
		GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
	}

	// One service-wide index and one one-shot timer. All index operations use the
	// same lock, so the timer cannot dispose a volume during refresh or search.
	private sealed class IndexState : IDisposable
	{
		internal readonly Lock Sync = new();
		internal readonly List<VolumeIndex> Indexes = new();
		internal readonly Timer IdleTimer;
		internal bool Unloaded = true;
		// Searches answered since the last periodic reclamation, across all sessions. Guarded by Sync.
		internal int SearchesSinceReclaim;
		private long idleDeadline = long.MaxValue;
		// Ten minutes initially; one hour after the first query or initial idle unload.
		internal TimeSpan IdleDelay = TimeSpan.FromMinutes(10);

		internal IndexState() => IdleTimer = new(static value => ((IndexState)value!).OnIdleTimerTick(),
			this, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);

		// Startup, queries and statistics share one build gate, including retries after unload.
		internal void EnsureIndexes(CancellationToken token)
		{
			lock (Sync)
			{
				token.ThrowIfCancellationRequested();
				if (!Unloaded) return;
				BuildIndexes(Indexes, token);
				Unloaded = false;
				ResetIdleTimer();
			}
		}

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
				if (Unloaded || idleDeadline == long.MaxValue) return;
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
				ReclaimReleasedIndexMemory();
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
				StopIdleTimer();
				IdleTimer.Dispose();
				ReleaseIndexes();
			}
		}
	}

	// Enable the process-token privilege before the listeners start.
	private static void EnableStartupSecurityPrivilege()
	{
		const uint TokenAdjustPrivileges = 0x0020;
		const uint SePrivilegeEnabled = 0x00000002;
		const int ErrorNotAllAssigned = 1300;

		if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
				TokenAdjustPrivileges, out nint token))
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
			// No previous-state buffer is needed because startup does not restore the privilege.
			if (!NativeMethods.AdjustTokenPrivileges(token, false, ref enabled,
					0, nint.Zero, nint.Zero))
				throw new Win32Exception(Marshal.GetLastPInvokeError(), "Enabling SeSecurityPrivilege failed");
			// A nonzero API return does not guarantee that the token held the privilege.
			int privilegeError = Marshal.GetLastPInvokeError();
			if (privilegeError == ErrorNotAllAssigned)
				throw new Win32Exception(privilegeError, "SeSecurityPrivilege is not assigned to the service token");
			if (privilegeError != 0)
				throw new Win32Exception(privilegeError, "Enabling SeSecurityPrivilege failed");
		}
		finally { _ = NativeMethods.CloseHandle(token); }
	}

	// The startup-enabled process token supplies the privilege needed for the SACL.
	private static NamedPipeServerStream CreatePipeWithMandatoryLabel(PipeSecurity security, string pipeName = PipeName) =>
		NamedPipeServerStreamAcl.Create(
			pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
			PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 0, 0, security);

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
		Span<byte> bytes = stackalloc byte[length];
		reader.BaseStream.ReadExactly(bytes);
		return Encoding.UTF8.GetString(bytes);
	}

	private static void SearchIndexes(string query, List<VolumeIndex> indexes, SearchResponse response)
	{
		response.Clear();
		if (query.Length == 0) return;
		// Prepared once and shared by every volume.
		NameQuery prepared = new(query);
		// Refresh each volume separately so one journal failure does not hide other results.
		for (int i = 0; i < indexes.Count;)
		{
			VolumeIndex index = indexes[i];
			try
			{
				index.Refresh();
				index.Search(prepared, response);
				i++;
			}
			catch (Exception exception) when (exception is Win32Exception or IOException or NotSupportedException)
			{
				SearchLog.ReportWarning($"Index for {index.Drive}:\\ is no longer usable: {Describe(exception)}");
				index.Dispose();
				indexes.RemoveAt(i);
			}
			if (response.IsFull) break;
		}
	}

	private static void HandleSession(NamedPipeServerStream pipe, IndexState state, CancellationToken token, ref bool buildingIndexes)
	{
		using BinaryReader reader = new(pipe, Encoding.UTF8, leaveOpen: true);
		using BinaryWriter writer = new(pipe, Encoding.UTF8, leaveOpen: true);
		writer.Write((byte)1);
		// The handshake confirms listener readiness, not that an index has been built.
		writer.Write("Search service ready.");
		writer.Flush();
		SearchResponse response = new();
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
			// EndOfStreamException is an IOException; both end only this session.
			catch (IOException) { break; }
			if (query is null) break;
			lock (state.Sync)
			{
				state.IdleDelay = TimeSpan.FromHours(1);
				state.StopIdleTimer();
				try
				{
					if (state.Unloaded && query.Length != 0)
					{
						// Notify the client before the synchronous build, including rebuilds after idle unload.
						writer.Write((byte)5); // Indexing; the normal result frame still follows.
						writer.Flush();
						// Keep build failures distinct from ordinary client disconnects.
						buildingIndexes = true;
						state.EnsureIndexes(token);
						buildingIndexes = false;
					}
					SearchIndexes(query, state.Indexes, response);
					// Snapshot the indexes currently held after this query's refresh, without walking their entries.
					long indexedItems = 0;
					foreach (VolumeIndex index in state.Indexes) indexedItems += index.IndexedItemCount;
					response.WriteTo(pipe, indexedItems);
					if (state.Indexes.Count == 0) SearchLog.ReportWarning("No usable indexes remain. Restart the service to rebuild.");
					// Reclaim after the response is sent, so this response is never delayed by the collection.
					if (++state.SearchesSinceReclaim >= SearchesPerReclaim)
					{
						state.SearchesSinceReclaim = 0;
						ReclaimReleasedIndexMemory();
					}
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
