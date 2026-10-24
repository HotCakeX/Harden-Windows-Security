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
	// Tag, count and indexed items.
	private const int HeaderSize = 13;
	private const int InitialFrameSize = 16 * 1024;
	private const int InitialPathSize = 1024;
	// Buffers grown by many or unusually long paths are released after the response instead of being kept for the session.
	// 256 KB holds the default 100 paths averaging over 850 characters, even when each character takes 3 UTF-8 bytes.
	// A higher result limit grows the frame only while that response is built and sent.
	private const int RetainedFrameSize = 256 * 1024;
	private const int RetainedPathSize = 32 * 1024;
	private byte[] frame = new byte[InitialFrameSize];
	private char[] path = new char[InitialPathSize];
	private int length = HeaderSize;
	private int limit;

	internal int Count { get; private set; }
	internal bool IsFull => Count >= limit;

	// Starts the response of a query that accepts up to limit results.
	internal void Clear(int limit)
	{
		this.limit = limit;
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
	private static unsafe void ServiceMainCallback(uint count, nint arguments) =>
		ServiceMain(count > 1 && string.Equals(new string(((char**)arguments)[1]), Atlas.GlobalSearchIndexAtStartupArgument, StringComparison.OrdinalIgnoreCase));

	[UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
	private static uint ControlCallback(uint control, uint eventType, nint eventData, nint context)
	{
		if (control is NativeMethods.SERVICE_CONTROL_STOP or NativeMethods.SERVICE_CONTROL_SHUTDOWN) RequestStop();
		return 0;
	}

	// Ends the listeners so ServiceMain reports SERVICE_STOPPED; used by SCM controls and the idle timeout.
	// The indexes are saved before the service stops, so it is reported as stopping before its pipe closes. A client
	// that starts the service meanwhile then waits for it to stop and starts it again, instead of waiting for the pipe.
	private static void RequestStop()
	{
		SetStatus(SERVICE_STATE.SERVICE_STOP_PENDING);
		_stop?.Cancel();
		_pipe?.Dispose();
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

	private static void ServiceMain(bool indexAtStartup)
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
			Task worker = Task.Run(() => ServeWithStatisticsAsync(indexAtStartup, stop.Token));
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

	private static async Task ServeAsync(IndexState state, bool indexAtStartup, CancellationToken cancellationToken)
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
			// Arm the idle timeout now, so a start that never receives a request still stops the service.
			lock (state.Sync) state.ResetIdleTimer();
			// Only the Global Search startup task asks for indexing at start; other starts stay request-driven.
			try
			{
				if (indexAtStartup) state.EnsureIndexes(cancellationToken);
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
		// Each index is saved here when the service stops and loaded from here at the next start.
		int loaded = 0;
		_ = indexes.EnsureCapacity(driveRoots.Length);
		try
		{
			foreach (string driveRoot in driveRoots)
			{
				cancellationToken.ThrowIfCancellationRequested();
				char drive = driveRoot[0];
				try
				{
					indexes.Add(OpenIndex(drive, out bool wasLoaded));
					if (wasLoaded) loaded++;
				}
				catch (Exception exception) when (exception is Win32Exception or IOException or UnauthorizedAccessException or NotSupportedException)
				{
					SearchLog.ReportWarning($"Skipping {drive}:\\: {Describe(exception)}");
				}
			}
			initialTime.Stop();
			SearchLog.Report($"Completion time: {initialTime.Elapsed.TotalMilliseconds / 1000} seconds. Indexes loaded from disk: {loaded} of {indexes.Count}.");
			if (indexes.Count == 0)
				SearchLog.ReportWarning("No drives could be indexed. Check that an NTFS or ReFS volume with a USN journal is available.");
			DeleteUnusedSavedIndexes(indexes);
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

	// Loads the saved index of a drive, or builds it when the saved one cannot be used. loaded is true when it was loaded.
	private static VolumeIndex OpenIndex(char drive, out bool loaded)
	{
		VolumeIndex index = new(drive, DatabaseDirectory);
		try
		{
			loaded = index.LoadOrBuild();
			if (index.InaccessibleDirectoryCount != 0)
				SearchLog.ReportWarning($"WARNING: {drive}:\\ index is PARTIAL: {index.InaccessibleDirectoryCount:N0} inaccessible director{(index.InaccessibleDirectoryCount == 1 ? "y" : "ies")} not traversed.");
			return index;
		}
		catch
		{
			index.Dispose();
			throw;
		}
	}

	// The package's per-machine folder, which Windows creates when the app is installed and deletes when it is removed.
	// Only SYSTEM and TrustedInstaller can write to it; administrators can read it.
	// https://github.com/microsoft/WindowsAppSDK/blob/main/specs/applicationdata/ApplicationData.md#34-per-machine-data-store
	private static readonly string DatabaseDirectory = Directory.CreateDirectory(Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
			"Microsoft", "Windows", "AppRepository", "Families", "ApplicationData", Atlas.HardenSystemSecurityPackageFamilyName, "Machine", "GlobalSearch")).FullName;

	// Deletes the saved indexes of drives that are no longer indexed, such as a removed drive, so they do not keep
	// using disk space. Every saved file name starts with its drive letter.
	private static void DeleteUnusedSavedIndexes(List<VolumeIndex> indexes)
	{
		try
		{
			foreach (string path in Directory.EnumerateFiles(DatabaseDirectory))
			{
				char drive = char.ToUpperInvariant(Path.GetFileName(path.AsSpan())[0]);
				if (!indexes.Exists(index => index.Drive == drive)) VolumeIndex.TryDelete(path);
			}
		}
		catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
		{
			SearchLog.ReportWarning($"Could not delete unused saved indexes: {Describe(exception)}");
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
	// same lock, so the idle timeout cannot stop the service during refresh or search.
	private sealed class IndexState : IDisposable
	{
		internal readonly Lock Sync = new();
		internal readonly List<VolumeIndex> Indexes = new();
		internal readonly Timer IdleTimer;
		internal bool Unloaded = true;
		// Searches answered since the last periodic reclamation, across all sessions. Guarded by Sync.
		internal int SearchesSinceReclaim;
		private long idleDeadline = long.MaxValue;
		// The service stops after two hours without activity, counted from its start, the index build, or the last response.
		private static readonly TimeSpan IdleDelay = TimeSpan.FromHours(2);

		internal IndexState() => IdleTimer = new(static value => ((IndexState)value!).OnIdleTimerTick(),
			this, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);

		// Startup, queries and statistics share one build gate, including retries after a failed build.
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
			try { StopIfIdle(); }
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

		// The service stops itself once idle; the Top Bar starts it again when it is needed.
		private void StopIfIdle()
		{
			lock (Sync)
			{
				if (idleDeadline == long.MaxValue) return;
				long now = Stopwatch.GetTimestamp();
				if (now < idleDeadline)
				{
					// An already queued callback must not override a later query's reset.
					_ = IdleTimer.Change(Stopwatch.GetElapsedTime(now, idleDeadline), Timeout.InfiniteTimeSpan);
					return;
				}
				StopIdleTimer();
				RequestStop();
			}
		}

		public void Dispose()
		{
			lock (Sync)
			{
				StopIdleTimer();
				IdleTimer.Dispose();
				foreach (VolumeIndex index in Indexes) index.Dispose();
				Indexes.Clear();
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

	// The filter and the result limit precede the length: kind (0 files and folders, 1 files only, 2 folders only),
	// file type bits, then the 7-bit encoded result limit.
	// Reject the declared length before reading or allocating the payload. The service owns the length limit.
	private static string? ReadQuery(BinaryReader reader, BinaryWriter writer, out byte kind, out byte fileTypes, out int limit)
	{
		kind = reader.ReadByte();
		fileTypes = reader.ReadByte();
		// Folders have no file type, so a type filter is valid only when files are included.
		if (kind > 2 || (kind == 2 && fileTypes != 0)) throw new InvalidDataException("Invalid search filter.");
		limit = reader.Read7BitEncodedInt();
		if (limit < 1 || limit > Atlas.GlobalSearchMaxResultLimit) throw new InvalidDataException("Invalid search result limit.");
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

	private static void SearchIndexes(string query, byte kind, byte fileTypes, int limit, List<VolumeIndex> indexes, SearchResponse response)
	{
		response.Clear(limit);
		if (query.Length == 0) return;
		// Prepared once and shared by every volume.
		NameQuery prepared = new(query, kind, fileTypes);
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
			catch (Exception exception) when (exception is Win32Exception or IOException or UnauthorizedAccessException or NotSupportedException)
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
			byte kind;
			byte fileTypes;
			int limit;
			try { query = ReadQuery(reader, writer, out kind, out fileTypes, out limit); }
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
				state.StopIdleTimer();
				try
				{
					if (state.Unloaded && query.Length != 0)
					{
						// Notify the client before the synchronous build, including retries after a failed build.
						writer.Write((byte)5); // Indexing; the normal result frame still follows.
						writer.Flush();
						// Keep build failures distinct from ordinary client disconnects.
						buildingIndexes = true;
						state.EnsureIndexes(token);
						buildingIndexes = false;
					}
					SearchIndexes(query, kind, fileTypes, limit, state.Indexes, response);
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
