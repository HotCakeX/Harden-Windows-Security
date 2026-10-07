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
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace GlobalSearchService;

internal readonly record struct NameRef
{
	private const ulong DirectoryMask = 1UL << 63;
	private const ulong ChunkMask = 0x7FFFFFFFUL;
	private readonly ulong value;

	internal int Chunk => (int)((value >> 32) & ChunkMask);
	internal int Offset => (int)((value >> 16) & ushort.MaxValue);
	internal int Length => (int)(value & ushort.MaxValue);
	internal bool IsDirectory => (value & DirectoryMask) != 0;

	internal NameRef(int chunk, int offset, int length)
	{
		if (chunk < 0 || (uint)offset > ushort.MaxValue || (uint)length > ushort.MaxValue)
			throw new ArgumentOutOfRangeException(nameof(length), "The name location exceeds its packed representation.");

		value = ((ulong)(uint)chunk << 32) | ((ulong)(uint)offset << 16) | (uint)length;
	}

	private NameRef(ulong value) => this.value = value;

	internal NameRef WithDirectory(bool isDirectory) => new(isDirectory ? value | DirectoryMask : value & ~DirectoryMask);
}

// Own stable chunks instead of retaining pointers into reusable enumeration buffers.
internal sealed class NameArena
{
	private const int ChunkSize = 64 * 1024;
	private readonly List<char[]> chunks = [];
	private readonly Dictionary<int, Stack<NameRef>> freeSlots = [];
	private int used;
	private long writtenCharacters;
	private long liveCharacters;

	// Compact only after enough dead space accumulates to justify a full copy.
	internal bool NeedsCompaction =>
		writtenCharacters - liveCharacters >= 8L * 1024 * 1024 &&
		writtenCharacters - liveCharacters >= liveCharacters / 4;

	internal void Clear()
	{
		chunks.Clear();
		freeSlots.Clear();
		used = 0;
		writtenCharacters = 0;
		liveCharacters = 0;
	}

	private Span<char> Reserve(int length, out NameRef name)
	{
		// Reuse an exact-length slot; references to other names remain stable.
		if (freeSlots.TryGetValue(length, out Stack<NameRef>? slots) && slots.Count != 0)
		{
			name = slots.Pop();
			liveCharacters += length;
			return chunks[name.Chunk].AsSpan(name.Offset, length);
		}
		if (chunks.Count == 0 || chunks[^1].Length - used < length)
		{
			int size = Math.Max(ChunkSize, length);
			chunks.Add(new char[size]);
			used = 0;
		}
		name = new(chunks.Count - 1, used, length);
		Span<char> target = chunks[^1].AsSpan(used, length);
		used += length;
		writtenCharacters += length;
		liveCharacters += length;
		return target;
	}

	// Called only after an entry stops referencing its old name.
	internal void Release(NameRef name)
	{
		if (name.Length == 0) return;
		if (!freeSlots.TryGetValue(name.Length, out Stack<NameRef>? slots))
		{
			slots = new Stack<NameRef>();
			freeSlots.Add(name.Length, slots);
		}
		slots.Push(name);
		liveCharacters -= name.Length;
	}

	internal NameRef Add(ReadOnlySpan<char> text)
	{
		if (text.IsEmpty) return default;
		Span<char> target = Reserve(text.Length, out NameRef name);
		text.CopyTo(target);
		return name;
	}

	internal NameRef AddUtf16(ReadOnlySpan<byte> bytes)
	{
		if (bytes.IsEmpty) return default;
		// Callers validate that Windows filename bytes contain complete UTF-16LE code units.
		ReadOnlySpan<char> characters = MemoryMarshal.Cast<byte, char>(bytes);
		Span<char> target = Reserve(characters.Length, out NameRef name);
		characters.CopyTo(target);
		return name;
	}

	internal ReadOnlySpan<char> GetSpan(NameRef name) => name.Length == 0
		? ReadOnlySpan<char>.Empty
		: chunks[name.Chunk].AsSpan(name.Offset, name.Length);
}

internal readonly record struct FileId(ulong Low, ulong High);

internal readonly record struct Entry(FileId Parent, NameRef Name);
internal readonly record struct NtfsEntry(ulong Parent, NameRef Name);

internal readonly record struct Journal(ulong Id, long First, long Next);

internal sealed unsafe class VolumeIndex : IDisposable
{
	private const int BufferSize = 1024 * 1024;
	private const int DirectoryBufferSize = 64 * 1024;
	private const uint ReparsePointAttribute = 0x00000400;
	private const uint EnumUsn = 0x000900B3;
	private const uint ReadUsn = 0x000900BB;
	private const uint QueryUsn = 0x000900F4;
	private const uint FileDelete = 0x00000200;
	private const uint RenameOldName = 0x00001000;
	private const uint RenameNewName = 0x00002000;
	private const uint DirectoryAttribute = 0x00000010;
	private static readonly nint InvalidHandleValue = -1;
	private nint volume;
	private bool disposed;
	private readonly string root;
	private readonly bool refs;
	private readonly FileId rootId;
	private Dictionary<FileId, Entry>? wideEntries;
	private Dictionary<ulong, NtfsEntry>? ntfsEntries;
	private NameArena nameArena = new();
	private readonly HashSet<FileId> inaccessibleDirectories = [];
	private ulong journalId;
	private long nextUsn;
	private bool built;
	private byte[]? refreshBuffer;
	internal char Drive => root[0];
	// Includes indexed files and directories; reading Dictionary.Count does not scan the index.
	internal int IndexedItemCount => wideEntries?.Count ?? ntfsEntries!.Count;
	internal int InaccessibleDirectoryCount => inaccessibleDirectories.Count;

	internal VolumeIndex(char drive)
	{
		root = $"{drive}:\\";
		byte* fsName = stackalloc byte[64];
		if (!NativeMethods.GetVolumeInformationW(root, null, 0, null, null, null, (char*)fsName, 32))
			throw Error("GetVolumeInformationW");
		string fs = new((char*)fsName);
		if (!string.Equals(fs, "NTFS", StringComparison.OrdinalIgnoreCase) &&
			!string.Equals(fs, "ReFS", StringComparison.OrdinalIgnoreCase))
			throw new NotSupportedException($"Only local NTFS and ReFS volumes are supported; found {fs}.");
		refs = string.Equals(fs, "ReFS", StringComparison.OrdinalIgnoreCase);
		if (refs) wideEntries = [];
		else ntfsEntries = [];
		volume = NativeMethods.CreateFileW($"\\\\.\\{drive}:", 0x80000000, 7, IntPtr.Zero, 3, 0, IntPtr.Zero);
		if (volume == 0 || volume == InvalidHandleValue) throw Error("Open volume (run elevated)");
		try
		{
			nint rootHandle = NativeMethods.CreateFileW(root, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
			if (rootHandle == 0 || rootHandle == InvalidHandleValue) throw Error("Open volume root");
			try
			{
				byte* info = stackalloc byte[24];
				if (!NativeMethods.GetFileInformationByHandleEx(rootHandle, 18, info, 24)) throw Error("Get root file ID");
				rootId = new(BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(info + 8, 8)),
							 BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(info + 16, 8)));
			}
			finally
			{
				_ = NativeMethods.CloseHandle(rootHandle);
			}
		}
		catch
		{
			_ = NativeMethods.CloseHandle(volume);
			volume = InvalidHandleValue;
			throw;
		}
	}

	internal void Build()
	{
		wideEntries?.Clear();
		ntfsEntries?.Clear();
		nameArena.Clear();
		inaccessibleDirectories.Clear();
		built = false;
		Journal start = QueryJournal();
		byte[]? enumerationBuffer = null;
		if (refs)
		{
			// ReFS MFT_ENUM_DATA_V1 is not supported on Windows clients. Enumerate
			// directory entries in batches instead, preserving their 128-bit file IDs.
			EnumerateReFsDirectories();
		}
		else
		{
			enumerationBuffer = EnumerateNtfs(start.Next);
		}
		journalId = start.Id;
		nextUsn = start.Next;
		Refresh(enumerationBuffer); // Replay changes that happened while enumerating.
		CompactNamesIfNeeded();
		built = true;
	}

	private byte[] EnumerateNtfs(long highUsn)
	{
		byte[] buffer = new byte[BufferSize];
		ulong cursor = 0;
		fixed (byte* output = buffer)
		{
			while (true)
			{
				MftV0 request = new() { Start = cursor, Low = 0, High = highUsn };
				uint bytes = 0;
				if (!NativeMethods.DeviceIoControl(volume, EnumUsn, &request, (uint)sizeof(MftV0), output, BufferSize, ref bytes, IntPtr.Zero))
				{
					int error = Marshal.GetLastPInvokeError();
					if (error == 38) break; // ERROR_HANDLE_EOF.
					throw new Win32Exception(error, $"FSCTL_ENUM_USN_DATA failed on {root}");
				}
				if (bytes < 8 || bytes > BufferSize) throw new InvalidDataException("Invalid enumeration response.");
				ulong next = BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(0, 8));
				if (next <= cursor) throw new InvalidDataException("Enumeration cursor did not advance.");
				Walk(buffer.AsSpan(8, (int)bytes - 8), initialEnumeration: true);
				cursor = next;
			}
		}
		return buffer;
	}

	// Skip object-scoped failures for non-root ReFS directories without discarding the volume index.
	// 2: file not found
	// 3: path not found
	// 5: access denied
	// 32: sharing violation
	// 303: delete pending
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool IsSkippableReFsDirectoryError(int error) => error is 2 or 3 or 5 or 32 or 303;

	private void EnumerateReFsDirectories()
	{
		// Queue IDs only.
		Stack<FileId> pending = new();
		pending.Push(rootId);
		HashSet<FileId> visited = [];
		byte[] buffer = new byte[DirectoryBufferSize];
		fixed (byte* output = buffer)
		{
			while (pending.Count != 0)
			{
				FileId parent = pending.Pop();
				if (!visited.Add(parent)) continue;
				// ExtendedFileIdType preserves all 128 bits of the ReFS identifier.
				FILE_ID_DESCRIPTOR descriptor = new()
				{
					dwSize = (uint)sizeof(FILE_ID_DESCRIPTOR),
					Type = FILE_ID_TYPE.ExtendedFileIdType,
					ExtendedFileIdLow = parent.Low,
					ExtendedFileIdHigh = parent.High
				};
				nint directory = NativeMethods.OpenFileById(volume, &descriptor, 1, 7, null, 0x02000000);
				if (directory == 0 || directory == InvalidHandleValue)
				{
					int error = Marshal.GetLastPInvokeError();
					if (parent != rootId && IsSkippableReFsDirectoryError(error))
					{
						_ = inaccessibleDirectories.Add(parent);
						// SearchLog.ReportWarning($"Skipping inaccessible ReFS directory: {root} file ID {parent.High:X16}{parent.Low:X16}");
						continue;
					}
					throw new Win32Exception(error, $"Open ReFS directory {root} file ID {parent.High:X16}{parent.Low:X16}");
				}

				try
				{
					while (true)
					{
						if (!NativeMethods.GetFileInformationByHandleEx(directory, 19, output, DirectoryBufferSize))
						{
							int error = Marshal.GetLastPInvokeError();
							if (error is 18 or 38) break; // ERROR_NO_MORE_FILES / ERROR_HANDLE_EOF.
							if (parent != rootId && IsSkippableReFsDirectoryError(error))
							{
								_ = inaccessibleDirectories.Add(parent);
								// SearchLog.ReportWarning($"Skipping inaccessible ReFS directory: {root} file ID {parent.High:X16}{parent.Low:X16}");
								break;
							}
							throw new Win32Exception(error, $"FileIdExtdDirectoryInfo failed for {root} file ID {parent.High:X16}{parent.Low:X16}");
						}

						int offset = 0;
						while (true)
						{
							ReadOnlySpan<byte> remaining = buffer.AsSpan(offset);
							if (remaining.Length < 88) throw new InvalidDataException($"Truncated ReFS directory entry in {root} file ID {parent.High:X16}{parent.Low:X16}.");
							uint next = BinaryPrimitives.ReadUInt32LittleEndian(remaining);
							uint nameLength = BinaryPrimitives.ReadUInt32LittleEndian(remaining.Slice(60, 4));
							if ((nameLength & 1) != 0 || nameLength == 0 || nameLength > remaining.Length - 88)
								throw new InvalidDataException($"Invalid ReFS filename in {root} file ID {parent.High:X16}{parent.Low:X16}.");
							int requiredLength = 88 + (int)nameLength;
							if (next != 0 && ((next & 7) != 0 || next < requiredLength || next > remaining.Length))
								throw new InvalidDataException($"Invalid ReFS directory entry size in {root} file ID {parent.High:X16}{parent.Low:X16}.");
							int entryLength = next == 0 ? requiredLength : (int)next;
							ReadOnlySpan<byte> item = remaining[..entryLength];
							ReadOnlySpan<byte> nameBytes = item.Slice(88, (int)nameLength);
							// Dot entries have fixed UTF-16 bytes; no string is needed to reject them.
							if (!(nameBytes.Length == 2 && nameBytes[0] == (byte)'.' && nameBytes[1] == 0) &&
								!(nameBytes.Length == 4 && nameBytes[0] == (byte)'.' && nameBytes[1] == 0 &&
								  nameBytes[2] == (byte)'.' && nameBytes[3] == 0))
							{
								FileId id = new(BinaryPrimitives.ReadUInt64LittleEndian(item.Slice(72, 8)),
												BinaryPrimitives.ReadUInt64LittleEndian(item.Slice(80, 8)));
								uint attributes = BinaryPrimitives.ReadUInt32LittleEndian(item.Slice(56, 4));
								bool isDirectory = (attributes & DirectoryAttribute) != 0;
								SetEntry(id, parent, nameArena.AddUtf16(nameBytes), isDirectory);
								// Never traverse junctions or symlinks into another volume.
								if (isDirectory && (attributes & ReparsePointAttribute) == 0)
								{
									pending.Push(id);
								}
							}
							if (next == 0) break;
							offset += entryLength;
						}
					}
				}
				finally
				{
					_ = NativeMethods.CloseHandle(directory);
				}
			}
		}
	}

	internal void Refresh(byte[]? enumerationBuffer = null)
	{
		Journal current = QueryJournal();
		if (current.Id != journalId || nextUsn < current.First || nextUsn > current.Next)
			throw new IOException("USN journal changed or lost records. Restart to rebuild the index.");
		if (nextUsn == current.Next) return;
		// Allocate only when there are changes, then reuse this volume's buffer on later refreshes.
		// Reuse the NTFS enumeration buffer for the initial catch-up, then retain it for later reads.
		byte[] buffer = refreshBuffer ??= enumerationBuffer ?? new byte[BufferSize];
		fixed (byte* output = buffer)
		{
			while (nextUsn < current.Next)
			{
				ReadV1 request = new() { Start = nextUsn, ReasonMask = uint.MaxValue, JournalId = journalId, Min = 2, Max = 3 };
				uint bytes = 0;
				if (!NativeMethods.DeviceIoControl(volume, ReadUsn, &request, (uint)sizeof(ReadV1), output, BufferSize, ref bytes, IntPtr.Zero))
					throw Error("FSCTL_READ_USN_JOURNAL (restart to rebuild if journal was truncated)");
				if (bytes < 8 || bytes > BufferSize) throw new InvalidDataException("Invalid journal response.");
				long next = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(0, 8));
				if (next <= nextUsn) throw new InvalidDataException("Journal cursor is invalid.");
				Walk(buffer.AsSpan(8, (int)bytes - 8), initialEnumeration: false);
				nextUsn = next;
				CompactNamesIfNeeded();
				TrimEntriesIfNeeded();
			}
		}
	}

	internal IEnumerable<string> Search(string query, int limit)
	{
		if (!built) throw new InvalidOperationException("Build the index first.");
		int count = 0;
		List<NameRef>? names = null;
		if (wideEntries is not null)
		{
			HashSet<FileId>? visited = null;
			foreach (KeyValuePair<FileId, Entry> pair in wideEntries)
			{
				if (nameArena.GetSpan(pair.Value.Name).IndexOf(query.AsSpan(), StringComparison.OrdinalIgnoreCase) < 0) continue;
				// Scratch storage belongs to this search enumeration, not the volume or other searches.
				names ??= [];
				visited ??= [];
				string? path = ResolveWide(pair.Key, names, visited);
				if (path is null) continue;
				yield return path;
				if (++count >= limit) yield break;
			}
		}
		else
		{
			HashSet<ulong>? visited = null;
			foreach (KeyValuePair<ulong, NtfsEntry> pair in ntfsEntries!)
			{
				if (nameArena.GetSpan(pair.Value.Name).IndexOf(query.AsSpan(), StringComparison.OrdinalIgnoreCase) < 0) continue;
				names ??= [];
				visited ??= [];
				string? path = ResolveNtfs(pair.Key, names, visited);
				if (path is null) continue;
				yield return path;
				if (++count >= limit) yield break;
			}
		}
	}

	private string? ResolveWide(FileId id, List<NameRef> names, HashSet<FileId> visited)
	{
		names.Clear();
		visited.Clear();
		while (id != rootId)
		{
			// Do not expose descendants introduced by journal replay under skipped directories.
			if (!visited.Add(id) || !wideEntries!.TryGetValue(id, out Entry entry)) return null;
			if (names.Count != 0 && inaccessibleDirectories.Contains(id)) return null;
			names.Add(entry.Name);
			id = entry.Parent;
		}
		return CreatePath(names);
	}

	private string? ResolveNtfs(ulong id, List<NameRef> names, HashSet<ulong> visited)
	{
		names.Clear();
		visited.Clear();
		while (id != rootId.Low)
		{
			if (!visited.Add(id) || !ntfsEntries!.TryGetValue(id, out NtfsEntry entry)) return null;
			names.Add(entry.Name);
			id = entry.Parent;
		}
		return CreatePath(names);
	}

	private string CreatePath(List<NameRef> names)
	{
		if (names.Count == 0) return root;
		int length = checked(root.Length + names.Count - 1);
		foreach (NameRef name in names) length = checked(length + name.Length);
		// Write the root and reverse-ordered components directly into the final string.
		return string.Create(length, (root, names, nameArena), static (Span<char> destination, (string Root, List<NameRef> Names, NameArena Arena) state) =>
		{
			state.Root.AsSpan().CopyTo(destination);
			int offset = state.Root.Length;
			for (int i = state.Names.Count - 1; i >= 0; i--)
			{
				ReadOnlySpan<char> component = state.Arena.GetSpan(state.Names[i]);
				component.CopyTo(destination[offset..]);
				offset += component.Length;
				if (i != 0) destination[offset++] = '\\';
			}
		});
	}

	// Build the replacement before releasing the old slot so it cannot be reused prematurely.
	private void SetEntry(FileId id, FileId parent, NameRef name, bool isDirectory)
	{
		if (wideEntries is not null)
		{
			// One lookup for insert or replacement. Do not retain this ref across dictionary mutations.
			ref Entry slot = ref CollectionsMarshal.GetValueRefOrAddDefault(wideEntries, id, out bool exists);
			Entry old = slot;
			slot = new Entry(parent, name.WithDirectory(isDirectory));
			if (exists) nameArena.Release(old.Name);
			return;
		}
		if ((id.High | parent.High) != 0)
		{
			PromoteNtfsToWideIds();
			SetEntry(id, parent, name, isDirectory);
			return;
		}
		Dictionary<ulong, NtfsEntry> entries = ntfsEntries!;
		// One lookup for insert or replacement. Do not retain this ref across dictionary mutations.
		ref NtfsEntry ntfsSlot = ref CollectionsMarshal.GetValueRefOrAddDefault(entries, id.Low, out bool ntfsExists);
		NtfsEntry ntfsOld = ntfsSlot;
		ntfsSlot = new NtfsEntry(parent.Low, name.WithDirectory(isDirectory));
		if (ntfsExists) nameArena.Release(ntfsOld.Name);
	}

	// Preserve full V3 identifiers if NTFS ever returns a nonzero high half.
	private void PromoteNtfsToWideIds()
	{
		Dictionary<ulong, NtfsEntry> source = ntfsEntries!;
		Dictionary<FileId, Entry> replacement = new(source.Count);
		foreach (KeyValuePair<ulong, NtfsEntry> pair in source)
		{
			NtfsEntry value = pair.Value;
			replacement.Add(new FileId(pair.Key, 0), new Entry(new FileId(value.Parent, 0), value.Name));
		}
		wideEntries = replacement;
		ntfsEntries = null;
	}

	// Reclaim dictionary storage after a substantial net deletion, not on every update.
	private void TrimEntriesIfNeeded()
	{
		if (wideEntries is not null) TrimEntriesIfNeeded(wideEntries);
		else TrimEntriesIfNeeded(ntfsEntries!);
	}

	private static void TrimEntriesIfNeeded<TKey, TValue>(Dictionary<TKey, TValue> entries) where TKey : notnull
	{
		int capacity = entries.EnsureCapacity(0);
		int count = entries.Count;
		if (capacity - count < 100_000 || count > capacity / 2) return;
		// Keep 25% headroom so ordinary journal additions do not immediately regrow it.
		entries.TrimExcess(count + count / 4);
	}

	// Copy only referenced names, then update values in place to preserve dictionary order.
	private void CompactNamesIfNeeded()
	{
		if (!nameArena.NeedsCompaction) return;
		NameArena replacement = new();
		if (wideEntries is not null)
		{
			FileId[] ids = new FileId[wideEntries.Count];
			int position = 0;
			foreach (FileId id in wideEntries.Keys) ids[position++] = id;
			// No dictionary enumeration or structural mutation is active while value references are used.
			for (int i = 0; i < position; i++)
			{
				ref Entry slot = ref CollectionsMarshal.GetValueRefOrNullRef(wideEntries, ids[i]);
				NameRef name = replacement.Add(nameArena.GetSpan(slot.Name)).WithDirectory(slot.Name.IsDirectory);
				slot = slot with { Name = name };
			}
		}
		else
		{
			Dictionary<ulong, NtfsEntry> entries = ntfsEntries!;
			ulong[] ids = new ulong[entries.Count];
			int position = 0;
			foreach (ulong id in entries.Keys) ids[position++] = id;
			// No dictionary enumeration or structural mutation is active while value references are used.
			for (int i = 0; i < position; i++)
			{
				ref NtfsEntry slot = ref CollectionsMarshal.GetValueRefOrNullRef(entries, ids[i]);
				NameRef name = replacement.Add(nameArena.GetSpan(slot.Name)).WithDirectory(slot.Name.IsDirectory);
				slot = slot with { Name = name };
			}
		}
		nameArena = replacement;
	}

	private void UpsertUsn(FileId id, FileId parent, ReadOnlySpan<byte> nameBytes, bool isDirectory, uint reason)
	{
		if (id == rootId) return;
		// This path is used only for NTFS initial enumeration.
		SetEntry(id, parent, nameArena.AddUtf16(nameBytes), isDirectory);
	}

	// Compare only the names needed by a journal operation.
	private static bool Utf16NameEquals(ReadOnlySpan<byte> nameBytes, ReadOnlySpan<char> expected) =>
		MemoryMarshal.Cast<byte, char>(nameBytes).Equals(expected, StringComparison.OrdinalIgnoreCase);

	private void ApplyUsn(FileId id, FileId parent, ReadOnlySpan<byte> nameBytes, bool isDirectory, uint reason)
	{
		if (id == rootId) return;
		if (wideEntries is null && (id.High | parent.High) != 0) PromoteNtfsToWideIds();
		if (wideEntries is not null) ApplyWideUsn(id, parent, nameBytes, isDirectory, reason);
		else ApplyNtfsUsn(id.Low, parent.Low, nameBytes, isDirectory, reason);
	}

	private void ApplyWideUsn(FileId id, FileId parent, ReadOnlySpan<byte> nameBytes, bool isDirectory, uint reason)
	{
		Dictionary<FileId, Entry> entries = wideEntries!;
		if ((reason & (FileDelete | RenameOldName)) != 0)
		{
			if (entries.TryGetValue(id, out Entry old) && old.Parent == parent &&
				Utf16NameEquals(nameBytes, nameArena.GetSpan(old.Name)) && entries.Remove(id)) nameArena.Release(old.Name);
		}
		else if ((reason & RenameNewName) != 0 || !entries.TryGetValue(id, out Entry old))
		{
			SetEntry(id, parent, nameArena.AddUtf16(nameBytes), isDirectory);
		}
		else entries[id] = old with { Name = old.Name.WithDirectory(isDirectory) };
	}

	private void ApplyNtfsUsn(ulong id, ulong parent, ReadOnlySpan<byte> nameBytes, bool isDirectory, uint reason)
	{
		Dictionary<ulong, NtfsEntry> entries = ntfsEntries!;
		if ((reason & (FileDelete | RenameOldName)) != 0)
		{
			if (entries.TryGetValue(id, out NtfsEntry old) && old.Parent == parent &&
				Utf16NameEquals(nameBytes, nameArena.GetSpan(old.Name)) && entries.Remove(id)) nameArena.Release(old.Name);
		}
		else if ((reason & RenameNewName) != 0 || !entries.TryGetValue(id, out NtfsEntry old))
		{
			SetEntry(new FileId(id, 0), new FileId(parent, 0), nameArena.AddUtf16(nameBytes), isDirectory);
		}
		else entries[id] = old with { Name = old.Name.WithDirectory(isDirectory) };
	}

	private Journal QueryJournal()
	{
		byte* output = stackalloc byte[80];
		uint bytes = 0;
		if (!NativeMethods.DeviceIoControl(volume, QueryUsn, null, 0, output, 80, ref bytes, IntPtr.Zero))
			throw Error("FSCTL_QUERY_USN_JOURNAL (journal must already exist)");
		if (bytes < 56) throw new InvalidDataException("Invalid USN journal metadata.");
		ReadOnlySpan<byte> data = new(output, (int)bytes);
		return new(BinaryPrimitives.ReadUInt64LittleEndian(data[..8]),
				   BinaryPrimitives.ReadInt64LittleEndian(data.Slice(8, 8)),
				   BinaryPrimitives.ReadInt64LittleEndian(data.Slice(16, 8)));
	}

	private void Walk(ReadOnlySpan<byte> buffer, bool initialEnumeration)
	{
		while (!buffer.IsEmpty)
		{
			if (buffer.Length < 8) throw new InvalidDataException("Truncated USN record header.");
			uint length = BinaryPrimitives.ReadUInt32LittleEndian(buffer);
			ushort version = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(4, 2));
			int minimum = version switch { 2 => 60, 3 => 76, _ => throw new NotSupportedException($"Unsupported USN record version {version}.") };
			if (length < minimum || length > buffer.Length) throw new InvalidDataException("Invalid USN record length.");
			ReadOnlySpan<byte> item = buffer[..(int)length];
			int nameLengthOffset = version == 2 ? 56 : 72;
			int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(item.Slice(nameLengthOffset, 2));
			int nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(item.Slice(nameLengthOffset + 2, 2));
			if (nameOffset < minimum || (nameLength & 1) != 0 || nameOffset > item.Length || nameLength > item.Length - nameOffset)
				throw new InvalidDataException("Invalid USN filename bounds.");
			FileId id = ReadId(item, 8, version);
			FileId parent = ReadId(item, version == 2 ? 16 : 24, version);
			int reasonOffset = version == 2 ? 40 : 56;
			uint reason = BinaryPrimitives.ReadUInt32LittleEndian(item.Slice(reasonOffset, 4));
			uint attributes = BinaryPrimitives.ReadUInt32LittleEndian(item.Slice(reasonOffset + 12, 4));
			ReadOnlySpan<byte> nameBytes = item.Slice(nameOffset, nameLength);
			bool isDirectory = (attributes & DirectoryAttribute) != 0;
			if (initialEnumeration) UpsertUsn(id, parent, nameBytes, isDirectory, reason);
			else ApplyUsn(id, parent, nameBytes, isDirectory, reason);
			buffer = buffer[(int)length..];
		}
	}

	private static FileId ReadId(ReadOnlySpan<byte> bytes, int offset, ushort version) =>
		new(BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(offset, 8)),
			version == 3 ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(offset + 8, 8)) : 0);

	private static Win32Exception Error(string operation) => new(Marshal.GetLastPInvokeError(), operation);

	public void Dispose()
	{
		if (disposed) return;
		disposed = true;
		if (volume == 0 || volume == InvalidHandleValue) return;
		_ = NativeMethods.CloseHandle(volume);
		volume = InvalidHandleValue;
	}
}
