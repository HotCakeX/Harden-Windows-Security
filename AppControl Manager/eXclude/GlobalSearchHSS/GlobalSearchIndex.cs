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
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace GlobalSearchService;

internal readonly record struct NameRef(int Chunk, int Offset, int Length);

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
		int length = Encoding.Unicode.GetCharCount(bytes);
		if (length == 0) return default;
		Span<char> target = Reserve(length, out NameRef name);
		if (Encoding.Unicode.GetChars(bytes, target) != length)
			throw new InvalidDataException("Inconsistent UTF-16 filename length.");
		return name;
	}

	internal ReadOnlySpan<char> GetSpan(NameRef name) => name.Length == 0
		? ReadOnlySpan<char>.Empty
		: chunks[name.Chunk].AsSpan(name.Offset, name.Length);

}

internal readonly record struct FileId(ulong Low, ulong High);

internal readonly record struct Entry(FileId Parent, NameRef Name, bool IsDirectory);

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
	private readonly SafeFileHandle volume;
	private readonly string root;
	private readonly bool refs;
	private readonly FileId rootId;
	private readonly Dictionary<FileId, Entry> entries;
	private NameArena nameArena = new();
	private readonly HashSet<FileId> inaccessibleDirectories = [];
	private ulong journalId;
	private long nextUsn;
	private bool built;
	private byte[]? refreshBuffer;
	internal char Drive => root[0];
	// Includes indexed files and directories; reading Dictionary.Count does not scan the index.
	internal int IndexedItemCount => entries.Count;
	internal int InaccessibleDirectoryCount => inaccessibleDirectories.Count;

	internal VolumeIndex(char drive)
	{
		root = $"{drive}:\\";
		entries = [];
		byte* fsName = stackalloc byte[64];
		if (!NativeMethods.GetVolumeInformationW(root, null, 0, null, null, null, (char*)fsName, 32))
			throw Error("GetVolumeInformationW");
		string fs = new((char*)fsName);
		if (!string.Equals(fs, "NTFS", StringComparison.OrdinalIgnoreCase) &&
			!string.Equals(fs, "ReFS", StringComparison.OrdinalIgnoreCase))
			throw new NotSupportedException($"Only local NTFS and ReFS volumes are supported; found {fs}.");
		refs = string.Equals(fs, "ReFS", StringComparison.OrdinalIgnoreCase);
		volume = NativeMethods.CreateFileW_Unsafe($"\\\\.\\{drive}:", 0x80000000, 7, null, 3, 0, 0);
		if (volume.IsInvalid)
		{
			volume.Dispose();
			throw Error("Open volume (run elevated)");
		}
		try
		{
			using SafeFileHandle rootHandle = NativeMethods.CreateFileW_Unsafe(root, 0, 7, null, 3, 0x02000000, 0);
			if (rootHandle.IsInvalid) throw Error("Open volume root");
			byte* info = stackalloc byte[24];
			if (!NativeMethods.GetFileInformationByHandleEx(rootHandle, 18, info, 24)) throw Error("Get root file ID");
			rootId = new(BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(info + 8, 8)),
						 BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(info + 16, 8)));
		}
		catch
		{
			volume.Dispose();
			throw;
		}
	}

	internal void Build()
	{
		entries.Clear();
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
				if (!NativeMethods.DeviceIoControl_Safe(volume, EnumUsn, &request, (uint)sizeof(MftV0), output, BufferSize, out uint bytes, null))
				{
					int error = Marshal.GetLastPInvokeError();
					if (error == 38) break; // ERROR_HANDLE_EOF.
					throw new Win32Exception(error, $"FSCTL_ENUM_USN_DATA failed on {root}");
				}
				if (bytes < 8 || bytes > BufferSize) throw new InvalidDataException("Invalid enumeration response.");
				ulong next = BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(0, 8));
				if (next <= cursor) throw new InvalidDataException("Enumeration cursor did not advance.");
				Walk(buffer.AsSpan(8, (int)bytes - 8), UpsertUsn);
				cursor = next;
			}
		}
		return buffer;
	}

	// ReFS root-only exclusions
	private bool IsExcludedReFsRootDirectory(FileId parent, ReadOnlySpan<char> name, bool isDirectory) =>
		refs && isDirectory && parent == rootId &&
		(name.Equals("System Volume Information".AsSpan(), StringComparison.OrdinalIgnoreCase) ||
		 name.Equals("$RECYCLE.BIN".AsSpan(), StringComparison.OrdinalIgnoreCase));

	private void EnumerateReFsDirectories()
	{
		Stack<(string Path, FileId Id)> pending = new();
		pending.Push((root, rootId));
		HashSet<FileId> visited = [];
		byte[] buffer = new byte[DirectoryBufferSize];
		fixed (byte* output = buffer)
		{
			while (pending.Count != 0)
			{
				(string path, FileId parent) = pending.Pop();
				if (!visited.Add(parent)) continue;
				// The extended path prefix permits directories longer than MAX_PATH.
				using SafeFileHandle directory = NativeMethods.CreateFileW_Unsafe(@"\\?\" + path, 1, 7, null, 3, 0x02000000, 0);
				if (directory.IsInvalid)
				{
					int error = Marshal.GetLastPInvokeError();
					if (error == 5 && parent != rootId) // ERROR_ACCESS_DENIED.
					{
						_ = inaccessibleDirectories.Add(parent);
						SearchLog.ReportWarning($"Skipping inaccessible ReFS directory: {path}");
						continue;
					}
					throw new Win32Exception(error, $"Open ReFS directory {path}");
				}

				while (true)
				{
					// GetFileInformationByHandleEx does not return a byte count. Clear
					// unused space so malformed records cannot reuse old buffer contents.
					Array.Clear(buffer);
					if (!NativeMethods.GetFileInformationByHandleEx(directory, 19, output, DirectoryBufferSize))
					{
						int error = Marshal.GetLastPInvokeError();
						if (error is 18 or 38) break; // ERROR_NO_MORE_FILES / ERROR_HANDLE_EOF.
						if (error == 5 && parent != rootId) // ERROR_ACCESS_DENIED.
						{
							_ = inaccessibleDirectories.Add(parent);
							SearchLog.ReportWarning($"Skipping inaccessible ReFS directory: {path}");
							break;
						}
						throw new Win32Exception(error, $"FileIdExtdDirectoryInfo failed for {path}");
					}

					int offset = 0;
					while (true)
					{
						ReadOnlySpan<byte> remaining = buffer.AsSpan(offset);
						if (remaining.Length < 88) throw new InvalidDataException($"Truncated ReFS directory entry in {path}.");
						uint next = BinaryPrimitives.ReadUInt32LittleEndian(remaining);
						int entryLength = next == 0 ? remaining.Length : next <= remaining.Length ? (int)next : 0;
						if (entryLength < 88 || entryLength > remaining.Length)
							throw new InvalidDataException($"Invalid ReFS directory entry size in {path}.");
						ReadOnlySpan<byte> item = remaining[..entryLength];
						uint nameLength = BinaryPrimitives.ReadUInt32LittleEndian(item.Slice(60, 4));
						if ((nameLength & 1) != 0 || nameLength > item.Length - 88 || nameLength == 0)
							throw new InvalidDataException($"Invalid ReFS filename in {path}.");
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
							// Do not index or traverse the two excluded ReFS root directories.
							if (isDirectory && parent == rootId &&
							(Utf16NameEquals(nameBytes, "System Volume Information".AsSpan()) ||
							 Utf16NameEquals(nameBytes, "$RECYCLE.BIN".AsSpan())))
							{
								if (next == 0) break;
								offset += entryLength;
								continue;
							}
							SetEntry(id, parent, nameArena.AddUtf16(nameBytes), isDirectory);
							// Never traverse junctions or symlinks into another volume.
							if (isDirectory && (attributes & ReparsePointAttribute) == 0)
							{
								bool separator = !path.EndsWith('\\');
								int nameCharacters = Encoding.Unicode.GetCharCount(nameBytes);
								int childLength = checked(path.Length + (separator ? 1 : 0) + nameCharacters);
								// Decode directly into the final path; the directory name needs no separate string.
								string childPath = string.Create(childLength, (path, buffer, offset + 88, (int)nameLength, separator),
									static (Span<char> destination, (string Path, byte[] Buffer, int NameOffset, int NameBytes, bool Separator) state) =>
									{
										state.Path.AsSpan().CopyTo(destination);
										int start = state.Path.Length;
										if (state.Separator) destination[start++] = '\\';
										int written = Encoding.Unicode.GetChars(state.Buffer.AsSpan(state.NameOffset, state.NameBytes), destination[start..]);
										if (written != destination.Length - start) throw new InvalidDataException("Inconsistent ReFS filename length.");
									});
								pending.Push((childPath, id));
							}
						}
						if (next == 0) break;
						offset += entryLength;
					}
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
				if (!NativeMethods.DeviceIoControl_Safe(volume, ReadUsn, &request, (uint)sizeof(ReadV1), output, BufferSize, out uint bytes, null))
					throw Error("FSCTL_READ_USN_JOURNAL (restart to rebuild if journal was truncated)");
				if (bytes < 8 || bytes > BufferSize) throw new InvalidDataException("Invalid journal response.");
				long next = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(0, 8));
				if (next <= nextUsn) throw new InvalidDataException("Journal cursor is invalid.");
				Walk(buffer.AsSpan(8, (int)bytes - 8), ApplyUsn);
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
		HashSet<FileId>? visited = null;
		foreach (KeyValuePair<FileId, Entry> pair in entries)
		{
			if (nameArena.GetSpan(pair.Value.Name).IndexOf(query.AsSpan(), StringComparison.OrdinalIgnoreCase) < 0) continue;
			// Scratch storage belongs to this search enumeration, not the volume or other searches.
			names ??= [];
			visited ??= [];
			string? path = Resolve(pair.Key, names, visited);
			if (path is null) continue;
			yield return path;
			if (++count >= limit) yield break;
		}
	}

	private string? Resolve(FileId id, List<NameRef> names, HashSet<FileId> visited)
	{
		names.Clear();
		visited.Clear();
		while (id != rootId)
		{
			// Do not expose descendants introduced by journal replay under skipped directories.
			if (!visited.Add(id) || !entries.TryGetValue(id, out Entry entry)) return null;
			// Journal replay must not expose descendants of excluded ReFS directories.
			if (IsExcludedReFsRootDirectory(entry.Parent, nameArena.GetSpan(entry.Name), entry.IsDirectory)) return null;
			if (names.Count != 0 && inaccessibleDirectories.Contains(id)) return null;
			names.Add(entry.Name);
			id = entry.Parent;
		}
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
		// One lookup for insert or replacement. Do not retain this ref across dictionary mutations.
		ref Entry slot = ref CollectionsMarshal.GetValueRefOrAddDefault(entries, id, out bool exists);
		Entry old = slot;
		slot = new Entry(parent, name, isDirectory);
		if (exists) nameArena.Release(old.Name);
	}

	// Reclaim dictionary storage after a substantial net deletion, not on every update.
	private void TrimEntriesIfNeeded()
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
		FileId[] ids = new FileId[entries.Count];
		NameRef[] names = new NameRef[entries.Count];
		int position = 0;
		foreach (KeyValuePair<FileId, Entry> pair in entries)
		{
			ids[position] = pair.Key;
			names[position] = replacement.Add(nameArena.GetSpan(pair.Value.Name));
			position++;
		}
		// No dictionary enumeration is active during value replacement.
		for (int i = 0; i < position; i++)
		{
			Entry old = entries[ids[i]];
			entries[ids[i]] = old with { Name = names[i] };
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
	private static bool Utf16NameEquals(ReadOnlySpan<byte> nameBytes, ReadOnlySpan<char> expected)
	{
		int length = Encoding.Unicode.GetCharCount(nameBytes);
		if (length != expected.Length) return false;
		Span<char> decoded = length <= 256 ? stackalloc char[length] : new char[length];
		if (Encoding.Unicode.GetChars(nameBytes, decoded) != length)
			throw new InvalidDataException("Inconsistent UTF-16 filename length.");
		return decoded.Equals(expected, StringComparison.OrdinalIgnoreCase);
	}

	private void ApplyUsn(FileId id, FileId parent, ReadOnlySpan<byte> nameBytes, bool isDirectory, uint reason)
	{
		if (id == rootId) return;
		if ((reason & (FileDelete | RenameOldName)) != 0)
		{
			if (entries.TryGetValue(id, out Entry old) &&
				old.Parent == parent && Utf16NameEquals(nameBytes, nameArena.GetSpan(old.Name)) &&
				entries.Remove(id))
				nameArena.Release(old.Name);
		}
		else if ((reason & RenameNewName) != 0 || !entries.TryGetValue(id, out Entry old))
		{
			// Only ReFS root directories need a name comparison before insertion.
			if (refs && isDirectory && parent == rootId &&
				(Utf16NameEquals(nameBytes, "System Volume Information".AsSpan()) ||
				 Utf16NameEquals(nameBytes, "$RECYCLE.BIN".AsSpan())))
			{
				if (entries.Remove(id, out Entry removed)) nameArena.Release(removed.Name);
				return;
			}
			SetEntry(id, parent, nameArena.AddUtf16(nameBytes), isDirectory);
		}
		else
		{
			entries[id] = old with { IsDirectory = isDirectory };
		}
	}

	private Journal QueryJournal()
	{
		byte* output = stackalloc byte[80];
		if (!NativeMethods.DeviceIoControl_Safe(volume, QueryUsn, null, 0, output, 80, out uint bytes, null))
			throw Error("FSCTL_QUERY_USN_JOURNAL (journal must already exist)");
		if (bytes < 56) throw new InvalidDataException("Invalid USN journal metadata.");
		ReadOnlySpan<byte> data = new(output, (int)bytes);
		return new(BinaryPrimitives.ReadUInt64LittleEndian(data[..8]),
				   BinaryPrimitives.ReadInt64LittleEndian(data.Slice(8, 8)),
				   BinaryPrimitives.ReadInt64LittleEndian(data.Slice(16, 8)));
	}

	private delegate void UsnVisitor(FileId id, FileId parent, ReadOnlySpan<byte> nameBytes, bool isDirectory, uint reason);

	private static void Walk(ReadOnlySpan<byte> buffer, UsnVisitor accept)
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
			accept(id, parent, item.Slice(nameOffset, nameLength),
				(attributes & DirectoryAttribute) != 0, reason);
			buffer = buffer[(int)length..];
		}
	}

	private static FileId ReadId(ReadOnlySpan<byte> bytes, int offset, ushort version) =>
		new(BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(offset, 8)),
			version == 3 ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(offset + 8, 8)) : 0);

	private static Win32Exception Error(string operation) => new(Marshal.GetLastPInvokeError(), operation);
	public void Dispose() => volume.Dispose();
}
