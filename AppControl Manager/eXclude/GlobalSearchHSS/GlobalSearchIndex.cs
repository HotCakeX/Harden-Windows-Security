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
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Text;
using System.Threading;

namespace GlobalSearchService;

// A 4-byte name reference. The name's length and encoding are stored with the name in its arena.
internal readonly record struct NameRef
{
	private const uint DirectoryMask = 1U << 31;
	private readonly uint value;

	// Offset of the name's header in its arena, in 2-byte units. Position 0 is the shared empty name.
	internal uint Position => value & ~DirectoryMask;
	internal bool IsDirectory => (value & DirectoryMask) != 0;

	// The arena keeps every position below 2^31.
	internal NameRef(uint position, bool isDirectory) => value = position | (isDirectory ? DirectoryMask : 0);

	internal NameRef WithDirectory(bool isDirectory) => new(Position, isDirectory);
}

// A search query prepared once per search instead of once per compared name.
internal sealed class NameQuery
{
	internal readonly string Text;
	// Only an ASCII-only query can match an ASCII-only name: under OrdinalIgnoreCase,
	// no non-ASCII UTF-16 code unit compares equal to an ASCII code unit.
	internal readonly bool IsAscii;
	// Lowercase ASCII bytes of the query, and an OR mask that is 0x20 for letters and 0 otherwise.
	// For a letter, (b | 0x20) == lower accepts exactly its two ASCII cases; other bytes compare exactly.
	private readonly byte[] lower;
	private readonly byte[] caseMask;
	// The first and last query bytes broadcast to every lane, so 16 candidate start positions are filtered per step.
	private readonly Vector128<byte> firstLower;
	private readonly Vector128<byte> firstMask;
	private readonly Vector128<byte> lastLower;
	private readonly Vector128<byte> lastMask;
	// The kind filter, read from the entry's directory bit before its name is compared.
	internal readonly bool IncludeFiles;
	internal readonly bool IncludeFolders;
	// Bit i accepts files of statistics category i; 0 accepts every file.
	internal readonly byte FileTypes;
	internal int Length => Text.Length;

	// The text must not be empty; the service never searches for an empty query.
	// Kind 0 accepts files and folders, 1 files only and 2 folders only. Folders have no file type,
	// so a file type filter accepts files only.
	internal NameQuery(string text, byte kind, byte fileTypes)
	{
		Text = text;
		IncludeFiles = kind != 2;
		IncludeFolders = kind != 1 && fileTypes == 0;
		FileTypes = fileTypes;
		IsAscii = Ascii.IsValid(text);
		if (!IsAscii)
		{
			lower = [];
			caseMask = [];
			return;
		}
		lower = new byte[text.Length];
		caseMask = new byte[text.Length];
		_ = Ascii.ToLower(text, lower, out _);
		for (int i = 0; i < lower.Length; i++)
			caseMask[i] = char.IsAsciiLetterLower((char)lower[i]) ? (byte)0x20 : (byte)0;
		firstLower = Vector128.Create(lower[0]);
		firstMask = Vector128.Create(caseMask[0]);
		lastLower = Vector128.Create(lower[^1]);
		lastMask = Vector128.Create(caseMask[^1]);
	}

	// ASCII case-insensitive substring search. Equivalent to an OrdinalIgnoreCase IndexOf when both
	// the name and the query are ASCII-only. The name is the first nameLength bytes of source; the bytes
	// after it are only read as vector padding and never affect the result.
	// The caller guarantees nameLength >= Length > 0, and that source holds Vector128<byte>.Count bytes after the
	// name, so both vectors of every candidate start position are in bounds and no scalar tail is needed.
	internal bool MatchesAscii(ReadOnlySpan<byte> source, int nameLength)
	{
		byte[] lowerQuery = lower;
		int queryLength = lowerQuery.Length;
		int candidates = nameLength - queryLength + 1;
		int start = 0;
		// Each step tests 16 start positions: the first query byte at start and the last at start + queryLength - 1.
		while (start < candidates)
		{
			Vector128<byte> first = Vector128.Create(source.Slice(start, Vector128<byte>.Count));
			Vector128<byte> last = Vector128.Create(source.Slice(start + queryLength - 1, Vector128<byte>.Count));
			uint bits = (Vector128.Equals(first | firstMask, firstLower) & Vector128.Equals(last | lastMask, lastLower)).ExtractMostSignificantBits();
			int remaining = candidates - start;
			// Discard start positions that are past the end of the name.
			if (remaining < Vector128<byte>.Count) bits &= (1U << remaining) - 1;
			while (bits != 0)
			{
				if (MiddleMatches(source, start + BitOperations.TrailingZeroCount(bits))) return true;
				bits &= bits - 1;
			}
			start += Vector128<byte>.Count;
		}
		return false;
	}

	// Compares the query bytes between the first and the last one, which the caller has already compared.
	private bool MiddleMatches(ReadOnlySpan<byte> source, int start)
	{
		byte[] lowerQuery = lower;
		byte[] mask = caseMask;
		ReadOnlySpan<byte> window = source.Slice(start, lowerQuery.Length);
		for (int i = 1; i < lowerQuery.Length - 1; i++)
		{
			if ((window[i] | mask[i]) != lowerQuery[i]) return false;
		}
		return true;
	}
}

// Index memory outside the GC heap. The collector never scans or copies it, nothing waits for a collection to be
// freed, and each release returns the memory to Windows at once. Committed memory reads as zero until written.
internal static unsafe class IndexMemory
{
	private const uint MEM_COMMIT = 0x00001000;
	private const uint MEM_RESERVE = 0x00002000;
	private const uint MEM_RELEASE = 0x00008000;
	private const uint PAGE_NOACCESS = 0x01;
	private const uint PAGE_READWRITE = 0x04;

	// Reserves and commits a zero-filled range.
	internal static void* Allocate(nuint size) => Check(NativeMethods.VirtualAlloc(null, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), "VirtualAlloc");

	// Reserves address space only; Commit makes parts of it usable.
	internal static void* Reserve(nuint size) => Check(NativeMethods.VirtualAlloc(null, size, MEM_RESERVE, PAGE_NOACCESS), "VirtualAlloc reserve");

	internal static void Commit(void* address, nuint size) => _ = Check(NativeMethods.VirtualAlloc(address, size, MEM_COMMIT, PAGE_READWRITE), "VirtualAlloc commit");

	// Releases a whole range returned by Allocate or Reserve.
	internal static void Free(void* address) => _ = NativeMethods.VirtualFree(address, 0, MEM_RELEASE);

	private static void* Check(void* address, string operation) =>
		address is not null ? address : throw new Win32Exception(Marshal.GetLastPInvokeError(), operation);
}

// Own stable storage instead of retaining pointers into reusable enumeration buffers.
// ASCII-only names are stored with one byte per character; any other name keeps its exact UTF-16 code units.
// All names are stored in one address range outside the GC heap, reserved once and committed as it fills, so a
// 4-byte NameRef locates a name directly. Each name follows a header byte holding its encoding, whether it is shared
// and its length; a name of LongLength or more code units stores its length in the two bytes before the header
// instead. Headers are at odd offsets, so a NameRef addresses them in 2-byte units and every name starts at an even
// offset, keeping UTF-16 code units naturally aligned.
// Identical names are stored once while a volume is first enumerated, because most names on a volume repeat, and
// the NameRef of every entry with that name points to the same stored copy. A shared copy is never reused for
// another name, since the arena does not count how many entries still reference it.
internal sealed unsafe class NameArena
{
	private const int WideFlag = 0x80;
	private const int SharedFlag = 0x40;
	private const int LongLength = 0x3F;
	// 2^31 two-byte positions address 4 GiB of names, over 100 million typical file names.
	private const long MaxHeaderOffset = uint.MaxValue;
	// Offset 1 holds the empty name's header, so names are stored from offset 2.
	private const long FirstOffset = 2;
	// Committed memory always extends this far past the end of every name, so the vectorized ASCII search
	// can read a full vector after a name, which needs Vector128<byte>.Count - 1 bytes.
	private const int ReadPadding = 16;
	private const int CommitSize = 64 * 1024;
	// Room after the last possible header for the longest name and the padding, in whole commit units.
	private const long ReservedSize = MaxHeaderOffset + 1 + 3 * CommitSize;
	// The deduplication table stops growing here and deduplication ends, so it never holds more than 3/4 of this
	// many names. Twice that many shared names still round up to an int capacity for the compaction table.
	private const int MaxLookupCapacity = 1 << 29;
	// Varies the name hash per process, so a crafted set of file names cannot predictably collide.
#pragma warning disable CA5394 // Do not use insecure randomness
	private static readonly ulong HashSeed = (ulong)Random.Shared.NextInt64();
#pragma warning restore CA5394
	// The empty name's header, shared by every arena until it stores its first name.
	private static readonly byte* EmptyStore = (byte*)NativeMemory.AllocZeroed((nuint)FirstOffset);
	private byte* store = EmptyStore;
	private long committed;
	// Keyed by length and encoding, so a reused slot has the exact byte size and header.
	private readonly Dictionary<int, Stack<NameRef>> freeSlots = [];
	private long used = FirstOffset;
	// Each shared name is counted once and stays counted, so released references never make this negative.
	private long liveBytes;
	private int sharedCount;
	// Bytes of shared names released since the last compaction. A shared name is dead once its last reference is
	// released, which the arena cannot tell, so every release is counted and compaction finds the exact live set.
	private long sharedReleasedBytes;
	// Open addressing table used only while names are deduplicated or copied. Each slot holds a 32-bit key in its
	// upper half and a name position in its lower half; stored positions are never 0, so 0 marks an empty slot.
	private ulong* lookup;
	private int lookupMask;
	private int lookupCount;
	private bool deduplicating;

	// Compact only after enough dead space accumulates to justify a full copy.
	// Every byte past FirstOffset was written by a stored name, so used - FirstOffset is the bytes written.
	internal bool NeedsCompaction =>
		used - FirstOffset - liveBytes + sharedReleasedBytes >= 16L * 1024 * 1024 &&
		used - FirstOffset - liveBytes + sharedReleasedBytes >= liveBytes / 4;

	// Returns the memory to Windows. The arena is empty and can be reused.
	internal void Clear()
	{
		if (store != EmptyStore) IndexMemory.Free(store);
		store = EmptyStore;
		committed = 0;
		freeSlots.Clear();
		used = FirstOffset;
		liveBytes = 0;
		sharedCount = 0;
		sharedReleasedBytes = 0;
		FreeLookup();
		deduplicating = false;
	}

	// Stores identical names added from now on once, until EndDeduplication.
	internal void BeginDeduplication()
	{
		if (lookup is not null) return;
		AllocateLookup(1 << 16);
		deduplicating = true;
	}

	// Frees the deduplication table; names added later are stored separately again.
	internal void EndDeduplication()
	{
		deduplicating = false;
		FreeLookup();
	}

	// Frees the table that mapped shared source names to their copies.
	internal void FinishCopy() => FreeLookup();

	private void AllocateLookup(int capacity)
	{
		lookup = (ulong*)IndexMemory.Allocate((nuint)capacity * sizeof(ulong));
		lookupMask = capacity - 1;
		lookupCount = 0;
	}

	private void FreeLookup()
	{
		if (lookup is not null) IndexMemory.Free(lookup);
		lookup = null;
		lookupMask = 0;
		lookupCount = 0;
	}

	// Spreads a 32-bit key over the table so that similar keys do not cluster.
	// The multiplication wraps by design, and callers mask the result to the table size.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int LookupIndex(uint key) => unchecked((int)((key * 0x9E3779B97F4A7C15UL) >> 32));

	// Inserts a slot known to be absent. The table must have a free slot.
	private void InsertLookup(uint key, uint position)
	{
		int index = LookupIndex(key) & lookupMask;
		while (lookup[index] != 0) index = (index + 1) & lookupMask;
		lookup[index] = ((ulong)key << 32) | position;
		lookupCount++;
	}

	// Doubles the table once it is three quarters full, keeping probe sequences short.
	// At the largest size, deduplication ends instead; names added later are stored separately.
	private void GrowLookupIfNeeded()
	{
		if (lookupCount < lookupMask + 1 - ((lookupMask + 1) >> 2)) return;
		int oldCapacity = lookupMask + 1;
		if (oldCapacity >= MaxLookupCapacity)
		{
			EndDeduplication();
			return;
		}
		ulong* old = lookup;
		AllocateLookup(oldCapacity * 2);
		for (int i = 0; i < oldCapacity; i++)
		{
			ulong slot = old[i];
			// The lower half of a slot is its position; the truncation is intended.
			if (slot != 0) InsertLookup((uint)(slot >> 32), unchecked((uint)slot));
		}
		IndexMemory.Free(old);
	}

	// Marks a stored name as referenced by more than one entry.
	private void MarkShared(NameRef name)
	{
		byte* header = store + (((nuint)name.Position << 1) | 1);
		if ((*header & SharedFlag) != 0) return;
		*header |= SharedFlag;
		sharedCount++;
	}

	// Returns an identical stored name instead of the one just appended at mark, removing the appended copy.
	// Otherwise records the new name so later identical names can share it.
	private NameRef Deduplicate(NameRef name, long mark)
	{
		ReadOnlySpan<byte> bytes = GetBytes(name, out int length, out bool isWide);
		uint hash = HashName(bytes, isWide);
		int index = LookupIndex(hash) & lookupMask;
		while (true)
		{
			ulong slot = lookup[index];
			if (slot == 0) break;
			if ((uint)(slot >> 32) == hash)
			{
				NameRef existing = new(unchecked((uint)slot), isDirectory: false);
				ReadOnlySpan<byte> existingBytes = GetBytes(existing, out _, out bool existingWide);
				if (existingWide == isWide && existingBytes.SequenceEqual(bytes))
				{
					// The appended copy is the last record, so removing it only moves the end back.
					liveBytes -= RecordLength(length, isWide);
					used = mark;
					MarkShared(existing);
					return existing;
				}
			}
			index = (index + 1) & lookupMask;
		}
		lookup[index] = ((ulong)hash << 32) | name.Position;
		lookupCount++;
		GrowLookupIfNeeded();
		return name;
	}

	// Hashes a stored name 8 bytes at a time, which measured faster than HashCode.AddBytes for file names.
	// The last partial word is read whole and masked; the committed padding after every name makes that read safe.
	// The encoding is included because an ASCII name and a UTF-16 name can have the same bytes.
	private static uint HashName(ReadOnlySpan<byte> bytes, bool isWide)
	{
		unchecked
		{
			ulong hash = HashSeed ^ ((ulong)bytes.Length * 0x9E3779B97F4A7C15UL) ^ (isWide ? 0xA5A5A5A5UL : 0);
			ref byte start = ref MemoryMarshal.GetReference(bytes);
			int offset = 0;
			for (; offset + sizeof(ulong) <= bytes.Length; offset += sizeof(ulong))
			{
				hash = BitOperations.RotateLeft((hash ^ Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref start, offset))) * 0xFF51AFD7ED558CCDUL, 29);
			}
			int remaining = bytes.Length - offset;
			if (remaining != 0)
			{
				// x64 and ARM64 are little-endian, so the name's remaining bytes are the low bytes of the word.
				ulong tail = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref start, offset)) & (ulong.MaxValue >> ((sizeof(ulong) - remaining) * 8));
				hash = (hash ^ tail) * 0xC4CEB9FE1A85EC53UL;
			}
			hash ^= hash >> 32;
			return (uint)((hash * 0x9E3779B97F4A7C15UL) >> 32);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int SlotKey(int length, bool isWide) => (length << 1) | (isWide ? 1 : 0);

	// Bytes a stored name occupies, including its header and any long length.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int RecordLength(int length, bool isWide) => (isWide ? length * 2 : length) + (length >= LongLength ? 3 : 1);

	private static NotSupportedException CapacityExceeded() => new("The file names of the volume exceed the 4 GiB name storage of an index.");

	// Returns the first byte of the name, and its length in UTF-16 code units.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private byte* Locate(NameRef name, out int length, out bool isWide)
	{
		byte* header = store + (((nuint)name.Position << 1) | 1);
		int value = *header;
		length = value & LongLength;
		if (length == LongLength) length = Unsafe.ReadUnaligned<ushort>(header - 2);
		isWide = value >= WideFlag;
		return header + 1;
	}

	// Commits whole units up to the required offset, reserving the address range on first use.
	private void Commit(long required)
	{
		long target = (required + CommitSize - 1) & ~(CommitSize - 1);
		if (store != EmptyStore)
		{
			IndexMemory.Commit(store + committed, (nuint)(target - committed));
		}
		else
		{
			// The new range replaces the shared empty name only once it is readable.
			// x64 and ARM64 processes have a 64-bit address space, so the size is never truncated.
			byte* range = (byte*)IndexMemory.Reserve(unchecked((nuint)ReservedSize));
			try
			{
				IndexMemory.Commit(range, (nuint)target);
			}
			catch
			{
				IndexMemory.Free(range);
				throw;
			}
			store = range;
		}
		committed = target;
	}

	// Commits enough memory to copy every live name of the source before any entry references this arena,
	// so the copy cannot fail midway. Each copied name needs at most one byte of alignment padding.
	// The table that keeps shared names shared is sized for every shared source name, so it never grows midway.
	internal void PrepareCopy(NameArena source, int nameCount)
	{
		long required = FirstOffset + source.liveBytes + nameCount;
		if (required > MaxHeaderOffset) throw CapacityExceeded();
		Commit(required + ReadPadding);
		try
		{
			AllocateLookup((int)BitOperations.RoundUpToPowerOf2((uint)Math.Max(16, source.sharedCount * 2)));
		}
		catch
		{
			// The replacement is discarded, so its committed memory is returned now.
			Clear();
			throw;
		}
	}

	private Span<byte> Reserve(int length, bool isWide, out NameRef name)
	{
		int byteLength = isWide ? length * 2 : length;
		// Reuse an exact-size slot; references to other names remain stable. Its header already matches.
		// While deduplicating, names are only appended, so a duplicate can be removed by moving the end back.
		if (!deduplicating && freeSlots.TryGetValue(SlotKey(length, isWide), out Stack<NameRef>? slots) && slots.Count != 0)
		{
			name = slots.Pop();
			liveBytes += RecordLength(length, isWide);
			return new Span<byte>(store + (((nuint)name.Position << 1) | 1) + 1, byteLength);
		}
		bool isLong = length >= LongLength;
		// The first odd offset after the used bytes, leaving room for a long length before it.
		long header = (isLong ? used + 2 : used) | 1;
		long end = header + 1 + byteLength;
		if (header > MaxHeaderOffset) throw CapacityExceeded();
		if (end + ReadPadding > committed) Commit(end + ReadPadding);
		byte* target = store + header;
		if (isLong) Unsafe.WriteUnaligned(target - 2, (ushort)length);
		*target = (byte)((isWide ? WideFlag : 0) | (isLong ? LongLength : length));
		name = new((uint)(header >> 1), isDirectory: false);
		used = end;
		liveBytes += RecordLength(length, isWide);
		return new Span<byte>(target + 1, byteLength);
	}

	// Called only after an entry stops referencing its old name.
	// A shared name may still be referenced by other entries, so it stays in place and is never reused. While
	// deduplicating, the table may still return a released name, so it stays in place too.
	internal void Release(NameRef name)
	{
		byte* start = Locate(name, out int length, out bool isWide);
		if (length == 0 || deduplicating) return;
		if ((start[-1] & SharedFlag) != 0)
		{
			sharedReleasedBytes += RecordLength(length, isWide);
			return;
		}
		int key = SlotKey(length, isWide);
		if (!freeSlots.TryGetValue(key, out Stack<NameRef>? slots))
		{
			slots = new Stack<NameRef>();
			freeSlots.Add(key, slots);
		}
		slots.Push(name);
		liveBytes -= RecordLength(length, isWide);
	}

	// Callers validate that Windows filename bytes contain complete UTF-16LE code units.
	internal NameRef AddUtf16(ReadOnlySpan<byte> bytes)
	{
		ReadOnlySpan<char> text = MemoryMarshal.Cast<byte, char>(bytes);
		if (text.IsEmpty) return default;
		long mark = used;
		if (Ascii.IsValid(text))
		{
			Span<byte> narrow = Reserve(text.Length, isWide: false, out NameRef asciiName);
			_ = Ascii.FromUtf16(text, narrow, out _);
			return deduplicating ? Deduplicate(asciiName, mark) : asciiName;
		}
		Span<byte> target = Reserve(text.Length, isWide: true, out NameRef name);
		MemoryMarshal.AsBytes(text).CopyTo(target);
		return deduplicating ? Deduplicate(name, mark) : name;
	}

	// Copies a name from another arena without re-encoding it, preserving its directory flag.
	// Every reference to a shared source name receives the same copy, found by its source position.
	internal NameRef AddCopy(NameArena source, NameRef name)
	{
		byte* start = source.Locate(name, out int length, out bool isWide);
		if (length == 0) return default;
		bool shared = (start[-1] & SharedFlag) != 0;
		int index = 0;
		if (shared)
		{
			index = LookupIndex(name.Position) & lookupMask;
			while (true)
			{
				ulong slot = lookup[index];
				if (slot == 0) break;
				if ((uint)(slot >> 32) == name.Position)
				{
					NameRef existing = new(unchecked((uint)slot), isDirectory: false);
					MarkShared(existing);
					return existing.WithDirectory(name.IsDirectory);
				}
				index = (index + 1) & lookupMask;
			}
		}
		Span<byte> target = Reserve(length, isWide, out NameRef copy);
		new ReadOnlySpan<byte>(start, isWide ? length * 2 : length).CopyTo(target);
		// The table is sized for every shared source name and never grows, so its count is not kept.
		if (shared) lookup[index] = ((ulong)name.Position << 32) | copy.Position;
		return copy.WithDirectory(name.IsDirectory);
	}

	private ReadOnlySpan<byte> GetBytes(NameRef name, out int length, out bool isWide)
	{
		byte* start = Locate(name, out length, out isWide);
		return new(start, isWide ? length * 2 : length);
	}

	// Length in UTF-16 code units, independent of the stored encoding.
	internal int GetLength(NameRef name)
	{
		_ = Locate(name, out int length, out _);
		return length;
	}

	// Writes the original UTF-16 name; stored ASCII bytes widen losslessly. Returns its length.
	internal int CopyTo(NameRef name, Span<char> destination)
	{
		ReadOnlySpan<byte> bytes = GetBytes(name, out int length, out bool isWide);
		if (isWide) MemoryMarshal.Cast<byte, char>(bytes).CopyTo(destination);
		else _ = Ascii.ToUtf16(bytes, destination, out _);
		return length;
	}

	// Returns the original UTF-16 name, widening ASCII names into scratch.
	// NTFS and ReFS limit a file name to 255 UTF-16 code units, so a 255-character scratch always fits.
	internal ReadOnlySpan<char> GetChars(NameRef name, Span<char> scratch)
	{
		ReadOnlySpan<byte> bytes = GetBytes(name, out int length, out bool isWide);
		if (isWide) return MemoryMarshal.Cast<byte, char>(bytes);
		Span<char> target = scratch[..length];
		_ = Ascii.ToUtf16(bytes, target, out _);
		return target;
	}

	// Same result as an OrdinalIgnoreCase comparison of the original UTF-16 names.
	// Callers validate that Windows filename bytes contain complete UTF-16LE code units.
	internal bool NameEquals(NameRef name, ReadOnlySpan<byte> otherBytes)
	{
		ReadOnlySpan<char> other = MemoryMarshal.Cast<byte, char>(otherBytes);
		ReadOnlySpan<byte> bytes = GetBytes(name, out _, out bool isWide);
		return isWide
			? MemoryMarshal.Cast<byte, char>(bytes).Equals(other, StringComparison.OrdinalIgnoreCase)
			: Ascii.EqualsIgnoreCase(bytes, other);
	}

	// Same result as an OrdinalIgnoreCase IndexOf of the query in the original UTF-16 name.
	internal bool Contains(NameRef name, NameQuery query)
	{
		byte* start = Locate(name, out int length, out bool isWide);
		// OrdinalIgnoreCase maps code units one-to-one, so a match is never shorter than the query.
		if (length < query.Length) return false;
		if (isWide)
		{
			ReadOnlySpan<char> characters = new(start, length);
			return characters.IndexOf(query.Text.AsSpan(), StringComparison.OrdinalIgnoreCase) >= 0;
		}
		// The committed padding after the name is passed so the vectorized search can read past its end.
		return query.IsAscii && query.MatchesAscii(new ReadOnlySpan<byte>(start, length + ReadPadding), length);
	}
}

// NTFS file reference numbers hold a 48-bit MFT segment number and a 16-bit sequence number.
// Segment numbers are dense, so entries are addressed directly by segment in fixed-size pages
// instead of being hashed. Pages are allocated on first use and released when they become empty.
// Pages are allocated outside the GC heap; a 12-byte slot makes each page exactly three 4 KiB memory pages.
internal sealed unsafe class NtfsEntryTable
{
	private const int PageShift = 10;
	private const int PageSize = 1 << PageShift;
	private const int PageMask = PageSize - 1;
	private const ulong SegmentMask = 0x0000_FFFF_FFFF_FFFFUL;
	// NTFS holds at most 2^32 - 1 files per volume, so every MFT segment number fits in 32 bits.
	private const ulong ParentSegmentMask = uint.MaxValue;
	private nint[] pages = [];
	private int[] pageCounts = [];

	// Link layout: own sequence (bits 48-63), parent sequence (32-47), parent segment (0-31).
	// An occupied link is never zero: every entry has a parent directory, and segment 0 is $MFT, never a directory.
	// Packed to 12 bytes; x64 and ARM64 read the unaligned links directly.
	[StructLayout(LayoutKind.Sequential, Pack = 4)]
	private struct Slot
	{
		internal ulong Link;
		internal NameRef Name;
	}

	internal int Count { get; private set; }

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Pack(ulong id, ulong parent) => (id & ~SegmentMask) | ((parent >> 48) << 32) | (parent & ParentSegmentMask);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong GetParent(ulong link) => (((link >> 32) & ushort.MaxValue) << 48) | (link & ParentSegmentMask);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong GetSequence(ulong link) => link >> 48;

	// Returns every page to Windows. The table must not be used afterwards.
	internal void Clear()
	{
		foreach (nint page in pages)
		{
			if (page != 0) IndexMemory.Free((void*)page);
		}
	}

	// Returns the occupied slot with this exact file reference number, or a null reference.
	private ref Slot Find(ulong id, out int pageIndex)
	{
		ulong segment = id & SegmentMask;
		ulong pageNumber = segment >> PageShift;
		// Checked casts: the page number is converted only after the bounds check.
		pageIndex = pageNumber < (ulong)pages.Length ? (int)pageNumber : -1;
		Slot* page = pageIndex >= 0 ? (Slot*)pages[pageIndex] : null;
		if (page != null)
		{
			ref Slot slot = ref page[(int)(segment & PageMask)];
			if (slot.Link != 0 && GetSequence(slot.Link) == id >> 48) return ref slot;
		}
		return ref Unsafe.NullRef<Slot>();
	}

	internal bool TryGetValue(ulong id, out NtfsEntry entry)
	{
		ref Slot slot = ref Find(id, out _);
		if (Unsafe.IsNullRef(ref slot))
		{
			entry = default;
			return false;
		}
		entry = new(GetParent(slot.Link), slot.Name);
		return true;
	}

	// Stores the entry in its MFT segment. An MFT record holds one file at a time, so this
	// replaces any entry in the segment and returns its name for release.
	internal bool Set(ulong id, ulong parent, NameRef name, out NameRef replaced)
	{
		int pageIndex = (int)((id & SegmentMask) >> PageShift);
		if (pageIndex >= pages.Length)
		{
			int length = Math.Max(pageIndex + 1, pages.Length * 2);
			Array.Resize(ref pages, length);
			Array.Resize(ref pageCounts, length);
		}
		Slot* page = (Slot*)pages[pageIndex];
		if (page == null) pages[pageIndex] = (nint)(page = (Slot*)IndexMemory.Allocate((nuint)(PageSize * sizeof(Slot))));
		ref Slot slot = ref page[(int)(id & PageMask)];
		bool exists = slot.Link != 0;
		replaced = slot.Name;
		if (!exists)
		{
			pageCounts[pageIndex]++;
			Count++;
		}
		slot.Link = Pack(id, parent);
		slot.Name = name;
		return exists;
	}

	// Call only for an ID that TryGetValue just found.
	internal void Remove(ulong id)
	{
		ref Slot slot = ref Find(id, out int pageIndex);
		slot = default;
		Count--;
		if (--pageCounts[pageIndex] == 0)
		{
			IndexMemory.Free((void*)pages[pageIndex]);
			pages[pageIndex] = 0;
		}
	}

	// Rewrites every name into the target arena in place.
	internal void RewriteNames(NameArena source, NameArena target)
	{
		foreach (nint pointer in pages)
		{
			if (pointer == 0) continue;
			Slot* page = (Slot*)pointer;
			for (int i = 0; i < PageSize; i++)
			{
				ref Slot slot = ref page[i];
				if (slot.Link != 0) slot.Name = target.AddCopy(source, slot.Name);
			}
		}
	}

	internal Enumerator GetEnumerator() => new(this);

	// Enumerates occupied slots in segment order without boxing. The table must not be modified during enumeration.
	internal struct Enumerator
	{
		private readonly nint[] pages;
		private Slot* page;
		private int pageIndex;
		private int slotIndex;

		internal Enumerator(NtfsEntryTable table)
		{
			pages = table.pages;
			pageIndex = -1;
			slotIndex = PageSize;
		}

		internal bool MoveNext()
		{
			while (true)
			{
				if (++slotIndex >= PageSize)
				{
					do
					{
						if (++pageIndex >= pages.Length) return false;
						page = (Slot*)pages[pageIndex];
					}
					while (page == null);
					slotIndex = 0;
				}
				if (page[slotIndex].Link != 0) return true;
			}
		}

		internal readonly NameRef Name => page[slotIndex].Name;

		internal readonly ulong Id => (GetSequence(page[slotIndex].Link) << 48) | ((ulong)(uint)pageIndex << PageShift) | (uint)slotIndex;

		internal readonly NtfsEntry Entry => new(GetParent(page[slotIndex].Link), page[slotIndex].Name);
	}
}

// ReFS uses 128-bit file IDs, so its entries cannot be addressed by segment like NTFS entries.
// They are stored in fixed-size pages in insertion order and found through a chained hash index.
// Each entry links to its parent directory by slot index instead of repeating the parent's 16-byte ID,
// so a slot is 28 bytes, pages are never copied when the table grows, and a path is resolved by
// following slot indices instead of hashing every component. Pages and buckets are allocated outside the GC heap;
// a 28-byte slot makes each page exactly seven 4 KiB memory pages.
internal sealed unsafe class WideEntryTable
{
	private const int PageShift = 10;
	private const int PageSize = 1 << PageShift;
	private const int PageMask = PageSize - 1;
	private const int MinimumBucketCount = 16;
	// Reclaim removed slots only after enough accumulate to justify rewriting the table.
	private const int CompactionThreshold = 100_000;
	// The parent link of entries in the volume root directory.
	internal const int Root = -1;
	// The parent link of a slot that holds no entry: a parent directory that has not been seen yet,
	// or a removed entry. It keeps its ID so entries linked to it resolve again if it is added back,
	// for example when a directory is renamed.
	private const int Absent = -2;
	private readonly FileId rootId;
	private nint[] pages = [];
	// Bucket heads and chain links hold a slot index plus one, so zero ends a chain.
	private int* buckets;
	private int bucketCount;
	private int bucketShift;
	private int slotCount;
	// Absent slots that were still linked by entries at the last compaction.
	private int retainedSlots;
	// Directory listings and journal batches add many entries with the same parent in a row.
	private FileId lastParent;
	private int lastParentIndex = -1;

	// Packed to 28 bytes; x64 and ARM64 read the unaligned IDs directly.
	[StructLayout(LayoutKind.Sequential, Pack = 4)]
	private struct Slot
	{
		internal FileId Id;
		internal NameRef Name;
		internal int Parent;
		internal int Next;
	}

	internal WideEntryTable(FileId rootId) => this.rootId = rootId;

	internal int Count { get; private set; }

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private ref Slot At(int index) => ref ((Slot*)pages[index >> PageShift])[index & PageMask];

	// Returns all pages and buckets to Windows. The table must not be used afterwards.
	internal void Clear()
	{
		foreach (nint page in pages)
		{
			if (page != 0) IndexMemory.Free((void*)page);
		}
		if (buckets != null) IndexMemory.Free(buckets);
	}

	// Fibonacci hashing: the top bits of the mixed ID select the bucket.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int GetBucket(FileId id) => (int)(unchecked(id.Low * 0x9E3779B97F4A7C15UL + id.High * 0xC2B2AE3D27D4EB4FUL) >> bucketShift);

	// Returns the slot holding this ID, or -1.
	private int Find(FileId id)
	{
		if (bucketCount == 0) return -1;
		int link = buckets[GetBucket(id)];
		while (link != 0)
		{
			ref Slot slot = ref At(link - 1);
			if (slot.Id == id) return link - 1;
			link = slot.Next;
		}
		return -1;
	}

	private int FindOrAdd(FileId id)
	{
		int index = Find(id);
		if (index >= 0) return index;
		// Keep at most one slot per bucket on average.
		if (slotCount == bucketCount) Rehash(Math.Max(MinimumBucketCount, bucketCount * 2));
		index = slotCount;
		int pageIndex = index >> PageShift;
		if (pageIndex == pages.Length) Array.Resize(ref pages, Math.Max(4, pages.Length * 2));
		Slot* page = (Slot*)pages[pageIndex];
		if (page == null) pages[pageIndex] = (nint)(page = (Slot*)IndexMemory.Allocate((nuint)(PageSize * sizeof(Slot))));
		int bucket = GetBucket(id);
		page[index & PageMask] = new Slot { Id = id, Parent = Absent, Next = buckets[bucket] };
		buckets[bucket] = index + 1;
		slotCount++;
		return index;
	}

	private void Rehash(int bucketCount)
	{
		// The old buckets are released only after the new ones are allocated.
		int* replacement = (int*)IndexMemory.Allocate((nuint)bucketCount * sizeof(int));
		if (buckets != null) IndexMemory.Free(buckets);
		buckets = replacement;
		this.bucketCount = bucketCount;
		bucketShift = 64 - BitOperations.Log2((uint)bucketCount);
		for (int i = 0; i < slotCount; i++)
		{
			ref Slot slot = ref At(i);
			int bucket = GetBucket(slot.Id);
			slot.Next = buckets[bucket];
			buckets[bucket] = i + 1;
		}
	}

	private int GetParentIndex(FileId parent)
	{
		if (parent == rootId) return Root;
		if (lastParentIndex >= 0 && parent == lastParent) return lastParentIndex;
		int index = FindOrAdd(parent);
		lastParent = parent;
		lastParentIndex = index;
		return index;
	}

	internal bool TryGetValue(FileId id, out Entry entry)
	{
		int index = Find(id);
		if (index >= 0)
		{
			ref Slot slot = ref At(index);
			if (slot.Parent != Absent)
			{
				entry = new(slot.Parent == Root ? rootId : At(slot.Parent).Id, slot.Name);
				return true;
			}
		}
		entry = default;
		return false;
	}

	// Stores the entry and returns whether it replaced one, whose name is returned for release.
	internal bool Set(FileId id, FileId parent, NameRef name, out NameRef replaced)
	{
		int index = FindOrAdd(id);
		int parentIndex = GetParentIndex(parent);
		ref Slot slot = ref At(index);
		bool exists = slot.Parent != Absent;
		replaced = exists ? slot.Name : default;
		if (!exists) Count++;
		slot.Parent = parentIndex;
		slot.Name = name;
		return exists;
	}

	// Call only for an ID that TryGetValue just found.
	internal void Remove(FileId id)
	{
		ref Slot slot = ref At(Find(id));
		slot.Parent = Absent;
		slot.Name = default;
		Count--;
	}

	// Reads one link of a path. Returns false for a slot that holds no entry.
	internal bool TryGetLink(int index, out FileId id, out int parent, out NameRef name)
	{
		ref Slot slot = ref At(index);
		id = slot.Id;
		parent = slot.Parent;
		name = slot.Name;
		return parent != Absent;
	}

	// Rewrites every name into the target arena in place.
	internal void RewriteNames(NameArena source, NameArena target)
	{
		for (int i = 0; i < slotCount; i++)
		{
			ref Slot slot = ref At(i);
			if (slot.Parent != Absent) slot.Name = target.AddCopy(source, slot.Name);
		}
	}

	internal void CompactIfNeeded()
	{
		int reclaimable = slotCount - Count - retainedSlots;
		if (reclaimable >= CompactionThreshold && reclaimable >= Count / 4) Compact();
	}

	// Drops absent slots that no entry links to and closes the gaps, preserving the order of the rest.
	private void Compact()
	{
		// Mark slots that entries link to; the chain links are rebuilt at the end.
		for (int i = 0; i < slotCount; i++) At(i).Next = 0;
		for (int i = 0; i < slotCount; i++)
		{
			int parent = At(i).Parent;
			if (parent >= 0) At(parent).Next = 1;
		}
		// Store each kept slot's new index in its chain link, and -1 for dropped slots.
		int kept = 0;
		for (int i = 0; i < slotCount; i++)
		{
			ref Slot slot = ref At(i);
			slot.Next = slot.Parent != Absent || slot.Next != 0 ? kept++ : -1;
		}
		// Translate parent links while every slot is still at its old index. A linked slot is always kept.
		for (int i = 0; i < slotCount; i++)
		{
			ref Slot slot = ref At(i);
			if (slot.Next >= 0 && slot.Parent >= 0) slot.Parent = At(slot.Parent).Next;
		}
		// A slot never moves to a higher index, so no slot is overwritten before it is moved.
		for (int i = 0; i < slotCount; i++)
		{
			ref Slot slot = ref At(i);
			if (slot.Next >= 0 && slot.Next != i) At(slot.Next) = slot;
		}
		int pageCount = (kept + PageMask) >> PageShift;
		// Return the pages that no longer hold slots.
		for (int i = pageCount; i < pages.Length; i++)
		{
			if (pages[i] != 0) IndexMemory.Free((void*)pages[i]);
		}
		Array.Resize(ref pages, pageCount);
		slotCount = kept;
		retainedSlots = kept - Count;
		lastParentIndex = -1;
		Rehash(Math.Max(MinimumBucketCount, (int)BitOperations.RoundUpToPowerOf2((uint)kept)));
	}

	internal Enumerator GetEnumerator() => new(this);

	// Enumerates entries in slot order. The table must not be modified during enumeration.
	internal struct Enumerator
	{
		private readonly nint[] pages;
		private readonly int count;
		private Slot* page;

		internal Enumerator(WideEntryTable table)
		{
			pages = table.pages;
			count = table.slotCount;
			Index = -1;
		}

		internal bool MoveNext()
		{
			while (++Index < count)
			{
				if ((Index & PageMask) == 0) page = (Slot*)pages[Index >> PageShift];
				if (page[Index & PageMask].Parent != Absent) return true;
			}
			return false;
		}

		// The slot index, for TryGetLink.
		internal int Index { get; private set; }

		internal readonly NameRef Name => page[Index & PageMask].Name;
	}
}

internal readonly record struct FileId(ulong Low, ulong High);
internal readonly record struct Entry(FileId Parent, NameRef Name);
internal readonly record struct NtfsEntry(ulong Parent, NameRef Name);
internal readonly record struct Journal(ulong Id, long First, long Next);

internal sealed unsafe partial class VolumeIndex : IDisposable
{
	private const int BufferSize = 1024 * 1024;
	// Changes between searches are small, so later journal reads do not need the enumeration buffer's size.
	private const int RefreshBufferSize = 64 * 1024;
	private const int DirectoryBufferSize = 64 * 1024;
	private const uint ReparsePointAttribute = 0x00000400;
	private const uint EnumUsn = 0x000900B3;
	private const uint ReadUsn = 0x000900BB;
	private const uint QueryUsn = 0x000900F4;
	private const uint FileDelete = 0x00000200;
	private const uint RenameOldName = 0x00001000;
	private const uint RenameNewName = 0x00002000;
	private const uint DirectoryAttribute = 0x00000010;
	private const uint StorageQueryProperty = 0x002D1400;
	// ReFS directories are read by at most this many threads on volumes without a seek penalty. (benchmarks revealed 4 is the optimal value)
	private const int MaxReFsWorkers = 4;
	private const int ReFsWorkerStackSize = 256 * 1024;
	private static readonly nint InvalidHandleValue = -1;
	private nint volume;
	private readonly string root;
	private readonly bool refs;
	private readonly FileId rootId;
	private WideEntryTable? wideEntries;
	private NtfsEntryTable? ntfsEntries;
	private NameArena nameArena = new();
	private readonly HashSet<FileId> inaccessibleDirectories = [];
	private ulong journalId;
	private long nextUsn;
	private byte[]? refreshBuffer;
	// Path scratch reused by every search instead of being allocated per search. Searches of one volume never overlap.
	private readonly List<NameRef> pathNames = [];
	private readonly HashSet<ulong> pathVisited = [];
	internal char Drive => root[0];
	// Includes indexed files and directories; reading Count does not scan the index.
	internal int IndexedItemCount => wideEntries?.Count ?? ntfsEntries!.Count;
	internal int InaccessibleDirectoryCount => inaccessibleDirectories.Count;

	internal VolumeIndex(char drive)
	{
		root = $"{drive}:\\";
		byte* fsName = stackalloc byte[64];
		if (!NativeMethods.GetVolumeInformationW(root, null, 0, null, null, null, (char*)fsName, 32))
			throw Error("GetVolumeInformationW");
		string fs = new((char*)fsName);
		refs = string.Equals(fs, "ReFS", StringComparison.OrdinalIgnoreCase);
		if (!refs && !string.Equals(fs, "NTFS", StringComparison.OrdinalIgnoreCase))
			throw new NotSupportedException($"Only local NTFS and ReFS volumes are supported; found {fs}.");
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
		// The ReFS table needs the root ID to recognize entries in the root directory.
		if (refs) wideEntries = new(rootId);
		else ntfsEntries = new();
	}

	internal void Build()
	{
		Journal start = QueryJournal();
		byte[]? enumerationBuffer = null;
		// Store each distinct name of the volume once. The table is only needed while every name is added at once.
		nameArena.BeginDeduplication();
		try
		{
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
		}
		finally
		{
			nameArena.EndDeduplication();
		}
		journalId = start.Id;
		nextUsn = start.Next;
		Refresh(enumerationBuffer); // Replay changes that happened while enumerating.
	}

	// FSCTL_ENUM_USN_DATA is already the fastest way to enumerate NTFS. Manually reading and parsing the raw $MFT
	// was measured to give no indexing speedup, because both read the same MFT data and the disk/SSD is the bottleneck.
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
		ReFsWalk walk = new();
		walk.Pending.Push(rootId);
		int workers = CountReFsWorkers();
		// Extra workers exist only during the walk; each reads its own directories into its own buffer.
		Thread[] threads = new Thread[workers - 1];
		int started = 0;
		try
		{
			for (; started < threads.Length; started++)
			{
				threads[started] = new Thread(() => WalkReFsDirectories(walk), ReFsWorkerStackSize) { IsBackground = true };
				threads[started].Start();
			}
			WalkReFsDirectories(walk);
		}
		finally
		{
			// Started workers finish the walk on their own, so the index is never changed after Build returns.
			for (int i = 0; i < started; i++) threads[i].Join();
		}
		walk.Failure?.Throw();
	}

	// Volumes without a seek penalty serve several directory reads at once; a disk that seeks, or one that
	// does not report its seek penalty, keeps the single reader so its reads are not interleaved.
	private int CountReFsWorkers()
	{
		// STORAGE_PROPERTY_QUERY: StorageDeviceSeekPenaltyProperty (7), PropertyStandardQuery (0).
		uint* query = stackalloc uint[] { 7, 0, 0 };
		// DEVICE_SEEK_PENALTY_DESCRIPTOR: Version, Size, IncursSeekPenalty.
		byte* descriptor = stackalloc byte[12];
		uint bytes = 0;
		if (!NativeMethods.DeviceIoControl(volume, StorageQueryProperty, query, 12, descriptor, 12, ref bytes, IntPtr.Zero) ||
			bytes < 9 || descriptor[8] != 0) return 1;
		// The workers mostly wait for the device, so their number does not depend on the processor count.
		return MaxReFsWorkers;
	}

	// Directories still to be read, shared by the walk's workers. The index is only changed under Sync.
	private sealed class ReFsWalk
	{
		internal readonly object Sync = new();
		internal readonly Stack<FileId> Pending = new();
		internal readonly HashSet<FileId> Visited = [];
		internal ExceptionDispatchInfo? Failure;
		// Directories being read; the walk ends when none are pending or being read.
		private int active;

		internal bool TryTake(out FileId directory)
		{
			lock (Sync)
			{
				while (Failure is null)
				{
					if (Pending.Count != 0)
					{
						directory = Pending.Pop();
						if (!Visited.Add(directory)) continue;
						active++;
						return true;
					}
					if (active == 0) break;
					_ = Monitor.Wait(Sync);
				}
				Monitor.PulseAll(Sync);
				directory = default;
				return false;
			}
		}

		internal void Complete(Exception? failure)
		{
			lock (Sync)
			{
				Failure ??= failure is null ? null : ExceptionDispatchInfo.Capture(failure);
				active--;
				if (Failure is not null || (active == 0 && Pending.Count == 0)) Monitor.PulseAll(Sync);
			}
		}
	}

	private void WalkReFsDirectories(ReFsWalk walk)
	{
		byte[] buffer = new byte[DirectoryBufferSize];
		fixed (byte* output = buffer)
		{
			while (walk.TryTake(out FileId parent))
			{
				Exception? failure = null;
				try
				{
					EnumerateReFsDirectory(walk, parent, buffer, output);
				}
				catch (Exception exception)
				{
					failure = exception;
				}
				walk.Complete(failure);
			}
		}
	}

	private void EnumerateReFsDirectory(ReFsWalk walk, FileId parent, byte[] buffer, byte* output)
	{
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
				lock (walk.Sync) _ = inaccessibleDirectories.Add(parent);
				return;
			}
			throw new Win32Exception(error, $"Open ReFS directory {root} file ID {parent.High:X16}{parent.Low:X16}");
		}

		try
		{
			while (true)
			{
				// The directory is read outside the lock so other workers can read theirs at the same time.
				if (!NativeMethods.GetFileInformationByHandleEx(directory, 19, output, DirectoryBufferSize))
				{
					int error = Marshal.GetLastPInvokeError();
					if (error is 18 or 38) break; // ERROR_NO_MORE_FILES / ERROR_HANDLE_EOF.
					if (parent != rootId && IsSkippableReFsDirectoryError(error))
					{
						lock (walk.Sync) _ = inaccessibleDirectories.Add(parent);
						break;
					}
					throw new Win32Exception(error, $"FileIdExtdDirectoryInfo failed for {root} file ID {parent.High:X16}{parent.Low:X16}");
				}

				lock (walk.Sync)
				{
					int pushed = walk.Pending.Count;
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
								walk.Pending.Push(id);
							}
						}
						if (next == 0) break;
						offset += entryLength;
					}
					// Wake workers waiting for directories.
					if (walk.Pending.Count != pushed) Monitor.PulseAll(walk.Sync);
				}
			}
		}
		finally
		{
			_ = NativeMethods.CloseHandle(directory);
		}
	}

	internal void Refresh(byte[]? enumerationBuffer = null)
	{
		Journal current = QueryJournal();
		if (current.Id != journalId || nextUsn < current.First || nextUsn > current.Next)
			throw new IOException("USN journal changed or lost records. Restart to rebuild the index.");
		if (nextUsn == current.Next) return;
		// Allocate only when there are changes, then reuse this volume's buffer on later refreshes.
		// Reuse the NTFS enumeration buffer for the initial catch-up; it is released when the build returns.
		byte[] buffer = enumerationBuffer ?? (refreshBuffer ??= new byte[RefreshBufferSize]);
		fixed (byte* output = buffer)
		{
			while (nextUsn < current.Next)
			{
				ReadV1 request = new() { Start = nextUsn, ReasonMask = uint.MaxValue, JournalId = journalId, Min = 2, Max = 3 };
				uint bytes = 0;
				if (!NativeMethods.DeviceIoControl(volume, ReadUsn, &request, (uint)sizeof(ReadV1), output, (uint)buffer.Length, ref bytes, IntPtr.Zero))
					throw Error("FSCTL_READ_USN_JOURNAL (restart to rebuild if journal was truncated)");
				if (bytes < 8 || bytes > buffer.Length) throw new InvalidDataException("Invalid journal response.");
				long next = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(0, 8));
				if (next <= nextUsn) throw new InvalidDataException("Journal cursor is invalid.");
				Walk(buffer.AsSpan(8, (int)bytes - 8), initialEnumeration: false);
				nextUsn = next;
				CompactNamesIfNeeded();
				TrimEntriesIfNeeded();
			}
		}
	}

	// Adds matching paths to the response until it is full. Nothing is allocated per search or per match.
	internal void Search(NameQuery query, SearchResponse response)
	{
		// Widens ASCII names for the file type filter. NTFS and ReFS names fit in 255 UTF-16 code units.
		Span<char> scratch = stackalloc char[256];
		if (wideEntries is not null)
		{
			WideEntryTable.Enumerator entries = wideEntries.GetEnumerator();
			while (entries.MoveNext())
			{
				if (!Matches(entries.Name, query, scratch) || !ResolveWide(entries.Index)) continue;
				WritePath(response);
				if (response.IsFull) return;
			}
		}
		else
		{
			// Read only the name of each entry; the ID is decoded only for matches.
			NtfsEntryTable.Enumerator entries = ntfsEntries!.GetEnumerator();
			while (entries.MoveNext())
			{
				if (!Matches(entries.Name, query, scratch) || !ResolveNtfs(entries.Id)) continue;
				WritePath(response);
				if (response.IsFull) return;
			}
		}
	}

	// The kind is a single bit test, so it skips entries before their names are compared.
	// The file type is classified only for names that already contain the query.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private bool Matches(NameRef name, NameQuery query, Span<char> scratch) =>
		(name.IsDirectory ? query.IncludeFolders : query.IncludeFiles) &&
		nameArena.Contains(name, query) &&
		(query.FileTypes == 0 || HasFileType(nameArena.GetChars(name, scratch), query.FileTypes));

	// Collects the path's names, leaf first, into pathNames. Returns false if the path cannot be shown.
	private bool ResolveWide(int index)
	{
		pathNames.Clear();
		pathVisited.Clear();
		WideEntryTable entries = wideEntries!;
		while (index != WideEntryTable.Root)
		{
			// Do not expose descendants introduced by journal replay under skipped directories.
			if (!pathVisited.Add((uint)index) || !entries.TryGetLink(index, out FileId id, out int parent, out NameRef name)) return false;
			if (pathNames.Count != 0 && inaccessibleDirectories.Contains(id)) return false;
			pathNames.Add(name);
			index = parent;
		}
		return true;
	}

	private bool ResolveNtfs(ulong id)
	{
		pathNames.Clear();
		pathVisited.Clear();
		while (id != rootId.Low)
		{
			if (!pathVisited.Add(id) || !ntfsEntries!.TryGetValue(id, out NtfsEntry entry)) return false;
			pathNames.Add(entry.Name);
			id = entry.Parent;
		}
		return true;
	}

	private void WritePath(SearchResponse response)
	{
		List<NameRef> names = pathNames;
		if (names.Count == 0)
		{
			response.Add(root);
			return;
		}
		int length = root.Length + names.Count - 1;
		foreach (NameRef name in names) length += nameArena.GetLength(name);
		// Write the root and reverse-ordered components into the response's reusable scratch instead of a new string.
		Span<char> destination = response.GetPathBuffer(length);
		root.AsSpan().CopyTo(destination);
		int offset = root.Length;
		for (int i = names.Count - 1; i >= 0; i--)
		{
			NameRef component = names[i];
			offset += nameArena.CopyTo(component, destination[offset..]);
			if (i != 0) destination[offset++] = '\\';
		}
		response.Add(destination);
	}

	// Build the replacement before releasing the old slot so it cannot be reused prematurely.
	private void SetEntry(FileId id, FileId parent, NameRef name, bool isDirectory)
	{
		if (wideEntries is not null)
		{
			if (wideEntries.Set(id, parent, name.WithDirectory(isDirectory), out NameRef wideOld)) nameArena.Release(wideOld);
			return;
		}
		// One direct slot write for insert or replacement.
		if (ntfsEntries!.Set(id.Low, parent.Low, name.WithDirectory(isDirectory), out NameRef ntfsOld)) nameArena.Release(ntfsOld);
	}

	// Preserve full V3 identifiers if NTFS ever returns a nonzero high half.
	private void PromoteNtfsToWideIds()
	{
		NtfsEntryTable source = ntfsEntries!;
		WideEntryTable replacement = new(rootId);
		try
		{
			NtfsEntryTable.Enumerator entries = source.GetEnumerator();
			while (entries.MoveNext())
			{
				NtfsEntry value = entries.Entry;
				_ = replacement.Set(new FileId(entries.Id, 0), new FileId(value.Parent, 0), value.Name, out _);
			}
		}
		catch
		{
			// The NTFS table is unchanged and stays in use.
			replacement.Clear();
			throw;
		}
		wideEntries = replacement;
		ntfsEntries = null;
		source.Clear();
	}

	// Reclaim removed ReFS slots after a substantial net deletion, not on every update.
	// The NTFS table releases its empty pages as entries are removed.
	private void TrimEntriesIfNeeded() => wideEntries?.CompactIfNeeded();

	// Copy only referenced names, then update slots in place to preserve their order.
	private void CompactNamesIfNeeded()
	{
		if (!nameArena.NeedsCompaction) return;
		NameArena replacement = new();
		// Commit the copy's full size first: slots are rewritten one by one, so the copy must not fail midway.
		replacement.PrepareCopy(nameArena, IndexedItemCount);
		// Slots are rewritten in place; no ID snapshot is needed.
		if (wideEntries is not null) wideEntries.RewriteNames(nameArena, replacement);
		else ntfsEntries!.RewriteNames(nameArena, replacement);
		replacement.FinishCopy();
		nameArena.Clear();
		nameArena = replacement;
	}

	private void UpsertUsn(FileId id, FileId parent, ReadOnlySpan<byte> nameBytes, bool isDirectory)
	{
		if (id == rootId) return;
		// This path is used only for NTFS initial enumeration.
		// EnumerateNtfs sends MFT_ENUM_DATA_V0, which has no MinMajorVersion/MaxMajorVersion fields. Only MFT_ENUM_DATA_V1
		// documents that MaxMajorVersion 3 is needed to receive USN_RECORD_V3 (128-bit IDs), so V2 records are expected here.
		if (wideEntries is null && (id.High | parent.High) != 0) PromoteNtfsToWideIds();
		SetEntry(id, parent, nameArena.AddUtf16(nameBytes), isDirectory);
	}

	private void ApplyUsn(FileId id, FileId parent, ReadOnlySpan<byte> nameBytes, bool isDirectory, uint reason)
	{
		if (id == rootId) return;
		// Refresh reads the journal with READ_USN_JOURNAL_DATA_V1 and MaxMajorVersion 3, the request introduced
		// for 128-bit file IDs, so USN_RECORD_V3 records can arrive here even on NTFS.
		// https://learn.microsoft.com/windows/win32/api/winioctl/ns-winioctl-read_usn_journal_data_v1
		if (wideEntries is null && (id.High | parent.High) != 0) PromoteNtfsToWideIds();
		if (wideEntries is not null) ApplyWideUsn(id, parent, nameBytes, isDirectory, reason);
		else ApplyNtfsUsn(id.Low, parent.Low, nameBytes, isDirectory, reason);
	}

	private void ApplyWideUsn(FileId id, FileId parent, ReadOnlySpan<byte> nameBytes, bool isDirectory, uint reason)
	{
		WideEntryTable entries = wideEntries!;
		if ((reason & (FileDelete | RenameOldName)) != 0)
		{
			if (entries.TryGetValue(id, out Entry old) && old.Parent == parent && nameArena.NameEquals(old.Name, nameBytes))
			{
				entries.Remove(id);
				nameArena.Release(old.Name);
			}
		}
		else if ((reason & RenameNewName) != 0 || !entries.TryGetValue(id, out Entry old))
		{
			SetEntry(id, parent, nameArena.AddUtf16(nameBytes), isDirectory);
		}
		// Updates the existing entry in place; its name is kept, so it is not released.
		else _ = entries.Set(id, old.Parent, old.Name.WithDirectory(isDirectory), out _);
	}

	private void ApplyNtfsUsn(ulong id, ulong parent, ReadOnlySpan<byte> nameBytes, bool isDirectory, uint reason)
	{
		NtfsEntryTable entries = ntfsEntries!;
		if ((reason & (FileDelete | RenameOldName)) != 0)
		{
			if (entries.TryGetValue(id, out NtfsEntry old) && old.Parent == parent && nameArena.NameEquals(old.Name, nameBytes))
			{
				entries.Remove(id);
				nameArena.Release(old.Name);
			}
		}
		else if ((reason & RenameNewName) != 0 || !entries.TryGetValue(id, out NtfsEntry old))
		{
			SetEntry(new FileId(id, 0), new FileId(parent, 0), nameArena.AddUtf16(nameBytes), isDirectory);
		}
		// Updates the existing entry in place; its name is kept, so it is not released.
		else _ = entries.Set(id, old.Parent, old.Name.WithDirectory(isDirectory), out _);
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
			// When nameOffset is past the end of the record, item.Length - nameOffset is negative, so the last test rejects it.
			if (nameOffset < minimum || (nameLength & 1) != 0 || nameLength > item.Length - nameOffset)
				throw new InvalidDataException("Invalid USN filename bounds.");
			FileId id = ReadId(item, 8, version);
			FileId parent = ReadId(item, version == 2 ? 16 : 24, version);
			int reasonOffset = version == 2 ? 40 : 56;
			uint attributes = BinaryPrimitives.ReadUInt32LittleEndian(item.Slice(reasonOffset + 12, 4));
			ReadOnlySpan<byte> nameBytes = item.Slice(nameOffset, nameLength);
			bool isDirectory = (attributes & DirectoryAttribute) != 0;
			if (initialEnumeration) UpsertUsn(id, parent, nameBytes, isDirectory);
			// Initial enumeration has no change reason to read.
			else ApplyUsn(id, parent, nameBytes, isDirectory, BinaryPrimitives.ReadUInt32LittleEndian(item.Slice(reasonOffset, 4)));
			buffer = buffer[(int)length..];
		}
	}

	private static FileId ReadId(ReadOnlySpan<byte> bytes, int offset, ushort version) =>
		new(BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(offset, 8)),
			version == 3 ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(offset + 8, 8)) : 0);

	private static Win32Exception Error(string operation) => new(Marshal.GetLastPInvokeError(), operation);

	// Safe to call more than once: every step below leaves the index in a state that repeating it does not change.
	public void Dispose()
	{
		// A disposed request index may remain referenced by the listener's async state.
		// Release its index memory and managed payload as well as its native handle.
		wideEntries?.Clear();
		wideEntries = null;
		ntfsEntries?.Clear();
		ntfsEntries = null;
		nameArena.Clear();
		refreshBuffer = null;
		// The constructor never keeps a zero handle, so only the invalid value marks a closed one.
		if (volume != InvalidHandleValue)
		{
			_ = NativeMethods.CloseHandle(volume);
			volume = InvalidHandleValue;
		}
	}
}
