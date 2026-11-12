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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace HardenSystemSecurity.DNS;

/// <summary>
/// Caches DNS responses for as long as their records may be kept (RFC 1035, RFC 2181, RFC 2308), so repeated queries
/// of the local devices are answered right away instead of waiting for an upstream resolver.
/// A response served from the cache gets the transaction ID and the letter case of the new query,
/// and every TTL in it is reduced by the time the response has spent in the cache.
/// </summary>
internal sealed class DnsResponseCache
{
	/// <summary>
	/// The most responses that are kept. It bounds the memory when clients query endless random names.
	/// </summary>
	private const int MaximumEntries = 4096;

	private const ushort SoaRecordType = 6;
	private const ushort SigRecordType = 24;
	private const ushort OptRecordType = 41;
	private const ushort TsigRecordType = 250;

	/// <summary>
	/// Records with longer TTLs are still refreshed after this time, so a changed record is picked up within an hour.
	/// </summary>
	private static readonly TimeSpan MaximumPositiveLifetime = TimeSpan.FromHours(1);

	/// <summary>
	/// Negative answers (a name or a record type that does not exist) are kept for a short time only,
	/// so a record that is created afterwards is found quickly.
	/// </summary>
	private static readonly TimeSpan MaximumNegativeLifetime = TimeSpan.FromMinutes(5);

	private readonly ConcurrentDictionary<string, Entry> Entries = new(StringComparer.Ordinal);

	/// <summary>
	/// Removes every cached response.
	/// </summary>
	internal void Clear() => Entries.Clear();

	/// <summary>
	/// Calculates how long <paramref name="response"/> to <paramref name="request"/> may be kept, and caches it under
	/// <paramref name="key"/> when the key is not null and the lifetime is not zero.
	/// Only complete responses with NOERROR or NXDOMAIN that belong to the query are cached.
	/// </summary>
	/// <param name="negativeLifetimeWithoutSoa">How long a negative answer without an SOA record is kept. RFC 2308 Section 5 says that it must not be cached, which is zero.</param>
	/// <returns>The time the response may be kept, which is also its freshness lifetime for HTTP caches. Zero when it must not be cached.</returns>
	internal TimeSpan Store(string? key, ReadOnlySpan<byte> request, in DnsQuery query, byte[] response, TimeSpan negativeLifetimeWithoutSoa)
	{
		if (!TryReadLifetime(request, query, response, negativeLifetimeWithoutSoa, out TimeSpan lifetime, out int[] ttlOffsets) || lifetime <= TimeSpan.Zero)
		{
			return TimeSpan.Zero;
		}
		if (key is not null)
		{
			if (Entries.Count >= MaximumEntries)
			{
				RemoveExpiredEntries();
			}
			uint[] ttls = new uint[ttlOffsets.Length];
			for (int index = 0; index < ttlOffsets.Length; index++)
			{
				ttls[index] = BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(ttlOffsets[index]));
			}

			// A copy is kept so that the caller can still change or send its response.
			Entries[key] = new Entry(response.AsSpan().ToArray(), ttlOffsets, ttls, Stopwatch.GetTimestamp(), lifetime);
		}
		return lifetime;
	}

	/// <summary>
	/// Returns a cached response for <paramref name="request"/>, adjusted to the request, when one is cached under <paramref name="key"/> and still valid.
	/// </summary>
	/// <param name="remainingLifetime">How much longer the cached response is valid.</param>
	internal bool TryGet(string key, ReadOnlySpan<byte> request, in DnsQuery query, [NotNullWhen(true)] out byte[]? response, out TimeSpan remainingLifetime)
	{
		response = null;
		remainingLifetime = TimeSpan.Zero;
		if (!Entries.TryGetValue(key, out Entry? entry))
		{
			return false;
		}
		TimeSpan age = Stopwatch.GetElapsedTime(entry.CreatedTimestamp);
		if (age >= entry.Lifetime)
		{
			// Only this expired entry is removed, never a newer one that another query stored in the meantime.
			_ = Entries.TryRemove(KeyValuePair.Create(key, entry));
			return false;
		}
		byte[] adjusted = entry.Response.AsSpan().ToArray();
		request[..2].CopyTo(adjusted);

		// The question is echoed with the letter case of this query, which clients that randomize the case verify.
		request[DnsMessage.HeaderLength..query.QuestionEndOffset].CopyTo(adjusted.AsSpan(DnsMessage.HeaderLength));
		uint elapsedSeconds = (uint)age.TotalSeconds;
		for (int index = 0; index < entry.TtlOffsets.Length; index++)
		{
			uint ttl = entry.Ttls[index];
			BinaryPrimitives.WriteUInt32BigEndian(adjusted.AsSpan(entry.TtlOffsets[index]), ttl > elapsedSeconds ? ttl - elapsedSeconds : 0);
		}
		response = adjusted;
		remainingLifetime = entry.Lifetime - age;
		return true;
	}

	/// <summary>
	/// Validates the response and reads the offsets of its TTLs and the time it may be kept.
	/// </summary>
	private static bool TryReadLifetime(ReadOnlySpan<byte> request, in DnsQuery query, ReadOnlySpan<byte> response, TimeSpan negativeLifetimeWithoutSoa, out TimeSpan lifetime, out int[] ttlOffsets)
	{
		lifetime = TimeSpan.Zero;
		ttlOffsets = [];
		if (response.Length < query.QuestionEndOffset)
		{
			return false;
		}

		// Only a complete response (QR set, TC clear) to a standard query with NOERROR or NXDOMAIN is cached.
		int flags = BinaryPrimitives.ReadUInt16BigEndian(response[2..]);
		int responseCode = flags & 0x0F;
		if ((flags & 0x8000) == 0 ||
			(flags & 0x7800) != 0 ||
			(flags & 0x0200) != 0 ||
			responseCode is not (0 or 3) ||
			BinaryPrimitives.ReadUInt16BigEndian(response[4..]) != 1 ||
			!DnsMessage.QuestionEquals(request, response, query.QuestionEndOffset))
		{
			return false;
		}
		int answerCount = BinaryPrimitives.ReadUInt16BigEndian(response[6..]);
		int authorityCount = BinaryPrimitives.ReadUInt16BigEndian(response[8..]);
		int recordCount = answerCount + authorityCount + BinaryPrimitives.ReadUInt16BigEndian(response[10..]);
		List<int> offsets = new(recordCount);
		uint minimumTtl = uint.MaxValue;
		uint? negativeTtl = null;
		int offset = query.QuestionEndOffset;
		for (int index = 0; index < recordCount; index++)
		{
			if (!DnsMessage.TrySkipName(response, ref offset) || offset + 10 > response.Length)
			{
				return false;
			}
			ushort type = BinaryPrimitives.ReadUInt16BigEndian(response[offset..]);
			uint ttl = BinaryPrimitives.ReadUInt32BigEndian(response[(offset + 4)..]);
			int dataLength = BinaryPrimitives.ReadUInt16BigEndian(response[(offset + 8)..]);
			int dataOffset = offset + 10;
			if (dataOffset + dataLength > response.Length)
			{
				return false;
			}

			// A signed response belongs to the client that asked for the signature.
			if (type is SigRecordType or TsigRecordType)
			{
				return false;
			}

			// The TTL field of an OPT record holds the extended flags instead of a TTL.
			if (type != OptRecordType)
			{
				// A TTL with the most significant bit set is treated as zero (RFC 2181 Section 8).
				uint effectiveTtl = ttl > int.MaxValue ? 0 : ttl;
				minimumTtl = Math.Min(minimumTtl, effectiveTtl);
				offsets.Add(offset + 4);

				// The SOA record of the authority section limits how long a negative answer is kept (RFC 2308 Section 5).
				// Its MINIMUM field is the last 4 bytes of its data, after two names of at least one byte and four other 32-bit fields.
				if (type == SoaRecordType && index >= answerCount && index < answerCount + authorityCount && dataLength >= 22)
				{
					uint soaMinimum = BinaryPrimitives.ReadUInt32BigEndian(response[(dataOffset + dataLength - 4)..]);
					negativeTtl = Math.Min(effectiveTtl, soaMinimum > int.MaxValue ? 0 : soaMinimum);
				}
			}
			offset = dataOffset + dataLength;
		}
		if (offset != response.Length)
		{
			return false;
		}

		// NXDOMAIN, and NOERROR without answers (NODATA), are negative answers.
		if (responseCode == 3 || answerCount == 0)
		{
			TimeSpan negativeLifetime = negativeTtl is uint soaTtl ? TimeSpan.FromSeconds(soaTtl) : negativeLifetimeWithoutSoa;
			if (minimumTtl != uint.MaxValue && TimeSpan.FromSeconds(minimumTtl) < negativeLifetime)
			{
				negativeLifetime = TimeSpan.FromSeconds(minimumTtl);
			}
			lifetime = negativeLifetime < MaximumNegativeLifetime ? negativeLifetime : MaximumNegativeLifetime;
		}
		else
		{
			TimeSpan positiveLifetime = TimeSpan.FromSeconds(minimumTtl);
			lifetime = positiveLifetime < MaximumPositiveLifetime ? positiveLifetime : MaximumPositiveLifetime;
		}
		ttlOffsets = [.. offsets];
		return true;
	}

	/// <summary>
	/// Removes the expired responses. When every response is still valid, the cache starts over,
	/// which bounds its memory without tracking how often every response is used.
	/// </summary>
	private void RemoveExpiredEntries()
	{
		foreach (KeyValuePair<string, Entry> pair in Entries)
		{
			if (Stopwatch.GetElapsedTime(pair.Value.CreatedTimestamp) >= pair.Value.Lifetime)
			{
				_ = Entries.TryRemove(pair);
			}
		}
		if (Entries.Count >= MaximumEntries)
		{
			Entries.Clear();
		}
	}

	/// <summary>
	/// A cached response with the offsets and the original values of its TTLs.
	/// </summary>
	private sealed class Entry(byte[] response, int[] ttlOffsets, uint[] ttls, long createdTimestamp, TimeSpan lifetime)
	{
		internal readonly byte[] Response = response;
		internal readonly int[] TtlOffsets = ttlOffsets;
		internal readonly uint[] Ttls = ttls;
		internal readonly long CreatedTimestamp = createdTimestamp;
		internal readonly TimeSpan Lifetime = lifetime;
	}
}
