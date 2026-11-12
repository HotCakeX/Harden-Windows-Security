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
using System.Text;

namespace HardenSystemSecurity.DNS;

/// <summary>
/// A standard DNS query (RFC 1035) as read by <see cref="DnsMessage.TryParseQuery"/>.
/// </summary>
/// <param name="Name">The queried name for display and the domain log: the labels joined with dots, or "." for the root.</param>
/// <param name="Type">The queried record type.</param>
/// <param name="Class">The queried class.</param>
/// <param name="QuestionEndOffset">The offset right after the question, which is also the length of the header and the question.</param>
/// <param name="HasEdns">Whether the query has an EDNS OPT record (RFC 6891).</param>
/// <param name="EdnsUdpPayloadSize">The UDP payload size the client accepts according to its OPT record, at least 512.</param>
/// <param name="DnssecOk">Whether the client set the DNSSEC OK bit in its OPT record (RFC 3225).</param>
/// <param name="WireName">The queried name in its wire format, with the ASCII letters in lower case, so it is the same for every letter case of the name.</param>
/// <param name="CacheFlags">The flags of the query that change the response: RD, AD and CD from the header, and the presence of EDNS and its DO bit.</param>
/// <param name="IsCacheable">Whether a response to this query may be shared with other clients through a response cache.</param>
internal readonly record struct DnsQuery(
	string Name,
	ushort Type,
	ushort Class,
	int QuestionEndOffset,
	bool HasEdns,
	int EdnsUdpPayloadSize,
	bool DnssecOk,
	string WireName,
	int CacheFlags,
	bool IsCacheable)
{
	/// <summary>
	/// The key of the response cache for this query. Queries with the same key get the same response from a resolver.
	/// </summary>
	internal string CacheKey => $"{Type}:{Class}:{CacheFlags}:{WireName}";
}

/// <summary>
/// Reads and builds DNS messages (RFC 1035, RFC 6891) for the DNS server and the DNS over HTTPS server.
/// </summary>
internal static class DnsMessage
{
	internal const int HeaderLength = 12;

	/// <summary>
	/// The length of an OPT record without options: the root name, type, UDP payload size, extended flags and an empty RDATA.
	/// </summary>
	private const int OptRecordLength = 11;

	/// <summary>
	/// The UDP payload size that the servers announce in their OPT records, which avoids IP fragmentation (DNS Flag Day 2020).
	/// </summary>
	internal const int AnnouncedUdpPayloadSize = 1232;

	private const int MaximumWireNameLength = 255;
	private const int MaximumLabelLength = 63;
	private const ushort OptRecordType = 41;
	private const ushort PaddingOptionCode = 12;

	// Header flags (RFC 1035 Section 4.1.1, RFC 4035 Section 3.2).
	private const int ResponseFlag = 0x8000;
	private const int OpcodeMask = 0x7800;
	private const int RecursionDesiredFlag = 0x0100;
	private const int RecursionAvailableFlag = 0x0080;
	private const int AuthenticatedDataFlag = 0x0020;
	private const int CheckingDisabledFlag = 0x0010;

	internal const int ServerFailure = 2;

	/// <summary>
	/// Reads the single question and the EDNS settings of a standard query. Returns false for anything that is not a
	/// standard query (QR clear, opcode 0) with exactly one question whose name is not compressed.
	/// </summary>
	internal static bool TryParseQuery(ReadOnlySpan<byte> message, out DnsQuery query)
	{
		query = default;
		if (message.Length < HeaderLength)
		{
			return false;
		}
		int flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..]);
		if ((flags & (ResponseFlag | OpcodeMask)) != 0 || BinaryPrimitives.ReadUInt16BigEndian(message[4..]) != 1)
		{
			return false;
		}

		// The name is collected twice: once for display and once in a case-insensitive wire form for the cache key.
		Span<char> displayName = stackalloc char[MaximumWireNameLength];
		Span<char> wireName = stackalloc char[MaximumWireNameLength];
		int displayLength = 0;
		int wireLength = 0;
		int offset = HeaderLength;
		while (true)
		{
			if (offset >= message.Length)
			{
				return false;
			}

			// A query's question never uses compression pointers, and longer labels are reserved label types.
			int labelLength = message[offset];
			if (labelLength > MaximumLabelLength || wireLength + 1 + labelLength > MaximumWireNameLength || offset + 1 + labelLength > message.Length)
			{
				return false;
			}
			wireName[wireLength++] = (char)labelLength;
			offset++;
			if (labelLength == 0)
			{
				break;
			}
			if (displayLength != 0)
			{
				displayName[displayLength++] = '.';
			}
			foreach (byte character in message.Slice(offset, labelLength))
			{
				wireName[wireLength++] = (char)(character is >= (byte)'A' and <= (byte)'Z' ? character + 32 : character);

				// Bytes that can't be displayed, and dots inside a label that would look like a label separator, are shown as '?'.
				displayName[displayLength++] = character is >= 0x21 and <= 0x7E and not (byte)'.' ? (char)character : '?';
			}
			offset += labelLength;
		}
		if (offset + 4 > message.Length)
		{
			return false;
		}
		ushort type = BinaryPrimitives.ReadUInt16BigEndian(message[offset..]);
		ushort queryClass = BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 2)..]);
		int questionEndOffset = offset + 4;

		int answerCount = BinaryPrimitives.ReadUInt16BigEndian(message[6..]);
		int authorityCount = BinaryPrimitives.ReadUInt16BigEndian(message[8..]);
		int additionalCount = BinaryPrimitives.ReadUInt16BigEndian(message[10..]);

		// Zone transfers (IXFR, AXFR) and queries that carry records in the answer or authority sections are never shared.
		bool isCacheable = type is not (251 or 252) && answerCount == 0 && authorityCount == 0;
		bool hasEdns = false;
		int ednsUdpPayloadSize = 0;
		bool dnssecOk = false;
		offset = questionEndOffset;
		int recordCount = answerCount + authorityCount + additionalCount;
		for (int index = 0; index < recordCount; index++)
		{
			int nameOffset = offset;
			if (!TrySkipName(message, ref offset) || offset + 10 > message.Length)
			{
				isCacheable = false;
				break;
			}
			ushort recordType = BinaryPrimitives.ReadUInt16BigEndian(message[offset..]);
			ushort recordClass = BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 2)..]);
			uint recordTtl = BinaryPrimitives.ReadUInt32BigEndian(message[(offset + 4)..]);
			int dataLength = BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 8)..]);
			int dataOffset = offset + 10;
			if (dataOffset + dataLength > message.Length)
			{
				isCacheable = false;
				break;
			}
			offset = dataOffset + dataLength;
			if (index >= answerCount + authorityCount && recordType == OptRecordType && message[nameOffset] == 0 && !hasEdns)
			{
				hasEdns = true;

				// The class of an OPT record is the requestor's UDP payload size; values below 512 are treated as 512 (RFC 6891 Section 6.2.3).
				ednsUdpPayloadSize = Math.Max((int)recordClass, 512);
				dnssecOk = (recordTtl & 0x8000) != 0;

				// Another EDNS version than 0 must be answered by the resolver itself with BADVERS.
				if (((recordTtl >> 16) & 0xFF) != 0)
				{
					isCacheable = false;
				}

				// Options such as cookies or the client subnet make the response specific to this client; only padding does not.
				int optionOffset = dataOffset;
				while (optionOffset + 4 <= offset)
				{
					if (BinaryPrimitives.ReadUInt16BigEndian(message[optionOffset..]) != PaddingOptionCode)
					{
						isCacheable = false;
					}
					optionOffset += 4 + BinaryPrimitives.ReadUInt16BigEndian(message[(optionOffset + 2)..]);
				}
				if (optionOffset != offset)
				{
					isCacheable = false;
				}
				continue;
			}

			// Any other record, such as a second OPT record or a TSIG or SIG(0) signature, makes the query unique.
			isCacheable = false;
		}

		int cacheFlags = (flags & (RecursionDesiredFlag | AuthenticatedDataFlag | CheckingDisabledFlag)) |
			(hasEdns ? 0x10000 : 0) |
			(dnssecOk ? 0x20000 : 0);
		query = new DnsQuery(
			displayLength == 0 ? "." : new string(displayName[..displayLength]),
			type,
			queryClass,
			questionEndOffset,
			hasEdns,
			ednsUdpPayloadSize,
			dnssecOk,
			new string(wireName[..wireLength]),
			cacheFlags,
			isCacheable);
		return true;
	}

	/// <summary>
	/// Moves <paramref name="offset"/> past a possibly compressed name. Returns false when the name is truncated or uses a reserved label type.
	/// </summary>
	internal static bool TrySkipName(ReadOnlySpan<byte> message, ref int offset)
	{
		int position = offset;
		while (position < message.Length)
		{
			int labelLength = message[position];
			switch (labelLength & 0xC0)
			{
				case 0:
					if (labelLength == 0)
					{
						offset = position + 1;
						return true;
					}
					position += 1 + labelLength;
					break;
				case 0xC0:
					// A compression pointer ends the name.
					if (position + 2 > message.Length)
					{
						return false;
					}
					offset = position + 2;
					return true;
				default:
					return false;
			}
		}
		return false;
	}

	/// <summary>
	/// Compares the question of a response with the question of the request: the name without regard to the letter
	/// case of ASCII letters (RFC 4343), and the type and class exactly. Both questions end at <paramref name="questionEndOffset"/>.
	/// </summary>
	internal static bool QuestionEquals(ReadOnlySpan<byte> request, ReadOnlySpan<byte> response, int questionEndOffset)
	{
		if (request.Length < questionEndOffset || response.Length < questionEndOffset)
		{
			return false;
		}
		ReadOnlySpan<byte> requestName = request[HeaderLength..(questionEndOffset - 4)];
		ReadOnlySpan<byte> responseName = response[HeaderLength..(questionEndOffset - 4)];
		for (int index = 0; index < requestName.Length; index++)
		{
			if (ToLowerAscii(requestName[index]) != ToLowerAscii(responseName[index]))
			{
				return false;
			}
		}
		return request[(questionEndOffset - 4)..questionEndOffset].SequenceEqual(response[(questionEndOffset - 4)..questionEndOffset]);
	}

	/// <summary>
	/// Builds a response without records to a parsed query: the request's header and question with the given response code.
	/// When the client uses EDNS, the response has an OPT record too, as RFC 6891 requires.
	/// </summary>
	internal static byte[] BuildEmptyResponse(ReadOnlySpan<byte> request, in DnsQuery query, int responseCode)
	{
		byte[] response = new byte[query.QuestionEndOffset + (query.HasEdns ? OptRecordLength : 0)];
		request[..query.QuestionEndOffset].CopyTo(response);

		// QR (response) and RA (recursion available) are set, and the client's RD and CD flags are copied (RFC 1035, RFC 4035).
		int requestFlags = BinaryPrimitives.ReadUInt16BigEndian(request[2..]);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2), (ushort)(ResponseFlag | RecursionAvailableFlag | (requestFlags & (RecursionDesiredFlag | CheckingDisabledFlag)) | (responseCode & 0x0F)));
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6), 0);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(8), 0);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10), (ushort)(query.HasEdns ? 1 : 0));
		if (query.HasEdns)
		{
			WriteOptRecord(response.AsSpan(query.QuestionEndOffset), query.DnssecOk);
		}
		return response;
	}

	/// <summary>
	/// Appends an OPT record to a response that has none, for a client that used EDNS.
	/// The response is returned unchanged when it already has additional records.
	/// </summary>
	internal static byte[] AppendOptRecord(byte[] response, in DnsQuery query)
	{
		if (!query.HasEdns || response.Length < HeaderLength || BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(10)) != 0)
		{
			return response;
		}
		byte[] extended = new byte[response.Length + OptRecordLength];
		response.CopyTo(extended, 0);
		WriteOptRecord(extended.AsSpan(response.Length), query.DnssecOk);
		BinaryPrimitives.WriteUInt16BigEndian(extended.AsSpan(10), 1);
		return extended;
	}

	/// <summary>
	/// Builds the response to a request that is not a usable standard query: NOTIMP (4) for another opcode,
	/// and FORMERR (1) for a malformed query. Returns null for a message that must not be answered,
	/// which is a message too short to have a header or a message that is itself a response.
	/// </summary>
	internal static byte[]? TryBuildErrorResponse(ReadOnlySpan<byte> request)
	{
		if (request.Length < HeaderLength)
		{
			return null;
		}
		int requestFlags = BinaryPrimitives.ReadUInt16BigEndian(request[2..]);
		if ((requestFlags & ResponseFlag) != 0)
		{
			return null;
		}

		// Only the header is returned, because the question of a malformed query can't be trusted (RFC 1035 Section 4.1.1).
		byte[] response = new byte[HeaderLength];
		request[..2].CopyTo(response);
		int responseCode = (requestFlags & OpcodeMask) != 0 ? 4 : 1;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2), (ushort)(ResponseFlag | (requestFlags & (OpcodeMask | RecursionDesiredFlag)) | RecursionAvailableFlag | responseCode));
		return response;
	}

	/// <summary>
	/// The response code of a response, from its header.
	/// </summary>
	internal static int GetResponseCode(ReadOnlySpan<byte> response) => response.Length < HeaderLength ? ServerFailure : response[3] & 0x0F;

	/// <summary>
	/// The number of answer records of a response, from its header.
	/// </summary>
	internal static int GetAnswerCount(ReadOnlySpan<byte> response) => response.Length < HeaderLength ? 0 : BinaryPrimitives.ReadUInt16BigEndian(response[6..]);

	/// <summary>
	/// Returns a domain name in lower case, which is how the same name is written by every client.
	/// A name that is already in lower case is returned as is, without allocating a new string.
	/// </summary>
	internal static string ToLowerCaseName(string name) => name.AsSpan().ContainsAnyInRange('A', 'Z') || !Ascii.IsValid(name)
		? string.Create(name.Length, name, static (destination, source) => _ = source.AsSpan().ToLowerInvariant(destination))
		: name;

	/// <summary>
	/// The mnemonic of a DNS record type for the logs, or its number in the generic format of RFC 3597.
	/// </summary>
	internal static string GetTypeName(ushort type) => type switch
	{
		1 => "A",
		2 => "NS",
		5 => "CNAME",
		6 => "SOA",
		12 => "PTR",
		15 => "MX",
		16 => "TXT",
		28 => "AAAA",
		33 => "SRV",
		35 => "NAPTR",
		43 => "DS",
		46 => "RRSIG",
		47 => "NSEC",
		48 => "DNSKEY",
		50 => "NSEC3",
		52 => "TLSA",
		64 => "SVCB",
		65 => "HTTPS",
		255 => "ANY",
		257 => "CAA",
		_ => $"TYPE{type}"
	};

	/// <summary>
	/// The mnemonic of a DNS response code for the logs (RFC 1035, RFC 2136).
	/// </summary>
	internal static string GetResponseCodeName(int responseCode) => responseCode switch
	{
		0 => "NOERROR",
		1 => "FORMERR",
		2 => "SERVFAIL",
		3 => "NXDOMAIN",
		4 => "NOTIMP",
		5 => "REFUSED",
		_ => $"RCODE{responseCode}"
	};

	// Writes an OPT record without options that announces the server's UDP payload size and echoes the client's DO bit (RFC 3225).
	private static void WriteOptRecord(Span<byte> destination, bool dnssecOk)
	{
		destination[0] = 0;
		BinaryPrimitives.WriteUInt16BigEndian(destination[1..], OptRecordType);
		BinaryPrimitives.WriteUInt16BigEndian(destination[3..], AnnouncedUdpPayloadSize);
		BinaryPrimitives.WriteUInt32BigEndian(destination[5..], dnssecOk ? 0x8000u : 0u);
		BinaryPrimitives.WriteUInt16BigEndian(destination[9..], 0);
	}

	private static byte ToLowerAscii(byte value) => value is >= (byte)'A' and <= (byte)'Z' ? (byte)(value + 32) : value;
}
