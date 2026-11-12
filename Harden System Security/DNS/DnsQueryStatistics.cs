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

using System.Collections.Concurrent;
using System.Net;
using System.Threading;

namespace HardenSystemSecurity.DNS;

/// <summary>
/// The query counts of a DNS server since it was started.
/// </summary>
/// <param name="Total">Every query that the server answered.</param>
/// <param name="CacheHits">The queries that were answered from the cache.</param>
/// <param name="Failed">The queries that were answered with an error other than NXDOMAIN, such as SERVFAIL or FORMERR, or with an HTTP error by the DoH server.</param>
/// <param name="Clients">The distinct client IP addresses that sent queries.</param>
internal readonly record struct DnsQueryStatistics(long Total, long CacheHits, long Failed, int Clients);

/// <summary>
/// Counts the queries of a DNS server. Every method can be called from any thread.
/// </summary>
internal sealed class DnsQueryCounters
{
	/// <summary>
	/// The most client addresses that are tracked, which bounds the memory of the client count.
	/// </summary>
	private const int MaximumTrackedClients = 65536;

	private readonly ConcurrentDictionary<IPAddress, byte> Clients = new();
	private long Total;
	private long CacheHits;
	private long Failed;

	/// <summary>
	/// Counts a query of the client.
	/// </summary>
	internal void RecordQuery(IPAddress? client)
	{
		_ = Interlocked.Increment(ref Total);
		if (client is null)
		{
			return;
		}

		// A dual-stack listener reports IPv4 clients as IPv4-mapped IPv6 addresses, which are the same clients.
		IPAddress address = client.IsIPv4MappedToIPv6 ? client.MapToIPv4() : client;
		if (!Clients.ContainsKey(address) && Clients.Count < MaximumTrackedClients)
		{
			_ = Clients.TryAdd(address, 0);
		}
	}

	/// <summary>
	/// Counts a query that was answered from the cache.
	/// </summary>
	internal void RecordCacheHit() => _ = Interlocked.Increment(ref CacheHits);

	/// <summary>
	/// Counts a query that was answered with an error.
	/// </summary>
	internal void RecordFailure() => _ = Interlocked.Increment(ref Failed);

	/// <summary>
	/// Returns the current counts.
	/// </summary>
	internal DnsQueryStatistics Snapshot() => new(Interlocked.Read(ref Total), Interlocked.Read(ref CacheHits), Interlocked.Read(ref Failed), Clients.Count);

	/// <summary>
	/// Sets every count back to zero, which is done when the server starts.
	/// </summary>
	internal void Reset()
	{
		_ = Interlocked.Exchange(ref Total, 0);
		_ = Interlocked.Exchange(ref CacheHits, 0);
		_ = Interlocked.Exchange(ref Failed, 0);
		Clients.Clear();
	}
}
