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
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;

namespace HardenSystemSecurity.DNS;

/// <summary>
/// A regular (unencrypted) DNS server for local devices. It listens on UDP and TCP port 53 of the selected adapter.
/// Without Tor, every query is forwarded unchanged to the upstream DNS servers: the DNS servers of a destination
/// adapter, through that adapter, or DNS servers entered by the user, through the system's routing.
/// With Tor, the queries are resolved by the DNS port of the shared Tor session, so the resolvers on the Internet
/// never see the address of this network. Tor only resolves A, AAAA and PTR queries; every other query type is
/// then answered with an empty response.
/// The responses are cached for as long as their records may be kept, so repeated queries are answered right away.
/// </summary>
internal static class DnsServer
{
	private const int DnsPort = 53;
	private const int MaximumDnsMessageSize = 65535;

	/// <summary>
	/// The largest UDP response sent to a client that did not announce a larger size with EDNS (RFC 1035 Section 4.2.1).
	/// </summary>
	private const int ClassicUdpResponseSize = 512;

	/// <summary>
	/// Queries that are resolved at the same time; more queries than this are dropped and the clients retry them.
	/// </summary>
	private const int MaximumConcurrentQueries = 256;

	/// <summary>
	/// Resolving through Tor takes longer than a direct query, because the request travels through a circuit to an exit relay.
	/// </summary>
	private static readonly TimeSpan TorResolveTimeout = TimeSpan.FromSeconds(20);

	/// <summary>
	/// The time one upstream DNS server gets to answer before the next upstream server is tried.
	/// </summary>
	private static readonly TimeSpan UpstreamAttemptTimeout = TimeSpan.FromSeconds(3);

	private static readonly TimeSpan TcpClientIdleTimeout = TimeSpan.FromSeconds(30);

	/// <summary>
	/// Tor's negative answers have no SOA record that tells how long they may be kept, so they are kept for this time.
	/// </summary>
	private static readonly TimeSpan TorNegativeCacheLifetime = TimeSpan.FromSeconds(30);

	private static readonly DnsResponseCache Cache = new();

	/// <summary>
	/// The query counts of the current run, which the DNS page displays.
	/// </summary>
	internal static readonly DnsQueryCounters Statistics = new();

	// Limits the queries that are resolved at the same time, across the UDP and the TCP listener.
	private static readonly SemaphoreSlim ConcurrentQueries = new(MaximumConcurrentQueries, MaximumConcurrentQueries);
	private static Action<string>? LogSink;

	// The configuration of the current run. Only one instance of the server runs at a time.
	private static bool UseTor;
	private static IPAddress[] UpstreamServers = [];
	private static IPAddress? OutboundAddress;
	private static DnsDomainLog? DomainLog;

	// The upstream server that answered last, which is asked first, so a server that does not respond
	// does not delay every query by the time it gets to answer.
	private static int PreferredUpstreamIndex;

	// 1 once the hint about upstream servers that never respond was logged, so it is logged once per run.
	private static int UnreachableHintLogged;

	/// <summary>
	/// Runs the DNS server until <paramref name="cancellationToken"/> is canceled or one of the listeners fails.
	/// With <paramref name="useTor"/>, Tor must have been initialized with <see cref="TorSessionManager.InitializeAsync"/> first;
	/// otherwise the queries are forwarded to <paramref name="upstreamServers"/>.
	/// The name of every query is counted in <paramref name="domainLog"/> when one is supplied.
	/// </summary>
	/// <param name="outboundAddress">
	/// The address of the adapter that the queries to the upstream servers are sent from, or null to let the system's routing choose it.
	/// A VPN that blocks DNS traffic to every server but its own is passed by sending the queries from its adapter to its DNS servers.
	/// </param>
	internal static async Task RunAsync(
		Action<string> logSink,
		IPAddress listenerAddress,
		bool useTor,
		IPAddress[] upstreamServers,
		IPAddress? outboundAddress,
		DnsDomainLog? domainLog,
		CancellationToken cancellationToken)
	{
		if (useTor && !TorSessionManager.IsReady)
		{
			throw new InvalidOperationException("Initialize Tor before starting the DNS server with Tor.");
		}

		// An upstream server that is this server itself would send every query back to it in an endless loop,
		// and a socket bound to the outbound address can only reach servers of the same address family.
		IPAddress[] usableUpstreamServers = [.. upstreamServers.Where(address =>
			!address.Equals(listenerAddress) &&
			(outboundAddress is null || address.AddressFamily == outboundAddress.AddressFamily))];
		if (!useTor && usableUpstreamServers.Length == 0)
		{
			throw new InvalidOperationException(outboundAddress is null
				? "Enter at least one upstream DNS server other than the listener address."
				: "The selected destination adapter has no DNS servers that can be used.");
		}
		LogSink = logSink;
		UseTor = useTor;
		UpstreamServers = usableUpstreamServers;
		OutboundAddress = useTor ? null : outboundAddress;
		DomainLog = domainLog;
		_ = Interlocked.Exchange(ref PreferredUpstreamIndex, 0);
		_ = Interlocked.Exchange(ref UnreachableHintLogged, 0);
		Statistics.Reset();
		Cache.Clear();

		// A linked token lets a failing listener stop the other one, so a port that is already in use is reported right away.
		using CancellationTokenSource listenersCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		Task[] listeners =
		[
			RunUdpAsync(listenerAddress, listenersCancellation.Token),
			RunTcpAsync(listenerAddress, listenersCancellation.Token)
		];
		WriteLine(useTor
			? $"DNS SERVER READY listener={listenerAddress}:{DnsPort} protocols=UDP,TCP route=Tor torDns=127.0.0.1:{TorSessionManager.DnsPort} supportedTypes=A,AAAA,PTR cache=on domainLog={domainLog?.FilePath ?? "off"}"
			: $"DNS SERVER READY listener={listenerAddress}:{DnsPort} protocols=UDP,TCP route=direct upstreams={string.Join(',', usableUpstreamServers.Select(static address => address.ToString()))} outbound={OutboundAddress?.ToString() ?? "system-routing"} cache=on domainLog={domainLog?.FilePath ?? "off"}");
		try
		{
			_ = await Task.WhenAny(listeners);
			await listenersCancellation.CancelAsync();
			try
			{
				await Task.WhenAll(listeners);
			}
			catch (Exception)
			{
				// Inspected below so that the first real listener failure is reported instead of a cancellation.
			}
			foreach (Task listener in listeners)
			{
				if (listener.IsFaulted && listener.Exception?.InnerException is Exception listenerException)
				{
					WriteLine($"Fatal error: {listenerException}");
					ExceptionDispatchInfo.Throw(listenerException);
				}
			}
			cancellationToken.ThrowIfCancellationRequested();
		}
		finally
		{
			DomainLog = null;

			// The cached responses are not needed anymore, and the next run starts with an empty cache.
			Cache.Clear();
			DnsQueryStatistics statistics = Statistics.Snapshot();
			WriteLine($"DNS SERVER STOPPED queries={statistics.Total} cacheHits={statistics.CacheHits} failed={statistics.Failed} clients={statistics.Clients}");
		}
	}

	private static async Task RunUdpAsync(IPAddress address, CancellationToken cancellationToken)
	{
		using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

		// A response sent to a client that already went away must not stop the listener with a ConnectionReset error.
		SmartDNSEngine.DisableUdpConnectionReset(socket);
		socket.Bind(new IPEndPoint(address, DnsPort));

		// Started request handlers are tracked so that every handler that uses the listener socket
		// completes before the socket is disposed when the server loop ends.
		List<Task> handlers = [];
		byte[] buffer = GC.AllocateUninitializedArray<byte>(MaximumDnsMessageSize);
		try
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				SocketReceiveFromResult received;
				try
				{
					received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), cancellationToken);
				}
				catch (SocketException exception) when (exception.SocketErrorCode is SocketError.ConnectionReset or SocketError.NetworkReset or SocketError.MessageSize)
				{
					// An error reported for one datagram must not stop the listener.
					continue;
				}
				if (received.RemoteEndPoint is not IPEndPoint client || !SmartDNSEngine.IsLocalClient(client.Address))
				{
					WriteLine($"Rejected DNS client {received.RemoteEndPoint}");
					continue;
				}
				if (!await ConcurrentQueries.WaitAsync(TimeSpan.Zero, cancellationToken))
				{
					// Too many queries are in flight; the client retries the dropped query.
					continue;
				}
				byte[] request = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
				_ = handlers.RemoveAll(static handler => handler.IsCompleted);

				// The socket is captured through this local function's closure instead of being passed as an
				// explicit argument to the fire-and-forget call.
				async Task HandleDatagramAsync()
				{
					try
					{
						byte[]? response = await CreateResponseAsync(request, client, false, cancellationToken);
						if (response is not null)
						{
							_ = await socket.SendToAsync(response, SocketFlags.None, client, cancellationToken);
						}
					}
					catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
					{
					}
					catch (Exception exception)
					{
						// A failing query must never stop the listener.
						WriteLine($"DNS SERVER UDP error for {client}: {exception.Message}");
					}
					finally
					{
						_ = ConcurrentQueries.Release();
					}
				}
				handlers.Add(HandleDatagramAsync());
			}
		}
		finally
		{
			await Task.WhenAll(handlers);
		}
	}

	private static async Task RunTcpAsync(IPAddress address, CancellationToken cancellationToken)
	{
		using TcpListener listener = new(address, DnsPort);
		listener.Start();

		// Accepted clients are handled concurrently, and every handler is awaited before the listener is disposed.
		List<Task> handlers = [];
		try
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				TcpClient client = await listener.AcceptTcpClientAsync(cancellationToken);
				_ = handlers.RemoveAll(static handler => handler.IsCompleted);

				// The accepted client is captured through this local function's closure instead of being passed
				// as an explicit argument to the fire-and-forget call.
				async Task HandleClientAsync() => await HandleTcpClientAsync(client, cancellationToken);
				handlers.Add(HandleClientAsync());
			}
		}
		finally
		{
			listener.Stop();
			await Task.WhenAll(handlers);
		}
	}

	private static async Task HandleTcpClientAsync(TcpClient client, CancellationToken cancellationToken)
	{
		using (client)
		{
			EndPoint? remoteEndPoint = client.Client.RemoteEndPoint;

			// Cancels the read of the next query when the client keeps the connection open without sending one.
			using CancellationTokenSource idleTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			try
			{
				if (remoteEndPoint is not IPEndPoint remote || !SmartDNSEngine.IsLocalClient(remote.Address))
				{
					WriteLine($"Rejected TCP DNS client {remoteEndPoint}");
					return;
				}
				NetworkStream stream = client.GetStream();
				byte[] lengthBuffer = new byte[2];
				while (true)
				{
					idleTimeout.CancelAfter(TcpClientIdleTimeout);
					if (!await SmartDNSEngine.ReadExactlyOrEofAsync(stream, lengthBuffer, idleTimeout.Token))
					{
						return;
					}
					int requestLength = BinaryPrimitives.ReadUInt16BigEndian(lengthBuffer);
					if (requestLength < DnsMessage.HeaderLength)
					{
						throw new InvalidDataException("Invalid DNS-over-TCP message length.");
					}
					byte[] request = GC.AllocateUninitializedArray<byte>(requestLength);
					if (!await SmartDNSEngine.ReadExactlyOrEofAsync(stream, request, idleTimeout.Token))
					{
						throw new EndOfStreamException("Truncated DNS-over-TCP request.");
					}

					// The idle timer is stopped while the query is resolved, which can take longer than the idle timeout.
					idleTimeout.CancelAfter(Timeout.InfiniteTimeSpan);
					await ConcurrentQueries.WaitAsync(cancellationToken);
					byte[]? response;
					try
					{
						response = await CreateResponseAsync(request, remote, true, cancellationToken);
					}
					finally
					{
						_ = ConcurrentQueries.Release();
					}
					if (response is null)
					{
						return;
					}
					BinaryPrimitives.WriteUInt16BigEndian(lengthBuffer, checked((ushort)response.Length));
					await stream.WriteAsync(lengthBuffer, cancellationToken);
					await stream.WriteAsync(response, cancellationToken);
				}
			}
			catch (OperationCanceledException)
			{
				// The server is stopping or the client was idle for too long.
			}
			catch (Exception exception) when (exception is IOException or SocketException or InvalidDataException)
			{
				WriteLine($"DNS SERVER TCP error for {remoteEndPoint}: {exception.Message}");
			}
		}
	}

	// Creates the response for one query, or null when the request must not be answered.
	private static async Task<byte[]?> CreateResponseAsync(byte[] request, IPEndPoint client, bool tcp, CancellationToken cancellationToken)
	{
		if (!DnsMessage.TryParseQuery(request, out DnsQuery query))
		{
			// A malformed query gets FORMERR and another operation, such as a dynamic update, gets NOTIMP,
			// so the client stops waiting instead of retrying (RFC 1035 Section 4.1.1).
			byte[]? errorResponse = DnsMessage.TryBuildErrorResponse(request);
			if (errorResponse is not null)
			{
				Statistics.RecordQuery(client.Address);
				Statistics.RecordFailure();
				WriteLine($"DNS QUERY {client} -> rcode={DnsMessage.GetResponseCodeName(DnsMessage.GetResponseCode(errorResponse))} reason=not-a-standard-query bytes={request.Length}");
			}
			return errorResponse;
		}
		Statistics.RecordQuery(client.Address);
		DomainLog?.Record(query.Name);
		byte[] response = UseTor
			? await ResolveThroughTorAsync(request, query, client, cancellationToken)
			: await ResolveDirectAsync(request, query, client, tcp, cancellationToken);

		// NXDOMAIN is a valid answer; every other error code means that the client did not get an answer.
		if (DnsMessage.GetResponseCode(response) is not (0 or 3))
		{
			Statistics.RecordFailure();
		}
		return FitUdpResponse(request, query, response, tcp);
	}

	// Answers the query from the cache, or forwards the complete query to the upstream servers over the transport the
	// client used and returns the first valid response. Every record type, EDNS option and DNSSEC flag reaches the
	// upstream server unchanged, and its response is returned unchanged, so the client gets exactly what the upstream server answers.
	private static async Task<byte[]> ResolveDirectAsync(byte[] request, DnsQuery query, IPEndPoint client, bool tcp, CancellationToken cancellationToken)
	{
		string typeName = DnsMessage.GetTypeName(query.Type);
		string? cacheKey = query.IsCacheable ? query.CacheKey : null;
		if (cacheKey is not null && Cache.TryGet(cacheKey, request, query, out byte[]? cachedResponse, out _))
		{
			Statistics.RecordCacheHit();
			WriteLine($"DNS QUERY {client} {typeName} {query.Name} -> rcode={DnsMessage.GetResponseCodeName(DnsMessage.GetResponseCode(cachedResponse))} answers={DnsMessage.GetAnswerCount(cachedResponse)} route=cache");
			return cachedResponse;
		}
		long started = Stopwatch.GetTimestamp();
		IPAddress[] upstreamServers = UpstreamServers;
		int preferredIndex = Volatile.Read(ref PreferredUpstreamIndex);
		string failures = string.Empty;
		bool everyAttemptTimedOut = upstreamServers.Length != 0;
		for (int attempt = 0; attempt < upstreamServers.Length; attempt++)
		{
			int index = (preferredIndex + attempt) % upstreamServers.Length;
			IPAddress upstreamServer = upstreamServers[index];
			string failure;
			try
			{
				byte[] response = await ForwardToUpstreamServerAsync(request, query, upstreamServer, tcp, cancellationToken);
				Volatile.Write(ref PreferredUpstreamIndex, index);
				if (cacheKey is not null)
				{
					_ = Cache.Store(cacheKey, request, query, response, TimeSpan.Zero);
				}
				WriteLine($"DNS QUERY {client} {typeName} {query.Name} -> rcode={DnsMessage.GetResponseCodeName(DnsMessage.GetResponseCode(response))} answers={DnsMessage.GetAnswerCount(response)} route=direct upstream={upstreamServer} transport={(tcp ? "TCP" : "UDP")} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F0}");
				return response;
			}
			catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
			{
				throw;
			}
			catch (OperationCanceledException)
			{
				failure = $"{upstreamServer}:no-response-within-{UpstreamAttemptTimeout.TotalSeconds:F0}s";
			}
			catch (Exception exception) when (exception is SocketException or IOException or InvalidDataException)
			{
				// The next upstream server is tried.
				everyAttemptTimedOut = false;
				failure = $"{upstreamServer}:{exception.GetType().Name}:{exception.Message}";
			}
			failures = failures.Length == 0 ? failure : $"{failures}; {failure}";
		}
		if (everyAttemptTimedOut && Interlocked.Exchange(ref UnreachableHintLogged, 1) == 0)
		{
			WriteLine(OutboundAddress is null
				? "DNS SERVER HINT No upstream DNS server responded. A VPN or a firewall may block DNS traffic on port 53 to every server except its own. Select the destination adapter as the source of the upstream DNS servers and choose the VPN's adapter."
				: $"DNS SERVER HINT No DNS server of the destination adapter responded through {OutboundAddress}. Make sure the adapter is connected, or select another destination adapter.");
		}

		// Server failure (RCODE 2) lets the client retry or use its next DNS server.
		WriteLine($"DNS QUERY {client} {typeName} {query.Name} -> rcode=SERVFAIL route=direct transport={(tcp ? "TCP" : "UDP")} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F0} error={(failures.Length == 0 ? "no-upstream-server" : failures)}");
		return DnsMessage.BuildEmptyResponse(request, query, DnsMessage.ServerFailure);
	}

	// Sends the query to one upstream server and returns its response.
	private static async Task<byte[]> ForwardToUpstreamServerAsync(byte[] request, DnsQuery query, IPAddress upstreamServer, bool tcp, CancellationToken cancellationToken)
	{
		using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		timeout.CancelAfter(UpstreamAttemptTimeout);
		return tcp
			? await ForwardOverTcpAsync(request, query, upstreamServer, timeout.Token)
			: await ForwardOverUdpAsync(request, query, upstreamServer, timeout.Token);
	}

	private static async Task<byte[]> ForwardOverUdpAsync(byte[] request, DnsQuery query, IPAddress upstreamServer, CancellationToken cancellationToken)
	{
		// A socket of its own gives every query a random source port, and connecting it makes the system
		// discard datagrams that do not come from the upstream server.
		using Socket socket = new(upstreamServer.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
		if (OutboundAddress is IPAddress outboundAddress)
		{
			// Binding the socket to the destination adapter's address sends the query through that adapter.
			socket.Bind(new IPEndPoint(outboundAddress, 0));
		}
		await socket.ConnectAsync(new IPEndPoint(upstreamServer, DnsPort), cancellationToken);
		_ = await socket.SendAsync(request, SocketFlags.None, cancellationToken);
		byte[] buffer = GC.AllocateUninitializedArray<byte>(MaximumDnsMessageSize);
		while (true)
		{
			int received = await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken);

			// A datagram that does not answer this query is ignored and the real response is still awaited.
			if (IsResponseToQuery(request, query, buffer.AsSpan(0, received)))
			{
				return buffer.AsSpan(0, received).ToArray();
			}
		}
	}

	private static async Task<byte[]> ForwardOverTcpAsync(byte[] request, DnsQuery query, IPAddress upstreamServer, CancellationToken cancellationToken)
	{
		using TcpClient client = new(upstreamServer.AddressFamily) { NoDelay = true };
		if (OutboundAddress is IPAddress outboundAddress)
		{
			// Binding the socket to the destination adapter's address sends the query through that adapter.
			client.Client.Bind(new IPEndPoint(outboundAddress, 0));
		}
		await client.ConnectAsync(upstreamServer, DnsPort, cancellationToken);
		NetworkStream stream = client.GetStream();

		// DNS over TCP prefixes every message with its length (RFC 1035 Section 4.2.2).
		byte[] lengthPrefix = new byte[2];
		BinaryPrimitives.WriteUInt16BigEndian(lengthPrefix, checked((ushort)request.Length));
		await stream.WriteAsync(lengthPrefix, cancellationToken);
		await stream.WriteAsync(request, cancellationToken);
		await stream.ReadExactlyAsync(lengthPrefix, cancellationToken);
		byte[] response = GC.AllocateUninitializedArray<byte>(BinaryPrimitives.ReadUInt16BigEndian(lengthPrefix));
		await stream.ReadExactlyAsync(response, cancellationToken);
		if (!IsResponseToQuery(request, query, response))
		{
			throw new InvalidDataException("The upstream DNS server returned a response that does not match the query.");
		}
		return response;
	}

	// A response belongs to the query when it has the query's transaction ID, the QR flag, and the query's question.
	// Some servers return errors such as FORMERR without the question, which are accepted too.
	private static bool IsResponseToQuery(ReadOnlySpan<byte> request, in DnsQuery query, ReadOnlySpan<byte> response) =>
		response.Length >= DnsMessage.HeaderLength &&
		response[..2].SequenceEqual(request[..2]) &&
		(response[2] & 0x80) != 0 &&
		(BinaryPrimitives.ReadUInt16BigEndian(response[4..]) == 0 || DnsMessage.QuestionEquals(request, response, query.QuestionEndOffset));

	// Answers the query from the cache or through the DNS port of the Tor session.
	private static async Task<byte[]> ResolveThroughTorAsync(byte[] request, DnsQuery query, IPEndPoint client, CancellationToken cancellationToken)
	{
		string typeName = DnsMessage.GetTypeName(query.Type);
		if (query.Class != 1 || query.Type is not (1 or 28 or 12))
		{
			// Tor cannot resolve this query type, so the client is told that the name has no record of that type.
			WriteLine($"DNS QUERY {client} {typeName} {query.Name} -> rcode=NOERROR answers=0 route=Tor reason=type-not-supported-by-tor");
			return DnsMessage.BuildEmptyResponse(request, query, 0);
		}

		// Tor's response only depends on the name, the type and the class, never on the flags or the EDNS options of the query.
		string cacheKey = $"tor:{query.Type}:{query.Class}:{query.WireName}";
		if (Cache.TryGet(cacheKey, request, query, out byte[]? cachedResponse, out _))
		{
			Statistics.RecordCacheHit();
			byte[] adaptedCachedResponse = AdaptTorResponse(request, query, cachedResponse);
			WriteLine($"DNS QUERY {client} {typeName} {query.Name} -> rcode={DnsMessage.GetResponseCodeName(DnsMessage.GetResponseCode(adaptedCachedResponse))} answers={DnsMessage.GetAnswerCount(adaptedCachedResponse)} route=cache");
			return adaptedCachedResponse;
		}
		long started = Stopwatch.GetTimestamp();
		byte[] response;
		try
		{
			response = await QueryTorAsync(request, query, cancellationToken);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception exception) when (exception is SocketException or OperationCanceledException or InvalidDataException)
		{
			// Server failure (RCODE 2) lets the client retry or use its next DNS server.
			WriteLine($"DNS QUERY {client} {typeName} {query.Name} -> rcode=SERVFAIL route=Tor durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F0} error={exception.GetType().Name}:{exception.Message}");
			return DnsMessage.BuildEmptyResponse(request, query, DnsMessage.ServerFailure);
		}

		// The cache keeps a copy of Tor's own response, which is adapted to every query that it answers.
		_ = Cache.Store(cacheKey, request, query, response, TorNegativeCacheLifetime);
		byte[] adaptedResponse = AdaptTorResponse(request, query, response);
		WriteLine($"DNS QUERY {client} {typeName} {query.Name} -> rcode={DnsMessage.GetResponseCodeName(DnsMessage.GetResponseCode(adaptedResponse))} answers={DnsMessage.GetAnswerCount(adaptedResponse)} route=Tor durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F0}");
		return adaptedResponse;
	}

	// Sends the question to the DNS port of the Tor session and returns Tor's response.
	private static async Task<byte[]> QueryTorAsync(byte[] request, DnsQuery query, CancellationToken cancellationToken)
	{
		// Only the header and the question are forwarded; Tor does not use EDNS or any other additional record.
		byte[] torQuery = new byte[query.QuestionEndOffset];
		request.AsSpan(0, query.QuestionEndOffset).CopyTo(torQuery);
		BinaryPrimitives.WriteUInt16BigEndian(torQuery.AsSpan(2, 2), 0x0100);
		BinaryPrimitives.WriteUInt16BigEndian(torQuery.AsSpan(6, 2), 0);
		BinaryPrimitives.WriteUInt16BigEndian(torQuery.AsSpan(8, 2), 0);
		BinaryPrimitives.WriteUInt16BigEndian(torQuery.AsSpan(10, 2), 0);
		using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		timeout.CancelAfter(TorResolveTimeout);
		using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
		socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
		await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, TorSessionManager.DnsPort), timeout.Token);
		_ = await socket.SendAsync(torQuery, SocketFlags.None, timeout.Token);
		byte[] buffer = GC.AllocateUninitializedArray<byte>(MaximumDnsMessageSize);
		int received = await socket.ReceiveAsync(buffer, SocketFlags.None, timeout.Token);
		if (received < query.QuestionEndOffset ||
			!buffer.AsSpan(0, 2).SequenceEqual(request.AsSpan(0, 2)) ||
			(buffer[2] & 0x80) == 0 ||
			BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(4, 2)) != 1 ||
			!DnsMessage.QuestionEquals(request, buffer.AsSpan(0, received), query.QuestionEndOffset))
		{
			throw new InvalidDataException("Tor returned a DNS response that does not match the query.");
		}

		// The question is echoed with the letter case the client used, which clients that randomize the case verify.
		request.AsSpan(DnsMessage.HeaderLength, query.QuestionEndOffset - DnsMessage.HeaderLength).CopyTo(buffer.AsSpan(DnsMessage.HeaderLength));
		return buffer.AsSpan(0, received).ToArray();
	}

	// Gives Tor's response the flags that belong to the client's query: the client's RD and CD flags, RA,
	// and no AD flag because Tor does not validate DNSSEC. A client that used EDNS gets an OPT record too (RFC 6891).
	private static byte[] AdaptTorResponse(ReadOnlySpan<byte> request, in DnsQuery query, byte[] response)
	{
		int torFlags = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2));
		int requestFlags = BinaryPrimitives.ReadUInt16BigEndian(request[2..]);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2), (ushort)((torFlags & ~0x0130) | (requestFlags & 0x0110) | 0x0080));
		return DnsMessage.AppendOptRecord(response, query);
	}

	// A UDP response that is larger than the client accepts is replaced by a truncated one, which makes the client retry over TCP.
	// Clients that use EDNS get up to the size they announced, but no more than the size that avoids IP fragmentation.
	private static byte[] FitUdpResponse(byte[] request, in DnsQuery query, byte[] response, bool tcp)
	{
		if (tcp)
		{
			return response;
		}
		int limit = query.HasEdns
			? Math.Clamp(query.EdnsUdpPayloadSize, ClassicUdpResponseSize, DnsMessage.AnnouncedUdpPayloadSize)
			: ClassicUdpResponseSize;
		if (response.Length <= limit)
		{
			return response;
		}
		byte[] truncated = DnsMessage.BuildEmptyResponse(request, query, DnsMessage.GetResponseCode(response));
		truncated[2] |= 0x02;
		return truncated;
	}

	private static void WriteLine(string message) => LogSink?.Invoke($"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz}] {message}");
}
