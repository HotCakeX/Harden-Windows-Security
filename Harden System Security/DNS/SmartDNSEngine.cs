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

using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace HardenSystemSecurity.DNS;

/// <summary>
/// The Smart DNS engine.
/// It listens on the selected source (LAN) adapter for DNS (UDP/TCP 53), HTTP (TCP 80), TLS (TCP 443) and QUIC/HTTP3 (UDP 443) traffic from local devices,
/// answers A and HTTPS queries with the LAN listener address so that local devices connect to this machine,
/// and proxies their connections to the real destinations either through the selected destination (outbound) adapter or through Tor.
/// QUIC is relayed only for destinations that pass the QUIC safety gate; every other destination is reached over TCP.
/// </summary>
internal static class SmartDNSEngine
{
	private const int DnsPort = 53;
	private const int HttpPort = 80;
	private const int HttpsPort = 443;
	private const int MaxDnsSize = 65535;
	private const int MaxHeaderSize = 65536;
	private const int OptRecordType = 41;
	private const int OptRecordLength = 11;
	private const ushort MinimumEdnsUdpPayloadSize = 512;
	private const ushort MaximumEdnsUdpPayloadSize = 4096;
	private const int MaxUdpDatagramSize = 65535;
	private const uint QuicVersion1 = 0x00000001;
	private const uint QuicVersion2 = 0x6b3343cf;
	private const int QuicMinimumClientInitialDatagramSize = 1200;
	private const int QuicMaxConnectionIdLength = 20;
	private const int QuicAeadTagLength = 16;
	private const int QuicHeaderProtectionSampleLength = 16;

	/// <summary>
	/// Sized for multi-megabyte video bursts: at a typical 1200-1500 byte QUIC datagram size this holds
	/// several megabytes per direction, so a transient scheduling delay never turns into dropped datagrams.
	/// </summary>
	private const int QuicFlowQueueCapacity = 4096;

	private const int QuicMaxPreConnectDatagrams = 64;

	/// <summary>
	/// Upper bound of the host names remembered for the QUIC safety gate; the oldest entries are trimmed first.
	/// </summary>
	private const int MaximumClientResolvedHosts = 4096;

	/// <summary>
	/// 16 MB kernel buffers give a high bandwidth-delay-product path (a VPN exit hundreds of milliseconds
	/// away delivering multi-megabyte video bursts) enough headroom that the kernel does not silently
	/// discard datagrams while the relay is momentarily busy; the OS may grant less, which is logged.
	/// </summary>
	private const int UdpProxySocketBufferSize = 1 << 24;

	/// <summary>
	/// Queue-full drops are logged on the first occurrence and then every this many drops, keeping
	/// sustained overload loudly visible without flooding the log during a burst.
	/// </summary>
	private const int QueueDropLogInterval = 200;
	private const int MaximumDnsCacheEntries = 4096;
	private const int DnsCacheTrimTarget = 3584;

	private static readonly TimeSpan PerAddressConnectTimeout = TimeSpan.FromSeconds(5);

	/// <summary>
	/// Building a Tor circuit to a new destination routinely takes far longer than a direct TCP connect,
	/// so the SOCKS5 connect through Tor gets its own timeout instead of the per-address direct connect timeout.
	/// </summary>
	private static readonly TimeSpan TorConnectTimeout = TimeSpan.FromSeconds(60);
	private static readonly TimeSpan QuicHandshakeTimeout = TimeSpan.FromSeconds(10);

	/// <summary>
	/// Video players routinely pause QUIC connections for minutes between segment fetches, so the relay
	/// keeps quiet flows alive well past the endpoints' own keep-alive cadence before reclaiming them.
	/// </summary>
	private static readonly TimeSpan QuicIdleTimeout = TimeSpan.FromSeconds(300);

	private static readonly TimeSpan QuicIdleScanInterval = TimeSpan.FromSeconds(5);

	/// <summary>
	/// Cadence of the per-connection PROGRESS diagnostics emitted while traffic is moving.
	/// </summary>
	private static readonly TimeSpan RelayProgressInterval = TimeSpan.FromSeconds(15);

	/// <summary>
	/// An expired flow can be transparently resumed from its tombstone for this long after it closed.
	/// </summary>
	private static readonly TimeSpan QuicTombstoneLifetime = TimeSpan.FromMinutes(15);

	/// <summary>
	/// How long the certificate names of a destination are trusted before they are fetched again.
	/// </summary>
	private static readonly TimeSpan CertificateNamesLifetime = TimeSpan.FromHours(1);

	/// <summary>
	/// A destination whose certificate could not be fetched is not probed again for this long.
	/// </summary>
	private static readonly TimeSpan CertificateProbeRetryInterval = TimeSpan.FromSeconds(60);

	private static readonly TimeSpan CertificateProbeTimeout = TimeSpan.FromSeconds(3);

	/// <summary>
	/// The longest a new QUIC flow waits for the safety gate before QUIC is refused for that attempt.
	/// </summary>
	private static readonly TimeSpan QuicGateTimeout = TimeSpan.FromSeconds(5);

	/// <summary>
	/// A name that could not be resolved for the safety gate is not looked up again for this long.
	/// </summary>
	private static readonly TimeSpan ClientResolutionRetryInterval = TimeSpan.FromSeconds(60);

	/// <summary>
	/// A host name that a client resolved is considered potentially still in use by that client for this long.
	/// </summary>
	private static readonly TimeSpan ClientResolvedHostLifetime = TimeSpan.FromMinutes(30);

	/// <summary>
	/// After a QUIC flow is closed because of a conflict, the client's DNS answer is held back for this long
	/// so that the client processes the ICMP report (and drops its QUIC connection) before it can reuse that connection.
	/// It is the only time an answer is held back, and it is kept far below the time after which a resolver gives up.
	/// </summary>
	private static readonly TimeSpan QuicConflictSettleDelay = TimeSpan.FromMilliseconds(15);

	/// <summary>
	/// The shortest interval between two ICMP reports sent to the same client endpoint.
	/// </summary>
	private static readonly TimeSpan IcmpReportInterval = TimeSpan.FromMilliseconds(200);

	/// <summary>
	/// Retransmissions of a refused QUIC connection's first packet are answered with the refusal for this long.
	/// It covers the time a client keeps retransmitting when it did not receive the report.
	/// </summary>
	private static readonly TimeSpan RefusedQuicConnectionLifetime = TimeSpan.FromSeconds(30);

	/// <summary>
	/// An idle TCP connection is probed after this long, so a peer that disappeared without closing it is detected.
	/// </summary>
	private const int TcpKeepAliveTimeSeconds = 60;

	private const int TcpKeepAliveIntervalSeconds = 10;
	private const int TcpKeepAliveRetryCount = 5;

	/// <summary>
	/// An established QUIC flow survives socket errors of one direction for this long before it is closed.
	/// </summary>
	private static readonly TimeSpan QuicSocketErrorTolerance = TimeSpan.FromSeconds(15);

	private static readonly TimeSpan QuicSocketErrorRetryDelay = TimeSpan.FromMilliseconds(50);

	/// <summary>
	/// HKDF-Extract salts for deriving QUIC Initial packet protection secrets, from RFC 9001 Section 5.2 and RFC 9369 Section 3.3.1.
	/// </summary>
	private static readonly byte[] QuicVersion1InitialSalt = [0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a];

	private static readonly byte[] QuicVersion2InitialSalt = [0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9];
	private static readonly ConcurrentDictionary<IPAddress, ClientTrafficCounters> ClientTraffic = new();
	private static readonly ConcurrentDictionary<string, DnsCacheEntry> DnsAddressCache = new(StringComparer.OrdinalIgnoreCase);
	private static readonly ConcurrentDictionary<string, Lazy<Task<DnsCacheEntry>>> PendingDnsAddressQueries = new(StringComparer.OrdinalIgnoreCase);
	private static readonly Lock DnsCacheInsertionLock = new();

	/// <summary>
	/// State of the QUIC safety gate, <see cref="RegisterQuicFlowIfSafe"/>. Everything except the certificate cache is guarded by <see cref="QuicGateLock"/>.
	/// </summary>
	private static readonly ConcurrentDictionary<string, Lazy<Task<CertificateProbeResult>>> CertificateNameCache = new(StringComparer.OrdinalIgnoreCase);
	private static readonly Lock QuicGateLock = new();

	// The host names that clients resolved through this engine, with the IPv4 addresses they really live on.
	private static readonly Dictionary<string, ResolvedHost> ClientResolvedHosts = new(StringComparer.OrdinalIgnoreCase);

	// The same host names grouped by their parent domain, so the hosts covered by a wildcard certificate name are found directly.
	private static readonly Dictionary<string, List<string>> ClientResolvedHostsByParent = new(StringComparer.OrdinalIgnoreCase);

	// Parent domains of wildcard certificate names that are proven to cover hosts living on different servers.
	private static readonly HashSet<string> SharedWildcardParents = new(StringComparer.OrdinalIgnoreCase);

	// The QUIC flows that passed the safety gate and are still running.
	private static readonly List<QuicFlow> LiveQuicFlows = [];

	// Rate limiting state of the "QUIC REFUSED" log lines, keyed by client address and host name.
	private static readonly ConcurrentDictionary<string, long> QuicRefusalLogTimestamps = new(StringComparer.OrdinalIgnoreCase);

	// Names that could not be resolved for the safety gate, with the time of the failed attempt.
	private static readonly ConcurrentDictionary<string, long> FailedClientResolutions = new(StringComparer.OrdinalIgnoreCase);

	// Hosts whose servers did not answer QUIC at all, with the time of the failed attempt. HTTP/3 is not advertised
	// for them and their QUIC flows are refused right away, instead of every flow waiting for the connect timeout.
	private static readonly ConcurrentDictionary<string, long> QuicUnresponsiveHosts = new(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// How long a host stays in <see cref="QuicUnresponsiveHosts"/> before QUIC is tried with it again.
	/// </summary>
	private static readonly TimeSpan QuicUnresponsiveRetryInterval = TimeSpan.FromMinutes(10);

	// The raw socket used for ICMP reports; null when it could not be created.
	private static Socket? IcmpSocket;
	private static Action<string>? LogSink;
	private static long NextConnectionId;
	private static long TotalBytesSent;
	private static long TotalBytesReceived;
	private static int ActiveConnections;

	/// <summary>
	/// Resets the global and per-client traffic counters.
	/// Must be called before a new run is started and before the UI captures its baseline traffic snapshot,
	/// so that speed calculations of the new run start from zero instead of from the totals of the previous run.
	/// </summary>
	internal static void ResetTrafficCounters()
	{
		_ = Interlocked.Exchange(ref TotalBytesSent, 0);
		_ = Interlocked.Exchange(ref TotalBytesReceived, 0);
		ClientTraffic.Clear();
	}

	/// <summary>
	/// Runs the engine until <paramref name="cancellationToken"/> is canceled or one of the listeners fails.
	/// Listener failures (such as a port that is already in use) are logged and rethrown to the caller.
	/// With <paramref name="useTor"/>, Tor must have been initialized with <see cref="TorSessionManager.InitializeAsync"/> first.
	/// </summary>
	internal static async Task RunAsync(
		Action<string> logSink,
		NetworkAdapterOption sourceAdapter,
		NetworkAdapterOption destinationAdapter,
		bool useTor,
		bool enableUdp,
		CancellationToken cancellationToken)
	{
		LogSink = logSink;
		DnsAddressCache.Clear();
		PendingDnsAddressQueries.Clear();

		// The QUIC safety gate starts every run without knowledge from a previous run.
		CertificateNameCache.Clear();
		QuicRefusalLogTimestamps.Clear();
		FailedClientResolutions.Clear();
		QuicUnresponsiveHosts.Clear();
		lock (QuicGateLock)
		{
			ClientResolvedHosts.Clear();
			ClientResolvedHostsByParent.Clear();
			SharedWildcardParents.Clear();
			LiveQuicFlows.Clear();
		}
		using CancellationTokenRegistration shutdownRegistration = cancellationToken.Register(
			static () => WriteLine($"SERVER STOPPING activeConnections={Volatile.Read(ref ActiveConnections)}"));
		try
		{
			IPAddress lanAddress = sourceAdapter.Address;
			IPAddress outboundAddress = destinationAdapter.Address;

			// DNS servers that point back to the LAN listener itself are excluded, otherwise forwarded queries would loop back to this engine.
			IPAddress[] dnsServers = destinationAdapter.DnsServers.Where(address => !address.Equals(lanAddress)).ToArray();
			if (!useTor && dnsServers.Length == 0)
			{
				throw new InvalidOperationException($"The selected destination adapter '{destinationAdapter.Name}' has no configured IPv4 DNS servers that can be used.");
			}
			if (useTor && !TorSessionManager.IsReady)
			{
				throw new InvalidOperationException("Initialize Tor before starting the Smart DNS with the Tor outbound route.");
			}
			WriteLine($"LAN listener: {lanAddress} ({sourceAdapter.Name})");
			if (useTor)
			{
				WriteLine($"Outbound route: Tor SOCKS5 at 127.0.0.1:{TorSessionManager.SocksPort}");
				WriteLine("The LAN listener accepts local devices. TCP traffic and destination name resolution are routed through Tor.");
			}
			else
			{
				WriteLine($"Outbound adapter: {outboundAddress} ({destinationAdapter.Name})");
				WriteLine($"Destination adapter DNS servers: {string.Join(", ", dnsServers.Select(static address => address.ToString()))}");
				WriteLine("The LAN listener accepts local devices. Outbound DNS and proxy sockets are bound to the selected destination adapter.");
			}
			WriteLine(useTor || !enableUdp
				? "Allow inbound TCP 80/443 and UDP/TCP 53, then set the test device DNS to the LAN listener address."
				: "Allow inbound TCP 80/443, UDP 443, and UDP/TCP 53, then set the test device DNS to the LAN listener address.");
			WriteLine("Use the Stop button to stop.");
			WriteLine(useTor || !enableUdp
				? "SUPPORTED INBOUND APPLICATION TRAFFIC protocols=TCP ports=80,443; DNS protocols=UDP,TCP port=53; other destination ports are not intercepted by this process."
				: "SUPPORTED INBOUND APPLICATION TRAFFIC protocols=TCP ports=80,443; QUIC/HTTP3 protocol=UDP port=443; DNS protocols=UDP,TCP port=53; other destination ports are not intercepted by this process.");

			// A linked token lets a failing listener stop the remaining listeners.
			// Without it, a single listener failure (e.g. port 53 already in use) would leave the other listeners running
			// indefinitely and the error would never surface until the user manually stopped the engine.
			using CancellationTokenSource listenersCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			List<Task> listeners = new(5)
			{
				RunUdpDnsAsync(lanAddress, outboundAddress, dnsServers, useTor, enableUdp, listenersCancellation.Token),
				RunTcpDnsAsync(lanAddress, outboundAddress, dnsServers, useTor, enableUdp, listenersCancellation.Token),
				RunProxyAsync(lanAddress, outboundAddress, dnsServers, HttpPort, false, useTor, listenersCancellation.Token),
				RunProxyAsync(lanAddress, outboundAddress, dnsServers, HttpsPort, true, useTor, listenersCancellation.Token)
			};
			if (!useTor && enableUdp)
			{
				listeners.Add(RunQuicProxyAsync(lanAddress, outboundAddress, dnsServers, HttpsPort, listenersCancellation.Token));
			}

			// Whichever listener completes first (due to cancellation or failure), the rest are stopped too.
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
		}
		finally
		{
			WriteLine($"SERVER STOPPED activeConnections={Volatile.Read(ref ActiveConnections)}");
			LogSink = null;
		}
	}

	internal static TrafficSnapshot GetTrafficSnapshot()
	{
		List<ClientTrafficSnapshot> clients = new(ClientTraffic.Count);
		foreach (KeyValuePair<IPAddress, ClientTrafficCounters> pair in ClientTraffic)
		{
			ClientTrafficCounters counters = pair.Value;
			clients.Add(new ClientTrafficSnapshot(
				pair.Key,
				Interlocked.Read(ref counters.TotalBytesSent),
				Interlocked.Read(ref counters.TotalBytesReceived),
				Volatile.Read(ref counters.ActiveConnections)));
		}
		return new TrafficSnapshot(
			Interlocked.Read(ref TotalBytesSent),
			Interlocked.Read(ref TotalBytesReceived),
			Volatile.Read(ref ActiveConnections),
			clients);
	}

	internal static List<NetworkAdapterOption> GetNetworkAdapters()
	{
		NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
		List<NetworkAdapterOption> adapters = [with(networkInterfaces.Length)];
		foreach (NetworkInterface networkInterface in networkInterfaces)
		{
			if (networkInterface.OperationalStatus != OperationalStatus.Up || networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
			{
				continue;
			}
			IPInterfaceProperties properties = networkInterface.GetIPProperties();
			UnicastIPAddressInformation? preferredAddress = null;
			foreach (UnicastIPAddressInformation address in properties.UnicastAddresses)
			{
				if (address.Address.AddressFamily == AddressFamily.InterNetwork && address.AddressPreferredLifetime != 0 && address.DuplicateAddressDetectionState == DuplicateAddressDetectionState.Preferred && !IsLinkLocal(address.Address))
				{
					preferredAddress ??= address;
					if (address.PrefixOrigin == PrefixOrigin.Dhcp || address.SuffixOrigin == SuffixOrigin.OriginDhcp)
					{
						preferredAddress = address;
						break;
					}
				}
			}
			if (preferredAddress is null)
			{
				continue;
			}
			List<IPAddress> dnsServers = [with(properties.DnsAddresses.Count)];
			foreach (IPAddress dnsAddress in properties.DnsAddresses)
			{
				if (dnsAddress.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(dnsAddress))
				{
					dnsServers.Add(dnsAddress);
				}
			}
			IPv4InterfaceProperties ipv4Properties = properties.GetIPv4Properties();
			adapters.Add(new NetworkAdapterOption(
				networkInterface.Id,
				networkInterface.Name,
				networkInterface.Description,
				preferredAddress.Address,
				ipv4Properties.Index,
				dnsServers));
		}
		adapters.Sort(static (left, right) => StringComparer.OrdinalIgnoreCase.Compare(left.DisplayName, right.DisplayName));
		return adapters;
	}

	private static async Task RunUdpDnsAsync(IPAddress address, IPAddress outboundAddress, IPAddress[] dnsServers, bool useTor, bool enableUdp, CancellationToken cancellationToken)
	{
		using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

		// On Windows, an ICMP "port unreachable" received after sending a response to a client that has already gone away
		// makes the next receive operation fail with WSAECONNRESET, which would otherwise terminate the whole UDP DNS listener.
		DisableUdpConnectionReset(socket);
		socket.Bind(new IPEndPoint(address, DnsPort));
		WriteLine($"DNS UDP listening on {address}:{DnsPort}");

		// Started request handlers are tracked so that every handler that uses the listener socket
		// completes before the socket is disposed when the server loop ends.
		List<Task> handlers = [];
		try
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				byte[] buffer = GC.AllocateUninitializedArray<byte>(MaxDnsSize);

				SocketReceiveFromResult received;
				try
				{
					received = await socket.ReceiveFromAsync(
						buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), cancellationToken);
				}
				catch (SocketException exception) when (exception.SocketErrorCode == SocketError.ConnectionReset)
				{
					// Defensive: a reset reported for a previous datagram must not stop the listener.
					continue;
				}

				byte[] request = buffer.AsSpan(0, received.ReceivedBytes).ToArray();

				// Completed handlers are discarded so the tracking list stays proportional to the in-flight requests.
				_ = handlers.RemoveAll(static handler => handler.IsCompleted);

				// The socket is captured through this local function's closure instead of being passed as an
				// explicit argument to the fire-and-forget call, and HandleUdpDnsAsync is awaited directly inside it.
				async Task HandleReceivedDatagramAsync()
				{
					await HandleUdpDnsAsync(socket, request, received.RemoteEndPoint, address, outboundAddress, dnsServers, useTor, enableUdp, cancellationToken);
				}
				handlers.Add(HandleReceivedDatagramAsync());
			}
		}
		finally
		{
			await Task.WhenAll(handlers);
		}
	}

	private static async Task HandleUdpDnsAsync(
		Socket socket,
		byte[] request,
		EndPoint remoteEndPoint,
		IPAddress localAddress,
		IPAddress outboundAddress,
		IPAddress[] dnsServers,
		bool useTor,
		bool enableUdp,
		CancellationToken cancellationToken)
	{
		try
		{
			if (remoteEndPoint is not IPEndPoint client || !IsLocalClient(client.Address))
			{
				WriteLine($"Rejected DNS client {remoteEndPoint}");
				return;
			}
			byte[] response = await CreateDnsResponseAsync(request, localAddress, outboundAddress, dnsServers, false, useTor, enableUdp, client.Address, client.ToString(), cancellationToken);
			_ = await socket.SendToAsync(response, SocketFlags.None, remoteEndPoint, cancellationToken);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
		}
		catch (Exception exception)
		{
			WriteLine($"UDP DNS error for {remoteEndPoint}: {exception.Message}");
		}
	}

	private static async Task RunTcpDnsAsync(IPAddress address, IPAddress outboundAddress, IPAddress[] dnsServers, bool useTor, bool enableUdp, CancellationToken cancellationToken)
	{
		using TcpListener listener = new(address, DnsPort);
		listener.Start();
		WriteLine($"DNS TCP listening on {address}:{DnsPort}");

		// Accepted clients are handled concurrently, and every handler is awaited before the listener is disposed.
		List<Task> handlers = [];
		try
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				TcpClient client = await listener.AcceptTcpClientAsync(cancellationToken);
				_ = handlers.RemoveAll(static handler => handler.IsCompleted);

				// The accepted client is captured through this local function's closure instead of being passed
				// as an explicit argument to the fire-and-forget call, and HandleTcpDnsAsync is awaited directly inside it.
				async Task HandleAcceptedDnsClientAsync()
				{
					await HandleTcpDnsAsync(client, address, outboundAddress, dnsServers, useTor, enableUdp, cancellationToken);
				}
				handlers.Add(HandleAcceptedDnsClientAsync());
			}
		}
		finally
		{
			listener.Stop();
			await Task.WhenAll(handlers);
		}
	}

	private static async Task HandleTcpDnsAsync(TcpClient client, IPAddress localAddress, IPAddress outboundAddress, IPAddress[] dnsServers, bool useTor, bool enableUdp, CancellationToken cancellationToken)
	{
		using (client)
		{
			EndPoint? remoteEndPoint = client.Client.RemoteEndPoint;
			try
			{
				if (remoteEndPoint is not IPEndPoint remote || !IsLocalClient(remote.Address))
				{
					WriteLine($"Rejected TCP DNS client {remoteEndPoint}");
					return;
				}
				NetworkStream stream = client.GetStream();
				byte[] lengthBuffer = new byte[2];
				while (await ReadExactlyOrEofAsync(stream, lengthBuffer, cancellationToken))
				{
					int requestLength = BinaryPrimitives.ReadUInt16BigEndian(lengthBuffer);
					if (requestLength < 12)
					{
						throw new InvalidDataException("Invalid DNS-over-TCP message length.");
					}
					byte[] request = GC.AllocateUninitializedArray<byte>(requestLength);
					if (!await ReadExactlyOrEofAsync(stream, request, cancellationToken))
					{
						throw new EndOfStreamException("Truncated DNS-over-TCP request.");
					}
					byte[] response = await CreateDnsResponseAsync(request, localAddress, outboundAddress, dnsServers, true, useTor, enableUdp, remote.Address, remote.ToString(), cancellationToken);
					BinaryPrimitives.WriteUInt16BigEndian(lengthBuffer, checked((ushort)response.Length));
					await stream.WriteAsync(lengthBuffer, cancellationToken);
					await stream.WriteAsync(response, cancellationToken);
				}
			}
			catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
			{
			}
			catch (Exception exception)
			{
				WriteLine($"TCP DNS error for {remoteEndPoint}: {exception.Message}");
			}
		}
	}

	private static async Task<byte[]> CreateDnsResponseAsync(
		byte[] request,
		IPAddress localAddress,
		IPAddress outboundAddress,
		IPAddress[] dnsServers,
		bool tcpUpstream,
		bool useTor,
		bool enableUdp,
		IPAddress clientAddress,
		string clientLabel,
		CancellationToken cancellationToken)
	{
		DnsQuestion question = ParseQuestion(request);
		if (question.Class == 1 && question.Type is 1 or 65 && !useTor && enableUdp)
		{
			// QUIC is relayed in this configuration, so the safety gate has to know which hosts this client is
			// about to use, and it has to close conflicting QUIC flows before the client receives its answer.
			await ObserveClientResolutionAsync(clientAddress, question.Name, outboundAddress, dnsServers, cancellationToken);
		}
		if (question.Class == 1 && question.Type == 1)
		{
			WriteLine($"DNS {clientLabel} A {question.Name} -> {localAddress}");
			return BuildAResponse(request, question, localAddress);
		}
		if (question.Class == 1 && question.Type == 65)
		{
			if (useTor)
			{
				WriteLine($"DNS {clientLabel} HTTPS {question.Name} -> {localAddress}:{HttpsPort} alpn=h2 route=Tor");
				return BuildTorHttpsResponse(request, question, localAddress);
			}
			if (!enableUdp)
			{
				WriteLine($"DNS {clientLabel} HTTPS {question.Name} -> {localAddress}:{HttpsPort} alpn=h2 route=destination-adapter udp=disabled");
				return BuildTorHttpsResponse(request, question, localAddress);
			}
			if (IsQuicKnownUnsafe(question.Name))
			{
				// HTTP/3 is not advertised for a host whose QUIC connections would be refused anyway.
				WriteLine($"DNS {clientLabel} HTTPS {question.Name} -> {localAddress}:{HttpsPort} alpn=h2 route=destination-adapter quic=refused");
				return BuildTorHttpsResponse(request, question, localAddress);
			}
			WriteLine($"DNS {clientLabel} HTTPS {question.Name} -> {localAddress}:{HttpsPort} alpn=h3,h2");
			return BuildHttpsResponse(request, question, localAddress);
		}
		if (question.Class == 1 && question.Type is 28 or 64)
		{
			WriteLine($"DNS {clientLabel} type {question.Type} {question.Name} -> empty");
			return BuildEmptyResponse(request, question);
		}
		if (useTor)
		{
			WriteLine($"DNS {clientLabel} type {question.Type} {question.Name} -> empty route=Tor");
			return BuildEmptyResponse(request, question);
		}
		return tcpUpstream
			? await ForwardTcpDnsAsync(request, outboundAddress, dnsServers, cancellationToken)
			: await ForwardUdpDnsAsync(request, outboundAddress, dnsServers, cancellationToken);
	}

	private static DnsQuestion ParseQuestion(ReadOnlySpan<byte> message)
	{
		if (message.Length < 12 || BinaryPrimitives.ReadUInt16BigEndian(message[4..6]) != 1)
		{
			throw new InvalidDataException("Only DNS messages with exactly one question are supported.");
		}
		ushort flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..4]);
		if ((flags & 0x8000) != 0 || (flags & 0x7800) != 0)
		{
			throw new InvalidDataException("Only standard DNS queries are supported.");
		}
		int offset = 12;
		StringBuilder name = new(64);
		while (true)
		{
			if ((uint)offset >= (uint)message.Length)
			{
				throw new InvalidDataException("Truncated DNS name.");
			}
			int labelLength = message[offset++];
			if (labelLength == 0)
			{
				break;
			}
			if (labelLength > 63 || offset + labelLength > message.Length)
			{
				throw new InvalidDataException("Invalid DNS question name.");
			}
			if (name.Length != 0)
			{
				_ = name.Append('.');
			}
			_ = name.Append(Encoding.ASCII.GetString(message.Slice(offset, labelLength)));
			offset += labelLength;
		}
		if (offset + 4 > message.Length)
		{
			throw new InvalidDataException("Truncated DNS question.");
		}
		ushort type = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
		ushort questionClass = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 2, 2));
		int questionEndOffset = offset + 4;
		ushort additionalRecordCount = BinaryPrimitives.ReadUInt16BigEndian(message[10..12]);
		bool hasEdns = TryParseEdnsOpt(message, questionEndOffset, additionalRecordCount, out ushort requestorUdpPayloadSize);
		return new DnsQuestion(name.ToString(), type, questionClass, questionEndOffset, hasEdns, requestorUdpPayloadSize);
	}

	private static bool TryParseEdnsOpt(
		ReadOnlySpan<byte> message,
		int offset,
		ushort additionalRecordCount,
		out ushort requestorUdpPayloadSize)
	{
		requestorUdpPayloadSize = 0;
		if (additionalRecordCount == 0)
		{
			return false;
		}
		// The OPT pseudo-record's owner name must be the root domain, encoded as a single zero-length
		// label. Any other shape here is tolerated by simply reporting no EDNS support rather than
		// throwing, since this program only needs to recognize a well-formed OPT record, not validate
		// or reject every possible malformed additional section.
		if (offset >= message.Length || message[offset] != 0)
		{
			return false;
		}
		offset += 1;
		if (offset + 8 > message.Length)
		{
			return false;
		}
		ushort recordType = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
		if (recordType != OptRecordType)
		{
			return false;
		}
		offset += 2;
		ushort udpPayloadSize = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
		offset += 2;

		// The next 4 bytes are the OPT record's repurposed TTL field, which encodes the extended
		// RCODE, EDNS version, and DO/flags bits. We always answer as EDNS version 0 with
		// no flags regardless of what the client advertised, so those bytes are intentionally skipped
		// rather than interpreted.
		offset += 4;
		if (offset + 2 > message.Length)
		{
			return false;
		}
		ushort rdataLength = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
		offset += 2;
		if (offset + rdataLength > message.Length)
		{
			return false;
		}

		// Any EDNS options present in the RDATA (such as Cookie or Padding) are intentionally not
		// parsed or echoed back; acknowledging the OPT record's existence and payload size is
		// sufficient for tolerance, since synthetic responses never need to negotiate
		// those options.
		requestorUdpPayloadSize = udpPayloadSize;
		return true;
	}

	private static void WriteOptRecord(byte[] response, int offset, ushort requestorUdpPayloadSize)
	{
		// Root domain name, encoded as a single zero-length label.
		response[offset] = 0;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 1, 2), OptRecordType);
		ushort responsePayloadSize = Math.Clamp(
			requestorUdpPayloadSize == 0 ? MaximumEdnsUdpPayloadSize : requestorUdpPayloadSize,
			MinimumEdnsUdpPayloadSize,
			MaximumEdnsUdpPayloadSize);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 3, 2), responsePayloadSize);

		// Extended RCODE, EDNS version, and flags all remain zero: standard RCODE, version 0, DO bit unset.
		BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(offset + 5, 4), 0);

		// RDLENGTH is zero because no EDNS options are echoed back.
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 9, 2), 0);
	}

	private static byte[] BuildAResponse(byte[] request, DnsQuestion question, IPAddress localAddress)
	{
		int questionLength = question.EndOffset - 12;
		int optionalRecordsLength = question.HasEdns ? OptRecordLength : 0;
		byte[] response = new byte[12 + questionLength + 16 + optionalRecordsLength];
		request.AsSpan(0, 2).CopyTo(response);
		ushort requestFlags = BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(2, 2));
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), (ushort)(0x8080 | (requestFlags & 0x0100)));
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(4, 2), 1);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), 1);

		// NSCOUNT (offset 8) stays zero. ARCOUNT (offset 10) is 1 only when an OPT record is echoed
		// back below, so that a client that sent EDNS0 sees a well-formed EDNS-aware reply instead of
		// its OPT record being silently dropped.
		if (question.HasEdns)
		{
			BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10, 2), 1);
		}
		request.AsSpan(12, questionLength).CopyTo(response.AsSpan(12));
		int offset = 12 + questionLength;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 0xC00C);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 2, 2), 1);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 4, 2), 1);
		BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(offset + 6, 4), 30);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 10, 2), 4);
		localAddress.GetAddressBytes().CopyTo(response, offset + 12);
		if (question.HasEdns)
		{
			WriteOptRecord(response, offset + 16, question.RequestorUdpPayloadSize);
		}
		return response;
	}

	private static byte[] BuildHttpsResponse(byte[] request, DnsQuestion question, IPAddress localAddress)
	{
		const int rdataLength = 27;
		// The advertised TTL intentionally matches the original per-host route's TTL value (300 seconds),
		// since only the advertised port and its allocation/expiration machinery were removed; the record's
		// cache lifetime semantics for the client are otherwise unchanged from before.
		const uint recordTtlSeconds = 300;
		int questionLength = question.EndOffset - 12;
		int optionalLength = question.HasEdns ? OptRecordLength : 0;
		byte[] response = new byte[12 + questionLength + 12 + rdataLength + optionalLength];
		request.AsSpan(0, 2).CopyTo(response);
		ushort requestFlags = BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(2, 2));
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), (ushort)(0x8080 | (requestFlags & 0x0100)));
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(4, 2), 1);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), 1);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10, 2), question.HasEdns ? (ushort)1 : (ushort)0);
		request.AsSpan(12, questionLength).CopyTo(response.AsSpan(12));
		int offset = 12 + questionLength;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 0xC00C);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 2, 2), 65);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 4, 2), 1);
		BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(offset + 6, 4), recordTtlSeconds);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 10, 2), rdataLength);
		offset += 12;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 1);
		response[offset + 2] = 0;
		offset += 3;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 1);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 2, 2), 6);
		response[offset + 4] = 2; response[offset + 5] = (byte)'h'; response[offset + 6] = (byte)'3';
		response[offset + 7] = 2; response[offset + 8] = (byte)'h'; response[offset + 9] = (byte)'2';
		offset += 10;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 3);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 2, 2), 2);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 4, 2), HttpsPort);
		offset += 6;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 4);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 2, 2), 4);
		localAddress.GetAddressBytes().CopyTo(response, offset + 4);
		offset += 8;
		if (question.HasEdns) WriteOptRecord(response, offset, question.RequestorUdpPayloadSize);
		return response;
	}

	private static byte[] BuildTorHttpsResponse(byte[] request, DnsQuestion question, IPAddress localAddress)
	{
		const int rdataLength = 24;
		const uint recordTtlSeconds = 300;
		int questionLength = question.EndOffset - 12;
		int optionalLength = question.HasEdns ? OptRecordLength : 0;
		byte[] response = new byte[12 + questionLength + 12 + rdataLength + optionalLength];
		request.AsSpan(0, 2).CopyTo(response);
		ushort requestFlags = BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(2, 2));
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), (ushort)(0x8080 | (requestFlags & 0x0100)));
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(4, 2), 1);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), 1);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10, 2), question.HasEdns ? (ushort)1 : (ushort)0);
		request.AsSpan(12, questionLength).CopyTo(response.AsSpan(12));
		int offset = 12 + questionLength;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 0xC00C);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 2, 2), 65);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 4, 2), 1);
		BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(offset + 6, 4), recordTtlSeconds);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 10, 2), rdataLength);
		offset += 12;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 1);
		response[offset + 2] = 0;
		offset += 3;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 1);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 2, 2), 3);
		response[offset + 4] = 2; response[offset + 5] = (byte)'h'; response[offset + 6] = (byte)'2';
		offset += 7;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 3);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 2, 2), 2);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 4, 2), HttpsPort);
		offset += 6;
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 4);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 2, 2), 4);
		localAddress.GetAddressBytes().CopyTo(response, offset + 4);
		offset += 8;
		if (question.HasEdns) WriteOptRecord(response, offset, question.RequestorUdpPayloadSize);
		return response;
	}

	private static byte[] BuildEmptyResponse(byte[] request, DnsQuestion question)
	{
		int optionalRecordsLength = question.HasEdns ? OptRecordLength : 0;
		byte[] response = new byte[question.EndOffset + optionalRecordsLength];
		request.AsSpan(0, question.EndOffset).CopyTo(response);
		ushort requestFlags = BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(2, 2));
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), (ushort)(0x8080 | (requestFlags & 0x0100)));
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), 0);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(8, 2), 0);
		BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10, 2), question.HasEdns ? (ushort)1 : (ushort)0);
		if (question.HasEdns)
		{
			WriteOptRecord(response, question.EndOffset, question.RequestorUdpPayloadSize);
		}
		return response;
	}

	private static async Task<byte[]> ForwardUdpDnsAsync(
		byte[] request,
		IPAddress outboundAddress,
		IPAddress[] dnsServers,
		CancellationToken cancellationToken)
	{
		DnsQueryMetadata query = GetDnsQueryMetadata(request);
		Exception? lastException = null;
		foreach (IPAddress dnsServer in dnsServers)
		{
			using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			timeout.CancelAfter(TimeSpan.FromSeconds(5));
			long started = Stopwatch.GetTimestamp();
			try
			{
				using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
				socket.Bind(new IPEndPoint(outboundAddress, 0));
				IPEndPoint upstream = new(dnsServer, DnsPort);
				await socket.ConnectAsync(upstream, timeout.Token);
				_ = await socket.SendAsync(request, SocketFlags.None, timeout.Token);
				byte[] buffer = GC.AllocateUninitializedArray<byte>(MaxDnsSize);
				int received = await socket.ReceiveAsync(buffer, SocketFlags.None, timeout.Token);
				ReadOnlySpan<byte> response = buffer.AsSpan(0, received);
				ValidateDnsResponse(request, response, socket.RemoteEndPoint ?? upstream, dnsServer);
				DnsResponseMetadata metadata = GetDnsResponseMetadata(response);
				WriteLine($"DNS UPSTREAM SUCCESS transport=UDP query={query.Name} type={GetDnsTypeName(query.Type)} transactionId={query.TransactionId} server={dnsServer}:{DnsPort} local={socket.LocalEndPoint} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1} rcode={metadata.ResponseCode} answers={metadata.AnswerCount} truncated={metadata.Truncated}");
				return response.ToArray();
			}
			catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
			{
				throw;
			}
			catch (OperationCanceledException exception) when (timeout.IsCancellationRequested)
			{
				lastException = exception;
				WriteLine($"DNS UPSTREAM TIMEOUT transport=UDP query={query.Name} type={GetDnsTypeName(query.Type)} transactionId={query.TransactionId} server={dnsServer}:{DnsPort} localAddress={outboundAddress} timeoutMs=5000 durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1}");
			}
			catch (Exception exception) when (exception is SocketException or InvalidDataException)
			{
				lastException = exception;
				WriteLine($"DNS UPSTREAM FAILURE transport=UDP query={query.Name} type={GetDnsTypeName(query.Type)} transactionId={query.TransactionId} server={dnsServer}:{DnsPort} localAddress={outboundAddress} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1} error={exception.GetType().Name}:{exception.Message}");
			}
		}
		throw new DnsResolutionException("Every DNS server configured on the selected destination adapter failed.", lastException);
	}

	private static async Task<byte[]> ForwardTcpDnsAsync(
		byte[] request,
		IPAddress outboundAddress,
		IPAddress[] dnsServers,
		CancellationToken cancellationToken)
	{
		DnsQueryMetadata query = GetDnsQueryMetadata(request);
		Exception? lastException = null;
		foreach (IPAddress dnsServer in dnsServers)
		{
			using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			timeout.CancelAfter(TimeSpan.FromSeconds(5));
			long started = Stopwatch.GetTimestamp();
			try
			{
				using TcpClient client = new(AddressFamily.InterNetwork);
				client.Client.Bind(new IPEndPoint(outboundAddress, 0));
				await client.ConnectAsync(dnsServer, DnsPort, timeout.Token);
				NetworkStream stream = client.GetStream();
				byte[] lengthBuffer = new byte[2];
				BinaryPrimitives.WriteUInt16BigEndian(lengthBuffer, checked((ushort)request.Length));
				await stream.WriteAsync(lengthBuffer, timeout.Token);
				await stream.WriteAsync(request, timeout.Token);
				if (!await ReadExactlyOrEofAsync(stream, lengthBuffer, timeout.Token))
				{
					throw new EndOfStreamException("Upstream DNS closed the connection.");
				}
				byte[] response = GC.AllocateUninitializedArray<byte>(BinaryPrimitives.ReadUInt16BigEndian(lengthBuffer));
				if (!await ReadExactlyOrEofAsync(stream, response, timeout.Token))
				{
					throw new EndOfStreamException("Truncated upstream DNS response.");
				}
				ValidateDnsResponse(request, response, new IPEndPoint(dnsServer, DnsPort), dnsServer);
				DnsResponseMetadata metadata = GetDnsResponseMetadata(response);
				WriteLine($"DNS UPSTREAM SUCCESS transport=TCP query={query.Name} type={GetDnsTypeName(query.Type)} transactionId={query.TransactionId} server={dnsServer}:{DnsPort} local={client.Client.LocalEndPoint} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1} rcode={metadata.ResponseCode} answers={metadata.AnswerCount} truncated={metadata.Truncated}");
				return response;
			}
			catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
			{
				throw;
			}
			catch (OperationCanceledException exception) when (timeout.IsCancellationRequested)
			{
				lastException = exception;
				WriteLine($"DNS UPSTREAM TIMEOUT transport=TCP query={query.Name} type={GetDnsTypeName(query.Type)} transactionId={query.TransactionId} server={dnsServer}:{DnsPort} localAddress={outboundAddress} timeoutMs=5000 durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1}");
			}
			catch (Exception exception) when (exception is SocketException or IOException or InvalidDataException)
			{
				lastException = exception;
				WriteLine($"DNS UPSTREAM FAILURE transport=TCP query={query.Name} type={GetDnsTypeName(query.Type)} transactionId={query.TransactionId} server={dnsServer}:{DnsPort} localAddress={outboundAddress} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1} error={exception.GetType().Name}:{exception.Message}");
			}
		}
		throw new DnsResolutionException("Every DNS server configured on the selected destination adapter failed.", lastException);
	}

	private static void ValidateDnsResponse(
		ReadOnlySpan<byte> request,
		ReadOnlySpan<byte> response,
		EndPoint responseSource,
		IPAddress expectedServer)
	{
		if (responseSource is not IPEndPoint source || !source.Address.Equals(expectedServer) || source.Port != DnsPort)
		{
			throw new InvalidDataException($"DNS response arrived from unexpected source {responseSource}.");
		}
		if (response.Length < 12 ||
			!response[..2].SequenceEqual(request[..2]) ||
			(BinaryPrimitives.ReadUInt16BigEndian(response[2..4]) & 0x8000) == 0)
		{
			throw new InvalidDataException("The upstream DNS response has an invalid transaction ID or header.");
		}
	}

	private static DnsQueryMetadata GetDnsQueryMetadata(ReadOnlySpan<byte> request)
	{
		DnsQuestion question = ParseQuestion(request);
		ushort transactionId = BinaryPrimitives.ReadUInt16BigEndian(request[..2]);
		return new DnsQueryMetadata(question.Name, question.Type, transactionId);
	}

	private static DnsResponseMetadata GetDnsResponseMetadata(ReadOnlySpan<byte> response)
	{
		Require(response, 0, 12);
		ushort flags = BinaryPrimitives.ReadUInt16BigEndian(response[2..4]);
		return new DnsResponseMetadata(
			BinaryPrimitives.ReadUInt16BigEndian(response[6..8]),
			flags & 0x000F,
			(flags & 0x0200) != 0);
	}

	private static string GetDnsTypeName(ushort type) => type switch
	{
		1 => "A",
		2 => "NS",
		5 => "CNAME",
		12 => "PTR",
		15 => "MX",
		16 => "TXT",
		28 => "AAAA",
		33 => "SRV",
		64 => "SVCB",
		65 => "HTTPS",
		_ => type.ToString(CultureInfo.InvariantCulture)
	};

	private static async Task RunProxyAsync(
		IPAddress address,
		IPAddress outboundAddress,
		IPAddress[] dnsServers,
		int port,
		bool tls,
		bool useTor,
		CancellationToken cancellationToken)
	{
		using TcpListener listener = new(address, port);
		listener.Start();
		WriteLine($"{(tls ? "TLS" : "HTTP")} proxy listening on {address}:{port}");

		// Accepted clients are handled concurrently, and every handler is awaited before the listener is disposed.
		List<Task> handlers = [];
		try
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				TcpClient client = await listener.AcceptTcpClientAsync(cancellationToken);
				ConfigureTcpKeepAlive(client.Client);
				_ = handlers.RemoveAll(static handler => handler.IsCompleted);

				// The accepted client is captured through this local function's closure instead of being passed
				// as an explicit argument to the fire-and-forget call, and HandleProxyAsync is awaited directly inside it.
				async Task HandleAcceptedProxyClientAsync()
				{
					await HandleProxyAsync(client, outboundAddress, dnsServers, port, tls, useTor, cancellationToken);
				}
				handlers.Add(HandleAcceptedProxyClientAsync());
			}
		}
		finally
		{
			listener.Stop();
			await Task.WhenAll(handlers);
		}
	}

	private static async Task HandleProxyAsync(
		TcpClient client,
		IPAddress outboundAddress,
		IPAddress[] dnsServers,
		int port,
		bool tls,
		bool useTor,
		CancellationToken cancellationToken)
	{
		long connectionId = Interlocked.Increment(ref NextConnectionId);
		int activeConnections = Interlocked.Increment(ref ActiveConnections);
		using (client)
		{
			EndPoint? clientEndPoint = client.Client.RemoteEndPoint;
			ClientTrafficCounters? clientTraffic = null;
			WriteLine($"CONNECTION #{connectionId} ACCEPTED client={clientEndPoint} listenerPort={port} activeConnections={activeConnections}");
			try
			{
				if (clientEndPoint is not IPEndPoint remote || !IsLocalClient(remote.Address))
				{
					WriteLine($"CONNECTION #{connectionId} REJECTED client={clientEndPoint} reason=non-local-client");
					return;
				}
				clientTraffic = ClientTraffic.GetOrAdd(remote.Address, static _ => new ClientTrafficCounters());
				_ = Interlocked.Increment(ref clientTraffic.ActiveConnections);
				NetworkStream clientStream = client.GetStream();
				using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
				timeout.CancelAfter(TimeSpan.FromSeconds(10));
				byte[] initialData;
				try
				{
					initialData = tls
						? await ReadTlsClientHelloAsync(clientStream, timeout.Token)
						: await ReadHttpHeadersAsync(clientStream, timeout.Token);
				}
				catch (IOException exception)
				{
					string failure = FormatRelayIOException("initial-source-read", "sourceRole", "client", "sourceEndpoint", clientEndPoint, exception);
					WriteLine($"CONNECTION #{connectionId} INITIAL READ FAILURE client={clientEndPoint} protocol={(tls ? "TLS" : "HTTP")} {failure}");
					return;
				}
				catch (SocketException exception)
				{
					string failure = FormatRelaySocketException("initial-source-read", "sourceRole", "client", "sourceEndpoint", clientEndPoint, exception);
					WriteLine($"CONNECTION #{connectionId} INITIAL READ FAILURE client={clientEndPoint} protocol={(tls ? "TLS" : "HTTP")} {failure}");
					return;
				}
				string host = tls ? ExtractSni(initialData) : ExtractHttpHost(initialData);
				TcpClient destinationClient;
				string resolvedDestination;
				if (useTor)
				{
					destinationClient = await ConnectTcpThroughTorAsync(host, port, connectionId, cancellationToken);
					resolvedDestination = "Tor";
				}
				else
				{
					IPAddress[] addresses;

					// Hosts that are IPv4 literals (e.g. "Host: 203.0.113.10") are used directly; sending them to DNS as names would always fail.
					if (IPAddress.TryParse(host, out IPAddress? literalAddress) && literalAddress.AddressFamily == AddressFamily.InterNetwork)
					{
						addresses = [literalAddress];
					}
					else
					{
						try
						{
							addresses = await ResolveHostAddressesAsync(host, outboundAddress, dnsServers, cancellationToken);
						}
						catch (DnsResolutionException exception)
						{
							WriteLine($"CONNECTION #{connectionId} DNS RESOLUTION FAILURE client={clientEndPoint} host={host} type=A error={exception.Message} innerError={exception.InnerException?.GetType().Name}:{exception.InnerException?.Message}");
							return;
						}
					}
					IPAddress[] candidateAddresses = [.. addresses.Where(static item =>
						item.AddressFamily == AddressFamily.InterNetwork && IsPublic(item))];
					(destinationClient, IPAddress destinationAddress) = await ConnectTcpToAnyAddressAsync(
						candidateAddresses, outboundAddress, host, port, connectionId, cancellationToken);
					resolvedDestination = destinationAddress.ToString();
				}
				using TcpClient destination = destinationClient;

				// Through Tor the destination connection is a loopback connection to Tor, which is probed the same way.
				ConfigureTcpKeepAlive(destination.Client);
				NetworkStream destinationStream = destination.GetStream();
				await destinationStream.WriteAsync(initialData, cancellationToken);
				_ = Interlocked.Add(ref TotalBytesSent, initialData.LongLength);
				_ = Interlocked.Add(ref clientTraffic.TotalBytesSent, initialData.LongLength);
				WriteLine($"CONNECTION #{connectionId} OPEN client={clientEndPoint} protocol={(tls ? "TLS" : "HTTP")} destination={host}:{port} resolved={resolvedDestination} outboundLocal={destination.Client.LocalEndPoint} outboundRemote={destination.Client.RemoteEndPoint}");
				long relayStarted = Stopwatch.GetTimestamp();
				RelayResult[] relayResults = await RelayBidirectionallyAsync(
					connectionId,
					clientStream,
					destinationStream,
					destination.Client,
					client.Client,
					clientEndPoint,
					destination.Client.RemoteEndPoint,
					clientTraffic,
					cancellationToken);
				RelayResult outgoingResult = relayResults[0];
				RelayResult incomingResult = relayResults[1];
				long totalSent = checked(initialData.LongLength + outgoingResult.Bytes);
				WriteLine($"CONNECTION #{connectionId} CLOSED client={clientEndPoint} destination={host}:{port} sent={totalSent}B received={incomingResult.Bytes}B durationSeconds={Stopwatch.GetElapsedTime(relayStarted).TotalSeconds:F1} clientToServer={outgoingResult.Termination} serverToClient={incomingResult.Termination}");
			}
			catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
			{
				WriteLine($"CONNECTION #{connectionId} CANCELED client={clientEndPoint} reason=program-shutdown");
			}
			catch (OperationCanceledException)
			{
				WriteLine($"CONNECTION #{connectionId} TIMEOUT client={clientEndPoint} stage=initial-request timeoutMs=10000");
			}
			catch (SocketException exception)
			{
				WriteLine($"CONNECTION #{connectionId} SOCKET FAILURE client={clientEndPoint} socketError={exception.SocketErrorCode} error={exception.Message}");
			}
			catch (Exception exception)
			{
				WriteLine($"CONNECTION #{connectionId} PROTOCOL FAILURE client={clientEndPoint} error={exception}");
			}
			finally
			{
				if (clientTraffic is not null)
				{
					_ = Interlocked.Decrement(ref clientTraffic.ActiveConnections);
				}
				int remainingConnections = Interlocked.Decrement(ref ActiveConnections);
				WriteLine($"CONNECTION #{connectionId} RELEASED client={clientEndPoint} activeConnections={remainingConnections}");
			}
		}
	}

	private static async Task<RelayResult[]> RelayBidirectionallyAsync(
		long connectionId,
		Stream clientStream,
		Stream destinationStream,
		Socket destinationSocket,
		Socket clientSocket,
		EndPoint? clientEndPoint,
		EndPoint? serverEndPoint,
		ClientTrafficCounters clientTraffic,
		CancellationToken cancellationToken)
	{
		// When one direction fails (reset, abort, write failure), the other direction is canceled as well.
		// Otherwise it could wait forever on a peer that never sends or closes, leaking the connection.
		using CancellationTokenSource relayCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		Task<RelayResult> outgoing = CopyAsync(connectionId, clientStream, destinationStream, destinationSocket, "client", clientEndPoint, "server", serverEndPoint, clientTraffic, true, relayCancellation.Token, cancellationToken);
		Task<RelayResult> incoming = CopyAsync(connectionId, destinationStream, clientStream, clientSocket, "server", serverEndPoint, "client", clientEndPoint, clientTraffic, false, relayCancellation.Token, cancellationToken);
		Task<RelayResult> first = await Task.WhenAny(outgoing, incoming);
		bool cancelOppositeDirection;
		try
		{
			cancelOppositeDirection = !string.Equals((await first).Termination, "end-of-stream", StringComparison.Ordinal);
		}
		catch
		{
			// The exception is observed again and propagated by the Task.WhenAll below.
			cancelOppositeDirection = true;
		}
		if (cancelOppositeDirection)
		{
			await relayCancellation.CancelAsync();
		}
		return await Task.WhenAll(outgoing, incoming);
	}

	private static async Task<IPAddress[]> ResolveHostAddressesAsync(
		string host,
		IPAddress outboundAddress,
		IPAddress[] dnsServers,
		CancellationToken cancellationToken)
	{
		if (DnsAddressCache.TryGetValue(host, out DnsCacheEntry? cachedEntry))
		{
			TimeSpan age = Stopwatch.GetElapsedTime(cachedEntry.CreatedTimestamp);
			if (age < cachedEntry.Lifetime)
			{
				WriteLine($"DNS CACHE HIT query={host} type=A addresses={cachedEntry.Addresses.Length} remainingTtlSeconds={Math.Max(0, (cachedEntry.Lifetime - age).TotalSeconds):F1}");
				return cachedEntry.Addresses;
			}
			_ = DnsAddressCache.TryRemove(KeyValuePair.Create(host, cachedEntry));
			WriteLine($"DNS CACHE EXPIRED query={host} type=A");
		}
		Lazy<Task<DnsCacheEntry>> newQuery = new(
			() => ResolveAndCacheHostAddressesAsync(host, outboundAddress, dnsServers, cancellationToken),
			LazyThreadSafetyMode.ExecutionAndPublication);
		Lazy<Task<DnsCacheEntry>> pendingQuery = PendingDnsAddressQueries.GetOrAdd(host, newQuery);
		if (!ReferenceEquals(pendingQuery, newQuery))
		{
			WriteLine($"DNS QUERY COALESCED query={host} type=A");
		}
		try
		{
			DnsCacheEntry entry = await pendingQuery.Value.WaitAsync(cancellationToken);
			return entry.Addresses;
		}
		finally
		{
			if (pendingQuery.IsValueCreated && pendingQuery.Value.IsCompleted)
			{
				_ = PendingDnsAddressQueries.TryRemove(KeyValuePair.Create(host, pendingQuery));
			}
		}
	}

	private static async Task<DnsCacheEntry> ResolveAndCacheHostAddressesAsync(
		string host,
		IPAddress outboundAddress,
		IPAddress[] dnsServers,
		CancellationToken cancellationToken)
	{
		WriteLine($"DNS CACHE MISS query={host} type=A");
		try
		{
			byte[] request = BuildDnsAQuery(host);
			byte[] response;
			try
			{
				response = await ForwardUdpDnsAsync(request, outboundAddress, dnsServers, cancellationToken);
				ushort flags = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2, 2));
				if ((flags & 0x0200) != 0)
				{
					WriteLine($"DNS UPSTREAM RETRY transport=TCP query={host} type=A reason=truncated-UDP-response");
					response = await ForwardTcpDnsAsync(request, outboundAddress, dnsServers, cancellationToken);
				}
			}
			catch (DnsResolutionException exception)
			{
				WriteLine($"DNS UPSTREAM RETRY transport=TCP query={host} type=A reason=udp-failure udpError={exception.InnerException?.GetType().Name}:{exception.InnerException?.Message}");
				response = await ForwardTcpDnsAsync(request, outboundAddress, dnsServers, cancellationToken);
			}
			DnsAddressResult result = ParseDnsAResponse(response);
			DnsCacheEntry entry = new(result.Addresses, Stopwatch.GetTimestamp(), result.Lifetime);
			if (result.Lifetime > TimeSpan.Zero)
			{
				StoreDnsCacheEntry(host, entry);
				WriteLine($"DNS CACHE STORE query={host} type=A addresses={result.Addresses.Length} ttlSeconds={result.Lifetime.TotalSeconds:F0}");
			}
			else
			{
				WriteLine($"DNS CACHE BYPASS query={host} type=A reason=zero-ttl");
			}
			return entry;
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (DnsResolutionException)
		{
			throw;
		}
		catch (Exception exception) when (exception is SocketException or InvalidDataException)
		{
			throw new DnsResolutionException("The DNS response could not produce a usable IPv4 destination.", exception);
		}
	}

	private static void StoreDnsCacheEntry(string host, DnsCacheEntry entry)
	{
		lock (DnsCacheInsertionLock)
		{
			if (DnsAddressCache.ContainsKey(host))
			{
				DnsAddressCache[host] = entry;
				return;
			}
			int cacheCount = DnsAddressCache.Count;
			if (cacheCount >= MaximumDnsCacheEntries)
			{
				List<KeyValuePair<string, DnsCacheEntry>> liveEntries = [with(cacheCount)];
				foreach (KeyValuePair<string, DnsCacheEntry> cachedEntry in DnsAddressCache)
				{
					if (Stopwatch.GetElapsedTime(cachedEntry.Value.CreatedTimestamp) >= cachedEntry.Value.Lifetime)
					{
						_ = DnsAddressCache.TryRemove(cachedEntry);
					}
					else
					{
						liveEntries.Add(cachedEntry);
					}
				}
				cacheCount = DnsAddressCache.Count;
				if (cacheCount >= MaximumDnsCacheEntries)
				{
					liveEntries.Sort(static (left, right) => left.Value.CreatedTimestamp.CompareTo(right.Value.CreatedTimestamp));
					int entriesToRemove = cacheCount - DnsCacheTrimTarget;
					for (int index = 0; index < entriesToRemove; index++)
					{
						_ = DnsAddressCache.TryRemove(liveEntries[index]);
					}
				}
			}
			DnsAddressCache[host] = entry;
		}
	}

	private static byte[] BuildDnsAQuery(string host)
	{
		string[] labels = host.Split('.');
		int encodedNameLength = 1;
		foreach (string label in labels)
		{
			if (label.Length is 0 or > 63)
			{
				throw new InvalidDataException("Invalid DNS host name label.");
			}
			encodedNameLength = checked(encodedNameLength + 1 + label.Length);
		}
		byte[] request = new byte[12 + encodedNameLength + 4];
		BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(0, 2), unchecked((ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue + 1)));
		BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2, 2), 0x0100);
		BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(4, 2), 1);
		int offset = 12;
		foreach (string label in labels)
		{
			request[offset++] = checked((byte)label.Length);
			offset += Encoding.ASCII.GetBytes(label, request.AsSpan(offset));
		}
		request[offset++] = 0;
		BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(offset, 2), 1);
		BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(offset + 2, 2), 1);
		return request;
	}

	private static DnsAddressResult ParseDnsAResponse(ReadOnlySpan<byte> response)
	{
		if (response.Length < 12)
		{
			throw new InvalidDataException("Truncated DNS response.");
		}
		ushort flags = BinaryPrimitives.ReadUInt16BigEndian(response[2..4]);
		if ((flags & 0x000F) != 0)
		{
			throw new InvalidDataException($"DNS resolver returned response code {flags & 0x000F}.");
		}
		ushort questionCount = BinaryPrimitives.ReadUInt16BigEndian(response[4..6]);
		ushort answerCount = BinaryPrimitives.ReadUInt16BigEndian(response[6..8]);
		int offset = 12;
		for (int index = 0; index < questionCount; index++)
		{
			SkipDnsName(response, ref offset);
			Require(response, offset, 4);
			offset += 4;
		}
		List<IPAddress> addresses = [with(answerCount)];
		uint minimumTtlSeconds = uint.MaxValue;
		for (int index = 0; index < answerCount; index++)
		{
			SkipDnsName(response, ref offset);
			Require(response, offset, 10);
			ushort type = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(offset, 2));
			ushort recordClass = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(offset + 2, 2));
			uint ttlSeconds = BinaryPrimitives.ReadUInt32BigEndian(response.Slice(offset + 4, 4));
			ushort dataLength = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(offset + 8, 2));
			offset += 10;
			Require(response, offset, dataLength);
			if (type == 1 && recordClass == 1 && dataLength == 4)
			{
				IPAddress address = new(response.Slice(offset, 4));
				if (!addresses.Contains(address))
				{
					addresses.Add(address);
				}
				minimumTtlSeconds = Math.Min(minimumTtlSeconds, ttlSeconds);
			}
			offset += dataLength;
		}
		if (addresses.Count == 0)
		{
			throw new SocketException((int)SocketError.HostNotFound);
		}
		TimeSpan lifetime = TimeSpan.FromSeconds(minimumTtlSeconds == uint.MaxValue ? 0 : minimumTtlSeconds);
		return new DnsAddressResult([.. addresses], lifetime);
	}

	private static void SkipDnsName(ReadOnlySpan<byte> message, ref int offset)
	{
		int labels = 0;
		while (true)
		{
			Require(message, offset, 1);
			byte length = message[offset++];
			if (length == 0)
			{
				return;
			}
			if ((length & 0xC0) == 0xC0)
			{
				Require(message, offset, 1);
				offset++;
				return;
			}
			if ((length & 0xC0) != 0 || length > 63 || ++labels > 127)
			{
				throw new InvalidDataException("Invalid DNS name encoding.");
			}
			Require(message, offset, length);
			offset += length;
		}
	}

	private static async Task<TcpClient> ConnectTcpThroughTorAsync(
		string host,
		int port,
		long connectionId,
		CancellationToken cancellationToken)
	{
		// Ownership of the client moves to the caller only on success; the finally block disposes it on every failure path.
		TcpClient? client = new(AddressFamily.InterNetwork) { NoDelay = true };
		using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		timeout.CancelAfter(TorConnectTimeout);
		long started = Stopwatch.GetTimestamp();
		WriteLine($"CONNECTION #{connectionId} TOR CONNECT ATTEMPT host={host} remotePort={port} socks=127.0.0.1:{TorSessionManager.SocksPort}");
		try
		{
			await client.ConnectAsync(IPAddress.Loopback, TorSessionManager.SocksPort, timeout.Token);
			NetworkStream stream = client.GetStream();
			await Socks5Protocol.WriteNoAuthenticationNegotiationAsync(stream, timeout.Token);
			byte[] methodResponse = new byte[2];
			if (!await ReadExactlyOrEofAsync(stream, methodResponse, timeout.Token) || methodResponse[0] != 5 || methodResponse[1] != 0)
			{
				throw new InvalidDataException("Tor rejected the SOCKS5 authentication negotiation.");
			}
			if (!Socks5Protocol.TryCreateDomainConnectRequest(host, port, out byte[] request))
			{
				throw new InvalidDataException("The destination host name is too long for SOCKS5.");
			}
			await stream.WriteAsync(request, timeout.Token);
			byte[] responseHeader = new byte[4];
			if (!await ReadExactlyOrEofAsync(stream, responseHeader, timeout.Token) || responseHeader[0] != 5)
			{
				throw new InvalidDataException("Tor returned an invalid SOCKS5 response.");
			}
			if (responseHeader[1] != 0)
			{
				throw new SocketException(responseHeader[1] == 4 ? (int)SocketError.HostUnreachable : (int)SocketError.ConnectionRefused);
			}
			int boundAddressLength = responseHeader[3] switch
			{
				1 => 4,
				3 => await ReadSocksDomainLengthAsync(stream, timeout.Token),
				4 => 16,
				_ => throw new InvalidDataException("Tor returned an invalid SOCKS5 address type.")
			};
			byte[] boundAddressAndPort = new byte[boundAddressLength + 2];
			if (!await ReadExactlyOrEofAsync(stream, boundAddressAndPort, timeout.Token))
			{
				throw new EndOfStreamException("Tor returned a truncated SOCKS5 response.");
			}
			WriteLine($"CONNECTION #{connectionId} TOR CONNECT SUCCESS host={host} remotePort={port} local={client.Client.LocalEndPoint} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1}");
			TcpClient connectedClient = client;
			client = null;
			return connectedClient;
		}
		catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
		{
			// The Tor connect timeout is reported as a socket timeout. Rethrowing the OperationCanceledException itself
			// would make the caller misreport it as a timeout of the client's initial request.
			WriteLine($"CONNECTION #{connectionId} TOR CONNECT TIMEOUT host={host} remotePort={port} timeoutMs={TorConnectTimeout.TotalMilliseconds:F0}");
			throw new SocketException((int)SocketError.TimedOut);
		}
		finally
		{
			client?.Dispose();
		}
	}

	private static async Task<int> ReadSocksDomainLengthAsync(Stream stream, CancellationToken cancellationToken)
	{
		byte[] length = new byte[1];
		if (!await ReadExactlyOrEofAsync(stream, length, cancellationToken))
		{
			throw new EndOfStreamException("Tor returned a truncated SOCKS5 domain address.");
		}
		return length[0];
	}

	private static async Task<(TcpClient Client, IPAddress Address)> ConnectTcpToAnyAddressAsync(
		IPAddress[] candidates,
		IPAddress outboundAddress,
		string host,
		int port,
		long connectionId,
		CancellationToken cancellationToken)
	{
		Exception? lastException = null;
		for (int index = 0; index < candidates.Length; index++)
		{
			IPAddress candidate = candidates[index];
			TcpClient client = new(AddressFamily.InterNetwork) { NoDelay = true };
			using CancellationTokenSource attemptTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			attemptTimeout.CancelAfter(PerAddressConnectTimeout);
			long started = Stopwatch.GetTimestamp();
			try
			{
				// Binding happens inside the try block so the client is disposed if binding to the outbound address fails.
				client.Client.Bind(new IPEndPoint(outboundAddress, 0));
				WriteLine($"CONNECTION #{connectionId} CONNECT ATTEMPT host={host} remote={candidate}:{port} local={client.Client.LocalEndPoint} attempt={index + 1}/{candidates.Length}");
				await client.ConnectAsync(candidate, port, attemptTimeout.Token);
				WriteLine($"CONNECTION #{connectionId} CONNECT SUCCESS host={host} remote={client.Client.RemoteEndPoint} local={client.Client.LocalEndPoint} attempt={index + 1}/{candidates.Length} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1}");
				return (client, candidate);
			}
			catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
			{
				client.Dispose();
				throw;
			}
			catch (OperationCanceledException exception) when (attemptTimeout.IsCancellationRequested)
			{
				client.Dispose();
				lastException = exception;
				WriteLine($"CONNECTION #{connectionId} CONNECT TIMEOUT host={host} remote={candidate}:{port} localAddress={outboundAddress} attempt={index + 1}/{candidates.Length} timeoutMs={PerAddressConnectTimeout.TotalMilliseconds:F0} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1}");
			}
			catch (SocketException exception)
			{
				client.Dispose();
				lastException = exception;
				WriteLine($"CONNECTION #{connectionId} CONNECT FAILURE host={host} remote={candidate}:{port} localAddress={outboundAddress} attempt={index + 1}/{candidates.Length} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1} socketError={exception.SocketErrorCode} error={exception.Message}");
			}
			catch
			{
				client.Dispose();
				throw;
			}
		}

		// A per-address connect timeout is reported as a socket timeout. Rethrowing the OperationCanceledException itself
		// would make the caller misreport it as a timeout of the client's initial request.
		throw lastException switch
		{
			null => new SocketException((int)SocketError.HostNotFound),
			OperationCanceledException => new SocketException((int)SocketError.TimedOut),
			_ => lastException
		};
	}

	// The QUIC safety gate.
	//
	// Every host name is answered with this machine's address, so a client sees all servers at one address.
	// HTTP clients reuse an existing connection for another host name when that name resolves to the same
	// address and the connection's certificate covers it. On a QUIC connection the requests are encrypted,
	// so this engine cannot route them one by one: everything a client sends on a connection reaches the
	// server that the connection was opened to. A request for a host that lives on another server is then
	// answered by the wrong server, which shows up as failing downloads in Google Play app and YouTube videos that do not start in a timely fashion after playing 1 or 2 videos.
	//
	// The gate therefore only relays a QUIC connection while its certificate cannot cover a host that the
	// client uses and that lives on a different server. A refused connection falls back to TCP, where the
	// client opens a separate connection after the wrong server answers "421 Misdirected Request".

	// Tells the safety gate that a client is resolving a host, and closes that client's QUIC flows that
	// the client could wrongly reuse for the host.
	//
	// The client's DNS answer is never held back for a name lookup. An answer that arrives hundreds of
	// milliseconds late makes a browser's resolver give up on this server and ask the device's other DNS
	// servers, whose answers send the browser around the engine. The gate therefore decides at once from
	// what it already knows, and the real addresses of an unknown host are looked up in the background.
	private static async Task ObserveClientResolutionAsync(
		IPAddress clientAddress,
		string name,
		IPAddress outboundAddress,
		IPAddress[] dnsServers,
		CancellationToken cancellationToken)
	{
		string host;
		try
		{
			// Names that cannot be host names (for example service labels with underscores) are never connected to.
			host = ValidateHost(name);
		}
		catch (InvalidDataException)
		{
			return;
		}
		bool flowsClosed;
		if (TryGetKnownHostAddresses(host, out IPAddress[] knownAddresses, out bool isCurrent))
		{
			flowsClosed = ApplyClientResolution(clientAddress, host, knownAddresses);
		}
		else
		{
			// Nothing is known about the host yet. A flow whose certificate covers it is closed, because
			// the client may reuse that flow for the host before its real addresses are known.
			flowsClosed = CloseFlowsCoveringUnknownHost(clientAddress, host);
		}
		if (!isCurrent &&
			!(FailedClientResolutions.TryGetValue(host, out long failedTimestamp) && Stopwatch.GetElapsedTime(failedTimestamp) < ClientResolutionRetryInterval))
		{
			// The lookup continues after the client has its answer. It ends with the listeners.
			_ = ResolveClientHostInBackgroundAsync(clientAddress, host, outboundAddress, dnsServers, cancellationToken);
		}
		if (flowsClosed)
		{
			// The client processes the report about its closed connection before it can use the answer.
			await Task.Delay(QuicConflictSettleDelay, cancellationToken);
		}
	}

	// Returns the public IPv4 addresses of a host without a network lookup: from the DNS cache (isCurrent
	// is true), or else the addresses that a client's earlier query for the host produced.
	private static bool TryGetKnownHostAddresses(string host, out IPAddress[] addresses, out bool isCurrent)
	{
		if (DnsAddressCache.TryGetValue(host, out DnsCacheEntry? cachedEntry) &&
			Stopwatch.GetElapsedTime(cachedEntry.CreatedTimestamp) < cachedEntry.Lifetime)
		{
			addresses = [.. cachedEntry.Addresses.Where(static item => item.AddressFamily == AddressFamily.InterNetwork && IsPublic(item))];
			isCurrent = true;
			return addresses.Length != 0;
		}
		isCurrent = false;
		lock (QuicGateLock)
		{
			if (ClientResolvedHosts.TryGetValue(host, out ResolvedHost? resolved) &&
				Stopwatch.GetElapsedTime(resolved.Timestamp) < ClientResolvedHostLifetime)
			{
				addresses = resolved.Addresses;
				return true;
			}
		}
		addresses = [];
		return false;
	}

	// Looks up the real addresses of a host that a client resolved, and applies them to the safety gate.
	// Every failure ends here, because nothing awaits this task.
	private static async Task ResolveClientHostInBackgroundAsync(
		IPAddress clientAddress,
		string host,
		IPAddress outboundAddress,
		IPAddress[] dnsServers,
		CancellationToken cancellationToken)
	{
		try
		{
			IPAddress[] resolved = await ResolveHostAddressesAsync(host, outboundAddress, dnsServers, cancellationToken);
			IPAddress[] addresses = [.. resolved.Where(static item => item.AddressFamily == AddressFamily.InterNetwork && IsPublic(item))];
			if (addresses.Length != 0)
			{
				_ = ApplyClientResolution(clientAddress, host, addresses);
			}
		}
		catch (OperationCanceledException)
		{
			// The engine is stopping, or the lookup was shared with a request that was canceled.
			// The host is looked up again with a later query of the client.
		}
		catch (DnsResolutionException)
		{
			// The name is not looked up again for a while; the failure itself is already in the logs.
			if (FailedClientResolutions.Count >= MaximumClientResolvedHosts)
			{
				FailedClientResolutions.Clear();
			}
			FailedClientResolutions[host] = Stopwatch.GetTimestamp();
		}
		catch (Exception exception)
		{
			WriteLine($"QUIC GATE LOOKUP FAILURE host={host} error={exception.GetType().Name}:{exception.Message}");
		}
	}

	// Closes the client's QUIC flows whose certificate covers a host about which nothing is known yet.
	// Returns whether a flow was closed.
	private static bool CloseFlowsCoveringUnknownHost(IPAddress clientAddress, string name)
	{
		List<QuicFlow>? coveringFlows = null;
		string? parent = GetParentDomain(name);
		lock (QuicGateLock)
		{
			foreach (QuicFlow flow in LiveQuicFlows)
			{
				if (flow.GateNames is not CertificateNames names ||
					string.Equals(flow.GateHost, name, StringComparison.OrdinalIgnoreCase) ||
					!flow.ClientEndPoint.Address.Equals(clientAddress))
				{
					continue;
				}
				if ((parent is not null && names.WildcardParents.Contains(parent)) || names.ExactNames.Contains(name))
				{
					(coveringFlows ??= []).Add(flow);
				}
			}
		}
		if (coveringFlows is null)
		{
			return false;
		}
		foreach (QuicFlow flow in coveringFlows)
		{
			flow.Terminate($"certificate-covers-{name}-whose-server-is-not-known-yet", true);
		}
		return true;
	}

	// Remembers the real addresses of a host that a client resolved and closes that client's QUIC flows
	// whose certificate covers the host although the host lives on a different server.
	// Returns whether a flow was closed.
	private static bool ApplyClientResolution(IPAddress clientAddress, string name, IPAddress[] addresses)
	{
		List<QuicFlow>? conflictingFlows = null;
		string? parent = GetParentDomain(name);
		lock (QuicGateLock)
		{
			RecordClientResolvedHost(name, parent, addresses);
			foreach (QuicFlow flow in LiveQuicFlows)
			{
				if (flow.GateNames is not CertificateNames names || string.Equals(flow.GateHost, name, StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}
				bool coveredByWildcard = parent is not null && names.WildcardParents.Contains(parent);
				if (!coveredByWildcard && !names.ExactNames.Contains(name))
				{
					continue;
				}
				if (AddressesOverlap(flow.GateAddresses, addresses))
				{
					continue;
				}
				if (coveredByWildcard)
				{
					// The wildcard name is now known to span servers, so no later flow is relayed with it.
					_ = SharedWildcardParents.Add(parent!);
				}

				// Only the client that is resolving the host can reuse its own flow for it.
				if (flow.ClientEndPoint.Address.Equals(clientAddress))
				{
					(conflictingFlows ??= []).Add(flow);
				}
			}
		}
		if (conflictingFlows is null)
		{
			return false;
		}
		foreach (QuicFlow flow in conflictingFlows)
		{
			flow.Terminate($"certificate-covers-{name}-which-lives-on-another-server", true);
		}
		return true;
	}

	// Registers a new QUIC flow when relaying it is safe. Returns null on success, otherwise the reason for refusing QUIC.
	private static string? RegisterQuicFlowIfSafe(QuicFlow flow, string host, IPAddress[] addresses, CertificateNames names)
	{
		lock (QuicGateLock)
		{
			foreach (string exactName in names.ExactNames)
			{
				if (!string.Equals(exactName, host, StringComparison.OrdinalIgnoreCase) && LivesOnAnotherServer(exactName, addresses))
				{
					return $"certificate-covers-{exactName}-which-lives-on-another-server";
				}
			}
			foreach (string parent in names.WildcardParents)
			{
				if (SharedWildcardParents.Contains(parent))
				{
					return $"certificate-name-*.{parent}-spans-servers";
				}
				if (!ClientResolvedHostsByParent.TryGetValue(parent, out List<string>? siblings))
				{
					continue;
				}
				foreach (string sibling in siblings)
				{
					if (!string.Equals(sibling, host, StringComparison.OrdinalIgnoreCase) && LivesOnAnotherServer(sibling, addresses))
					{
						_ = SharedWildcardParents.Add(parent);
						return $"certificate-covers-{sibling}-which-lives-on-another-server";
					}
				}
			}
			flow.GateHost = host;
			flow.GateNames = names;
			flow.GateAddresses = addresses;
			LiveQuicFlows.Add(flow);
			return null;
		}
	}

	private static void UnregisterQuicFlow(QuicFlow flow)
	{
		lock (QuicGateLock)
		{
			_ = LiveQuicFlows.Remove(flow);
		}
	}

	/// <summary>
	/// Must be called while <see cref="QuicGateLock"/> is held.
	/// </summary>
	private static bool LivesOnAnotherServer(string host, IPAddress[] addresses)
		=> ClientResolvedHosts.TryGetValue(host, out ResolvedHost? resolved) &&
			Stopwatch.GetElapsedTime(resolved.Timestamp) < ClientResolvedHostLifetime &&
			!AddressesOverlap(resolved.Addresses, addresses);

	/// <summary>
	/// Must be called while <see cref="QuicGateLock"/> is held.
	/// </summary>
	private static void RecordClientResolvedHost(string host, string? parent, IPAddress[] addresses)
	{
		bool isNewHost = !ClientResolvedHosts.ContainsKey(host);
		if (isNewHost && ClientResolvedHosts.Count >= MaximumClientResolvedHosts)
		{
			// The oldest half is forgotten; a forgotten host is recorded again with the client's next query.
			List<KeyValuePair<string, ResolvedHost>> entries = [.. ClientResolvedHosts];
			entries.Sort(static (left, right) => left.Value.Timestamp.CompareTo(right.Value.Timestamp));
			for (int index = 0; index < entries.Count / 2; index++)
			{
				string staleHost = entries[index].Key;
				_ = ClientResolvedHosts.Remove(staleHost);
				if (GetParentDomain(staleHost) is string staleParent && ClientResolvedHostsByParent.TryGetValue(staleParent, out List<string>? staleSiblings))
				{
					_ = staleSiblings.RemoveAll(sibling => string.Equals(sibling, staleHost, StringComparison.OrdinalIgnoreCase));
					if (staleSiblings.Count == 0)
					{
						_ = ClientResolvedHostsByParent.Remove(staleParent);
					}
				}
			}
		}
		ClientResolvedHosts[host] = new ResolvedHost(addresses, Stopwatch.GetTimestamp());
		if (isNewHost && parent is not null)
		{
			if (!ClientResolvedHostsByParent.TryGetValue(parent, out List<string>? siblings))
			{
				siblings = [];
				ClientResolvedHostsByParent[parent] = siblings;
			}
			siblings.Add(host);
		}
	}

	// True when QUIC connections to the host are known to be refused, so HTTP/3 should not be advertised for it.
	private static bool IsQuicKnownUnsafe(string host) => GetKnownQuicRefusal(host) is not null;

	// Returns the reason for refusing QUIC to the host when it is already known without contacting anything:
	// the host's server recently did not answer QUIC, or the host is covered by a wildcard certificate name
	// that is proven to span servers. Returns null otherwise.
	private static string? GetKnownQuicRefusal(string host)
	{
		// A host whose server recently did not answer QUIC is refused until the retry interval passes.
		if (QuicUnresponsiveHosts.TryGetValue(host, out long failedTimestamp))
		{
			if (Stopwatch.GetElapsedTime(failedTimestamp) < QuicUnresponsiveRetryInterval)
			{
				return "server-did-not-answer-quic-recently";
			}
			_ = QuicUnresponsiveHosts.TryRemove(new KeyValuePair<string, long>(host, failedTimestamp));
		}
		CertificateNames? names = null;
		if (CertificateNameCache.TryGetValue(host, out Lazy<Task<CertificateProbeResult>>? cached) &&
			cached.IsValueCreated && cached.Value.IsCompletedSuccessfully)
		{
			names = cached.Value.Result.Names;
		}
		lock (QuicGateLock)
		{
			if (GetParentDomain(host) is string parent && SharedWildcardParents.Contains(parent))
			{
				return $"certificate-name-*.{parent}-spans-servers";
			}
			if (names is not null)
			{
				foreach (string wildcardParent in names.WildcardParents)
				{
					if (SharedWildcardParents.Contains(wildcardParent))
					{
						return $"certificate-name-*.{wildcardParent}-spans-servers";
					}
				}
			}
		}
		return null;
	}

	// The domain that a wildcard certificate name would have to carry to cover the host: the host without its first label.
	private static string? GetParentDomain(string host)
	{
		int dot = host.IndexOf('.', StringComparison.Ordinal);
		return dot > 0 && dot < host.Length - 1 ? host[(dot + 1)..] : null;
	}

	private static bool AddressesOverlap(IPAddress[] left, IPAddress[] right)
	{
		foreach (IPAddress leftAddress in left)
		{
			foreach (IPAddress rightAddress in right)
			{
				if (leftAddress.Equals(rightAddress))
				{
					return true;
				}
			}
		}
		return false;
	}

	// Returns the DNS names of the certificate that the destination presents, or null when they cannot be determined.
	// The result is cached per host, and concurrent requests for the same host share one probe.
	private static async Task<CertificateNames?> GetCertificateNamesAsync(
		string host,
		IPAddress[] addresses,
		IPAddress outboundAddress,
		CancellationToken programCancellationToken,
		CancellationToken cancellationToken)
	{
		if (CertificateNameCache.TryGetValue(host, out Lazy<Task<CertificateProbeResult>>? cached) &&
			cached.IsValueCreated && cached.Value.IsCompleted)
		{
			bool expired = true;
			if (cached.Value.IsCompletedSuccessfully)
			{
				CertificateProbeResult cachedResult = await cached.Value;
				TimeSpan lifetime = cachedResult.Names is null ? CertificateProbeRetryInterval : CertificateNamesLifetime;
				expired = Stopwatch.GetElapsedTime(cachedResult.Timestamp) >= lifetime;
			}
			if (expired)
			{
				_ = CertificateNameCache.TryRemove(KeyValuePair.Create(host, cached));
			}
		}

		// The probe runs on the program's token instead of the requesting flow's token, because other flows may be waiting for it too.
		Lazy<Task<CertificateProbeResult>> probe = CertificateNameCache.GetOrAdd(
			host,
			_ => new Lazy<Task<CertificateProbeResult>>(
				() => ProbeCertificateNamesAsync(host, addresses, outboundAddress, programCancellationToken),
				LazyThreadSafetyMode.ExecutionAndPublication));
		try
		{
			CertificateProbeResult result = await probe.Value.WaitAsync(QuicGateTimeout, cancellationToken);
			return result.Names;
		}
		catch (TimeoutException)
		{
			return null;
		}
	}

	// Fetches the destination's certificate with a TLS handshake over TCP through the outbound adapter.
	private static async Task<CertificateProbeResult> ProbeCertificateNamesAsync(
		string host,
		IPAddress[] addresses,
		IPAddress outboundAddress,
		CancellationToken cancellationToken)
	{
		long started = Stopwatch.GetTimestamp();
		string failure = "no-address";
		foreach (IPAddress address in addresses)
		{
			using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			timeout.CancelAfter(CertificateProbeTimeout);
			HashSet<string> exactNames = new(StringComparer.OrdinalIgnoreCase);
			HashSet<string> wildcardParents = new(StringComparer.OrdinalIgnoreCase);
			try
			{
				using TcpClient client = new(new IPEndPoint(outboundAddress, 0));
				await client.ConnectAsync(address, HttpsPort, timeout.Token);
				using SslStream tls = new(client.GetStream(), false);
				SslClientAuthenticationOptions options = new()
				{
					TargetHost = host,

					// The chain is built from the certificates the server sends and the local stores only.
					// Downloading missing issuer certificates or revocation lists took several seconds on a
					// slow outbound path, and every new QUIC connection waited for it.
					CertificateChainPolicy = new X509ChainPolicy
					{
						RevocationMode = X509RevocationMode.NoCheck,
						DisableCertificateDownloads = true
					},
					RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
					{
						// The names are only used to decide whether QUIC is relayed. The client still validates
						// the server's certificate itself, end to end, in its own handshake.
						CollectCertificateNames(certificate, exactNames, wildcardParents);
						return errors == SslPolicyErrors.None;
					}
				};
				try
				{
					await tls.AuthenticateAsClientAsync(options, timeout.Token);
				}
				catch (AuthenticationException)
				{
					// The names were collected before the validation result ended the handshake.
				}
				if (exactNames.Count != 0 || wildcardParents.Count != 0)
				{
					WriteLine($"QUIC GATE CERTIFICATE host={host} remote={address}:{HttpsPort} names={exactNames.Count} wildcards={wildcardParents.Count} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1}");
					return new CertificateProbeResult(new CertificateNames(exactNames, wildcardParents), Stopwatch.GetTimestamp());
				}
				failure = "certificate-without-dns-names";
			}
			catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
			{
				throw;
			}
			catch (Exception exception) when (exception is SocketException or IOException or OperationCanceledException)
			{
				failure = $"{exception.GetType().Name}:{exception.Message}";
			}
		}
		WriteLine($"QUIC GATE CERTIFICATE UNAVAILABLE host={host} addresses={addresses.Length} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1} error={failure}");
		return new CertificateProbeResult(null, Stopwatch.GetTimestamp());
	}

	private static void CollectCertificateNames(X509Certificate? certificate, HashSet<string> exactNames, HashSet<string> wildcardParents)
	{
		if (certificate is not X509Certificate2 certificate2)
		{
			return;
		}
		foreach (X509Extension extension in certificate2.Extensions)
		{
			if (extension is not X509SubjectAlternativeNameExtension subjectAlternativeName)
			{
				continue;
			}
			foreach (string dnsName in subjectAlternativeName.EnumerateDnsNames())
			{
				if (dnsName.StartsWith("*.", StringComparison.Ordinal))
				{
					_ = wildcardParents.Add(dnsName[2..]);
				}
				else if (dnsName.Length != 0)
				{
					_ = exactNames.Add(dnsName);
				}
			}
		}
	}

	// Logs a refused QUIC connection once per client address and host within the progress interval;
	// a client retransmits its first packet several times, and every retransmission is refused again.
	private static void LogQuicRefusal(long connectionId, IPEndPoint client, string host, string reason)
	{
		string key = $"{client.Address}|{host}";
		long now = Stopwatch.GetTimestamp();
		if (QuicRefusalLogTimestamps.TryGetValue(key, out long lastLogged) && Stopwatch.GetElapsedTime(lastLogged, now) < RelayProgressInterval)
		{
			return;
		}
		if (QuicRefusalLogTimestamps.Count > 4096)
		{
			QuicRefusalLogTimestamps.Clear();
		}
		QuicRefusalLogTimestamps[key] = now;
		WriteLine($"CONNECTION #{connectionId} QUIC REFUSED client={client} host={host} reason={reason} icmpReport={Volatile.Read(ref IcmpSocket) is not null}; the client is expected to use TCP for this host");
	}

	// Creates the raw socket for ICMP reports. Raw sockets require elevation, so null is returned when it cannot be created.
	private static Socket? CreateIcmpSocket(IPAddress address)
	{
		Socket? socket = null;
		try
		{
			socket = new(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
			socket.Bind(new IPEndPoint(address, 0));
			return socket;
		}
		catch (SocketException exception)
		{
			socket?.Dispose();
			WriteLine($"QUIC ICMP REPORTS UNAVAILABLE socketError={exception.SocketErrorCode}; run the app elevated to tell clients immediately when a QUIC connection is refused or gone. Without it they notice through their own timeouts.");
			return null;
		}
	}

	// Sends an ICMP "destination unreachable, port unreachable" report for a datagram that the client sent
	// from the given endpoint to the QUIC listener. The client's socket reports it as a refused connection,
	// which makes the client drop that QUIC connection at once instead of waiting for its timeouts, exactly
	// as if nothing was listening on the port.
	private static void SendPortUnreachable(IPEndPoint client, IPEndPoint listener)
	{
		Socket? socket = Volatile.Read(ref IcmpSocket);
		if (socket is null)
		{
			return;
		}

		// ICMP header (8 bytes), then the IPv4 header (20 bytes) and the UDP header (8 bytes) of the datagram being reported.
		Span<byte> message = stackalloc byte[36];
		message.Clear();
		message[0] = 3;
		message[1] = 3;
		Span<byte> ipHeader = message.Slice(8, 20);
		ipHeader[0] = 0x45;
		BinaryPrimitives.WriteUInt16BigEndian(ipHeader.Slice(2, 2), 28);
		ipHeader[6] = 0x40;
		ipHeader[8] = 64;
		ipHeader[9] = 17;
		if (!client.Address.TryWriteBytes(ipHeader.Slice(12, 4), out _) || !listener.Address.TryWriteBytes(ipHeader.Slice(16, 4), out _))
		{
			return;
		}
		BinaryPrimitives.WriteUInt16BigEndian(ipHeader.Slice(10, 2), ComputeInternetChecksum(ipHeader));
		Span<byte> udpHeader = message.Slice(28, 8);
		BinaryPrimitives.WriteUInt16BigEndian(udpHeader[..2], (ushort)client.Port);
		BinaryPrimitives.WriteUInt16BigEndian(udpHeader.Slice(2, 2), (ushort)listener.Port);
		BinaryPrimitives.WriteUInt16BigEndian(udpHeader.Slice(4, 2), 8);
		BinaryPrimitives.WriteUInt16BigEndian(message.Slice(2, 2), ComputeInternetChecksum(message));
		try
		{
			_ = socket.SendTo(message, SocketFlags.None, new IPEndPoint(client.Address, 0));
		}
		catch (SocketException)
		{
			// The report is best effort; without it the client notices through its own timeouts.
		}
		catch (ObjectDisposedException)
		{
			// The listener is shutting down.
		}
	}

	// The 16-bit one's complement checksum of RFC 1071. The data length is always even here.
	private static ushort ComputeInternetChecksum(ReadOnlySpan<byte> data)
	{
		uint sum = 0;
		for (int index = 0; index + 1 < data.Length; index += 2)
		{
			sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(index, 2));
		}
		while (sum >> 16 != 0)
		{
			sum = (sum & 0xFFFF) + (sum >> 16);
		}

		// The folded sum fits in 16 bits, so its complement is taken in 16 bits too. Complementing the
		// 32-bit value and narrowing it afterwards overflows because this project is checked for underflow/overflows.
		return (ushort)(sum ^ 0xFFFF);
	}

	private static async Task RunQuicProxyAsync(
		IPAddress address,
		IPAddress outboundAddress,
		IPAddress[] dnsServers,
		int listenerPort,
		CancellationToken cancellationToken)
	{
		using Socket listener = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
		ConfigureUdpProxySocket(listener);
		DisableUdpConnectionReset(listener);
		listener.Bind(new IPEndPoint(address, listenerPort));

		// The granted buffer sizes are logged because the OS may clamp the requested values, and a
		// clamped receive buffer is the first suspect when high-bandwidth flows lose datagrams.
		WriteLine($"QUIC UDP proxy listening on {address}:{listenerPort} receiveBuffer={listener.ReceiveBufferSize}B sendBuffer={listener.SendBufferSize}B");

		// ICMP reports tell a client at once that a QUIC connection was refused or is gone.
		using Socket? icmpSocket = CreateIcmpSocket(address);
		Volatile.Write(ref IcmpSocket, icmpSocket);
		IPEndPoint listenerEndPoint = new(address, listenerPort);

		// Each active client endpoint owns one flow; the flow removes itself from this table when it ends.
		ConcurrentDictionary<IPEndPoint, QuicFlow> flows = new();

		// Datagrams that cannot be routed to any flow are counted per client endpoint and logged with
		// rate limiting, so a client stuck on a dead connection becomes visible in the logs.
		Dictionary<IPEndPoint, UnroutableDatagramLogState> unroutable = [];
		long lastMaintenanceTimestamp = Stopwatch.GetTimestamp();

		// Started flows are tracked so that every flow that uses the listener socket completes before
		// the socket is disposed when the server loop ends.
		List<Task> handlers = [];

		// The flows run on their own token, so they end together with the server loop however it ends.
		// Without it, a failing server loop would wait for every flow to go idle (up to the idle timeout)
		// before its failure is reported, while no flow receives client datagrams anymore.
		using CancellationTokenSource flowsCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		CancellationToken flowsToken = flowsCancellation.Token;

		// Client endpoints whose connection was refused a moment ago. A client that has not noticed the
		// refusal yet keeps retransmitting its first packet; those retransmissions are answered with
		// another report instead of each starting a new flow that repeats the whole decision.
		ConcurrentDictionary<IPEndPoint, RefusedQuicConnection> refusedConnections = new();

		// The flow is captured through this local function's closure instead of being passed as an
		// explicit argument to the fire-and-forget call, and the flow removes its own table entry when it completes.
		async Task RunFlowAsync(QuicFlow flow)
		{
			try
			{
				await flow.RunAsync(flowsToken);
			}
			finally
			{
				if (flow.WasRefused)
				{
					refusedConnections[flow.ClientEndPoint] = new RefusedQuicConnection(flow.InitialDestinationConnectionId);
				}
				_ = flows.TryRemove(KeyValuePair.Create(flow.ClientEndPoint, flow));
			}
		}
		byte[] buffer = GC.AllocateUninitializedArray<byte>(MaxUdpDatagramSize);
		try
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				SocketReceiveFromResult received;
				try
				{
					received = await listener.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), cancellationToken);
				}
				catch (SocketException exception) when (exception.SocketErrorCode is SocketError.ConnectionReset or SocketError.NetworkReset or SocketError.MessageSize)
				{
					// ICMP errors reported against the shared listener socket (such as a client that went
					// away) must not stop the whole proxy; the affected flow simply loses that datagram.
					// Other socket errors are persistent (e.g. the adapter went away) and end the listener
					// instead of spinning in a tight loop that floods the log.
					WriteLine($"QUIC LISTENER RECEIVE ERROR socketError={exception.SocketErrorCode} error={exception.Message}");
					continue;
				}
				if (Stopwatch.GetElapsedTime(lastMaintenanceTimestamp) >= TimeSpan.FromSeconds(60))
				{
					lastMaintenanceTimestamp = Stopwatch.GetTimestamp();
					SweepQuicRoutingState(unroutable);
					foreach (KeyValuePair<IPEndPoint, RefusedQuicConnection> refused in refusedConnections)
					{
						if (Stopwatch.GetElapsedTime(refused.Value.Timestamp) >= RefusedQuicConnectionLifetime)
						{
							_ = refusedConnections.TryRemove(refused);
						}
					}
				}
				if (received.RemoteEndPoint is not IPEndPoint client || !IsLocalClient(client.Address))
				{
					WriteLine($"Rejected QUIC client {received.RemoteEndPoint}");
					continue;
				}
				ReadOnlySpan<byte> datagram = buffer.AsSpan(0, received.ReceivedBytes);
				bool isClientInitial = IsQuicClientInitialDatagram(datagram, out uint unsupportedVersion, out byte[]? initialDestinationConnectionId);
				if (flows.TryGetValue(client, out QuicFlow? existingFlow))
				{
					if (!isClientInitial || !existingFlow.IsEstablished || existingFlow.IsInitialOfThisConnection(initialDestinationConnectionId))
					{
						// This also covers the Initial packets of a handshake that is still in progress: after a
						// server Retry, and once the server has answered, the client's Initial packets carry a
						// server-chosen Destination Connection ID instead of the original one.
						existingFlow.EnqueueClientDatagram(datagram);
						continue;
					}

					// A client that finished its handshake never sends Initial packets for that connection again,
					// so this Initial opens a new connection from a UDP port that the client is reusing. Forwarding
					// it to the old flow would deliver the new connection to the previous flow's server.
					WriteLine($"QUIC CLIENT ENDPOINT REUSED client={client} previousConnectionId={existingFlow.ConnectionId} destinationConnectionId={Convert.ToHexString(initialDestinationConnectionId ?? [])}; the previous flow is closed and a new flow is started");
					existingFlow.Terminate("client-endpoint-reused-by-new-connection", false);
					_ = flows.TryRemove(KeyValuePair.Create(client, existingFlow));
				}
				if (!isClientInitial)
				{
					bool isShortHeader = datagram.Length != 0 && (datagram[0] & 0x80) == 0;
					if (isShortHeader && TryFindFlowByServerConnectionId(flows, client, datagram) is QuicFlow movedFlow)
					{
						// The packet belongs to a live connection whose client endpoint changed, which happens when
						// a NAT between the client and this machine assigns the connection a new port. The flow
						// follows the client to its new endpoint, like the server itself would.
						IPEndPoint previousEndPoint = movedFlow.ClientEndPoint;
						_ = flows.TryRemove(KeyValuePair.Create(previousEndPoint, movedFlow));
						movedFlow.ClientEndPoint = client;
						flows[client] = movedFlow;
						WriteLine($"CONNECTION #{movedFlow.ConnectionId} CLIENT ENDPOINT CHANGED previous={previousEndPoint} current={client}");
						movedFlow.EnqueueClientDatagram(datagram);
						continue;
					}
					string unroutableReason = unsupportedVersion == 0
						? "no-live-flow"
						: $"unsupported-version-0x{unsupportedVersion:x8}";
					UnroutableDatagramLogState unroutableState = LogUnroutableDatagram(unroutable, client, datagram, unroutableReason);

					// A short header packet belongs to a connection that no longer has a flow here (it was
					// closed, refused, or it expired). Silently dropping it would leave the client waiting for
					// its own timeouts, so the client is told that the connection is gone.
					if (isShortHeader && (unroutableState.LastIcmpTimestamp == 0 || Stopwatch.GetElapsedTime(unroutableState.LastIcmpTimestamp) >= IcmpReportInterval))
					{
						unroutableState.LastIcmpTimestamp = Stopwatch.GetTimestamp();
						SendPortUnreachable(client, listenerEndPoint);
					}
					continue;
				}

				// A retransmitted first packet of a connection that was just refused gets the refusal again.
				if (refusedConnections.TryGetValue(client, out RefusedQuicConnection? refusedConnection))
				{
					if (Stopwatch.GetElapsedTime(refusedConnection.Timestamp) < RefusedQuicConnectionLifetime &&
						refusedConnection.Matches(initialDestinationConnectionId))
					{
						if (refusedConnection.LastIcmpTimestamp == 0 || Stopwatch.GetElapsedTime(refusedConnection.LastIcmpTimestamp) >= IcmpReportInterval)
						{
							refusedConnection.LastIcmpTimestamp = Stopwatch.GetTimestamp();
							SendPortUnreachable(client, listenerEndPoint);
						}
						continue;
					}

					// The client opened a different connection from the same UDP port, which is decided on its own.
					_ = refusedConnections.TryRemove(KeyValuePair.Create(client, refusedConnection));
				}

				// No active route exists for this client endpoint, so this Initial starts a new flow.
				QuicFlow flow = new(listener, client, listenerEndPoint, outboundAddress, dnsServers, initialDestinationConnectionId);
				flows[client] = flow;
				flow.EnqueueClientDatagram(datagram);

				// Completed handlers are discarded so the tracking list stays proportional to the active flows.
				_ = handlers.RemoveAll(static handler => handler.IsCompleted);
				handlers.Add(RunFlowAsync(flow));
			}
		}
		finally
		{
			// The flows are ended first: they all use the listener socket, and nothing delivers client datagrams to them anymore.
			await flowsCancellation.CancelAsync();
			await Task.WhenAll(handlers);
			Volatile.Write(ref IcmpSocket, null);
		}
	}

	// Finds the flow of the same client address whose server-chosen connection ID starts the given short header packet.
	private static QuicFlow? TryFindFlowByServerConnectionId(ConcurrentDictionary<IPEndPoint, QuicFlow> flows, IPEndPoint client, ReadOnlySpan<byte> datagram)
	{
		foreach (KeyValuePair<IPEndPoint, QuicFlow> entry in flows)
		{
			if (entry.Key.Address.Equals(client.Address) && entry.Value.MatchesServerConnectionId(datagram))
			{
				return entry.Value;
			}
		}
		return null;
	}

	// Removes stale unroutable-datagram log entries. The table is also cleared defensively if it
	// somehow grows past any plausible number of client endpoints.
	private static void SweepQuicRoutingState(Dictionary<IPEndPoint, UnroutableDatagramLogState> unroutable)
	{
		List<IPEndPoint>? staleEndpoints = null;
		foreach (KeyValuePair<IPEndPoint, UnroutableDatagramLogState> entry in unroutable)
		{
			if (Stopwatch.GetElapsedTime(entry.Value.LastSeenTimestamp) >= QuicTombstoneLifetime)
			{
				(staleEndpoints ??= []).Add(entry.Key);
			}
		}
		if (staleEndpoints is not null)
		{
			foreach (IPEndPoint endpoint in staleEndpoints)
			{
				_ = unroutable.Remove(endpoint);
			}
		}
		if (unroutable.Count > 4096)
		{
			unroutable.Clear();
		}
	}

	// Logs the first unroutable datagram of a client endpoint immediately and later ones at most once
	// per progress interval, so a retry storm of a dead connection stays readable in the logs.
	// Returns the state of the client endpoint, which also rate limits its ICMP reports.
	private static UnroutableDatagramLogState LogUnroutableDatagram(
		Dictionary<IPEndPoint, UnroutableDatagramLogState> unroutable,
		IPEndPoint client,
		ReadOnlySpan<byte> datagram,
		string reason)
	{
		if (!unroutable.TryGetValue(client, out UnroutableDatagramLogState? state))
		{
			state = new UnroutableDatagramLogState();
			unroutable[client] = state;
		}
		state.Count++;
		state.LastSeenTimestamp = Stopwatch.GetTimestamp();
		if (state.LastLogTimestamp != 0 && Stopwatch.GetElapsedTime(state.LastLogTimestamp) < RelayProgressInterval)
		{
			return state;
		}
		state.LastLogTimestamp = Stopwatch.GetTimestamp();
		string headerForm = datagram.Length == 0 ? "empty" : (datagram[0] & 0x80) != 0 ? "long" : "short";
		WriteLine($"QUIC UNROUTABLE DATAGRAM client={client} reason={reason} size={datagram.Length}B headerForm={headerForm} firstByte=0x{(datagram.Length == 0 ? 0 : datagram[0]):x2} count={state.Count}");
		return state;
	}

	// Enables TCP keep-alive probes on a relayed connection. A phone that leaves the network or goes to
	// sleep does not close its connections, and without probes such a connection (and its counterpart
	// to the destination) would stay open here until the program stops.
	private static void ConfigureTcpKeepAlive(Socket socket)
	{
		try
		{
			socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
			socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, TcpKeepAliveTimeSeconds);
			socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, TcpKeepAliveIntervalSeconds);
			socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, TcpKeepAliveRetryCount);
		}
		catch (SocketException)
		{
			// The connection works without the probes; a dead peer is then only noticed when data is sent to it.
		}
	}

	private static void ConfigureUdpProxySocket(Socket socket)
	{
		// Video-rate QUIC traffic arrives in bursts, so the default socket buffers are enlarged to avoid drops.
		socket.ReceiveBufferSize = UdpProxySocketBufferSize;
		socket.SendBufferSize = UdpProxySocketBufferSize;
	}

	internal static void DisableUdpConnectionReset(Socket socket)
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}
		try
		{
			// SIO_UDP_CONNRESET (0x9800000C) set to FALSE stops Windows from surfacing ICMP
			// port-unreachable reports as ConnectionReset errors on later socket operations, which would
			// otherwise tear down the shared listener loop or an established relay flow.
			_ = socket.IOControl(unchecked((int)0x9800000C), [0, 0, 0, 0], null);
		}
		catch (SocketException)
		{
		}
		try
		{
			// SIO_UDP_NETRESET (0x9800000F) set to FALSE does the same for ICMP network-unreachable and
			// time-exceeded reports, which routers send during a short outage of the outbound path and
			// which Windows would otherwise surface as NetworkReset errors.
			_ = socket.IOControl(unchecked((int)0x9800000F), [0, 0, 0, 0], null);
		}
		catch (SocketException)
		{
		}
	}

	private static bool IsQuicClientInitialDatagram(
		ReadOnlySpan<byte> datagram,
		out uint unsupportedVersion,
		out byte[]? destinationConnectionId)
	{
		unsupportedVersion = 0;
		destinationConnectionId = null;

		// Datagrams that carry a client Initial packet are at least 1200 bytes (RFC 9000 Section 14.1) and
		// coalesced packet sequences start with the Initial packet, so a new flow is only started for a
		// long header packet of that size. The header form bit is the only reliable first-byte invariant.
		if (datagram.Length < QuicMinimumClientInitialDatagramSize || (datagram[0] & 0x80) == 0)
		{
			return false;
		}
		uint version = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(1, 4));
		int packetType = (datagram[0] & 0x30) >> 4;
		bool isInitial = version == QuicVersion1 ? packetType == 0 : version == QuicVersion2 && packetType == 1;
		if (isInitial)
		{
			int destinationConnectionIdLength = datagram[5];
			if (destinationConnectionIdLength > QuicMaxConnectionIdLength || 6 + destinationConnectionIdLength > datagram.Length)
			{
				return false;
			}
			destinationConnectionId = datagram.Slice(6, destinationConnectionIdLength).ToArray();
			return true;
		}
		if (version != 0 && version != QuicVersion1 && version != QuicVersion2)
		{
			unsupportedVersion = version;
		}
		return false;
	}

	private static void ParseQuicInitialDatagram(ReadOnlySpan<byte> datagram, QuicClientHelloAssembler assembler)
	{
		// A datagram may coalesce several QUIC packets (RFC 9000 Section 12.2). Every Initial packet is
		// decrypted for CRYPTO frames; other packet types are skipped using their length field. Structural
		// problems end the scan of the remaining bytes without failing the flow, because the client keeps
		// retransmitting its Initial flight until the ClientHello can be assembled or the flow times out.
		int offset = 0;
		while (offset < datagram.Length)
		{
			int packetStart = offset;
			byte firstByte = datagram[offset];
			if ((firstByte & 0x80) == 0 || datagram.Length - offset < 5)
			{
				// A short header packet has no length field and always consumes the rest of the datagram.
				return;
			}
			uint version = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(offset + 1, 4));
			if (version != QuicVersion1 && version != QuicVersion2)
			{
				// Version Negotiation packets and unknown versions do not use the version 1/2 long header
				// layout beyond the connection IDs, so nothing after this point can be parsed safely.
				return;
			}
			offset += 5;
			if (offset >= datagram.Length)
			{
				return;
			}
			int destinationConnectionIdLength = datagram[offset++];
			if (destinationConnectionIdLength > QuicMaxConnectionIdLength || destinationConnectionIdLength > datagram.Length - offset)
			{
				return;
			}
			ReadOnlySpan<byte> destinationConnectionId = datagram.Slice(offset, destinationConnectionIdLength);
			offset += destinationConnectionIdLength;
			if (offset >= datagram.Length)
			{
				return;
			}
			int sourceConnectionIdLength = datagram[offset++];
			if (sourceConnectionIdLength > QuicMaxConnectionIdLength || sourceConnectionIdLength > datagram.Length - offset)
			{
				return;
			}
			offset += sourceConnectionIdLength;

			// Long header packet types differ between the versions (RFC 9000 Section 17.2, RFC 9369 Section 3.2).
			int packetType = (firstByte & 0x30) >> 4;
			bool isInitial = version == QuicVersion1 ? packetType == 0 : packetType == 1;
			bool isRetry = version == QuicVersion1 ? packetType == 3 : packetType == 0;
			if (isRetry)
			{
				// Retry packets have no length field and consume the rest of the datagram; clients never send them.
				return;
			}
			if (isInitial)
			{
				if (!TryReadQuicVariableLength(datagram, ref offset, out ulong tokenLength) ||
					tokenLength > (ulong)(datagram.Length - offset))
				{
					return;
				}
				offset += (int)tokenLength;
			}
			if (!TryReadQuicVariableLength(datagram, ref offset, out ulong payloadLength) ||
				payloadLength > (ulong)(datagram.Length - offset))
			{
				return;
			}
			int packetNumberOffset = offset;
			int packetEnd = offset + checked((int)payloadLength);
			if (isInitial)
			{
				byte[]? plaintext = DecryptQuicInitialPacket(datagram, packetStart, packetNumberOffset, packetEnd, version, destinationConnectionId);
				if (plaintext is not null)
				{
					ParseQuicInitialFrames(plaintext, assembler);
				}
			}
			offset = packetEnd;
		}
	}
	private static byte[]? DecryptQuicInitialPacket(
		ReadOnlySpan<byte> datagram,
		int packetStart,
		int packetNumberOffset,
		int packetEnd,
		uint version,
		ReadOnlySpan<byte> destinationConnectionId)
	{
		// The packet number is at most 4 bytes and the header protection sample starts 4 bytes into that
		// field (RFC 9001 Section 5.4.2), so a decryptable payload needs the sample plus the AEAD tag.
		if (packetNumberOffset > packetEnd || packetEnd - packetNumberOffset < 4 + QuicHeaderProtectionSampleLength)
		{
			return null;
		}
		Span<byte> key = stackalloc byte[16];
		Span<byte> iv = stackalloc byte[12];
		Span<byte> headerProtectionKey = stackalloc byte[16];
		DeriveQuicInitialClientKeys(version, destinationConnectionId, key, iv, headerProtectionKey);

		// Header protection removal (RFC 9001 Section 5.4): the mask is the AES-ECB encryption of the
		// sample; the low 4 bits of the first byte and the packet number bytes are unmasked with it.
		Span<byte> mask = stackalloc byte[QuicHeaderProtectionSampleLength];
		using (Aes headerProtection = Aes.Create())
		{
			headerProtection.Key = headerProtectionKey.ToArray();
			_ = headerProtection.EncryptEcb(datagram.Slice(packetNumberOffset + 4, QuicHeaderProtectionSampleLength), mask, PaddingMode.None);
		}
		byte firstByte = (byte)(datagram[packetStart] ^ (mask[0] & 0x0F));
		int packetNumberLength = (firstByte & 0x03) + 1;

		// The associated data is the whole header, from the first byte through the unprotected packet number.
		if (packetNumberOffset < packetStart || packetNumberLength > packetEnd - packetNumberOffset)
		{
			return null;
		}
		int headerLength = packetNumberOffset - packetStart + packetNumberLength;
		byte[] header = datagram.Slice(packetStart, headerLength).ToArray();
		header[0] = firstByte;
		ulong packetNumber = 0;
		for (int index = 0; index < packetNumberLength; index++)
		{
			byte unprotectedByte = (byte)(datagram[packetNumberOffset + index] ^ mask[1 + index]);
			header[headerLength - packetNumberLength + index] = unprotectedByte;
			packetNumber = (packetNumber << 8) | unprotectedByte;
		}

		// Only the client's first flight is parsed here, so the truncated packet number is already the
		// full value and no reconstruction against a largest received number is needed.
		Span<byte> nonce = stackalloc byte[12];
		iv.CopyTo(nonce);
		for (int index = 0; index < 8; index++)
		{
			int shift = 56 - (8 * index);
			nonce[4 + index] ^= checked((byte)((packetNumber >> shift) & byte.MaxValue));
		}
		ReadOnlySpan<byte> ciphertext = datagram[(packetNumberOffset + packetNumberLength)..(packetEnd - QuicAeadTagLength)];
		ReadOnlySpan<byte> tag = datagram.Slice(packetEnd - QuicAeadTagLength, QuicAeadTagLength);
		byte[] plaintext = GC.AllocateUninitializedArray<byte>(ciphertext.Length);
		try
		{
			using AesGcm aead = new(key, QuicAeadTagLength);
			aead.Decrypt(nonce, ciphertext, tag, plaintext, header);
		}
		catch (CryptographicException)
		{
			// An authentication failure means this is not a valid Initial packet for the derived keys;
			// the packet is skipped and later datagrams may still complete the ClientHello.
			return null;
		}
		return plaintext;
	}

	private static void DeriveQuicInitialClientKeys(
		uint version,
		ReadOnlySpan<byte> destinationConnectionId,
		Span<byte> key,
		Span<byte> iv,
		Span<byte> headerProtectionKey)
	{
		// Initial packet protection keys (RFC 9001 Section 5.2, RFC 9369 Section 3.3.1) are derived from
		// the client's Destination Connection ID with a version-specific salt and version-specific labels.
		byte[] salt = version == QuicVersion2 ? QuicVersion2InitialSalt : QuicVersion1InitialSalt;
		Span<byte> initialSecret = stackalloc byte[32];
		_ = HKDF.Extract(HashAlgorithmName.SHA256, destinationConnectionId, salt, initialSecret);
		Span<byte> clientInitialSecret = stackalloc byte[32];
		HkdfExpandLabel(initialSecret, "client in", clientInitialSecret);
		HkdfExpandLabel(clientInitialSecret, version == QuicVersion2 ? "quicv2 key" : "quic key", key);
		HkdfExpandLabel(clientInitialSecret, version == QuicVersion2 ? "quicv2 iv" : "quic iv", iv);
		HkdfExpandLabel(clientInitialSecret, version == QuicVersion2 ? "quicv2 hp" : "quic hp", headerProtectionKey);
	}

	private static void HkdfExpandLabel(ReadOnlySpan<byte> secret, string label, Span<byte> output)
	{
		// HkdfLabel structure from RFC 8446 Section 7.1 with an empty context: the output length, the
		// label prefixed with "tls13 ", and a zero-length context.
		int labelLength = 6 + label.Length;
		Span<byte> info = stackalloc byte[4 + labelLength];
		BinaryPrimitives.WriteUInt16BigEndian(info, checked((ushort)output.Length));
		info[2] = checked((byte)labelLength);
		_ = Encoding.ASCII.GetBytes("tls13 ", info.Slice(3, 6));
		_ = Encoding.ASCII.GetBytes(label, info.Slice(9, label.Length));
		info[3 + labelLength] = 0;
		HKDF.Expand(HashAlgorithmName.SHA256, secret, output, info);
	}

	private static bool TryReadQuicVariableLength(ReadOnlySpan<byte> data, ref int offset, out ulong value)
	{
		// Variable-length integer encoding from RFC 9000 Section 16: the two most significant bits of the
		// first byte select a total length of 1, 2, 4, or 8 bytes.
		value = 0;
		if (offset >= data.Length)
		{
			return false;
		}
		int length = 1 << (data[offset] >> 6);
		if (length > data.Length - offset)
		{
			return false;
		}
		value = (ulong)(data[offset] & 0x3F);
		for (int index = 1; index < length; index++)
		{
			value = (value << 8) | data[offset + index];
		}
		offset += length;
		return true;
	}

	private static void ParseQuicInitialFrames(ReadOnlySpan<byte> plaintext, QuicClientHelloAssembler assembler)
	{
		// Initial packets may carry PADDING, PING, ACK, CRYPTO, and CONNECTION_CLOSE frames
		// (RFC 9000 Section 12.4). CRYPTO frame contents are collected; the others are skipped.
		int offset = 0;
		while (offset < plaintext.Length)
		{
			if (plaintext[offset] == 0)
			{
				// PADDING frames form long runs, so single zero bytes are skipped without varint decoding.
				offset++;
				continue;
			}
			if (!TryReadQuicVariableLength(plaintext, ref offset, out ulong frameType))
			{
				return;
			}
			switch (frameType)
			{
				case 0x00:
				case 0x01:
					// PADDING encoded as a longer varint, and PING, carry no fields.
					break;
				case 0x02:
				case 0x03:
					{
						if (!TryReadQuicVariableLength(plaintext, ref offset, out _) ||
							!TryReadQuicVariableLength(plaintext, ref offset, out _) ||
							!TryReadQuicVariableLength(plaintext, ref offset, out ulong ackRangeCount) ||
							!TryReadQuicVariableLength(plaintext, ref offset, out _))
						{
							return;
						}
						for (ulong index = 0; index < ackRangeCount; index++)
						{
							if (!TryReadQuicVariableLength(plaintext, ref offset, out _) ||
								!TryReadQuicVariableLength(plaintext, ref offset, out _))
							{
								return;
							}
						}
						if (frameType == 0x03 &&
							(!TryReadQuicVariableLength(plaintext, ref offset, out _) ||
							!TryReadQuicVariableLength(plaintext, ref offset, out _) ||
							!TryReadQuicVariableLength(plaintext, ref offset, out _)))
						{
							return;
						}
						break;
					}
				case 0x06:
					{
						if (!TryReadQuicVariableLength(plaintext, ref offset, out ulong cryptoOffset) ||
							!TryReadQuicVariableLength(plaintext, ref offset, out ulong cryptoLength) ||
							cryptoLength > (ulong)(plaintext.Length - offset))
						{
							return;
						}
						assembler.Add(cryptoOffset, plaintext.Slice(offset, checked((int)cryptoLength)));
						offset += (int)cryptoLength;
						break;
					}
				case 0x1c:
					{
						if (!TryReadQuicVariableLength(plaintext, ref offset, out _) ||
							!TryReadQuicVariableLength(plaintext, ref offset, out _) ||
							!TryReadQuicVariableLength(plaintext, ref offset, out ulong reasonLength) ||
							reasonLength > (ulong)(plaintext.Length - offset))
						{
							return;
						}
						offset += (int)reasonLength;
						break;
					}
				default:
					// The length of an unknown frame cannot be determined, so the rest of the packet is skipped.
					return;
			}
		}
	}

	private static async Task<byte[]> ReadTlsClientHelloAsync(Stream stream, CancellationToken cancellationToken)
	{
		using MemoryStream captured = new(MaxHeaderSize);
		using MemoryStream handshake = new(MaxHeaderSize);
		byte[] header = new byte[5];
		while (captured.Length < MaxHeaderSize)
		{
			if (!await ReadExactlyOrEofAsync(stream, header, cancellationToken) || header[0] != 22)
			{
				throw new InvalidDataException("Expected a TLS handshake record.");
			}
			int payloadLength = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3, 2));
			if (payloadLength <= 0 || captured.Length + 5 + payloadLength > MaxHeaderSize)
			{
				throw new InvalidDataException("Invalid or oversized TLS ClientHello.");
			}
			byte[] payload = GC.AllocateUninitializedArray<byte>(payloadLength);
			if (!await ReadExactlyOrEofAsync(stream, payload, cancellationToken))
			{
				throw new EndOfStreamException("Truncated TLS record.");
			}
			captured.Write(header);
			captured.Write(payload);
			handshake.Write(payload);
			if (handshake.Length >= 4)
			{
				byte[] bytes = handshake.GetBuffer();
				if (bytes[0] != 1)
				{
					throw new InvalidDataException("The first TLS handshake message is not ClientHello.");
				}
				int length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
				if (length + 4 > MaxHeaderSize)
				{
					throw new InvalidDataException("Oversized TLS ClientHello.");
				}
				if (handshake.Length >= length + 4)
				{
					return captured.ToArray();
				}
			}
		}
		throw new InvalidDataException("TLS ClientHello was not found.");
	}

	private static string ExtractSni(byte[] records)
	{
		using MemoryStream combined = new(records.Length);
		int recordOffset = 0;
		while (recordOffset < records.Length)
		{
			Require(records, recordOffset, 5);
			if (records[recordOffset] != 22)
			{
				throw new InvalidDataException("Invalid TLS record sequence.");
			}
			int length = BinaryPrimitives.ReadUInt16BigEndian(records.AsSpan(recordOffset + 3, 2));
			recordOffset += 5;
			Require(records, recordOffset, length);
			combined.Write(records, recordOffset, length);
			recordOffset += length;
		}
		ReadOnlySpan<byte> data = combined.GetBuffer().AsSpan(0, checked((int)combined.Length));
		return ExtractSniFromClientHello(data);
	}

	private static string ExtractSniFromClientHello(ReadOnlySpan<byte> data)
	{
		Require(data, 0, 4);
		if (data[0] != 1)
		{
			throw new InvalidDataException("Invalid TLS ClientHello.");
		}
		int offset = 4;
		Require(data, offset, 34);
		offset += 34;
		int sessionIdLength = ReadByte(data, ref offset);
		Require(data, offset, sessionIdLength);
		offset += sessionIdLength;
		int cipherLength = ReadUInt16(data, ref offset);
		Require(data, offset, cipherLength);
		offset += cipherLength;
		int compressionMethodsLength = ReadByte(data, ref offset);
		Require(data, offset, compressionMethodsLength);
		offset += compressionMethodsLength;
		int extensionsLength = ReadUInt16(data, ref offset);
		int extensionsEnd = checked(offset + extensionsLength);
		Require(data, offset, extensionsLength);
		while (offset < extensionsEnd)
		{
			int type = ReadUInt16(data, ref offset);
			int extensionLength = ReadUInt16(data, ref offset);
			int extensionEnd = checked(offset + extensionLength);
			if (extensionEnd > extensionsEnd)
			{
				throw new InvalidDataException("Invalid TLS extension length.");
			}
			if (type == 0)
			{
				int listLength = ReadUInt16(data, ref offset);
				int listEnd = checked(offset + listLength);
				if (listEnd > extensionEnd)
				{
					throw new InvalidDataException("Invalid TLS server_name extension.");
				}
				while (offset < listEnd)
				{
					int nameType = ReadByte(data, ref offset);
					int nameLength = ReadUInt16(data, ref offset);
					Require(data, offset, nameLength);
					if (offset + nameLength > listEnd)
					{
						throw new InvalidDataException("Invalid TLS server name.");
					}
					if (nameType == 0)
					{
						return ValidateHost(Encoding.ASCII.GetString(data.Slice(offset, nameLength)));
					}
					offset += nameLength;
				}
			}
			offset = extensionEnd;
		}
		throw new InvalidDataException("TLS ClientHello has no usable SNI host name.");
	}

	private static async Task<byte[]> ReadHttpHeadersAsync(Stream stream, CancellationToken cancellationToken)
	{
		byte[] buffer = new byte[MaxHeaderSize];
		int length = 0;
		while (length < buffer.Length)
		{
			int read = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken);
			if (read == 0)
			{
				throw new EndOfStreamException("HTTP request ended before its headers.");
			}
			length += read;
			if (FindHeaderEnd(buffer.AsSpan(0, length)) >= 0)
			{
				return buffer.AsSpan(0, length).ToArray();
			}
		}
		throw new InvalidDataException("HTTP headers are too large.");
	}

	private static string ExtractHttpHost(byte[] request)
	{
		int end = FindHeaderEnd(request);
		if (end < 0)
		{
			throw new InvalidDataException("Incomplete HTTP headers.");
		}
		string[] lines = Encoding.ASCII.GetString(request, 0, end).Split("\r\n", StringSplitOptions.None);
		foreach (string line in lines)
		{
			if (!line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}
			string authority = line[5..].Trim();
			int colon = authority.AsSpan().LastIndexOf(':');
			string host = colon > 0 && authority.IndexOf(':', StringComparison.Ordinal) == colon ? authority[..colon] : authority;
			return ValidateHost(host.Trim());
		}
		throw new InvalidDataException("HTTP request has no Host header.");
	}

	private static string ValidateHost(string host)
	{
		if (host.Length is 0 or > 253 || host[^1] == '.')
		{
			throw new InvalidDataException("Invalid host name.");
		}
		foreach (char character in host)
		{
			if (!char.IsAsciiLetterOrDigit(character) && character is not '-' and not '.')
			{
				throw new InvalidDataException("Invalid host name.");
			}
		}
		return host;
	}

	private static int FindHeaderEnd(ReadOnlySpan<byte> data)
	{
		for (int index = 0; index <= data.Length - 4; index++)
		{
			if (data[index] == 13 && data[index + 1] == 10 && data[index + 2] == 13 && data[index + 3] == 10)
			{
				return index + 4;
			}
		}
		return -1;
	}

	private static async Task<RelayResult> CopyAsync(
		long connectionId,
		Stream source,
		Stream destination,
		Socket destinationSocket,
		string sourceRole,
		EndPoint? sourceEndPoint,
		string destinationRole,
		EndPoint? destinationEndPoint,
		ClientTrafficCounters clientTraffic,
		bool upload,
		CancellationToken cancellationToken,
		CancellationToken shutdownToken)
	{
		byte[] buffer = GC.AllocateUninitializedArray<byte>(65536);
		long totalBytes = 0;

		// Progress diagnostics reveal whether a quiet connection is truly stalled or still trickling.
		long progressTimestamp = Stopwatch.GetTimestamp();
		long progressBytes = 0;
		string termination = "end-of-stream";
		try
		{
			while (true)
			{
				int bytesRead;
				try
				{
					bytesRead = await source.ReadAsync(buffer, cancellationToken);
				}
				catch (IOException exception)
				{
					termination = FormatRelayIOException("source-read", "sourceRole", sourceRole, "sourceEndpoint", sourceEndPoint, exception);
					break;
				}
				catch (SocketException exception)
				{
					termination = FormatRelaySocketException("source-read", "sourceRole", sourceRole, "sourceEndpoint", sourceEndPoint, exception);
					break;
				}
				if (bytesRead == 0)
				{
					break;
				}
				try
				{
					await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
				}
				catch (IOException exception)
				{
					termination = FormatRelayIOException("destination-write", "destinationRole", destinationRole, "destinationEndpoint", destinationEndPoint, exception);
					break;
				}
				catch (SocketException exception)
				{
					termination = FormatRelaySocketException("destination-write", "destinationRole", destinationRole, "destinationEndpoint", destinationEndPoint, exception);
					break;
				}
				totalBytes += bytesRead;
				if (upload)
				{
					_ = Interlocked.Add(ref TotalBytesSent, bytesRead);
					_ = Interlocked.Add(ref clientTraffic.TotalBytesSent, bytesRead);
				}
				else
				{
					_ = Interlocked.Add(ref TotalBytesReceived, bytesRead);
					_ = Interlocked.Add(ref clientTraffic.TotalBytesReceived, bytesRead);
				}
				if (Stopwatch.GetElapsedTime(progressTimestamp) >= RelayProgressInterval)
				{
					WriteLine($"CONNECTION #{connectionId} PROGRESS direction={sourceRole}->{destinationRole} intervalBytes={totalBytes - progressBytes}B totalBytes={totalBytes}B");
					progressTimestamp = Stopwatch.GetTimestamp();
					progressBytes = totalBytes;
				}
			}
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			termination = shutdownToken.IsCancellationRequested ? "program-shutdown" : "opposite-direction-failed";
		}
		finally
		{
			try
			{
				destinationSocket.Shutdown(SocketShutdown.Send);
			}
			catch (SocketException exception)
			{
				if (string.Equals(termination, "end-of-stream", StringComparison.Ordinal))
				{
					termination = $"shutdown-SocketException:{exception.SocketErrorCode}:{exception.Message}";
				}
			}
			catch (ObjectDisposedException)
			{
				if (string.Equals(termination, "end-of-stream", StringComparison.Ordinal))
				{
					termination = "shutdown-object-disposed";
				}
			}
		}
		return new RelayResult(totalBytes, termination);
	}

	private static string FormatRelayIOException(
		string operation,
		string roleLabel,
		string role,
		string endpointLabel,
		EndPoint? endpoint,
		IOException exception)
		=> exception.InnerException is SocketException socketException
			? FormatRelaySocketException(operation, roleLabel, role, endpointLabel, endpoint, socketException)
			: $"{operation}-io-failure {roleLabel}={role} {endpointLabel}={endpoint} error={exception.GetType().Name}:{exception.Message}";

	private static string FormatRelaySocketException(
		string operation,
		string roleLabel,
		string role,
		string endpointLabel,
		EndPoint? endpoint,
		SocketException exception)
		=> $"{operation}-{GetRelaySocketFailureName(exception.SocketErrorCode)} {roleLabel}={role} {endpointLabel}={endpoint} socketError={exception.SocketErrorCode} error={exception.Message}";

	private static string GetRelaySocketFailureName(SocketError socketError) => socketError switch
	{
		SocketError.ConnectionReset => "reset",
		SocketError.ConnectionAborted => "aborted",
		SocketError.TimedOut => "timeout",
		_ => "socket-failure"
	};

	internal static async Task<bool> ReadExactlyOrEofAsync(
		Stream stream,
		Memory<byte> destination,
		CancellationToken cancellationToken)
	{
		int total = 0;
		while (total < destination.Length)
		{
			int read = await stream.ReadAsync(destination[total..], cancellationToken);
			if (read == 0)
			{
				if (total == 0)
				{
					return false;
				}
				throw new EndOfStreamException($"The stream ended after {total} of {destination.Length} required bytes were received.");
			}
			total += read;
		}
		return true;
	}

	private static int ReadByte(ReadOnlySpan<byte> data, ref int offset)
	{
		Require(data, offset, 1);
		return data[offset++];
	}

	private static int ReadUInt16(ReadOnlySpan<byte> data, ref int offset)
	{
		Require(data, offset, 2);
		int value = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
		offset += 2;
		return value;
	}

	private static void Require(ReadOnlySpan<byte> data, int offset, int length)
	{
		if (offset < 0 || length < 0 || offset > data.Length - length)
		{
			throw new InvalidDataException("Truncated or malformed protocol message.");
		}
	}

	private static void WriteLine(string message) => LogSink?.Invoke($"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz}] {message}");

	private static bool IsLinkLocal(IPAddress address)
	{
		byte[] bytes = address.GetAddressBytes();
		return bytes[0] == 169 && bytes[1] == 254;
	}

	internal static bool IsLocalClient(IPAddress address) => IPAddress.IsLoopback(address) || IsPrivate(address);

	private static bool IsPrivate(IPAddress address)
	{
		if (address.AddressFamily != AddressFamily.InterNetwork)
		{
			return false;
		}
		byte[] bytes = address.GetAddressBytes();
		return bytes[0] == 10 || bytes[0] == 127 ||
			bytes[0] == 192 && bytes[1] == 168 ||
			bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
			bytes[0] == 169 && bytes[1] == 254;
	}

	private static bool IsPublic(IPAddress address)
	{
		if (address.AddressFamily != AddressFamily.InterNetwork || IsPrivate(address))
		{
			return false;
		}
		byte[] bytes = address.GetAddressBytes();
		return bytes[0] != 0 && bytes[0] < 224 &&
			!(bytes[0] == 100 && bytes[1] is >= 64 and <= 127) &&
			!(bytes[0] == 192 && bytes[1] == 0 && bytes[2] is 0 or 2) &&
			!(bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100) &&
			!(bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113);
	}

	private sealed class QuicClientHelloAssembler
	{
		// CRYPTO frame contents are placed at their stream offsets and the received ranges are tracked,
		// because a large ClientHello can span multiple Initial packets that may arrive out of order,
		// duplicated, or overlapping (retransmissions carry identical bytes).
		private readonly byte[] Buffer = new byte[MaxHeaderSize];
		private readonly List<(int Start, int End)> Ranges = [with(4)];
		internal void Add(ulong offset, ReadOnlySpan<byte> data)
		{
			if (data.Length == 0)
			{
				return;
			}
			if (offset >= MaxHeaderSize || (ulong)data.Length > MaxHeaderSize - offset)
			{
				return;
			}
			int start = checked((int)offset);
			int end = start + data.Length;
			data.CopyTo(Buffer.AsSpan(start));
			int index = 0;
			while (index < Ranges.Count && Ranges[index].End < start)
			{
				index++;
			}
			// Every stored range that overlaps or touches the new range is folded into it.
			while (index < Ranges.Count && Ranges[index].Start <= end)
			{
				start = Math.Min(start, Ranges[index].Start);
				end = Math.Max(end, Ranges[index].End);
				Ranges.RemoveAt(index);
			}
			Ranges.Insert(index, (start, end));
		}

		internal bool TryGetClientHello(out ReadOnlyMemory<byte> clientHello)
		{
			clientHello = default;
			int contiguousLength = Ranges.Count != 0 && Ranges[0].Start == 0 ? Ranges[0].End : 0;

			// The 4-byte TLS handshake message header carries the message type and body length.
			if (contiguousLength < 4)
			{
				return false;
			}
			if (Buffer[0] != 1)
			{
				throw new InvalidDataException("The first QUIC handshake message is not ClientHello.");
			}
			int messageLength = (Buffer[1] << 16) | (Buffer[2] << 8) | Buffer[3];
			if (messageLength > MaxHeaderSize - 4)
			{
				throw new InvalidDataException("Oversized QUIC ClientHello.");
			}
			int totalLength = messageLength + 4;
			if (contiguousLength < totalLength)
			{
				return false;
			}
			clientHello = Buffer.AsMemory(0, totalLength);
			return true;
		}
	}

	// Rate-limiting state for the unroutable-datagram log lines and ICMP reports of one client endpoint.
	private sealed class UnroutableDatagramLogState
	{
		internal long Count;
		internal long LastLogTimestamp;
		internal long LastSeenTimestamp;
		internal long LastIcmpTimestamp;
	}

	// A QUIC connection that the safety gate refused, identified by the Destination Connection ID of its first packet.
	private sealed class RefusedQuicConnection(byte[]? initialDestinationConnectionId)
	{
		internal readonly long Timestamp = Stopwatch.GetTimestamp();

		// Only read and written by the listener loop.
		internal long LastIcmpTimestamp;

		internal bool Matches(byte[]? destinationConnectionId) =>
			initialDestinationConnectionId is not null &&
			destinationConnectionId is not null &&
			destinationConnectionId.AsSpan().SequenceEqual(initialDestinationConnectionId);
	}
	private sealed class QuicFlow
	{
		private readonly Socket ListenerSocket;

		// The client endpoint changes when the client's packets start arriving from a new address or port.
		private volatile IPEndPoint CurrentClientEndPoint;
		internal IPEndPoint ClientEndPoint
		{
			get => CurrentClientEndPoint;
			set => CurrentClientEndPoint = value;
		}
		private readonly IPEndPoint ListenerEndPoint;
		private readonly IPAddress OutboundAddress;
		private readonly IPAddress[] DnsServers;

		// The client's Initial Destination Connection ID identifies retransmissions of the same
		// handshake even when the client reuses its UDP endpoint.
		internal readonly byte[]? InitialDestinationConnectionId;

		// Set when the safety gate refused this connection, so retransmissions of it are refused without a new flow.
		internal volatile bool WasRefused;

		// The connection ID that the server chose for itself during the handshake. The client puts it at the
		// start of every short header packet, which identifies the connection when its endpoint changes.
		private byte[]? ServerConnectionId;

		// Set once the client sends a short header packet, which it only does after its handshake completed.
		private volatile bool Established;
		internal bool IsEstablished => Established;

		// Set by the safety gate when the flow is registered; read while QuicGateLock is held.
		internal string? GateHost;
		internal CertificateNames? GateNames;
		internal IPAddress[] GateAddresses = [];

		// Lets Terminate end the flow from outside; null before the flow starts and after it ended.
		private CancellationTokenSource? FlowCancellationSource;

		// Client datagrams are queued by the shared listener loop and consumed by exactly one flow phase
		// at a time. Wait mode makes TryWrite report failure when the queue is full (the Drop* modes
		// report success even while discarding), so every dropped datagram is counted and logged; QUIC
		// loss recovery then handles the drop like any other packet loss.
		private readonly Channel<byte[]> ClientDatagrams = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(QuicFlowQueueCapacity)
		{
			SingleReader = true,
			SingleWriter = false,
			FullMode = BoundedChannelFullMode.Wait
		});

		// Server datagrams are received and queued by the receive task and delivered by the dedicated
		// send task, so a slow or contended send on the shared listener socket can never stall the
		// receive loop and overflow the kernel receive buffer. Wait mode gives the same explicit,
		// counted drop behavior as the client-side queue.
		private readonly Channel<ServerDatagram> ServerDatagrams = Channel.CreateBounded<ServerDatagram>(new BoundedChannelOptions(QuicFlowQueueCapacity)
		{
			SingleReader = true,
			SingleWriter = true,
			FullMode = BoundedChannelFullMode.Wait
		});
		internal long ConnectionId;
		private string? Host;
		private uint NegotiatedQuicVersion;
		private readonly long StartTimestamp = Stopwatch.GetTimestamp();
		private long LastClientActivityTimestamp = Stopwatch.GetTimestamp();
		private long LastServerActivityTimestamp = Stopwatch.GetTimestamp();
		private long BytesSentToServer;
		private long BytesReceivedFromServer;
		private long DatagramsSentToServer;
		private long DatagramsReceivedFromServer;
		private int MaxDatagramToServer;
		private int MaxDatagramToClient;
		private long QueueFullDropsToServer;
		private long QueueFullDropsToClient;
		private long OversizedDropsToServer;
		private long OversizedDropsToClient;
		private long PreConnectSendFailures;

		// Socket errors that the flow survived, and since when each direction has been failing without a success in between.
		private long TransientSocketErrors;
		private long SendToServerErrorsSince;
		private long ReceiveFromServerErrorsSince;
		private long SendToClientErrorsSince;
		private string? FlowTermination;
		private CancellationToken ProgramCancellationToken;

		// Set before the client queue is completed at shutdown so a datagram racing with the flow's end
		// is not miscounted (and logged) as a queue-full drop.
		private volatile bool FlowClosing;

		internal QuicFlow(
			Socket listenerSocket,
			IPEndPoint clientEndPoint,
			IPEndPoint listenerEndPoint,
			IPAddress outboundAddress,
			IPAddress[] dnsServers,
			byte[]? initialDestinationConnectionId)
		{
			ListenerSocket = listenerSocket;
			CurrentClientEndPoint = clientEndPoint;
			ListenerEndPoint = listenerEndPoint;
			OutboundAddress = outboundAddress;
			DnsServers = dnsServers;
			InitialDestinationConnectionId = initialDestinationConnectionId;
		}

		// True when an Initial packet with this Destination Connection ID can belong to this flow's connection:
		// the client addresses its Initial packets to the ID it first chose, or to the ID the server answered with.
		internal bool IsInitialOfThisConnection(byte[]? destinationConnectionId)
		{
			if (destinationConnectionId is null)
			{
				return false;
			}
			byte[]? serverConnectionId = Volatile.Read(ref ServerConnectionId);
			return (InitialDestinationConnectionId is not null && destinationConnectionId.AsSpan().SequenceEqual(InitialDestinationConnectionId)) ||
				(serverConnectionId is not null && destinationConnectionId.AsSpan().SequenceEqual(serverConnectionId));
		}

		// True when the short header packet starts with this flow's server connection ID. Very short IDs
		// are not matched, because they could equal the first bytes of an unrelated packet by chance.
		internal bool MatchesServerConnectionId(ReadOnlySpan<byte> datagram)
		{
			byte[]? serverConnectionId = Volatile.Read(ref ServerConnectionId);
			return serverConnectionId is { Length: >= 4 } &&
				datagram.Length > serverConnectionId.Length &&
				datagram.Slice(1, serverConnectionId.Length).SequenceEqual(serverConnectionId);
		}

		// Records the Source Connection ID of the server's long header packets (RFC 8999 Section 5.1).
		private void ObserveServerDatagram(ReadOnlySpan<byte> datagram)
		{
			if (datagram.Length < 7 || (datagram[0] & 0x80) == 0 || BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(1, 4)) == 0)
			{
				// Short header packets and Version Negotiation packets do not identify the connection for the server.
				return;
			}
			int sourceConnectionIdOffset = 6 + datagram[5];
			if (sourceConnectionIdOffset >= datagram.Length)
			{
				return;
			}
			int sourceConnectionIdLength = datagram[sourceConnectionIdOffset];
			if (sourceConnectionIdLength > QuicMaxConnectionIdLength || sourceConnectionIdOffset + 1 + sourceConnectionIdLength > datagram.Length)
			{
				return;
			}
			ReadOnlySpan<byte> sourceConnectionId = datagram.Slice(sourceConnectionIdOffset + 1, sourceConnectionIdLength);
			byte[]? current = Volatile.Read(ref ServerConnectionId);
			if (current is null || !sourceConnectionId.SequenceEqual(current))
			{
				Volatile.Write(ref ServerConnectionId, sourceConnectionId.ToArray());
			}
		}

		// Ends the flow from outside. With notifyClient, the client is told that its connection is gone.
		internal void Terminate(string reason, bool notifyClient)
		{
			_ = Interlocked.CompareExchange(ref FlowTermination, reason, null);
			try
			{
				Volatile.Read(ref FlowCancellationSource)?.Cancel();
			}
			catch (ObjectDisposedException)
			{
				// The flow ended on its own at the same moment.
			}
			if (notifyClient)
			{
				SendPortUnreachable(ClientEndPoint, ListenerEndPoint);
			}
		}

		// The datagram bytes are copied because the caller's receive buffer is reused for the next datagram.
		// A failed write means the bounded queue is full (or the flow is closing) and the datagram is
		// dropped like any lost packet; the drop is counted and logged so queue pressure is never silent.
		internal void EnqueueClientDatagram(ReadOnlySpan<byte> datagram)
		{
			if (!Established && datagram.Length != 0 && (datagram[0] & 0x80) == 0)
			{
				Established = true;
			}
			if (!ClientDatagrams.Writer.TryWrite(datagram.ToArray()) && !FlowClosing)
			{
				RecordQueueDrop(toServer: true, datagram.Length);
			}
		}

		// Counts a queue-full drop for one direction and logs the first occurrence plus every
		// QueueDropLogInterval-th after that. QUIC loss recovery retransmits a dropped datagram, but
		// repeated drops collapse throughput, so sustained queue pressure must be visible in the logs.
		private void RecordQueueDrop(bool toServer, int size)
		{
			ref long counter = ref toServer ? ref QueueFullDropsToServer : ref QueueFullDropsToClient;
			long drops = Interlocked.Increment(ref counter);
			if (drops == 1 || drops % QueueDropLogInterval == 0)
			{
				WriteLine($"CONNECTION #{ConnectionId} QUEUE FULL DROP direction={(toServer ? "client->server" : "server->client")} size={size}B totalDrops={drops} queueCapacity={QuicFlowQueueCapacity}");
			}
		}

		internal async Task RunAsync(CancellationToken cancellationToken)
		{
			CancellationToken programCancellationToken = cancellationToken;
			ProgramCancellationToken = programCancellationToken;
			using CancellationTokenSource flowCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			Volatile.Write(ref FlowCancellationSource, flowCancellation);
			cancellationToken = flowCancellation.Token;
			long connectionId = Interlocked.Increment(ref NextConnectionId);
			ConnectionId = connectionId;
			int activeConnections = Interlocked.Increment(ref ActiveConnections);
			ClientTrafficCounters clientTraffic = ClientTraffic.GetOrAdd(ClientEndPoint.Address, static _ => new ClientTrafficCounters());
			_ = Interlocked.Increment(ref clientTraffic.ActiveConnections);
			WriteLine($"CONNECTION #{connectionId} ACCEPTED client={ClientEndPoint} listenerPort={ListenerEndPoint.Port} transport=UDP activeConnections={activeConnections}");
			bool registeredWithGate = false;
			try
			{
				string host;
				Socket destinationSocket;
				IPAddress destinationAddress;
				byte[] firstServerDatagram;

				// Phase 1: assemble the ClientHello from the client's Initial flight and extract the SNI host.
				List<byte[]> initialFlight = [with(QuicMaxPreConnectDatagrams)];
				host = await ReadClientHelloHostAsync(initialFlight, cancellationToken);

				// A host under a wildcard name that is already known to span servers is refused right away,
				// without a name lookup and without fetching its certificate again.
				if (GetKnownQuicRefusal(host) is string knownRefusal)
				{
					WasRefused = true;
					LogQuicRefusal(connectionId, ClientEndPoint, host, knownRefusal);
					SendPortUnreachable(ClientEndPoint, ListenerEndPoint);
					return;
				}
				IPAddress[] addresses;
				try
				{
					// The lookup is shared with other requests for the same name, so it runs on the program's
					// token; only the wait for it ends when this flow is canceled.
					addresses = await ResolveHostAddressesAsync(host, OutboundAddress, DnsServers, programCancellationToken).WaitAsync(cancellationToken);
				}
				catch (DnsResolutionException exception)
				{
					WriteLine($"CONNECTION #{connectionId} DNS RESOLUTION FAILURE client={ClientEndPoint} host={host} type=A error={exception.Message} innerError={exception.InnerException?.GetType().Name}:{exception.InnerException?.Message}");
					return;
				}
				IPAddress[] candidateAddresses = [.. addresses.Where(static item =>
						item.AddressFamily == AddressFamily.InterNetwork && IsPublic(item))];

				// The safety gate decides whether this connection may use QUIC at all. A refused client is told
				// that nothing accepts QUIC here, which makes it use TCP for this host.
				string? refusal = "no-public-address";
				if (candidateAddresses.Length != 0)
				{
					CertificateNames? certificateNames = await GetCertificateNamesAsync(host, candidateAddresses, OutboundAddress, programCancellationToken, cancellationToken);
					refusal = certificateNames is null
						? "certificate-unavailable"
						: RegisterQuicFlowIfSafe(this, host, candidateAddresses, certificateNames);
				}
				if (refusal is not null)
				{
					WasRefused = true;
					LogQuicRefusal(connectionId, ClientEndPoint, host, refusal);
					SendPortUnreachable(ClientEndPoint, ListenerEndPoint);
					return;
				}
				registeredWithGate = true;

				// Phase 2: reach a destination over the selected outbound adapter and wait for its first answer.
				(destinationSocket, destinationAddress, firstServerDatagram) = await ConnectUdpToAnyAddressAsync(
					candidateAddresses, initialFlight, host, connectionId, clientTraffic, cancellationToken);
				Host = host;
				using Socket destination = destinationSocket;
				ObserveServerDatagram(firstServerDatagram);
				try
				{
					_ = await ListenerSocket.SendToAsync(firstServerDatagram, SocketFlags.None, ClientEndPoint, cancellationToken);
					CountServerToClient(firstServerDatagram.Length, clientTraffic);
				}
				catch (SocketException)
				{
					// A failed delivery of the first response behaves like a lost datagram; QUIC retransmits it.
				}

				string quicVersion = NegotiatedQuicVersion == 0 ? "unknown" : $"0x{NegotiatedQuicVersion:x8}";
				WriteLine($"CONNECTION #{connectionId} OPEN client={ClientEndPoint} protocol=QUIC destination={host}:{HttpsPort} resolved={destinationAddress} outboundLocal={destination.LocalEndPoint} outboundRemote={destination.RemoteEndPoint} quicVersion={quicVersion} resumed=False receiveBuffer={destination.ReceiveBufferSize}B sendBuffer={destination.SendBufferSize}B");

				// Phase 3: relay datagrams in both directions until the flow goes idle or the program stops.
				(string clientToServer, string serverToClient) = await RelayAsync(destination, clientTraffic, cancellationToken);
				WriteLine($"CONNECTION #{connectionId} CLOSED client={ClientEndPoint} destination={host}:{HttpsPort} sent={Interlocked.Read(ref BytesSentToServer)}B received={Interlocked.Read(ref BytesReceivedFromServer)}B datagramsSent={Interlocked.Read(ref DatagramsSentToServer)} datagramsReceived={Interlocked.Read(ref DatagramsReceivedFromServer)} maxDatagramUp={MaxDatagramToServer}B maxDatagramDown={MaxDatagramToClient}B queueFullDropsUp={Interlocked.Read(ref QueueFullDropsToServer)} queueFullDropsDown={Interlocked.Read(ref QueueFullDropsToClient)} oversizedDropsUp={Interlocked.Read(ref OversizedDropsToServer)} oversizedDropsDown={Interlocked.Read(ref OversizedDropsToClient)} preConnectSendFailures={Interlocked.Read(ref PreConnectSendFailures)} lastClientActivity={Stopwatch.GetElapsedTime(Volatile.Read(ref LastClientActivityTimestamp)).TotalSeconds:F1}s lastServerActivity={Stopwatch.GetElapsedTime(Volatile.Read(ref LastServerActivityTimestamp)).TotalSeconds:F1}s durationSeconds={Stopwatch.GetElapsedTime(StartTimestamp).TotalSeconds:F1} clientToServer={clientToServer} serverToClient={serverToClient}");
			}
			catch (OperationCanceledException) when (programCancellationToken.IsCancellationRequested)
			{
				WriteLine($"CONNECTION #{connectionId} CANCELED client={ClientEndPoint} reason=program-shutdown");
			}
			catch (OperationCanceledException) when (Volatile.Read(ref FlowTermination) is string termination)
			{
				// The flow was ended from outside before it started relaying.
				WriteLine($"CONNECTION #{connectionId} TERMINATED client={ClientEndPoint} reason={termination}");
			}
			catch (OperationCanceledException)
			{
				WriteLine($"CONNECTION #{connectionId} TIMEOUT client={ClientEndPoint} stage=quic-client-hello timeoutMs={(int)QuicHandshakeTimeout.TotalMilliseconds}");
			}
			catch (SocketException exception)
			{
				WriteLine($"CONNECTION #{connectionId} SOCKET FAILURE client={ClientEndPoint} socketError={exception.SocketErrorCode} error={exception.Message}");

				// The destination did not answer over QUIC, so the client is told right away instead of
				// being left to wait for its own handshake timeout before it uses TCP.
				SendPortUnreachable(ClientEndPoint, ListenerEndPoint);
			}
			catch (Exception exception)
			{
				WriteLine($"CONNECTION #{connectionId} PROTOCOL FAILURE client={ClientEndPoint} error={exception}");
			}
			finally
			{
				FlowClosing = true;
				Volatile.Write(ref FlowCancellationSource, null);
				if (registeredWithGate)
				{
					UnregisterQuicFlow(this);
				}
				_ = ClientDatagrams.Writer.TryComplete();
				_ = Interlocked.Decrement(ref clientTraffic.ActiveConnections);
				int remainingConnections = Interlocked.Decrement(ref ActiveConnections);
				WriteLine($"CONNECTION #{connectionId} RELEASED client={ClientEndPoint} activeConnections={remainingConnections}");
			}
		}

		private async Task<string> ReadClientHelloHostAsync(List<byte[]> initialFlight, CancellationToken cancellationToken)
		{
			using CancellationTokenSource handshakeTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			handshakeTimeout.CancelAfter(QuicHandshakeTimeout);
			QuicClientHelloAssembler assembler = new();
			while (true)
			{
				byte[] datagram = await ClientDatagrams.Reader.ReadAsync(handshakeTimeout.Token);
				if (NegotiatedQuicVersion == 0 && datagram.Length >= 5 && (datagram[0] & 0x80) != 0)
				{
					// The version field of the first long header packet is recorded for diagnostics.
					NegotiatedQuicVersion = BinaryPrimitives.ReadUInt32BigEndian(datagram.AsSpan(1, 4));
				}
				AddToFlight(initialFlight, datagram);
				ParseQuicInitialDatagram(datagram, assembler);
				if (assembler.TryGetClientHello(out ReadOnlyMemory<byte> clientHello))
				{
					return ExtractSniFromClientHello(clientHello.Span);
				}
			}
		}

		private static void AddToFlight(List<byte[]> initialFlight, byte[] datagram)
		{
			// The pre-connect flight buffer is bounded; QUIC retransmissions recover anything dropped beyond the cap.
			if (initialFlight.Count < QuicMaxPreConnectDatagrams)
			{
				initialFlight.Add(datagram);
			}
		}

		private async Task<(Socket Socket, IPAddress Address, byte[] FirstServerDatagram)> ConnectUdpToAnyAddressAsync(
			IPAddress[] candidates,
			List<byte[]> initialFlight,
			string host,
			long connectionId,
			ClientTrafficCounters clientTraffic,
			CancellationToken cancellationToken)
		{
			Exception? lastException = null;
			for (int index = 0; index < candidates.Length; index++)
			{
				IPAddress candidate = candidates[index];
				Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
				long started = Stopwatch.GetTimestamp();
				try
				{
					ConfigureUdpProxySocket(socket);
					socket.Bind(new IPEndPoint(OutboundAddress, 0));
					await socket.ConnectAsync(candidate, HttpsPort, cancellationToken);
					WriteLine($"CONNECTION #{connectionId} CONNECT ATTEMPT host={host} remote={candidate}:{HttpsPort} local={socket.LocalEndPoint} transport=UDP attempt={index + 1}/{candidates.Length}");
					await SendFlightAsync(socket, initialFlight, clientTraffic, cancellationToken);
					byte[]? firstServerDatagram = await WaitForFirstServerDatagramAsync(socket, initialFlight, clientTraffic, cancellationToken);
					if (firstServerDatagram is not null)
					{
						WriteLine($"CONNECTION #{connectionId} CONNECT SUCCESS host={host} remote={socket.RemoteEndPoint} local={socket.LocalEndPoint} attempt={index + 1}/{candidates.Length} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1}");

						// ICMP unreachable reports were useful for candidate failover, but once the
						// destination has answered they must not tear down a long-lived flow.
						DisableUdpConnectionReset(socket);
						return (socket, candidate, firstServerDatagram);
					}
					socket.Dispose();
					lastException ??= new SocketException((int)SocketError.TimedOut);
					WriteLine($"CONNECTION #{connectionId} CONNECT TIMEOUT host={host} remote={candidate}:{HttpsPort} localAddress={OutboundAddress} attempt={index + 1}/{candidates.Length} timeoutMs={PerAddressConnectTimeout.TotalMilliseconds:F0} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1}");
				}
				catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
				{
					socket.Dispose();
					throw;
				}
				catch (SocketException exception)
				{
					socket.Dispose();
					lastException = exception;
					WriteLine($"CONNECTION #{connectionId} CONNECT FAILURE host={host} remote={candidate}:{HttpsPort} localAddress={OutboundAddress} attempt={index + 1}/{candidates.Length} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F1} socketError={exception.SocketErrorCode} error={exception.Message}");
				}
				catch
				{
					socket.Dispose();
					throw;
				}
			}

			// No candidate answered QUIC, so HTTP/3 is not offered for this host for a while.
			QuicUnresponsiveHosts[host] = Stopwatch.GetTimestamp();

			// When every candidate only timed out, a TimedOut socket error is reported instead of HostNotFound.
			throw lastException ?? new SocketException((int)SocketError.HostNotFound);
		}

		private async Task SendFlightAsync(Socket socket, List<byte[]> initialFlight, ClientTrafficCounters clientTraffic, CancellationToken cancellationToken)
		{
			for (int index = 0; index < initialFlight.Count; index++)
			{
				byte[] datagram = initialFlight[index];
				try
				{
					_ = await socket.SendAsync(datagram, cancellationToken);
				}
				catch (SocketException exception) when (exception.SocketErrorCode == SocketError.MessageSize)
				{
					// An oversized datagram is dropped exactly like a router would drop it, but counted so
					// path MTU problems show up in the logs instead of looking like silent stalls.
					RecordOversizedDrop(toServer: true, datagram.Length);
					continue;
				}
				CountClientToServer(datagram.Length, clientTraffic);
			}
		}

		// Counts an oversized-datagram drop for one direction and logs the first occurrence plus every
		// fiftieth after that, keeping a possible MTU mismatch visible without flooding the log.
		private void RecordOversizedDrop(bool toServer, int size)
		{
			ref long counter = ref toServer ? ref OversizedDropsToServer : ref OversizedDropsToClient;
			long drops = Interlocked.Increment(ref counter);
			if (drops == 1 || drops % 50 == 0)
			{
				WriteLine($"CONNECTION #{ConnectionId} OVERSIZED DATAGRAM DROP direction={(toServer ? "client->server" : "server->client")} size={size}B totalDrops={drops}");
			}
		}

		private async Task<byte[]?> WaitForFirstServerDatagramAsync(
			Socket socket,
			List<byte[]> initialFlight,
			ClientTrafficCounters clientTraffic,
			CancellationToken cancellationToken)
		{
			using CancellationTokenSource responseTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			responseTimeout.CancelAfter(PerAddressConnectTimeout);

			// Client datagrams that arrive while the destination's answer is awaited (Initial
			// retransmissions and continuation packets of a large ClientHello) are appended to the flight
			// and forwarded immediately, so a lossy path can still complete the handshake within this attempt.
			Task forwarder = ForwardClientDatagramsDuringConnectAsync(socket, initialFlight, clientTraffic, responseTimeout.Token);
			try
			{
				byte[] buffer = GC.AllocateUninitializedArray<byte>(MaxUdpDatagramSize);
				int received = await socket.ReceiveAsync(buffer, responseTimeout.Token);
				return buffer.AsSpan(0, received).ToArray();
			}
			catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
			{
				throw;
			}
			catch (OperationCanceledException)
			{
				// The candidate did not answer within the per-address timeout.
				return null;
			}
			finally
			{
				await responseTimeout.CancelAsync();
				await forwarder;
			}
		}

		private async Task ForwardClientDatagramsDuringConnectAsync(
			Socket socket,
			List<byte[]> initialFlight,
			ClientTrafficCounters clientTraffic,
			CancellationToken cancellationToken)
		{
			try
			{
				while (true)
				{
					byte[] datagram = await ClientDatagrams.Reader.ReadAsync(cancellationToken);
					AddToFlight(initialFlight, datagram);
					try
					{
						_ = await socket.SendAsync(datagram, cancellationToken);
					}
					catch (SocketException exception)
					{
						// Send failures during establishment surface through the receive path of the
						// attempt; the datagram stays in the flight buffer and is resent to the next candidate.
						long failures = Interlocked.Increment(ref PreConnectSendFailures);
						if (failures == 1)
						{
							WriteLine($"CONNECTION #{ConnectionId} PRE-CONNECT SEND FAILURE socketError={exception.SocketErrorCode} error={exception.Message}");
						}
						continue;
					}
					CountClientToServer(datagram.Length, clientTraffic);
				}
			}
			catch (OperationCanceledException) { }
		}

		private async Task<(string ClientToServer, string ServerToClient)> RelayAsync(
			Socket destinationSocket,
			ClientTrafficCounters clientTraffic,
			CancellationToken cancellationToken)
		{
			using CancellationTokenSource flowCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			long relayStart = Stopwatch.GetTimestamp();
			Volatile.Write(ref LastClientActivityTimestamp, relayStart);
			Volatile.Write(ref LastServerActivityTimestamp, relayStart);

			// All four tasks are awaited below before the cancellation source is disposed; the analyzer cannot see through Task.WhenAll.
#pragma warning disable CA2025
			Task<string> outgoing = RelayClientToServerAsync(destinationSocket, clientTraffic, flowCancellation);

			// The server-to-client direction is split into a receive task and a send task joined by the
			// ServerDatagrams queue, so the receive loop drains the kernel buffer at line rate even while
			// a send on the shared listener socket is waiting its turn behind other flows.
			Task<string> incoming = ReceiveFromServerAsync(destinationSocket, flowCancellation);
			Task sender = SendToClientAsync(clientTraffic, flowCancellation);
			Task watchdog = WatchIdleAsync(destinationSocket, flowCancellation);
#pragma warning restore CA2025

			// Every task is awaited before the shared cancellation source is disposed. Each relay direction
			// cancels the flow when it ends, so the sender and the watchdog always unwind with them.
			await Task.WhenAll(outgoing, incoming, sender, watchdog);
			return (await outgoing, await incoming);
		}

		private async Task<string> RelayClientToServerAsync(Socket destinationSocket, ClientTrafficCounters clientTraffic, CancellationTokenSource flowCancellation)
		{
			try
			{
				while (true)
				{
					byte[] datagram = await ClientDatagrams.Reader.ReadAsync(flowCancellation.Token);
					try
					{
						_ = await destinationSocket.SendAsync(datagram, flowCancellation.Token);
					}
					catch (SocketException exception) when (exception.SocketErrorCode == SocketError.MessageSize)
					{
						// An oversized datagram (a path MTU probe) is dropped exactly like a router would drop it.
						RecordOversizedDrop(toServer: true, datagram.Length);
						continue;
					}
					catch (SocketException exception)
					{
						if (ShouldContinueAfterSocketError(ref SendToServerErrorsSince, "send-to-server", exception))
						{
							// The datagram is lost like any dropped packet and QUIC retransmits it.
							continue;
						}
						string failure = FormatRelaySocketException("destination-write", "destinationRole", "server", "destinationEndpoint", destinationSocket.RemoteEndPoint, exception);
						_ = Interlocked.CompareExchange(ref FlowTermination, failure, null);
						return failure;
					}
					Volatile.Write(ref SendToServerErrorsSince, 0);
					CountClientToServer(datagram.Length, clientTraffic);
				}
			}
			catch (OperationCanceledException)
			{
				return GetFlowCancellationReason();
			}
			finally
			{
				// The sibling relay direction and the idle watchdog unwind together with this direction.
				await flowCancellation.CancelAsync();
			}
		}

		// Decides whether an established flow survives a socket error. A UDP socket reports conditions that
		// a TCP connection rides out on its own: a route that is unavailable for a moment, an ICMP report
		// from a router, a full buffer. Ending the flow for one of them would leave the client sending into
		// a connection that no longer exists, so a single error only costs the datagram. The flow ends when
		// the errors of one direction persist beyond the tolerance, which means the path is really gone.
		private bool ShouldContinueAfterSocketError(ref long errorsSince, string operation, SocketException exception)
		{
			long now = Stopwatch.GetTimestamp();
			long firstError = Interlocked.CompareExchange(ref errorsSince, now, 0);
			long errors = Interlocked.Increment(ref TransientSocketErrors);
			if (errors == 1 || errors % QueueDropLogInterval == 0)
			{
				WriteLine($"CONNECTION #{ConnectionId} TRANSIENT SOCKET ERROR operation={operation} socketError={exception.SocketErrorCode} error={exception.Message} totalErrors={errors}");
			}
			return firstError == 0 || Stopwatch.GetElapsedTime(firstError, now) < QuicSocketErrorTolerance;
		}

		private string GetFlowCancellationReason()
		{
			string? termination = Volatile.Read(ref FlowTermination);
			if (termination is not null)
			{
				return termination;
			}
			if (ProgramCancellationToken.IsCancellationRequested)
			{
				return "program-shutdown";
			}
			return "relay-canceled";
		}

		// Receives datagrams from the destination and queues them for the send task. Receiving never
		// waits on the client-facing send, so bursts are absorbed by the queue instead of piling up in
		// (and eventually overflowing) the kernel receive buffer where drops would be invisible.
		private async Task<string> ReceiveFromServerAsync(Socket destinationSocket, CancellationTokenSource flowCancellation)
		{
			byte[] buffer = GC.AllocateUninitializedArray<byte>(MaxUdpDatagramSize);
			try
			{
				while (true)
				{
					int received;
					try
					{
						received = await destinationSocket.ReceiveAsync(buffer, flowCancellation.Token);
					}
					catch (SocketException exception)
					{
						if (ShouldContinueAfterSocketError(ref ReceiveFromServerErrorsSince, "receive-from-server", exception))
						{
							// A persistent error would otherwise be reported again immediately, in a tight loop.
							await Task.Delay(QuicSocketErrorRetryDelay, flowCancellation.Token);
							continue;
						}
						string failure = FormatRelaySocketException("source-read", "sourceRole", "server", "sourceEndpoint", destinationSocket.RemoteEndPoint, exception);
						_ = Interlocked.CompareExchange(ref FlowTermination, failure, null);
						return failure;
					}
					Volatile.Write(ref ReceiveFromServerErrorsSince, 0);

					// The server is alive from the moment its datagram arrives, even while the datagram
					// still waits in the send queue, so queued time never counts as server silence.
					Volatile.Write(ref LastServerActivityTimestamp, Stopwatch.GetTimestamp());

					// The server's handshake packets carry the connection ID that identifies this connection later.
					if (received != 0 && (buffer[0] & 0x80) != 0)
					{
						ObserveServerDatagram(buffer.AsSpan(0, received));
					}

					// The datagram is copied into a right-sized pooled array because the receive buffer is
					// reused for the next datagram; the send task returns the array to the pool after use.
					byte[] rented = ArrayPool<byte>.Shared.Rent(received);

					buffer.AsSpan(0, received).CopyTo(rented);
					if (!ServerDatagrams.Writer.TryWrite(new ServerDatagram(rented, received)))
					{
						ArrayPool<byte>.Shared.Return(rented);
						RecordQueueDrop(toServer: false, received);
					}
				}
			}
			catch (OperationCanceledException)
			{
				return GetFlowCancellationReason();
			}
			finally
			{
				// Completing the queue stops the send task once it has drained what was already received,
				// and the sibling tasks unwind together with this direction.
				_ = ServerDatagrams.Writer.TryComplete();
				await flowCancellation.CancelAsync();
			}
		}

		// Delivers queued server datagrams to the client through the shared listener socket, preserving
		// arrival order because this is the queue's only reader. A failed client write terminates the
		// flow exactly like the previous combined relay loop did.
		private async Task SendToClientAsync(ClientTrafficCounters clientTraffic, CancellationTokenSource flowCancellation)
		{
			try
			{
				while (await ServerDatagrams.Reader.WaitToReadAsync(flowCancellation.Token))
				{
					while (ServerDatagrams.Reader.TryRead(out ServerDatagram datagram))
					{
						try
						{
							_ = await ListenerSocket.SendToAsync(datagram.Buffer.AsMemory(0, datagram.Length), SocketFlags.None, ClientEndPoint, flowCancellation.Token);
							Volatile.Write(ref SendToClientErrorsSince, 0);
							CountServerToClient(datagram.Length, clientTraffic);
						}
						catch (SocketException exception) when (exception.SocketErrorCode == SocketError.MessageSize)
						{
							// An oversized datagram (a path MTU probe) is dropped exactly like a router would drop it.
							RecordOversizedDrop(toServer: false, datagram.Length);
						}
						catch (SocketException exception)
						{
							if (ShouldContinueAfterSocketError(ref SendToClientErrorsSince, "send-to-client", exception))
							{
								// The datagram is lost like any dropped packet and QUIC retransmits it.
								continue;
							}
							string failure = FormatRelaySocketException("destination-write", "destinationRole", "client", "destinationEndpoint", ClientEndPoint, exception);
							_ = Interlocked.CompareExchange(ref FlowTermination, failure, null);
							return;
						}
						finally
						{
							ArrayPool<byte>.Shared.Return(datagram.Buffer);
						}
					}
				}
			}
			catch (OperationCanceledException)
			{
			}
			finally
			{
				// Undelivered datagrams of an ending flow are returned to the pool, and the sibling relay
				// tasks and the idle watchdog unwind together with this direction.
				while (ServerDatagrams.Reader.TryRead(out ServerDatagram leftover))
				{
					ArrayPool<byte>.Shared.Return(leftover.Buffer);
				}
				await flowCancellation.CancelAsync();
			}
		}

		private async Task WatchIdleAsync(Socket destinationSocket, CancellationTokenSource flowCancellation)
		{
			// Snapshots of the byte counters let the watchdog print periodic progress deltas, which show
			// whether a long-lived flow is actually moving data or silently stalled.
			long lastProgressTimestamp = Stopwatch.GetTimestamp();
			long lastProgressSent = Interlocked.Read(ref BytesSentToServer);
			long lastProgressReceived = Interlocked.Read(ref BytesReceivedFromServer);
			int receiveBufferSize = destinationSocket.ReceiveBufferSize;
			try
			{
				while (true)
				{
					await Task.Delay(QuicIdleScanInterval, flowCancellation.Token);

					// Bytes sitting unread in the kernel receive buffer mean the relay is draining slower
					// than the destination sends; sustained growth predicts kernel drops, so it is logged
					// before the damage shows up as unexplained stalls.
					int receiveBacklog;
					try
					{
						receiveBacklog = destinationSocket.Available;
					}
					catch (SocketException)
					{
						receiveBacklog = 0;
					}
					if (receiveBacklog > receiveBufferSize / 4 * 3)
					{
						WriteLine($"CONNECTION #{ConnectionId} RECEIVE BACKLOG HIGH destination={Host}:{HttpsPort} availableBytes={receiveBacklog} receiveBuffer={receiveBufferSize}B; the relay drains slower than data arrives and the kernel may drop datagrams");
					}
					long lastClientActivity = Volatile.Read(ref LastClientActivityTimestamp);
					long lastServerActivity = Volatile.Read(ref LastServerActivityTimestamp);
					long mostRecentActivity = Math.Max(lastClientActivity, lastServerActivity);
					if (Stopwatch.GetElapsedTime(mostRecentActivity) >= QuicIdleTimeout)
					{
						// QUIC has no end-of-stream signal, so a quiet period in both directions ends the flow.
						_ = Interlocked.CompareExchange(ref FlowTermination, "idle-timeout", null);
						await flowCancellation.CancelAsync();
						return;
					}
					if (Stopwatch.GetElapsedTime(lastProgressTimestamp) >= RelayProgressInterval)
					{
						long sent = Interlocked.Read(ref BytesSentToServer);
						long received = Interlocked.Read(ref BytesReceivedFromServer);
						if (sent != lastProgressSent || received != lastProgressReceived)
						{
							WriteLine($"CONNECTION #{ConnectionId} PROGRESS destination={Host}:{HttpsPort} protocol=QUIC sentInterval={sent - lastProgressSent}B sentTotal={sent}B receivedInterval={received - lastProgressReceived}B receivedTotal={received}B datagramsSent={Interlocked.Read(ref DatagramsSentToServer)} datagramsReceived={Interlocked.Read(ref DatagramsReceivedFromServer)} maxDatagramUp={MaxDatagramToServer}B maxDatagramDown={MaxDatagramToClient}B upQueue={ClientDatagrams.Reader.Count} downQueue={ServerDatagrams.Reader.Count} receiveBacklog={receiveBacklog}B queueFullDropsUp={Interlocked.Read(ref QueueFullDropsToServer)} queueFullDropsDown={Interlocked.Read(ref QueueFullDropsToClient)} oversizedDropsUp={Interlocked.Read(ref OversizedDropsToServer)} oversizedDropsDown={Interlocked.Read(ref OversizedDropsToClient)} lastClientActivity={Stopwatch.GetElapsedTime(lastClientActivity).TotalSeconds:F1}s lastServerActivity={Stopwatch.GetElapsedTime(lastServerActivity).TotalSeconds:F1}s");
						}
						lastProgressTimestamp = Stopwatch.GetTimestamp();
						lastProgressSent = sent;
						lastProgressReceived = received;
					}
				}
			}
			catch (OperationCanceledException)
			{
			}
		}

		private void CountClientToServer(int byteCount, ClientTrafficCounters clientTraffic)
		{
			_ = Interlocked.Add(ref BytesSentToServer, byteCount);
			_ = Interlocked.Add(ref TotalBytesSent, byteCount);
			_ = Interlocked.Add(ref clientTraffic.TotalBytesSent, byteCount);
			_ = Interlocked.Increment(ref DatagramsSentToServer);
			if (byteCount > MaxDatagramToServer)
			{
				MaxDatagramToServer = byteCount;
			}
			Volatile.Write(ref LastClientActivityTimestamp, Stopwatch.GetTimestamp());
		}

		private void CountServerToClient(int byteCount, ClientTrafficCounters clientTraffic)
		{
			_ = Interlocked.Add(ref BytesReceivedFromServer, byteCount);
			_ = Interlocked.Add(ref TotalBytesReceived, byteCount);
			_ = Interlocked.Add(ref clientTraffic.TotalBytesReceived, byteCount);
			_ = Interlocked.Increment(ref DatagramsReceivedFromServer);
			if (byteCount > MaxDatagramToClient)
			{
				MaxDatagramToClient = byteCount;
			}
			Volatile.Write(ref LastServerActivityTimestamp, Stopwatch.GetTimestamp());
		}

		// A server datagram staged between the receive task and the send task; the buffer is rented from
		// the shared array pool and may be larger than Length. The array itself is needed to return it to the pool.
#pragma warning disable CA1819
		private readonly record struct ServerDatagram(byte[] Buffer, int Length);
#pragma warning restore CA1819
	}

	// Kept private because it never leaves this class: resolution failures are caught and logged here.
#pragma warning disable CA1064
	private sealed class DnsResolutionException : Exception
	{
		public DnsResolutionException()
		{
		}

		public DnsResolutionException(string message) : base(message)
		{
		}

		public DnsResolutionException(string message, Exception? innerException) : base(message, innerException)
		{
		}
	}
#pragma warning restore CA1064

	private sealed class ClientTrafficCounters
	{
		internal long TotalBytesSent;
		internal long TotalBytesReceived;
		internal int ActiveConnections;
	}

	// Private data carriers whose arrays are never exposed outside of this class.
#pragma warning disable CA1819
	private sealed record DnsCacheEntry(IPAddress[] Addresses, long CreatedTimestamp, TimeSpan Lifetime);

	// The DNS names of a destination's certificate: the exact names, and the parent domains of its wildcard names.
	private sealed record CertificateNames(HashSet<string> ExactNames, HashSet<string> WildcardParents);

	// The outcome of a certificate probe; Names is null when the certificate could not be fetched.
	private sealed record CertificateProbeResult(CertificateNames? Names, long Timestamp);

	// A host name that a client resolved through this engine and the public IPv4 addresses it really lives on.
	private sealed record ResolvedHost(IPAddress[] Addresses, long Timestamp);
	private readonly record struct DnsAddressResult(IPAddress[] Addresses, TimeSpan Lifetime);
#pragma warning restore CA1819
	private readonly record struct DnsQueryMetadata(string Name, ushort Type, ushort TransactionId);
	private readonly record struct DnsResponseMetadata(ushort AnswerCount, int ResponseCode, bool Truncated);
	private readonly record struct RelayResult(long Bytes, string Termination);
	private readonly record struct DnsQuestion(string Name, ushort Type, ushort Class, int EndOffset, bool HasEdns, ushort RequestorUdpPayloadSize);
}

/// <summary>
/// A network adapter that can be used as the source (LAN listener) or destination (outbound) adapter of the engine.
/// </summary>
internal sealed record NetworkAdapterOption(
	string Id,
	string Name,
	string Description,
	IPAddress Address,
	int InterfaceIndex,
	List<IPAddress> DnsServers)
{
	internal string DisplayName => $"{Name} - {Address} - {Description}";
	public override string ToString() => DisplayName;
}

internal readonly record struct ClientTrafficSnapshot(IPAddress Address, long TotalBytesSent, long TotalBytesReceived, int ActiveConnections);

internal readonly record struct TrafficSnapshot(long TotalBytesSent, long TotalBytesReceived, int ActiveConnections, List<ClientTrafficSnapshot> Clients);
