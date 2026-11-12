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
using System.Diagnostics;
using System.IO;
using System.IO.Pipelines;
using System.Net;
using System.Net.Http;
using System.Net.Quic;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace HardenSystemSecurity.DNS;

/// <summary>
/// A local DNS-over-HTTPS server (RFC 8484, over HTTP/1.1, HTTP/2 and HTTP/3) that forwards every query to the selected upstream DoH resolvers,
/// either directly or through the Tor session of <see cref="TorSessionManager"/>.
/// The responses are cached for as long as their records may be kept, and every response tells HTTP caches how long it stays fresh.
/// </summary>
internal static class DnsOverHttpsServer
{
	private const int MaximumDnsMessageSize = 65535;
	private const int MaximumHttpHeaderSize = 32768;
	private const string DnsMessageMediaType = "application/dns-message";

	/// <summary>
	/// The maximum time a single upstream DoH resolver gets to answer before the next selected resolver is tried.
	/// Without it, a stalled connection or Tor circuit would hang the client's request indefinitely because the HTTP client has no timeout.
	/// </summary>
	private static readonly TimeSpan UpstreamAttemptTimeout = TimeSpan.FromSeconds(30);

	private static readonly DnsResponseCache Cache = new();

	/// <summary>
	/// The query counts of the current run, which the DNS page displays.
	/// </summary>
	internal static readonly DnsQueryCounters Statistics = new();

	/// <summary>
	/// The upstream resolvers whose HTTP/3 connection failed during the current run; they are only reached over HTTP/2 or HTTP/1.1 afterwards,
	/// so a network that blocks QUIC delays only the first query that tries it.
	/// </summary>
	private static readonly ConcurrentDictionary<Uri, byte> Http3DisabledUpstreams = new();

	private static Action<string>? LogSink;

	/// <summary>
	/// Whether the upstream resolvers are reached over HTTP/3 once they advertise it. This is never the case with Tor, because
	/// Tor only carries TCP and HTTP/3 runs over UDP (QUIC), so HTTP/3 traffic would bypass Tor.
	/// </summary>
	private static bool UpstreamHttp3Enabled;

	/// <summary>
	/// Runs the server until <paramref name="cancellationToken"/> is canceled.
	/// With <paramref name="useTor"/>, Tor must have been initialized with <see cref="TorSessionManager.InitializeAsync"/> first.
	/// The name of every query is counted in <paramref name="domainLog"/> when one is supplied.
	/// </summary>
	internal static async Task RunAsync(
		Action<string> logSink,
		IPAddress listenerAddress,
		int listenerPort,
		string certificateThumbprint,
		StoreLocation certificateStoreLocation,
		string dohHostName,
		Uri[] upstreamDohUris,
		bool useTor,
		DnsDomainLog? domainLog,
		CancellationToken cancellationToken)
	{
		if (useTor && !TorSessionManager.IsReady)
		{
			throw new InvalidOperationException("Initialize Tor before starting the DNS-over-HTTPS server.");
		}
		if (upstreamDohUris.Length == 0)
		{
			throw new InvalidOperationException("Select at least one upstream DoH resolver.");
		}
		LogSink = logSink;
		UpstreamHttp3Enabled = !useTor && QuicConnection.IsSupported;
		Http3DisabledUpstreams.Clear();
		Statistics.Reset();
		Cache.Clear();
		using X509Certificate2 certificate = LoadServerCertificate(certificateThumbprint, certificateStoreLocation);
		ValidateCertificate(certificate, dohHostName);
		using SocketsHttpHandler upstreamHandler = new()
		{
			AllowAutoRedirect = false,
			AutomaticDecompression = DecompressionMethods.None,
			UseProxy = false,
			PooledConnectionLifetime = TimeSpan.FromMinutes(10)
		};
		if (useTor)
		{
			// Every connection to an upstream resolver is opened through Tor's SOCKS5 proxy, which also resolves the resolver's name.
			upstreamHandler.ConnectCallback = ConnectThroughTorAsync;
		}
		using HttpClient upstreamClient = new(upstreamHandler) { Timeout = Timeout.InfiniteTimeSpan };
		WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();

		// The app has its own log view, so the default ASP.NET Core console logging is not used.
		_ = builder.Logging.ClearProviders();

		// The slim builder does not include the HTTPS configuration services that HTTP/3 needs;
		// without this call, binding the HTTP/3 endpoint fails with an InvalidOperationException.
		_ = builder.WebHost.UseKestrelHttpsConfiguration();
		_ = builder.WebHost.UseQuic();
		_ = builder.WebHost.ConfigureKestrel(options =>
		{
			options.AddServerHeader = false;
			options.Limits.MaxRequestBodySize = MaximumDnsMessageSize;
			options.Limits.MaxRequestHeadersTotalSize = MaximumHttpHeaderSize;
			options.Listen(listenerAddress, listenerPort, listenOptions =>
			{
				listenOptions.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
				_ = listenOptions.UseHttps(certificate);
			});
		});
		await using WebApplication application = builder.Build();
		_ = application.Map("/dns-query", async context => await HandleDohRequestAsync(context, dohHostName, upstreamDohUris, upstreamClient, domainLog));
		_ = application.MapFallback(context => WriteHttpErrorAsync(context, StatusCodes.Status404NotFound, "Not Found"));
		await application.StartAsync(cancellationToken);
		WriteLine($"DOH SERVER READY uri=https://{FormatUriHost(dohHostName)}:{listenerPort}/dns-query listener={listenerAddress}:{listenerPort} protocols={(QuicListener.IsSupported ? "HTTP/1.1,HTTP/2,HTTP/3" : "HTTP/1.1,HTTP/2")} upstreams={string.Join(',', upstreamDohUris)} route={(useTor ? $"Tor SOCKS5 at 127.0.0.1:{TorSessionManager.SocksPort}" : "direct")} upstreamHttp3={(UpstreamHttp3Enabled ? "when-advertised" : useTor ? "off-with-Tor" : "not-supported")} cache=on domainLog={domainLog?.FilePath ?? "off"} certificateThumbprint={certificate.Thumbprint} certificateStore={certificateStoreLocation}");
		try
		{
			await application.WaitForShutdownAsync(cancellationToken);
		}
		finally
		{
			await application.StopAsync(CancellationToken.None);

			// The cached responses are not needed anymore, and the next run starts with an empty cache.
			Cache.Clear();
			DnsQueryStatistics statistics = Statistics.Snapshot();
			WriteLine($"DOH SERVER STOPPED queries={statistics.Total} cacheHits={statistics.CacheHits} failed={statistics.Failed} clients={statistics.Clients}");
		}
	}

	private static async Task HandleDohRequestAsync(HttpContext context, string dohHostName, Uri[] upstreamDohUris, HttpClient upstreamClient, DnsDomainLog? domainLog)
	{
		string client = context.Connection.RemoteIpAddress is null ? "unknown" : $"{context.Connection.RemoteIpAddress}:{context.Connection.RemotePort}";
		long started = Stopwatch.GetTimestamp();

		// The query is described in the logs of a canceled or failed request once it was read.
		string queryDescription = "name=unknown";
		try
		{
			if (!HostMatches(context.Request.Host.Host, dohHostName))
			{
				await WriteHttpErrorAsync(context, StatusCodes.Status421MisdirectedRequest, "Misdirected Request");
				return;
			}

			// RFC 8484 defines GET and POST; any other method is refused with the list of the allowed methods (RFC 9110 Section 15.5.6).
			bool isGet = HttpMethods.IsGet(context.Request.Method);
			if (!isGet && !HttpMethods.IsPost(context.Request.Method))
			{
				WriteLine($"DOH REJECTED client={client} protocol={context.Request.Protocol} method={context.Request.Method} status=405");
				context.Response.Headers.Allow = "GET, POST";
				await WriteHttpErrorAsync(context, StatusCodes.Status405MethodNotAllowed, "Method Not Allowed");
				return;
			}

			// A POST body in another format than a DNS message is refused with 415 (RFC 8484 Section 4.2.1).
			if (!isGet && !IsDnsMessageMediaType(context.Request.ContentType))
			{
				WriteLine($"DOH REJECTED client={client} protocol={context.Request.Protocol} method=POST status=415 contentType={context.Request.ContentType ?? "none"}");
				await WriteHttpErrorAsync(context, StatusCodes.Status415UnsupportedMediaType, "Unsupported Media Type");
				return;
			}
			byte[] dnsRequest;
			try
			{
				dnsRequest = await GetDnsRequestAsync(context.Request, isGet, context.RequestAborted);
			}
			catch (InvalidDataException exception)
			{
				WriteLine($"DOH REJECTED client={client} protocol={context.Request.Protocol} status=400 error={exception.Message}");
				await WriteHttpErrorAsync(context, StatusCodes.Status400BadRequest, "Bad Request");
				return;
			}

			// Parsed here so that a malformed DNS message is answered with 400 Bad Request instead of being forwarded.
			if (!DnsMessage.TryParseQuery(dnsRequest, out DnsQuery query))
			{
				WriteLine($"DOH REJECTED client={client} protocol={context.Request.Protocol} status=400 error=The DNS message is not a standard query with exactly one question.");
				await WriteHttpErrorAsync(context, StatusCodes.Status400BadRequest, "Bad Request");
				return;
			}
			string typeName = DnsMessage.GetTypeName(query.Type);
			queryDescription = $"name={query.Name} type={typeName}";
			Statistics.RecordQuery(context.Connection.RemoteIpAddress);
			domainLog?.Record(query.Name);

			byte[] dnsResponse;
			TimeSpan freshness;
			string upstream;
			string upstreamProtocol;
			string cacheResult;
			string? cacheKey = query.IsCacheable ? query.CacheKey : null;
			if (cacheKey is not null && Cache.TryGet(cacheKey, dnsRequest, query, out byte[]? cachedResponse, out TimeSpan remainingLifetime))
			{
				Statistics.RecordCacheHit();
				dnsResponse = cachedResponse;
				freshness = remainingLifetime;
				upstream = "none";
				upstreamProtocol = "none";
				cacheResult = "hit";
			}
			else
			{
				ForwardDnsResult? forwardResult = await ForwardDnsRequestAsync(upstreamClient, upstreamDohUris, dnsRequest, query, context.RequestAborted);
				if (forwardResult is ForwardDnsResult result)
				{
					dnsResponse = result.Response;
					freshness = Cache.Store(cacheKey, dnsRequest, query, dnsResponse, TimeSpan.Zero);
					upstream = result.Upstream.ToString();
					upstreamProtocol = result.Protocol.Major switch
					{
						3 => "HTTP/3",
						2 => "HTTP/2",
						_ => "HTTP/1.1"
					};
				}
				else
				{
					// Server failure (RCODE 2) in a regular DoH response tells the client that the name could not be resolved
					// right now, the same way a DNS server does, so the client can retry or use its next server.
					dnsResponse = DnsMessage.BuildEmptyResponse(dnsRequest, query, DnsMessage.ServerFailure);
					freshness = TimeSpan.Zero;
					upstream = "none";
					upstreamProtocol = "none";
				}
				cacheResult = cacheKey is null ? "bypass" : "miss";
			}
			int responseCode = DnsMessage.GetResponseCode(dnsResponse);

			// NXDOMAIN is a valid answer; every other error code means that the client did not get an answer.
			if (responseCode is not (0 or 3))
			{
				Statistics.RecordFailure();
			}

			// The HTTP freshness lifetime must not exceed the smallest TTL of the response (RFC 8484 Section 5.1).
			int maxAge = (int)freshness.TotalSeconds;
			context.Response.StatusCode = StatusCodes.Status200OK;
			context.Response.ContentType = DnsMessageMediaType;
			context.Response.ContentLength = dnsResponse.Length;
			context.Response.Headers.CacheControl = maxAge > 0 ? $"max-age={maxAge}" : "no-store";
			await context.Response.Body.WriteAsync(dnsResponse, context.RequestAborted);
			WriteLine($"DOH QUERY client={client} protocol={context.Request.Protocol} method={context.Request.Method} {queryDescription} -> rcode={DnsMessage.GetResponseCodeName(responseCode)} answers={DnsMessage.GetAnswerCount(dnsResponse)} upstream={upstream} upstreamProtocol={upstreamProtocol} cache={cacheResult} maxAge={maxAge} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F0}");
		}
		catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
		{
			// The client closed the request, which browsers do with parallel queries once one of them was answered.
			WriteLine($"DOH QUERY CANCELED client={client} protocol={context.Request.Protocol} {queryDescription} durationMs={Stopwatch.GetElapsedTime(started).TotalMilliseconds:F0}");
		}
		catch (Microsoft.AspNetCore.Http.BadHttpRequestException exception)
		{
			// The server rejected the request itself, for example a request body that is larger than any DNS message.
			WriteLine($"DOH REJECTED client={client} protocol={context.Request.Protocol} status={exception.StatusCode} error={exception.Message}");
			if (!context.Response.HasStarted)
			{
				await WriteHttpErrorAsync(context, exception.StatusCode, Microsoft.AspNetCore.WebUtilities.ReasonPhrases.GetReasonPhrase(exception.StatusCode));
			}
		}
		catch (Exception exception) when (exception is IOException or SocketException)
		{
			// The connection to the client failed, so no response can be sent anymore.
			WriteLine($"DOH CLIENT ERROR client={client} protocol={context.Request.Protocol} {queryDescription} error={exception.GetType().Name}:{exception.Message}");
			if (!context.Response.HasStarted)
			{
				context.Response.StatusCode = StatusCodes.Status400BadRequest;
			}
		}
	}

	// Whether the Content-Type header of a request is application/dns-message, with or without parameters.
	private static bool IsDnsMessageMediaType(string? contentType) =>
		MediaTypeHeaderValue.TryParse(contentType, out MediaTypeHeaderValue? mediaType) &&
		string.Equals(mediaType.MediaType.Value, DnsMessageMediaType, StringComparison.OrdinalIgnoreCase);

	private static async Task<byte[]> GetDnsRequestAsync(HttpRequest request, bool isGet, CancellationToken cancellationToken)
	{
		if (!isGet)
		{
			if (request.ContentLength is long declaredContentLength && !IsValidDnsMessageLength(declaredContentLength))
			{
				throw new InvalidDataException("The DoH POST body has an invalid DNS message length.");
			}
			int capacity = request.ContentLength is long contentLength
				? checked((int)contentLength)
				: 512;
			using MemoryStream body = new(capacity);
			PipeReader bodyReader = request.BodyReader;
			int totalLength = 0;
			while (true)
			{
				ReadResult readResult = await bodyReader.ReadAsync(cancellationToken);
				ReadOnlySequence<byte> buffer = readResult.Buffer;
				foreach (ReadOnlyMemory<byte> segment in buffer)
				{
					totalLength = checked(totalLength + segment.Length);
					if (totalLength > MaximumDnsMessageSize)
					{
						bodyReader.AdvanceTo(buffer.End);
						throw new InvalidDataException("The DoH POST body is too large.");
					}
					body.Write(segment.Span);
				}
				bodyReader.AdvanceTo(buffer.End);
				if (readResult.IsCompleted)
				{
					break;
				}
			}
			if (!IsValidDnsMessageLength(totalLength))
			{
				throw new InvalidDataException("The DoH POST body has an invalid DNS message length.");
			}
			return body.ToArray();
		}
		string value = request.Query["dns"].ToString();
		if (value.Length == 0)
		{
			throw new InvalidDataException("The DoH GET request has no dns parameter.");
		}
		string padded = value.Replace('-', '+').Replace('_', '/');
		padded = (padded.Length % 4) switch
		{
			0 => padded,
			2 => padded + "==",
			3 => padded + "=",
			_ => throw new InvalidDataException("The DoH GET request has invalid base64url data.")
		};
		byte[] decoded;
		try
		{
			decoded = Convert.FromBase64String(padded);
		}
		catch (FormatException exception)
		{
			throw new InvalidDataException("The DoH GET request has invalid base64url data.", exception);
		}
		if (!IsValidDnsMessageLength(decoded.Length))
		{
			throw new InvalidDataException("The DoH GET request has an invalid DNS message length.");
		}
		return decoded;
	}

	private static async Task WriteHttpErrorAsync(HttpContext context, int statusCode, string reason)
	{
		context.Response.StatusCode = statusCode;
		context.Response.ContentType = "text/plain; charset=utf-8";
		context.Response.ContentLength = Encoding.UTF8.GetByteCount(reason);
		await context.Response.WriteAsync(reason, context.RequestAborted);
	}

	/// <summary>
	/// Compares the request's Host header with the configured DoH host name.
	/// The Host header of an IPv6 literal is enclosed in brackets and IP literals may be written in different forms,
	/// so IP addresses are compared by value instead of by text.
	/// </summary>
	private static bool HostMatches(string requestHost, string dohHostName)
	{
		string host = requestHost.Length > 1 && requestHost[0] == '[' && requestHost[^1] == ']' ? requestHost[1..^1] : requestHost;
		if (IPAddress.TryParse(host, out IPAddress? requestAddress) && IPAddress.TryParse(dohHostName, out IPAddress? configuredAddress))
		{
			return requestAddress.Equals(configuredAddress);
		}
		return string.Equals(host, dohHostName, StringComparison.OrdinalIgnoreCase);
	}

	private static bool IsValidDnsMessageLength(long length) => length is >= 12 and <= MaximumDnsMessageSize;

	private static string FormatUriHost(string host)
		=> IPAddress.TryParse(host, out IPAddress? address) && address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{host}]" : host;

	// Forwards the query to the selected upstream resolvers, starting with a random one so the queries are spread across them,
	// and returns the first valid response. Returns null when every selected resolver failed.
	private static async Task<ForwardDnsResult?> ForwardDnsRequestAsync(
		HttpClient upstreamClient,
		Uri[] upstreamDohUris,
		byte[] dnsRequest,
		DnsQuery query,
		CancellationToken cancellationToken)
	{
		int startIndex = RandomNumberGenerator.GetInt32(upstreamDohUris.Length);
		for (int offset = 0; offset < upstreamDohUris.Length; offset++)
		{
			Uri upstreamDohUri = upstreamDohUris[(startIndex + offset) % upstreamDohUris.Length];
			using CancellationTokenSource attemptTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			attemptTimeout.CancelAfter(UpstreamAttemptTimeout);
			try
			{
				return await ForwardDnsRequestToUpstreamAsync(upstreamClient, upstreamDohUri, dnsRequest, query, attemptTimeout.Token);
			}
			catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
			{
				throw;
			}
			catch (OperationCanceledException)
			{
				WriteLine($"DOH UPSTREAM TIMEOUT upstream={upstreamDohUri} name={query.Name} timeoutMs={UpstreamAttemptTimeout.TotalMilliseconds:F0}");
			}
			catch (Exception exception) when (exception is HttpRequestException or IOException or SocketException or AuthenticationException or InvalidDataException)
			{
				WriteLine($"DOH UPSTREAM FAILURE upstream={upstreamDohUri} name={query.Name} error={exception.GetType().Name}:{exception.Message}");
			}
		}
		return null;
	}

	// Sends the query to one upstream resolver. HTTP/3 is used once the resolver advertised it with an Alt-Svc header (RFC 7838),
	// and HTTP/2 or HTTP/1.1 is used until then. A resolver whose HTTP/3 connection fails is asked again over HTTP/2 right away.
	private static async Task<ForwardDnsResult> ForwardDnsRequestToUpstreamAsync(
		HttpClient upstreamClient,
		Uri upstreamDohUri,
		byte[] dnsRequest,
		DnsQuery query,
		CancellationToken cancellationToken)
	{
		bool useHttp3 = UpstreamHttp3Enabled && !Http3DisabledUpstreams.ContainsKey(upstreamDohUri);
		try
		{
			return await SendDnsRequestToUpstreamAsync(upstreamClient, upstreamDohUri, dnsRequest, query, useHttp3 ? HttpVersion.Version30 : HttpVersion.Version20, cancellationToken);
		}
		catch (HttpRequestException exception) when (useHttp3 && !cancellationToken.IsCancellationRequested && IsQuicFailure(exception))
		{
			if (Http3DisabledUpstreams.TryAdd(upstreamDohUri, 0))
			{
				WriteLine($"DOH UPSTREAM HTTP/3 UNAVAILABLE upstream={upstreamDohUri} error={exception.Message}; this resolver is reached over HTTP/2 until the server is restarted");
			}
			return await SendDnsRequestToUpstreamAsync(upstreamClient, upstreamDohUri, dnsRequest, query, HttpVersion.Version20, cancellationToken);
		}
	}

	// Whether a request failed because of its QUIC connection, which happens when a network blocks or drops UDP traffic to port 443.
	private static bool IsQuicFailure(Exception exception)
	{
		for (Exception? current = exception; current is not null; current = current.InnerException)
		{
			if (current is QuicException)
			{
				return true;
			}
		}
		return false;
	}

	private static async Task<ForwardDnsResult> SendDnsRequestToUpstreamAsync(
		HttpClient upstreamClient,
		Uri upstreamDohUri,
		byte[] dnsRequest,
		DnsQuery query,
		Version httpVersion,
		CancellationToken cancellationToken)
	{
		using ByteArrayContent content = new(dnsRequest);
		content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(DnsMessageMediaType);
		using HttpRequestMessage request = new(HttpMethod.Post, upstreamDohUri)
		{
			Version = httpVersion,
			VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
			Content = content
		};
		request.Headers.Accept.ParseAdd(DnsMessageMediaType);
		using HttpResponseMessage response = await upstreamClient.SendAsync(
			request,
			HttpCompletionOption.ResponseHeadersRead,
			cancellationToken);
		if (!response.IsSuccessStatusCode)
		{
			throw new InvalidDataException($"The upstream DoH resolver returned HTTP {(int)response.StatusCode}.");
		}
		string? mediaType = response.Content.Headers.ContentType?.MediaType;
		if (!string.Equals(mediaType, DnsMessageMediaType, StringComparison.OrdinalIgnoreCase))
		{
			throw new InvalidDataException("The upstream DoH resolver returned an unexpected content type.");
		}
		long? contentLength = response.Content.Headers.ContentLength;
		if (contentLength is long declaredContentLength && !IsValidDnsMessageLength(declaredContentLength))
		{
			throw new InvalidDataException("The upstream DoH resolver returned an invalid DNS message length.");
		}
		byte[] dnsResponse = await response.Content.ReadAsByteArrayAsync(cancellationToken);
		if (!IsValidDnsMessageLength(dnsResponse.Length))
		{
			throw new InvalidDataException("The upstream DoH resolver returned an invalid DNS message.");
		}
		// The response must answer this query: the same transaction ID, the QR flag, and the same question.
		// Errors such as FORMERR may come without the question, which are accepted too.
		if (!dnsRequest.AsSpan(0, 2).SequenceEqual(dnsResponse.AsSpan(0, 2)) ||
			(BinaryPrimitives.ReadUInt16BigEndian(dnsResponse.AsSpan(2, 2)) & 0x8000) == 0 ||
			(BinaryPrimitives.ReadUInt16BigEndian(dnsResponse.AsSpan(4, 2)) != 0 && !DnsMessage.QuestionEquals(dnsRequest, dnsResponse, query.QuestionEndOffset)))
		{
			throw new InvalidDataException("The upstream DoH resolver returned a mismatched DNS response.");
		}
		return new ForwardDnsResult(dnsResponse, upstreamDohUri, response.Version);
	}

	private static async ValueTask<Stream> ConnectThroughTorAsync(
		SocketsHttpConnectionContext context,
		CancellationToken cancellationToken)
	{
		DnsEndPoint destination = context.DnsEndPoint;
		int hostLength = Encoding.ASCII.GetByteCount(destination.Host);
		if (hostLength is 0 or > byte.MaxValue)
		{
			throw new InvalidDataException("The upstream DoH hostname is too long for SOCKS5.");
		}
		// The socket and then the stream that owns it are disposed by the finally block unless the
		// SOCKS5 handshake succeeds and the stream is handed over to the HTTP client.
		Socket? socket = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
		NetworkStream? stream = null;
		try
		{
			await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, TorSessionManager.SocksPort), cancellationToken);
#pragma warning disable CA2000 // Disposed asynchronously by the finally block below unless it is returned to the caller.
			stream = new(socket, true);
#pragma warning restore CA2000
			socket = null;
			await Socks5Protocol.WriteNoAuthenticationNegotiationAsync(stream, cancellationToken);
			byte[] methodResponse = new byte[2];
			await stream.ReadExactlyAsync(methodResponse, cancellationToken);
			if (methodResponse[0] != 5 || methodResponse[1] != 0)
			{
				throw new InvalidDataException("Tor rejected the SOCKS5 authentication negotiation.");
			}
			if (!Socks5Protocol.TryCreateDomainConnectRequest(destination.Host, destination.Port, out byte[] connectRequest))
			{
				throw new InvalidDataException("The upstream DoH hostname is too long for SOCKS5.");
			}
			await stream.WriteAsync(connectRequest, cancellationToken);
			byte[] responseHeader = new byte[4];
			await stream.ReadExactlyAsync(responseHeader, cancellationToken);
			if (responseHeader[0] != 5 || responseHeader[1] != 0)
			{
				throw new SocketException((int)SocketError.HostUnreachable);
			}
			int boundAddressLength = responseHeader[3] switch
			{
				1 => 4,
				3 => await ReadSocksDomainLengthAsync(stream, cancellationToken),
				4 => 16,
				_ => throw new InvalidDataException("Tor returned an invalid SOCKS5 address type.")
			};
			byte[] boundAddressAndPort = new byte[boundAddressLength + 2];
			await stream.ReadExactlyAsync(boundAddressAndPort, cancellationToken);
			NetworkStream connectedStream = stream;
			stream = null;
			return connectedStream;
		}
		finally
		{
			if (stream is not null)
			{
				await stream.DisposeAsync();
			}
			socket?.Dispose();
		}
	}

	private static async Task<int> ReadSocksDomainLengthAsync(Stream stream, CancellationToken cancellationToken)
	{
		byte[] length = new byte[1];
		await stream.ReadExactlyAsync(length, cancellationToken);
		return length[0];
	}

	private static X509Certificate2 LoadServerCertificate(string thumbprint, StoreLocation storeLocation)
	{
		using X509Store store = new(StoreName.My, storeLocation);
		store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
		// Every certificate object returned by the store and by Find is a separate instance, so both collections are disposed.
		X509Certificate2Collection allCertificates = store.Certificates;
		X509Certificate2Collection matches = allCertificates.Find(
			X509FindType.FindByThumbprint,
			thumbprint,
			false);
		try
		{
			if (matches.Count != 1)
			{
				throw new InvalidOperationException($"The selected DoH certificate was not found in the {storeLocation} personal certificate store.");
			}
			return new X509Certificate2(matches[0]);
		}
		finally
		{
			foreach (X509Certificate2 match in matches)
			{
				match.Dispose();
			}
			foreach (X509Certificate2 certificate in allCertificates)
			{
				certificate.Dispose();
			}
		}
	}

	private static void ValidateCertificate(X509Certificate2 certificate, string dohHostName)
	{
		if (!certificate.HasPrivateKey)
		{
			throw new InvalidOperationException("The selected DoH certificate does not contain a private key.");
		}
		if (DateTimeOffset.Now < certificate.NotBefore || DateTimeOffset.Now > certificate.NotAfter)
		{
			throw new InvalidOperationException("The selected DoH certificate is not currently valid.");
		}
		if (!DnsOverHttpsCertificateManager.SupportsServerAuthentication(certificate))
		{
			throw new InvalidOperationException("The selected DoH certificate does not permit TLS server authentication.");
		}
		if (!certificate.MatchesHostname(dohHostName, true, false))
		{
			throw new InvalidOperationException($"The selected DoH certificate does not contain a matching DNS-name or IP-address subject alternative name for '{dohHostName}'.");
		}
	}

	private static void WriteLine(string message) => LogSink?.Invoke($"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz}] {message}");

	/// <summary>
	/// The response of an upstream resolver, the resolver, and the HTTP version of the exchange.
	/// </summary>
#pragma warning disable CA1819
	private readonly record struct ForwardDnsResult(byte[] Response, Uri Upstream, Version Protocol);
#pragma warning restore CA1819
}
