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
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AppControlManager.IntelGathering;

internal static class GetFirewallLogs
{
	// Security event log path.
	private const string SecurityLogPath = "Security";

	private static readonly Lazy<Dictionary<string, string>> FilterOriginRuleMap = new(FirewallWmiHelper.GetFirewallRulesMapping, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// 5152: The Windows Filtering Platform has blocked a packet.
	/// 5157: The Windows Filtering Platform has blocked a connection.
	/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5152
	/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5157
	/// </summary>
	private const string Query = "*[System[(EventID=5152 or EventID=5157)]]";

	// To reduce noise in the logs
	private static readonly FrozenSet<string> ExcludedFilterOrigins = new string[]
	{
			"Stealth", "Unknown", "Query User Default", "WSH Default"
	}.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

	// Watcher for real-time monitoring
	private static EventLogWatcher? watcher;

	// Cache to hold resolved destination addresses
	private static readonly ConcurrentDictionary<string, string> ResolvedAddressCache = new(StringComparer.OrdinalIgnoreCase);

	// Counter used to alternate between Cloudflare and Google DNS over HTTPS APIs across multiple threads
	private static long _dnsRequestCounter;

	// Shared HttpClient optimized for fast, direct connections to DNS over HTTPS APIs
	private static readonly HttpClient DnsHttpClient = new()
	{
		Timeout = TimeSpan.FromSeconds(3)
	};

	/// <summary>
	/// Retrieves blocked packet events.
	/// </summary>
	/// <param name="resolveDestinationAddresses">Determines whether to synchronously resolve destination IP addresses to domains.</param>
	/// <returns></returns>
	internal static async Task<List<FirewallEvent>> GetBlockedPackets(bool resolveDestinationAddresses)
	{
		return await Task.Run(() =>
		{
			List<FirewallEvent> results = [];

			EventLogQuery eventQuery = new(SecurityLogPath, PathType.LogName, Query);

			using EventLogReader logReader = new(eventQuery);

			EventRecord eventRecord;

			while ((eventRecord = logReader.ReadEvent()) is not null)
			{
				using (eventRecord)
				{
					FirewallEvent? fwEvent = ParseFirewallEvent(eventRecord, resolveDestinationAddresses);
					if (fwEvent is not null)
					{
						results.Add(fwEvent);
					}
				}
			}

			// Sort descending by time
			results.Sort((x, y) => Nullable.Compare(y.TimeCreated, x.TimeCreated));

			return results;

		});
	}

	/// <summary>
	/// Starts real-time monitoring of firewall blocked events.
	/// </summary>
	/// <param name="resolveDestinationAddresses">Determines whether to synchronously resolve destination IP addresses to domains.</param>
	/// <param name="callback">Action to invoke when a new event is found.</param>
	internal static void StartRealTimeMonitoring(bool resolveDestinationAddresses, Action<FirewallEvent> callback)
	{
		// Ensure any existing watcher is stopped
		StopRealTimeMonitoring();

		try
		{
			EventLogQuery eventQuery = new(SecurityLogPath, PathType.LogName, Query);
			watcher = new EventLogWatcher(eventQuery);

			watcher.EventRecordWritten += (sender, e) =>
			{
				EventRecord? record = e.EventRecord;
				if (record is null) return;

				try
				{
					using (record)
					{
						FirewallEvent? fwEvent = ParseFirewallEvent(record, resolveDestinationAddresses);
						if (fwEvent is not null)
						{
							callback(fwEvent);
						}
					}
				}
				catch
				{
					// Suppress errors for individual event parsing to keep the stream alive
				}
			};

			watcher.Enabled = true;
		}
		catch
		{
			StopRealTimeMonitoring();
			throw;
		}
	}

	/// <summary>
	/// Stops the real-time monitoring watcher.
	/// </summary>
	internal static void StopRealTimeMonitoring()
	{
		watcher?.Dispose();
		watcher = null;
	}

	/// <summary>
	/// Determines if an IPAddress is part of a private, link-local, or loopback range.
	/// </summary>
	/// <param name="ip">The IPAddress to check.</param>
	/// <returns>True if the IP is private or local, otherwise false.</returns>
	internal static bool IsPrivateOrLocalIpAddress(IPAddress ip)
	{
		if (IPAddress.IsLoopback(ip))
		{
			return true;
		}

		if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
		{
			Span<byte> bytes = stackalloc byte[4];
			if (ip.TryWriteBytes(bytes, out int bytesWritten))
			{
				byte b0 = bytes[0];
				byte b1 = bytes[1];

				// 10.0.0.0/8 (Private)
				if (b0 == 10)
				{
					return true;
				}

				// 172.16.0.0/12 (Private)
				if (b0 == 172 && b1 >= 16 && b1 <= 31)
				{
					return true;
				}

				// 192.168.0.0/16 (Private)
				if (b0 == 192 && b1 == 168)
				{
					return true;
				}

				// 169.254.0.0/16 (Link-local)
				if (b0 == 169 && b1 == 254)
				{
					return true;
				}

				// 100.64.0.0/10 (Carrier-grade NAT)
				if (b0 == 100 && b1 >= 64 && b1 <= 127)
				{
					return true;
				}
			}
		}
		else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
		{
			if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast)
			{
				return true;
			}

			Span<byte> bytes = stackalloc byte[16];
			if (ip.TryWriteBytes(bytes, out int bytesWritten))
			{
				byte b0 = bytes[0];

				// fc00::/7 Unique Local Address
				if ((b0 & 0xFE) == 0xFC)
				{
					return true;
				}
			}
		}

		return false;
	}

	/// <summary>
	/// Synchronously resolves an IP address to a domain name using Cloudflare's direct 1.1.1.1 or Google's direct 8.8.8.8 DoH API.
	/// </summary>
	/// <param name="ipAddress">The IP address to resolve.</param>
	/// <returns></returns>
	private static string ResolveIpAddress(string ipAddress)
	{
		if (ResolvedAddressCache.TryGetValue(ipAddress, out string? cachedHostName))
		{
			return cachedHostName;
		}

		if (!IPAddress.TryParse(ipAddress, out IPAddress? parsedIp))
		{
			return ipAddress; // Not a valid IP
		}

		// Skip DNS resolution for private, local, and loopback IP addresses
		if (IsPrivateOrLocalIpAddress(parsedIp))
		{
			return ipAddress;
		}

		try
		{
			string arpaName = GetArpaName(parsedIp);
			if (string.IsNullOrEmpty(arpaName))
			{
				return ipAddress;
			}

			// Alternate between Cloudflare (1.1.1.1) and Google (8.8.8.8) DoH APIs
			long counter = Interlocked.Increment(ref _dnsRequestCounter);
			bool useCloudflare = (counter % 2) != 0;
			string url = useCloudflare
				? $"https://1.1.1.1/dns-query?name={arpaName}&type=PTR"
				: $"https://8.8.8.8/resolve?name={arpaName}&type=PTR";

			using HttpRequestMessage request = new(HttpMethod.Get, url);
			request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-json"));

			using HttpResponseMessage response = DnsHttpClient.Send(request);

			if (response.IsSuccessStatusCode)
			{
				using Stream responseStream = response.Content.ReadAsStream();
				using JsonDocument jsonDoc = JsonDocument.Parse(responseStream);

				if (jsonDoc.RootElement.TryGetProperty("Answer", out JsonElement answers) &&
					answers.ValueKind == JsonValueKind.Array &&
					answers.GetArrayLength() > 0)
				{
					JsonElement firstAnswer = answers[0];
					if (firstAnswer.TryGetProperty("data", out JsonElement dataElement))
					{
						string? hostName = dataElement.GetString();
						if (!string.IsNullOrWhiteSpace(hostName))
						{
							// Cloudflare and Google return PTR records with a trailing dot (e.g., "example.com."). We strip it.
							if (hostName.EndsWith('.'))
							{
								hostName = hostName[..^1];
							}

							_ = ResolvedAddressCache.TryAdd(ipAddress, hostName);
							return hostName;
						}
					}
				}
			}

			// If we get here, resolution failed or no answer was provided (NXDOMAIN)
			_ = ResolvedAddressCache.TryAdd(ipAddress, ipAddress);
			return ipAddress;
		}
		catch
		{
			return ipAddress;
		}
	}

	/// <summary>
	/// Converts an IPAddress to its corresponding in-addr.arpa or ip6.arpa representation for reverse DNS lookups.
	/// </summary>
	/// <param name="ip">The IPAddress to parse.</param>
	/// <returns>The .arpa mapped name.</returns>
	private static string GetArpaName(IPAddress ip)
	{
		byte[] bytes = ip.GetAddressBytes();

		if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
		{
			return $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}.in-addr.arpa";
		}
		else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
		{
			return string.Create(72, bytes, static (span, b) =>
			{
				int pos = 0;
				for (int i = b.Length - 1; i >= 0; i--)
				{
					byte val = b[i];

					// Low nibble
					int low = val & 0x0F;
					span[pos++] = low < 10 ? (char)('0' + low) : (char)('a' + low - 10);
					span[pos++] = '.';

					// High nibble
					int high = (val >> 4) & 0x0F;
					span[pos++] = high < 10 ? (char)('0' + high) : (char)('a' + high - 10);
					span[pos++] = '.';
				}
				"ip6.arpa".AsSpan().CopyTo(span[pos..]);
			});
		}

		return string.Empty;
	}

	/// <summary>
	/// Parses an EventRecord into a <see cref="FirewallEvent"/> object.
	/// </summary>
	/// <param name="eventRecord"></param>
	/// <param name="resolveDestinationAddresses">Determines whether to synchronously resolve destination IP addresses to domains.</param>
	/// <returns></returns>
	private static FirewallEvent? ParseFirewallEvent(EventRecord eventRecord, bool resolveDestinationAddresses)
	{
		string xmlString = eventRecord.ToXml();
		ReadOnlySpan<char> xmlSpan = xmlString.AsSpan();

		// Parse the fields
		DateTime? timeCreated = eventRecord.TimeCreated;
		string? direction = GetEventLogsData.GetStringValue(xmlSpan, "Direction");
		string? protocol = GetEventLogsData.GetStringValue(xmlSpan, "Protocol");
		string? sourceAddress = GetEventLogsData.GetStringValue(xmlSpan, "SourceAddress");
		string? destAddress = GetEventLogsData.GetStringValue(xmlSpan, "DestAddress");
		string? sourcePort = GetEventLogsData.GetStringValue(xmlSpan, "SourcePort");
		string? destPort = GetEventLogsData.GetStringValue(xmlSpan, "DestPort");
		string? application = GetEventLogsData.GetStringValue(xmlSpan, "Application");
		string? processId = GetEventLogsData.GetStringValue(xmlSpan, "ProcessId");
		string? filterOrigin = GetEventLogsData.GetStringValue(xmlSpan, "FilterOrigin");
		string? layerName = GetEventLogsData.GetStringValue(xmlSpan, "LayerName");
		string? userId = eventRecord.UserId?.ToString();

		// Filter out unwanted origins
		if (filterOrigin is not null && ExcludedFilterOrigins.Contains(filterOrigin))
		{
			return null;
		}

		if (FilterOriginRuleMap.Value.TryGetValue(filterOrigin ?? string.Empty, out string? ruleName))
		{
			filterOrigin = ruleName;
		}

		// Clean up Direction
		if (string.Equals(direction, "%%14592", StringComparison.OrdinalIgnoreCase))
		{
			direction = "Inbound";
		}
		else if (string.Equals(direction, "%%14593", StringComparison.OrdinalIgnoreCase))
		{
			direction = "Outbound";
		}
		else if (string.Equals(direction, "%%14594", StringComparison.OrdinalIgnoreCase))
		{
			direction = "Forward";
		}
		else if (string.Equals(direction, "%%14595", StringComparison.OrdinalIgnoreCase))
		{
			direction = "Bidirectional";
		}

		// Clean up Protocol
		// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
		if (int.TryParse(protocol, out int protocolNum))
		{
			protocol = protocolNum switch
			{
				6 => "TCP",
				17 => "UDP",
				1 => "ICMP",
				58 => "ICMPv6",
				3 => "GGP",
				8 => "EGP",
				12 => "PUP",
				20 => "HMP",
				27 => "RDP",
				46 => "RSVP",
				47 => "GRE",
				50 => "ESP",
				51 => "AH",
				66 => "RVD",
				88 => "EIGRP",
				89 => "OSPFIGP",
				_ => protocol
			};
		}

		// Resolve destination address if requested
		if (resolveDestinationAddresses && !string.IsNullOrWhiteSpace(destAddress))
		{
			destAddress = ResolveIpAddress(destAddress);
		}

		// Clean up Application Path
		if (!string.IsNullOrEmpty(application))
		{
			application = GetEventLogsData.ResolvePath(application);
		}

		// Clean up LayerName
		if (layerName is not null)
		{
			layerName = layerName switch
			{
				"%%14596" => "IP Packet",
				"%%14597" => "Transport",
				"%%14598" => "Forward",
				"%%14599" => "Stream",
				"%%14600" => "Datagram Data",
				"%%14601" => "ICMP Error",
				"%%14602" => "MAC 802.3",
				"%%14603" => "MAC Native",
				"%%14604" => "vSwitch",
				"%%14608" => "Resource Assignment",
				"%%14609" => "Listen",
				"%%14610" => "Receive/Accept",
				"%%14611" => "Connect",
				"%%14612" => "Flow Established",
				"%%14614" => "Resource Release",
				"%%14615" => "Endpoint Closure",
				"%%14616" => "Connect Redirect",
				"%%14617" => "Bind Redirect",
				"%%14624" => "Stream Packet",
				_ => layerName
			};
		}

		return new()
		{
			TimeCreated = timeCreated,
			Application = application,
			Direction = direction,
			Protocol = protocol,
			SourceAddress = sourceAddress,
			DestAddress = destAddress,
			SourcePort = sourcePort,
			DestPort = destPort,
			ProcessId = processId,
			FilterOrigin = filterOrigin,
			UserID = userId,
			LayerName = layerName
		};
	}
}
