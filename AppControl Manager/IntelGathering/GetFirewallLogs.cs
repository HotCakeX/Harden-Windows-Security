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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Threading.Tasks;

namespace AppControlManager.IntelGathering;

internal static class GetFirewallLogs
{
	// Security event log path.
	private const string SecurityLogPath = "Security";

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

	/// <summary>
	/// Retrieves blocked packet events.
	/// </summary>
	/// <returns></returns>
	internal static async Task<List<FirewallEvent>> GetBlockedPackets()
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
					FirewallEvent? fwEvent = ParseFirewallEvent(eventRecord);
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
	/// <param name="callback">Action to invoke when a new event is found.</param>
	internal static void StartRealTimeMonitoring(Action<FirewallEvent> callback)
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
						FirewallEvent? fwEvent = ParseFirewallEvent(record);
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
	/// Parses an EventRecord into a <see cref="FirewallEvent"/> object.
	/// </summary>
	/// <param name="eventRecord"></param>
	/// <returns></returns>
	private static FirewallEvent? ParseFirewallEvent(EventRecord eventRecord)
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
