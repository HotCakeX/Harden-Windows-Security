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

using System.Collections.Generic;
using System.Diagnostics;

namespace HardenSystemSecurity.Widgets;

/// <summary>
/// A single network adapter of the machine, exactly as the Network Connections folder of Windows lists it.
/// </summary>
internal readonly struct NetworkAdapter(ulong interfaceLuid, uint interfaceIndex, string name, bool isConnected)
{
	/// <summary>
	/// The locally unique identifier of the interface, which stays the same for as long as the adapter exists and is
	/// therefore what the widget remembers its selection by.
	/// </summary>
	internal ulong InterfaceLuid => interfaceLuid;

	/// <summary>
	/// The interface index, which is only used to recognize the adapter that currently carries the internet traffic.
	/// </summary>
	internal uint InterfaceIndex => interfaceIndex;

	/// <summary>
	/// The connection name of the adapter, which is the very same name that Windows shows for it.
	/// </summary>
	internal string Name => name;

	/// <summary>
	/// Whether the operational status of the adapter is up.
	/// </summary>
	internal bool IsConnected => isConnected;
}

/// <summary>
/// The live throughput and the cumulative traffic of a single network adapter.
/// </summary>
internal readonly struct NetworkAdapterSample(
		double receiveBytesPerSecond,
		double sendBytesPerSecond,
		ulong totalReceivedBytes,
		ulong totalSentBytes)
{
	/// <summary>
	/// Bytes received per second over the interval between the two most recent samples of this adapter.
	/// </summary>
	internal double ReceiveBytesPerSecond => receiveBytesPerSecond;

	/// <summary>
	/// Bytes sent per second over the interval between the two most recent samples of this adapter.
	/// </summary>
	internal double SendBytesPerSecond => sendBytesPerSecond;

	/// <summary>
	/// Every byte that the adapter received since it was initialized, which is the same counter that the status dialog
	/// of the adapter in Windows shows.
	/// </summary>
	internal ulong TotalReceivedBytes => totalReceivedBytes;

	/// <summary>
	/// Every byte that the adapter sent since it was initialized, which is the same counter that the status dialog of
	/// the adapter in Windows shows.
	/// </summary>
	internal ulong TotalSentBytes => totalSentBytes;
}

/// <summary>
/// Enumerates the network adapters of the machine and measures the throughput of the ones that the Network widget
/// currently displays.
///
/// It has no UI/dispatcher dependency at all so that it can run inside of the headless widget provider COM server process.
///
/// The adapter list is walked through <see href="https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getiftable2ex">GetIfTable2Ex</see>
/// at the level that skips the statistics entirely, and it is only turned into managed objects again when the
/// interfaces of the machine actually changed, so listing the adapters costs no managed allocation at all in the steady
/// state. The traffic counters themselves are read one adapter at a time with
/// <see href="https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getifentry2">GetIfEntry2</see>, which
/// means that only the one or two adapters that are actually on screen are ever measured.
///
/// The counters are the same ones that the status dialog of an adapter in Windows shows, so both the totals and the
/// rates that are derived from them match what Windows itself reports.
///
/// The instance is not thread safe. The widget provider only ever touches it while holding its own state lock.
/// </summary>
internal sealed unsafe class NetworkThroughputSampler
{
	// https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-
	private const uint NO_ERROR = 0U;

	// https://learn.microsoft.com/windows/win32/api/ifdef/ne-ifdef-if_oper_status
	private const int IfOperStatusUp = 1;

	// The IANA interface types of the pseudo interfaces that Windows keeps out of its Network Connections folder.
	// https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_if_row2
	private const uint IfTypeSoftwareLoopback = 24U;
	private const uint IfTypeTunnel = 131U;

	// The NDIS media types used by the RAS pseudo adapters ("WAN Miniport (...)"), tunnel pseudo interfaces and the
	// loopback interface. Every one of them exists on a machine whether or not the user ever created a dial-up, PPPoE
	// or VPN connection, and none of them is listed by Windows, so the widget hides them as well.
	// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddndis/ne-ntddndis-_ndis_medium
	private const int NdisMediumWan = 3;
	private const int NdisMediumCoWan = 12;
	private const int NdisMediumTunnel = 15;
	private const int NdisMediumLoopback = 17;

	// The single bit of the "InterfaceAndOperStatusFlags" bit field of MIB_IF_ROW2 that tells an instance of an NDIS
	// light weight filter driver apart from a real adapter.
	// https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_if_row2
	private const int FilterInterfaceFlag = 0x2;

	// IF_MAX_STRING_SIZE + 1, which is the size of the alias buffer of MIB_IF_ROW2.
	private const int MaximumAliasLength = 257;

	// The 64 bit FNV-1a offset basis and prime, used to notice a change of the interfaces of the machine.
	// https://datatracker.ietf.org/doc/html/draft-eastlake-fnv
	private const ulong FnvOffsetBasis = 14695981039346656037UL;
	private const ulong FnvPrime = 1099511628211UL;

	// How long an enumerated adapter list stays valid before the interface table is walked again, which is what makes a
	// newly connected adapter (a VPN that just came up for example) show up without the widget having to be re-pinned.
	private static readonly long AdapterListLifetimeTicks = Stopwatch.Frequency * 15L;

	/// <summary>
	/// The previous reading of a single adapter, together with the result that the current sampling cycle produced for it.
	/// </summary>
	private struct AdapterCounters
	{
		internal ulong InOctets;
		internal ulong OutOctets;
		internal long Timestamp;
		internal long Generation;
		internal bool HasBaseline;
		internal NetworkAdapterSample Sample;
	}

	private readonly List<NetworkAdapter> _adapters = new(8);
	private readonly Dictionary<ulong, AdapterCounters> _counters = new(4);

	private long _adaptersTimestamp;
	private ulong _adaptersSignature;
	private bool _adaptersAvailable;
	private long _generation;

	/// <summary>
	/// The adapters of the machine, re-enumerated only once the cached list went stale.
	/// </summary>
	internal IReadOnlyList<NetworkAdapter> GetAdapters()
	{
		long now = Stopwatch.GetTimestamp();

		if (_adaptersAvailable && now - _adaptersTimestamp < AdapterListLifetimeTicks)
		{
			return _adapters;
		}

		// The timestamp is moved forward even when the enumeration fails so that a broken interface table cannot make
		// the widget walk it on every single update.
		_adaptersTimestamp = now;

		RefreshAdapters();

		return _adapters;
	}

	/// <summary>
	/// Opens a new sampling cycle, which drops the baseline of every adapter that no widget displayed during the
	/// previous one and makes sure that an adapter which several pinned widgets share is only measured once.
	/// </summary>
	internal void BeginSampleCycle()
	{
		foreach (KeyValuePair<ulong, AdapterCounters> counters in _counters)
		{
			if (counters.Value.Generation != _generation)
			{
				_ = _counters.Remove(counters.Key);
			}
		}

		_generation++;
	}

	/// <summary>
	/// Measures a single adapter, or returns the measurement that the current cycle already produced for it.
	/// </summary>
	/// <param name="interfaceLuid">The interface that has to be measured.</param>
	/// <param name="sample">The throughput and the totals of the adapter.</param>
	/// <returns>False when the adapter does not exist anymore.</returns>
	internal bool TrySample(ulong interfaceLuid, out NetworkAdapterSample sample)
	{
		if (interfaceLuid is 0UL)
		{
			sample = default;
			return false;
		}

		bool known = _counters.TryGetValue(interfaceLuid, out AdapterCounters counters);

		// A rate can only be derived once per cycle, so every widget that shows this adapter gets the very same result.
		if (known && counters.Generation == _generation)
		{
			sample = counters.Sample;
			return true;
		}

		MIB_IF_ROW2 row = default;
		row.InterfaceLuid = interfaceLuid;

		if (NativeMethods.GetIfEntry2(ref row) != NO_ERROR)
		{
			// The adapter is gone, so keeping its baseline around would only make the next adapter that reuses the
			// identifier start with a meaningless rate.
			_ = _counters.Remove(interfaceLuid);

			sample = default;
			return false;
		}

		long timestamp = Stopwatch.GetTimestamp();

		double receiveBytesPerSecond = 0.0;
		double sendBytesPerSecond = 0.0;

		if (counters.HasBaseline && timestamp > counters.Timestamp)
		{
			double elapsedSeconds = (timestamp - counters.Timestamp) / (double)Stopwatch.Frequency;

			if (elapsedSeconds > 0.0)
			{
				// A counter that went backwards means that the adapter was disabled and enabled again in between, in
				// which case there is nothing to report until the next cycle has established a new baseline.
				receiveBytesPerSecond = row.InOctets >= counters.InOctets ? (row.InOctets - counters.InOctets) / elapsedSeconds : 0.0;
				sendBytesPerSecond = row.OutOctets >= counters.OutOctets ? (row.OutOctets - counters.OutOctets) / elapsedSeconds : 0.0;
			}
		}

		sample = new NetworkAdapterSample(receiveBytesPerSecond, sendBytesPerSecond, row.InOctets, row.OutOctets);

		counters.InOctets = row.InOctets;
		counters.OutOctets = row.OutOctets;
		counters.Timestamp = timestamp;
		counters.Generation = _generation;
		counters.HasBaseline = true;
		counters.Sample = sample;

		_counters[interfaceLuid] = counters;

		return true;
	}

	/// <summary>
	/// The position of an adapter inside of a list, or -1 when the list does not contain it (anymore).
	/// </summary>
	internal static int IndexOf(IReadOnlyList<NetworkAdapter> adapters, ulong interfaceLuid)
	{
		if (interfaceLuid is 0UL)
		{
			return -1;
		}

		for (int index = 0; index < adapters.Count; index++)
		{
			if (adapters[index].InterfaceLuid == interfaceLuid)
			{
				return index;
			}
		}

		return -1;
	}

	/// <summary>
	/// The adapter that a freshly pinned widget starts on, which is the one that currently carries the traffic towards
	/// the internet because it is by far the most interesting one.
	/// </summary>
	internal static int GetPreferredAdapterIndex(IReadOnlyList<NetworkAdapter> adapters)
	{
		// 8.8.8.8, which only serves as a destination that is guaranteed to be routed off the machine. The address is
		// expected in network byte order, and this one reads the same in either order.
		const uint DestinationAddressNetworkOrder = (8U << 24) | (8U << 16) | (8U << 8) | 8U;

		if (NativeMethods.GetBestInterface(DestinationAddressNetworkOrder, out uint bestInterfaceIndex) == NO_ERROR)
		{
			for (int index = 0; index < adapters.Count; index++)
			{
				if (adapters[index].InterfaceIndex == bestInterfaceIndex)
				{
					return index;
				}
			}
		}

		return 0;
	}

	/// <summary>
	/// Walks the interface table of the machine and rebuilds the adapter list, but only when the interfaces really changed.
	/// </summary>
	private void RefreshAdapters()
	{
		IntPtr tablePointer = IntPtr.Zero;

		try
		{
			// The statistics of the interfaces are deliberately not gathered here, because the traffic counters of the
			// one or two adapters that the widget displays are read individually anyway.
			uint status = NativeMethods.GetIfTable2Ex(MIB_IF_TABLE_LEVEL.MibIfTableNormalWithoutStatistics, out tablePointer);

			if (status != NO_ERROR || tablePointer == IntPtr.Zero)
			{
				return;
			}

			MIB_IF_TABLE2* table = (MIB_IF_TABLE2*)tablePointer;
			uint entryCount = table->NumEntries;
			MIB_IF_ROW2* rows = &table->Table;

			ulong signature = ComputeSignature(rows, entryCount);

			// Nothing about the interfaces of the machine moved, so the already built list keeps serving the widget and
			// not a single managed object is created.
			if (_adaptersAvailable && signature == _adaptersSignature)
			{
				return;
			}

			_adapters.Clear();

			for (uint index = 0; index < entryCount; index++)
			{
				MIB_IF_ROW2* row = rows + index;

				if (!IsListedByWindows(row))
				{
					continue;
				}

				_adapters.Add(new NetworkAdapter(
					row->InterfaceLuid,
					row->InterfaceIndex,
					ReadAlias(row),
					row->OperStatus == IfOperStatusUp));
			}

			// A stable order keeps the carousel predictable across the refreshes of the list.
			_adapters.Sort(static (left, right) => string.Compare(left.Name, right.Name, StringComparison.OrdinalIgnoreCase));

			_adaptersSignature = signature;
			_adaptersAvailable = true;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
		finally
		{
			if (tablePointer != IntPtr.Zero)
			{
				NativeMethods.FreeMibTable(tablePointer);
			}
		}
	}

	/// <summary>
	/// Whether Windows itself lists the interface in its Network Connections folder, which is what the user recognizes
	/// as one of their network adapters no matter whether it belongs to a physical card, a VPN or a virtual switch.
	///
	/// Only the interfaces that Windows genuinely hides are dropped here. The "HardwareInterface" flag is deliberately
	/// not consulted, because Windows only sets it for an interface that a piece of hardware is behind, which would
	/// leave a machine with a single physical card showing a single adapter and would throw away every virtual adapter
	/// (a Hyper-V or WSL switch, a VPN, a Wi-Fi Direct adapter) that both the Network Connections folder and the
	/// Settings app list. The "EndPointInterface" flag is not consulted either, because Microsoft documents that such
	/// a device is only left out of the Network and Sharing Center and of the network icon of the notification area
	/// while "the connection is shown in the Network Connections Folder".
	/// https://learn.microsoft.com/windows-hardware/drivers/network/keywords-not-displayed-in-the-user-interface
	/// </summary>
	private static bool IsListedByWindows(MIB_IF_ROW2* row)
	{
		// The software loopback interface and every tunnel encapsulation interface (Teredo, ISATAP, 6to4, IP-HTTPS)
		// are pseudo interfaces that Windows never lists.
		if (row->Type is IfTypeSoftwareLoopback or IfTypeTunnel)
		{
			return false;
		}

		// An instance of an NDIS light weight filter driver is not an adapter of its own at all, it only describes a
		// layer that sits on top of one of the real adapters and would therefore duplicate it.
		if ((row->InterfaceAndOperStatusFlags & FilterInterfaceFlag) is not 0)
		{
			return false;
		}

		// The RAS, tunnel and loopback pseudo adapters are recognized by the medium that they run on rather than by name.
		if (row->MediaType is NdisMediumWan or NdisMediumCoWan or NdisMediumTunnel or NdisMediumLoopback)
		{
			return false;
		}

		// An interface that carries no connection name is nothing that the user could recognize.
		return row->Alias[0] is not '\0';
	}

	/// <summary>
	/// Reads the null terminated connection name out of the fixed buffer of an interface row.
	/// </summary>
	private static string ReadAlias(MIB_IF_ROW2* row)
	{
		char* alias = row->Alias;
		int length = 0;

		while (length < MaximumAliasLength && alias[length] is not '\0')
		{
			length++;
		}

		return new string(alias, 0, length);
	}

	/// <summary>
	/// A fingerprint of the identity, the name and the state of every interface of the machine, which is what tells the
	/// adapter list whether it has to be built again.
	/// </summary>
	private static ulong ComputeSignature(MIB_IF_ROW2* rows, uint entryCount)
	{
		ulong hash = FnvOffsetBasis;

		hash = Mix(hash, entryCount);

		for (uint index = 0; index < entryCount; index++)
		{
			MIB_IF_ROW2* row = rows + index;

			hash = Mix(hash, row->InterfaceLuid);
			hash = Mix(hash, row->Type);

			// Both of these are ULONG values of the native structure that are held in signed fields, so the conversion
			// back to their unsigned form has to be unchecked because the project compiles with checked arithmetic and
			// a bit field that has its highest bit set would otherwise throw.
			hash = Mix(hash, unchecked((uint)row->OperStatus));
			hash = Mix(hash, unchecked((uint)row->InterfaceAndOperStatusFlags));

			char* alias = row->Alias;

			for (int position = 0; position < MaximumAliasLength && alias[position] is not '\0'; position++)
			{
				hash = Mix(hash, alias[position]);
			}
		}

		return hash;
	}

	/// <summary>
	/// A single FNV-1a round. The multiplication of the hash by the prime deliberately wraps around, which is what the
	/// algorithm is defined to do, so it has to be unchecked because the project is compiled with checked arithmetic.
	/// </summary>
	private static ulong Mix(ulong hash, ulong value) => unchecked((hash ^ value) * FnvPrime);
}
