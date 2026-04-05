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
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

internal sealed partial class OpenPortsDialog : ContentDialogV2
{
	private readonly List<OpenPortItem> _allPorts = [];
	private readonly ObservableCollection<OpenPortItem> DisplayedPorts = [];

	private string _currentSortKey = "Port";
	private bool _isSortDescending;

	private readonly DispatcherTimer _refreshTimer = new();

	internal OpenPortsDialog()
	{
		InitializeComponent();

		_refreshTimer.Interval = TimeSpan.FromSeconds(5);
		_refreshTimer.Tick += RefreshTimer_Tick;

		LoadPortsData();
	}

	private void OpenPortsDialog_Closed(ContentDialog sender, ContentDialogClosedEventArgs args)
	{
		// Clean up the timer to prevent memory leaks when dialog is dismissed
		_refreshTimer.Stop();
		_refreshTimer.Tick -= RefreshTimer_Tick;
	}

	private void RefreshTimer_Tick(object? sender, object e) => LoadPortsData();

	private void AutoRefreshToggle_Toggled()
	{
		if (AutoRefreshToggle.IsOn)
		{
			_refreshTimer.Start();
		}
		else
		{
			_refreshTimer.Stop();
		}
	}

	private void RefreshIntervalBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
	{
		if (double.IsNaN(args.NewValue) || args.NewValue < 1)
		{
			return;
		}
		_refreshTimer.Interval = TimeSpan.FromSeconds(args.NewValue);
	}

	private void LoadPortsData()
	{
		List<OpenPortItem> newPorts = [];
		Dictionary<uint, string> processCache = [];

		try
		{
			LoadTcp4Ports(newPorts, processCache);
			LoadTcp6Ports(newPorts, processCache);
			LoadUdp4Ports(newPorts, processCache);
			LoadUdp6Ports(newPorts, processCache);

			// Group by the connection identity attributes to strip out any absolute duplicates
			List<OpenPortItem> distinctPorts = newPorts
				.GroupBy(p => new { p.Port, p.Protocol, p.LocalAddress, p.RemoteAddressAndPort, p.State, p.ProcessName })
				.Select(g => g.First())
				.ToList();

			_allPorts.Clear();
			_allPorts.AddRange(distinctPorts);

			ApplyFilterAndSort();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	private unsafe void LoadTcp4Ports(List<OpenPortItem> ports, Dictionary<uint, string> processCache)
	{
		int size = 0;
		uint result = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, true, NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);

		if (result == 122 || result == 120) // ERROR_INSUFFICIENT_BUFFER
		{
			IntPtr buffer = Marshal.AllocHGlobal(size);
			try
			{
				result = NativeMethods.GetExtendedTcpTable(buffer, ref size, true, NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
				if (result == 0) // NO_ERROR
				{
					int entries = Marshal.ReadInt32(buffer);
					IntPtr ptr = IntPtr.Add(buffer, 4); // Skip dwNumEntries

					for (int i = 0; i < entries; i++)
					{
						MIB_TCPROW_OWNER_PID* row = (MIB_TCPROW_OWNER_PID*)ptr;

						// Native representations are in network byte order so endianness must be reversed on typical systems
						ushort localPort = BinaryPrimitives.ReverseEndianness((ushort)row->localPort);
						ushort remotePort = BinaryPrimitives.ReverseEndianness((ushort)row->remotePort);
						IPAddress localIp = new(row->localAddr);
						IPAddress remoteIp = new(row->remoteAddr);
						string state = GetTcpState(row->state);
						string procName = GetProcessName(row->owningPid, processCache);

						ports.Add(new OpenPortItem(localPort, "TCP (v4)", localIp.ToString(), $"{remoteIp}:{remotePort}", state, procName));
						ptr += sizeof(MIB_TCPROW_OWNER_PID);
					}
				}
			}
			finally
			{
				Marshal.FreeHGlobal(buffer);
			}
		}
	}

	private unsafe void LoadTcp6Ports(List<OpenPortItem> ports, Dictionary<uint, string> processCache)
	{
		int size = 0;
		uint result = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, true, NativeMethods.AF_INET6, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);

		if (result == 122 || result == 120)
		{
			IntPtr buffer = Marshal.AllocHGlobal(size);
			try
			{
				result = NativeMethods.GetExtendedTcpTable(buffer, ref size, true, NativeMethods.AF_INET6, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
				if (result == 0)
				{
					int entries = Marshal.ReadInt32(buffer);
					IntPtr ptr = IntPtr.Add(buffer, 4);

					for (int i = 0; i < entries; i++)
					{
						MIB_TCP6ROW_OWNER_PID* row = (MIB_TCP6ROW_OWNER_PID*)ptr;

						ushort localPort = BinaryPrimitives.ReverseEndianness((ushort)row->localPort);
						ushort remotePort = BinaryPrimitives.ReverseEndianness((ushort)row->remotePort);

						IPAddress localIp = new(new ReadOnlySpan<byte>(row->localAddr, 16))
						{
							ScopeId = row->localScopeId
						};

						IPAddress remoteIp = new(new ReadOnlySpan<byte>(row->remoteAddr, 16))
						{
							ScopeId = row->remoteScopeId
						};

						string state = GetTcpState(row->state);
						string procName = GetProcessName(row->owningPid, processCache);

						ports.Add(new OpenPortItem(localPort, "TCP (v6)", localIp.ToString(), $"{remoteIp}:{remotePort}", state, procName));
						ptr += sizeof(MIB_TCP6ROW_OWNER_PID);
					}
				}
			}
			finally
			{
				Marshal.FreeHGlobal(buffer);
			}
		}
	}

	private unsafe void LoadUdp4Ports(List<OpenPortItem> ports, Dictionary<uint, string> processCache)
	{
		int size = 0;
		uint result = NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref size, true, NativeMethods.AF_INET, NativeMethods.UDP_TABLE_OWNER_PID, 0);

		if (result == 122 || result == 120)
		{
			IntPtr buffer = Marshal.AllocHGlobal(size);
			try
			{
				result = NativeMethods.GetExtendedUdpTable(buffer, ref size, true, NativeMethods.AF_INET, NativeMethods.UDP_TABLE_OWNER_PID, 0);
				if (result == 0)
				{
					int entries = Marshal.ReadInt32(buffer);
					IntPtr ptr = IntPtr.Add(buffer, 4);

					for (int i = 0; i < entries; i++)
					{
						MIB_UDPROW_OWNER_PID* row = (MIB_UDPROW_OWNER_PID*)ptr;

						ushort localPort = BinaryPrimitives.ReverseEndianness((ushort)row->localPort);
						IPAddress localIp = new(row->localAddr);
						string procName = GetProcessName(row->owningPid, processCache);

						ports.Add(new OpenPortItem(localPort, "UDP (v4)", localIp.ToString(), "N/A", "N/A", procName));
						ptr += sizeof(MIB_UDPROW_OWNER_PID);
					}
				}
			}
			finally
			{
				Marshal.FreeHGlobal(buffer);
			}
		}
	}

	private unsafe void LoadUdp6Ports(List<OpenPortItem> ports, Dictionary<uint, string> processCache)
	{
		int size = 0;
		uint result = NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref size, true, NativeMethods.AF_INET6, NativeMethods.UDP_TABLE_OWNER_PID, 0);

		if (result == 122 || result == 120)
		{
			IntPtr buffer = Marshal.AllocHGlobal(size);
			try
			{
				result = NativeMethods.GetExtendedUdpTable(buffer, ref size, true, NativeMethods.AF_INET6, NativeMethods.UDP_TABLE_OWNER_PID, 0);
				if (result == 0)
				{
					int entries = Marshal.ReadInt32(buffer);
					IntPtr ptr = IntPtr.Add(buffer, 4);

					for (int i = 0; i < entries; i++)
					{
						MIB_UDP6ROW_OWNER_PID* row = (MIB_UDP6ROW_OWNER_PID*)ptr;

						ushort localPort = BinaryPrimitives.ReverseEndianness((ushort)row->localPort);

						IPAddress localIp = new(new ReadOnlySpan<byte>(row->localAddr, 16))
						{
							ScopeId = row->localScopeId
						};

						string procName = GetProcessName(row->owningPid, processCache);

						ports.Add(new OpenPortItem(localPort, "UDP (v6)", localIp.ToString(), "N/A", "N/A", procName));
						ptr += sizeof(MIB_UDP6ROW_OWNER_PID);
					}
				}
			}
			finally
			{
				Marshal.FreeHGlobal(buffer);
			}
		}
	}

	private static string GetProcessName(uint pid, Dictionary<uint, string> cache)
	{
		if (cache.TryGetValue(pid, out string? cachedName))
		{
			return cachedName;
		}

		string name;

		if (pid == 0)
		{
			name = "System Idle Process";
		}
		else if (pid == 4)
		{
			name = "System";
		}
		else
		{
			try
			{
				using Process proc = Process.GetProcessById((int)pid);
				name = proc.ProcessName;
			}
			catch
			{
				name = $"Unknown (PID: {pid})";
			}
		}

		cache[pid] = name;
		return name;
	}

	private static string GetTcpState(uint state) => state switch
	{
		1 => "Closed",
		2 => "Listen",
		3 => "Syn Sent",
		4 => "Syn Received",
		5 => "Established",
		6 => "Fin Wait 1",
		7 => "Fin Wait 2",
		8 => "Close Wait",
		9 => "Closing",
		10 => "Last Ack",
		11 => "Time Wait",
		12 => "Delete TCB",
		_ => state.ToString()
	};

	private void HeaderSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			if (string.Equals(_currentSortKey, key, StringComparison.OrdinalIgnoreCase))
			{
				_isSortDescending = !_isSortDescending;
			}
			else
			{
				_currentSortKey = key;
				_isSortDescending = false;
			}

			ApplyFilterAndSort();
		}
	}

	private void ApplyFilterAndSort()
	{
		string searchTerm = SearchBox.Text.Trim();
		IEnumerable<OpenPortItem> query = _allPorts;

		if (!string.IsNullOrWhiteSpace(searchTerm))
		{
			query = query.Where(p =>
				p.Port.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				p.Protocol.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				p.LocalAddress.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				p.RemoteAddressAndPort.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				p.State.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				p.ProcessName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase));
		}

		query = _currentSortKey switch
		{
			"Protocol" => _isSortDescending ? query.OrderByDescending(p => p.Protocol) : query.OrderBy(p => p.Protocol),
			"LocalAddress" => _isSortDescending ? query.OrderByDescending(p => p.LocalAddress) : query.OrderBy(p => p.LocalAddress),
			"RemoteAddressAndPort" => _isSortDescending ? query.OrderByDescending(p => p.RemoteAddressAndPort) : query.OrderBy(p => p.RemoteAddressAndPort),
			"State" => _isSortDescending ? query.OrderByDescending(p => p.State) : query.OrderBy(p => p.State),
			"Process" => _isSortDescending ? query.OrderByDescending(p => p.ProcessName) : query.OrderBy(p => p.ProcessName),
			_ => _isSortDescending ? query.OrderByDescending(p => p.Port) : query.OrderBy(p => p.Port),
		};

		List<OpenPortItem> newItems = query.ToList();

		// Smart Merge so that updating elements sequentially directly on the list ensures that the List View
		// active selection and visual scrolling location do not flicker or jump to the top automatically.
		for (int i = 0; i < newItems.Count; i++)
		{
			if (i < DisplayedPorts.Count)
			{
				if (!AreItemsEqual(DisplayedPorts[i], newItems[i]))
				{
					DisplayedPorts[i] = newItems[i];
				}
			}
			else
			{
				DisplayedPorts.Add(newItems[i]);
			}
		}

		while (DisplayedPorts.Count > newItems.Count)
		{
			DisplayedPorts.RemoveAt(DisplayedPorts.Count - 1);
		}
	}

	private static bool AreItemsEqual(OpenPortItem a, OpenPortItem b) => a.Port == b.Port &&
			   string.Equals(a.Protocol, b.Protocol, StringComparison.Ordinal) &&
			   string.Equals(a.LocalAddress, b.LocalAddress, StringComparison.Ordinal) &&
			   string.Equals(a.RemoteAddressAndPort, b.RemoteAddressAndPort, StringComparison.Ordinal) &&
			   string.Equals(a.State, b.State, StringComparison.Ordinal) &&
			   string.Equals(a.ProcessName, b.ProcessName, StringComparison.Ordinal);

}

internal sealed class OpenPortItem(int port, string protocol, string localAddress, string remoteAddressAndPort, string state, string processName)
{
	internal int Port => port;
	internal string Protocol => protocol;
	internal string LocalAddress => localAddress;
	internal string RemoteAddressAndPort => remoteAddressAndPort;
	internal string State => state;
	internal string ProcessName => processName;
}
