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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using AppControlManager.CustomUIElements;
using CommonCore.Hardware;
using CommonCore.Power;
using CommonCore.ThermalMonitors;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Win32;

namespace AppControlManager.ViewModels;

internal sealed partial class HomeVM : ViewModelBase, IDisposable
{
	/// <summary>
	/// Event handler for when the home page is loaded.
	/// We do not auto-start the heavy edge pulse storyboard, instead we rasterize and pulse in code.
	/// Glitch storyboards are short, single-run bursts and are triggered by the page every N seconds.
	/// </summary>
	/// <param name="sender"></param>
	internal void OnHomePageLoaded(object sender)
	{
		// Let these finish without waiting for them.
		_ = Task.Run(() =>
		{
			try
			{
				// Initialize and start the minute-aligned clock updater that only fires when the minute changes.
				InitializeSystemTimeUpdater();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				// Initialize and start the app RAM usage updater that fires every 2 seconds.
				InitializeAppRamUpdater();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				// Initialize and start the open ports updater that fires every 4 seconds.
				InitializeOpenPortsUpdater();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				// Initialize CPU temperature sampler
				InitializeCpuTemperatureSampler();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				// Initialize and start the internet speed updater that fires every 2 second.
				InitializeInternetSpeedUpdater();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				// Refresh the Windows Defender feed info asynchronously (fire-and-forget)
				_ = RefreshDefenderFeedAsync();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				CpuDetailsText = GetCpuDetailsString();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				GpuNamesText = GetGpuNamesString();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

		});

		_ = Task.Run(() =>
		{

			try
			{
				UptimeText = GetSystemUptimeString();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				BiosBootTimeText = GetBiosBootTimeString();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				SystemRamText = GetPhysicalMemoryExtendedString();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				DiskSizeText = GetTotalPhysicalDiskSizeString();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				OsInfoText = GetOsDetailsString();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				ComputerNameText = Environment.MachineName;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				SystemInfoText = GetSystemModelInfoString();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				UserKindText = Environment.IsPrivilegedProcess ? $"{Environment.UserName} - Administrator Privilege" : $"{Environment.UserName} - Standard Privilege";
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				PowerPlanText = PowerPlan.GetActivePowerPlanFriendlyName();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}

			try
			{
				List<WindowsActivationStatus> actStats = GetOSActivationStates.Get();
				if (actStats.Count > 0)
				{
					// First one is the active OS license
					WindowsActivationStatus mainStat = actStats[0];
					string genuine = mainStat.ClcGenuineStatus ?? "Unknown";
					string channel = mainStat.ProductKeyChannel ?? "";

					ActivationStatusSummaryText = !string.IsNullOrWhiteSpace(channel) ? $"{genuine} - {channel}" : genuine;
				}
				else
				{
					ActivationStatusSummaryText = "Activation info unavailable";
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				ActivationStatusSummaryText = "Activation info unavailable";
			}

		});
	}

	/// <summary>
	/// Runs when the Home page is unloaded. Called by the page's code behind since it's the one using x:Bind in the XAML.
	/// The active timers and data retrievals should not run in background when user is not on Home page.
	/// </summary>
	internal void OnHomePageUnLoaded()
	{
		// Clean up the clock timer
		if (_clockTimer is not null)
		{
			_clockTimer.Stop();
			_clockTimer.Tick -= OnClockInitialTick;
			_clockTimer.Tick -= OnClockTick;
			_clockTimer = null;
		}

		// Clean up the app RAM usage timer
		if (_appRamTimer is not null)
		{
			_appRamTimer.Stop();
			_appRamTimer.Tick -= OnAppRamTick;
			_appRamTimer = null;
		}

		// Clean up the open ports timer
		if (_portsTimer is not null)
		{
			_portsTimer.Stop();
			_portsTimer.Tick -= OnOpenPortsTick;
			_portsTimer = null;
		}

		// Dispose CPU temperature sampler if active
		_temperatureSampler?.Dispose();
		_temperatureSampler = null;
	}

	// Textblock sources bound to the UI for the info tiles.
	internal string? SystemTimeText { get; private set => SP(ref field, value); }
	internal string? UserKindText { get; private set => SP(ref field, value); }
	internal string? UptimeText { get; private set => SP(ref field, value); }
	internal string? BiosBootTimeText { get; private set => SP(ref field, value); }
	internal string? SystemRamText { get; private set => SP(ref field, value); }
	internal string? AppRamText { get; private set => SP(ref field, value); }
	internal string? DiskSizeText { get; private set => SP(ref field, value); }
	internal string? DiskTemperatureText { get; private set => SP(ref field, value); } = "Storage Temp: Unavailable";
	internal string? InternetSpeedText { get; private set => SP(ref field, value); }
	internal string? InternetTotalText { get; private set => SP(ref field, value); } = "Total: 0.0 GB ↓ / 0.0 GB ↑";
	internal string? CpuTemperatureText { get; private set => SP(ref field, value); } = "CPU Temp: Unavailable";
	internal string? OpenPortsText { get; private set => SP(ref field, value); } = "TCP: 0 / UDP: 0";
	internal string? PowerPlanText { get; private set => SP(ref field, value); }
	internal string? OsInfoText { get; private set => SP(ref field, value); }
	internal string? CpuDetailsText { get; private set => SP(ref field, value); }
	internal string? GpuNamesText { get; private set => SP(ref field, value); }
	internal string? ComputerNameText { get; private set => SP(ref field, value); }
	internal string? SystemInfoText { get; private set => SP(ref field, value); }
	internal string? ActivationStatusSummaryText { get; private set => SP(ref field, value); } = "Checking...";

	/// <summary>
	/// Timer first used as one-shot to align to next minute, then switched to repeating every minute.
	/// </summary>
	private DispatcherQueueTimer? _clockTimer;

	/// <summary>
	/// Timer that updates the app's working set (RAM usage).
	/// </summary>
	private DispatcherQueueTimer? _appRamTimer;

	/// <summary>
	/// Timer that updates the open ports count.
	/// </summary>
	private DispatcherQueueTimer? _portsTimer;

	/// <summary>
	/// CPU temperature sampler instance
	/// </summary>
	private TemperatureSampler? _temperatureSampler;

	/// <summary>
	/// Sets the current time immediately, then aligns the timer to the next minute boundary.
	/// After the first tick, the same timer becomes a repeating one-minute timer.
	/// </summary>
	private void InitializeSystemTimeUpdater()
	{
		// Always set the initial value immediately.
		UpdateSystemTime();

		// Compute due time until the next minute boundary.
		DateTime now = DateTime.Now;
		int msIntoMinute = now.Second * 1000 + now.Millisecond;
		TimeSpan due = TimeSpan.FromMilliseconds(60000 - msIntoMinute);

		_clockTimer = Dispatcher.CreateTimer();
		_clockTimer.IsRepeating = false; // one-shot to align to the next minute
		_clockTimer.Interval = due;
		_clockTimer.Tick += OnClockInitialTick;
		_clockTimer.Start();
	}

	/// <summary>
	/// Initializes and starts the repeating timer that updates the app RAM usage every 2 seconds.
	/// Also sets the initial value immediately.
	/// </summary>
	private void InitializeAppRamUpdater()
	{
		// Always set the initial values immediately.
		AppRamText = GetAppPrivateWorkingSetBytes_Native();
		UpdateStorageTemperature();

		_appRamTimer = Dispatcher.CreateTimer();
		_appRamTimer.IsRepeating = true; // repeating update
		_appRamTimer.Interval = TimeSpan.FromSeconds(2);
		_appRamTimer.Tick += OnAppRamTick;
		_appRamTimer.Start();
	}

	/// <summary>
	/// Initializes and starts the repeating timer that updates the open ports count every 4 seconds.
	/// </summary>
	private void InitializeOpenPortsUpdater()
	{
		// Set initial value
		OpenPortsText = GetOpenPortsString();

		_portsTimer = Dispatcher.CreateTimer();
		_portsTimer.IsRepeating = true;
		_portsTimer.Interval = TimeSpan.FromSeconds(4);
		_portsTimer.Tick += OnOpenPortsTick;
		_portsTimer.Start();
	}

	/// <summary>
	/// Initializes the CPU temperature sampler.
	/// </summary>
	private void InitializeCpuTemperatureSampler()
	{
		try
		{
			_temperatureSampler = new TemperatureSampler();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
		UpdateCpuTemperature();
	}

	/// <summary>
	/// One-shot tick at the next minute boundary.
	/// Updates the time and switches the timer to repeating once per minute.
	/// </summary>
	private void OnClockInitialTick(DispatcherQueueTimer sender, object args)
	{
		sender.Tick -= OnClockInitialTick;

		// Show the exact minute we just hit.
		UpdateSystemTime();

		// Switch to repeating once per minute.
		sender.IsRepeating = true;
		sender.Interval = TimeSpan.FromMinutes(1);
		sender.Tick += OnClockTick;

		// Restart after converting to repeating.
		sender.Start();
	}

	/// <summary>
	/// Repeating minute timer tick updates the time text.
	/// </summary>
	private void OnClockTick(DispatcherQueueTimer sender, object args) => UpdateSystemTime();

	/// <summary>
	/// Repeating 2-second timer tick updates the app RAM usage and Internet speed.
	/// Also updates CPU temperature and Storage temperature.
	/// </summary>
	private void OnAppRamTick(DispatcherQueueTimer sender, object args)
	{
		AppRamText = GetAppPrivateWorkingSetBytes_Native();
		UpdateInternetSpeed(first: false);
		UpdateCpuTemperature();
		UpdateStorageTemperature();
	}

	/// <summary>
	/// Repeating 4-second timer tick updates the open ports count.
	/// </summary>
	private void OnOpenPortsTick(DispatcherQueueTimer sender, object args) => OpenPortsText = GetOpenPortsString();

	/// <summary>
	/// Formats and sets the current system time text with hour and minute only.
	/// Respects system 12/24-hour preference and appends the UTC offset.
	/// </summary>
	private void UpdateSystemTime()
	{
		DateTime now = DateTime.Now;

		// Detect 24-hour vs 12-hour from the current culture's short time pattern.
		bool is24Hour = CultureInfo.CurrentCulture.DateTimeFormat.ShortTimePattern.Contains('H', StringComparison.Ordinal);

		string format = is24Hour ? "HH:mm" : "h:mm tt";

		string timeString = now.ToString(format, CultureInfo.CurrentCulture);
		string timeZoneString = GetLocalUtcOffsetString();

		SystemTimeText = $"{timeString}  ( {timeZoneString} )";
	}

	/// <summary>
	/// Samples current CPU temperature and updates bound text.
	/// </summary>
	private void UpdateCpuTemperature()
	{
		if (_temperatureSampler is null)
			return;

		double celsius = _temperatureSampler.SampleCelsiusOneShot();

		if (double.IsNaN(celsius) || double.IsInfinity(celsius))
			return;

		CpuTemperatureText = celsius.ToString("0.0", CultureInfo.InvariantCulture) + " °C";
	}

	/// <summary>
	/// Samples current Storage temperatures and updates bound text.
	/// </summary>
	private void UpdateStorageTemperature()
	{
		try
		{
			List<int> temps = StorageTemperature.GetDriveTemperatures();

			if (temps.Count > 0)
			{
				// Join disk temperatures
				DiskTemperatureText = string.Join(" - ", temps.Select(t => t.ToString(CultureInfo.InvariantCulture) + " °C"));
			}
			else
			{
				DiskTemperatureText = "Storage Temp: Unavailable";
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			DiskTemperatureText = "Storage Temp: Unavailable";
		}
	}

	/// <summary>
	/// Returns the local time zone's UTC offset as a string in "+HH:mm" or "-HH:mm" format.
	/// </summary>
	/// <returns>formatted string</returns>
	private static string GetLocalUtcOffsetString()
	{
		TimeSpan offset = DateTimeOffset.Now.Offset; // DST-aware local offset
		int totalMinutes = (int)Math.Round(offset.TotalMinutes, MidpointRounding.AwayFromZero);
		int absMinutes = Math.Abs(totalMinutes);
		int hours = absMinutes / 60;
		int minutes = absMinutes % 60;
		string sign = totalMinutes >= 0 ? "+" : "-";
		return FormattableString.Invariant($"{sign}{hours:00}:{minutes:00}");
	}

	/// <summary>
	/// Returns the System Uptime in a formatted string.
	/// </summary>
	/// <returns></returns>
	private static string GetSystemUptimeString()
	{
		// Monotonic uptime since system start; unaffected by manual clock changes.
		TimeSpan uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);

		int days = uptime.Days;
		int hours = uptime.Hours;
		int minutes = uptime.Minutes;

		string result = days > 0
			? string.Format(CultureInfo.InvariantCulture, "{0} days {1:D2} hours {2:D2} minutes", days, hours, minutes)
			: string.Format(CultureInfo.InvariantCulture, "{0:D2} hours {1:D2} minutes", hours, minutes);

		return result;
	}

	/// <summary>
	/// Returns the BIOS Boot Time (POST duration) as a formatted string.
	/// Reads from the registry key that Windows populates during boot.
	/// </summary>
	/// <returns></returns>
	private static string GetBiosBootTimeString()
	{
		try
		{
			// FwPOSTTime is stored in milliseconds in the Registry
			const string keyName = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power";
			object? value = Registry.GetValue(keyName, "FwPOSTTime", null);
			if (value is int ms)
			{
				TimeSpan t = TimeSpan.FromMilliseconds(ms);
				return $"{t.TotalSeconds:N1} seconds";
			}
		}
		catch { }
		return "Unavailable";
	}

	/// <summary>
	/// Gets the available RAM on the system.
	/// </summary>
	/// <returns></returns>
	private static string GetAvailablePhysicalMemoryBytes()
	{
		bool ok = NativeMethods.GetPhysicallyInstalledSystemMemory(out ulong totalKilobytes);
		if (!ok || totalKilobytes == 0)
			return "0";

		ulong bytes = totalKilobytes * 1024UL; // KB -> bytes
		return ByteToString(bytes);
	}

	/// <summary>
	/// Returns the current process's Private Working Set (bytes).
	/// Falls back to Working Set when PrivateWorkingSetSize is not available.
	/// </summary>
	/// <returns>bytes</returns>
	private static string GetAppPrivateWorkingSetBytes_Native()
	{
		PROCESS_MEMORY_COUNTERS_EX2 counters = default;
		counters.cb = (uint)Unsafe.SizeOf<PROCESS_MEMORY_COUNTERS_EX2>();

		IntPtr hProcess = NativeMethods.GetCurrentProcess();
		bool ok = NativeMethods.K32GetProcessMemoryInfo(hProcess, ref counters, counters.cb);
		if (!ok)
		{
			return ByteToString(0UL);
		}

		// Prefer Private Working Set to match Task Manager's reported value; if zero/unavailable, fall back to total Working Set.
		ulong privateWs = counters.PrivateWorkingSetSize;
		if (privateWs != 0UL)
		{
			return ByteToString(privateWs);
		}

		return ByteToString(counters.WorkingSetSize);
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
	private static string ByteToString(ulong bytes)
	{
		const ulong OneGB = 1024UL * 1024UL * 1024UL;
		const ulong OneMB = 1024UL * 1024UL;

		if (bytes >= OneGB)
		{
			double gb = bytes / (double)OneGB;
			return gb.ToString("0.#", CultureInfo.InvariantCulture) + " GB";
		}
		else
		{
			double mb = bytes / (double)OneMB;
			return mb.ToString("0.#", CultureInfo.InvariantCulture) + " MB";
		}
	}

	/// <summary>
	/// Returns the total combined size of all physical disks as a formatted string.
	/// Using managed code here so we can display this info in unelevated sessions as well.
	/// </summary>
	private static string GetTotalPhysicalDiskSizeString()
	{
		ulong totalBytes = 0UL;

		DriveInfo[] drives = DriveInfo.GetDrives();
		int count = drives.Length;
		for (int i = 0; i < count; i++)
		{
			DriveInfo drive = drives[i];

			// Only count fixed, ready volumes
			if (drive.DriveType == DriveType.Fixed && drive.IsReady)
			{
				long size = drive.TotalSize;
				if (size > 0)
				{
					totalBytes += (ulong)size;
				}
			}
		}

		return totalBytes == 0UL ? "0" : ByteToString(totalBytes);
	}

	// Cached interface index for the best route to the internet.
	private uint _netIfIndex;

	// 64-bit previous counters and timestamp to compute deltas.
	private ulong _prevInBytes;
	private ulong _prevOutBytes;
	private long _prevSampleTicks;

	/// <summary>
	/// Initializes and starts the internet speed (throughput) updater.
	/// Picks the interface Windows routes to 8.8.8.8 and computes bps from 64-bit octet deltas.
	/// </summary>
	private void InitializeInternetSpeedUpdater()
	{
		// Resolve the interface once at start; re-resolved automatically if needed later.
		_netIfIndex = ResolveBestInterfaceIndex();

		_prevInBytes = 0UL;
		_prevOutBytes = 0UL;
		_prevSampleTicks = 0;

		// Take an initial baseline sample (shows zeros first, as there's no prior delta yet).
		UpdateInternetSpeed(first: true);
	}

	/// <summary>
	/// Samples interface counters and updates InternetSpeedText as "X.X Mbps ↓ / Y.Y Mbps ↑".
	/// Uses 64-bit byte counters to avoid 32-bit wrap issues on high-speed links.
	/// Handles adapter changes and resets gracefully.
	/// </summary>
	private void UpdateInternetSpeed(bool first)
	{
		// If we do not have a valid interface index, try to resolve again.
		if (_netIfIndex == 0)
		{
			_netIfIndex = ResolveBestInterfaceIndex();

			if (_netIfIndex == 0)
			{
				InternetSpeedText = "0.0 Mbps ↓ / 0.0 Mbps ↑";
				InternetTotalText = "Total: 0 B ↓ / 0 B ↑";
				return;
			}
		}

		MIB_IF_ROW2 row = default;
		row.InterfaceIndex = _netIfIndex;

		uint result = NativeMethods.GetIfEntry2(ref row);

		// If call failed (like interface removed), try to re-resolve once.
		if (result != 0)
		{
			_netIfIndex = ResolveBestInterfaceIndex();
			if (_netIfIndex != 0)
			{
				row = default;
				row.InterfaceIndex = _netIfIndex;
				result = NativeMethods.GetIfEntry2(ref row);
			}
		}

		if (result != 0)
		{
			// Still failed
			InternetSpeedText = "0.0 Mbps ↓ / 0.0 Mbps ↑";
			InternetTotalText = "Total: 0 B ↓ / 0 B ↑";
			return;
		}

		long nowTicks = Environment.TickCount64;

		// First sample just seeds the baseline (no delta yet).
		if (first || _prevSampleTicks == 0)
		{
			_prevInBytes = row.InOctets;
			_prevOutBytes = row.OutOctets;
			_prevSampleTicks = nowTicks;
			InternetSpeedText = "0.0 Mbps ↓ / 0.0 Mbps ↑";
			InternetTotalText = "Total: " + FormatDataSize(_prevInBytes) + " ↓ / " + FormatDataSize(_prevOutBytes) + " ↑";
			return;
		}

		double elapsedSec = (nowTicks - _prevSampleTicks) / 1000.0;
		if (elapsedSec <= 0)
		{
			return;
		}

		ulong curIn = row.InOctets;
		ulong curOut = row.OutOctets;

		// Handle adapter reset (counters dropped), which manifests as a decreasing value even for 64-bit counters.
		if (curIn < _prevInBytes || curOut < _prevOutBytes)
		{
			_prevInBytes = curIn;
			_prevOutBytes = curOut;
			_prevSampleTicks = nowTicks;
			InternetSpeedText = "0.0 Mbps ↓ / 0.0 Mbps ↑";
			InternetTotalText = "Total: " + FormatDataSize(_prevInBytes) + " ↓ / " + FormatDataSize(_prevOutBytes) + " ↑";
			return;
		}

		ulong deltaIn = curIn - _prevInBytes;
		ulong deltaOut = curOut - _prevOutBytes;

		// Bytes/sec -> bits/sec, then format to human-readable Mbps/Gbps with one decimal.
		double bpsDown = deltaIn * 8.0 / elapsedSec;
		double bpsUp = deltaOut * 8.0 / elapsedSec;

		_prevInBytes = curIn;
		_prevOutBytes = curOut;
		_prevSampleTicks = nowTicks;

		InternetSpeedText = FormatBitrate(bpsDown) + " ↓ / " + FormatBitrate(bpsUp) + " ↑";
		InternetTotalText = "Total: " + FormatDataSize(curIn) + " ↓ / " + FormatDataSize(curOut) + " ↑";
	}

	/// <summary>
	/// Returns the Windows-selected interface index for reaching 8.8.8.8 (IPv4).
	/// </summary>
	private static uint ResolveBestInterfaceIndex()
	{
		// 8.8.8.8 in network byte order as a 32-bit IPv4 address: 0x08 0x08 0x08 0x08
		const uint destAddrNetworkOrder = (8 << 24) | (8 << 16) | (8 << 8) | 8;
		uint status = NativeMethods.GetBestInterface(destAddrNetworkOrder, out uint index);
		return status == 0 ? index : 0U; // 0 = NO_ERROR
	}

	/// <summary>
	/// Formats bits-per-second as "X.X Kbps/Mbps/Gbps" with one decimal.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
	private static string FormatBitrate(double bps)
	{
		const double Kbps = 1000.0;
		const double Mbps = 1000.0 * 1000.0;
		const double Gbps = 1000.0 * 1000.0 * 1000.0;

		if (bps >= Gbps)
		{
			double val = bps / Gbps;
			return val.ToString("0.0", CultureInfo.InvariantCulture) + " Gbps";
		}
		else if (bps >= Mbps)
		{
			double val = bps / Mbps;
			return val.ToString("0.0", CultureInfo.InvariantCulture) + " Mbps";
		}
		else
		{
			double val = bps / Kbps;
			return val.ToString("0.0", CultureInfo.InvariantCulture) + " Kbps";
		}
	}

	/// <summary>
	/// Formats a cumulative byte counter using binary units (KiB, MiB, GiB, TiB) collapsed to KB/MB/GB/TB labels,
	/// with one decimal precision.
	/// For values below 1 KB it shows raw bytes without decimal.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
	private static string FormatDataSize(ulong bytes)
	{
		const double OneKB = 1024.0;
		const double OneMB = OneKB * 1024.0;
		const double OneGB = OneMB * 1024.0;
		const double OneTB = OneGB * 1024.0;

		if (bytes >= (ulong)OneTB)
		{
			double val = bytes / OneTB;
			return val.ToString("0.0", CultureInfo.InvariantCulture) + " TB";
		}
		else if (bytes >= (ulong)OneGB)
		{
			double val = bytes / OneGB;
			return val.ToString("0.0", CultureInfo.InvariantCulture) + " GB";
		}
		else if (bytes >= (ulong)OneMB)
		{
			double val = bytes / OneMB;
			return val.ToString("0.0", CultureInfo.InvariantCulture) + " MB";
		}
		else if (bytes >= (ulong)OneKB)
		{
			double val = bytes / OneKB;
			return val.ToString("0.0", CultureInfo.InvariantCulture) + " KB";
		}
		else
		{
			// Show raw bytes for very small totals
			return bytes.ToString(CultureInfo.InvariantCulture) + " B";
		}
	}

	#region Defender Feed Fields

	internal string? EngineVersionText { get; private set => SP(ref field, value); } = "Antimalware engine version: Unavailable";
	internal string? SignatureVersionText { get; private set => SP(ref field, value); } = "Antivirus definition version: Unavailable";
	internal string? PlatformVersionText { get; private set => SP(ref field, value); } = "Platform version: Unavailable";
	internal string? SignatureUpdateDateText { get; private set => SP(ref field, value); } = "Definition update time: Unavailable";

	private static readonly Uri OnlineMSDefenderStatusURL = new("https://definitionupdates.microsoft.com/packages?action=info");

	private async Task RefreshDefenderFeedAsync(CancellationToken cancellationToken = default)
	{
		// Defaults for failure cases
		string engine = "Unavailable";
		string signatures = "Unavailable";
		string platform = "Unavailable";
		string dateText = "Unavailable";

		try
		{
			// Download XML
			string xml = await SecHttpClient.Instance.GetStringAsync(OnlineMSDefenderStatusURL, cancellationToken)
										 .ConfigureAwait(false);

			// Parse
			XDocument doc = XDocument.Parse(xml, LoadOptions.PreserveWhitespace | LoadOptions.SetLineInfo);
			XElement root = doc.Root!;
			if (root != null && string.Equals(root.Name.LocalName, "versions", StringComparison.OrdinalIgnoreCase))
			{
				string engineVal = root.Element(XName.Get("engine"))?.Value?.Trim() ?? string.Empty;
				string platformVal = root.Element(XName.Get("platform"))?.Value?.Trim() ?? string.Empty;

				XElement? sigEl = root.Element(XName.Get("signatures"));
				string signaturesVal = sigEl?.Value?.Trim() ?? string.Empty;
				string? dateAttr = sigEl?.Attribute(XName.Get("date"))?.Value;

				// Assign parsed or fallback
				engine = string.IsNullOrWhiteSpace(engineVal) ? "Unavailable" : engineVal;
				platform = string.IsNullOrWhiteSpace(platformVal) ? "Unavailable" : platformVal;
				signatures = string.IsNullOrWhiteSpace(signaturesVal) ? "Unavailable" : signaturesVal;

				if (!string.IsNullOrWhiteSpace(dateAttr))
				{
					// The feed gives "YYYY-MM-DD HH:MM:SSZ"
					if (DateTimeOffset.TryParse(dateAttr, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset dto))
					{
						// Keep UTC and format compactly
						dateText = dto.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
					}
				}
			}
		}
		catch
		{
			// Network/parse failures fall back to "Unavailable" texts
		}

		EngineVersionText = $"Antimalware engine version: {engine}";
		SignatureVersionText = $"Antivirus definition version: {signatures}";
		PlatformVersionText = $"Platform version: {platform}";
		SignatureUpdateDateText = $"Definition update time: {dateText}";
	}

	#endregion


	#region CPU

	private static unsafe string GetCpuDetailsString()
	{
		string brand = "Unknown CPU";
		try
		{
			object? value = Registry.GetValue(@"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString", null);
			if (value is string s && !string.IsNullOrWhiteSpace(s))
			{
				brand = s.Trim();
			}
		}
		catch
		{ }

		// Base clock
		string baseClock = "Base Clock N/A";
		try
		{
			object? mhzObj = Registry.GetValue(@"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0", "~MHz", null);
			if (mhzObj is int mhz && mhz > 0)
			{
				double ghz = mhz / 1000.0;
				baseClock = ghz.ToString("0.##", CultureInfo.InvariantCulture) + " GHz";
			}
		}
		catch
		{ }

		string archText = RuntimeInformation.ProcessArchitecture.ToString();
		int logicalThreads = Environment.ProcessorCount;
		int physicalCores = 0;
		int packageCount = 0;
		ulong largestCacheBytes = 0UL;

		// Topology enumeration
		try
		{
			int len = 0;
			bool firstOk = NativeMethods.GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP.RelationAll, IntPtr.Zero, ref len);
			int firstErr = Marshal.GetLastPInvokeError();
			if (!firstOk && firstErr == 122 && len > 0) // ERROR_INSUFFICIENT_BUFFER
			{
				IntPtr buffer = Marshal.AllocHGlobal(len);
				try
				{
					if (NativeMethods.GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP.RelationAll, buffer, ref len))
					{
						int offset = 0;
						while (offset < len)
						{
							int relationship = Marshal.ReadInt32(buffer, offset);
							int size = Marshal.ReadInt32(buffer, offset + 4);
							if (size <= 8 || offset + size > len)
							{
								break;
							}

							int dataOffset = offset + 8;
							if (dataOffset < 0 || dataOffset > len)
								break;

							IntPtr dataPtr = IntPtr.Add(buffer, dataOffset);
							switch (relationship)
							{
								case (int)LOGICAL_PROCESSOR_RELATIONSHIP.RelationProcessorCore:
									physicalCores++;
									break;
								case (int)LOGICAL_PROCESSOR_RELATIONSHIP.RelationProcessorPackage:
									packageCount++;
									break;
								case (int)LOGICAL_PROCESSOR_RELATIONSHIP.RelationCache:
									CACHE_RELATIONSHIP cacheRel = *(CACHE_RELATIONSHIP*)dataPtr;
									ulong cacheSize = cacheRel.CacheSize;
									if (cacheSize > largestCacheBytes)
									{
										largestCacheBytes = cacheSize;
									}
									break;
								default:
									break;
							}

							offset += size;
						}
					}
				}
				catch
				{ }
				finally
				{
					Marshal.FreeHGlobal(buffer);
				}
			}
		}
		catch
		{ }

		string cachePart = largestCacheBytes > 0UL ? FormatCache(largestCacheBytes) : "Cache N/A";

		StringBuilder sb = new(96);
		_ = sb.Append(brand);
		_ = sb.Append(" - ");
		_ = sb.Append(physicalCores.ToString(CultureInfo.InvariantCulture));
		_ = sb.Append(" Core / ");
		_ = sb.Append(logicalThreads.ToString(CultureInfo.InvariantCulture));
		_ = sb.Append(" Thread - ");
		_ = sb.Append(archText);
		_ = sb.Append(" - ");
		_ = sb.Append(baseClock);
		_ = sb.Append(" - ");
		_ = sb.Append(cachePart);
		_ = sb.Append(" - ");
		_ = sb.Append(packageCount.ToString(CultureInfo.InvariantCulture));
		_ = sb.Append(" Socket");

		return sb.ToString();
	}

	/// <summary>
	/// Formats bytes as MB or GB with one decimal, labeling as L3 if sufficiently large.
	/// </summary>
	private static string FormatCache(ulong bytes)
	{
		double mb = bytes / 1024.0 / 1024.0;
		string sizeText;
		if (mb >= 1024.0)
		{
			double gb = mb / 1024.0;
			sizeText = gb.ToString("0.#", CultureInfo.InvariantCulture) + " GB";
		}
		else
		{
			sizeText = mb.ToString("0.#", CultureInfo.InvariantCulture) + " MB";
		}

		return sizeText + " L3 Cache";
	}

	#endregion

	#region Extended RAM

	private static string GetPhysicalMemoryExtendedString()
	{
		string sizeText = GetAvailablePhysicalMemoryBytes();
		string? genSpeed = TryGetMemoryGenerationAndSpeed();
		if (string.IsNullOrEmpty(genSpeed))
		{
			return sizeText;
		}
		return sizeText + " - " + genSpeed;
	}

	/// <summary>
	/// Parses the SMBIOS (Type 17) structure to find the configured memory speed and generation.
	/// Returns the maximum configured speed found (e.g. "DDR4 3200 MT/s").
	/// Sources of truth: 7.18 Memory Device (Type 17) in the following PDF spec:
	/// https://www.dmtf.org/dsp/DSP0134
	/// https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.9.0.pdf
	/// </summary>
	private static string? TryGetMemoryGenerationAndSpeed()
	{
		try
		{
			const uint ProviderRSMB = 0x52534D42; // 'RSMB' (Raw SMBIOS)
			uint tableSize = NativeMethods.GetSystemFirmwareTable(ProviderRSMB, 0, IntPtr.Zero, 0);
			if (tableSize == 0 || tableSize > 1_000_000U)
			{
				return null;
			}

			IntPtr buffer = Marshal.AllocHGlobal((int)tableSize);
			try
			{
				uint read = NativeMethods.GetSystemFirmwareTable(ProviderRSMB, 0, buffer, tableSize);
				if (read != tableSize || tableSize < 8)
				{
					return null;
				}

				// Raw SMBIOS header: first 8 bytes.
				// DWORD at offset 4 is table data length.
				// BYTE at offset 1 is Major Version, BYTE at offset 2 is Minor Version.
				uint smbiosDataLength = (uint)Marshal.ReadInt32(buffer, 4);
				int headerSize = 8;
				uint expectedEnd = (uint)headerSize + smbiosDataLength;
				if (expectedEnd > tableSize)
				{
					// Clamp if firmware reports inconsistent size.
					smbiosDataLength = tableSize - (uint)headerSize;
					expectedEnd = (uint)headerSize + smbiosDataLength;
				}

				int pos = headerSize;
				int max = (int)expectedEnd;

				// We'll collect the chosen speed for each populated slot, then pick the max.
				List<uint> chosenSpeeds = new(8);
				int detectedMemoryType = 0; // 0 = Unknown

				// Type 17 (Memory Device) field offsets (Decimal):
				const int OffsetMemoryType = 18; // (0x12): Memory Type (BYTE)
				const int OffsetSpeed = 21; // (0x15): Speed (WORD)
				const int OffsetConfiguredSpeed = 32; // (0x20): Configured Memory Clock Speed (WORD)
				const int OffsetExtendedSpeed = 57; // (0x39): Extended Speed (DWORD) - SMBIOS 3.3+
				const int OffsetExtendedConfiguredSpeed = 61; // (0x3D): Extended Configured Memory Speed (DWORD) - SMBIOS 3.3+

				while (pos + 4 <= max)
				{
					byte structureType = Marshal.ReadByte(buffer, pos);
					byte length = Marshal.ReadByte(buffer, pos + 1);

					if (length < 4 || pos + length > max)
					{
						break;
					}

					if (structureType == 17)
					{
						ushort baseSpeed = 0;
						ushort configuredSpeed = 0;
						uint extendedSpeed = 0;
						uint extendedConfiguredSpeed = 0;
						byte currentType = 0;

						// 0. Memory Type (Offset 18)
						// We need length >= 19 to read byte at offset 18 safely
						if (length >= OffsetMemoryType + 1)
						{
							currentType = Marshal.ReadByte(buffer, pos + OffsetMemoryType);
						}

						// 1. Speed (Offset 21)
						if (length >= OffsetSpeed + 2)
						{
							baseSpeed = (ushort)Marshal.ReadInt16(buffer, pos + OffsetSpeed);
						}

						// 2. Configured Clock Speed (Offset 32)
						if (length >= OffsetConfiguredSpeed + 2)
						{
							configuredSpeed = (ushort)Marshal.ReadInt16(buffer, pos + OffsetConfiguredSpeed);
						}

						// 3. Extended Speed (Offset 57) - DWORD
						if (length >= OffsetExtendedSpeed + 4)
						{
							extendedSpeed = (uint)Marshal.ReadInt32(buffer, pos + OffsetExtendedSpeed);
						}

						// 4. Extended Configured Speed (Offset 61) - DWORD
						if (length >= OffsetExtendedConfiguredSpeed + 4)
						{
							extendedConfiguredSpeed = (uint)Marshal.ReadInt32(buffer, pos + OffsetExtendedConfiguredSpeed);
						}

						// Logic to determine actual speed for this stick:
						// "0" usually means unknown.
						// "0xFFFF" means the value is too large for WORD and resides in the Extended field.
						uint selected = 0;

						// Priority 1: Extended Configured Speed (if ConfiguredSpeed == 0xFFFF)
						if (configuredSpeed == 0xFFFF && extendedConfiguredSpeed != 0)
						{
							selected = extendedConfiguredSpeed;
						}
						// Priority 2: Standard Configured Speed
						else if (configuredSpeed != 0 && configuredSpeed != 0xFFFF)
						{
							selected = configuredSpeed;
						}
						// Priority 3: Extended Speed (if BaseSpeed == 0xFFFF)
						else if (baseSpeed == 0xFFFF && extendedSpeed != 0)
						{
							selected = extendedSpeed;
						}
						// Priority 4: Standard Base Speed
						else if (baseSpeed != 0 && baseSpeed != 0xFFFF)
						{
							selected = baseSpeed;
						}

						// Filter out plausible garbage or "Unknown" (0)
						// MT/s is typically >= 300 for DDR1 and up to ~10000+ for future DDR5/6.
						if (selected >= 300 && selected <= 30000)
						{
							chosenSpeeds.Add(selected);

							// If we found a valid speed, capture the memory type of this stick.
							// We prefer a known type (e.g. DDR4/5) over unknown.
							if (currentType > 0 && detectedMemoryType == 0)
							{
								detectedMemoryType = currentType;
							}
							else if (currentType > detectedMemoryType)
							{
								// Heuristic: if we have mixed types (unlikely), pick the "newer" one (higher value typically)
								// or just stick to the first found.
								detectedMemoryType = currentType;
							}
						}
					}

					// Advance to next structure.
					// Structures are double-null terminated (formatted section + string set).
					int stringStart = pos + length;
					int scan = stringStart;
					while (scan < max - 1)
					{
						byte b0 = Marshal.ReadByte(buffer, scan);
						byte b1 = Marshal.ReadByte(buffer, scan + 1);
						if (b0 == 0 && b1 == 0)
						{
							scan += 2; // Skip the two nulls
							break;
						}
						scan++;
					}

					// Safely advance 'pos'. If 'scan' didn't move or went out of bounds, force break.
					if (scan <= pos || scan > max)
					{
						break;
					}
					pos = scan;
				}

				if (chosenSpeeds.Count == 0)
				{
					return null;
				}

				// Return the maximum speed found among all populated slots.
				uint maxSpeed = 0;
				foreach (uint val in chosenSpeeds)
				{
					if (val > maxSpeed)
					{
						maxSpeed = val;
					}
				}

				string typeString = detectedMemoryType switch
				{
					0x18 => "DDR3",
					0x1A => "DDR4",
					0x1B => "LPDDR3",
					0x1C => "LPDDR4",
					0x22 => "DDR5",
					0x23 => "LPDDR5",
					_ => string.Empty
				};

				string speedString = maxSpeed.ToString(CultureInfo.InvariantCulture) + " MT/s";

				if (!string.IsNullOrEmpty(typeString))
				{
					return $"{typeString} {speedString}";
				}

				return speedString;
			}
			finally
			{
				Marshal.FreeHGlobal(buffer);
			}
		}
		catch
		{
			return null;
		}
	}

	#endregion

	#region OS Info

	/// <summary>
	/// Retrieves OS details such as Name, Edition, Display Version, and Build Number.
	/// </summary>
	/// <returns></returns>
	private static string GetOsDetailsString()
	{
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
			if (key is null)
			{
				return "Unknown OS";
			}

			string installationType = key.GetValue("InstallationType") as string ?? "Client";
			string currentBuild = key.GetValue("CurrentBuild") as string ?? "0";

			if (installationType.Contains("Server", StringComparison.OrdinalIgnoreCase))
			{
				string productName = key.GetValue("ProductName") as string ?? "Windows Server";
				return $"{productName} - Build {currentBuild}";
			}
			else
			{
				string editionId = key.GetValue("EditionID") as string ?? "Unknown";
				string displayVersion = key.GetValue("DisplayVersion") as string ?? "Unknown";
				return $"Microsoft Windows - {editionId} - Version {displayVersion} - Build {currentBuild}";
			}
		}
		catch
		{
			return "Unknown OS";
		}
	}

	/// <summary>
	/// Retrieves the System Manufacturer and Product Name (Model).
	/// </summary>
	private static string GetSystemModelInfoString()
	{
		string manufacturer = "Unknown Manufacturer";
		string model = "Unknown Model";

		try
		{
			const string keyName = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemInformation";

			object? manVal = Registry.GetValue(keyName, "SystemManufacturer", null);
			if (manVal is string sMan && !string.IsNullOrWhiteSpace(sMan))
			{
				manufacturer = sMan;
			}

			object? modVal = Registry.GetValue(keyName, "SystemProductName", null);
			if (modVal is string sMod && !string.IsNullOrWhiteSpace(sMod))
			{
				model = sMod;
			}
		}
		catch { }

		return $"{manufacturer} - {model}";
	}

	#endregion

	#region Open Ports

	private static string GetOpenPortsString()
	{
		try
		{
			IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
			// Get Active TCP Listeners
			int tcpCount = properties.GetActiveTcpListeners().Length;
			// Get Active UDP Listeners
			int udpCount = properties.GetActiveUdpListeners().Length;

			return $"TCP: {tcpCount} - UDP: {udpCount}";
		}
		catch
		{
			return "TCP: 0 - UDP: 0";
		}
	}

	#endregion

	#region GPU

	/// <summary>
	/// Retrieves a formatted string of available GPU names.
	/// </summary>
	/// <returns></returns>
	private static string GetGpuNamesString()
	{
		List<GpuInfo> gpus = GPUInfoManager.GetSystemGPUs();
		return gpus.Count > 0 ? string.Join(" - ", gpus.Select(g => g.Name)) : "Unavailable";
	}

	#endregion

	/// <summary>
	/// Handler for the Computer Name button click event.
	/// Opens a dialog to allow the user to rename the computer.
	/// </summary>
	internal async void OnComputerNameClick(object sender, RoutedEventArgs e)
	{
		try
		{
			if (!Environment.IsPrivilegedProcess)
			{
				using ContentDialogV2 errorDialog = new()
				{
					Title = GlobalVars.GetStr("AppElevationNoticeTitle"),
					Content = GlobalVars.GetStr("NeedAdminToRenamePCMsg"),
					CloseButtonText = GlobalVars.GetStr("OK"),
					DefaultButton = ContentDialogButton.Close
				};
				_ = await errorDialog.ShowAsync();
				return;
			}

			// The input dialog
			TextBox nameInput = new()
			{
				Header = GlobalVars.GetStr("NewComputerName"),
				PlaceholderText = GlobalVars.GetStr("EnterNewName"),
				Text = ComputerNameText ?? string.Empty,
				HorizontalAlignment = HorizontalAlignment.Stretch
			};

			StackPanel contentPanel = new()
			{
				Spacing = 10,
				Children =
			{
				new TextBlock {
					Text = GlobalVars.GetStr("EnterANameForThisPCMsg"),
					TextWrapping = TextWrapping.Wrap
				},
				nameInput
			}
			};

			using ContentDialogV2 renameDialog = new()
			{
				Title = GlobalVars.GetStr("RenameComputer"),
				Content = contentPanel,
				PrimaryButtonText = GlobalVars.GetStr("Rename"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Primary
			};

			ContentDialogResult result = await renameDialog.ShowAsync();

			if (result == ContentDialogResult.Primary)
			{
				string newName = nameInput.Text.Trim();

				if (string.IsNullOrWhiteSpace(newName))
				{
					return;
				}

				// Set the computer name
				bool success = NativeMethods.SetComputerNameExW(
					COMPUTER_NAME_FORMAT.ComputerNamePhysicalDnsHostname,
					newName);

				if (success)
				{
					using ContentDialogV2 successDialog = new()
					{
						Title = GlobalVars.GetStr("SuccessText"),
						Content = string.Format(GlobalVars.GetStr("SuccessfullyRenamedPCTo"), newName),
						CloseButtonText = GlobalVars.GetStr("OK"),
						DefaultButton = ContentDialogButton.Close
					};
					_ = await successDialog.ShowAsync();
				}
				else
				{
					int errorCode = Marshal.GetLastPInvokeError();
					using ContentDialogV2 failDialog = new()
					{
						Title = GlobalVars.GetStr("ErrorTitle"),
						Content = string.Format(GlobalVars.GetStr("FailedToRenamePCError"), errorCode),
						CloseButtonText = GlobalVars.GetStr("OK"),
						DefaultButton = ContentDialogButton.Close
					};
					_ = await failDialog.ShowAsync();
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Handler for the GPU button click event.
	/// Opens a dialog to allow the user to see detailed GPU information.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal async void OnGpuClick(object sender, RoutedEventArgs e)
	{
		try
		{
			List<GpuInfo> gpus = GPUInfoManager.GetSystemGPUs();

			StackPanel contentPanel = new()
			{
				Spacing = 16,
				Padding = new Thickness(10, 0, 16, 0)
			};

			if (gpus.Count == 0)
			{
				contentPanel.Children.Add(new TextBlock { Text = "No GPU information detected." });
			}
			else
			{
				foreach (GpuInfo gpu in gpus)
				{
					// Group for one GPU
					StackPanel gpuGroup = new() { Spacing = 6 };

					// Title
					gpuGroup.Children.Add(new TextBlock
					{
						Text = gpu.Name,
						FontSize = 18,
						FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
						TextWrapping = TextWrapping.Wrap
					});

					// Details
					gpuGroup.Children.Add(CreateGpuDetailRow("Brand", gpu.Brand));
					gpuGroup.Children.Add(CreateGpuDetailRow("Manufacturer", gpu.Manufacturer));
					gpuGroup.Children.Add(CreateGpuDetailRow("Description", gpu.Description));
					gpuGroup.Children.Add(CreateGpuDetailRow("Device ID", $"0x{gpu.DeviceId:X}"));
					gpuGroup.Children.Add(CreateGpuDetailRow("Vendor ID", $"0x{gpu.VendorId:X}"));
					gpuGroup.Children.Add(CreateGpuDetailRow("Driver Version", gpu.DriverVersion));
					gpuGroup.Children.Add(CreateGpuDetailRow("Driver Date", FormatWmiDate(gpu.DriverDate)));
					gpuGroup.Children.Add(CreateGpuDetailRow("PNP Device ID", gpu.PnpDeviceId));

					if (gpu.ErrorCode != 0)
					{
						gpuGroup.Children.Add(CreateGpuDetailRow("Error Code", gpu.ErrorCode.ToString(CultureInfo.InvariantCulture)));
						gpuGroup.Children.Add(CreateGpuDetailRow("Error Message", gpu.ErrorMessage));
					}

					contentPanel.Children.Add(gpuGroup);

					// Separator between GPUs
					if (gpus.IndexOf(gpu) < gpus.Count - 1)
					{
						contentPanel.Children.Add(new MenuFlyoutSeparator());
					}
				}
			}

			// ScrollViewer for the content
			ScrollViewer scrollViewer = new()
			{
				Content = contentPanel,
				VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
				HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
			};

			using ContentDialogV2 gpuDialog = new()
			{
				Title = GlobalVars.GetStr("GPUDetails"),
				Content = scrollViewer,
				CloseButtonText = GlobalVars.GetStr("OK"),
				DefaultButton = ContentDialogButton.Close
			};

			_ = await gpuDialog.ShowAsync();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Helper to create a TextBlock with a bold Label and normal Value.
	/// </summary>
	private static TextBlock CreateGpuDetailRow(string label, string value)
	{
		TextBlock tb = new()
		{
			TextWrapping = TextWrapping.Wrap,
			IsTextSelectionEnabled = true
		};
		tb.Inlines.Add(new Microsoft.UI.Xaml.Documents.Run { Text = label + ": ", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
		tb.Inlines.Add(new Microsoft.UI.Xaml.Documents.Run { Text = string.IsNullOrEmpty(value) ? "N/A" : value });
		return tb;
	}

	/// <summary>
	/// Handler for the Activation button click event.
	/// Opens a dialog to allow the user to see detailed Windows Activation information.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal async void OnActivationInfoClick(object sender, RoutedEventArgs e)
	{
		try
		{
			List<WindowsActivationStatus> statuses = GetOSActivationStates.Get();

			StackPanel contentPanel = new()
			{
				Spacing = 16,
				Padding = new Thickness(10, 0, 16, 0)
			};

			if (statuses.Count == 0)
			{
				contentPanel.Children.Add(new TextBlock { Text = "No activation information available." });
			}
			else
			{
				foreach (WindowsActivationStatus status in statuses)
				{
					// Group for one Status entry
					StackPanel statusGroup = new() { Spacing = 6 };

					// Title
					statusGroup.Children.Add(new TextBlock
					{
						Text = status.Name ?? "Unknown Product",
						FontSize = 18,
						FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
						TextWrapping = TextWrapping.Wrap
					});

					// Details
					statusGroup.Children.Add(CreateActivationDetailRow("Description", status.Description));
					statusGroup.Children.Add(CreateActivationDetailRow("Activation ID", status.ActivationId.ToString()));
					statusGroup.Children.Add(CreateActivationDetailRow("Extended PID", status.ExtendedPid));
					statusGroup.Children.Add(CreateActivationDetailRow("Product Key Channel", status.ProductKeyChannel));
					statusGroup.Children.Add(CreateActivationDetailRow("Partial Product Key", status.PartialProductKey));
					statusGroup.Children.Add(CreateActivationDetailRow("License Status", status.LicenseStatusString));
					statusGroup.Children.Add(CreateActivationDetailRow("Status Code", status.Status.ToString(CultureInfo.InvariantCulture)));
					statusGroup.Children.Add(CreateActivationDetailRow("Grace Time", $"{status.GraceTime} minutes"));
					statusGroup.Children.Add(CreateActivationDetailRow("Reason Code", $"0x{status.Reason:X}"));
					statusGroup.Children.Add(CreateActivationDetailRow("Validity Expiration", status.Validity.ToString(CultureInfo.InvariantCulture)));
					statusGroup.Children.Add(CreateActivationDetailRow("Genuine Status", status.ClcGenuineStatus));
					statusGroup.Children.Add(CreateActivationDetailRow("Digital License", status.ClcIsDigitalLicense ? "Yes" : "No"));
					statusGroup.Children.Add(CreateActivationDetailRow("Last Activation Time", status.ClcLastActivationTime));
					statusGroup.Children.Add(CreateActivationDetailRow("Last Activation HResult", status.ClcHResult));

					if (!string.IsNullOrWhiteSpace(status.ExpirationMsg))
					{
						statusGroup.Children.Add(CreateActivationDetailRow("Expiration Info", status.ExpirationMsg));
					}

					statusGroup.Children.Add(CreateActivationDetailRow("Is Subscription Supported", status.EdittionSupportsSubscription.ToString()));

					if (status.EdittionSupportsSubscription)
					{
						statusGroup.Children.Add(CreateActivationDetailRow("Subscription Enabled", status.IsSubscriptionEnabled ? "Yes" : "No"));
						if (status.IsSubscriptionEnabled)
						{
							statusGroup.Children.Add(CreateActivationDetailRow("Subscription SKU", status.SubscriptionSku));
							statusGroup.Children.Add(CreateActivationDetailRow("Subscription State", status.SubscriptionState));
						}
					}

					if (!string.IsNullOrWhiteSpace(status.ClcStateData))
					{
						statusGroup.Children.Add(CreateActivationDetailRow("State Data", status.ClcStateData));
					}

					contentPanel.Children.Add(statusGroup);

					// Separator between entries
					if (statuses.IndexOf(status) < statuses.Count - 1)
					{
						contentPanel.Children.Add(new MenuFlyoutSeparator());
					}
				}
			}

			// ScrollViewer for the content
			ScrollViewer scrollViewer = new()
			{
				Content = contentPanel,
				VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
				HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
			};

			using ContentDialogV2 actDialog = new()
			{
				Title = "Activation Details",
				Content = scrollViewer,
				CloseButtonText = GlobalVars.GetStr("OK"),
				DefaultButton = ContentDialogButton.Close
			};

			_ = await actDialog.ShowAsync();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Helper to create a TextBlock for activation details.
	/// </summary>
	private static TextBlock CreateActivationDetailRow(string label, string? value)
	{
		TextBlock tb = new()
		{
			TextWrapping = TextWrapping.Wrap,
			IsTextSelectionEnabled = true
		};
		tb.Inlines.Add(new Microsoft.UI.Xaml.Documents.Run { Text = label + ": ", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
		tb.Inlines.Add(new Microsoft.UI.Xaml.Documents.Run { Text = string.IsNullOrEmpty(value) ? "N/A" : value });
		return tb;
	}


	/// <summary>
	/// Formats the WMI date string (yyyyMMdd...) into a user-friendly date format.
	/// </summary>
	/// <param name="wmiDate">The raw WMI date string.</param>
	/// <returns>Formatted date string or original if parsing fails.</returns>
	private static string FormatWmiDate(string wmiDate)
	{
		// Valid WMI date starts with 4 digit year, 2 digit month, 2 digit day
		// We only need the first 8 characters for the date.
		if (!string.IsNullOrWhiteSpace(wmiDate) && wmiDate.Length >= 8)
		{
			// Try to parse the yyyyMMdd part
			if (DateTime.TryParseExact(wmiDate.AsSpan(0, 8), "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime dt))
			{
				// Return in Long Date pattern
				return dt.ToString("D", CultureInfo.CurrentCulture);
			}
		}

		return wmiDate;
	}

	#region Windows Activation and Licensing Info

	/// <summary>
	/// Class that holds activation data such as SKU-specific Status and Global Client Licensing Data
	/// </summary>
	internal sealed class WindowsActivationStatus(
		string? name,
		string? description,
		Guid activationId,
		string? extendedPid,
		string? productKeyChannel,
		string? partialProductKey,
		int status,
		int graceTime,
		int reason,
		long validity,
		string? clcStateData,
		string? clcHResult,
		string? clcLastActivationTime,
		string? clcGenuineStatus,
		bool clcIsDigitalLicense,
		bool edittionSupportsSubscription,
		bool isSubscriptionEnabled,
		string? subscriptionSku,
		string? subscriptionState,
		string? expirationMsg
		)
	{
		internal string? Name => name;
		internal string? Description => description;
		internal Guid ActivationId => activationId;
		internal string? ExtendedPid => extendedPid;
		internal string? ProductKeyChannel => productKeyChannel;
		internal string? PartialProductKey => partialProductKey;
		internal int Status => status;
		internal int GraceTime => graceTime;
		internal int Reason => reason;
		internal long Validity => validity;
		internal string? ClcStateData => clcStateData;
		internal string? ClcHResult => clcHResult;
		internal string? ClcLastActivationTime => clcLastActivationTime;
		internal string? ClcGenuineStatus => clcGenuineStatus;
		internal bool ClcIsDigitalLicense => clcIsDigitalLicense;
		internal bool EdittionSupportsSubscription => edittionSupportsSubscription;
		internal bool IsSubscriptionEnabled => isSubscriptionEnabled;
		internal string? SubscriptionSku => subscriptionSku;
		internal string? SubscriptionState => subscriptionState;
		internal string? ExpirationMsg => expirationMsg;

		/// <summary>
		/// https://learn.microsoft.com/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct
		/// </summary>
		internal string LicenseStatusString => Status switch
		{
			0 => "Unlicensed",
			1 => "Licensed",
			2 => "OOBGrace (Out-of-Box grace period)",
			3 => "OOTGrace (Out-of-Tolerance grace period)",
			4 => "NonGenuineGrace (Non-genuine grace period)",
			5 => "Notification",
			6 => "ExtendedGrace (Extended grace period)",
			_ => "Unknown"
		};
	}

	internal static class GetOSActivationStates
	{
		/// <summary>
		/// https://github.com/MicrosoftDocs/SupportArticles-docs/blob/main/support/windows-client/licensing-and-activation/activation-failures-not-genuine-notifications-volume-licensed-kms-client.md
		/// </summary>
		private static readonly Guid WindowsAppId = new("55c92734-d682-4d71-983e-d6ec3f16059f");

		// https://learn.microsoft.com/windows/win32/api/slpublic/ne-slpublic-sl_genuine_state
		private const int SL_GEN_STATE_IS_GENUINE = 0;
		private const int SL_GEN_STATE_INVALID_LICENSE = 1;
		private const int SL_GEN_STATE_TAMPERED = 2;
		private const int SL_GEN_STATE_OFFLINE = 3;
		private const int SL_GEN_STATE_LAST = 4;

		internal static List<WindowsActivationStatus> Get()
		{
			IntPtr hSLC = IntPtr.Zero;
			int result = NativeMethods.SLOpen(ref hSLC);

			if (result != 0)
			{
				throw new InvalidOperationException("Failed to open Software Licensing Client.");
			}

			try
			{
				// Gather all data: Windows Status + Client Licensing
				return GetWindowsActivationStatus(hSLC);
			}
			finally
			{
				if (hSLC != IntPtr.Zero)
				{
					int closeResult = NativeMethods.SLClose(hSLC);
					if (closeResult != 0)
					{
						Logger.Write($"Failed to close Software Licensing Client. Error Code: 0x{closeResult:X8}", LogTypeIntel.Error);
					}
				}
			}
		}

		private static unsafe List<WindowsActivationStatus> GetWindowsActivationStatus(IntPtr hSLC)
		{
			List<WindowsActivationStatus> results = new();
			uint count = 0;
			IntPtr pIds = IntPtr.Zero;

			(bool, bool, string?, string?) subscriptionStatus = GetSubscriptionStatus();

			// Collect SKU List
			int hr = NativeMethods.SLGetSLIDList(hSLC, 0, WindowsAppId, 1, ref count, ref pIds);

			if (hr != 0 || count == 0)
			{
				return results;
			}

			try
			{
				int guidSize = sizeof(Guid);

				for (int i = 0; i < count; i++)
				{
					IntPtr currentPtr = IntPtr.Add(pIds, i * guidSize);
					Guid skuId = *(Guid*)currentPtr;

					string? pkeyIdStr = GetSkuInfoString(hSLC, skuId, "pkeyId");

					if (string.IsNullOrEmpty(pkeyIdStr)) continue;
					if (!Guid.TryParse(pkeyIdStr, out Guid pkeyId)) continue;

					string? description = GetSkuInfoString(hSLC, skuId, "Description");
					string? extendedPid = GetPKeyInfoString(hSLC, pkeyId, "DigitalPID");
					string? channel = GetPKeyInfoString(hSLC, pkeyId, "Channel");
					string? partialKey = GetPKeyInfoString(hSLC, pkeyId, "PartialProductKey");

					GetLicensingStatus(hSLC, WindowsAppId, skuId, out int status, out int grace, out int reason, out long validity);

					results.Add(new WindowsActivationStatus(
						name: GetSkuInfoString(hSLC, skuId, "Name"),
						description: description ?? string.Empty,
						activationId: skuId,
						extendedPid: extendedPid,
						productKeyChannel: channel,
						partialProductKey: partialKey,
						status: status,
						graceTime: grace,
						reason: reason,
						validity: validity,
						clcStateData: GetStateData(),
						clcHResult: GetLastActivationHResult(),
						clcLastActivationTime: GetLastActivationTime(),
						clcGenuineStatus: GetIsWindowsGenuine(),
						clcIsDigitalLicense: GetDigitalLicenseStatus(),
						edittionSupportsSubscription: subscriptionStatus.Item1,
						isSubscriptionEnabled: subscriptionStatus.Item2,
						subscriptionSku: subscriptionStatus.Item3,
						subscriptionState: subscriptionStatus.Item4,
						expirationMsg: GetExpirationMessage(status, description: description, grace, reason)
					));
				}
			}
			finally
			{
				if (pIds != IntPtr.Zero)
				{
					Marshal.FreeHGlobal(pIds);
				}
			}
			return results;
		}

		private static string? GetSkuInfoString(IntPtr hSLC, Guid skuId, string valueName)
		{
			uint dataType = 0;
			uint dataSize = 0;
			IntPtr dataPtr = IntPtr.Zero;

			int hr = NativeMethods.SLGetProductSkuInformation(hSLC, skuId, valueName, ref dataType, ref dataSize, ref dataPtr);

			if (hr == 0 && dataType == 1 && dataPtr != IntPtr.Zero)
			{
				string? result = Marshal.PtrToStringUni(dataPtr);
				Marshal.FreeHGlobal(dataPtr);
				return result;
			}

			if (dataPtr != IntPtr.Zero) Marshal.FreeHGlobal(dataPtr);
			return null;
		}

		private static string? GetPKeyInfoString(IntPtr hSLC, Guid pKeyId, string valueName)
		{
			uint dataType = 0;
			uint dataSize = 0;
			IntPtr dataPtr = IntPtr.Zero;

			int hr = NativeMethods.SLGetPKeyInformation(hSLC, pKeyId, valueName, ref dataType, ref dataSize, ref dataPtr);

			if (hr == 0 && dataType == 1 && dataPtr != IntPtr.Zero)
			{
				string? result = Marshal.PtrToStringUni(dataPtr);
				Marshal.FreeHGlobal(dataPtr);
				return result;
			}

			if (dataPtr != IntPtr.Zero) Marshal.FreeHGlobal(dataPtr);
			return null;
		}

		private static unsafe void GetLicensingStatus(IntPtr hSLC, Guid appId, Guid skuId, out int status, out int grace, out int reason, out long validity)
		{
			status = 0;
			grace = 0;
			reason = 0;
			validity = 0;

			uint count = 0;
			IntPtr ptr = IntPtr.Zero;

			int hr = NativeMethods.SLGetLicensingStatusInformation(hSLC, appId, skuId, null, ref count, ref ptr);

			if (hr == 0 && count > 0 && ptr != IntPtr.Zero)
			{
				SL_LICENSING_STATUS info = *(SL_LICENSING_STATUS*)ptr;

				status = (int)info.eStatus;
				grace = (int)info.dwGraceTime;
				reason = info.hrReason;
				validity = info.qwValidityExpiration;

				if (status == 3) status = 5;
				if (status == 2)
				{
					if (reason == unchecked(0x4004F00D)) status = 3;
					else if (reason == unchecked(0x4004F065)) status = 4;
					else if (reason == unchecked(0x4004FC06)) status = 6;
				}
			}

			if (ptr != IntPtr.Zero) Marshal.FreeHGlobal(ptr);
		}

		private static string GetExpirationMessage(int status, string? description, int grace, int reason)
		{
			double days = Math.Round(grace / 1440.0);
			bool inGrace = grace > 0;
			string safeDesc = description ?? string.Empty;

			string expiryDateStr = "";
			if (inGrace)
			{
				expiryDateStr = DateTime.Now.AddMinutes(grace).ToString("yyyy-MM-dd hh:mm:ss tt");
			}

			if (status == 1) // Licensed
			{
				if (grace == 0)
				{
					return "Permanently activated.";
				}
				else
				{
					string actTag = "Time-based";
					if (safeDesc.Contains("VOLUME_KMSCLIENT", StringComparison.OrdinalIgnoreCase))
					{
						actTag = "Volume KMS";
					}
					else if (safeDesc.Contains("VIRTUAL_MACHINE_ACTIVATION", StringComparison.OrdinalIgnoreCase))
					{
						actTag = "VM Activation";
					}

					if (inGrace)
					{
						return $"{actTag} activation will expire: {expiryDateStr}";
					}
					else
					{
						return $"{actTag} activation expiration: {grace} minutes - {days} days";
					}
				}
			}
			else if (status == 2 && inGrace)
			{
				return $"Initial grace period ends {expiryDateStr}";
			}
			else if ((status == 3 || status == 4 || status == 6) && inGrace)
			{
				return $"Grace period ends {expiryDateStr}";
			}
			else if (status == 5)
			{
				return $"Notification Reason: 0x{reason:X}";
			}
			return string.Empty;
		}

		private static string GetStateData()
		{
			uint type = 0;
			uint size = 0;
			IntPtr ptr = IntPtr.Zero;

			int hr = NativeMethods.SLGetWindowsInformation("Security-SPP-Action-StateData", ref type, ref size, ref ptr);

			if (hr == 0 && ptr != IntPtr.Zero)
			{
				string raw = Marshal.PtrToStringUni(ptr) ?? "";
				Marshal.FreeHGlobal(ptr);
				return "    " + raw.Replace(";", "\n    ");
			}
			return string.Empty;
		}

		private static string GetLastActivationHResult()
		{
			uint type = 0;
			uint size = 0;
			IntPtr ptr = IntPtr.Zero;

			int hr = NativeMethods.SLGetWindowsInformation("Security-SPP-LastWindowsActivationHResult", ref type, ref size, ref ptr);

			if (hr == 0 && ptr != IntPtr.Zero)
			{
				int val = Marshal.ReadInt32(ptr);
				Marshal.FreeHGlobal(ptr);
				return $"0x{val:x8}";
			}
			return string.Empty;
		}

		private static string GetLastActivationTime()
		{
			uint type = 0;
			uint size = 0;
			IntPtr ptr = IntPtr.Zero;

			int hr = NativeMethods.SLGetWindowsInformation("Security-SPP-LastWindowsActivationTime", ref type, ref size, ref ptr);

			if (hr == 0 && ptr != IntPtr.Zero)
			{
				long val = Marshal.ReadInt64(ptr);
				Marshal.FreeHGlobal(ptr);

				if (val != 0)
				{
					try
					{
						return DateTime.FromFileTimeUtc(val).ToString("yyyy/MM/dd:HH:mm:ss");
					}
					catch { }
				}
			}
			return string.Empty;
		}

		/// <summary>
		/// Get the License status of the Windows, whetther it is genuine or not.
		/// </summary>
		/// <returns></returns>
		private static string GetIsWindowsGenuine()
		{
			int genuineState = 0;
			int hr = NativeMethods.SLIsWindowsGenuineLocal(ref genuineState);

			if (hr == 0)
			{
				// https://learn.microsoft.com/windows/win32/api/slpublic/ne-slpublic-sl_genuine_state
				return genuineState switch
				{
					SL_GEN_STATE_IS_GENUINE => "Genuine",
					SL_GEN_STATE_INVALID_LICENSE => "Invalid License",
					SL_GEN_STATE_TAMPERED => "Tampered",
					SL_GEN_STATE_OFFLINE => "Offline",
					SL_GEN_STATE_LAST => "Last State",
					_ => genuineState.ToString()
				};
			}
			return string.Empty;
		}

		/// <summary>
		/// Get the Digital License information.
		/// </summary>
		/// <returns></returns>
		private static bool GetDigitalLicenseStatus()
		{
			try
			{
				int hr = NativeMethods.CLSIDFromProgID("EditionUpgradeManagerObj.EditionUpgradeManager", out Guid clsid);
				if (hr != 0) return false;

				Guid iid = typeof(IEditionUpgradeManager).GUID;
				hr = NativeMethods.CoCreateInstanceForLicensing(in clsid, IntPtr.Zero, 1, in iid, out IEditionUpgradeManager eum);

				if (hr == 0 && eum != null)
				{
					// Calls the 5th method in the VTable
					hr = eum.GetWindowsLicense(1, out int result);
					if (hr == 0)
					{
						return result >= 0 && result != 1;
					}
				}
			}
			catch { }
			return false;
		}

		/// <summary>
		/// Get the subscription details.
		/// </summary>
		/// <returns></returns>
		private static unsafe (bool, bool, string?, string?) GetSubscriptionStatus()
		{
			bool EdittionSupportsSubscription = false;
			bool IsSubscriptionEnabled = false;
			string? SubscriptionSku = null;
			string? SubscriptionState = null;

			int dwSupported = 0;

			int hr = NativeMethods.SLGetWindowsInformationDWORD("ConsumeAddonPolicySet", ref dwSupported);

			if (hr != 0) return (EdittionSupportsSubscription, IsSubscriptionEnabled, SubscriptionSku, SubscriptionState);

			EdittionSupportsSubscription = dwSupported != 0;

			IntPtr pStatus = IntPtr.Zero;
			hr = NativeMethods.ClipGetSubscriptionStatus(ref pStatus);

			if (hr == 0 && pStatus != IntPtr.Zero)
			{
				SubscriptionStatus status = *(SubscriptionStatus*)pStatus;
				Marshal.FreeHGlobal(pStatus);

				IsSubscriptionEnabled = status.dwEnabled != 0;

				if (status.dwEnabled != 0)
				{
					SubscriptionSku = status.dwSku.ToString();
					SubscriptionState = status.dwState.ToString();
				}
			}
			return (EdittionSupportsSubscription, IsSubscriptionEnabled, SubscriptionSku, SubscriptionState);
		}
	}

	#endregion

	public void Dispose()
	{
		_temperatureSampler?.Dispose();
		_temperatureSampler = null;
	}

}
