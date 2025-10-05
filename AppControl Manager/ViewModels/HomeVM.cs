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

using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.UI.Dispatching;

namespace AppControlManager.ViewModels;

internal sealed partial class HomeVM : ViewModelBase
{
	/// <summary>
	/// Event handler for when the home page is loaded.
	/// We do not auto-start the heavy edge pulse storyboard, instead we rasterize and pulse in code.
	/// Glitch storyboards are short, single-run bursts and are triggered by the page every N seconds.
	/// </summary>
	/// <param name="sender"></param>
	internal void OnHomePageLoaded(object sender)
	{
		// Initialize and start the minute-aligned clock updater that only fires when the minute changes.
		InitializeSystemTimeUpdater();

		// Initialize and start the app RAM usage updater that fires every 2 seconds.
		InitializeAppRamUpdater();

		// Initialize and start the internet speed updater that fires every 2 second.
		InitializeInternetSpeedUpdater();

		// Refresh the Windows Defender feed info asynchronously (fire-and-forget)
		_ = RefreshDefenderFeedAsync();
	}

	/// <summary>
	/// Runs when the Home page is unloaded. Called by the page's code behind since it's the one using x:Bind in the XAML.
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
	}

	// Textblock sources bound to the UI for system info HUDs.
	internal string? SystemTimeText { get; set => SP(ref field, value); }
	internal string TimeZoneText { get; set => SP(ref field, value); } = GetLocalUtcOffsetString();
	internal string UserKindText { get; set => SP(ref field, value); } = Environment.IsPrivilegedProcess ? $"{Environment.UserName} - Administrator Privilege" : $"{Environment.UserName} - Standard Privilege";
	internal string UptimeText { get; set => SP(ref field, value); } = GetSystemUptimeString();
	internal string SystemRamText { get; set => SP(ref field, value); } = GetAvailablePhysicalMemoryBytes();
	internal string? AppRamText { get; set => SP(ref field, value); }
	internal string DiskSizeText { get; set => SP(ref field, value); } = GetTotalPhysicalDiskSizeString();
	internal string? InternetSpeedText { get; set => SP(ref field, value); }

	/// <summary>
	/// Timer first used as one-shot to align to next minute, then switched to repeating every minute.
	/// </summary>
	private DispatcherQueueTimer? _clockTimer;

	/// <summary>
	/// Timer that updates the app's working set (RAM usage).
	/// </summary>
	private DispatcherQueueTimer? _appRamTimer;

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
		// Always set the initial value immediately.
		AppRamText = GetAppPrivateWorkingSetBytes_Native();

		_appRamTimer = Dispatcher.CreateTimer();
		_appRamTimer.IsRepeating = true; // repeating update
		_appRamTimer.Interval = TimeSpan.FromSeconds(2);
		_appRamTimer.Tick += OnAppRamTick;
		_appRamTimer.Start();
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
	/// </summary>
	private void OnAppRamTick(DispatcherQueueTimer sender, object args)
	{
		AppRamText = GetAppPrivateWorkingSetBytes_Native();
		UpdateInternetSpeed(first: false);
	}

	/// <summary>
	/// Formats and sets the current system time text with hour and minute only.
	/// Respects system 12/24-hour preference.
	/// </summary>
	private void UpdateSystemTime()
	{
		DateTime now = DateTime.Now;
		DateTimeFormatInfo dfi = CultureInfo.CurrentCulture.DateTimeFormat;

		// Detect 24-hour vs 12-hour from the current culture's short time pattern.
		bool is24Hour = dfi.ShortTimePattern.Contains('H');

		string format = is24Hour ? "HH:mm" : "h:mm tt";

		SystemTimeText = now.ToString(format, CultureInfo.CurrentCulture);
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
			? string.Format(CultureInfo.InvariantCulture, "{0}d {1:D2}h {2:D2}m", days, hours, minutes)
			: string.Format(CultureInfo.InvariantCulture, "{0:D2}h {1:D2}m", hours, minutes);

		return result;
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

	// Cached NetworkInterface for the selected index (resolved lazily and re-resolved as needed).
	private NetworkInterface? _netInterface;

	/// <summary>
	/// Initializes and starts the internet speed (throughput) updater.
	/// Picks the interface Windows routes to 8.8.8.8 and computes bps from 64-bit octet deltas.
	/// </summary>
	private void InitializeInternetSpeedUpdater()
	{
		// Resolve the interface once at start; re-resolved automatically if needed later.
		_netIfIndex = ResolveBestInterfaceIndex();
		_netInterface = ResolveNetworkInterface(_netIfIndex);

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
			_netInterface = ResolveNetworkInterface(_netIfIndex);

			if (_netIfIndex == 0 || _netInterface is null)
			{
				InternetSpeedText = "0.0 Mbps ↓ / 0.0 Mbps ↑";
				return;
			}
		}

		// Ensure the cached NetworkInterface maps to the current index; re-resolve if needed.
		if (_netInterface is null || !IsMatchingInterface(_netInterface, _netIfIndex))
		{
			_netInterface = ResolveNetworkInterface(_netIfIndex);
			if (_netInterface is null)
			{
				InternetSpeedText = "0.0 Mbps ↓ / 0.0 Mbps ↑";
				return;
			}
		}

		IPv4InterfaceStatistics stats;
		try
		{
			stats = _netInterface.GetIPv4Statistics();
		}
		catch
		{
			// Adapter might have gone away; force re-resolve next tick.
			_netIfIndex = 0;
			_netInterface = null;
			InternetSpeedText = "0.0 Mbps ↓ / 0.0 Mbps ↑";
			return;
		}

		long nowTicks = Environment.TickCount64;

		// First sample just seeds the baseline (no delta yet).
		if (first || _prevSampleTicks == 0)
		{
			_prevInBytes = (ulong)stats.BytesReceived;
			_prevOutBytes = (ulong)stats.BytesSent;
			_prevSampleTicks = nowTicks;
			InternetSpeedText = "0.0 Mbps ↓ / 0.0 Mbps ↑";
			return;
		}

		double elapsedSec = (nowTicks - _prevSampleTicks) / 1000.0;
		if (elapsedSec <= 0)
		{
			return;
		}

		ulong curIn = (ulong)stats.BytesReceived;
		ulong curOut = (ulong)stats.BytesSent;

		// Handle adapter reset (counters dropped), which manifests as a decreasing value even for 64-bit counters.
		if (curIn < _prevInBytes || curOut < _prevOutBytes)
		{
			_prevInBytes = curIn;
			_prevOutBytes = curOut;
			_prevSampleTicks = nowTicks;
			InternetSpeedText = "0.0 Mbps ↓ / 0.0 Mbps ↑";
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
	/// Finds the NetworkInterface whose IPv4 index matches the provided MIB index and is operational.
	/// </summary>
	private static NetworkInterface? ResolveNetworkInterface(uint index)
	{
		if (index == 0)
		{
			return null;
		}

		NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
		int count = nics.Length;
		for (int i = 0; i < count; i++)
		{
			NetworkInterface nic = nics[i];
			if (nic.OperationalStatus != OperationalStatus.Up)
			{
				continue;
			}

			IPInterfaceProperties props;
			IPv4InterfaceProperties? ipv4Props;
			try
			{
				props = nic.GetIPProperties();
				ipv4Props = props.GetIPv4Properties();
			}
			catch
			{
				continue;
			}

			if (ipv4Props is not null && (uint)ipv4Props.Index == index)
			{
				return nic;
			}
		}

		return null;
	}

	/// <summary>
	/// Checks whether the given NetworkInterface still maps to the specified MIB index.
	/// </summary>
	private static bool IsMatchingInterface(NetworkInterface nic, uint index)
	{
		try
		{
			IPv4InterfaceProperties? ipv4Props = nic.GetIPProperties().GetIPv4Properties();
			return ipv4Props is not null && (uint)ipv4Props.Index == index && nic.OperationalStatus == OperationalStatus.Up;
		}
		catch
		{
			return false;
		}
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

	#region Defender Feed Fields

	internal string? EngineVersionText { get; set => SP(ref field, value); } = "Antimalware engine version: Unavailable";
	internal string? SignatureVersionText { get; set => SP(ref field, value); } = "Antivirus definition version: Unavailable";
	internal string? PlatformVersionText { get; set => SP(ref field, value); } = "Platform version: Unavailable";
	internal string? SignatureUpdateDateText { get; set => SP(ref field, value); } = "Definition update time: Unavailable";

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
			using HttpClient httpClient = new()
			{
				Timeout = TimeSpan.FromSeconds(8)
			};

			// Download XML

			using CancellationTokenSource timeoutCts = new(TimeSpan.FromSeconds(10));
			using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(timeoutCts.Token, cancellationToken);
			string xml = await httpClient.GetStringAsync(OnlineMSDefenderStatusURL, linked.Token)
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

}
