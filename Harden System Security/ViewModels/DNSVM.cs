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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.ViewModels;
using HardenSystemSecurity.DNS;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinRT;

namespace HardenSystemSecurity.ViewModels;

/// <summary>
/// Displays the live traffic statistics of a single client IP address of the Smart DNS.
/// </summary>
internal sealed partial class ClientTrafficDisplay(string address) : ViewModelBase
{
	internal string Address => address;
	internal string UploadSpeed { get; private set => SP(ref field, value); } = HomeVM.FormatNetworkDataValue(0, true);
	internal string DownloadSpeed { get; private set => SP(ref field, value); } = HomeVM.FormatNetworkDataValue(0, true);
	internal string CombinedSpeed { get; private set => SP(ref field, value); } = HomeVM.FormatNetworkDataValue(0, true);
	internal string TotalUploaded { get; private set => SP(ref field, value); } = HomeVM.FormatNetworkDataValue(0, false);
	internal string TotalDownloaded { get; private set => SP(ref field, value); } = HomeVM.FormatNetworkDataValue(0, false);
	internal string ActiveConnections { get; private set => SP(ref field, value); } = "0";

	internal void Update(string uploadSpeed, string downloadSpeed, string combinedSpeed, string totalUploaded, string totalDownloaded, string activeConnections)
	{
		UploadSpeed = uploadSpeed;
		DownloadSpeed = downloadSpeed;
		CombinedSpeed = combinedSpeed;
		TotalUploaded = totalUploaded;
		TotalDownloaded = totalDownloaded;
		ActiveConnections = activeConnections;
	}
}

/// <summary>
/// The previous cumulative byte counters of a client, used to calculate its speeds.
/// </summary>
internal readonly record struct ClientTrafficPreviousSnapshot(long TotalBytesSent, long TotalBytesReceived);

/// <summary>
/// Displays the query statistics of the DNS over HTTPS server or the DNS server since it was started.
/// </summary>
internal sealed partial class DnsQueryStatisticsDisplay : ViewModelBase
{
	internal string TotalQueries { get; private set => SP(ref field, value); } = "0";
	internal string CacheHits { get; private set => SP(ref field, value); } = "0";
	internal string FailedQueries { get; private set => SP(ref field, value); } = "0";
	internal string Clients { get; private set => SP(ref field, value); } = "0";

	internal void Update(DnsQueryStatistics statistics)
	{
		TotalQueries = statistics.Total.ToString("N0", CultureInfo.CurrentCulture);
		CacheHits = statistics.CacheHits.ToString("N0", CultureInfo.CurrentCulture);
		FailedQueries = statistics.Failed.ToString("N0", CultureInfo.CurrentCulture);
		Clients = statistics.Clients.ToString("N0", CultureInfo.CurrentCulture);
	}
}

/// <summary>
/// An upstream DNS-over-HTTPS resolver that the DoH server can forward queries to through Tor.
/// </summary>
internal sealed partial class DohResolverOption(string company, string uriText, string description) : ViewModelBase
{
	internal string Company => company;
	internal string UriText => uriText;
	internal string Description => description;

	/// <summary>
	/// Whether this resolver is used by the DoH server. Bound to the CheckBox of the resolver in the UI.
	/// </summary>
	internal bool IsSelected { get; set => SP(ref field, value); } = true;
}

/// <summary>
/// ViewModel of the DNS page that hosts the Smart DNS, the DNS over HTTPS server and the DNS server.
/// </summary>
internal sealed partial class DNSVM : ViewModelBase, IDisposable
{
	/// <summary>
	/// The most log lines that are kept and displayed. Once the limit is reached, every new line replaces the oldest one.
	/// </summary>
	private const int MaximumDisplayedLogLines = 3000;

	private const int MaximumQueuedLogMessages = 5000;
	private const int MaximumLogMessagesPerFlush = 1000;

	// The sections of the page, in the order of the items of the SelectorBar.
	private const int SmartDnsSectionIndex = 0;
	private const int DohSectionIndex = 1;
	private const int DnsSectionIndex = 2;

	// The sources of the upstream DNS servers of the DNS server, in the order of the items of its ComboBox.
	private const int DnsUpstreamSourceDestinationAdapter = 0;
	private const int DnsUpstreamSourceCustom = 1;

	internal DNSVM()
	{
		TrafficTimer = Atlas.AppDispatcher.CreateTimer();
		TrafficTimer.Interval = TimeSpan.FromSeconds(1);
		TrafficTimer.Tick += TrafficTimer_Tick;

		LogTimer = Atlas.AppDispatcher.CreateTimer();
		LogTimer.Interval = TimeSpan.FromMilliseconds(500);
		LogTimer.Tick += LogTimer_Tick;

		UpdateTrafficDisplay(0, 0, 0);
		LoadNetworkAdapters();
		LoadDohCertificates(null, null);
		LoadDefaultDohResolvers();
		UpdateDohHttpsTemplate();
		UpdateModeControls();
	}

	internal readonly InfoBarSettings MainInfoBar = new();

	/// <summary>
	/// Timer that refreshes the speed statistics of the Smart DNS, or the query statistics of the
	/// DNS over HTTPS server and the DNS server, every second while one of them is running.
	/// </summary>
	private readonly DispatcherQueueTimer TrafficTimer;

	/// <summary>
	/// Timer that flushes the queued log messages to the UI in batches while one of the servers or Tor is active.
	/// </summary>
	private readonly DispatcherQueueTimer LogTimer;

	private readonly ConcurrentQueue<string> PendingLogMessages = new();
	private readonly Dictionary<IPAddress, ClientTrafficPreviousSnapshot> PreviousClientTraffic = [];
	private readonly Dictionary<IPAddress, ClientTrafficDisplay> ClientTrafficByAddress = [];
	private int PendingLogMessageCount;

	// The kept log lines form a ring: LogLineStart is the index of the oldest line and LogLineCount the number of lines.
	private readonly string[] LogLines = new string[MaximumDisplayedLogLines];
	private int LogLineStart;
	private int LogLineCount;

	// The total number of characters of the kept lines, so the displayed text is built without resizing.
	private int LogLineCharacters;

	/// <summary>
	/// True when the kept lines changed after the displayed text was last built from them.
	/// </summary>
	private bool LogTextIsStale;
	private CancellationTokenSource? ServerCancellationTokenSource;
	private CancellationTokenSource? TorInitializationCancellationTokenSource;
	private Task? ActiveServerTask;
	private Task? ActiveTorInitializationTask;
	private long LastTrafficTimestamp;
	private long LastTotalBytesSent;
	private long LastTotalBytesReceived;

	/// <summary>
	/// True while the DoH hostname is being filled automatically from the listener adapter's address.
	/// </summary>
	private bool IsUpdatingDohIdentityFromListener;

	/// <summary>
	/// True once the user has typed a DoH hostname, so changing the listener adapter no longer overwrites it.
	/// </summary>
	private bool IsDohIdentityUserModified;

	/// <summary>
	/// Whether one of the servers is currently running.
	/// </summary>
	private bool IsRunning;

	/// <summary>
	/// Whether the running server uses Tor, which means that it has to stop when Tor is stopped.
	/// </summary>
	private bool RunningServerUsesTor;

	/// <summary>
	/// The query counters of the running DNS over HTTPS server or DNS server, and the statistics display that shows them.
	/// Both are null while neither of these servers is running.
	/// </summary>
	private DnsQueryCounters? RunningQueryCounters;
	private DnsQueryStatisticsDisplay? RunningQueryStatisticsDisplay;

	/// <summary>
	/// The section that is displayed, one of the section index constants.
	/// </summary>
	private int SelectedSectionIndex;

	#region Sections

	/// <summary>
	/// Event handler for the SelectorBar. Displays the section of the selected item.
	/// </summary>
	internal void SectionSelectorBar_SelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
	{
		SelectedSectionIndex = sender.SelectedItem is null ? SmartDnsSectionIndex : sender.Items.IndexOf(sender.SelectedItem);
		UpdateModeControls();
	}

	#endregion

	#region Adapters and Smart DNS

	/// <summary>
	/// Network adapters that can be selected as the source or destination adapters.
	/// </summary>
	internal readonly ObservableCollection<NetworkAdapterOption> NetworkAdapters = [];

	/// <summary>
	/// The adapter that local devices connect to (LAN listener).
	/// The DoH hostname follows its address until the user types a different one.
	/// </summary>
	internal NetworkAdapterOption? SelectedSourceAdapter
	{
		get; set
		{
			if (SP(ref field, value) && (!IsDohIdentityUserModified || string.IsNullOrWhiteSpace(DohHostName)))
			{
				UpdateDohIdentityFromListenerAdapter();
			}
		}
	}

	/// <summary>
	/// The adapter used for outbound DNS and proxied traffic.
	/// </summary>
	internal NetworkAdapterOption? SelectedDestinationAdapter { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the Smart DNS sends the traffic through Tor instead of the destination adapter.
	/// </summary>
	internal bool SmartDnsUseTor
	{
		get; set
		{
			if (SP(ref field, value))
			{
				UpdateModeControls();
			}
		}
	}

	/// <summary>
	/// Whether application UDP (including QUIC/HTTP3) is relayed by the Smart DNS. Not available through Tor.
	/// </summary>
	internal bool EnableUdp { get; set => SP(ref field, value); } = true;

	#endregion

	#region Tor

	/// <summary>
	/// The root folder of the extracted Tor Expert Bundle. It is shared by every section and remembered in the app settings.
	/// </summary>
	internal string TorBundlePath
	{
		get; set
		{
			if (SP(ref field, value))
			{
				// Text that is still being typed is not a path yet, so only a complete path (or an empty one) is saved.
				string path = field.Trim();
				if (path.Length == 0 || Path.IsPathFullyQualified(path))
				{
					Atlas.Settings.DNSTorBundleDirectory = path;
				}
			}
		}
	} = Atlas.Settings.DNSTorBundleDirectory;

	/// <summary>
	/// The index of the selected <see cref="TorConnectionMethod"/>. The ComboBox items follow the enum's order.
	/// </summary>
	internal int TorConnectionMethodIndex { get; set => SP(ref field, value); }

	/// <summary>
	/// The state of Tor that is displayed in the Tor settings: not running, initializing or ready.
	/// </summary>
	internal string TorStatusText { get; private set => SP(ref field, value); } = string.Empty;

	/// <summary>
	/// Whether Tor is being initialized, which is shown with a progress ring.
	/// </summary>
	internal bool TorIsInitializing { get; private set => SP(ref field, value); }

	#endregion

	#region DNS server

	/// <summary>
	/// Whether the DNS server resolves the queries through Tor instead of the upstream DNS servers.
	/// </summary>
	internal bool DnsUseTor
	{
		get; set
		{
			if (SP(ref field, value))
			{
				UpdateModeControls();
			}
		}
	}

	/// <summary>
	/// The source of the upstream DNS servers when Tor is not used, one of the DNS upstream source constants.
	/// The DNS servers of the destination adapter are queried through that adapter, which keeps working when a VPN
	/// Blocks DNS traffic to every server except its own.
	/// </summary>
	internal int DnsUpstreamSourceIndex
	{
		get; set
		{
			if (SP(ref field, value))
			{
				UpdateModeControls();
			}
		}
	} = DnsUpstreamSourceDestinationAdapter;

	/// <summary>
	/// The IP addresses of the custom DNS servers that the DNS server forwards the queries to.
	/// They are separated by commas, semicolons or spaces.
	/// </summary>
	internal string DnsUpstreamServers { get; set => SP(ref field, value); } = "1.1.1.1, 1.0.0.1";

	/// <summary>
	/// The query statistics of the DNS server.
	/// </summary>
	internal readonly DnsQueryStatisticsDisplay DnsStatistics = new();

	#endregion

	#region Domain log

	/// <summary>
	/// Whether the DNS over HTTPS server and the DNS server count the queried domain names in the domain log file.
	/// </summary>
	internal bool DomainLogIsEnabled
	{
		get; set
		{
			// The file and the options of the log are displayed when it is turned on.
			if (SP(ref field, value) && field)
			{
				DomainLogSettingsExpanderIsExpanded = true;
			}
		}
	}

	/// <summary>
	/// The file in which the DNS over HTTPS server and the DNS server count the queried domain names.
	/// </summary>
	internal string DomainLogPath
	{
		get; private set
		{
			// Remember the location in the app settings.
			if (SP(ref field, value))
			{
				Atlas.Settings.DNSDomainLogFilePath = field;
			}
		}
	} = Atlas.Settings.DNSDomainLogFilePath;

	/// <summary>
	/// Whether only the root domains are counted, such as <c>microsoft.com</c> for <c>azure.homefront.microsoft.com</c>, instead of the full names.
	/// </summary>
	internal bool DomainLogRootDomainsOnly { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the settings expander of the domain log is expanded.
	/// </summary>
	internal bool DomainLogSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	/// <summary>
	/// Event handler for the button that selects the file of the domain log. Selecting a file turns the log on.
	/// </summary>
	internal void SelectDomainLogFile_Click()
	{
		try
		{
			string? selectedFile = FileDialogHelper.ShowSaveFileDialog(Atlas.JSONPickerFilter, "DNS domains.json");
			if (!string.IsNullOrWhiteSpace(selectedFile))
			{
				DomainLogPath = selectedFile;
				DomainLogIsEnabled = true;
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	#endregion

	#region DNS over HTTPS

	/// <summary>
	/// Whether the DNS over HTTPS server reaches the upstream resolvers through Tor instead of directly.
	/// </summary>
	internal bool DohUseTor
	{
		get; set
		{
			if (SP(ref field, value))
			{
				UpdateModeControls();
			}
		}
	}

	/// <summary>
	/// Certificates with a private key that can be used by the DoH server.
	/// </summary>
	internal readonly ObservableCollection<DohCertificateOption> DohCertificates = [];

	internal DohCertificateOption? SelectedDohCertificate { get; set => SP(ref field, value); }

	/// <summary>
	/// The hostname or IP address that clients use to reach the DoH server. It must be contained in the certificate.
	/// </summary>
	internal string DohHostName
	{
		get; set
		{
			if (SP(ref field, value))
			{
				if (!IsUpdatingDohIdentityFromListener)
				{
					IsDohIdentityUserModified = true;
				}
				UpdateDohHttpsTemplate();
			}
		}
	} = string.Empty;

	/// <summary>
	/// The TCP/UDP port of the DoH server. Double because it's bound to a NumberBox, which uses NaN for an empty value.
	/// </summary>
	internal double DohPort
	{
		get; set
		{
			if (SP(ref field, value))
			{
				UpdateDohHttpsTemplate();
			}
		}
	} = 443;

	/// <summary>
	/// The DoH template to configure on Windows clients.
	/// </summary>
	internal string DohHttpsTemplate { get; private set => SP(ref field, value); } = string.Empty;

	/// <summary>
	/// The upstream DoH resolvers that the DoH server forwards the queries to through Tor.
	/// </summary>
	internal readonly ObservableCollection<DohResolverOption> DohResolvers = [];

	/// <summary>
	/// The query statistics of the DNS over HTTPS server.
	/// </summary>
	internal readonly DnsQueryStatisticsDisplay DohStatistics = new();

	#endregion

	#region UI state

	/// <summary>
	/// Live traffic statistics per client IP address.
	/// </summary>
	internal readonly ObservableCollection<ClientTrafficDisplay> ClientTrafficItems = [];

	/// <summary>
	/// Whether the configuration and start controls are enabled. False while one of the servers is running.
	/// </summary>
	internal bool ElementsAreEnabled
	{
		get; private set
		{
			if (SP(ref field, value))
			{
				UseTorToggleIsEnabled = field && InitializeTorButtonIsEnabled;
			}
		}
	} = true;

	/// <summary>
	/// Whether the destination adapter and the UDP option are enabled. They don't apply when the Smart DNS uses Tor.
	/// </summary>
	internal bool DestinationAdapterAndUdpAreEnabled { get; private set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the Stop button is enabled.
	/// </summary>
	internal bool StopButtonIsEnabled { get; private set => SP(ref field, value); }

	/// <summary>
	/// Whether the Initialize Tor button is enabled. False while Tor is initializing, running or stopping.
	/// </summary>
	internal bool InitializeTorButtonIsEnabled
	{
		get; private set
		{
			if (SP(ref field, value))
			{
				UseTorToggleIsEnabled = field && ElementsAreEnabled;
			}
		}
	} = true;

	internal bool StopTorButtonIsEnabled { get; private set => SP(ref field, value); }

	/// <summary>
	/// Whether the Use Tor toggle switches of the sections are enabled.
	/// They stay locked while Tor is initializing, running or stopping, until the Stop Tor button stops it.
	/// </summary>
	internal bool UseTorToggleIsEnabled { get; private set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the certificate settings expander of the DNS over HTTPS section is expanded.
	/// </summary>
	internal bool DohCertificateSettingsExpanderIsExpanded { get; set => SP(ref field, value); } = true;

	// The SelectorBar chooses which section of the page is shown.
	internal Visibility SmartDnsSectionVisibility { get; private set => SP(ref field, value); } = Visibility.Visible;
	internal Visibility DohSectionVisibility { get; private set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility DnsSectionVisibility { get; private set => SP(ref field, value); } = Visibility.Collapsed;

	// The Tor settings are only displayed in a section while its server is set to use Tor.
	internal Visibility SmartDnsTorSettingsVisibility { get; private set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility DohTorSettingsVisibility { get; private set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility DnsTorSettingsVisibility { get; private set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Visibility of the source of the upstream DNS servers of the DNS server, which is not used with Tor.
	/// </summary>
	internal Visibility DnsUpstreamSourceVisibility { get; private set => SP(ref field, value); } = Visibility.Visible;

	/// <summary>
	/// Visibility of the destination adapter of the DNS server, whose DNS servers are the upstream servers when it's the selected source.
	/// </summary>
	internal Visibility DnsDestinationAdapterVisibility { get; private set => SP(ref field, value); } = Visibility.Visible;

	/// <summary>
	/// Visibility of the custom upstream DNS servers of the DNS server, which are used when they are the selected source.
	/// </summary>
	internal Visibility DnsUpstreamServersVisibility { get; private set => SP(ref field, value); } = Visibility.Collapsed;

	internal string? UploadSpeedText { get; private set => SP(ref field, value); }
	internal string? DownloadSpeedText { get; private set => SP(ref field, value); }
	internal string? CombinedSpeedText { get; private set => SP(ref field, value); }
	internal string? ActiveConnectionsText { get; private set => SP(ref field, value); }

	/// <summary>
	/// The text displayed in the logs TextBox. It is only built from the kept log lines while the logs pane is open.
	/// </summary>
	internal string LogText { get; private set => SP(ref field, value); } = string.Empty;

	/// <summary>
	/// Whether the logs pane is open. The logs are collected either way, but the displayed text is only
	/// updated while they are visible, so a busy server costs the UI nothing when nobody looks at the logs.
	/// </summary>
	internal bool LogsPaneIsOpen
	{
		get; set
		{
			if (SP(ref field, value) && field && LogTextIsStale)
			{
				RebuildLogText();
			}
		}
	}

	/// <summary>
	/// Updates the visibility and the enabled state of the controls based on the selected section and the running state.
	/// </summary>
	private void UpdateModeControls()
	{
		bool isTorInitializing = TorInitializationCancellationTokenSource is not null;
		bool isTorReady = TorSessionManager.IsReady;

		SmartDnsSectionVisibility = SelectedSectionIndex == SmartDnsSectionIndex ? Visibility.Visible : Visibility.Collapsed;
		DohSectionVisibility = SelectedSectionIndex == DohSectionIndex ? Visibility.Visible : Visibility.Collapsed;
		DnsSectionVisibility = SelectedSectionIndex == DnsSectionIndex ? Visibility.Visible : Visibility.Collapsed;
		SmartDnsTorSettingsVisibility = SmartDnsUseTor ? Visibility.Visible : Visibility.Collapsed;
		DohTorSettingsVisibility = DohUseTor ? Visibility.Visible : Visibility.Collapsed;
		DnsTorSettingsVisibility = DnsUseTor ? Visibility.Visible : Visibility.Collapsed;
		DnsUpstreamSourceVisibility = DnsUseTor ? Visibility.Collapsed : Visibility.Visible;
		DnsDestinationAdapterVisibility = !DnsUseTor && DnsUpstreamSourceIndex == DnsUpstreamSourceDestinationAdapter ? Visibility.Visible : Visibility.Collapsed;
		DnsUpstreamServersVisibility = !DnsUseTor && DnsUpstreamSourceIndex == DnsUpstreamSourceCustom ? Visibility.Visible : Visibility.Collapsed;
		DestinationAdapterAndUdpAreEnabled = !IsRunning && !SmartDnsUseTor;
		InitializeTorButtonIsEnabled = !isTorInitializing && !isTorReady;
		StopTorButtonIsEnabled = isTorInitializing || isTorReady;
		TorIsInitializing = isTorInitializing;
		TorStatusText = Atlas.GetStr(isTorInitializing ? "DNSTorInitializing" : isTorReady ? "DNSTorReady" : "DNSTorNotRunning");
	}

	#endregion

	/// <summary>
	/// Loads the network adapters while preserving the current selections when the adapters still exist.
	/// </summary>
	internal void LoadNetworkAdapters()
	{
		try
		{
			string? previousSourceId = SelectedSourceAdapter?.Id;
			string? previousDestinationId = SelectedDestinationAdapter?.Id;

			List<NetworkAdapterOption> adapters = SmartDNSEngine.GetNetworkAdapters();

			NetworkAdapters.Clear();
			foreach (NetworkAdapterOption adapter in adapters)
			{
				NetworkAdapters.Add(adapter);
			}

			SelectedSourceAdapter = FindAdapter(adapters, previousSourceId);
			SelectedDestinationAdapter = FindAdapter(adapters, previousDestinationId);

			if (adapters.Count == 0)
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("DNSNoAdaptersFound"));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Returns the adapter with the specified ID, or the first adapter if it's not found.
	/// </summary>
	private static NetworkAdapterOption? FindAdapter(List<NetworkAdapterOption> adapters, string? id)
	{
		if (id is not null)
		{
			foreach (NetworkAdapterOption adapter in adapters)
			{
				if (string.Equals(adapter.Id, id, StringComparison.OrdinalIgnoreCase))
				{
					return adapter;
				}
			}
		}

		return adapters.Count > 0 ? adapters[0] : null;
	}

	/// <summary>
	/// Event handler for the Browse button of the Tor Expert Bundle folder.
	/// </summary>
	internal void BrowseTorBundle_Click()
	{
		string? selectedFolder = FileDialogHelper.ShowDirectoryPickerDialog();
		if (!string.IsNullOrWhiteSpace(selectedFolder))
		{
			TorBundlePath = selectedFolder;
		}
	}

	/// <summary>
	/// Event handler for the Start button. Runs the server of the displayed section until it is stopped or fails.
	/// </summary>
	internal async void Start_Click()
	{
		if (SelectedSourceAdapter is not NetworkAdapterOption sourceAdapter)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("DNSSelectListenerAdapter"));
			return;
		}

		bool useDnsOverHttps = SelectedSectionIndex == DohSectionIndex;
		bool useDns = SelectedSectionIndex == DnsSectionIndex;
		bool useSmartDns = !useDnsOverHttps && !useDns;
		bool useTor = useSmartDns ? SmartDnsUseTor : useDnsOverHttps ? DohUseTor : DnsUseTor;
		NetworkAdapterOption? destinationAdapter = SelectedDestinationAdapter;

		if (useSmartDns && destinationAdapter is null)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("DNSSelectBothAdapters"));
			return;
		}

		DohCertificateOption? certificate = SelectedDohCertificate;
		string dohHostName = DohHostName.Trim();
		double dohPortValue = DohPort;
		Uri[] upstreamDohUris = [];

		if (useDnsOverHttps)
		{
			if (certificate is null)
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("DNSSelectCertificate"));
				return;
			}
			if (!DnsOverHttpsCertificateManager.IsValidIdentity(dohHostName))
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("DNSInvalidDohHostName"));
				return;
			}
			if (!IsValidDohPort(dohPortValue))
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("DNSInvalidDohPort"));
				return;
			}
			upstreamDohUris = GetSelectedDohResolverUris();
			if (upstreamDohUris.Length == 0)
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("DNSSelectResolver"));
				return;
			}
		}

		// The DNS server forwards the queries to the DNS servers of the destination adapter through that adapter,
		// or to the custom upstream DNS servers through the system's routing. Neither is used with Tor.
		IPAddress[] upstreamDnsServers = [];
		IPAddress? dnsOutboundAddress = null;
		if (useDns && !useTor)
		{
			if (DnsUpstreamSourceIndex == DnsUpstreamSourceDestinationAdapter)
			{
				if (destinationAdapter is null || destinationAdapter.DnsServers.Count == 0)
				{
					MainInfoBar.WriteWarning(Atlas.GetStr("DNSDestinationAdapterHasNoDnsServers"));
					return;
				}
				upstreamDnsServers = [.. destinationAdapter.DnsServers];
				dnsOutboundAddress = destinationAdapter.Address;
			}
			else if (!TryParseUpstreamDnsServers(DnsUpstreamServers, out upstreamDnsServers))
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("DNSInvalidUpstreamServers"));
				return;
			}
		}

		// Only the DNS over HTTPS server and the DNS server count the queried domain names.
		bool useDomainLog = !useSmartDns && DomainLogIsEnabled;
		if (useDomainLog && DomainLogPath.Length == 0)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("DNSSelectDomainLogFile"));
			return;
		}
		string? domainLogPath = useDomainLog ? DomainLogPath : null;
		bool domainLogRootDomainsOnly = DomainLogRootDomainsOnly;

		// UDP can't be relayed through Tor, so it's only enabled for the destination adapter route.
		bool enableUdp = !useTor && EnableUdp;

		// Registered as an active operation so that closing the app while the server is running asks for confirmation.
		using IDisposable taskTracker = TaskTracking.RegisterOperation();

		// The controls are disabled before Tor is initialized, so nothing can be changed or started in the meantime.
		ElementsAreEnabled = false;

		// Every server that uses Tor shares one Tor session, which is started here when it is not running yet.
		if (useTor && !await EnsureTorIsReadyAsync())
		{
			ElementsAreEnabled = true;
			UpdateModeControls();
			return;
		}

		CancellationTokenSource cancellationTokenSource = new();
		ServerCancellationTokenSource = cancellationTokenSource;
		IsRunning = true;
		RunningServerUsesTor = useTor;
		StopButtonIsEnabled = true;
		UpdateModeControls();

		// The counters are reset before the baseline is captured so that the speeds of this run start from zero.
		SmartDNSEngine.ResetTrafficCounters();
		LastTotalBytesSent = 0;
		LastTotalBytesReceived = 0;
		LastTrafficTimestamp = Stopwatch.GetTimestamp();
		UpdateTrafficDisplay(0, 0, 0);
		ClearClientTraffic();

		// The query counters are reset here too, so the previous run's counts are never displayed while the server starts.
		if (!useSmartDns)
		{
			DnsQueryCounters queryCounters = useDnsOverHttps ? DnsOverHttpsServer.Statistics : DnsServer.Statistics;
			DnsQueryStatisticsDisplay queryStatisticsDisplay = useDnsOverHttps ? DohStatistics : DnsStatistics;
			queryCounters.Reset();
			queryStatisticsDisplay.Update(queryCounters.Snapshot());
			RunningQueryCounters = queryCounters;
			RunningQueryStatisticsDisplay = queryStatisticsDisplay;
		}

		TrafficTimer.Start();
		LogTimer.Start();

		string stoppedMessage = Atlas.GetStr(useDnsOverHttps ? "DNSDohServerStopped" : useDns ? "DNSServerStopped" : "SmartDNSStopped");
		string failedMessage = Atlas.GetStr(useDnsOverHttps ? "DNSDohServerFailed" : useDns ? "DNSServerFailed" : "SmartDNSFailed");

		try
		{
			Task serverTask;

			// The servers run on the thread pool so that their continuations never compete with the UI thread.
			if (useDnsOverHttps)
			{
				int dohPort = (int)dohPortValue;
				string certificateThumbprint = certificate!.Thumbprint;
				StoreLocation certificateStoreLocation = certificate.StoreLocation;

				MainInfoBar.WriteInfo(string.Format(CultureInfo.CurrentCulture, Atlas.GetStr("DNSDohServerRunning"), DnsOverHttpsCertificateManager.BuildHttpsTemplate(dohHostName, dohPort)));

				serverTask = Task.Run(async () =>
				{
					// The domain log is opened here so that a file that cannot be used is reported like any other start failure.
					using DnsDomainLog? domainLog = domainLogPath is null ? null : DnsDomainLog.Open(domainLogPath, domainLogRootDomainsOnly, WriteLog);
					await DnsOverHttpsServer.RunAsync(
						WriteLog,
						sourceAdapter.Address,
						dohPort,
						certificateThumbprint,
						certificateStoreLocation,
						dohHostName,
						upstreamDohUris,
						useTor,
						domainLog,
						cancellationTokenSource.Token);
				});
			}
			else if (useDns)
			{
				MainInfoBar.WriteInfo(string.Format(CultureInfo.CurrentCulture, Atlas.GetStr("DNSServerRunning"), sourceAdapter.Address));

				serverTask = Task.Run(async () =>
				{
					using DnsDomainLog? domainLog = domainLogPath is null ? null : DnsDomainLog.Open(domainLogPath, domainLogRootDomainsOnly, WriteLog);
					await DnsServer.RunAsync(WriteLog, sourceAdapter.Address, useTor, upstreamDnsServers, dnsOutboundAddress, domainLog, cancellationTokenSource.Token);
				});
			}
			else
			{
				NetworkAdapterOption outboundAdapter = destinationAdapter!;

				MainInfoBar.WriteInfo(string.Format(CultureInfo.CurrentCulture, Atlas.GetStr("SmartDNSRunning"), sourceAdapter.Address));

				serverTask = Task.Run(() => SmartDNSEngine.RunAsync(
					WriteLog,
					sourceAdapter,
					outboundAdapter,
					useTor,
					enableUdp,
					cancellationTokenSource.Token));
			}

			ActiveServerTask = serverTask;
			await serverTask;

			MainInfoBar.WriteSuccess(stoppedMessage);
		}
		catch (OperationCanceledException) when (cancellationTokenSource.IsCancellationRequested)
		{
			MainInfoBar.WriteSuccess(stoppedMessage);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, failedMessage);
		}
		finally
		{
			TrafficTimer.Stop();
			UpdateTrafficDisplay(0, 0, 0);
			ClearClientTraffic();

			// The final query counts stay displayed after the server stops.
			if (RunningQueryCounters is DnsQueryCounters finalQueryCounters)
			{
				RunningQueryStatisticsDisplay?.Update(finalQueryCounters.Snapshot());
			}
			RunningQueryCounters = null;
			RunningQueryStatisticsDisplay = null;
			cancellationTokenSource.Dispose();
			if (ReferenceEquals(ServerCancellationTokenSource, cancellationTokenSource))
			{
				ServerCancellationTokenSource = null;
				ActiveServerTask = null;
			}
			IsRunning = false;
			RunningServerUsesTor = false;
			StopButtonIsEnabled = false;
			ElementsAreEnabled = true;
			UpdateModeControls();
			StopLogTimerIfIdle();
		}
	}

	/// <summary>
	/// Event handler for the Stop button.
	/// </summary>
	internal void Stop_Click()
	{
		StopButtonIsEnabled = false;
		ServerCancellationTokenSource?.Cancel();
	}

	/// <summary>
	/// Reads the upstream DNS servers from the text the user entered. Returns false when there is no server or an entry is not an IP address.
	/// </summary>
	private static bool TryParseUpstreamDnsServers(string text, out IPAddress[] servers)
	{
		string[] entries = text.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
		List<IPAddress> addresses = new(entries.Length);
		foreach (string entry in entries)
		{
			if (!IPAddress.TryParse(entry, out IPAddress? address))
			{
				servers = [];
				return false;
			}
			if (!addresses.Contains(address))
			{
				addresses.Add(address);
			}
		}
		servers = [.. addresses];
		return servers.Length != 0;
	}

	/// <summary>
	/// Event handler for the Initialize Tor button. Starts the Tor session that every server that uses Tor shares.
	/// </summary>
	internal async void InitializeTor_Click() => _ = await EnsureTorIsReadyAsync();

	/// <summary>
	/// Starts Tor when it is not running yet and waits until it is connected. Returns whether Tor is ready.
	/// Every failure is displayed here, so the callers only need the result.
	/// </summary>
	private async Task<bool> EnsureTorIsReadyAsync()
	{
		if (TorSessionManager.IsReady)
		{
			return true;
		}

		// An initialization that is already in progress is joined instead of starting a second one.
		if (ActiveTorInitializationTask is Task initializationInProgress)
		{
			try
			{
				await initializationInProgress;
			}
			catch (Exception)
			{
				// Displayed by the call that started the initialization.
			}
			return TorSessionManager.IsReady;
		}

		string torBundlePath = TorBundlePath.Trim();
		if (!IsValidTorBundlePath(torBundlePath))
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("DNSInvalidTorBundle"));
			return false;
		}

		TorConnectionMethod torConnectionMethod = (TorConnectionMethod)Math.Clamp(TorConnectionMethodIndex, (int)TorConnectionMethod.Direct, (int)TorConnectionMethod.Meek);

		using IDisposable taskTracker = TaskTracking.RegisterOperation();

		CancellationTokenSource cancellationTokenSource = new();
		TorInitializationCancellationTokenSource = cancellationTokenSource;
		UpdateModeControls();
		LogTimer.Start();

		MainInfoBar.WriteInfo(Atlas.GetStr("DNSTorInitializing"));

		try
		{
			Task initializationTask = Task.Run(() => TorSessionManager.InitializeAsync(WriteLog, torBundlePath, torConnectionMethod, cancellationTokenSource.Token));
			ActiveTorInitializationTask = initializationTask;
			await initializationTask;

			MainInfoBar.WriteSuccess(Atlas.GetStr("DNSTorReady"));
		}
		catch (OperationCanceledException) when (cancellationTokenSource.IsCancellationRequested)
		{
			// Cancelled by the Stop Tor button or by closing the app.
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, Atlas.GetStr("DNSTorInitializationFailed"));
		}
		finally
		{
			cancellationTokenSource.Dispose();
			if (ReferenceEquals(TorInitializationCancellationTokenSource, cancellationTokenSource))
			{
				TorInitializationCancellationTokenSource = null;
				ActiveTorInitializationTask = null;
			}
			UpdateModeControls();
			StopLogTimerIfIdle();
		}
		return TorSessionManager.IsReady;
	}

	/// <summary>
	/// Event handler for the Stop Tor button. Cancels the Tor initialization and the server that uses Tor, then stops Tor.
	/// </summary>
	internal async void StopTor_Click()
	{
		StopTorButtonIsEnabled = false;
		InitializeTorButtonIsEnabled = false;

		CancellationTokenSource? initializationCancellationTokenSource = TorInitializationCancellationTokenSource;
		Task? initializationTask = ActiveTorInitializationTask;

		// A server that does not use Tor keeps running.
		CancellationTokenSource? serverCancellationTokenSource = RunningServerUsesTor ? ServerCancellationTokenSource : null;
		Task? serverTask = RunningServerUsesTor ? ActiveServerTask : null;

		initializationCancellationTokenSource?.Cancel();
		serverCancellationTokenSource?.Cancel();

		try
		{
			if (initializationTask is not null)
			{
				await initializationTask;
			}
			if (serverTask is not null)
			{
				await serverTask;
			}
		}
		catch (OperationCanceledException)
		{
			// Expected since the active work was cancelled.
		}
		catch (Exception ex)
		{
			// The failures of the active work are already displayed by their own handlers.
			WriteLog($"Tor shutdown encountered an error while waiting for active work: {ex.Message}");
		}
		finally
		{
			TorSessionManager.Shutdown();
			MainInfoBar.WriteSuccess(Atlas.GetStr("DNSTorStopped"));
			UpdateModeControls();
			StopLogTimerIfIdle();
		}
	}

	/// <summary>
	/// Event handler for the Refresh button of the certificates. Keeps the current selection when it still exists.
	/// </summary>
	internal void RefreshCertificates_Click()
	{
		DohCertificateOption? selected = SelectedDohCertificate;
		LoadDohCertificates(selected?.Thumbprint, selected?.StoreLocation);
	}

	/// <summary>
	/// Loads the certificates that can be used by the DoH server and selects the specified one if it exists.
	/// </summary>
	private void LoadDohCertificates(string? selectedThumbprint, StoreLocation? selectedStoreLocation)
	{
		try
		{
			List<DohCertificateOption> certificates = DnsOverHttpsCertificateManager.GetAvailableCertificates();

			DohCertificates.Clear();
			DohCertificateOption? selectedCertificate = null;
			foreach (DohCertificateOption certificate in certificates)
			{
				DohCertificates.Add(certificate);
				if (selectedStoreLocation == certificate.StoreLocation &&
					string.Equals(selectedThumbprint, certificate.Thumbprint, StringComparison.OrdinalIgnoreCase))
				{
					selectedCertificate = certificate;
				}
			}

			SelectedDohCertificate = selectedCertificate;
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Event handler for the Generate and trust certificate button.
	/// Creates a self-signed certificate for the DoH hostname, trusts it and selects it.
	/// </summary>
	internal async void GenerateCertificate_Click()
	{
		string hostName = DohHostName.Trim();
		double portValue = DohPort;

		if (!DnsOverHttpsCertificateManager.IsValidIdentity(hostName))
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("DNSInvalidDohHostName"));
			return;
		}
		if (!IsValidDohPort(portValue))
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("DNSInvalidDohPort"));
			return;
		}

		int port = (int)portValue;
		ElementsAreEnabled = false;
		try
		{
			// Key generation and the certificate store operations run off the UI thread.
			DnsOverHttpsCertificateManager.CertificateCreationResult result = await Task.Run(() => DnsOverHttpsCertificateManager.CreateAndTrust(hostName, port));

			LoadDohCertificates(result.Thumbprint, result.StoreLocation);
			DohHttpsTemplate = result.HttpsTemplate;

			WriteLog($"Created, trusted, and selected the self-signed DoH certificate '{hostName}'. thumbprint={result.Thumbprint} store={result.StoreLocation} expires={result.NotAfter:O}");
			MainInfoBar.WriteSuccess(string.Format(CultureInfo.CurrentCulture, Atlas.GetStr("DNSCertificateCreated"), hostName));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, Atlas.GetStr("DNSCertificateCreationFailed"));
		}
		finally
		{
			ElementsAreEnabled = !IsRunning;
			FlushAllPendingLogs();
		}
	}

	/// <summary>
	/// Fills the DoH hostname with the address of the listener adapter without marking it as user-modified.
	/// </summary>
	private void UpdateDohIdentityFromListenerAdapter()
	{
		if (SelectedSourceAdapter is not NetworkAdapterOption listenerAdapter)
		{
			return;
		}

		IsUpdatingDohIdentityFromListener = true;
		try
		{
			DohHostName = listenerAdapter.Address.ToString();
		}
		finally
		{
			IsUpdatingDohIdentityFromListener = false;
		}
	}

	private void UpdateDohHttpsTemplate() => DohHttpsTemplate = IsValidDohPort(DohPort)
		? DnsOverHttpsCertificateManager.BuildHttpsTemplate(DohHostName.Trim(), (int)DohPort)
		: string.Empty;

	/// <summary>
	/// Whether the value is a whole number in the valid TCP/UDP port range. Checked before every cast to int.
	/// </summary>
	private static bool IsValidDohPort(double port) => !double.IsNaN(port) && port == Math.Truncate(port) && port is >= 1 and <= 65535;

	/// <summary>
	/// Whether the folder is the root of an extracted Tor Expert Bundle.
	/// </summary>
	private static bool IsValidTorBundlePath(string bundlePath)
	{
		if (string.IsNullOrWhiteSpace(bundlePath))
		{
			return false;
		}

		try
		{
			string root = Path.GetFullPath(bundlePath);
			return File.Exists(Path.Join(root, "tor", "tor.exe")) &&
				File.Exists(Path.Join(root, "data", "geoip")) &&
				File.Exists(Path.Join(root, "data", "geoip6"));
		}
		catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException or System.Security.SecurityException)
		{
			return false;
		}
	}

	/// <summary>
	/// Adds the default upstream DoH resolvers, all of them selected.
	/// </summary>
	private void LoadDefaultDohResolvers()
	{
		DohResolvers.Add(new DohResolverOption("Cloudflare", "https://cloudflare-dns.com/dns-query", Atlas.GetStr("DNSResolverCloudflareStandardDescription")));
		DohResolvers.Add(new DohResolverOption("Cloudflare", "https://security.cloudflare-dns.com/dns-query", Atlas.GetStr("DNSResolverCloudflareSecurityDescription")) { IsSelected = false });
		DohResolvers.Add(new DohResolverOption("Cloudflare", "https://family.cloudflare-dns.com/dns-query", Atlas.GetStr("DNSResolverCloudflareFamilyDescription")) { IsSelected = false });
		DohResolvers.Add(new DohResolverOption("Google", "https://dns.google/dns-query", Atlas.GetStr("DNSResolverGoogleDescription")));
		DohResolvers.Add(new DohResolverOption("Quad9", "https://dns.quad9.net/dns-query", Atlas.GetStr("DNSResolverQuad9RecommendedDescription")));
		DohResolvers.Add(new DohResolverOption("Quad9", "https://dns11.quad9.net/dns-query", Atlas.GetStr("DNSResolverQuad9EcsDescription")) { IsSelected = false });
		DohResolvers.Add(new DohResolverOption("Quad9", "https://dns10.quad9.net/dns-query", Atlas.GetStr("DNSResolverQuad9UnsecuredDescription")) { IsSelected = false });
	}

	/// <summary>
	/// Event handler for the Add resolver button. Asks for the details of a custom HTTPS resolver in a dialog, then adds and selects it.
	/// </summary>
	internal async void AddDohResolver_Click()
	{
		try
		{
			using AddDohResolverDialog dialog = new();
			ContentDialogResult result = await dialog.ShowAsync();
			if (result is not ContentDialogResult.Primary)
			{
				return;
			}

			string company = dialog.Company.Trim();
			string uriText = dialog.ResolverUri.Trim();
			string description = dialog.Description.Trim();

			if (!AddDohResolverDialog.IsValidResolver(company, uriText, description) || !Uri.TryCreate(uriText, UriKind.Absolute, out Uri? uri))
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("DNSInvalidCustomResolver"));
				return;
			}

			foreach (DohResolverOption resolver in DohResolvers)
			{
				if (string.Equals(resolver.UriText, uri.AbsoluteUri, StringComparison.OrdinalIgnoreCase))
				{
					MainInfoBar.WriteWarning(Atlas.GetStr("DNSDuplicateResolver"));
					return;
				}
			}

			DohResolvers.Add(new DohResolverOption(company, uri.AbsoluteUri, description));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private Uri[] GetSelectedDohResolverUris()
	{
		List<Uri> upstreamDohUris = new(DohResolvers.Count);
		foreach (DohResolverOption resolver in DohResolvers)
		{
			if (resolver.IsSelected)
			{
				upstreamDohUris.Add(new Uri(resolver.UriText, UriKind.Absolute));
			}
		}
		return upstreamDohUris.ToArray();
	}

	/// <summary>
	/// Event handler for the Clear logs button.
	/// </summary>
	internal void ClearLogs_Click()
	{
		PendingLogMessages.Clear();
		_ = Interlocked.Exchange(ref PendingLogMessageCount, 0);
		Array.Clear(LogLines);
		LogLineStart = 0;
		LogLineCount = 0;
		LogLineCharacters = 0;
		LogTextIsStale = false;
		LogText = string.Empty;
	}

	/// <summary>
	/// Event handler for the Copy logs button. Copies every kept log line, whether or not the logs pane is open.
	/// </summary>
	internal void CopyLogs_Click()
	{
		FlushAllPendingLogs();
		if (LogLineCount != 0)
		{
			ClipboardManagement.CopyText(BuildLogText());
		}
	}

	private void ClearClientTraffic()
	{
		PreviousClientTraffic.Clear();
		ClientTrafficByAddress.Clear();
		ClientTrafficItems.Clear();
	}

	private void TrafficTimer_Tick(DispatcherQueueTimer sender, object args)
	{
		// The DNS over HTTPS server and the DNS server only display their query statistics.
		if (RunningQueryCounters is DnsQueryCounters queryCounters && RunningQueryStatisticsDisplay is DnsQueryStatisticsDisplay queryStatisticsDisplay)
		{
			queryStatisticsDisplay.Update(queryCounters.Snapshot());
			return;
		}

		long timestamp = Stopwatch.GetTimestamp();
		double elapsedSeconds = Stopwatch.GetElapsedTime(LastTrafficTimestamp, timestamp).TotalSeconds;
		TrafficSnapshot snapshot = SmartDNSEngine.GetTrafficSnapshot();
		long sentDelta = Math.Max(0, snapshot.TotalBytesSent - LastTotalBytesSent);
		long receivedDelta = Math.Max(0, snapshot.TotalBytesReceived - LastTotalBytesReceived);
		double uploadBytesPerSecond = elapsedSeconds > 0 ? sentDelta / elapsedSeconds : 0;
		double downloadBytesPerSecond = elapsedSeconds > 0 ? receivedDelta / elapsedSeconds : 0;
		LastTrafficTimestamp = timestamp;
		LastTotalBytesSent = snapshot.TotalBytesSent;
		LastTotalBytesReceived = snapshot.TotalBytesReceived;
		UpdateTrafficDisplay(uploadBytesPerSecond, downloadBytesPerSecond, snapshot.ActiveConnections);
		UpdateClientTrafficDisplay(snapshot.Clients, elapsedSeconds);
	}

	private void UpdateClientTrafficDisplay(List<ClientTrafficSnapshot> clients, double elapsedSeconds)
	{
		foreach (ClientTrafficSnapshot client in clients)
		{
			_ = PreviousClientTraffic.TryGetValue(client.Address, out ClientTrafficPreviousSnapshot previous);
			long sentDelta = Math.Max(0, client.TotalBytesSent - previous.TotalBytesSent);
			long receivedDelta = Math.Max(0, client.TotalBytesReceived - previous.TotalBytesReceived);
			double uploadBytesPerSecond = elapsedSeconds > 0 ? sentDelta / elapsedSeconds : 0;
			double downloadBytesPerSecond = elapsedSeconds > 0 ? receivedDelta / elapsedSeconds : 0;
			if (!ClientTrafficByAddress.TryGetValue(client.Address, out ClientTrafficDisplay? item))
			{
				item = new ClientTrafficDisplay(client.Address.ToString());
				ClientTrafficByAddress.Add(client.Address, item);
				ClientTrafficItems.Add(item);
			}
			item.Update(
				HomeVM.FormatNetworkDataValue(uploadBytesPerSecond, true),
				HomeVM.FormatNetworkDataValue(downloadBytesPerSecond, true),
				HomeVM.FormatNetworkDataValue(uploadBytesPerSecond + downloadBytesPerSecond, true),
				HomeVM.FormatNetworkDataValue(client.TotalBytesSent, false),
				HomeVM.FormatNetworkDataValue(client.TotalBytesReceived, false),
				client.ActiveConnections.ToString(CultureInfo.CurrentCulture));
			PreviousClientTraffic[client.Address] = new ClientTrafficPreviousSnapshot(client.TotalBytesSent, client.TotalBytesReceived);
		}
	}

	private void UpdateTrafficDisplay(double uploadBytesPerSecond, double downloadBytesPerSecond, int activeConnections)
	{
		UploadSpeedText = HomeVM.FormatNetworkDataValue(uploadBytesPerSecond, true);
		DownloadSpeedText = HomeVM.FormatNetworkDataValue(downloadBytesPerSecond, true);
		CombinedSpeedText = HomeVM.FormatNetworkDataValue(uploadBytesPerSecond + downloadBytesPerSecond, true);
		ActiveConnectionsText = activeConnections.ToString(CultureInfo.CurrentCulture);
	}

	/// <summary>
	/// Queues a log message. Called by the servers and Tor from any thread.
	/// The oldest queued messages are dropped when the queue limit is exceeded.
	/// </summary>
	private void WriteLog(string message)
	{
		string timestampedMessage = message.StartsWith('[')
			? message
			: $"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz}] {message}";
		PendingLogMessages.Enqueue(timestampedMessage);
		int queuedCount = Interlocked.Increment(ref PendingLogMessageCount);
		while (queuedCount > MaximumQueuedLogMessages && PendingLogMessages.TryDequeue(out _))
		{
			queuedCount = Interlocked.Decrement(ref PendingLogMessageCount);
		}
	}

	/// <summary>
	/// Flushes the queued logs. The timer keeps running while the Tor session is alive because Tor keeps writing logs.
	/// </summary>
	private void LogTimer_Tick(DispatcherQueueTimer sender, object args)
	{
		FlushPendingLogs();
		StopLogTimerIfIdle();
	}

	/// <summary>
	/// Stops the log timer and displays every remaining message when nothing that writes logs is active.
	/// </summary>
	private void StopLogTimerIfIdle()
	{
		if (IsRunning || TorInitializationCancellationTokenSource is not null || TorSessionManager.IsReady)
		{
			return;
		}

		LogTimer.Stop();
		FlushAllPendingLogs();

		// Tor may have exited on its own, so the Tor buttons are refreshed too.
		UpdateModeControls();
	}

	/// <summary>
	/// Moves every queued log message to the kept log lines.
	/// </summary>
	private void FlushAllPendingLogs()
	{
		while (Volatile.Read(ref PendingLogMessageCount) > 0 && !PendingLogMessages.IsEmpty)
		{
			FlushPendingLogs();
		}
	}

	/// <summary>
	/// Moves a batch of queued log messages to the kept log lines, and updates the displayed text when the logs pane is open.
	/// </summary>
	private void FlushPendingLogs()
	{
		if (Volatile.Read(ref PendingLogMessageCount) == 0)
		{
			return;
		}

		int flushedMessages = 0;
		while (flushedMessages < MaximumLogMessagesPerFlush && PendingLogMessages.TryDequeue(out string? message))
		{
			_ = Interlocked.Decrement(ref PendingLogMessageCount);
			flushedMessages++;

			// A message can span several lines (an exception with its stack trace), and every one of them counts as a line.
			foreach (ReadOnlySpan<char> line in message.AsSpan().EnumerateLines())
			{
				AddLogLine(line.ToString());
			}
		}

		if (flushedMessages == 0)
		{
			return;
		}

		LogTextIsStale = true;
		if (LogsPaneIsOpen)
		{
			RebuildLogText();
		}
	}

	/// <summary>
	/// Adds a line to the kept log lines. When the limit is reached, the line takes the place of the oldest one.
	/// </summary>
	private void AddLogLine(string line)
	{
		if (LogLineCount < MaximumDisplayedLogLines)
		{
			LogLines[(LogLineStart + LogLineCount) % MaximumDisplayedLogLines] = line;
			LogLineCount++;
		}
		else
		{
			LogLineCharacters -= LogLines[LogLineStart].Length;
			LogLines[LogLineStart] = line;
			LogLineStart = (LogLineStart + 1) % MaximumDisplayedLogLines;
		}
		LogLineCharacters += line.Length;
	}

	/// <summary>
	/// Joins the kept log lines, from the oldest to the newest.
	/// </summary>
	private string BuildLogText()
	{
		StringBuilder text = new(LogLineCharacters + (LogLineCount * Environment.NewLine.Length));
		for (int index = 0; index < LogLineCount; index++)
		{
			if (index != 0)
			{
				_ = text.AppendLine();
			}
			_ = text.Append(LogLines[(LogLineStart + index) % MaximumDisplayedLogLines]);
		}
		return text.ToString();
	}

	/// <summary>
	/// Displays the kept log lines.
	/// </summary>
	private void RebuildLogText()
	{
		LogText = BuildLogText();
		LogTextIsStale = false;
	}

	/// <summary>
	/// Stops the running server and Tor when the app is closing.
	/// </summary>
	public void Dispose()
	{
		TrafficTimer.Stop();
		LogTimer.Stop();
		// Cancelled before being disposed so the running work observes the cancellation instead of a disposed source.
		ServerCancellationTokenSource?.Cancel();
		TorInitializationCancellationTokenSource?.Cancel();
		try
		{
			// The server gets a moment to stop, so the domain log is written to its file before the app exits.
			// It runs on the thread pool, so waiting for it here cannot deadlock.
			_ = ActiveServerTask?.Wait(TimeSpan.FromSeconds(3));
		}
		catch (AggregateException)
		{
			// The server ended with its cancellation or with a failure, which no longer matters.
		}
		ServerCancellationTokenSource?.Dispose();
		TorInitializationCancellationTokenSource?.Dispose();
		TorSessionManager.Shutdown();
	}

	/// <summary>
	/// Keeps the logs scrolled to the newest entries.
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(TextBox))]
	internal void LogTextBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		TextBox tb = (TextBox)sender;
		tb.SelectionStart = tb.Text.Length;
	}
}
