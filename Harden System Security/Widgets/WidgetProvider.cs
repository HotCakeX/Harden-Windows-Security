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
using System.Threading;
using System.Threading.Tasks;
using HardenSystemSecurity.WinGet;
using Microsoft.Windows.Widgets;
using Microsoft.Windows.Widgets.Providers;

namespace HardenSystemSecurity.Widgets;

/// <summary>
/// The single widget provider of the app.
///
/// The Widgets Board activates the COM server of this class whenever it needs one of the widgets, then it drives the
/// whole life cycle through the <see cref="IWidgetProvider"/> callbacks. The Widgets platform allows exactly one
/// provider class per widget provider app extension, so every widget definition of the package is served by this one
/// object and the callbacks are routed by <see cref="WidgetContext.DefinitionId"/>.
/// https://learn.microsoft.com/windows/apps/develop/widgets/implement-widget-provider-cs
///
/// The Performance widget is driven by a timer that only samples the machine metrics while at least one pinned instance
/// of it is visible, so it costs nothing while the Widgets Board is closed. The Network widget owns a timer of its own
/// because its throughput has to be refreshed considerably more often, and it only ever measures the one or two
/// adapters that its carousels currently show. The App Updates widget owns no timer at all because its WinGet query is
/// expensive and therefore only ever runs when the user explicitly asks for it.
/// </summary>
internal sealed partial class WidgetProvider : IWidgetProvider
{
	/// <summary>
	/// Must be identical to the "Id" of the Performance widget definition in the package manifest.
	/// </summary>
	internal const string PerformanceWidgetDefinitionId = "HardenSystemSecurity_Performance";

	/// <summary>
	/// Must be identical to the "Id" of the App Updates widget definition in the package manifest.
	/// </summary>
	internal const string WinGetUpdatesWidgetDefinitionId = "HardenSystemSecurity_WinGetUpdates";

	/// <summary>
	/// Must be identical to the "Id" of the Network widget definition in the package manifest.
	/// </summary>
	internal const string NetworkWidgetDefinitionId = "HardenSystemSecurity_Network";

	/// <summary>
	/// The verb of the App Updates widget button that starts a new WinGet update check.
	/// </summary>
	private const string CheckForUpdatesVerb = "checkForWinGetUpdates";

	/// <summary>
	/// The verb of the App Updates widget button that brings the app itself up.
	/// </summary>
	private const string OpenAppVerb = "openApp";

	/// <summary>
	/// The verbs of the four carousel arrows of the Network widget, of which the lower panel only exists on the large size.
	/// </summary>
	private const string NetworkPreviousFirstVerb = "networkPreviousFirst",
		NetworkNextFirstVerb = "networkNextFirst",
		NetworkPreviousSecondVerb = "networkPreviousSecond",
		NetworkNextSecondVerb = "networkNextSecond";

	/// <summary>
	/// The separator between the two adapters that the custom state of a Network widget remembers.
	/// </summary>
	private const char NetworkCustomStateSeparator = '|';

	// How often the live metrics of the Performance widget are refreshed while it is visible.
	private const int UpdateIntervalMilliseconds = 2000;

	// How often the throughput of the Network widget is refreshed while it is visible. Measuring one or two interfaces
	// costs next to nothing, and a second is the very same cadence at which Windows itself reports network activity.
	private const int NetworkUpdateIntervalMilliseconds = 1000;

	// A WinGet update check has to correlate every installed program with its source, which can take a long time on a
	// slow connection, but it must not stay stuck forever either because the widget would keep claiming to be busy.
	private static readonly TimeSpan WinGetUpdateCheckTimeout = TimeSpan.FromMinutes(5);

	/// <summary>
	/// Signaled when the last pinned instance of every widget gets removed so that the COM server process can exit.
	/// </summary>
	internal static readonly ManualResetEvent NoWidgetsRemainingEvent = new(false);

	/// <summary>
	/// The connection to the Widgets Board. A single one serves the whole lifetime of the COM server, because handing
	/// out a card through a freshly acquired manager would create a COM object on every single tick of the sampling
	/// timers, and a headless process that allocates next to nothing lets thousands of them pile up before the garbage
	/// collector ever gets around to releasing them.
	/// </summary>
	private static readonly Lock _widgetManagerLock = new();
	private static WidgetManager? _widgetManager;

	private readonly Lock _stateLock = new();

	// Widget IDs that the Widgets Board currently has pinned, mapped to the widget they belong to, their current
	// visibility and the size that the user pinned them at.
	private readonly Dictionary<string, WidgetState> _widgets = new(StringComparer.OrdinalIgnoreCase);

	private PerformanceMetricsSampler? _sampler;
	private Timer? _timer;

	// Only ever measures the adapters that the visible carousels of the pinned Network widgets currently show.
	private NetworkThroughputSampler? _networkSampler;
	private Timer? _networkTimer;

	// The result of the latest WinGet update check. Every pinned App Updates widget displays the very same machine wide
	// information, therefore a single shared snapshot serves all of them.
	private WinGetUpdatesSnapshot _winGetUpdates = WinGetUpdatesSnapshot.Idle;

	// Guards against a second update check being started while one is already running, no matter how many pinned
	// instances of the widget the button was pressed on.
	private int _winGetUpdateCheckRunning;

	// Guard against a tick of one of the sampling timers being joined by the next one while it is still running.
	private int _performanceTickRunning;
	private int _networkTickRunning;

	/// <summary>
	/// The state of a single pinned widget, which is the widget it belongs to, its visibility, the size that the user
	/// pinned it at, for the Network widget the adapters that its two carousels are parked on, and the card that the
	/// Widgets Board was last given for it.
	///
	/// It is a mutable object rather than a value so that a tick of the sampling timers only touches the fields that
	/// really changed instead of rewriting the whole entry of the dictionary, which is what keeps the steady state of
	/// a provider that runs in the background for days free of avoidable work.
	/// </summary>
	private sealed class WidgetState(string id, string definitionId, bool isActive, WidgetSize size)
	{
		/// <summary>
		/// The identifier that the Widgets Board knows this pinned widget by.
		/// </summary>
		internal string Id => id;

		internal string DefinitionId => definitionId;
		internal bool IsActive { get; set; } = isActive;
		internal WidgetSize Size { get; set; } = size;

		/// <summary>
		/// The locally unique identifier of the adapter that the upper carousel shows, or zero while none was chosen yet.
		/// </summary>
		internal ulong FirstAdapterLuid { get; set; }

		/// <summary>
		/// The locally unique identifier of the adapter that the lower carousel shows, or zero while none was chosen yet.
		/// </summary>
		internal ulong SecondAdapterLuid { get; set; }

		/// <summary>
		/// The template, the data payload and the custom state that the Widgets Board was last given for this widget,
		/// each of them null for as long as it never received one. They are what lets an update carry nothing but the
		/// parts that actually changed, and be skipped altogether when nothing did.
		/// </summary>
		internal string? SentTemplate { get; set; }
		internal string? SentData { get; set; }
		internal string? SentCustomState { get; set; }

		/// <summary>
		/// How many cards were prepared for this widget, and which of them was the last one that actually reached the
		/// Widgets Board. Cards can be prepared by a sampling timer and by a Widgets Board callback at the same time,
		/// and comparing the two numbers is what keeps an older card from landing on top of a newer one.
		/// </summary>
		internal long PreparedSequence { get; set; }
		internal long DeliveredSequence { get; set; }

		/// <summary>
		/// Serializes the cards of this widget on their way to the Widgets Board, so that an older one can never land
		/// on top of a newer one. Every widget has one of its own, because a Widgets Board that is slow to accept the
		/// card of one widget must not hold up any of the others.
		/// </summary>
		internal Lock SendLock { get; } = new();

		/// <summary>
		/// Forgets everything that the Widgets Board was given, which makes the next update carry the whole card again.
		/// </summary>
		internal void ForgetSentCard()
		{
			SentTemplate = null;
			SentData = null;
			SentCustomState = null;
		}
	}

	/// <summary>
	/// A card of a single widget that is ready to be handed to the Widgets Board. Only the parts that changed since the
	/// previous update of that widget are carried, and every part that is null is left untouched by the Widgets Board.
	/// </summary>
	private readonly struct PreparedUpdate(string widgetId, long sequence, string? template, string? data, string? customState)
	{
		internal string WidgetId => widgetId;
		internal long Sequence => sequence;
		internal string? Template => template;
		internal string? Data => data;
		internal string? CustomState => customState;
	}

	private WidgetProvider()
	{
		RecoverPinnedWidgets();

		// A relaunched COM server can already have visible widgets, so the sampling timer has to reflect that right away.
		SynchronizeTimer();
	}

	/// <summary>
	/// Only a single provider object is handed out because every pinned widget shares the same sampler, timer and
	/// WinGet update check.
	/// </summary>
	internal static readonly Lazy<WidgetProvider> Instance = new(static () => new());

	/// <summary>
	/// The COM server can be relaunched while widgets are already pinned, in which case the Widgets Board does not
	/// replay the CreateWidget callbacks, so the already pinned widgets have to be discovered explicitly.
	/// </summary>
	private void RecoverPinnedWidgets()
	{
		try
		{
			WidgetInfo[] widgetInfos = GetWidgetManager().GetWidgetInfos();

			foreach (WidgetInfo widgetInfo in widgetInfos)
			{
				WidgetContext widgetContext = widgetInfo.WidgetContext;

				if (!IsKnownDefinitionId(widgetContext.DefinitionId))
				{
					continue;
				}

				// The carousel positions of a Network widget survive a restart of the COM server because the Widgets
				// Board hands the custom state that was stored with the last update back here.
				ParseNetworkCustomState(widgetInfo.CustomState, out ulong firstAdapterLuid, out ulong secondAdapterLuid);

				_widgets[widgetContext.Id] = new WidgetState(widgetContext.Id, widgetContext.DefinitionId, widgetContext.IsActive, widgetContext.Size)
				{
					FirstAdapterLuid = firstAdapterLuid,
					SecondAdapterLuid = secondAdapterLuid
				};
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Reads back the two adapters that a Network widget was left on, which are stored as their decimal locally unique
	/// identifiers separated by a single character.
	/// </summary>
	private static void ParseNetworkCustomState(string? customState, out ulong firstAdapterLuid, out ulong secondAdapterLuid)
	{
		firstAdapterLuid = 0;
		secondAdapterLuid = 0;

		if (string.IsNullOrEmpty(customState))
		{
			return;
		}

		ReadOnlySpan<char> state = customState.AsSpan();
		int separator = state.IndexOf(NetworkCustomStateSeparator);

		if (separator < 0)
		{
			_ = ulong.TryParse(state, NumberStyles.None, CultureInfo.InvariantCulture, out firstAdapterLuid);
			return;
		}

		_ = ulong.TryParse(state[..separator], NumberStyles.None, CultureInfo.InvariantCulture, out firstAdapterLuid);
		_ = ulong.TryParse(state[(separator + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out secondAdapterLuid);
	}

	/// <summary>
	/// Stores the two adapters that a Network widget is parked on so that they can be restored later on.
	/// </summary>
	private static string BuildNetworkCustomState(ulong firstAdapterLuid, ulong secondAdapterLuid) =>
		string.Create(CultureInfo.InvariantCulture, $"{firstAdapterLuid}{NetworkCustomStateSeparator}{secondAdapterLuid}");

	private static bool IsKnownDefinitionId(string definitionId) =>
		string.Equals(definitionId, PerformanceWidgetDefinitionId, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(definitionId, WinGetUpdatesWidgetDefinitionId, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(definitionId, NetworkWidgetDefinitionId, StringComparison.OrdinalIgnoreCase);

	public void CreateWidget(WidgetContext widgetContext)
	{
		if (!IsKnownDefinitionId(widgetContext.DefinitionId))
		{
			return;
		}

		lock (_stateLock)
		{
			// The Widgets Board is starting this widget over, so the whole card has to be handed to it again.
			GetOrAddWidget(widgetContext).ForgetSentCard();
		}

		UpdateWidget(widgetContext.DefinitionId, widgetContext.Id, widgetContext.Size);
		SynchronizeTimer();
	}

	/// <summary>
	/// The state of a pinned widget, which is created the first time that the Widgets Board mentions it and otherwise
	/// only has its visibility and its size brought up to date, so that everything the widget remembers survives.
	/// It must only be called while <see cref="_stateLock"/> is held.
	/// </summary>
	private WidgetState GetOrAddWidget(WidgetContext widgetContext)
	{
		if (_widgets.TryGetValue(widgetContext.Id, out WidgetState? widgetState))
		{
			widgetState.IsActive = widgetContext.IsActive;
			widgetState.Size = widgetContext.Size;

			return widgetState;
		}

		widgetState = new WidgetState(widgetContext.Id, widgetContext.DefinitionId, widgetContext.IsActive, widgetContext.Size);
		_widgets[widgetContext.Id] = widgetState;

		return widgetState;
	}

	public void DeleteWidget(string widgetId, string customState)
	{
		bool noneLeft;

		lock (_stateLock)
		{
			// Everything that was remembered for the widget, including the card that it was last given, goes with it.
			_ = _widgets.Remove(widgetId);
			noneLeft = _widgets.Count == 0;
		}

		SynchronizeTimer();

		if (noneLeft)
		{
			// Letting the host process shut the COM server down because it is no longer needed by anything.
			_ = NoWidgetsRemainingEvent.Set();
		}
	}

	public void Activate(WidgetContext widgetContext)
	{
		if (!IsKnownDefinitionId(widgetContext.DefinitionId))
		{
			return;
		}

		lock (_stateLock)
		{
			WidgetState widgetState = GetOrAddWidget(widgetContext);
			widgetState.IsActive = true;

			// The widget is about to be shown again, so the card is rebuilt in full instead of relying on what the
			// Widgets Board still has stored for it.
			widgetState.ForgetSentCard();
		}

		UpdateWidget(widgetContext.DefinitionId, widgetContext.Id, widgetContext.Size);
		SynchronizeTimer();
	}

	public void Deactivate(string widgetId)
	{
		lock (_stateLock)
		{
			if (_widgets.TryGetValue(widgetId, out WidgetState? widgetState))
			{
				widgetState.IsActive = false;
			}
		}

		SynchronizeTimer();
	}

	public void OnWidgetContextChanged(WidgetContextChangedArgs contextChangedArgs)
	{
		WidgetContext widgetContext = contextChangedArgs.WidgetContext;

		if (!IsKnownDefinitionId(widgetContext.DefinitionId))
		{
			return;
		}

		lock (_stateLock)
		{
			// The size of the widget changed, which the whole layout of the card depends on, so none of what the
			// Widgets Board was given before still applies.
			GetOrAddWidget(widgetContext).ForgetSentCard();
		}

		// The card is re-sent in order to immediately reflect the new layout.
		UpdateWidget(widgetContext.DefinitionId, widgetContext.Id, widgetContext.Size);
		SynchronizeTimer();
	}

	public void OnActionInvoked(WidgetActionInvokedArgs actionInvokedArgs)
	{
		// The Performance card is purely informational and declares no actions, so only the App Updates verbs and the
		// carousel arrows of the Network widget arrive here.
		string verb = actionInvokedArgs.Verb;

		if (string.Equals(verb, CheckForUpdatesVerb, StringComparison.OrdinalIgnoreCase))
		{
			BeginWinGetUpdateCheck();
		}
		else if (string.Equals(verb, OpenAppVerb, StringComparison.OrdinalIgnoreCase))
		{
			OpenApp();
		}
		else if (string.Equals(verb, NetworkPreviousFirstVerb, StringComparison.OrdinalIgnoreCase))
		{
			MoveNetworkSelection(actionInvokedArgs.WidgetContext.Id, false, -1);
		}
		else if (string.Equals(verb, NetworkNextFirstVerb, StringComparison.OrdinalIgnoreCase))
		{
			MoveNetworkSelection(actionInvokedArgs.WidgetContext.Id, false, 1);
		}
		else if (string.Equals(verb, NetworkPreviousSecondVerb, StringComparison.OrdinalIgnoreCase))
		{
			MoveNetworkSelection(actionInvokedArgs.WidgetContext.Id, true, -1);
		}
		else if (string.Equals(verb, NetworkNextSecondVerb, StringComparison.OrdinalIgnoreCase))
		{
			MoveNetworkSelection(actionInvokedArgs.WidgetContext.Id, true, 1);
		}
	}

	/// <summary>
	/// Brings the app itself up through its app execution alias.
	///
	/// The launch is delegated to the shell instead of being started from this process directly because the widget
	/// provider is a headless COM server without any window of its own.
	///
	/// It runs on the thread pool because it performs cross process COM calls into the shell and the Widgets Board
	/// callback that requested it has to return immediately.
	/// </summary>
	private static void OpenApp() => _ = Task.Run(static () =>
	{
		try
		{
			// The Widgets Board never runs elevated, so this simply launches the app the same way that double clicking
			// its Start menu entry would.
			int launchResult = NativeMethods.launch_unelevated(UnelevatedOperations.AppAliasExecutableName, "--navtag=WinGetManagement", null);

			if (launchResult < 0)
			{
				Logger.Write($"App Updates widget: launching the app failed with HRESULT 0x{launchResult:X8}", LogTypeIntel.Error);
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	});

	/// <summary>
	/// Starts a WinGet update check unless one is already running, and immediately reflects the busy state on every
	/// pinned App Updates widget so the user gets feedback the moment the button is pressed.
	/// </summary>
	private void BeginWinGetUpdateCheck()
	{
		if (Interlocked.CompareExchange(ref _winGetUpdateCheckRunning, 1, 0) is not 0)
		{
			return;
		}

		ApplyWinGetUpdatesSnapshot(WinGetUpdatesSnapshot.Checking);

		// Fire and forget on purpose. The Widgets Board callback must return right away and the whole task body is
		// exception safe, so nothing can ever be left unobserved.
		_ = RunWinGetUpdateCheckAsync();
	}

	private async Task RunWinGetUpdateCheckAsync()
	{
		try
		{
			using CancellationTokenSource cancellationTokenSource = new(WinGetUpdateCheckTimeout);

			List<WinGetAvailableUpdate> updates = await WinGetPackageSearchService.GetAvailableUpdatesAsync(cancellationTokenSource.Token);

			ApplyWinGetUpdatesSnapshot(WinGetUpdatesSnapshot.FromUpdates(updates));
		}
		catch (OperationCanceledException)
		{
			ApplyWinGetUpdatesSnapshot(WinGetUpdatesSnapshot.FromFailure("The update check took too long and was stopped."));
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			ApplyWinGetUpdatesSnapshot(WinGetUpdatesSnapshot.FromFailure(ex.Message));
		}
		finally
		{
			_ = Interlocked.Exchange(ref _winGetUpdateCheckRunning, 0);
		}
	}

	/// <summary>
	/// Stores the latest WinGet update check state and pushes it to every pinned App Updates widget.
	/// </summary>
	private void ApplyWinGetUpdatesSnapshot(WinGetUpdatesSnapshot snapshot)
	{
		List<PreparedUpdate>? updates = null;

		lock (_stateLock)
		{
			_winGetUpdates = snapshot;

			List<WidgetState> winGetWidgets = GetWidgetsOfDefinition(WinGetUpdatesWidgetDefinitionId, onlyActive: false);

			// The layout of the card depends on the size of the widget, so one payload is built per distinct size, of
			// which the App Updates widget only offers the medium and the large one.
			Dictionary<WidgetSize, string> dataPerSize = new(2);

			foreach (WidgetState widgetState in winGetWidgets)
			{
				if (!dataPerSize.TryGetValue(widgetState.Size, out string? data))
				{
					data = WinGetUpdatesWidgetCard.BuildData(snapshot, widgetState.Size);
					dataPerSize[widgetState.Size] = data;
				}

				if (TryPrepareUpdate(widgetState, WinGetUpdatesWidgetCard.Template.Value, data, null, out PreparedUpdate update))
				{
					updates ??= new List<PreparedUpdate>(winGetWidgets.Count);
					updates.Add(update);
				}
			}
		}

		SendUpdates(updates);
	}

	/// <summary>
	/// Collects the pinned widgets of a single widget definition. It must only be called while <see cref="_stateLock"/>
	/// is held.
	/// </summary>
	private List<WidgetState> GetWidgetsOfDefinition(string definitionId, bool onlyActive)
	{
		List<WidgetState> matches = new(_widgets.Count);

		foreach (KeyValuePair<string, WidgetState> widget in _widgets)
		{
			if ((!onlyActive || widget.Value.IsActive) && string.Equals(widget.Value.DefinitionId, definitionId, StringComparison.OrdinalIgnoreCase))
			{
				matches.Add(widget.Value);
			}
		}

		return matches;
	}

	/// <summary>
	/// Starts the sampling timers when at least one widget that needs them is visible and stops them (releasing the PDH
	/// handles of the Performance sampler) otherwise. A single timer and a single sampler serve every pinned widget of
	/// their definition and every metric of their card, which keeps the resource usage of the widgets at the absolute
	/// minimum.
	/// </summary>
	private void SynchronizeTimer()
	{
		bool anyPerformanceActive = false;
		bool anyNetworkActive = false;

		lock (_stateLock)
		{
			foreach (KeyValuePair<string, WidgetState> widget in _widgets)
			{
				if (!widget.Value.IsActive)
				{
					continue;
				}

				if (string.Equals(widget.Value.DefinitionId, PerformanceWidgetDefinitionId, StringComparison.OrdinalIgnoreCase))
				{
					anyPerformanceActive = true;
				}
				else if (string.Equals(widget.Value.DefinitionId, NetworkWidgetDefinitionId, StringComparison.OrdinalIgnoreCase))
				{
					anyNetworkActive = true;
				}

				if (anyPerformanceActive && anyNetworkActive)
				{
					break;
				}
			}

			if (anyPerformanceActive)
			{
				_sampler ??= new PerformanceMetricsSampler();
				_timer ??= new Timer(OnTimerTick, null, UpdateIntervalMilliseconds, UpdateIntervalMilliseconds);
			}
			else
			{
				_timer?.Dispose();
				_timer = null;

				_sampler?.Dispose();
				_sampler = null;
			}

			if (anyNetworkActive)
			{
				_networkSampler ??= new NetworkThroughputSampler();
				_networkTimer ??= new Timer(OnNetworkTimerTick, null, NetworkUpdateIntervalMilliseconds, NetworkUpdateIntervalMilliseconds);
			}
			else
			{
				_networkTimer?.Dispose();
				_networkTimer = null;

				// The sampler holds nothing but managed memory, so dropping it is all that is needed to stop it from
				// keeping the counters of adapters that nothing looks at anymore.
				_networkSampler = null;
			}
		}
	}

	private void OnTimerTick(object? state)
	{
		// A tick that takes longer than the interval of the timer must not be joined by the next one, which would only
		// pile up cross process calls in front of a Widgets Board that is not keeping up with them.
		if (Interlocked.CompareExchange(ref _performanceTickRunning, 1, 0) is not 0)
		{
			return;
		}

		try
		{
			List<WidgetState> activeWidgets;
			bool anyStorageTemperatureConsumer = false;

			lock (_stateLock)
			{
				activeWidgets = GetWidgetsOfDefinition(PerformanceWidgetDefinitionId, onlyActive: true);

				foreach (WidgetState widgetState in activeWidgets)
				{
					// Only the medium and the large card have room for the disk temperature, so the physical drives
					// are not scanned at all while every visible widget is pinned at the small size.
					if (widgetState.Size is not WidgetSize.Small)
					{
						anyStorageTemperatureConsumer = true;
						break;
					}
				}
			}

			if (activeWidgets.Count == 0)
			{
				return;
			}

			// The very last widget can have been hidden in between, in which case the sampler is already gone and
			// bringing it back for a tick that nothing is waiting for would leave its counters open indefinitely.
			if (!TrySampleMetrics(anyStorageTemperatureConsumer, out PerformanceSnapshot snapshot))
			{
				return;
			}

			// The layout of the card depends on the size of the widget, so one payload is built per distinct size.
			Dictionary<WidgetSize, string> dataPerSize = new(3);
			List<PreparedUpdate>? updates = null;

			lock (_stateLock)
			{
				foreach (WidgetState widgetState in activeWidgets)
				{
					if (!dataPerSize.TryGetValue(widgetState.Size, out string? data))
					{
						data = PerformanceWidgetCard.BuildData(snapshot, widgetState.Size);
						dataPerSize[widgetState.Size] = data;
					}

					if (TryPrepareUpdate(widgetState, PerformanceWidgetCard.Template.Value, data, null, out PreparedUpdate update))
					{
						updates ??= new List<PreparedUpdate>(activeWidgets.Count);
						updates.Add(update);
					}
				}
			}

			SendUpdates(updates);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
		finally
		{
			_ = Interlocked.Exchange(ref _performanceTickRunning, 0);
		}
	}

	private void OnNetworkTimerTick(object? state)
	{
		// Just like the metrics of the Performance widget, a measurement that is still running must not be joined by
		// the next one, which would additionally derive its rates from an interval that never really elapsed.
		if (Interlocked.CompareExchange(ref _networkTickRunning, 1, 0) is not 0)
		{
			return;
		}

		try
		{
			RenderNetworkWidgets(null, true);
		}
		finally
		{
			_ = Interlocked.Exchange(ref _networkTickRunning, 0);
		}
	}

	/// <summary>
	/// Rebuilds the card of every visible Network widget, or of a single one of them when <paramref name="onlyWidgetId"/>
	/// is given.
	///
	/// Only the adapters that the carousels of those widgets actually show are measured, which is what keeps the widget
	/// from doing any work for the adapters that nobody looks at.
	/// </summary>
	/// <param name="onlyWidgetId">The single widget to render, or null to render all of the visible ones.</param>
	/// <param name="beginSampleCycle">
	/// Whether a new measurement interval starts. It is only true for the timer, because deriving a rate from the couple
	/// of milliseconds that pass between two renders of the very same tick would produce meaningless numbers.
	/// </param>
	private void RenderNetworkWidgets(string? onlyWidgetId, bool beginSampleCycle)
	{
		try
		{
			List<PreparedUpdate>? updates = null;

			// Neither the sampler nor the adapter list behind it is thread safe, so the payloads are built while the
			// lock is held, and they are handed to the Widgets Board afterwards because that is a cross process call.
			lock (_stateLock)
			{
				List<WidgetState> networkWidgets = GetWidgetsOfDefinition(NetworkWidgetDefinitionId, onlyWidgetId is null);

				if (networkWidgets.Count == 0)
				{
					return;
				}

				_networkSampler ??= new NetworkThroughputSampler();

				if (beginSampleCycle)
				{
					_networkSampler.BeginSampleCycle();
				}

				IReadOnlyList<NetworkAdapter> adapters = _networkSampler.GetAdapters();

				foreach (WidgetState widgetState in networkWidgets)
				{
					if (onlyWidgetId is not null && !string.Equals(widgetState.Id, onlyWidgetId, StringComparison.OrdinalIgnoreCase))
					{
						continue;
					}

					bool isLarge = widgetState.Size is WidgetSize.Large;
					int firstIndex = -1;
					int secondIndex = -1;

					if (adapters.Count > 0)
					{
						firstIndex = NetworkThroughputSampler.IndexOf(adapters, widgetState.FirstAdapterLuid);

						// A freshly pinned widget, and one whose adapter was removed from the machine, both land here.
						if (firstIndex < 0)
						{
							firstIndex = NetworkThroughputSampler.GetPreferredAdapterIndex(adapters);
						}

						// The lower carousel only exists on the large size, therefore nothing is measured for it while
						// the widget has no room to show it, even though its selection is still remembered.
						if (isLarge)
						{
							secondIndex = NetworkThroughputSampler.IndexOf(adapters, widgetState.SecondAdapterLuid);

							if (secondIndex < 0 && adapters.Count > 1)
							{
								secondIndex = (firstIndex + 1) % adapters.Count;
							}
						}
					}

					NetworkPanelData first = BuildNetworkPanel(adapters, firstIndex);
					NetworkPanelData second = BuildNetworkPanel(adapters, secondIndex);

					ulong firstLuid = firstIndex >= 0 ? adapters[firstIndex].InterfaceLuid : widgetState.FirstAdapterLuid;
					ulong secondLuid = secondIndex >= 0 ? adapters[secondIndex].InterfaceLuid : widgetState.SecondAdapterLuid;

					widgetState.FirstAdapterLuid = firstLuid;
					widgetState.SecondAdapterLuid = secondLuid;

					// The selection is only worth persisting when it actually changed, which the comparison against
					// what was last sent takes care of, so a Widgets Board that already knows it is left alone.
					if (TryPrepareUpdate(
						widgetState,
						NetworkWidgetCard.Template.Value,
						NetworkWidgetCard.BuildData(first, second, widgetState.Size),
						BuildNetworkCustomState(firstLuid, secondLuid),
						out PreparedUpdate update))
					{
						updates ??= new List<PreparedUpdate>(networkWidgets.Count);
						updates.Add(update);
					}
				}
			}

			SendUpdates(updates);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Measures the adapter of a single carousel. It must only be called while <see cref="_stateLock"/> is held.
	/// </summary>
	/// <param name="adapters">The adapters that are currently present on the machine.</param>
	/// <param name="index">The adapter to measure, or a negative value when the panel shows nothing at all.</param>
	private NetworkPanelData BuildNetworkPanel(IReadOnlyList<NetworkAdapter> adapters, int index)
	{
		if (index < 0)
		{
			return new NetworkPanelData(string.Empty, 0, adapters.Count, false, default);
		}

		NetworkAdapter adapter = adapters[index];

		// A sample that could not be taken leaves the zeroed out result behind, which is exactly what an adapter that
		// vanished in between two ticks should display.
		_ = _networkSampler!.TrySample(adapter.InterfaceLuid, out NetworkAdapterSample sample);

		return new NetworkPanelData(adapter.Name, index + 1, adapters.Count, adapter.IsConnected, sample);
	}

	/// <summary>
	/// Moves one of the two carousels of a Network widget to the previous or the next adapter and immediately re-renders
	/// that widget so that the user does not have to wait for the next tick of the timer.
	/// </summary>
	/// <param name="widgetId">The widget whose carousel arrow was pressed.</param>
	/// <param name="secondPanel">Whether the lower carousel of the large card was the one that moved.</param>
	/// <param name="step">Minus one for the previous adapter and plus one for the next one.</param>
	private void MoveNetworkSelection(string widgetId, bool secondPanel, int step)
	{
		lock (_stateLock)
		{
			if (!_widgets.TryGetValue(widgetId, out WidgetState? widgetState) ||
				!string.Equals(widgetState.DefinitionId, NetworkWidgetDefinitionId, StringComparison.OrdinalIgnoreCase))
			{
				return;
			}

			_networkSampler ??= new NetworkThroughputSampler();

			IReadOnlyList<NetworkAdapter> adapters = _networkSampler.GetAdapters();

			if (adapters.Count == 0)
			{
				return;
			}

			int currentIndex = NetworkThroughputSampler.IndexOf(adapters, secondPanel ? widgetState.SecondAdapterLuid : widgetState.FirstAdapterLuid);

			if (currentIndex < 0)
			{
				currentIndex = secondPanel ? 0 : NetworkThroughputSampler.GetPreferredAdapterIndex(adapters);
			}

			// Both ends of the carousel wrap around.
			ulong nextLuid = adapters[(currentIndex + step + adapters.Count) % adapters.Count].InterfaceLuid;

			if (secondPanel)
			{
				widgetState.SecondAdapterLuid = nextLuid;
			}
			else
			{
				widgetState.FirstAdapterLuid = nextLuid;
			}
		}

		RenderNetworkWidgets(widgetId, false);
	}

	/// <summary>
	/// Renders the card of a single widget, whichever widget it belongs to.
	/// </summary>
	private void UpdateWidget(string definitionId, string widgetId, WidgetSize size)
	{
		try
		{
			if (string.Equals(definitionId, NetworkWidgetDefinitionId, StringComparison.OrdinalIgnoreCase))
			{
				// The card is rendered from whatever the running measurement interval already produced, because opening
				// a new one just for it would derive its rates from the few milliseconds that passed since the last one.
				RenderNetworkWidgets(widgetId, false);
				return;
			}

			string template;
			string data;

			if (string.Equals(definitionId, PerformanceWidgetDefinitionId, StringComparison.OrdinalIgnoreCase))
			{
				template = PerformanceWidgetCard.Template.Value;
				data = PerformanceWidgetCard.BuildData(SampleMetrics(size is not WidgetSize.Small), size);
			}
			else
			{
				WinGetUpdatesSnapshot snapshot;

				lock (_stateLock)
				{
					snapshot = _winGetUpdates;
				}

				template = WinGetUpdatesWidgetCard.Template.Value;
				data = WinGetUpdatesWidgetCard.BuildData(snapshot, size);
			}

			PreparedUpdate update;

			lock (_stateLock)
			{
				if (!_widgets.TryGetValue(widgetId, out WidgetState? widgetState) ||
					!TryPrepareUpdate(widgetState, template, data, null, out update))
				{
					return;
				}
			}

			SendUpdate(update);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	private PerformanceSnapshot SampleMetrics(bool includeStorageTemperature)
	{
		// The PDH query handles are not thread safe, so sampling happens under the same lock that guards them.
		lock (_stateLock)
		{
			_sampler ??= new PerformanceMetricsSampler();
			return _sampler.Sample(includeStorageTemperature);
		}
	}

	/// <summary>
	/// Measures the machine without ever bringing the sampler back to life, because a sampler that is created for a
	/// widget which is not visible anymore would keep its performance counters open for as long as the process lives.
	/// </summary>
	/// <returns>False when the sampler was already let go of, in which case nothing has to be rendered at all.</returns>
	private bool TrySampleMetrics(bool includeStorageTemperature, out PerformanceSnapshot snapshot)
	{
		// The PDH query handles are not thread safe, so sampling happens under the same lock that guards them.
		lock (_stateLock)
		{
			if (_sampler is null)
			{
				snapshot = default;
				return false;
			}

			snapshot = _sampler.Sample(includeStorageTemperature);
			return true;
		}
	}

	/// <summary>
	/// Works out the parts of a card that the Widgets Board does not have yet, so that a tick which produced exactly the
	/// same numbers as the previous one does not turn into a cross process call at all, and so that the template, which
	/// is by far the largest part of the payload, only travels once per widget instead of once per second.
	///
	/// It must only be called while <see cref="_stateLock"/> is held.
	/// </summary>
	/// <param name="customState">The state to persist, or null when the widget has nothing to remember.</param>
	/// <param name="update">The parts that have to be sent, which is only meaningful when true is returned.</param>
	/// <returns>Whether anything at all has to be handed to the Widgets Board.</returns>
	private static bool TryPrepareUpdate(WidgetState widgetState, string template, string data, string? customState, out PreparedUpdate update)
	{
		update = default;

		// The card cannot be rendered without its template, so nothing is sent when the template file is unreadable.
		if (template.Length == 0)
		{
			return false;
		}

		string? templateToSend = string.Equals(widgetState.SentTemplate, template, StringComparison.Ordinal) ? null : template;
		string? dataToSend = string.Equals(widgetState.SentData, data, StringComparison.Ordinal) ? null : data;

		string? customStateToSend = customState is null || string.Equals(widgetState.SentCustomState, customState, StringComparison.Ordinal)
			? null
			: customState;

		if (templateToSend is null && dataToSend is null && customStateToSend is null)
		{
			return false;
		}

		// What is about to be sent is remembered right away, and it is forgotten again when the call fails, so that a
		// dropped update is retried on the next tick.
		widgetState.SentTemplate = template;
		widgetState.SentData = data;

		if (customState is not null)
		{
			widgetState.SentCustomState = customState;
		}

		widgetState.PreparedSequence++;

		update = new PreparedUpdate(widgetState.Id, widgetState.PreparedSequence, templateToSend, dataToSend, customStateToSend);
		return true;
	}

	/// <summary>
	/// Hands a batch of rendered cards to the Widgets Board. It must only be called while <see cref="_stateLock"/> is
	/// not held, because every one of those calls crosses a process boundary.
	/// </summary>
	private void SendUpdates(List<PreparedUpdate>? updates)
	{
		if (updates is null)
		{
			return;
		}

		foreach (PreparedUpdate update in updates)
		{
			SendUpdate(update);
		}
	}

	/// <summary>
	/// Hands a rendered card to the Widgets Board, and makes the widget rebuild its card from scratch on the next tick
	/// when the call did not go through or when a newer card overtook this one.
	/// </summary>
	private void SendUpdate(in PreparedUpdate update)
	{
		WidgetState? widgetState;

		lock (_stateLock)
		{
			if (!_widgets.TryGetValue(update.WidgetId, out widgetState))
			{
				// The widget was unpinned while its card was being built.
				return;
			}
		}

		// Only one card of this widget at a time travels to the Widgets Board, because an older one that arrived after
		// a newer one would leave it displaying numbers that nothing is ever going to correct again.
		lock (widgetState.SendLock)
		{
			lock (_stateLock)
			{
				if (widgetState.DeliveredSequence >= update.Sequence)
				{
					// A newer card already reached the Widgets Board, and it was prepared under the assumption that
					// everything this one carries had been delivered, so the whole card is rebuilt on the next tick.
					widgetState.ForgetSentCard();
					return;
				}
			}

			bool delivered = TrySendUpdate(update);

			lock (_stateLock)
			{
				if (delivered)
				{
					widgetState.DeliveredSequence = update.Sequence;
				}
				else
				{
					widgetState.ForgetSentCard();
				}
			}
		}
	}

	/// <summary>
	/// Hands the parts of a card that actually changed to the Widgets Board.
	/// </summary>
	/// <returns>Whether the Widgets Board accepted the update.</returns>
	private static bool TrySendUpdate(in PreparedUpdate update)
	{
		try
		{
			// The options object cannot be reused across calls because the widget it targets is fixed at construction
			// time, and because the Widgets Board is free to hold on to it for as long as it wants.
			WidgetUpdateRequestOptions updateOptions = new(update.WidgetId);

			// Properties that are not assigned keep whatever the Widgets Board already stored for the widget, which is
			// what lets an update carry nothing but the handful of numbers that changed since the previous one.
			if (update.Template is not null)
			{
				updateOptions.Template = update.Template;
			}

			if (update.Data is not null)
			{
				updateOptions.Data = update.Data;
			}

			if (update.CustomState is not null)
			{
				updateOptions.CustomState = update.CustomState;
			}

			GetWidgetManager().UpdateWidget(updateOptions);
			return true;
		}
		catch (Exception ex)
		{
			// The Widgets Board may have gone away, in which case the connection that is held on to is worthless and a
			// new one has to be established for the next attempt.
			DropWidgetManager();
			Logger.Write(ex);
			return false;
		}
	}

	/// <summary>
	/// Returns the single connection to the Widgets Board that this process uses, which is kept around instead of being
	/// established for every single update, because each one of those brings a COM proxy into the process that only a
	/// garbage collection can release again.
	/// </summary>
	private static WidgetManager GetWidgetManager()
	{
		lock (_widgetManagerLock)
		{
			return _widgetManager ??= WidgetManager.GetDefault();
		}
	}

	/// <summary>
	/// Throws away the connection to the Widgets Board so that the next call establishes a fresh one.
	/// </summary>
	private static void DropWidgetManager()
	{
		lock (_widgetManagerLock)
		{
			_widgetManager = null;
		}
	}
}
