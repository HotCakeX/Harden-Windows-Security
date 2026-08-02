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
/// of it is visible, so it costs nothing while the Widgets Board is closed. The App Updates widget owns no timer at all
/// because its WinGet query is expensive and therefore only ever runs when the user explicitly asks for it.
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
	/// The verb of the App Updates widget button that starts a new WinGet update check.
	/// </summary>
	private const string CheckForUpdatesVerb = "checkForWinGetUpdates";

	/// <summary>
	/// The verb of the App Updates widget button that brings the app itself up.
	/// </summary>
	private const string OpenAppVerb = "openApp";

	// How often the live metrics of the Performance widget are refreshed while it is visible.
	private const int UpdateIntervalMilliseconds = 2000;

	// A WinGet update check has to correlate every installed program with its source, which can take a long time on a
	// slow connection, but it must not stay stuck forever either because the widget would keep claiming to be busy.
	private static readonly TimeSpan WinGetUpdateCheckTimeout = TimeSpan.FromMinutes(5);

	/// <summary>
	/// Signaled when the last pinned instance of every widget gets removed so that the COM server process can exit.
	/// </summary>
	internal static readonly ManualResetEvent NoWidgetsRemainingEvent = new(false);

	private static readonly Lock _instanceLock = new();

	private readonly Lock _stateLock = new();

	// Widget IDs that the Widgets Board currently has pinned, mapped to the widget they belong to, their current
	// visibility and the size that the user pinned them at.
	private readonly Dictionary<string, WidgetState> _widgets = new(StringComparer.OrdinalIgnoreCase);

	private PerformanceMetricsSampler? _sampler;
	private Timer? _timer;

	// The result of the latest WinGet update check. Every pinned App Updates widget displays the very same machine wide
	// information, therefore a single shared snapshot serves all of them.
	private WinGetUpdatesSnapshot _winGetUpdates = WinGetUpdatesSnapshot.Idle;

	// Guards against a second update check being started while one is already running, no matter how many pinned
	// instances of the widget the button was pressed on.
	private int _winGetUpdateCheckRunning;

	/// <summary>
	/// The state of a single pinned widget, which is the widget it belongs to, its visibility and the size that the
	/// user pinned it at.
	/// </summary>
	private readonly struct WidgetState(string definitionId, bool isActive, WidgetSize size)
	{
		internal string DefinitionId => definitionId;
		internal bool IsActive => isActive;
		internal WidgetSize Size => size;
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
	internal static WidgetProvider Instance
	{
		get
		{
			lock (_instanceLock)
			{
				field ??= new WidgetProvider();
				return field;
			}
		}
	}

	/// <summary>
	/// The COM server can be relaunched while widgets are already pinned, in which case the Widgets Board does not
	/// replay the CreateWidget callbacks, so the already pinned widgets have to be discovered explicitly.
	/// </summary>
	private void RecoverPinnedWidgets()
	{
		try
		{
			WidgetInfo[] widgetInfos = WidgetManager.GetDefault().GetWidgetInfos();

			foreach (WidgetInfo widgetInfo in widgetInfos)
			{
				WidgetContext widgetContext = widgetInfo.WidgetContext;

				if (!IsKnownDefinitionId(widgetContext.DefinitionId))
				{
					continue;
				}

				_widgets[widgetContext.Id] = new WidgetState(widgetContext.DefinitionId, widgetContext.IsActive, widgetContext.Size);
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	private static bool IsKnownDefinitionId(string definitionId) =>
		string.Equals(definitionId, PerformanceWidgetDefinitionId, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(definitionId, WinGetUpdatesWidgetDefinitionId, StringComparison.OrdinalIgnoreCase);

	public void CreateWidget(WidgetContext widgetContext)
	{
		if (!IsKnownDefinitionId(widgetContext.DefinitionId))
		{
			return;
		}

		lock (_stateLock)
		{
			_widgets[widgetContext.Id] = new WidgetState(widgetContext.DefinitionId, widgetContext.IsActive, widgetContext.Size);
		}

		UpdateWidget(widgetContext.DefinitionId, widgetContext.Id, widgetContext.Size);
		SynchronizeTimer();
	}

	public void DeleteWidget(string widgetId, string customState)
	{
		bool noneLeft;

		lock (_stateLock)
		{
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
			_widgets[widgetContext.Id] = new WidgetState(widgetContext.DefinitionId, true, widgetContext.Size);
		}

		UpdateWidget(widgetContext.DefinitionId, widgetContext.Id, widgetContext.Size);
		SynchronizeTimer();
	}

	public void Deactivate(string widgetId)
	{
		lock (_stateLock)
		{
			if (_widgets.TryGetValue(widgetId, out WidgetState widgetState))
			{
				_widgets[widgetId] = new WidgetState(widgetState.DefinitionId, false, widgetState.Size);
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
			_widgets[widgetContext.Id] = new WidgetState(widgetContext.DefinitionId, widgetContext.IsActive, widgetContext.Size);
		}

		// The size of the widget changed, so the card is re-sent in order to immediately reflect the new layout.
		UpdateWidget(widgetContext.DefinitionId, widgetContext.Id, widgetContext.Size);
		SynchronizeTimer();
	}

	public void OnActionInvoked(WidgetActionInvokedArgs actionInvokedArgs)
	{
		// The Performance card is purely informational and declares no actions, so only the App Updates verbs arrive here.
		if (string.Equals(actionInvokedArgs.Verb, CheckForUpdatesVerb, StringComparison.OrdinalIgnoreCase))
		{
			BeginWinGetUpdateCheck();
		}
		else if (string.Equals(actionInvokedArgs.Verb, OpenAppVerb, StringComparison.OrdinalIgnoreCase))
		{
			OpenApp();
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
		List<KeyValuePair<string, WidgetSize>> winGetWidgets;

		lock (_stateLock)
		{
			_winGetUpdates = snapshot;
			winGetWidgets = GetWidgetsOfDefinition(WinGetUpdatesWidgetDefinitionId, onlyActive: false);
		}

		// The layout of the card depends on the size of the widget, so one payload is built per distinct size, of which
		// the App Updates widget only offers the medium and the large one.
		Dictionary<WidgetSize, string> dataPerSize = new(2);

		foreach (KeyValuePair<string, WidgetSize> widget in winGetWidgets)
		{
			if (!dataPerSize.TryGetValue(widget.Value, out string? data))
			{
				data = WinGetUpdatesWidgetCard.BuildData(snapshot, widget.Value);
				dataPerSize[widget.Value] = data;
			}

			SendUpdate(widget.Key, WinGetUpdatesWidgetCard.Template, data);
		}
	}

	/// <summary>
	/// Collects the pinned widgets of a single widget definition. It must only be called while <see cref="_stateLock"/>
	/// is held.
	/// </summary>
	private List<KeyValuePair<string, WidgetSize>> GetWidgetsOfDefinition(string definitionId, bool onlyActive)
	{
		List<KeyValuePair<string, WidgetSize>> matches = new(_widgets.Count);

		foreach (KeyValuePair<string, WidgetState> widget in _widgets)
		{
			if ((!onlyActive || widget.Value.IsActive) && string.Equals(widget.Value.DefinitionId, definitionId, StringComparison.OrdinalIgnoreCase))
			{
				matches.Add(new KeyValuePair<string, WidgetSize>(widget.Key, widget.Value.Size));
			}
		}

		return matches;
	}

	/// <summary>
	/// Starts the sampling timer when at least one Performance widget is visible and stops it (releasing the PDH
	/// handles) otherwise. A single timer and a single sampler serve every pinned Performance widget and every metric of
	/// the card, which keeps the resource usage of the whole widget at the absolute minimum.
	/// </summary>
	private void SynchronizeTimer()
	{
		bool anyActive = false;

		lock (_stateLock)
		{
			foreach (KeyValuePair<string, WidgetState> widget in _widgets)
			{
				if (widget.Value.IsActive && string.Equals(widget.Value.DefinitionId, PerformanceWidgetDefinitionId, StringComparison.OrdinalIgnoreCase))
				{
					anyActive = true;
					break;
				}
			}

			if (anyActive)
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
		}
	}

	private void OnTimerTick(object? state)
	{
		try
		{
			List<KeyValuePair<string, WidgetSize>> activeWidgets;
			bool anyStorageTemperatureConsumer = false;

			lock (_stateLock)
			{
				activeWidgets = GetWidgetsOfDefinition(PerformanceWidgetDefinitionId, onlyActive: true);

				foreach (KeyValuePair<string, WidgetSize> widget in activeWidgets)
				{
					// Only the medium and the large card have room for the disk temperature, so the physical drives
					// are not scanned at all while every visible widget is pinned at the small size.
					if (widget.Value is not WidgetSize.Small)
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

			PerformanceSnapshot snapshot = SampleMetrics(anyStorageTemperatureConsumer);

			// The layout of the card depends on the size of the widget, so one payload is built per distinct size.
			Dictionary<WidgetSize, string> dataPerSize = new(3);

			foreach (KeyValuePair<string, WidgetSize> widget in activeWidgets)
			{
				if (!dataPerSize.TryGetValue(widget.Value, out string? data))
				{
					data = PerformanceWidgetCard.BuildData(snapshot, widget.Value);
					dataPerSize[widget.Value] = data;
				}

				SendUpdate(widget.Key, PerformanceWidgetCard.Template, data);
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Renders the card of a single widget, whichever widget it belongs to.
	/// </summary>
	private void UpdateWidget(string definitionId, string widgetId, WidgetSize size)
	{
		try
		{
			if (string.Equals(definitionId, PerformanceWidgetDefinitionId, StringComparison.OrdinalIgnoreCase))
			{
				SendUpdate(widgetId, PerformanceWidgetCard.Template, PerformanceWidgetCard.BuildData(SampleMetrics(size is not WidgetSize.Small), size));
				return;
			}

			WinGetUpdatesSnapshot snapshot;

			lock (_stateLock)
			{
				snapshot = _winGetUpdates;
			}

			SendUpdate(widgetId, WinGetUpdatesWidgetCard.Template, WinGetUpdatesWidgetCard.BuildData(snapshot, size));
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

	private static void SendUpdate(string widgetId, string template, string data)
	{
		try
		{
			// The card cannot be rendered without its template, so nothing is sent when the template file is unreadable.
			if (template.Length == 0)
			{
				return;
			}

			WidgetUpdateRequestOptions updateOptions = new(widgetId)
			{
				Template = template,
				Data = data
			};

			WidgetManager.GetDefault().UpdateWidget(updateOptions);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}
}
