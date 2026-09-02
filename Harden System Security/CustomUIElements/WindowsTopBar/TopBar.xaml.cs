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
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using CommonCore.AppSettings;
using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.Foundation;
using Windows.Graphics;
using Windows.Storage;
using Windows.UI.ViewManagement;
using WinRT;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

/// <summary>
/// A notch style top bar for Windows that is docked to the top center edge of the primary display.
/// It stays collapsed as a small pill and expands into a compact panel when the pointer hovers over it,
/// then it retracts back into the pill once the pointer leaves it.
/// The panel currently offers five views: the applications launcher, the pinned folders, the metrics of the machine and the
/// world clocks, and every one of them can be tailored by the user, whose choices are persisted via the app settings.
/// </summary>
internal sealed partial class TopBar : Window
{

	/// <summary>
	/// A generated cell of a view together with the transform that its entrance and retraction animations are applied to.
	/// </summary>
	private sealed class TopBarTile(FrameworkElement element, CompositeTransform transform)
	{
		internal FrameworkElement Element => element;
		internal CompositeTransform Transform => transform;
	}

	// The layout metrics of the bar are expressed in DIPs and they are converted into physical pixels with the rasterization scale.
	// They are deliberately small so that the bar takes as little of the display as it possibly can.
	// The notch has two shapes of its own, and the metrics of whichever one is in use are what the collapsed end of
	// every animation is built from, so switching between them changes nothing about the expanded panel.
	private const double StandardCollapsedWidthDips = 196.0;
	private const double StandardCollapsedHeightDips = 34.0;
	private const double StandardCollapsedCornerRadiusDips = 17.0;
	private const double StandardCollapsedGlyphFontSize = 14.0;
	private const double StandardCollapsedLabelFontSize = 12.0;
	private const double StandardCollapsedSpacingDips = 10.0;

	// The lower profile notch. It drops the chevron entirely and shrinks everything that is left of it, so that it
	// takes as little of the top edge of the display as it can while still naming the view that it opens into.
	private const double CompactCollapsedWidthDips = 118.0;
	private const double CompactCollapsedHeightDips = 20.0;
	private const double CompactCollapsedCornerRadiusDips = 7.0;
	private const double CompactCollapsedGlyphFontSize = 10.0;
	private const double CompactCollapsedLabelFontSize = 9.0;
	private const double CompactCollapsedSpacingDips = 5.0;

	private const double ExpandedHeightDips = 92.0;
	private const double ExpandedCornerRadiusDips = 24.0;
	private const double MinimumExpandedWidthDips = 380.0;
	private const double ExpandedContentPaddingDips = 20.0;

	// The bar is docked against the top edge of the display, so its two top corners are never rounded the way that the
	// two bottom ones are. They are flared outwards into the top edge instead, with a concave arc that leaves the side
	// of the bar tangentially and meets the top edge of the display tangentially as well, so that the bar reads as
	// something that grows out of the edge of the display rather than as a shape that merely sits against it.
	// The window is widened by one of these on each side to leave the two arcs somewhere to be drawn.
	private const double TopEdgeFilletRadiusDips = 9.0;

	// The smallest room that the views are ever left with, so that a display too narrow to hold the chrome of the bar
	// still shows something of the active view instead of nothing at all.
	private const double MinimumViewsWidthDips = 120.0;

	// The room that is left underneath the views for the horizontal scroll bar, so that the bar does not sit right on
	// top of the row of cells on the occasions where the active view holds more than the display can take at once.
	private const double ViewsScrollBarClearanceDips = 10.0;

	private const double TileWidthDips = 64.0;
	private const double TileHeightDips = 56.0;
	private const double TileSpacingDips = 4.0;

	// The height that the glyph and each line of the label of a tile take. They are pinned so that a label that wraps
	// onto a second line is always known to fit inside of the tile.
	private const double TileGlyphHeightDips = 20.0;
	private const double TileLabelLineHeightDips = 12.0;
	private const double TileContentSpacingDips = 3.0;
	private const double TileEntranceOffsetDips = 16.0;
	private const double TileMinimumScale = 0.82;
	private const double ClockWidthDips = 78.0;

	// The point of the expansion where the first cell starts to arrive, the span that the arrival of the cells is spread over
	// and the length of the arrival of each individual cell. They are all expressed as a fraction of the expansion.
	private const double TileStaggerStart = 0.25;
	private const double TileStaggerSpan = 0.30;
	private const double TileStaggerWindow = 0.42;

	// How quickly the content of the notch leaves and how the content of the panel arrives, both as a fraction of the expansion.
	private const double CollapsedFadeOutRate = 2.6;
	private const double ExpandedFadeInStart = 0.34;
	private const double ExpandedFadeInWindow = 0.46;

	private const double ExpansionDurationSeconds = 0.42;
	private const double RetractionDurationSeconds = 0.34;
	private const double RetractionDelayMilliseconds = 320.0;

	// How long the cells of a newly selected view take to arrive and how long the bar takes to grow or shrink into the
	// width that the newly selected view needs.
	private const double ViewSwitchDurationSeconds = 0.30;
	private const double WidthTransitionDurationSeconds = 0.32;

	// The overshoot that gives the expansion its springy feeling.
	private const double ExpansionOvershoot = 1.05;

	private const double ProgressEpsilon = 0.0001;

	// How often the metrics of the machine and the world clocks are refreshed while either of those views is on display.
	private const double LiveRefreshIntervalMilliseconds = 1000.0;

	/// <summary>
	/// The largest amount of world clocks that the bar shows.
	/// </summary>
	private const int MaximumClockCount = 7;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/dwmapi/ne-dwmapi-dwmwindowattribute
	/// </summary>
	private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
	private const int DWMWA_BORDER_COLOR = 34;
	private const int DWMWA_SYSTEMBACKDROP_TYPE = 38;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/dwmapi/ne-dwmapi-dwm_window_corner_preference
	/// </summary>
	private const uint DWMWCP_DONOTROUND = 1;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/dwmapi/ne-dwmapi-dwm_systembackdrop_type
	/// </summary>
	private const uint DWMSBT_NONE = 1;

	/// <summary>
	/// Suppresses the drawing of the border of the window entirely.
	/// https://learn.microsoft.com/windows/win32/api/dwmapi/ne-dwmapi-dwmwindowattribute
	/// </summary>
	private const uint DWMWA_COLOR_NONE = 0xFFFFFFFE;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-getwindowlongptrw
	/// </summary>
	private const int GWL_STYLE = -16;
	private const int GWL_EXSTYLE = -20;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/winmsg/window-styles
	/// </summary>
	private const long WS_POPUP = 0x80000000L;
	private const long WS_BORDER = 0x00800000L;
	private const long WS_DLGFRAME = 0x00400000L;
	private const long WS_CAPTION = 0x00C00000L;
	private const long WS_THICKFRAME = 0x00040000L;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/winmsg/extended-window-styles
	/// </summary>
	private const long WS_EX_DLGMODALFRAME = 0x00000001L;
	private const long WS_EX_WINDOWEDGE = 0x00000100L;
	private const long WS_EX_CLIENTEDGE = 0x00000200L;
	private const long WS_EX_STATICEDGE = 0x00020000L;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-setwindowpos
	/// </summary>
	private const uint SWP_NOSIZE = 0x0001;
	private const uint SWP_NOMOVE = 0x0002;
	private const uint SWP_NOZORDER = 0x0004;
	private const uint SWP_NOACTIVATE = 0x0010;
	private const uint SWP_FRAMECHANGED = 0x0020;

	/// <summary>
	/// Sent to every top-level window after the display resolution changes.
	/// https://learn.microsoft.com/windows/win32/gdi/wm-displaychange
	/// </summary>
	private const uint WM_DISPLAYCHANGE = 0x007E;

	/// <summary>
	/// The identifier of the subclass that suppresses the non client area of the bar.
	/// </summary>
	private const uint SubclassId = 1;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/wingdi/nf-wingdi-combinergn
	/// </summary>
	private const int RegionAnd = 1;
	private const int RegionOr = 2;
	private const int RegionError = 0;

	/// <summary>
	/// The opaque colors that the whole client area of the bar is painted with. The bar has to be painted with a solid
	/// color so that no lighter pixel of the window itself can show up along the edges that the window region clips.
	/// </summary>
	private static readonly Windows.UI.Color DarkBarColor = Windows.UI.Color.FromArgb(255, 12, 12, 16);
	private static readonly Windows.UI.Color LightBarColor = Windows.UI.Color.FromArgb(255, 243, 243, 245);

	// Only a single top bar can exist at any given time.
	private static TopBar? _currentInstance;

	/// <summary>
	/// The name of the guard that keeps a single bar on the desktop even when several instances of the app run at the
	/// same time. It is created in the local namespace so that every session of the machine owns a bar of its own.
	/// https://learn.microsoft.com/windows/win32/termserv/kernel-object-namespaces
	/// </summary>
	private const string SingleInstanceGuardName = @"Local\HardenSystemSecurity.WindowsTopBar.SingleInstance";

	// The handle that holds the desktop wide ownership of the bar for as long as this instance of the app shows one.
	private static Mutex? _singleInstanceGuard;

	/// <summary>
	/// Whether a top bar is currently open, which is what the access point of the app reflects.
	/// </summary>
	internal static bool IsOpen => _currentInstance is not null;

	private readonly Stopwatch _animationClock = Stopwatch.StartNew();
	private readonly DispatcherTimer _retractionTimer = new();
	private readonly DispatcherTimer _liveRefreshTimer = new();
	private readonly UISettings _uiSettings = new();
	private readonly IntPtr _windowHandle;

	// The cells of every view, so that switching a view only swaps which list the animations are applied to.
	private readonly Dictionary<TopBarView, List<TopBarTile>> _viewTiles = new(5);

	private readonly TopBarConfiguration _configuration = TopBarConfigurationManager.Load();

	// The labels of the world clocks, kept aside so that the tick does not have to walk the visual tree.
	private readonly List<TextBlock> _clockTimeLabels = new(MaximumClockCount);
	private readonly List<TextBlock> _clockDateLabels = new(MaximumClockCount);
	private readonly List<TimeZoneInfo?> _clockZones = new(MaximumClockCount);

	private List<TopBarTile> _tiles = [];
	private TopBarMetricsSampler? _metricsSampler;
	private TopBarNetworkQualitySampler? _networkQualitySampler;
	private CancellationTokenSource? _networkQualityCancellation;
	private Task? _networkQualityTask;
	private XamlRoot? _xamlRoot;
	private double _rasterizationScale = 1.0;
	private double _expandedWidthDips = MinimumExpandedWidthDips;

	// The current amount of the expansion of the bar. 0 is fully collapsed and 1 is fully expanded.
	private double _progress;

	private double _animationStartProgress;
	private double _animationTargetProgress;
	private double _animationStartSeconds;
	private double _viewSwitchStartSeconds;
	private double _widthTransitionStartSeconds;
	private double _widthTransitionStartDips;
	private double _widthTransitionTargetDips;
	private int _displayLeft;
	private int _displayTop;
	private int _displayWidth;

	// How many flyouts of the bar are currently open. The bar must not retract while any of them is, because a flyout
	// lives in a window of its own, so moving the pointer onto it makes the pointer leave the bar.
	private int _openFlyoutCount;

	private TopBarView _activeView = TopBarView.Apps;

	// The shape that the notch is currently taking, which the collapsed end of every animation is built from.
	private TopBarNotchStyle _notchStyle = TopBarConfigurationManager.LoadNotchStyle();

	// Whether the views are currently leaving room underneath themselves for the horizontal scroll bar.
	private bool _isScrollBarClearanceApplied;

	private bool _isExpansionAnimating;
	private bool _isViewSwitchAnimating;
	private bool _isWidthTransitionAnimating;
	private bool _isRenderHookAttached;
	private bool _isPinned;
	private bool _isFolderDragInProgress;
	private bool _doesFolderDragContainFolders;
	private int _folderDragGeneration;
	private bool _isClosed;

	// Whether the bar is currently being driven by touch, which it has to retract differently from.
	private bool _isTouchInteraction;

	// The presenter of the window, which is kept so that the z order of the bar can be changed later on.
	private readonly OverlappedPresenter _presenter;

	private TopBar()
	{
		InitializeComponent();

		// The bar is not a regular window so it must not show up in the task bar or in the task switcher.
		AppWindow.IsShownInSwitchers = false;

		OverlappedPresenter presenter = OverlappedPresenter.Create();
		presenter.SetBorderAndTitleBar(false, false);
		presenter.IsAlwaysOnTop = Atlas.Settings.WindowsTopBarAlwaysOnTop;
		presenter.IsResizable = false;
		presenter.IsMaximizable = false;
		presenter.IsMinimizable = false;
		AppWindow.SetPresenter(presenter);
		_presenter = presenter;

		_windowHandle = WinRT.Interop.WindowNative.GetWindowHandle(this);

		// The window procedure is subclassed before the frame of the window is touched so that the measurement of the
		// frame is already being answered by the bar itself by the time the frame is recalculated below.
		SuppressNonClientArea();

		// The XamlRoot is not available yet at this point, so the scale is acquired from the window itself
		// in order to have the correct geometry already applied before the bar becomes visible.
		uint dpi = NativeMethods.GetDpiForWindow(_windowHandle);
		_rasterizationScale = dpi == 0U ? 1.0 : dpi / 96.0;

		RemoveWindowBorder();

		// The two menus carry no text of their own in the markup, so every one of their items is named from here.
		AppsViewMenuItem.Text = Atlas.GetStr("TopBarViewApps");
		FoldersViewMenuItem.Text = Atlas.GetStr("TopBarViewFolders");
		PerformanceViewMenuItem.Text = Atlas.GetStr("TopBarViewPerformance");
		ClocksViewMenuItem.Text = Atlas.GetStr("TopBarViewClocks");
		NetworkQualityViewMenuItem.Text = "Network quality";

		NotchStyleMenuItem.Text = Atlas.GetStr("TopBarNotchStyleMenuItem");
		OpenOnHoverMenuItem.Text = Atlas.GetStr("TopBarOpenOnHoverMenuItem");
		AlwaysOnTopMenuItem.Text = Atlas.GetStr("TopBarAlwaysOnTopMenuItem");
		PinMenuItem.Text = Atlas.GetStr("TopBarPinMenuItem");
		StartupMenuItem.Text = Atlas.GetStr("TopBarStartupMenuItem");

		AlwaysOnTopMenuItem.IsChecked = Atlas.Settings.WindowsTopBarAlwaysOnTop;

		ToolTipService.SetToolTip(ViewSwitcherButton, Atlas.GetStr("TopBarViewSwitcherToolTip"));
		ToolTipService.SetToolTip(SettingsButton, Atlas.GetStr("TopBarSettingsToolTip"));
		ToolTipService.SetToolTip(PinMenuItem, Atlas.GetStr("TopBarPinToolTip"));
		ToolTipService.SetToolTip(CloseButton, Atlas.GetStr("TopBarCloseToolTip"));
		ToolTipService.SetToolTip(AddButton, Atlas.GetStr("TopBarAddToolTip"));
		ToolTipService.SetToolTip(NotchStyleMenuItem, Atlas.GetStr("TopBarNotchStyleToolTip"));
		ToolTipService.SetToolTip(StartupMenuItem, Atlas.GetStr("TopBarStartupToolTip"));
		ToolTipService.SetToolTip(OpenOnHoverMenuItem, Atlas.GetStr("TopBarOpenOnHoverToolTip"));
		ToolTipService.SetToolTip(AlwaysOnTopMenuItem, Atlas.GetStr("TopBarAlwaysOnTopToolTip"));

		// Neither of the two menus may let the bar retract while it is open, exactly like the menu of a tile does.
		TrackFlyout(ViewSwitcherMenu);
		TrackFlyout(SettingsMenu);

		// Both hosts keep a fixed size so that the visual tree is not re-laid out while the window is being resized.
		ApplyNotchStyle(_notchStyle);
		ExpandedHost.Height = ExpandedHeightDips;

		AppsPanel.Spacing = TileSpacingDips;
		FoldersPanel.Spacing = TileSpacingDips;

		// Explorer normally runs unelevated, and Windows blocks drag and drop across the lower-to-higher integrity boundary.
		// The root remains present while the bar is collapsed, so it owns the drop target and can reveal the folders view
		// only when the user has allowed hover-driven expansion.
		RootGrid.AllowDrop = !Atlas.IsElevated;

		ApplyMetricCaptions();
		PrepareMetricCells();
		PrepareNetworkQualityView();
		NetworkQualityDestinationBox.SelectedIndex = 0;

		RebuildAppTiles();
		RebuildFolderTiles();
		RebuildClocks();

		SetActiveView(TopBarView.Apps, animate: false);

		// The bar follows the theme of the app, exactly like the main window of the app does.
		AppThemeManager.AppThemeChanged += OnAppThemeChanged;
		_uiSettings.ColorValuesChanged += SystemWideThemeChangedEventHandler;
		ApplyTheme(Atlas.Settings.AppTheme);

		_retractionTimer.Interval = TimeSpan.FromMilliseconds(RetractionDelayMilliseconds);
		_retractionTimer.Tick += OnRetractionTimerTick;

		_liveRefreshTimer.Interval = TimeSpan.FromMilliseconds(LiveRefreshIntervalMilliseconds);
		_liveRefreshTimer.Tick += OnLiveRefreshTimerTick;

		ExpandedHost.SizeChanged += OnExpandedHostSizeChanged;
		ViewsScrollViewer.SizeChanged += OnViewsScrollViewerSizeChanged;
		RootGrid.Loaded += OnRootGridLoaded;
		Activated += OnWindowActivated;

		RefreshDisplayMetrics();
		ApplyState(0.0);
	}

	/// <summary>
	/// Shows the top bar, creating it first if it does not exist yet.
	/// Only a single bar can ever exist on the desktop, even when several instances of the app run at the same time,
	/// which is what the cross process guard below enforces.
	/// </summary>
	internal static void Launch()
	{
		if (_currentInstance is not null)
		{
			_currentInstance.Activate();
			_currentInstance.RemoveWindowBorder();

			return;
		}

		if (!TryAcquireSingleInstanceGuard())
		{
			// Another instance of the app already owns the bar, so the access point is put back into the state that
			// reflects that this instance does not own one.
#if DEBUG
			Logger.Write("The Windows top bar is already open in another instance of the app. Only one top bar can be shown at a time.");
#endif
			return;
		}

		_currentInstance = new TopBar();
		_currentInstance.Activate();

		// Showing the window makes the presenter lay out its own frame again, so the frame is stripped once more afterwards.
		_currentInstance.RemoveWindowBorder();
	}

	/// <summary>
	/// Takes the desktop wide ownership of the bar.
	/// The guard is a named mutex that is merely held open instead of being owned, so it is destroyed by the system as
	/// soon as the last handle to it goes away, which means an instance of the app that is killed can never leave the
	/// bar unavailable to the instances that come after it.
	/// </summary>
	private static bool TryAcquireSingleInstanceGuard()
	{
		try
		{
			Mutex guard = new(false, SingleInstanceGuardName, out bool createdNew);

			if (!createdNew)
			{
				guard.Dispose();

				return false;
			}

			_singleInstanceGuard = guard;

			return true;
		}
		catch (Exception ex)
		{
			// A machine that refuses to hand out the guard must not be left without a bar, so the bar is allowed
			// through and only the desktop wide uniqueness of it is given up.
			Logger.Write(ex);

			return true;
		}
	}

	private static void ReleaseSingleInstanceGuard()
	{
		_singleInstanceGuard?.Dispose();
		_singleInstanceGuard = null;
	}

	/// <summary>
	/// Removes every part of the frame that the system would otherwise draw around the bar.
	/// A top level window carries a non client area that both the desktop window manager and the window manager paint on,
	/// which is what produces the thin outline around the bar, so the window is turned into a plain pop up window that
	/// owns no frame at all and the frame related attributes of the desktop window manager are switched off on top of that.
	/// </summary>
	private void RemoveWindowBorder()
	{
		if (_windowHandle == IntPtr.Zero)
		{
			return;
		}

		// A pop up window that carries none of the frame styles has no non client area whatsoever,
		// so there is nothing left for the window manager to draw a border on.
		long style = NativeMethods.GetWindowLongPtrW(_windowHandle, GWL_STYLE).ToInt64();
		style &= ~(WS_CAPTION | WS_BORDER | WS_DLGFRAME | WS_THICKFRAME);
		style |= WS_POPUP;
		_ = NativeMethods.SetWindowLongPtrW(_windowHandle, GWL_STYLE, (nint)style);

		// The extended styles that add an edge around the window are dropped as well.
		long extendedStyle = NativeMethods.GetWindowLongPtrW(_windowHandle, GWL_EXSTYLE).ToInt64();
		extendedStyle &= ~(WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE | WS_EX_STATICEDGE);
		_ = NativeMethods.SetWindowLongPtrW(_windowHandle, GWL_EXSTYLE, (nint)extendedStyle);

		// A system drawn backdrop is painted behind the non client area as well and it brings its own outline with it.
		ApplyWindowAttribute(DWMWA_SYSTEMBACKDROP_TYPE, DWMSBT_NONE);

		// The silhouette of the bar is produced by the window region, so the corner rounding of the system,
		// which is drawn together with its own outline, must not be applied on top of it.
		ApplyWindowAttribute(DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_DONOTROUND);

		// Suppresses the one pixel border that the desktop window manager draws around every top level window.
		// This is applied last so that none of the attributes above can bring the border back.
		ApplyWindowAttribute(DWMWA_BORDER_COLOR, DWMWA_COLOR_NONE);

		// The changed styles only take effect once the frame of the window is recalculated.
		_ = NativeMethods.SetWindowPos(_windowHandle, IntPtr.Zero, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
	}

	/// <summary>
	/// Applies a single desktop window manager attribute on the bar.
	/// </summary>
	private void ApplyWindowAttribute(int attribute, uint value)
	{
		int result = NativeMethods.DwmSetWindowAttribute(_windowHandle, attribute, ref value, sizeof(uint));

		if (result != 0)
		{
			Logger.Write($"Failed to apply the window attribute {attribute} on the top bar. DwmSetWindowAttribute returned: {result}", LogTypeIntel.Error);
		}
	}

	/// <summary>
	/// Subclasses the window procedure of the bar so that the window never gets a non client area in the first place.
	/// Clearing the frame styles and the attributes of the desktop window manager asks the system not to draw a frame,
	/// while this makes it impossible for one to exist at all, because the size of the frame is what the window itself
	/// reports back when the system asks it to measure its own client area.
	/// </summary>
	private void SuppressNonClientArea()
	{
		if (_windowHandle == IntPtr.Zero)
		{
			return;
		}

		if (!NativeMethods.SetWindowSubclass(_windowHandle, GetSubclassProcedure(), SubclassId, IntPtr.Zero))
		{
			Logger.Write("Failed to subclass the window procedure of the top bar, so the frame of the window could not be suppressed.", LogTypeIntel.Error);
		}
	}

	/// <summary>
	/// The address of the subclass procedure of the bar.
	/// https://learn.microsoft.com/windows/win32/api/commctrl/nc-commctrl-subclassproc
	/// </summary>
	private static IntPtr GetSubclassProcedure()
	{
		unsafe
		{
			return (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, WinMsg, UIntPtr, IntPtr, uint, IntPtr, IntPtr>)&SubClassProc_Unmanaged;
		}
	}

	/// <summary>
	/// Callback for the subclass procedure of the top bar. This method is called by Windows for window messages.
	/// The system asks a window to measure the area that its frame occupies and it asks it to paint that area afterwards,
	/// and both of those requests are answered here instead of being forwarded to the default handling of the window,
	/// which is what leaves the bar without a frame and therefore without the outline that is drawn around it.
	/// </summary>
	[UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvStdcall) })]
	private static IntPtr SubClassProc_Unmanaged(IntPtr hWnd, WinMsg Msg, UIntPtr wParam, IntPtr lParam, uint uIdSubclass, IntPtr dwRefData)
	{
#pragma warning disable IDE0010
		switch (Msg)
		{
			// The rectangle that the system proposes is the new rectangle of the whole window, and whatever is left in it
			// once the message has been handled becomes the client area. Returning without touching it therefore makes the
			// client area cover the entire window and leaves no room at all for a frame to be measured into.
			// https://learn.microsoft.com/windows/win32/winmsg/wm-nccalcsize
			case WinMsg.WM_NCCALCSIZE:
				return IntPtr.Zero;

			// The frame of a window is painted separately from its client area, so the request to paint it is swallowed
			// as well and nothing is ever drawn outside of the content of the bar.
			// https://learn.microsoft.com/windows/win32/gdi/wm-ncpaint
			case WinMsg.WM_NCPAINT:
				return IntPtr.Zero;
			// A dynamic resolution change (such as in a Hyper-V VM) can leave the XAML rasterization scale unchanged, so XamlRoot.Changed
			// is not sufficient to refresh the cached display bounds. Windows sends this message specifically when the
			// display resolution changes, which makes it the authoritative point at which to recalculate the bar.
			case (WinMsg)WM_DISPLAYCHANGE:
				_currentInstance?.QueueDisplayMetricsRefresh();
				break;

			// The subclass has to be released while the window still exists, otherwise it outlives the window.
			// https://learn.microsoft.com/windows/win32/winmsg/wm-ncdestroy
			case WinMsg.WM_NCDESTROY:
				_ = NativeMethods.RemoveWindowSubclass(hWnd, GetSubclassProcedure(), uIdSubclass);
				break;

			default:
				break;
		}
#pragma warning restore IDE0010

		return NativeMethods.DefSubclassProc(hWnd, Msg, wParam, lParam);
	}

	/// <summary>
	/// Event handler for the global theme change event of the app.
	/// </summary>
	private void OnAppThemeChanged(object? sender, AppThemeChangedEventArgs e) => ApplyTheme(e.NewTheme);

	/// <summary>
	/// Event handler for the system wide theme changes that are triggered when the user changes the theme in the
	/// personalization settings of Windows. Only the bar of a app that follows the system has to react to them.
	/// </summary>
	private void SystemWideThemeChangedEventHandler(UISettings sender, object args)
	{
		if (!string.Equals(Atlas.Settings.AppTheme, "Use System Setting", StringComparison.OrdinalIgnoreCase))
		{
			return;
		}

		// The notification arrives on a thread of the system, so the bar is only touched back on its own thread.
		_ = DispatcherQueue.TryEnqueue(() => ApplyTheme(Application.Current.RequestedTheme.ToString()));
	}

	/// <summary>
	/// Applies the supplied theme on the bar. Every brush of the bar is a theme resource, so assigning the requested
	/// theme is enough for all of them, while the two opaque backgrounds are picked here because they have to stay
	/// opaque and therefore cannot be theme resources.
	/// </summary>
	private void ApplyTheme(string? themeName)
	{
		if (_isClosed)
		{
			return;
		}

		ElementTheme requestedTheme = ElementTheme.Default;

		if (string.Equals(themeName, "Light", StringComparison.OrdinalIgnoreCase))
		{
			requestedTheme = ElementTheme.Light;
		}
		else if (string.Equals(themeName, "Dark", StringComparison.OrdinalIgnoreCase))
		{
			requestedTheme = ElementTheme.Dark;
		}

		RootGrid.RequestedTheme = requestedTheme;

		// A bar that follows the system has to resolve which of the two themes the system is currently on, because the
		// background of the bar is a plain color instead of a theme resource.
		bool isDark = requestedTheme == ElementTheme.Default
			? Application.Current.RequestedTheme == ApplicationTheme.Dark
			: requestedTheme == ElementTheme.Dark;

		SolidColorBrush barBrush = new(isDark ? DarkBarColor : LightBarColor);

		RootGrid.Background = barBrush;
		BarBorder.Background = barBrush;
	}

	/// <summary>
	/// Applies the localized caption of every metric of the performance view.
	/// </summary>
	private void ApplyMetricCaptions()
	{
		CpuUsageCaption.Text = Atlas.GetStr("TopBarMetricCpuUsage");
		CpuTemperatureCaption.Text = Atlas.GetStr("TopBarMetricCpuTemperature");
		MemoryCaption.Text = Atlas.GetStr("TopBarMetricMemory");
		StorageTemperatureCaption.Text = Atlas.GetStr("TopBarMetricStorageTemperature");
		DiskActivityCaption.Text = Atlas.GetStr("TopBarMetricDiskActivity");
		NetworkCaption.Text = Atlas.GetStr("TopBarMetricNetwork");
		SystemPowerCaption.Text = Atlas.GetStr("TopBarMetricSystemPower");
		BatteryDischargeCaption.Text = Atlas.GetStr("TopBarMetricBatteryDischarge");
		AppMemoryCaption.Text = Atlas.GetStr("TopBarMetricAppMemory");
	}

	/// <summary>
	/// Gives every cell of the performance view a transform so that the cells can arrive with the very same staggering
	/// that the cells of the other views arrive with. The cells themselves are declared in the markup because they
	/// are a fixed set that never changes.
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	private void PrepareMetricCells()
	{
		List<TopBarTile> tiles = new(PerformancePanel.Children.Count);

		foreach (UIElement child in PerformancePanel.Children)
		{
			if (child is not FrameworkElement cell)
			{
				continue;
			}

			tiles.Add(new TopBarTile(cell, AttachEntranceTransform(cell)));
		}

		_viewTiles[TopBarView.Performance] = tiles;
	}

	/// <summary>
	/// Treats the complete network quality dashboard as a single animated cell.
	/// </summary>
	private void PrepareNetworkQualityView()
	{
		List<TopBarTile> tiles = new(1)
		{
			new TopBarTile(NetworkQualityPanel, AttachEntranceTransform(NetworkQualityPanel))
		};
		_viewTiles[TopBarView.NetworkQuality] = tiles;
	}

	/// <summary>
	/// Gives an element the transform that its entrance and retraction animations are applied to.
	/// </summary>
	private static CompositeTransform AttachEntranceTransform(FrameworkElement element)
	{
		CompositeTransform transform = new()
		{
			ScaleX = TileMinimumScale,
			ScaleY = TileMinimumScale,
			TranslateY = TileEntranceOffsetDips
		};

		element.Opacity = 0.0;
		element.RenderTransformOrigin = new Point(0.5, 0.5);
		element.RenderTransform = transform;

		return transform;
	}

	/// <summary>
	/// Generates the tiles of the applications view from the entries of the bar.
	/// </summary>
	private void RebuildAppTiles()
	{
		AppsPanel.Children.Clear();

		List<TopBarTile> tiles = new(_configuration.Apps.Count);

		foreach (TopBarAppEntry entry in _configuration.Apps)
		{
			// The entry is captured by the handlers so the sender of the event never needs to be cast.
			TopBarTile tile = CreateTile(entry.Glyph, entry.DisplayName, () => LaunchTarget(entry.LaunchTarget), () => RemoveAppEntry(entry), RemoveAllAppEntries);

			AppsPanel.Children.Add(tile.Element);

			tiles.Add(tile);
		}

		_viewTiles[TopBarView.Apps] = tiles;

		if (_activeView == TopBarView.Apps)
		{
			_tiles = tiles;
		}
	}

	/// <summary>
	/// Generates the tiles of the folders view from the entries of the bar.
	/// </summary>
	private void RebuildFolderTiles()
	{
		FoldersPanel.Children.Clear();

		List<TopBarTile> tiles = new(_configuration.Folders.Count);

		foreach (TopBarFolderEntry entry in _configuration.Folders)
		{
			TopBarTile tile = CreateTile("\uE8B7", entry.DisplayName, () => LaunchTarget(entry.FolderPath), () => RemoveFolderEntry(entry), RemoveAllFolderEntries);

			ToolTipService.SetToolTip(tile.Element, entry.FolderPath);

			FoldersPanel.Children.Add(tile.Element);

			tiles.Add(tile);
		}

		_viewTiles[TopBarView.Folders] = tiles;

		if (_activeView == TopBarView.Folders)
		{
			_tiles = tiles;
		}
	}

	[DynamicWindowsRuntimeCast(typeof(StorageFolder))]
	private async void OnFoldersPanelDragEnter(object sender, DragEventArgs e)
	{
		_isFolderDragInProgress = true;
		_doesFolderDragContainFolders = false;
		int dragGeneration = ++_folderDragGeneration;
		e.AcceptedOperation = DataPackageOperation.None;

		if (Atlas.IsElevated || !e.DataView.Contains(StandardDataFormats.StorageItems))
		{
			return;
		}

		try
		{
			IReadOnlyList<IStorageItem> storageItems = await e.DataView.GetStorageItemsAsync();
			if (!_isFolderDragInProgress || dragGeneration != _folderDragGeneration)
			{
				return;
			}

			foreach (IStorageItem storageItem in storageItems)
			{
				if (storageItem is StorageFolder)
				{
					_doesFolderDragContainFolders = true;
					break;
				}
			}

			if (!_doesFolderDragContainFolders)
			{
				return;
			}

			bool isOpening = _isExpansionAnimating && _animationTargetProgress > 0.0;
			bool canAcceptWhileCollapsed = Atlas.Settings.WindowsTopBarOpenOnHover;
			if (!canAcceptWhileCollapsed && _progress <= 0.0 && !isOpening)
			{
				_doesFolderDragContainFolders = false;
				return;
			}

			_retractionTimer.Stop();
			if (_activeView != TopBarView.Folders)
			{
				SetActiveView(TopBarView.Folders, animate: _progress > 0.0);
			}
			if (canAcceptWhileCollapsed && !isOpening && _progress < 1.0)
			{
				StartAnimation(1.0);
			}
		}
		catch (Exception ex)
		{
			_doesFolderDragContainFolders = false;
			Logger.Write(ex);
		}
	}

	private void OnFoldersPanelDragOver(object sender, DragEventArgs e)
	{
		if (!_doesFolderDragContainFolders)
		{
			e.AcceptedOperation = DataPackageOperation.None;
			e.Handled = true;
			return;
		}

		e.AcceptedOperation = DataPackageOperation.Copy;
		e.DragUIOverride.Caption = "Add folder to Top Bar";
		e.DragUIOverride.IsCaptionVisible = true;
		e.DragUIOverride.IsContentVisible = true;
		e.Handled = true;
	}

	private void OnFoldersPanelDragLeave()
	{
		_isFolderDragInProgress = false;
		_doesFolderDragContainFolders = false;
		_folderDragGeneration++;
		if (!_isPinned && !_isClosed)
		{
			_retractionTimer.Stop();
			_retractionTimer.Start();
		}
	}

	[DynamicWindowsRuntimeCast(typeof(StorageFolder))]
	private async void OnFoldersPanelDrop(object sender, DragEventArgs e)
	{
		bool canProcessDrop = _doesFolderDragContainFolders;
		_isFolderDragInProgress = false;
		_doesFolderDragContainFolders = false;
		_folderDragGeneration++;
		if (!canProcessDrop || Atlas.IsElevated || _activeView != TopBarView.Folders)
		{
			return;
		}

		try
		{
			IReadOnlyList<IStorageItem> storageItems = await e.DataView.GetStorageItemsAsync();
			bool configurationChanged = false;
			foreach (IStorageItem storageItem in storageItems)
			{
				if (storageItem is not StorageFolder folder || string.IsNullOrWhiteSpace(folder.Path) || FolderEntryExists(folder.Path))
				{
					continue;
				}

				_configuration.Folders.Add(new TopBarFolderEntry
				{
					DisplayName = string.IsNullOrWhiteSpace(folder.DisplayName) ? folder.Name : folder.DisplayName,
					FolderPath = folder.Path
				});
				configurationChanged = true;
			}

			if (configurationChanged)
			{
				TopBarConfigurationManager.Save(_configuration);
				RebuildFolderTiles();
				SetActiveView(TopBarView.Folders, animate: true);
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	private bool FolderEntryExists(string folderPath)
	{
		string normalizedFolderPath = folderPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
		foreach (TopBarFolderEntry entry in _configuration.Folders)
		{
			string normalizedEntryPath = entry.FolderPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
			if (string.Equals(normalizedEntryPath, normalizedFolderPath, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}
		return false;
	}

	/// <summary>
	/// Builds a single tile of the applications view or of the folders view.
	/// </summary>
	private TopBarTile CreateTile(string glyph, string displayName, Action onInvoked, Action onRemove, Action onRemoveAll)
	{
		FontIcon icon = new()
		{
			Glyph = glyph,
			FontSize = 18.0,
			Height = TileGlyphHeightDips,
			HorizontalAlignment = HorizontalAlignment.Center
		};

		// A name that does not fit on a single line is wrapped onto a second one instead of being cut short, which is
		// what lets a name of two words be read in full. Anything that still does not fit is trimmed, and the whole
		// name remains available on the tool tip of the tile either way.
		TextBlock label = new()
		{
			Text = displayName,
			FontSize = 10.0,
			LineHeight = TileLabelLineHeightDips,
			MaxWidth = TileWidthDips - 8.0,
			MaxLines = 2,
			TextWrapping = TextWrapping.Wrap,
			TextAlignment = TextAlignment.Center,
			TextTrimming = TextTrimming.CharacterEllipsis,
			HorizontalAlignment = HorizontalAlignment.Center
		};

		StackPanel content = new()
		{
			Orientation = Orientation.Vertical,
			Spacing = TileContentSpacingDips,
			HorizontalAlignment = HorizontalAlignment.Center,
			VerticalAlignment = VerticalAlignment.Center
		};

		content.Children.Add(icon);
		content.Children.Add(label);

		Button tile = new()
		{
			Content = content,
			Width = TileWidthDips,
			Height = TileHeightDips,
			Padding = new Thickness(2.0),
			CornerRadius = new CornerRadius(10.0),
			BorderThickness = new Thickness(0.0)
		};

		ToolTipService.SetToolTip(tile, displayName);

		CompositeTransform transform = AttachEntranceTransform(tile);

		tile.Click += (_, _) => onInvoked();

		AttachRemoveMenu(tile, onRemove, onRemoveAll);

		return new TopBarTile(tile, transform);
	}

	/// <summary>
	/// Generates the cells of the clocks view from the entries of the bar.
	/// </summary>
	private void RebuildClocks()
	{
		ClocksPanel.Children.Clear();
		_clockTimeLabels.Clear();
		_clockDateLabels.Clear();
		_clockZones.Clear();

		List<TopBarTile> tiles = new(_configuration.Clocks.Count);

		foreach (TopBarClockEntry entry in _configuration.Clocks)
		{
			// The labels deliberately carry no brush of their own so that they keep following the theme of the bar,
			// and the secondary ones are only toned down with their opacity for the very same reason.
			// Every label is centered inside of its cell so that the trailing room of a cell that is wider than the
			// moment it displays does not read as a gap between the clocks and whatever follows them.
			TextBlock nameLabel = new()
			{
				Text = entry.DisplayName,
				FontSize = 9.0,
				FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
				TextTrimming = TextTrimming.CharacterEllipsis,
				TextAlignment = TextAlignment.Center,
				HorizontalAlignment = HorizontalAlignment.Stretch,
				Opacity = 0.6
			};

			TextBlock timeLabel = new()
			{
				FontSize = 15.0,
				FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
				TextTrimming = TextTrimming.CharacterEllipsis,
				TextAlignment = TextAlignment.Center,
				HorizontalAlignment = HorizontalAlignment.Stretch
			};

			TextBlock dateLabel = new()
			{
				FontSize = 9.0,
				TextTrimming = TextTrimming.CharacterEllipsis,
				TextAlignment = TextAlignment.Center,
				HorizontalAlignment = HorizontalAlignment.Stretch,
				Opacity = 0.6
			};

			StackPanel cell = new()
			{
				Orientation = Orientation.Vertical,
				Width = ClockWidthDips,
				Spacing = 1.0,
				VerticalAlignment = VerticalAlignment.Center
			};

			cell.Children.Add(nameLabel);
			cell.Children.Add(timeLabel);
			cell.Children.Add(dateLabel);

			ClocksPanel.Children.Add(cell);

			_clockTimeLabels.Add(timeLabel);
			_clockDateLabels.Add(dateLabel);

			// The time zone of an entry is resolved once here rather than on every tick, because the lookup allocates
			// and an entry naming a zone the machine does not know about would otherwise throw once per second.
			_clockZones.Add(ResolveTimeZone(entry.TimeZoneId));

			tiles.Add(new TopBarTile(cell, AttachEntranceTransform(cell)));

			AttachRemoveMenu(cell, () => RemoveClockEntry(entry), RemoveAllClockEntries);
		}

		_viewTiles[TopBarView.Clocks] = tiles;

		if (_activeView == TopBarView.Clocks)
		{
			_tiles = tiles;
		}

		UpdateClocks();
	}

	/// <summary>
	/// Attaches the context menu that removes the entry that the supplied element stands for.
	/// The menu is not constrained to the bounds of the bar because the bar is only a few tiles tall and its window is
	/// clipped into a rounded silhouette, so a menu that had to fit inside of it would not be usable.
	/// </summary>
	private void AttachRemoveMenu(FrameworkElement element, Action onRemove, Action onRemoveAll)
	{
		MenuFlyoutItem removeItem = new()
		{
			Text = Atlas.GetStr("TopBarRemoveMenuItem"),
			Icon = new FontIcon { Glyph = "\uE74D" }
		};

		removeItem.Click += (_, _) => onRemove();

		MenuFlyoutItem removeAllItem = new()
		{
			Text = "Remove all",
			Icon = new FontIcon { Glyph = "\uE74D" }
		};
		removeAllItem.Click += (_, _) => onRemoveAll();

		MenuFlyout menu = new()
		{
			ShouldConstrainToRootBounds = false
		};

		menu.Items.Add(removeItem);

		menu.Items.Add(new MenuFlyoutSeparator());
		menu.Items.Add(removeAllItem);
		TrackFlyout(menu);

		element.ContextFlyout = menu;

		// A right click has to bring the menu up even where the element itself does not handle it.
		element.RightTapped += OnElementRightTapped;
	}

	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	private void OnElementRightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (sender is not FrameworkElement element || element.ContextFlyout is not FlyoutBase flyout)
		{
			return;
		}

		flyout.ShowAt(element);

		e.Handled = true;
	}

	/// <summary>
	/// Keeps the bar expanded for as long as the supplied flyout is open.
	/// </summary>
	private void TrackFlyout(FlyoutBase flyout)
	{
		flyout.Opened += OnFlyoutOpened;
		flyout.Closed += OnFlyoutClosed;
	}

	private void OnFlyoutOpened(object? sender, object e)
	{
		_openFlyoutCount++;

		_retractionTimer.Stop();
	}

	private void OnFlyoutClosed(object? sender, object e)
	{
		if (_openFlyoutCount > 0)
		{
			_openFlyoutCount--;
		}

		// The pointer may well have ended up outside of the bar while the flyout was open, so the bar retracts unless
		// it is pinned, exactly like it would have done when the pointer left it.
		if (_openFlyoutCount == 0 && !_isPinned && !_isClosed)
		{
			_retractionTimer.Stop();
			_retractionTimer.Start();
		}
	}

	/// <summary>
	/// Selects the view that the bar shows while it is expanded.
	/// </summary>
	private void SetActiveView(TopBarView view, bool animate)
	{
		if (_activeView == TopBarView.NetworkQuality && view != TopBarView.NetworkQuality)
		{
			StopNetworkQualityTest();
		}
		_activeView = view;

		AppsPanel.Visibility = view == TopBarView.Apps ? Visibility.Visible : Visibility.Collapsed;
		FoldersPanel.Visibility = view == TopBarView.Folders ? Visibility.Visible : Visibility.Collapsed;
		PerformancePanel.Visibility = view == TopBarView.Performance ? Visibility.Visible : Visibility.Collapsed;
		ClocksPanel.Visibility = view == TopBarView.Clocks ? Visibility.Visible : Visibility.Collapsed;
		NetworkQualityPanel.Visibility = view == TopBarView.NetworkQuality ? Visibility.Visible : Visibility.Collapsed;

		AppsViewMenuItem.IsChecked = view == TopBarView.Apps;
		FoldersViewMenuItem.IsChecked = view == TopBarView.Folders;
		PerformanceViewMenuItem.IsChecked = view == TopBarView.Performance;
		ClocksViewMenuItem.IsChecked = view == TopBarView.Clocks;

		// There is nothing to add to the metrics of the machine or to the fixed network quality destination list.
		AddButton.Visibility = view is TopBarView.Performance or TopBarView.NetworkQuality
			? Visibility.Collapsed
			: Visibility.Visible;

		// The bar is full once it holds every clock it can, so the affordance goes away.
		if (view == TopBarView.Clocks && _configuration.Clocks.Count >= MaximumClockCount)
		{
			AddButton.Visibility = Visibility.Collapsed;
		}

		// The notch names the view that the bar opens into, so the collapsed bar always tells what it currently holds.
		CollapsedLabel.Text = GetViewName(view);
		CollapsedGlyph.Glyph = GetViewGlyph(view);

		_tiles = _viewTiles.TryGetValue(view, out List<TopBarTile>? tiles) ? tiles : [];

		UpdateLiveRefreshTimer();

		if (animate && _progress > 0.0)
		{
			// The cells of the newly selected view arrive with the very same staggering that they arrive with when the
			// bar expands, which is what makes switching a view feel like a part of the bar instead of a plain swap.
			ApplyTileStagger(TileStaggerStart);

			_viewSwitchStartSeconds = _animationClock.Elapsed.TotalSeconds;
			_isViewSwitchAnimating = true;

			AttachRenderHook();
		}
		else
		{
			ApplyTileStagger(_progress);
		}
	}

	private void OnAppsViewButtonClick() => SetActiveView(TopBarView.Apps, animate: true);

	/// <summary>
	/// The localized name of a view, which the notch of the collapsed bar is labelled with.
	/// </summary>
	private static string GetViewName(TopBarView view) => view switch
	{
		TopBarView.Folders => Atlas.GetStr("TopBarViewFolders"),
		TopBarView.Performance => Atlas.GetStr("TopBarViewPerformance"),
		TopBarView.Clocks => Atlas.GetStr("TopBarViewClocks"),
		TopBarView.NetworkQuality => "Network quality",
		_ => Atlas.GetStr("TopBarViewApps")
	};

	/// <summary>
	/// The glyph of a view, which is the very same one that the button of the view carries in the switcher.
	/// </summary>
	private static string GetViewGlyph(TopBarView view) => view switch
	{
		TopBarView.Folders => "\uE8B7",
		TopBarView.Performance => "\uE9D9",
		TopBarView.Clocks => "\uE823",
		TopBarView.NetworkQuality => "\uE968",
		_ => "\uECAA"
	};

	private void OnFoldersViewButtonClick() => SetActiveView(TopBarView.Folders, animate: true);

	private void OnPerformanceViewButtonClick() => SetActiveView(TopBarView.Performance, animate: true);

	private void OnClocksViewButtonClick() => SetActiveView(TopBarView.Clocks, animate: true);

	private void OnNetworkQualityViewButtonClick() => SetActiveView(TopBarView.NetworkQuality, animate: true);

	/// <summary>
	/// Adds a new entry to the view that is currently on display.
	/// </summary>
	private void OnAddButtonClick()
	{
		switch (_activeView)
		{
			case TopBarView.Apps:
				AddAppEntry();
				break;

			case TopBarView.Folders:
				AddFolderEntry();
				break;

			case TopBarView.Clocks:
				ShowAddClockFlyout();
				break;

			// The metrics of the machine are read from the machine itself, so there is nothing to add to them.
			case TopBarView.Performance:
			case TopBarView.NetworkQuality:
				break;

			default:
				break;
		}
	}

	/// <summary>
	/// Asks the user for an executable and pins it to the applications view.
	/// </summary>
	private void AddAppEntry()
	{
		try
		{
			string? selectedPath = FileDialogHelper.ShowFilePickerDialog(Atlas.ExecutablesPickerFilter);

			if (string.IsNullOrWhiteSpace(selectedPath))
			{
				return;
			}

			_configuration.Apps.Add(new TopBarAppEntry
			{
				DisplayName = Path.GetFileNameWithoutExtension(selectedPath),
				Glyph = "\uE737",
				LaunchTarget = selectedPath
			});

			TopBarConfigurationManager.Save(_configuration);

			RebuildAppTiles();
			SetActiveView(TopBarView.Apps, animate: true);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Asks the user for a folder and pins it to the folders view.
	/// </summary>
	private void AddFolderEntry()
	{
		try
		{
			string? selectedPath = FileDialogHelper.ShowDirectoryPickerDialog();

			if (string.IsNullOrWhiteSpace(selectedPath))
			{
				return;
			}

			string trimmedPath = selectedPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

			// The name of a folder that sits at the root of a drive is empty, so the path itself is displayed instead.
			string displayName = Path.GetFileName(trimmedPath);

			_configuration.Folders.Add(new TopBarFolderEntry
			{
				DisplayName = string.IsNullOrEmpty(displayName) ? selectedPath : displayName,
				FolderPath = selectedPath
			});

			TopBarConfigurationManager.Save(_configuration);

			RebuildFolderTiles();
			SetActiveView(TopBarView.Folders, animate: true);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Asks the user for the name and for the time zone of a new world clock.
	/// </summary>
	private void ShowAddClockFlyout()
	{
		TextBox nameBox = new()
		{
			PlaceholderText = Atlas.GetStr("TopBarClockNameLabel"),
			Header = Atlas.GetStr("TopBarClockNameLabel"),
			Width = 240.0
		};

		ComboBox timeZoneBox = new()
		{
			Header = Atlas.GetStr("TopBarClockTimeZoneLabel"),
			Width = 240.0
		};

		IReadOnlyCollection<TimeZoneInfo> timeZones = TimeZoneInfo.GetSystemTimeZones();

		foreach (TimeZoneInfo timeZone in timeZones)
		{
			// The display name of a time zone is not available while the app runs in the invariant globalization mode,
			// so the identifier is shown instead, which is readable on its own on Windows.
			string label = string.IsNullOrWhiteSpace(timeZone.DisplayName) ? timeZone.Id : timeZone.DisplayName;

			// The identifier is carried by the item itself so that the selection never has to be matched back by its text.
			timeZoneBox.Items.Add(new ComboBoxItem
			{
				Content = label,
				Tag = timeZone.Id
			});
		}

		Button confirmButton = new()
		{
			Content = Atlas.GetStr("TopBarAddClockConfirm"),
			HorizontalAlignment = HorizontalAlignment.Right
		};

		StackPanel content = new()
		{
			Orientation = Orientation.Vertical,
			Spacing = 8.0
		};

		content.Children.Add(nameBox);
		content.Children.Add(timeZoneBox);
		content.Children.Add(confirmButton);

		Flyout flyout = new()
		{
			Content = content,
			ShouldConstrainToRootBounds = false
		};

		TrackFlyout(flyout);

		confirmButton.Click += (_, _) =>
		{
			if (timeZoneBox.SelectedItem is ComboBoxItem { Tag: string timeZoneId } && !string.IsNullOrWhiteSpace(timeZoneId))
			{
				string displayName = nameBox.Text.Trim();

				_configuration.Clocks.Add(new TopBarClockEntry
				{
					DisplayName = string.IsNullOrEmpty(displayName) ? timeZoneId : displayName,
					TimeZoneId = timeZoneId
				});

				TopBarConfigurationManager.Save(_configuration);

				RebuildClocks();
				SetActiveView(TopBarView.Clocks, animate: true);
			}

			flyout.Hide();
		};

		flyout.ShowAt(AddButton);
	}

	private void RemoveAppEntry(TopBarAppEntry entry)
	{
		if (!_configuration.Apps.Remove(entry))
		{
			return;
		}

		TopBarConfigurationManager.Save(_configuration);

		RebuildAppTiles();
		SetActiveView(TopBarView.Apps, animate: true);
	}

	private void RemoveFolderEntry(TopBarFolderEntry entry)
	{
		if (!_configuration.Folders.Remove(entry))
		{
			return;
		}

		TopBarConfigurationManager.Save(_configuration);

		RebuildFolderTiles();
		SetActiveView(TopBarView.Folders, animate: true);
	}

	private void RemoveClockEntry(TopBarClockEntry entry)
	{
		if (!_configuration.Clocks.Remove(entry))
		{
			return;
		}

		TopBarConfigurationManager.Save(_configuration);

		RebuildClocks();
		SetActiveView(TopBarView.Clocks, animate: true);
	}

	private void RemoveAllAppEntries()
	{
		if (_configuration.Apps.Count == 0)
		{
			return;
		}

		_configuration.Apps.Clear();
		TopBarConfigurationManager.Save(_configuration);
		RebuildAppTiles();
		SetActiveView(TopBarView.Apps, animate: true);
	}

	private void RemoveAllFolderEntries()
	{
		if (_configuration.Folders.Count == 0)
		{
			return;
		}

		_configuration.Folders.Clear();
		TopBarConfigurationManager.Save(_configuration);
		RebuildFolderTiles();
		SetActiveView(TopBarView.Folders, animate: true);
	}

	private void RemoveAllClockEntries()
	{
		if (_configuration.Clocks.Count == 0)
		{
			return;
		}

		_configuration.Clocks.Clear();
		TopBarConfigurationManager.Save(_configuration);
		RebuildClocks();
		SetActiveView(TopBarView.Clocks, animate: true);
	}

	/// <summary>
	/// Hands the supplied target over to the shell, which is what both an executable and a shell location need.
	/// </summary>
	private void LaunchTarget(string target)
	{
		if (string.IsNullOrWhiteSpace(target))
		{
			return;
		}

		try
		{
			_ = Process.Start(new ProcessStartInfo
			{
				FileName = target,
				UseShellExecute = true
			});
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}

		if (!_isPinned)
		{
			StartAnimation(0.0);
		}
	}

	private void OnNetworkQualityDestinationDropDownOpened()
	{
		_openFlyoutCount++;
		_retractionTimer.Stop();
	}

	private void OnNetworkQualityDestinationDropDownClosed()
	{
		if (_openFlyoutCount > 0)
		{
			_openFlyoutCount--;
		}

		if (_openFlyoutCount == 0 && !_isPinned && !_isClosed)
		{
			_retractionTimer.Stop();
			_retractionTimer.Start();
		}
	}

	private async void OnNetworkQualityStartStopButtonClick()
	{
		if (_networkQualityTask is not null)
		{
			StopNetworkQualityTest();
			return;
		}

		string destination = NetworkQualityDestinationBox.Text.Trim();
		if (string.IsNullOrWhiteSpace(destination))
		{
			NetworkQualityStatusText.Text = "Enter an IP address or domain";
			return;
		}

		CancellationTokenSource cancellation = new();
		TopBarNetworkQualitySampler sampler = new();
		_networkQualityCancellation = cancellation;
		_networkQualitySampler = sampler;
		NetworkQualityDestinationBox.IsEnabled = false;
		NetworkQualityStartStopButton.Content = "Stop";
		NetworkQualityStatusText.Text = "Testing " + destination;
		Task task = RunNetworkQualityTestAsync(destination, sampler, cancellation);
		_networkQualityTask = task;
		await task;
	}

	private async Task RunNetworkQualityTestAsync(
		string destination,
		TopBarNetworkQualitySampler sampler,
		CancellationTokenSource cancellation)
	{
		try
		{
			while (!cancellation.IsCancellationRequested && _activeView == TopBarView.NetworkQuality && !_isClosed)
			{
				TopBarNetworkQualitySnapshot snapshot = await sampler.SampleAsync(destination, cancellation.Token);
				cancellation.Token.ThrowIfCancellationRequested();
				if (_isClosed)
				{
					break;
				}
				ApplyNetworkQualitySnapshot(snapshot, sampler.History);
				await Task.Delay(TimeSpan.FromSeconds(1.0), cancellation.Token);
			}
		}
		catch (OperationCanceledException)
		{
			// Stopping the test or leaving the view cancels both the active echo and the delay between echoes.
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			if (!_isClosed)
			{
				NetworkQualityStatusText.Text = "Unable to test destination";
			}
		}
		finally
		{
			sampler.Dispose();
			cancellation.Dispose();
			if (ReferenceEquals(_networkQualitySampler, sampler))
			{
				_networkQualitySampler = null;
				_networkQualityCancellation = null;
				_networkQualityTask = null;
				if (!_isClosed)
				{
					NetworkQualityDestinationBox.IsEnabled = true;
					NetworkQualityStartStopButton.Content = "Start";
					NetworkQualityStatusText.Text = "Stopped";
					NetworkQualityGraphPanel.Children.Clear();
					RefreshCollapsedLabel();
				}
			}
		}
	}

	private void StopNetworkQualityTest() => _networkQualityCancellation?.Cancel();

	private void ApplyNetworkQualitySnapshot(
		TopBarNetworkQualitySnapshot snapshot,
		IReadOnlyCollection<long?> history)
	{
		string currentText = snapshot.Succeeded ? snapshot.CurrentRoundtripMilliseconds.ToString(CultureInfo.InvariantCulture) + " ms" : "Timeout";
		NetworkQualityCurrentValue.Text = "Current: " + currentText;
		NetworkQualityAverageValue.Text = "Average: " + FormatMilliseconds(snapshot.AverageRoundtripMilliseconds);
		NetworkQualityJitterValue.Text = "Jitter: " + FormatMilliseconds(snapshot.JitterMilliseconds);
		NetworkQualityLossValue.Text = "Loss: " + snapshot.PacketLossPercent.ToString("0.0", CultureInfo.InvariantCulture) + "%";
		NetworkQualityLowValue.Text = "Low: " + FormatMilliseconds(snapshot.MinimumRoundtripMilliseconds);
		NetworkQualityHighValue.Text = "High: " + FormatMilliseconds(snapshot.MaximumRoundtripMilliseconds);
		NetworkQualityStatusText.Text = snapshot.Succeeded ? "Receiving replies" : "No reply";
		CollapsedLabel.Text = currentText;
		RebuildNetworkQualityGraph(history);
	}

	private void RebuildNetworkQualityGraph(IReadOnlyCollection<long?> history)
	{
		NetworkQualityGraphPanel.Children.Clear();
		long highest = 1L;
		foreach (long? sample in history)
		{
			if (sample.HasValue)
			{
				highest = Math.Max(highest, sample.Value);
			}
		}

		foreach (long? sample in history)
		{
			double height = sample.HasValue ? Math.Max(3.0, 44.0 * sample.Value / highest) : 44.0;
			Border bar = new()
			{
				Width = 4.0,
				Height = height,
				CornerRadius = new CornerRadius(2.0),
				VerticalAlignment = VerticalAlignment.Bottom,
				Background = new SolidColorBrush(sample.HasValue
					? Windows.UI.Color.FromArgb(255, 52, 199, 89)
					: Windows.UI.Color.FromArgb(255, 255, 69, 58))
			};
			NetworkQualityGraphPanel.Children.Add(bar);
		}
	}

	private static string FormatMilliseconds(double value) => double.IsNaN(value) || value < 0.0
		? "--"
		: value.ToString("0.0", CultureInfo.InvariantCulture) + " ms";

	private static string FormatMilliseconds(long value) => value < 0L
		? "--"
		: value.ToString(CultureInfo.InvariantCulture) + " ms";

	private void RefreshCollapsedLabel()
	{
		CollapsedLabel.Text = GetViewName(_activeView);
		CollapsedGlyph.Glyph = GetViewGlyph(_activeView);
	}

	/// <summary>
	/// The metrics of the machine and the world clocks are only sampled while the view that displays them is on
	/// display and the bar is expanded, so a collapsed bar costs nothing at all.
	/// </summary>
	private void UpdateLiveRefreshTimer()
	{
		bool isNeeded = !_isClosed
			&& _progress > 0.0
			&& (_activeView == TopBarView.Performance || _activeView == TopBarView.Clocks);

		if (isNeeded)
		{
			if (!_liveRefreshTimer.IsEnabled)
			{
				_liveRefreshTimer.Start();
			}

			OnLiveRefreshTimerTick(null, EventArgs.Empty);

			return;
		}

		_liveRefreshTimer.Stop();
	}

	private void OnLiveRefreshTimerTick(object? sender, object e)
	{
		if (_activeView == TopBarView.Performance)
		{
			UpdateMetrics();

			return;
		}

		if (_activeView == TopBarView.Clocks)
		{
			UpdateClocks();
		}
	}

	/// <summary>
	/// Reads every metric of the machine once and applies it on the performance view.
	/// </summary>
	private void UpdateMetrics()
	{
		// The sampler is only created once the metrics are actually looked at, and it is kept alive afterwards because
		// a rate counter needs two collections that are spaced apart in time before it can produce a value.
		_metricsSampler ??= new TopBarMetricsSampler();

		TopBarMetricsSnapshot snapshot = _metricsSampler.Sample();

		CpuUsageValue.Text = FormatPercentage(snapshot.CpuUsagePercent);
		CpuTemperatureValue.Text = FormatTemperature(snapshot.CpuTemperatureCelsius);
		MemoryValue.Text = FormatPercentage(snapshot.MemoryUsagePercent);
		StorageTemperatureValue.Text = FormatTemperature(snapshot.StorageTemperatureCelsius);
		DiskActivityValue.Text = FormatThroughputPair(snapshot.DiskReadBytesPerSecond, snapshot.DiskWriteBytesPerSecond);
		NetworkValue.Text = FormatThroughputPair(snapshot.NetworkReceiveBytesPerSecond, snapshot.NetworkSendBytesPerSecond);
		SystemPowerValue.Text = FormatWatts(snapshot.TotalSystemPowerWatts);
		BatteryDischargeValue.Text = FormatWatts(snapshot.BatteryDischargeWatts);
		AppMemoryValue.Text = FormatBytes(snapshot.AppMemoryBytes);

		// The exact amount of the physical memory does not fit into a cell of this size, so it is offered on demand.
		ToolTipService.SetToolTip(MemoryValue, snapshot.TotalPhysicalBytes > 0UL
			? FormatBytes(snapshot.UsedPhysicalBytes) + " / " + FormatBytes(snapshot.TotalPhysicalBytes)
			: Atlas.GetStr("TopBarMetricUnavailable"));
	}

	/// <summary>
	/// Applies the current moment on every world clock of the bar.
	/// </summary>
	private void UpdateClocks()
	{
		DateTimeOffset now = DateTimeOffset.Now;

		for (int index = 0; index < _clockZones.Count && index < _clockTimeLabels.Count; index++)
		{
			TimeZoneInfo? zone = _clockZones[index];

			DateTimeOffset localized = zone is null ? now : TimeZoneInfo.ConvertTime(now, zone);

			_clockTimeLabels[index].Text = localized.ToString("HH:mm", CultureInfo.InvariantCulture);
			_clockDateLabels[index].Text = localized.ToString("ddd d MMM", CultureInfo.InvariantCulture);
		}
	}

	/// <summary>
	/// Turns the time zone identifier of a clock entry into the zone it names, where an empty identifier and one that
	/// the machine does not know about both fall back to the local time of the machine.
	/// </summary>
	private static TimeZoneInfo? ResolveTimeZone(string timeZoneId)
	{
		if (string.IsNullOrEmpty(timeZoneId))
		{
			return null;
		}

		try
		{
			return TimeZoneInfo.FindSystemTimeZoneById(timeZoneId);
		}
		catch (Exception ex)
		{
			// A time zone that the machine does not know about only makes this single clock fall back to the local
			// time, which is why it must not take the whole rebuild down with it.
			Logger.Write(ex);
			return null;
		}
	}

	private static string FormatPercentage(double value) => double.IsNaN(value)
		? Atlas.GetStr("TopBarMetricUnavailable")
		: value.ToString("0", CultureInfo.InvariantCulture) + "%";

	private static string FormatTemperature(double value) => double.IsNaN(value)
		? Atlas.GetStr("TopBarMetricUnavailable")
		: value.ToString("0", CultureInfo.InvariantCulture) + " \u00B0C";

	private static string FormatWatts(double value) => double.IsNaN(value)
		? Atlas.GetStr("TopBarMetricUnavailable")
		: value.ToString("0.0", CultureInfo.InvariantCulture) + " W";

	/// <summary>
	/// Formats a pair of throughputs into a single compact reading that shares one unit between the two of them,
	/// which is what makes both of them fit into a cell of the bar.
	/// </summary>
	private static string FormatThroughputPair(double first, double second)
	{
		if (double.IsNaN(first) || double.IsNaN(second))
		{
			return Atlas.GetStr("TopBarMetricUnavailable");
		}

		// The unit is picked from the larger of the two so that the smaller one never turns into a row of zeroes.
		double largest = Math.Max(first, second);
		int unitIndex = 0;
		double divisor = 1.0;

		while (unitIndex < 3 && largest / divisor >= 1024.0)
		{
			divisor *= 1024.0;
			unitIndex++;
		}

		string firstText = (first / divisor).ToString(divisor == 1.0 ? "0" : "0.0", CultureInfo.InvariantCulture);
		string secondText = (second / divisor).ToString(divisor == 1.0 ? "0" : "0.0", CultureInfo.InvariantCulture);

		return firstText + " / " + secondText + " " + ThroughputUnits[unitIndex];
	}

	private static readonly string[] ThroughputUnits = ["B/s", "KB/s", "MB/s", "GB/s"];

	private static readonly string[] SizeUnits = ["B", "KB", "MB", "GB", "TB"];

	private static string FormatBytes(ulong value)
	{
		if (value == 0UL)
		{
			return Atlas.GetStr("TopBarMetricUnavailable");
		}

		double amount = value;
		int unitIndex = 0;

		while (unitIndex < SizeUnits.Length - 1 && amount >= 1024.0)
		{
			amount /= 1024.0;
			unitIndex++;
		}

		return amount.ToString(unitIndex == 0 ? "0" : "0.0", CultureInfo.InvariantCulture) + " " + SizeUnits[unitIndex];
	}

	private void QueueDisplayMetricsRefresh()
	{
		_ = DispatcherQueue.TryEnqueue(() =>
		{
			if (_isClosed)
			{
				return;
			}

			RefreshDisplayMetrics();
			UpdateViewsMaximumWidth();
			ApplyState(_progress);
		});
	}

	/// <summary>
	/// Acquires the bounds of the display that the bar is docked to.
	/// </summary>
	private void RefreshDisplayMetrics()
	{
		DisplayArea display = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary);

		// The outer bounds are used instead of the work area so the bar can hug the very top edge of the display.
		RectInt32 bounds = display.OuterBounds;

		_displayLeft = bounds.X;
		_displayTop = bounds.Y;
		_displayWidth = bounds.Width;
	}

	/// <summary>
	/// Applies a single frame of the expansion to the window and to the content of the bar.
	/// </summary>
	/// <param name="progress">0 is the fully collapsed notch and 1 is the fully expanded panel.</param>
	private void ApplyState(double progress)
	{
		double clampedProgress = Math.Max(progress, 0.0);

		// The corner radius must not follow the overshoot of the expansion, otherwise the bar would look inflated.
		double expansion = Math.Min(clampedProgress, 1.0);

		double collapsedWidthDips = _notchStyle == TopBarNotchStyle.Compact ? CompactCollapsedWidthDips : StandardCollapsedWidthDips;
		double collapsedHeightDips = _notchStyle == TopBarNotchStyle.Compact ? CompactCollapsedHeightDips : StandardCollapsedHeightDips;
		double collapsedCornerRadiusDips = _notchStyle == TopBarNotchStyle.Compact ? CompactCollapsedCornerRadiusDips : StandardCollapsedCornerRadiusDips;

		double widthDips = collapsedWidthDips + ((_expandedWidthDips - collapsedWidthDips) * clampedProgress);
		double heightDips = collapsedHeightDips + ((ExpandedHeightDips - collapsedHeightDips) * clampedProgress);
		double cornerRadiusDips = collapsedCornerRadiusDips + ((ExpandedCornerRadiusDips - collapsedCornerRadiusDips) * expansion);

		// The two flares sit outside of the body of the bar, so the window has to carry one of them on each side on top
		// of whatever the body itself takes.
		int filletRadius = (int)Math.Round(TopEdgeFilletRadiusDips * _rasterizationScale);
		int height = (int)Math.Round(heightDips * _rasterizationScale);
		int width = (int)Math.Round(widthDips * _rasterizationScale) + (filletRadius * 2);

		// The overshoot of the expansion must never push the bar outside of the display.
		if (_displayWidth > 0 && width > _displayWidth)
		{
			width = _displayWidth;
		}

		int left = _displayLeft + ((_displayWidth - width) / 2);

		AppWindow.MoveAndResize(new RectInt32(left, _displayTop, width, height));

		ApplyRoundedRegion(width, height, filletRadius, cornerRadiusDips);

		// The two top corners of the bar are never rounded inwards, so only the bottom two follow the expansion.
		BarBorder.CornerRadius = new CornerRadius(0.0, 0.0, cornerRadiusDips, cornerRadiusDips);

		// The content of the notch leaves as soon as the bar starts to grow.
		CollapsedHost.Opacity = Math.Clamp(1.0 - (clampedProgress * CollapsedFadeOutRate), 0.0, 1.0);

		// The content of the panel arrives during the second half of the expansion.
		double expandedOpacity = Math.Clamp((clampedProgress - ExpandedFadeInStart) / ExpandedFadeInWindow, 0.0, 1.0);

		ExpandedHost.Opacity = expandedOpacity;
		ExpandedHost.IsHitTestVisible = expandedOpacity >= 1.0;

		ApplyTileStagger(clampedProgress);
	}

	/// <summary>
	/// Staggers the arrival of the cells of the active view so they do not all appear at the same time.
	/// The very same staggering plays in reverse while the bar retracts because the progress travels backwards.
	/// </summary>
	private void ApplyTileStagger(double progress)
	{
		if (_tiles.Count == 0)
		{
			return;
		}

		// The step is derived from the amount of the cells so the last cell always completes before the expansion does.
		double staggerStep = _tiles.Count > 1 ? TileStaggerSpan / (_tiles.Count - 1) : 0.0;

		for (int index = 0; index < _tiles.Count; index++)
		{
			TopBarTile tile = _tiles[index];

			double tileProgress = Math.Clamp((progress - (TileStaggerStart + (staggerStep * index))) / TileStaggerWindow, 0.0, 1.0);
			double easedTileProgress = EaseOutCubic(tileProgress);
			double tileScale = TileMinimumScale + ((1.0 - TileMinimumScale) * easedTileProgress);

			tile.Element.Opacity = easedTileProgress;
			tile.Transform.TranslateY = (1.0 - easedTileProgress) * TileEntranceOffsetDips;
			tile.Transform.ScaleX = tileScale;
			tile.Transform.ScaleY = tileScale;
		}
	}

	/// <summary>
	/// Clips the window into the silhouette of the bar. The clipped away area is also excluded from the
	/// hit testing of the window, so the parts of the window that are not visible never swallow any input.
	/// The body of the bar is inset by the radius of the flare on both sides, and the strip that is left over on
	/// either side of it only holds the concave arc that carries the bar into the top edge of the display.
	/// </summary>
	private void ApplyRoundedRegion(int width, int height, int filletRadius, double bottomCornerRadiusDips)
	{
		if (_windowHandle == IntPtr.Zero || width <= 0 || height <= 0)
		{
			return;
		}

		// A flare is only ever drawn while there is room for both of them and for a body in between them.
		int fillet = Math.Clamp(filletRadius, 0, (width - 1) / 2);
		fillet = Math.Min(fillet, height);

		int bodyLeft = fillet;
		int bodyRight = width - fillet;

		// The ellipse of the round rectangle region is the diameter of the corner radius in physical pixels.
		int bottomDiameter = Math.Clamp((int)Math.Round(bottomCornerRadiusDips * _rasterizationScale * 2.0), 0, Math.Min(bodyRight - bodyLeft, height));

		IntPtr region = CreateBodyRegion(bodyLeft, bodyRight, height, bottomDiameter);

		if (region == IntPtr.Zero)
		{
			return;
		}

		if (fillet > 0 && !TryAddTopEdgeFillets(region, width, fillet))
		{
			_ = NativeMethods.DeleteObject(region);
			return;
		}

		// The system takes the ownership of the region when the call succeeds, so it is only released when it fails.
		if (NativeMethods.SetWindowRgn(_windowHandle, region, true) == 0)
		{
			_ = NativeMethods.DeleteObject(region);
		}
	}

	/// <summary>
	/// Builds the body of the bar, which is square along its two top corners and rounded along its two bottom ones.
	/// </summary>
	private static IntPtr CreateBodyRegion(int left, int right, int height, int bottomDiameter)
	{
		// The right and the bottom edges of a region are exclusive, so the region ends up covering exactly the body.
		if (bottomDiameter <= 0)
		{
			return NativeMethods.CreateRectRgn(left, 0, right, height);
		}

		IntPtr bodyRegion = NativeMethods.CreateRectRgn(left, 0, right, height);

		if (bodyRegion == IntPtr.Zero)
		{
			return IntPtr.Zero;
		}

		// A round rectangle rounds all four of its corners by the same amount, so the one that carries the two bottom
		// corners is started far enough above the bar for its own two top corners to land outside of the body entirely.
		// Intersecting it with the plain body therefore rounds the bottom of the bar and leaves the top of it square.
		IntPtr bottomRegion = NativeMethods.CreateRoundRectRgn(left, -(height + bottomDiameter), right, height, bottomDiameter, bottomDiameter);

		if (bottomRegion == IntPtr.Zero)
		{
			_ = NativeMethods.DeleteObject(bodyRegion);
			return IntPtr.Zero;
		}

		int combineResult = NativeMethods.CombineRgn(bodyRegion, bodyRegion, bottomRegion, RegionAnd);

		// The rounded rectangle is only ever an ingredient of the intersection, so it is released either way.
		_ = NativeMethods.DeleteObject(bottomRegion);

		if (combineResult == RegionError)
		{
			_ = NativeMethods.DeleteObject(bodyRegion);
			return IntPtr.Zero;
		}

		return bodyRegion;
	}

	/// <summary>
	/// Flares the two top corners of the supplied body outwards into the top edge of the display.
	/// Every row of the flare is added as a single rectangle that runs across the whole bar rather than as two separate
	/// pieces that are butted against the sides of the body, so the flare and the body can never meet along a seam.
	/// Both ends of each of those rows are placed from the very same inset as well, which keeps the two flares exact
	/// mirrors of one another instead of leaving one of them a pixel wider than the other.
	/// </summary>
	private static bool TryAddTopEdgeFillets(IntPtr region, int width, int fillet)
	{
		// Consecutive rows that share an inset are added as one rectangle, and a row whose inset has already reached
		// the side of the body adds nothing at all because the body itself already covers it.
		// The rows are walked from the bottom of the flare upwards because that is the direction in which a row can be
		// told how far it is allowed to reach past the row underneath it.
		int runInset = fillet;
		int runBottom = fillet;

		for (int row = fillet - 1; row >= 0; row--)
		{
			// No row is allowed to reach more than a single pixel past the row underneath it. The arc is almost flat
			// where it meets the top edge of the display, so sampling those last rows on their own lets them jump
			// several pixels outwards at once and leaves a spur sticking out of the top of the flare, which reads as a
			// cut in an otherwise continuous curve. Holding every step down to one pixel keeps the curve unbroken, and
			// because both ends of every row are placed from the very same inset the two flares stay exact mirrors.
			int inset = Math.Max(MeasureFilletInset(row, fillet), runInset - 1);

			if (inset == runInset)
			{
				continue;
			}

			// The run that was open covers every row between the one below the current row and the row it started at.
			if (runInset < fillet && !TryAddRow(region, runInset, row + 1, width - runInset, runBottom))
			{
				return false;
			}

			runInset = inset;
			runBottom = row + 1;
		}

		// Whatever run is still open by the time the top of the flare is reached ends at the top edge of the display.
		return runInset >= fillet || TryAddRow(region, runInset, 0, width - runInset, runBottom);
	}

	/// <summary>
	/// Measures how far the supplied row of the flare sits away from the edge of the window.
	/// The arc is the quarter of the circle that is centred on the point where the side of the body meets the depth of
	/// the flare, which leaves the side of the body vertically and reaches the top edge of the display horizontally.
	/// The row is sampled through its middle so that the arc is not biased towards either of its two ends.
	/// </summary>
	private static int MeasureFilletInset(int row, int fillet)
	{
		double depth = fillet - (row + 0.5);
		double reach = Math.Sqrt((fillet * (double)fillet) - (depth * depth));

		return Math.Clamp((int)Math.Ceiling(reach - 0.5), 0, fillet);
	}

	/// <summary>
	/// Adds a single rectangle to the supplied region.
	/// </summary>
	private static bool TryAddRow(IntPtr region, int left, int top, int right, int bottom)
	{
		IntPtr rowRegion = NativeMethods.CreateRectRgn(left, top, right, bottom);

		if (rowRegion == IntPtr.Zero)
		{
			return false;
		}

		int combineResult = NativeMethods.CombineRgn(region, region, rowRegion, RegionOr);

		// The row is only ever an ingredient of the union, so it is released either way.
		_ = NativeMethods.DeleteObject(rowRegion);

		return combineResult != RegionError;
	}

	/// <summary>
	/// Begins an animation towards the supplied amount of the expansion, starting from wherever the bar currently is.
	/// </summary>
	private void StartAnimation(double targetProgress)
	{
		if (_isClosed || Math.Abs(targetProgress - _progress) < ProgressEpsilon)
		{
			return;
		}

		_animationStartProgress = _progress;
		_animationTargetProgress = targetProgress;
		_animationStartSeconds = _animationClock.Elapsed.TotalSeconds;
		_isExpansionAnimating = true;

		// The expansion drives the cells on its own, so a view switch that is still playing would only fight with it.
		_isViewSwitchAnimating = false;

		AttachRenderHook();
	}

	private void AttachRenderHook()
	{
		if (_isRenderHookAttached)
		{
			return;
		}

		CompositionTarget.Rendering += OnRendering;
		_isRenderHookAttached = true;
	}

	private void DetachRenderHook()
	{
		if (!_isRenderHookAttached)
		{
			return;
		}

		CompositionTarget.Rendering -= OnRendering;
		_isRenderHookAttached = false;
	}

	private void OnRendering(object? sender, object e)
	{
		double now = _animationClock.Elapsed.TotalSeconds;

		// The bar grows into the width of the newly selected view instead of snapping into it.
		if (_isWidthTransitionAnimating)
		{
			double widthProgress = Math.Clamp((now - _widthTransitionStartSeconds) / WidthTransitionDurationSeconds, 0.0, 1.0);

			_expandedWidthDips = _widthTransitionStartDips + ((_widthTransitionTargetDips - _widthTransitionStartDips) * EaseInOutCubic(widthProgress));

			if (widthProgress >= 1.0)
			{
				_expandedWidthDips = _widthTransitionTargetDips;
				_isWidthTransitionAnimating = false;
			}
		}

		if (_isExpansionAnimating)
		{
			bool isExpanding = _animationTargetProgress > _animationStartProgress;
			double duration = isExpanding ? ExpansionDurationSeconds : RetractionDurationSeconds;
			double linearProgress = Math.Clamp((now - _animationStartSeconds) / duration, 0.0, 1.0);
			double easedProgress = isExpanding ? EaseOutBack(linearProgress) : EaseInOutCubic(linearProgress);

			_progress = _animationStartProgress + ((_animationTargetProgress - _animationStartProgress) * easedProgress);

			if (linearProgress >= 1.0)
			{
				_progress = _animationTargetProgress;
				_isExpansionAnimating = false;

				// Sampling only has to run while the bar is actually showing the metrics or the clocks.
				UpdateLiveRefreshTimer();
			}

			ApplyState(_progress);
		}
		else
		{
			if (_isWidthTransitionAnimating)
			{
				ApplyState(_progress);
			}

			if (_isViewSwitchAnimating)
			{
				double switchProgress = Math.Clamp((now - _viewSwitchStartSeconds) / ViewSwitchDurationSeconds, 0.0, 1.0);

				// The staggering of the cells is replayed over the span that it occupies during a full expansion.
				ApplyTileStagger(TileStaggerStart + (switchProgress * (1.0 - TileStaggerStart)));

				if (switchProgress >= 1.0)
				{
					_isViewSwitchAnimating = false;
				}
			}
		}

		// The bar has settled so no more frames are needed.
		if (!_isExpansionAnimating && !_isViewSwitchAnimating && !_isWidthTransitionAnimating)
		{
			DetachRenderHook();
		}
	}

	/// <summary>
	/// Eases out with a slight overshoot past the target, which is what gives the expansion its springy feeling.
	/// </summary>
	private static double EaseOutBack(double progress)
	{
		double shifted = progress - 1.0;
		return 1.0 + (((ExpansionOvershoot + 1.0) * shifted * shifted * shifted) + (ExpansionOvershoot * shifted * shifted));
	}

	private static double EaseInOutCubic(double progress) => progress < 0.5 ? 4.0 * progress * progress * progress : 1.0 - (Math.Pow((-2.0 * progress) + 2.0, 3.0) / 2.0);

	private static double EaseOutCubic(double progress) => 1.0 - Math.Pow(1.0 - progress, 3.0);

	private void OnRootPointerEntered(object sender, PointerRoutedEventArgs e)
	{
		// A touch contact reports itself as entering the bar the moment the finger lands on it, so the bar is remembered
		// as being driven by touch and stays open once it is opened by a tap.
		_isTouchInteraction = e.Pointer.PointerDeviceType == PointerDeviceType.Touch;

		_retractionTimer.Stop();

		// A bar that is set to only open when it is asked to must not follow a pointer that is merely travelling over
		// it on its way somewhere else. A finger is never merely travelling over the bar though, because a contact only
		// ever begins exactly where the user put it, so a touch always opens the bar however the option is set.
		if (!Atlas.Settings.WindowsTopBarOpenOnHover && !_isTouchInteraction)
		{
			return;
		}

		StartAnimation(1.0);
	}

	/// <summary>
	/// Opens a bar that is set to only open when it is asked to.
	/// The bar is opened from the pointer being pressed rather than from a click so that it begins to open the very
	/// moment the notch is touched instead of only once the button is released.
	/// </summary>
	private void OnRootPointerPressed()
	{
		_retractionTimer.Stop();
		StartAnimation(1.0);
	}

	private void OnRootPointerExited(object sender, PointerRoutedEventArgs e)
	{
		// A flyout of the bar lives in a window of its own, so moving the pointer onto it makes the pointer leave the
		// bar, and retracting at that point would take the flyout away from underneath the pointer.
		if (_isPinned || _openFlyoutCount > 0 || _isFolderDragInProgress)
		{
			return;
		}

		// A finger leaves the bar as soon as it is lifted off the display, which is the very moment the user is about to
		// reach for whatever they just uncovered, so a touch driven bar is never retracted by the contact ending.
		// It is retracted instead when it is tapped away from, which arrives as the window being deactivated.
		if (e.Pointer.PointerDeviceType == PointerDeviceType.Touch)
		{
			return;
		}

		_isTouchInteraction = false;

		// The retraction is delayed so that briefly leaving the bar does not immediately collapse it.
		_retractionTimer.Stop();
		_retractionTimer.Start();
	}

	/// <summary>
	/// Retracts a bar that was opened by touch once the user taps away from it, which is the only signal that a touch
	/// driven bar gets that the user is done with it.
	/// </summary>
	private void OnWindowActivated(object sender, WindowActivatedEventArgs e)
	{
		if (e.WindowActivationState != WindowActivationState.Deactivated)
		{
			return;
		}

		if (!_isTouchInteraction || _isPinned || _openFlyoutCount > 0 || _isClosed)
		{
			return;
		}

		_isTouchInteraction = false;

		_retractionTimer.Stop();
		_retractionTimer.Start();
	}

	private void OnRetractionTimerTick(object? sender, object e)
	{
		_retractionTimer.Stop();

		if (_isPinned || _openFlyoutCount > 0)
		{
			return;
		}

		StartAnimation(0.0);
	}

	private void OnPinToggleClick()
	{
		_isPinned = PinMenuItem.IsChecked;

		if (_isPinned)
		{
			_retractionTimer.Stop();
			StartAnimation(1.0);
		}
	}

	/// <summary>
	/// Switches whether the bar stays above every other window, and remembers the choice for the next time the bar is
	/// launched. Changing the z order of the window makes the presenter lay its own frame out again, so the frame of
	/// the bar is stripped once more right afterwards.
	/// </summary>
	private void OnAlwaysOnTopMenuItemClick()
	{
		bool isAlwaysOnTop = AlwaysOnTopMenuItem.IsChecked;

		Atlas.Settings.WindowsTopBarAlwaysOnTop = isAlwaysOnTop;

		_presenter.IsAlwaysOnTop = isAlwaysOnTop;

		RemoveWindowBorder();
	}

	private void OnCloseButtonClick() => Close();

	/// <summary>
	/// Asks Windows to start running the app at sign in, or to stop doing so, and then puts the toggle onto whatever
	/// Windows settled on rather than onto what was asked of it.
	/// </summary>
	private async void OnStartupToggleClick()
	{
		bool requestedState = StartupMenuItem.IsChecked;

		// Nothing else is allowed to be asked of the startup task while one request is still on its way.
		StartupMenuItem.IsEnabled = false;

		TopBarStartupState resultingState = await TopBarStartupManager.SetAsync(requestedState);

		if (_isClosed)
		{
			return;
		}

		ApplyStartupState(resultingState);
	}

	/// <summary>
	/// Reads what Windows currently does with the startup task and puts the toggle onto it.
	/// This has to happen every time the bar appears, because the user can switch the entry off in Task Manager or in
	/// the Startup page of the Settings app at any moment, and the app is never told about it.
	/// </summary>
	private async Task SynchronizeStartupToggleAsync()
	{
		TopBarStartupState currentState = await TopBarStartupManager.GetStateAsync();

		if (_isClosed)
		{
			return;
		}

		ApplyStartupState(currentState);
	}

	/// <summary>
	/// Dresses the toggle of the sign in launch in the state that Windows reports, and remembers that state.
	/// </summary>
	private void ApplyStartupState(TopBarStartupState state)
	{
		bool isEnabled = state is TopBarStartupState.Enabled;

		StartupMenuItem.IsChecked = isEnabled;

		// A user who switched the entry off in Task Manager, and a policy that switched it off, both own it from then
		// on, because Windows forbids any API from overriding either of them. The toggle is therefore put out of reach
		// instead of being left to pretend that the app could still switch it back on.
		bool isBlocked = state is TopBarStartupState.BlockedByUser or TopBarStartupState.BlockedByPolicy or TopBarStartupState.Unavailable;

		StartupMenuItem.IsEnabled = !isBlocked;

		ToolTipService.SetToolTip(StartupMenuItem, state switch
		{
			TopBarStartupState.BlockedByUser => Atlas.GetStr("TopBarStartupBlockedByUserToolTip"),
			TopBarStartupState.BlockedByPolicy => Atlas.GetStr("TopBarStartupBlockedByPolicyToolTip"),
			TopBarStartupState.Unavailable => Atlas.GetStr("TopBarStartupUnavailableToolTip"),
			_ => Atlas.GetStr("TopBarStartupToolTip")
		});

		Atlas.Settings.WindowsTopBarLaunchAtStartup = isEnabled;
	}

	/// <summary>
	/// Switches the notch between its two shapes and remembers the one that it was switched to.
	/// </summary>
	private void OnNotchStyleToggleClick()
	{
		ApplyNotchStyle(NotchStyleMenuItem.IsChecked ? TopBarNotchStyle.Compact : TopBarNotchStyle.Standard);

		TopBarConfigurationManager.SaveNotchStyle(_notchStyle);

		// The geometry of the window is built from the metrics of the notch, so the current frame of the expansion is
		// applied again in order to have the bar take the shape of the notch that it was just switched to.
		ApplyState(_progress);
	}

	/// <summary>
	/// Dresses the notch in the given shape. Only the collapsed end of the bar is touched, because the panel that the
	/// bar expands into looks the very same in both of them.
	/// </summary>
	private void ApplyNotchStyle(TopBarNotchStyle style)
	{
		_notchStyle = style;

		bool isCompact = style == TopBarNotchStyle.Compact;

		CollapsedHost.Height = isCompact ? CompactCollapsedHeightDips : StandardCollapsedHeightDips;
		CollapsedHost.Spacing = isCompact ? CompactCollapsedSpacingDips : StandardCollapsedSpacingDips;

		CollapsedGlyph.FontSize = isCompact ? CompactCollapsedGlyphFontSize : StandardCollapsedGlyphFontSize;
		CollapsedLabel.FontSize = isCompact ? CompactCollapsedLabelFontSize : StandardCollapsedLabelFontSize;

		// The chevron is what the lower profile notch gives up first, because it carries no information of its own.
		CollapsedChevron.Visibility = isCompact ? Visibility.Collapsed : Visibility.Visible;

		NotchStyleMenuItem.IsChecked = isCompact;
	}

	private async void OnRootGridLoaded(object sender, RoutedEventArgs e)
	{
		_xamlRoot = RootGrid.XamlRoot;

		if (_xamlRoot is not null)
		{
			_xamlRoot.Changed += OnXamlRootChanged;

			ApplyRasterizationScale(_xamlRoot.RasterizationScale);
		}

		await SynchronizeStartupToggleAsync();
	}

	/// <summary>
	/// Keeps the geometry of the bar correct when it ends up on a display that has a different scaling.
	/// </summary>
	private void OnXamlRootChanged(XamlRoot sender, XamlRootChangedEventArgs args) => ApplyRasterizationScale(sender.RasterizationScale);

	private void ApplyRasterizationScale(double rasterizationScale)
	{
		if (rasterizationScale <= 0.0 || Math.Abs(rasterizationScale - _rasterizationScale) < ProgressEpsilon)
		{
			return;
		}

		_rasterizationScale = rasterizationScale;

		RefreshDisplayMetrics();
		UpdateViewsMaximumWidth();
		ApplyState(_progress);
	}

	/// <summary>
	/// The expanded width of the bar follows the width that the content of the active view needs.
	/// </summary>
	private void OnExpandedHostSizeChanged(object sender, SizeChangedEventArgs e)
	{
		// The room that the views are allowed to take is settled first, because it is what keeps the width that is
		// derived below inside of the display.
		UpdateViewsMaximumWidth();

		UpdateScrollBarClearance();

		double expandedWidthDips = Math.Max(e.NewSize.Width + (ExpandedContentPaddingDips * 2.0), MinimumExpandedWidthDips);

		// A display that is narrower than the smallest width of the bar still must not be grown past.
		double displayWidthDips = GetDisplayWidthDips();

		if (displayWidthDips > 0.0)
		{
			expandedWidthDips = Math.Min(expandedWidthDips, displayWidthDips);
		}

		if (Math.Abs(expandedWidthDips - _expandedWidthDips) < ProgressEpsilon)
		{
			return;
		}

		// A collapsed bar is not visible at its expanded width, so there is nothing to animate towards.
		if (_progress <= 0.0)
		{
			_expandedWidthDips = expandedWidthDips;
			_isWidthTransitionAnimating = false;

			ApplyState(_progress);

			return;
		}

		_widthTransitionStartDips = _expandedWidthDips;
		_widthTransitionTargetDips = expandedWidthDips;
		_widthTransitionStartSeconds = _animationClock.Elapsed.TotalSeconds;
		_isWidthTransitionAnimating = true;

		AttachRenderHook();
	}

	/// <summary>
	/// Re-evaluates the clearance whenever the panel that hosts the views is resized, which is when a view that no
	/// longer fits inside of it starts to be scrollable.
	/// </summary>
	private void OnViewsScrollViewerSizeChanged(object sender, SizeChangedEventArgs e) => UpdateScrollBarClearance();

	/// <summary>
	/// Leaves room underneath the views for the horizontal scroll bar of the panel, but only while the active view
	/// actually holds more than the panel can show at once, so that a view that fits keeps sitting centered.
	/// </summary>
	private void UpdateScrollBarClearance()
	{
		// The extent is only larger than the viewport once a real layout pass has run, which is exactly when the
		// scroll bar of the panel starts to be drawn on top of the bottom edge of the cells.
		bool isScrollable = ViewsScrollViewer.ExtentWidth - ViewsScrollViewer.ViewportWidth > ProgressEpsilon;

		if (isScrollable == _isScrollBarClearanceApplied)
		{
			return;
		}

		_isScrollBarClearanceApplied = isScrollable;

		ViewsHost.Margin = isScrollable
			? new Thickness(0.0, 0.0, 0.0, ViewsScrollBarClearanceDips)
			: new Thickness(0.0);
	}

	/// <summary>
	/// The width of the display that the bar is docked to, expressed in the units that the layout of the bar is.
	/// </summary>
	private double GetDisplayWidthDips() => _displayWidth <= 0 || _rasterizationScale <= 0.0
		? 0.0
		: _displayWidth / _rasterizationScale;

	/// <summary>
	/// Caps the room that the views are allowed to take at whatever is left of the display once the fixed chrome of the
	/// bar has taken its share, so a view that holds more entries than the display fits scrolls sideways instead of
	/// making the bar reach past the edges of the display.
	/// </summary>
	private void UpdateViewsMaximumWidth()
	{
		double displayWidthDips = GetDisplayWidthDips();

		if (displayWidthDips <= 0.0)
		{
			return;
		}

		double availableWidthDips = Math.Max(
			displayWidthDips - (TopEdgeFilletRadiusDips * 2.0) - MeasureChromeWidthDips() - (ExpandedContentPaddingDips * 2.0),
			MinimumViewsWidthDips);

		if (Math.Abs(availableWidthDips - ViewsScrollViewer.MaxWidth) < ProgressEpsilon)
		{
			return;
		}

		ViewsScrollViewer.MaxWidth = availableWidthDips;
	}

	/// <summary>
	/// The width that everything of the expanded bar other than the views themselves takes, which is measured instead of
	/// being assumed so that it stays correct however the chrome of the bar is arranged.
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	private double MeasureChromeWidthDips()
	{
		double totalWidthDips = 0.0;
		int visibleCount = 0;

		foreach (UIElement child in ExpandedHost.Children)
		{
			if (child is not FrameworkElement element || element.Visibility != Visibility.Visible)
			{
				continue;
			}

			visibleCount++;

			if (ReferenceEquals(child, ViewsScrollViewer))
			{
				continue;
			}

			totalWidthDips += element.ActualWidth;
		}

		if (visibleCount > 1)
		{
			totalWidthDips += ExpandedHost.Spacing * (visibleCount - 1);
		}

		return totalWidthDips;
	}

	private void OnWindowClosed()
	{
		_isClosed = true;
		StopNetworkQualityTest();

		DetachRenderHook();

		_retractionTimer.Stop();
		_retractionTimer.Tick -= OnRetractionTimerTick;

		_liveRefreshTimer.Stop();
		_liveRefreshTimer.Tick -= OnLiveRefreshTimerTick;

		AppThemeManager.AppThemeChanged -= OnAppThemeChanged;
		_uiSettings.ColorValuesChanged -= SystemWideThemeChangedEventHandler;

		ExpandedHost.SizeChanged -= OnExpandedHostSizeChanged;
		ViewsScrollViewer.SizeChanged -= OnViewsScrollViewerSizeChanged;
		RootGrid.Loaded -= OnRootGridLoaded;
		Activated -= OnWindowActivated;
		_xamlRoot?.Changed -= OnXamlRootChanged;
		_xamlRoot = null;

		_metricsSampler?.Dispose();
		_metricsSampler = null;

		_animationClock.Stop();

		if (ReferenceEquals(_currentInstance, this))
		{
			_currentInstance = null;

			// The desktop wide ownership is handed back so that another instance of the app can show a bar afterwards.
			ReleaseSingleInstanceGuard();
		}
	}
}
