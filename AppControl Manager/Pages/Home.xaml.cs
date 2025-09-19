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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using Microsoft.Graphics.Canvas;
using Microsoft.Graphics.Canvas.Brushes;
using Microsoft.Graphics.Canvas.Effects;
using Microsoft.Graphics.Canvas.Geometry;
using Microsoft.Graphics.Canvas.UI.Xaml;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;

#pragma warning disable CA5394

namespace AppControlManager.Pages;

internal sealed partial class Home : Page, IDisposable
{
#if HARDEN_SYSTEM_SECURITY
	private ViewModels.HomeVM ViewModel { get; } = HardenSystemSecurity.ViewModels.ViewModelProvider.HomeVM;
#else
	private ViewModels.HomeVM ViewModel { get; } = ViewModels.ViewModelProvider.HomeVM;
#endif

	// Stage resources
	private CanvasRenderTarget? _noiseTexture;
	private CanvasRenderTarget? _penumbraWarm;
	private CanvasRenderTarget? _penumbraPink;
	private CanvasRenderTarget? _penumbraGreen;
	private CanvasRenderTarget? _penumbraBlue;

	// Edge glow (FULL RASTERIZATION)
	private CanvasRenderTarget? _leftGlowBase;
	private CanvasRenderTarget? _leftGlowBright;
	private CanvasRenderTarget? _rightGlowBase;
	private CanvasRenderTarget? _rightGlowBright;

	private DispatcherTimer? _edgePulseTimer;
	private bool _edgePulseActive;
	private double _edgePulseStartTime;
	private const double _edgePulseDuration = 1.10; // seconds
	private double _edgeLastFrameTime;
	private const double _edgeTargetFrameInterval = 1.0 / 30.0; // ~30 FPS while pulsing

	private static readonly Random _random = new(0x5A17C3);

	private int _currentStageIndex;

	private static readonly TimeSpan SlideDuration = TimeSpan.FromMilliseconds(520);
	private static readonly TimeSpan ScaleDuration = TimeSpan.FromMilliseconds(420);

	private const double StageWidthRatio = 1;

	// Lazy stage content (UserControls)
	private UserControl? Stage1Content;
	private UserControl? Stage2Content;
	private UserControl? Stage3Content;
	private UserControl? Stage4Content;

	// Global timings
	private static readonly Stopwatch _animationStopwatch = Stopwatch.StartNew();
	private double _animationTimeSeconds;
	private bool _renderHookAttached;

	// Idle gating flags (avoids continuous redraws)
	private bool _needsStageRedrawAll;
	private bool _needsBackgroundRedrawOnce;

	// Web Background (clustered twinkles)

	private struct BgNode
	{
		internal float BaseX;
		internal float BaseY;
		internal float PhaseX;
		internal float PhaseY;
		internal float Seed;
		internal byte Layer;
	}

	private struct BgEdge
	{
		internal int A;
		internal int B;
		internal byte Layer;
	}

	private struct StarEdgePersist
	{
		internal int A;
		internal int B;
		internal byte Layer;
		internal double ExpireAt;
	}

	private BgNode[]? _bgNodes;
	private int _bgNodeCount;
	private BgEdge[]? _bgEdges;
	private int _bgEdgeCount;

	private List<StarEdgePersist>? _bgStarEdges;

	private float _bgLastW;
	private float _bgLastH;

	private double _bgLastEdgeRebuildTime;
	private double _bgLastStarCreateTime;

	// Background "twinkle" cadence (single frame)
	private double _bgNextTwinkleTime;

	// Glitch burst timer that fires every 4 seconds for short, single-run storyboards.
	private DispatcherTimer? _glitchTimer;

	// Swipe detection for touch navigation of the main stage area.
	private Point _swipeStartPoint;
	private double _swipeStartTimeSec;
	private const double SwipeMinDistance = 48.0;  // pixels
	private const double SwipeMaxDuration = 0.80;  // seconds
	private const double SwipeHorizontalBias = 1.2; // horizontal dominance over vertical

	internal Home()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	// Teardown and remove Item3's stage so its WebView2 is completely destroyed.
	private void TearDownStage3Content()
	{
#pragma warning disable IDE0001
		if (Stage3Content is AppControlManager.CustomUIElements.HomePageStageContents.Item3 item3)
#pragma warning restore IDE0001
		{
			// Stop playback immediately and navigate to blank.
			try
			{
				item3.StopAndTearDown();
			}
			catch { }
		}

		// Detach from visual tree to trigger Unloaded and allow GC to collect the WebView2 instance.
		if (ReferenceEquals(StagePresenter2.Content, Stage3Content))
		{
			StagePresenter2.Content = null;
		}

		Stage3Content = null;
	}
	private void OnInitialLoaded(object sender, RoutedEventArgs e)
	{
		UpdateCarouselLayout(StageCarouselViewport.ActualWidth);
		EnsureStageContent(0);
		EnsureStageContent(1);
		EnsureStageContent(2);
		EnsureStageContent(3);

		// One-time draws on load
		_needsStageRedrawAll = true;
		_needsBackgroundRedrawOnce = true;

		AttachRenderHook();

		// Initial invalidations
		if (BackgroundCanvas != null)
		{
			BackgroundCanvas.Invalidate();
			_needsBackgroundRedrawOnce = false;
		}
		InvalidateAllStageCanvasesOnce();

		// Edge glow pulse timer: one brief pulse every 14–20s (jitter)
		_edgePulseTimer = new DispatcherTimer
		{
			Interval = TimeSpan.FromSeconds(NextEdgePulseInterval())
		};
		_edgePulseTimer.Tick += OnEdgePulseTimerTick;
		_edgePulseTimer.Start();

		// Glitch bursts every 4 seconds (short non-looping storyboard)
		_glitchTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
		_glitchTimer.Tick += OnGlitchTimerTick;
		_glitchTimer.Start();

		// Schedule the first background twinkle refresh (slow cadence)
		_bgNextTwinkleTime = _animationStopwatch.Elapsed.TotalSeconds + 7.5 + _random.NextDouble() * 1.5;

		// Enable horizontal manipulation on the viewport and ensure we receive it even if children handle it.
		StageCarouselViewport.ManipulationMode = ManipulationModes.TranslateX;

		// Transparent background ensures hit-testing on empty areas so gestures fire consistently.
		StageCarouselViewport.Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent);

		// Listen even if a child marks it handled
		StageCarouselViewport.AddHandler(
			ManipulationCompletedEvent,
			new ManipulationCompletedEventHandler(OnCarouselManipulationCompleted),
			handledEventsToo: true);

		// Run the code that needs to run in ViewModel class when page is loaded.
		ViewModel.OnHomePageLoaded(sender);
	}

	/// <summary>
	/// Prevents double-navigation when both pointer and manipulation paths fire
	/// </summary>
	private bool _swipeNavigatedViaManipulation;

	/// <summary>
	/// Touch swipe → change stage. Uses velocity or distance thresholds.
	/// </summary>
	private void OnCarouselManipulationCompleted(object sender, ManipulationCompletedRoutedEventArgs e)
	{
		double vx = e.Velocities.Linear.X;      // px/ms (WinUI velocity units)
		double dx = e.Cumulative.Translation.X; // px (total horizontal translation)

		// Thresholds
		const double VelocityThreshold = 0.20;    // px/ms
		const double DistanceThreshold = 120.0;   // px

		bool navigated = false;

		if (vx <= -VelocityThreshold || dx <= -DistanceThreshold)
		{
			int next = _currentStageIndex + 1;
			if (next > 3) { next = 0; }
			AnimateToStage(next);
			navigated = true;
		}
		else if (vx >= VelocityThreshold || dx >= DistanceThreshold)
		{
			int prev = _currentStageIndex - 1;
			if (prev < 0) { prev = 3; }
			AnimateToStage(prev);
			navigated = true;
		}

		if (navigated)
		{
			// Mark so the PointerReleased path won't also navigate
			_swipeNavigatedViaManipulation = true;
			e.Handled = true;
		}
	}

	// 14–20 seconds (uniform jitter)
	private double NextEdgePulseInterval() => 14.0 + _random.NextDouble() * 6.0;

	private void OnGlitchTimerTick(object? sender, object e) => StartResourceStoryboardIfExists("GlitchJitterStoryboard");

	private void StartResourceStoryboardIfExists(string key)
	{
		if (!Resources.TryGetValue(key, out object storyboardObject))
			return;

		Storyboard? storyboard = storyboardObject as Storyboard;
		if (storyboard == null)
			return;

		storyboard.Stop();
		storyboard.Begin();
	}

	private void OnEdgePulseTimerTick(object? sender, object e)
	{
		// Start a short cross-fade pulse (bright overlay rises then falls in ~1.1s)
		_edgePulseActive = true;
		_edgePulseStartTime = _animationTimeSeconds;
		_edgeLastFrameTime = 0.0;

		// Force an initial draw of both edge canvases
		LeftGlowCanvas?.Invalidate();
		RightGlowCanvas?.Invalidate();

		// Re-jitter the timer for the next pulse
		_ = (_edgePulseTimer?.Interval = TimeSpan.FromSeconds(NextEdgePulseInterval()));
	}

	private void AttachRenderHook()
	{
		if (_renderHookAttached)
			return;

		CompositionTarget.Rendering += OnRendering;
		_renderHookAttached = true;
	}

	private void DetachRenderHook()
	{
		if (!_renderHookAttached)
			return;

		CompositionTarget.Rendering -= OnRendering;
		_renderHookAttached = false;
	}

	private void OnRendering(object? sender, object e)
	{
		_animationTimeSeconds = _animationStopwatch.Elapsed.TotalSeconds;

		// Stage canvases only when flagged
		if (_needsStageRedrawAll)
		{
			InvalidateAllStageCanvasesOnce();
		}

		// Background: single-frame refresh when needed, slow twinkles otherwise
		if (_needsBackgroundRedrawOnce && BackgroundCanvas != null)
		{
			BackgroundCanvas.Invalidate();
			_needsBackgroundRedrawOnce = false;
		}
		else if (BackgroundCanvas != null && _animationTimeSeconds >= _bgNextTwinkleTime)
		{
			BackgroundCanvas.Invalidate();
			_bgNextTwinkleTime = _animationTimeSeconds + 7.5 + _random.NextDouble() * 1.5;
		}

		// Run edge glow cross-fade only while the short pulse is active
		if (_edgePulseActive)
		{
			double elapsed = _animationTimeSeconds - _edgePulseStartTime;
			if (elapsed >= _edgePulseDuration)
			{
				_edgePulseActive = false;
			}
			else
			{
				// Throttle to ~30 FPS while pulsing
				if (_animationTimeSeconds - _edgeLastFrameTime >= _edgeTargetFrameInterval)
				{
					LeftGlowCanvas?.Invalidate();
					RightGlowCanvas?.Invalidate();
					_edgeLastFrameTime = _animationTimeSeconds;
				}
			}
		}
	}

	private void OnUnloadedDisposeResources(object sender, RoutedEventArgs e)
	{
		// Ensure the embedded YouTube video in WebView2 is fully stopped and destroyed when leaving the page.
		TearDownStage3Content();

		DetachRenderHook();

		if (_glitchTimer != null)
		{
			_glitchTimer.Stop();
			_glitchTimer.Tick -= OnGlitchTimerTick;
			_glitchTimer = null;
		}

		if (_edgePulseTimer != null)
		{
			_edgePulseTimer.Stop();
			_edgePulseTimer.Tick -= OnEdgePulseTimerTick;
			_edgePulseTimer = null;
		}

		_noiseTexture?.Dispose();
		_noiseTexture = null;

		_penumbraWarm?.Dispose();
		_penumbraWarm = null;
		_penumbraPink?.Dispose();
		_penumbraPink = null;
		_penumbraGreen?.Dispose();
		_penumbraGreen = null;
		_penumbraBlue?.Dispose();
		_penumbraBlue = null;

		_leftGlowBase?.Dispose(); _leftGlowBase = null;
		_leftGlowBright?.Dispose(); _leftGlowBright = null;
		_rightGlowBase?.Dispose(); _rightGlowBase = null;
		_rightGlowBright?.Dispose(); _rightGlowBright = null;

		_bgNodes = null;
		_bgEdges = null;
		_bgNodeCount = 0;
		_bgEdgeCount = 0;
		_bgStarEdges?.Clear();
		_bgStarEdges = null;

		// Run the code that needs to run in ViewModel class when page is unloaded.
		ViewModel.OnHomePageUnLoaded();
	}

	#region Navigation

	private void OnLeftNavClick(object sender, RoutedEventArgs e)
	{
		int next = _currentStageIndex - 1;
		if (next < 0)
		{
			next = 3; // wrap for 4 stages
		}
		AnimateToStage(next);
	}

	private void OnRightNavClick(object sender, RoutedEventArgs e)
	{
		int next = _currentStageIndex + 1;
		if (next > 3)
		{
			next = 0; // wrap for 4 stages
		}
		AnimateToStage(next);
	}

	private void OnCarouselPointerPressed(object sender, PointerRoutedEventArgs e)
	{
		// Only handle touch by default
		if (e.Pointer.PointerDeviceType != Microsoft.UI.Input.PointerDeviceType.Touch)
		{
			return;
		}
		_swipeStartPoint = e.GetCurrentPoint(StageCarouselViewport).Position;
		_swipeStartTimeSec = _animationStopwatch.Elapsed.TotalSeconds;
	}

	private void OnCarouselPointerReleased(object sender, PointerRoutedEventArgs e)
	{

		// Prevent double-navigation if the manipulation handler already handled this swipe
		if (_swipeNavigatedViaManipulation)
		{
			_swipeNavigatedViaManipulation = false;
			return;
		}

		// In OnCarouselPointerReleased
		if (e.Pointer.PointerDeviceType != Microsoft.UI.Input.PointerDeviceType.Touch)
		{
			return;
		}

		Point end = e.GetCurrentPoint(StageCarouselViewport).Position;
		double dt = _animationStopwatch.Elapsed.TotalSeconds - _swipeStartTimeSec;

		double dx = end.X - _swipeStartPoint.X;
		double dy = end.Y - _swipeStartPoint.Y;

		double absDx = Math.Abs(dx);
		double absDy = Math.Abs(dy);

		// Basic horizontal swipe detection with time and dominance thresholds
		if (dt <= SwipeMaxDuration && absDx >= SwipeMinDistance && absDx >= absDy * SwipeHorizontalBias)
		{
			if (dx < 0)
			{
				// Swipe left -> go to next stage
				int next = _currentStageIndex + 1;
				if (next > 3) { next = 0; }
				AnimateToStage(next);
				e.Handled = true;
			}
			else
			{
				// Swipe right -> go to previous stage
				int prev = _currentStageIndex - 1;
				if (prev < 0) { prev = 3; }
				AnimateToStage(prev);
				e.Handled = true;
			}
		}
	}

	private void OnViewportSizeChanged(object sender, SizeChangedEventArgs e)
	{
		CarouselClip.Rect = new Rect(0, 0, e.NewSize.Width, e.NewSize.Height);

		UpdateCarouselLayout(e.NewSize.Width);

		// Redraw once on size change
		_needsStageRedrawAll = true;
		_needsBackgroundRedrawOnce = true;

		_bgLastW = 0;
		_bgLastH = 0;

		// Rebuild edge glow textures on next draw by disposing (so they will be recreated)
		_leftGlowBase?.Dispose(); _leftGlowBase = null;
		_leftGlowBright?.Dispose(); _leftGlowBright = null;
		_rightGlowBase?.Dispose(); _rightGlowBase = null;
		_rightGlowBright?.Dispose(); _rightGlowBright = null;

		// Reschedule twinkle
		_bgNextTwinkleTime = _animationStopwatch.Elapsed.TotalSeconds + 7.5 + _random.NextDouble() * 1.5;

		// Force one redraw of glows to recreate textures for the new size
		LeftGlowCanvas?.Invalidate();
		RightGlowCanvas?.Invalidate();
	}

	private void UpdateCarouselLayout(double viewportWidth)
	{
		if (viewportWidth <= 0)
		{
			return;
		}

		double itemWidth = viewportWidth * StageWidthRatio;

		StageItem0.Width = itemWidth;
		StageItem1.Width = itemWidth;
		StageItem2.Width = itemWidth;
		StageItem3.Width = itemWidth;

		double centerOffset = (viewportWidth - itemWidth) * 0.5;
		PanelTransform.X = centerOffset - _currentStageIndex * itemWidth;
	}

	private void AnimateToStage(int newIndex)
	{
		if (newIndex == _currentStageIndex)
		{
			return;
		}

		double viewportWidth = StageCarouselViewport.ActualWidth;
		if (viewportWidth <= 0)
		{
			return;
		}

		// If we are leaving Stage 2 (index 2), tear down Item3 immediately so audio stops.
		// This is a special case only for this stage which contains WebView2 element with YouTube video in it.
		if (_currentStageIndex == 2 && newIndex != 2)
		{
			TearDownStage3Content();
		}

		double itemWidth = viewportWidth * StageWidthRatio;
		double centerOffset = (viewportWidth - itemWidth) * 0.5;

		double startX = PanelTransform.X;
		double endX = centerOffset - newIndex * itemWidth;

		Storyboard slide = new();
		DoubleAnimation slideAnim = new()
		{
			From = startX,
			To = endX,
			Duration = new Duration(SlideDuration),
			EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut },
			EnableDependentAnimation = true
		};
		Storyboard.SetTarget(slideAnim, PanelTransform);
		Storyboard.SetTargetProperty(slideAnim, "X");
		slide.Children.Add(slideAnim);
		slide.Begin();

		// Ensure all 4 stage contents are realized lazily
		EnsureStageContent(newIndex);
		EnsureStageContent((newIndex + 1) % 4);
		EnsureStageContent((newIndex + 2) % 4);
		EnsureStageContent((newIndex + 3) % 4);

		UpdateStageVisualState(newIndex);
		_currentStageIndex = newIndex;

		_needsStageRedrawAll = true;
	}

	private void UpdateStageVisualState(int activeIndex)
	{
		static void AnimateStage(Grid item, ScaleTransform scale, double targetScale, double targetOpacity)
		{
			double fromScale = scale.ScaleX;
			double fromOpacity = item.Opacity;

			Storyboard sb = new();

			DoubleAnimation scaleAnimX = new()
			{
				From = fromScale,
				To = targetScale,
				Duration = new Duration(ScaleDuration),
				EasingFunction = new QuarticEase { EasingMode = EasingMode.EaseInOut },
				EnableDependentAnimation = true
			};
			Storyboard.SetTarget(scaleAnimX, scale);
			Storyboard.SetTargetProperty(scaleAnimX, "ScaleX");

			DoubleAnimation scaleAnimY = new()
			{
				From = fromScale,
				To = targetScale,
				Duration = new Duration(ScaleDuration),
				EasingFunction = new QuarticEase { EasingMode = EasingMode.EaseInOut },
				EnableDependentAnimation = true
			};
			Storyboard.SetTarget(scaleAnimY, scale);
			Storyboard.SetTargetProperty(scaleAnimY, "ScaleY");

			DoubleAnimation opacityAnim = new()
			{
				From = fromOpacity,
				To = targetOpacity,
				Duration = new Duration(ScaleDuration),
				EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut },
				EnableDependentAnimation = true
			};
			Storyboard.SetTarget(opacityAnim, item);
			Storyboard.SetTargetProperty(opacityAnim, "Opacity");

			sb.Children.Add(scaleAnimX);
			sb.Children.Add(scaleAnimY);
			sb.Children.Add(opacityAnim);
			sb.Begin();
		}

		AnimateStage(StageItem0, StageScale0, activeIndex == 0 ? 1.0 : 0.85, activeIndex == 0 ? 1.0 : 0.55);
		AnimateStage(StageItem1, StageScale1, activeIndex == 1 ? 1.0 : 0.85, activeIndex == 1 ? 1.0 : 0.55);
		AnimateStage(StageItem2, StageScale2, activeIndex == 2 ? 1.0 : 0.85, activeIndex == 2 ? 1.0 : 0.55);
		AnimateStage(StageItem3, StageScale3, activeIndex == 3 ? 1.0 : 0.85, activeIndex == 3 ? 1.0 : 0.55);
	}

	private void InvalidateAllStageCanvasesOnce()
	{
		_needsStageRedrawAll = false;
		StageCanvas0.Invalidate();
		StageCanvas1.Invalidate();
		StageCanvas2.Invalidate();
		StageCanvas3.Invalidate();
	}

	#endregion

	#region Lazy Stage Content

	private enum ColorTint
	{
		Warm = 0,
		Pink = 1,
		Green = 2,
		LightBlue = 3
	}

	private void EnsureStageContent(int index)
	{
		if (index == 0 && Stage1Content is null)
		{
			Stage1Content = new CustomUIElements.HomePageStageContents.Item1();
			StagePresenter0.Content = Stage1Content;
			ApplyPanelTint(0, ColorTint.Warm);
		}
		else if (index == 1 && Stage2Content is null)
		{
			Stage2Content = new CustomUIElements.HomePageStageContents.Item2();
			StagePresenter1.Content = Stage2Content;
			ApplyPanelTint(1, ColorTint.Pink);
		}
		else if (index == 2 && Stage3Content == null)
		{
			Stage3Content = new CustomUIElements.HomePageStageContents.Item3();

			// Pass the page-level ContentHost directly so Item3 doesn't search the visual tree
			CustomUIElements.HomePageStageContents.Item3 item3Control =
				(CustomUIElements.HomePageStageContents.Item3)Stage3Content;

			item3Control.OverlayHostGrid = ContentHost;

			StagePresenter2.Content = Stage3Content;
			ApplyPanelTint(2, ColorTint.Green);
		}
		else if (index == 3 && Stage4Content is null)
		{
			Stage4Content = new CustomUIElements.HomePageStageContents.Item4();
			StagePresenter3.Content = Stage4Content;
			ApplyPanelTint(3, ColorTint.LightBlue);
		}
	}

	private void ApplyPanelTint(int index, ColorTint tint)
	{
		Color glowA;
		Color glowB;
		Color border;
		Color corner;
		if (tint == ColorTint.Warm)
		{
			glowA = Color.FromArgb(40, 255, 170, 60);
			glowB = Color.FromArgb(16, 255, 120, 30);
			border = Color.FromArgb(255, 138, 90, 24);
			corner = border;
			ApplyPanelBrush(index, glowA, glowB, border, corner);
		}
		else if (tint == ColorTint.Pink)
		{
			glowA = Color.FromArgb(50, 255, 90, 190);
			glowB = Color.FromArgb(18, 180, 30, 120);
			border = Color.FromArgb(255, 182, 64, 138);
			corner = border;
			ApplyPanelBrush(index, glowA, glowB, border, corner);
		}
		else if (tint == ColorTint.Green)
		{
			glowA = Color.FromArgb(48, 40, 250, 160);
			glowB = Color.FromArgb(18, 20, 140, 90);
			border = Color.FromArgb(255, 47, 159, 104);
			corner = border;
			ApplyPanelBrush(index, glowA, glowB, border, corner);
		}
		else // LightBlue
		{
			glowA = Color.FromArgb(48, 110, 200, 255);
			glowB = Color.FromArgb(18, 60, 150, 230);
			border = Color.FromArgb(255, 107, 183, 255);
			corner = border;
			ApplyPanelBrush(index, glowA, glowB, border, corner);
		}
	}

	private void ApplyPanelBrush(int index, Color glowA, Color glowB, Color border, Color corner)
	{
		LinearGradientBrush glowBrush = new()
		{
			StartPoint = new Point(0, 0),
			EndPoint = new Point(1, 1)
		};
		GradientStop gs1 = new() { Color = glowA, Offset = 0.0 };
		GradientStop gs2 = new() { Color = glowB, Offset = 1.0 };
		glowBrush.GradientStops.Add(gs1);
		glowBrush.GradientStops.Add(gs2);

		LinearGradientBrush borderBrush = new()
		{
			StartPoint = new Point(0, 0.5),
			EndPoint = new Point(1, 0.5)
		};
		GradientStop bs1 = new() { Color = border, Offset = 0.0 };
		GradientStop bs2 = new() { Color = Color.FromArgb(255, 32, 32, 32), Offset = 1.0 };
		borderBrush.GradientStops.Add(bs1);
		borderBrush.GradientStops.Add(bs2);

		if (index == 0)
		{
			PanelGlow0.Background = glowBrush;
			PanelBody0.BorderBrush = borderBrush;
			UpdateCornerColors(PanelCorners0, corner);
		}
		else if (index == 1)
		{
			PanelGlow1.Background = glowBrush;
			PanelBody1.BorderBrush = borderBrush;
			UpdateCornerColors(PanelCorners1, corner);
		}
		else if (index == 2)
		{
			PanelGlow2.Background = glowBrush;
			PanelBody2.BorderBrush = borderBrush;
			UpdateCornerColors(PanelCorners2, corner);
		}
		else if (index == 3)
		{
			PanelGlow3.Background = glowBrush;
			PanelBody3.BorderBrush = borderBrush;
			UpdateCornerColors(PanelCorners3, corner);
		}
	}

	private static void UpdateCornerColors(Grid cornerGrid, Color color)
	{
		int count = cornerGrid.Children.Count;
		for (int i = 0; i < count; i++)
		{
			Rectangle? rect = cornerGrid.Children[i] as Rectangle;
			if (rect != null)
			{
				SolidColorBrush scb = new(color);
				rect.Fill = scb;
			}
		}
	}

	#endregion

	#region Drawing (Per Stage)

	private void OnStageCanvasDraw(CanvasControl sender, CanvasDrawEventArgs args)
	{
		CanvasDrawingSession ds = args.DrawingSession;
		float w = (float)sender.ActualWidth;
		float h = (float)sender.ActualHeight;
		if (w <= 2.0f || h <= 2.0f)
		{
			return;
		}

		EnsureNoiseTexture(sender);
		EnsurePenumbraTargets(sender, w, h);

		float centerX = w * 0.5f;

		// Stage geometry
		float stageTopY = h * 0.66f;
		float stageRadius = MathF.Min(w * 0.22f, 320.0f);
		float stageVerticalRadius = stageRadius * 0.18f;
		float stageCenterY = stageTopY + stageVerticalRadius;

		float beamTopY = MathF.Max(h * 0.07f, 28.0f);
		float beamBottomY = stageTopY;

		float topWidth = MathF.Max(w * 0.055f, 54.0f);
		float bottomWidth = MathF.Min(w * 0.46f, topWidth * 7.2f);

		string? tag = sender.Tag as string;
		ColorTint tint = GetTint(tag);

		CanvasRenderTarget? penumbra = GetPenumbraForTint(tint);
		if (penumbra == null)
		{
			return;
		}

		// Render penumbra (beam) into offscreen target and blur once per draw
		RenderPenumbraTinted(penumbra, sender, tint, beamTopY, beamBottomY, centerX, topWidth, bottomWidth);

		using (GaussianBlurEffect blur = new()
		{
			Source = penumbra,                 // ICanvasImage source
			BlurAmount = 34.0f,
			BorderMode = EffectBorderMode.Hard
		})
		{
			ds.DrawImage(blur);
		}

		// Light noise layer within beam (single application per draw)
		if (_noiseTexture != null)
		{
			using (CanvasGeometry mask = CreateTaperGeometry(ds, centerX, beamTopY, beamBottomY, topWidth, bottomWidth, 0.12f))
			using (ds.CreateLayer(1.0f, mask))
			{
				int tileW = (int)_noiseTexture.SizeInPixels.Width;
				int tileH = (int)_noiseTexture.SizeInPixels.Height;
				float startX = centerX - bottomWidth * 0.55f;
				float endX = centerX + bottomWidth * 0.55f;
				for (float y = beamTopY; y < beamBottomY; y += tileH)
				{
					for (float x = startX; x < endX; x += tileW)
					{
						Rect dest = new(x, y, tileW, tileH);
						Rect src = new(0, 0, tileW, tileH);
						ds.DrawImage(_noiseTexture, dest, src, 0.04f, CanvasImageInterpolation.Linear);
					}
				}
			}
		}

		// Projector fixture and haze disc
		DrawSpotlightFixture(ds, centerX, beamTopY, topWidth, tint);

		DrawFlatStage(ds, centerX, stageTopY, stageCenterY, stageRadius, stageVerticalRadius, tint);

		// Reposition content frame
		float apparentRadiusY = stageVerticalRadius * 0.85f;
		float hazeCenterY = stageCenterY + apparentRadiusY * 0.95f;

		double desiredDelta = (double)hazeCenterY - (double)(h * 0.5f);
		double snapFactor = 0.55;
		double offsetY = desiredDelta * snapFactor;

		Grid? host = null;
		if (ReferenceEquals(sender, StageCanvas0)) { host = PanelHost0; }
		else if (ReferenceEquals(sender, StageCanvas1)) { host = PanelHost1; }
		else if (ReferenceEquals(sender, StageCanvas2)) { host = PanelHost2; }
		else if (ReferenceEquals(sender, StageCanvas3)) { host = PanelHost3; }

		if (host != null)
		{
			TranslateTransform? tt = host.RenderTransform as TranslateTransform;
			if (tt == null)
			{
				tt = new TranslateTransform { X = 0.0, Y = 0.0 };
				host.RenderTransform = tt;
			}
			tt.Y = offsetY;
		}
	}

	#endregion

	#region Edge Glow Rasterized Drawing

	private void OnLeftGlowCanvasDraw(CanvasControl sender, CanvasDrawEventArgs args)
	{
		float w = (float)sender.ActualWidth;
		float h = (float)sender.ActualHeight;
		if (w < 2.0f || h < 2.0f)
		{
			return;
		}
		EnsureEdgeGlowTargets(sender, true, w, h);

		CanvasDrawingSession ds = args.DrawingSession;
		// Base opacity always visible, bright overlay only during pulse
		float baseOpacity = 0.80f;
		float brightOpacity = GetEdgePulseOpacity();

		// Draw base
		if (_leftGlowBase != null)
		{
			using (ds.CreateLayer(baseOpacity))
			{
				ds.DrawImage(_leftGlowBase);
			}
		}
		// Bright overlay
		if (_leftGlowBright != null && brightOpacity > 0.001f)
		{
			using (ds.CreateLayer(brightOpacity))
			{
				ds.DrawImage(_leftGlowBright);
			}
		}
	}

	private void OnRightGlowCanvasDraw(CanvasControl sender, CanvasDrawEventArgs args)
	{
		float w = (float)sender.ActualWidth;
		float h = (float)sender.ActualHeight;
		if (w < 2.0f || h < 2.0f)
		{
			return;
		}
		EnsureEdgeGlowTargets(sender, false, w, h);

		CanvasDrawingSession ds = args.DrawingSession;
		float baseOpacity = 0.80f;
		float brightOpacity = GetEdgePulseOpacity();

		if (_rightGlowBase != null)
		{
			using (ds.CreateLayer(baseOpacity))
			{
				ds.DrawImage(_rightGlowBase);
			}
		}
		if (_rightGlowBright != null && brightOpacity > 0.001f)
		{
			using (ds.CreateLayer(brightOpacity))
			{
				ds.DrawImage(_rightGlowBright);
			}
		}
	}

	private float GetEdgePulseOpacity()
	{
		if (!_edgePulseActive)
		{
			return 0.0f;
		}
		double t = (_animationTimeSeconds - _edgePulseStartTime) / _edgePulseDuration;
		if (t <= 0.0 || t >= 1.0)
		{
			return 0.0f;
		}
		// Smooth in/out envelope; peak around the middle; max overlay ~0.38
		double s = Math.Sin(t * Math.PI);
		return (float)(0.38 * s);
	}

	private void EnsureEdgeGlowTargets(CanvasControl reference, bool isLeft, float width, float height)
	{
		// If target missing or size changed, recreate base and bright for that side
		if (isLeft)
		{
			bool recreate = _leftGlowBase == null ||
							Math.Abs(_leftGlowBase.SizeInPixels.Width - width) > 0.5f ||
							Math.Abs(_leftGlowBase.SizeInPixels.Height - height) > 0.5f;
			if (recreate)
			{
				_leftGlowBase?.Dispose();
				_leftGlowBright?.Dispose();
				_leftGlowBase = new CanvasRenderTarget(reference.Device, width, height, 96);
				_leftGlowBright = new CanvasRenderTarget(reference.Device, width, height, 96);
				RenderEdgeGlowToTarget(_leftGlowBase, isLeft, false);
				RenderEdgeGlowToTarget(_leftGlowBright, isLeft, true);
			}
		}
		else
		{
			bool recreate = _rightGlowBase == null ||
							Math.Abs(_rightGlowBase.SizeInPixels.Width - width) > 0.5f ||
							Math.Abs(_rightGlowBase.SizeInPixels.Height - height) > 0.5f;
			if (recreate)
			{
				_rightGlowBase?.Dispose();
				_rightGlowBright?.Dispose();
				_rightGlowBase = new CanvasRenderTarget(reference.Device, width, height, 96);
				_rightGlowBright = new CanvasRenderTarget(reference.Device, width, height, 96);
				RenderEdgeGlowToTarget(_rightGlowBase, isLeft, false);
				RenderEdgeGlowToTarget(_rightGlowBright, isLeft, true);
			}
		}
	}

	// Renders a side glow into the target. isLeft=true => magenta/teal-leaning; false => blue/cyan-leaning.
	// bright=true renders a stronger inner ring for the pulse overlay.
	private static void RenderEdgeGlowToTarget(CanvasRenderTarget target, bool isLeft, bool bright)
	{
		using CanvasDrawingSession ds = target.CreateDrawingSession();
		ds.Clear(Color.FromArgb(0, 0, 0, 0));

		float w = target.SizeInPixels.Width;
		float h = target.SizeInPixels.Height;

		// Center anchored to the side edge
		float cx = isLeft ? 0.0f : w;
		float cy = h * 0.5f;

		// Ellipse radii
		float rx = w * 0.95f;
		float ry = h * 0.55f;

		Color inner0 = isLeft ? Color.FromArgb(bright ? (byte)140 : (byte)110, 255, 160, 235)   // magenta-ish
							  : Color.FromArgb(bright ? (byte)130 : (byte)100, 135, 200, 255);  // blue/cyan
		Color inner1 = isLeft ? Color.FromArgb(bright ? (byte)110 : (byte)80, 255, 90, 190)
							  : Color.FromArgb(bright ? (byte)100 : (byte)75, 110, 180, 235);
		Color mid = isLeft ? Color.FromArgb(40, 255, 79, 175)
							  : Color.FromArgb(36, 135, 190, 255);
		Color outer = Color.FromArgb(0, 0, 0, 0);

		CanvasGradientStop[] stops =
		[
			new() { Color = Color.FromArgb(0, 0,0,0), Position = 0.00f },
			new() { Color = inner0, Position = 0.22f },
			new() { Color = inner1, Position = 0.35f },
			new() { Color = mid,    Position = 0.55f },
			new() { Color = outer,  Position = 0.95f }
		];

		using CanvasRadialGradientBrush brush = new(ds, stops)
		{
			Center = new Vector2(cx, cy),
			RadiusX = rx,
			RadiusY = ry
		};
		// Fill a large ellipse that spans the control (clipped by control bounds)
		ds.FillEllipse(cx, cy, rx, ry, brush);
	}

	#endregion

	#region Background Web (static idle, clustered one-frame twinkles)

	private void OnBackgroundCanvasDraw(CanvasControl sender, CanvasDrawEventArgs args)
	{
		float w = (float)sender.ActualWidth;
		float h = (float)sender.ActualHeight;
		if (w < 2.0f || h < 2.0f)
		{
			return;
		}

		// Initialize or rebuild graph on size change
		if (_bgNodes == null || _bgEdges == null || Math.Abs(w - _bgLastW) > 0.5f || Math.Abs(h - _bgLastH) > 0.5f)
		{
			InitializeBackgroundGraph(w, h);
			RebuildBackgroundEdges(w, h);
			_bgLastW = w;
			_bgLastH = h;
			_bgLastEdgeRebuildTime = _animationTimeSeconds;
			_bgNextTwinkleTime = _animationTimeSeconds + 7.5 + _random.NextDouble() * 1.5;
		}

		// Rebuild edges very infrequently (mostly static net) to keep GPU usage minimum.
		if (_animationTimeSeconds - _bgLastEdgeRebuildTime > 60.0)
		{
			RebuildBackgroundEdges(w, h);
			_bgLastEdgeRebuildTime = _animationTimeSeconds;
		}

		// Determine tint influence
		ColorTint activeTint = _currentStageIndex switch
		{
			1 => ColorTint.Pink,
			2 => ColorTint.Green,
			3 => ColorTint.LightBlue,
			_ => ColorTint.Warm
		};
		Color accent = GetAccentForTint(activeTint);
		double tintInfluence = 0.12;

		// Quantize time heavily to keep stillness
		double tQuant = Math.Floor(_animationTimeSeconds / 8.00) * 8.00;

		// Node positions
		Vector2[] positions = new Vector2[_bgNodeCount];
		const float layer0Speed = 0.50f;
		const float layer1Speed = 0.35f;
		float ampX0 = w * 0.006f;
		float ampY0 = h * 0.008f;
		float ampX1 = w * 0.004f;
		float ampY1 = h * 0.006f;

		for (int i = 0; i < _bgNodeCount; i++)
		{
			BgNode n = _bgNodes![i];
			float speed = n.Layer == 0 ? layer0Speed : layer1Speed;
			float ax = n.Layer == 0 ? ampX0 : ampX1;
			float ay = n.Layer == 0 ? ampY0 : ampY1;

			double t = tQuant * (0.05 + 0.03 * n.Seed) * speed;
			float dx = (float)(ax * Math.Sin(n.PhaseX + t));
			float dy = (float)(ay * Math.Cos(n.PhaseY + t * 0.85));

			float x = n.BaseX * w + dx;
			float y = n.BaseY * h + dy;

			positions[i] = new Vector2(x, y);
		}

		// Stars (persisting motifs)
		MaybeUpdateStarEdges(positions, w, h);

		// Colors
		Color baseEdge = Color.FromArgb(28, 70, 85, 110);
		Color edgeTint = MixColors(baseEdge, accent, tintInfluence);
		Color baseEdgeBack = Color.FromArgb(18, 60, 75, 100);
		Color edgeTintBack = MixColors(baseEdgeBack, accent, tintInfluence * 0.8);

		// Edges
		for (int i = 0; i < _bgEdgeCount; i++)
		{
			BgEdge e = _bgEdges![i];
			Vector2 a = positions[e.A];
			Vector2 b = positions[e.B];

			float dx = b.X - a.X;
			float dy = b.Y - a.Y;
			float dist = MathF.Sqrt(dx * dx + dy * dy);
			if (dist <= 0.5f)
			{
				continue;
			}

			float refDist = MathF.Min(w, h) * (e.Layer == 0 ? 0.18f : 0.22f);
			float lengthFactor = MathF.Max(0.0f, 1.0f - (dist / refDist));

			byte alpha = (byte)Math.Clamp((int)((e.Layer == 0 ? 38.0f : 26.0f) * lengthFactor), 8, 56);
			Color c = e.Layer == 0 ? Color.FromArgb(alpha, edgeTint.R, edgeTint.G, edgeTint.B)
								   : Color.FromArgb(alpha, edgeTintBack.R, edgeTintBack.G, edgeTintBack.B);

			args.DrawingSession.DrawLine(a, b, c, 1.0f);
		}

		// Persistent stars
		if (_bgStarEdges != null && _bgStarEdges.Count > 0)
		{
			for (int i = _bgStarEdges.Count - 1; i >= 0; i--)
			{
				StarEdgePersist se = _bgStarEdges[i];
				if (se.ExpireAt <= _animationTimeSeconds)
				{
					continue;
				}

				Vector2 a = positions[se.A];
				Vector2 b = positions[se.B];

				float dx = b.X - a.X;
				float dy = b.Y - a.Y;
				float dist = MathF.Sqrt(dx * dx + dy * dy);
				if (dist <= 0.5f)
				{
					continue;
				}

				Color baseC = Color.FromArgb(54, edgeTint.R, edgeTint.G, edgeTint.B);
				Color glowC = Color.FromArgb(18, edgeTint.R, edgeTint.G, edgeTint.B);

				args.DrawingSession.DrawLine(a, b, baseC, 1.2f);
				args.DrawingSession.DrawLine(a, b, glowC, 2.0f);
			}
		}

		// One-frame clustered twinkles (foreground layer)
		if (_bgEdgeCount > 0)
		{
			// Build adjacency for layer 0
			List<int>[] adj = new List<int>[_bgNodeCount];
			for (int i = 0; i < _bgNodeCount; i++) { adj[i] = new List<int>(6); }
			for (int i = 0; i < _bgEdgeCount; i++)
			{
				BgEdge e = _bgEdges![i];
				if (e.Layer != 0) { continue; }
				adj[e.A].Add(e.B);
				adj[e.B].Add(e.A);
			}

			int seedCount = Math.Clamp(_bgNodeCount / 80, 1, 2);
			List<int> seeds = new(seedCount);

			int attempts = 0;
			while (seeds.Count < seedCount && attempts < 40)
			{
				int idx = _random.Next(_bgNodeCount);
				attempts++;
				if (_bgNodes![idx].Layer != 0) { continue; }
				if (adj[idx].Count == 0) { continue; }
				bool already = false;
				for (int s = 0; s < seeds.Count; s++) { if (seeds[s] == idx) { already = true; break; } }
				if (!already) { seeds.Add(idx); }
			}
			if (seeds.Count == 0 && _bgNodeCount > 0) { seeds.Add(0); }

			for (int s = 0; s < seeds.Count; s++)
			{
				int seed = seeds[s];
				bool[] mask = new bool[_bgNodeCount];
				mask[seed] = true;
				List<int> neigh = adj[seed];
				for (int j = 0; j < neigh.Count; j++) { mask[neigh[j]] = true; }

				List<int> candidateEdges = new(32);
				for (int i = 0; i < _bgEdgeCount; i++)
				{
					BgEdge e = _bgEdges![i];
					if (e.Layer != 0) { continue; }
					if (mask[e.A] || mask[e.B]) { candidateEdges.Add(i); }
				}
				if (candidateEdges.Count == 0) { continue; }

				int perCluster = Math.Clamp(candidateEdges.Count / 6, 2, 6);

				Color baseC = edgeTint;
				for (int k = 0; k < perCluster; k++)
				{
					int ei = candidateEdges[_random.Next(candidateEdges.Count)];
					BgEdge e = _bgEdges![ei];

					Vector2 a = positions[e.A];
					Vector2 b = positions[e.B];
					float t = 0.35f + (float)_random.NextDouble() * 0.30f;
					Vector2 p = new(a.X + (b.X - a.X) * t, a.Y + (b.Y - a.Y) * t);

					byte twinkleAlpha = 140;
					byte haloAlpha = 40;

					Color twinkleColor = Color.FromArgb(twinkleAlpha, baseC.R, baseC.G, baseC.B);
					Color haloColor = Color.FromArgb(haloAlpha, baseC.R, baseC.G, baseC.B);

					float size = 2.4f;
					float halo = 5.0f;

					args.DrawingSession.FillEllipse(p, halo, halo, haloColor);
					Rect r = new(p.X - size * 0.5f, p.Y - size * 0.5f, size, size);
					args.DrawingSession.FillRectangle(r, twinkleColor);
				}
			}
		}
	}

	private void InitializeBackgroundGraph(float w, float h)
	{
		double density = Math.Sqrt(w * h) / 14.0;
		int totalNodes = Math.Clamp((int)Math.Round(density), 40, 100);

		_bgNodeCount = totalNodes;
		_bgNodes = new BgNode[_bgNodeCount];

		int layer0Count = (int)Math.Round(_bgNodeCount * 0.60);
		int layer1Count = _bgNodeCount - layer0Count;

		float margin = 0.04f;

		for (int i = 0; i < layer0Count; i++)
		{
			_bgNodes[i] = new BgNode
			{
				BaseX = margin + (float)_random.NextDouble() * (1.0f - 2.0f * margin),
				BaseY = margin + (float)_random.NextDouble() * (1.0f - 2.0f * margin),
				PhaseX = (float)(_random.NextDouble() * Math.PI * 2.0),
				PhaseY = (float)(_random.NextDouble() * Math.PI * 2.0),
				Seed = (float)_random.NextDouble(),
				Layer = 0
			};
		}

		for (int i = 0; i < layer1Count; i++)
		{
			int idx = layer0Count + i;
			_bgNodes[idx] = new BgNode
			{
				BaseX = margin + (float)_random.NextDouble() * (1.0f - 2.0f * margin),
				BaseY = margin + (float)_random.NextDouble() * (1.0f - 2.0f * margin),
				PhaseX = (float)(_random.NextDouble() * Math.PI * 2.0),
				PhaseY = (float)(_random.NextDouble() * Math.PI * 2.0),
				Seed = (float)_random.NextDouble(),
				Layer = 1
			};
		}

		if (_bgStarEdges == null)
		{
			_bgStarEdges = new List<StarEdgePersist>(16);
		}
		else
		{
			_bgStarEdges.Clear();
		}
	}

	private void RebuildBackgroundEdges(float w, float h)
	{
		if (_bgNodes == null || _bgNodeCount <= 1)
		{
			_bgEdges = [];
			_bgEdgeCount = 0;
			return;
		}

		Vector2[] pos = new Vector2[_bgNodeCount];

		double tQuant = Math.Floor(_animationTimeSeconds / 8.00) * 8.00;

		const float layer0Speed = 0.50f;
		const float layer1Speed = 0.35f;
		float ampX0 = w * 0.006f;
		float ampY0 = h * 0.008f;
		float ampX1 = w * 0.004f;
		float ampY1 = h * 0.006f;

		for (int i = 0; i < _bgNodeCount; i++)
		{
			BgNode n = _bgNodes[i];
			float speed = n.Layer == 0 ? layer0Speed : layer1Speed;
			float ax = n.Layer == 0 ? ampX0 : ampX1;
			float ay = n.Layer == 0 ? ampY0 : ampY1;

			double t = tQuant * (0.05 + 0.03 * n.Seed) * speed;
			float dx = (float)(ax * Math.Sin(n.PhaseX + t));
			float dy = (float)(ay * Math.Cos(n.PhaseY + t * 0.85));

			float x = n.BaseX * w + dx;
			float y = n.BaseY * h + dy;

			pos[i] = new Vector2(x, y);
		}

		List<BgEdge> edges = new(_bgNodeCount * 3);
		BuildEdgesForLayer(0, 3, pos, edges);
		BuildEdgesForLayer(1, 2, pos, edges);

		PruneAndAugmentEdges(pos, edges, w, h);

		_bgEdges = edges.ToArray();
		_bgEdgeCount = _bgEdges.Length;
	}

	private void BuildEdgesForLayer(byte layer, int k, Vector2[] pos, List<BgEdge> outEdges)
	{
		if (_bgNodes == null)
		{
			return;
		}

		for (int i = 0; i < _bgNodeCount; i++)
		{
			if (_bgNodes[i].Layer != layer)
			{
				continue;
			}

			int[] bestIdx = new int[k];
			float[] bestD2 = new float[k];
			for (int t = 0; t < k; t++)
			{
				bestIdx[t] = -1;
				bestD2[t] = float.MaxValue;
			}

			for (int j = 0; j < _bgNodeCount; j++)
			{
				if (j == i || _bgNodes[j].Layer != layer)
				{
					continue;
				}
				float dx = pos[j].X - pos[i].X;
				float dy = pos[j].Y - pos[i].Y;
				float d2 = dx * dx + dy * dy;

				for (int t = 0; t < k; t++)
				{
					if (d2 < bestD2[t])
					{
						for (int s = k - 1; s > t; s--)
						{
							bestD2[s] = bestD2[s - 1];
							bestIdx[s] = bestIdx[s - 1];
						}
						bestD2[t] = d2;
						bestIdx[t] = j;
						break;
					}
				}
			}

			for (int t = 0; t < k; t++)
			{
				int j = bestIdx[t];
				if (j >= 0 && i < j)
				{
					outEdges.Add(new BgEdge { A = i, B = j, Layer = layer });
				}
			}
		}
	}

	private void PruneAndAugmentEdges(Vector2[] pos, List<BgEdge> edges, float w, float h)
	{
		int count = edges.Count;
		if (count == 0)
		{
			return;
		}

		float[] lengths = new float[count];
		for (int i = 0; i < count; i++)
		{
			BgEdge e = edges[i];
			Vector2 a = pos[e.A];
			Vector2 b = pos[e.B];
			float dx = b.X - a.X;
			float dy = b.Y - a.Y;
			lengths[i] = MathF.Sqrt(dx * dx + dy * dy);
		}

		List<int> idxL0 = new(count);
		List<int> idxL1 = new(count);
		for (int i = 0; i < count; i++)
		{
			if (edges[i].Layer == 0) { idxL0.Add(i); } else { idxL1.Add(i); }
		}

		static float ComputeQuantile(List<int> idx, float[] values, double q)
		{
			if (idx.Count == 0) { return 0.0f; }
			int[] arr = idx.ToArray();
			Array.Sort(arr, (a, b) => values[a].CompareTo(values[b]));
			int qi = Math.Clamp((int)Math.Round((arr.Length - 1) * q), 0, arr.Length - 1);
			return values[arr[qi]];
		}

		float q20L0 = ComputeQuantile(idxL0, lengths, 0.20);
		float q20L1 = ComputeQuantile(idxL1, lengths, 0.20);

		List<BgEdge> kept = new(count);

		for (int i = 0; i < count; i++)
		{
			BgEdge e = edges[i];
			float len = lengths[i];

			float q = e.Layer == 0 ? q20L0 : q20L1;
			bool veryShort = len <= q * 1.02f;
			if (veryShort)
			{
				if (_random.NextDouble() < 0.50)
				{
					continue;
				}
			}

			kept.Add(e);
		}

		AugmentWithSpanEdges(0, (int)Math.Max(1, Math.Round(_bgNodeCount * 0.14)), pos, kept, w, h);
		AugmentWithSpanEdges(1, (int)Math.Max(1, Math.Round(_bgNodeCount * 0.08)), pos, kept, w, h);

		edges.Clear();
		edges.AddRange(kept);
	}

	private void AugmentWithSpanEdges(byte layer, int additions, Vector2[] pos, List<BgEdge> edges, float w, float h)
	{
		if (_bgNodes == null || additions <= 0)
		{
			return;
		}

		int attempts = additions * 2;
		int added = 0;

		for (int it = 0; it < attempts && added < additions; it++)
		{
			int i = _random.Next(_bgNodeCount);
			if (_bgNodes[i].Layer != layer)
			{
				continue;
			}

			int[] nnIdx = FindNearestInLayer(i, layer, pos, 6);
			if (nnIdx.Length < 5)
			{
				continue;
			}

			int kIdx = _random.NextDouble() < 0.5 ? 3 : 4;
			int j = nnIdx[kIdx];
			if (j < 0)
			{
				continue;
			}

			float dx = pos[j].X - pos[i].X;
			float dy = pos[j].Y - pos[i].Y;
			float len = MathF.Sqrt(dx * dx + dy * dy);
			float minL = MathF.Min(w, h) * 0.05f;
			float maxL = MathF.Min(w, h) * 0.35f;
			if (len < minL || len > maxL)
			{
				continue;
			}

			if (EdgeExists(edges, i, j))
			{
				continue;
			}

			int a = Math.Min(i, j);
			int b = Math.Max(i, j);
			edges.Add(new BgEdge { A = a, B = b, Layer = layer });
			added++;
		}
	}

	private int[] FindNearestInLayer(int index, byte layer, Vector2[] pos, int count)
	{
		if (_bgNodes == null)
		{
			return [];
		}

		int capacity = Math.Min(count, _bgNodeCount - 1);
		int[] bestIdx = new int[capacity];
		float[] bestD2 = new float[capacity];
		for (int t = 0; t < capacity; t++)
		{
			bestIdx[t] = -1;
			bestD2[t] = float.MaxValue;
		}

		Vector2 p = pos[index];
		for (int j = 0; j < _bgNodeCount; j++)
		{
			if (j == index || _bgNodes[j].Layer != layer)
			{
				continue;
			}
			float dx = pos[j].X - p.X;
			float dy = pos[j].Y - p.Y;
			float d2 = dx * dx + dy * dy;

			for (int t = 0; t < capacity; t++)
			{
				if (d2 < bestD2[t])
				{
					for (int s = capacity - 1; s > t; s--)
					{
						bestD2[s] = bestD2[s - 1];
						bestIdx[s] = bestIdx[s - 1];
					}
					bestD2[t] = d2;
					bestIdx[t] = j;
					break;
				}
			}
		}

		int valid = capacity;
		while (valid > 0 && bestIdx[valid - 1] == -1)
		{
			valid--;
		}
		if (valid == capacity)
		{
			return bestIdx;
		}
		int[] trimmed = new int[valid];
		for (int i = 0; i < valid; i++) { trimmed[i] = bestIdx[i]; }
		return trimmed;
	}

	private static bool EdgeExists(List<BgEdge> edges, int i, int j)
	{
		int a = Math.Min(i, j);
		int b = Math.Max(i, j);
		for (int t = 0; t < edges.Count; t++)
		{
			if (edges[t].A == a && edges[t].B == b)
			{
				return true;
			}
		}
		return false;
	}

	private void MaybeUpdateStarEdges(Vector2[] pos, float w, float h)
	{
		_bgStarEdges ??= new List<StarEdgePersist>(16);

		// Expire old motifs
		for (int i = _bgStarEdges.Count - 1; i >= 0; i--)
		{
			if (_bgStarEdges[i].ExpireAt <= _animationTimeSeconds)
			{
				_bgStarEdges.RemoveAt(i);
			}
		}

		// Limit to ~2 simultaneous motifs; throttle creation
		int approxMotifs = _bgStarEdges.Count / 6;
		if (_animationTimeSeconds - _bgLastStarCreateTime < 2.0 || approxMotifs >= 2)
		{
			return;
		}

		// Low probability attempt
		if (_random.NextDouble() < 0.35)
		{
			if (TryCreateStarUsingNodes(pos, w, h, out StarEdgePersist[] starEdges))
			{
				for (int k = 0; k < starEdges.Length; k++)
				{
					_bgStarEdges.Add(starEdges[k]);
				}
				_bgLastStarCreateTime = _animationTimeSeconds;
			}
		}
	}

	private bool TryCreateStarUsingNodes(Vector2[] pos, float w, float h, out StarEdgePersist[] edgesOut)
	{
		edgesOut = [];
		if (_bgNodes == null || _bgNodeCount < 12)
		{
			return false;
		}

		int centerIdx = -1;
		for (int attempts = 0; attempts < 8 && centerIdx < 0; attempts++)
		{
			int idx = _random.Next(_bgNodeCount);
			if (_bgNodes[idx].Layer == 0)
			{
				centerIdx = idx;
			}
		}
		if (centerIdx < 0)
		{
			return false;
		}

		Vector2 c = pos[centerIdx];
		float rBase = MathF.Min(w, h) * (0.10f + (float)_random.NextDouble() * 0.06f);
		float rMin = rBase * 0.65f;
		float rMax = rBase * 1.35f;

		List<int> candidates = new(24);
		for (int i = 0; i < _bgNodeCount; i++)
		{
			if (i == centerIdx || _bgNodes[i].Layer != 0)
			{
				continue;
			}
			float dx = pos[i].X - c.X;
			float dy = pos[i].Y - c.Y;
			float d = MathF.Sqrt(dx * dx + dy * dy);
			if (d >= rMin && d <= rMax)
			{
				candidates.Add(i);
			}
		}

		if (candidates.Count < 8)
		{
			return false;
		}

		double theta0 = _random.NextDouble() * Math.PI * 2.0;
		int sectorCount = 6;
		int[] chosen = new int[sectorCount];
		float[] bestDelta = new float[sectorCount];
		for (int s = 0; s < sectorCount; s++)
		{
			chosen[s] = -1;
			bestDelta[s] = float.MaxValue;
		}

		for (int idx = 0; idx < candidates.Count; idx++)
		{
			int i = candidates[idx];
			float dx = pos[i].X - c.X;
			float dy = pos[i].Y - c.Y;
			double ang = Math.Atan2(dy, dx);
			if (ang < 0) { ang += Math.PI * 2.0; }

			int bestSector = -1;
			float best = float.MaxValue;
			for (int s = 0; s < sectorCount; s++)
			{
				double center = theta0 + s * (Math.PI / 3.0);
				double dAng = Math.Abs(NormalizeAngle(ang - center));
				if (dAng < best)
				{
					best = (float)dAng;
					bestSector = s;
				}
			}

			if (bestSector >= 0 && best < bestDelta[bestSector])
			{
				bestDelta[bestSector] = best;
				chosen[bestSector] = i;
			}
		}

		int filled = 0;
		for (int s = 0; s < sectorCount; s++)
		{
			if (chosen[s] >= 0) { filled++; }
		}
		if (filled < 5)
		{
			return false;
		}

		List<int> verts = new(6);
		for (int s = 0; s < sectorCount; s++)
		{
			if (chosen[s] >= 0) { verts.Add(chosen[s]); }
		}
		if (verts.Count < 5)
		{
			return false;
		}
		if (verts.Count == 5)
		{
			verts.Add(verts[4]);
		}

		int[] starPairs =
		[
			verts[0], verts[2],
			verts[2], verts[4],
			verts[4], verts[0],
			verts[1], verts[3],
			verts[3], verts[5],
			verts[5], verts[1],
		];

		double ttl = 4.0 + _random.NextDouble() * 3.0;
		double expire = _animationTimeSeconds + ttl;

		StarEdgePersist[] result = new StarEdgePersist[starPairs.Length / 2];
		for (int k = 0; k < result.Length; k++)
		{
			int a = starPairs[k * 2 + 0];
			int b = starPairs[k * 2 + 1];

			int ia = Math.Min(a, b);
			int ib = Math.Max(a, b);

			result[k] = new StarEdgePersist
			{
				A = ia,
				B = ib,
				Layer = 0,
				ExpireAt = expire
			};
		}

		edgesOut = result;
		return true;
	}

	private static double NormalizeAngle(double x)
	{
		while (x < -Math.PI) { x += Math.PI * 2.0; }
		while (x > Math.PI) { x -= Math.PI * 2.0; }
		return Math.Abs(x);
	}

	private static Color GetAccentForTint(ColorTint tint)
	{
		if (tint == ColorTint.Pink) { return Color.FromArgb(255, 190, 120, 220); }
		if (tint == ColorTint.Green) { return Color.FromArgb(255, 110, 210, 180); }
		if (tint == ColorTint.LightBlue) { return Color.FromArgb(255, 140, 200, 255); }
		return Color.FromArgb(255, 220, 180, 110);
	}

	private static Color MixColors(Color a, Color b, double mix)
	{
		double m = Math.Clamp(mix, 0.0, 1.0);
		byte r = (byte)Math.Clamp((int)Math.Round(a.R * (1.0 - m) + b.R * m), 0, 255);
		byte g = (byte)Math.Clamp((int)Math.Round(a.G * (1.0 - m) + b.G * m), 0, 255);
		byte bl = (byte)Math.Clamp((int)Math.Round(a.B * (1.0 - m) + b.B * m), 0, 255);
		return Color.FromArgb(a.A, r, g, bl);
	}

	#endregion

	#region Penumbra / Beam Helpers

	private static ColorTint GetTint(string? tag)
	{
		if (string.Equals(tag, "pink", StringComparison.OrdinalIgnoreCase))
		{
			return ColorTint.Pink;
		}
		if (string.Equals(tag, "green", StringComparison.OrdinalIgnoreCase))
		{
			return ColorTint.Green;
		}
		if (string.Equals(tag, "blue", StringComparison.OrdinalIgnoreCase))
		{
			return ColorTint.LightBlue;
		}
		return ColorTint.Warm;
	}

	private CanvasRenderTarget? GetPenumbraForTint(ColorTint tint)
	{
		if (tint == ColorTint.Warm) { return _penumbraWarm; }
		if (tint == ColorTint.Pink) { return _penumbraPink; }
		if (tint == ColorTint.Green) { return _penumbraGreen; }
		if (tint == ColorTint.LightBlue) { return _penumbraBlue; }
		return _penumbraWarm;
	}

	private void RenderPenumbraTinted(CanvasRenderTarget target, CanvasControl reference, ColorTint tint,
	float topY, float bottomY, float centerX, float topWidth, float bottomWidth)
	{
		using CanvasDrawingSession pds = target.CreateDrawingSession();
		pds.Clear(Color.FromArgb(0, 0, 0, 0));

		using CanvasGeometry tapered = CreateTaperGeometry(pds, centerX, topY, bottomY, topWidth, bottomWidth, 0.18f);

		// Vertical gradient fill
		CanvasGradientStop[] verticalStops = CreateVerticalStopsForTint(tint);
		using (CanvasLinearGradientBrush vBrush = new(pds, verticalStops)
		{
			StartPoint = new Vector2(centerX, topY),
			EndPoint = new Vector2(centerX, bottomY)
		})
		{
			pds.FillGeometry(tapered, vBrush);
		}

		float beamHeight = bottomY - topY;
		float midY = topY + beamHeight * 0.55f;
		float midRadiusX = bottomWidth * 0.55f;
		float midRadiusY = beamHeight * 0.70f;

		// Radial gradient overlay
		CanvasGradientStop[] radialStops = CreateRadialStopsForTint(tint);
		using CanvasRadialGradientBrush midBrush = new(pds, radialStops)
		{
			Center = new Vector2(centerX, midY),
			RadiusX = midRadiusX,
			RadiusY = midRadiusY
		};

		using (pds.CreateLayer(1.0f, tapered))
		{
			pds.FillEllipse(centerX, midY, midRadiusX, midRadiusY, midBrush);
		}
	}

	private static CanvasGradientStop[] CreateVerticalStopsForTint(ColorTint tint)
	{
		if (tint == ColorTint.Pink)
		{
			return
			[
				new CanvasGradientStop { Color = Color.FromArgb(  0, 255,215,245), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb( 80, 255,205,240), Position = 0.18f },
				new CanvasGradientStop { Color = Color.FromArgb(140, 255,175,225), Position = 0.45f },
				new CanvasGradientStop { Color = Color.FromArgb(105, 255,150,210), Position = 0.70f },
				new CanvasGradientStop { Color = Color.FromArgb(  0, 255,140,200), Position = 1.00f }
			];
		}
		if (tint == ColorTint.Green)
		{
			return
			[
				new CanvasGradientStop { Color = Color.FromArgb(  0, 210,255,225), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb( 70, 200,255,215), Position = 0.18f },
				new CanvasGradientStop { Color = Color.FromArgb(130, 170,255,190), Position = 0.45f },
				new CanvasGradientStop { Color = Color.FromArgb(100, 150,245,170), Position = 0.70f },
				new CanvasGradientStop { Color = Color.FromArgb(  0, 130,235,150), Position = 1.00f }
			];
		}
		if (tint == ColorTint.LightBlue)
		{
			return
			[
				new CanvasGradientStop { Color = Color.FromArgb(  0, 200,230,255), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb( 70, 170,220,255), Position = 0.18f },
				new CanvasGradientStop { Color = Color.FromArgb(130, 150,210,255), Position = 0.45f },
				new CanvasGradientStop { Color = Color.FromArgb(100, 120,190,245), Position = 0.70f },
				new CanvasGradientStop { Color = Color.FromArgb(  0, 100,170,235), Position = 1.00f }
			];
		}
		return
		[
			new CanvasGradientStop { Color = Color.FromArgb(  0, 255,240,200), Position = 0.00f },
			new CanvasGradientStop { Color = Color.FromArgb( 70, 255,240,205), Position = 0.18f },
			new CanvasGradientStop { Color = Color.FromArgb(130, 255,228,175), Position = 0.45f },
			new CanvasGradientStop { Color = Color.FromArgb(100, 255,215,150), Position = 0.70f },
			new CanvasGradientStop { Color = Color.FromArgb(  0, 255,200,130), Position = 1.00f }
		];
	}

	private static CanvasGradientStop[] CreateRadialStopsForTint(ColorTint tint)
	{
		if (tint == ColorTint.Pink)
		{
			return
			[
				new CanvasGradientStop { Color = Color.FromArgb(120, 255,230,245), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb( 60, 255,190,225), Position = 0.55f },
				new CanvasGradientStop { Color = Color.FromArgb(  0, 255,160,205), Position = 1.00f }
			];
		}
		if (tint == ColorTint.Green)
		{
			return
			[
				new CanvasGradientStop { Color = Color.FromArgb(110, 230,255,230), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb( 55, 190,245,200), Position = 0.55f },
				new CanvasGradientStop { Color = Color.FromArgb(  0, 160,230,175), Position = 1.00f }
			];
		}
		if (tint == ColorTint.LightBlue)
		{
			return
			[
				new CanvasGradientStop { Color = Color.FromArgb(110, 200,235,255), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb( 60, 160,210,245), Position = 0.55f },
				new CanvasGradientStop { Color = Color.FromArgb(  0, 120,190,235), Position = 1.00f }
			];
		}
		return
		[
			new CanvasGradientStop { Color = Color.FromArgb(110, 255,250,230), Position = 0.00f },
			new CanvasGradientStop { Color = Color.FromArgb( 60, 255,235,195), Position = 0.55f },
			new CanvasGradientStop { Color = Color.FromArgb(  0, 255,220,160), Position = 1.00f }
		];
	}

	private static CanvasGeometry CreateTaperGeometry(CanvasDrawingSession ds, float cx, float topY, float bottomY, float topWidth, float bottomWidth, float edgeFeather)
	{
		float halfTop = topWidth * 0.5f;
		float halfBottom = bottomWidth * 0.5f;
		float h = bottomY - topY;

		float y1 = topY + h * 0.30f;
		float y2 = topY + h * 0.65f;

		float lateral1 = halfTop + (halfBottom - halfTop) * 0.40f;
		lateral1 *= 1.0f + edgeFeather;

		CanvasPathBuilder pb = new(ds.Device);
		pb.BeginFigure(cx - halfTop, topY);
		pb.AddCubicBezier(new Vector2(cx - halfTop, y1),
			new Vector2(cx - lateral1, y2),
			new Vector2(cx - halfBottom, bottomY));
		pb.AddLine(cx + halfBottom, bottomY);
		pb.AddCubicBezier(new Vector2(cx + lateral1, y2),
			new Vector2(cx + halfTop, y1),
			new Vector2(cx + halfTop, topY));
		pb.EndFigure(CanvasFigureLoop.Closed);
		CanvasGeometry g = CanvasGeometry.CreatePath(pb);
		pb.Dispose();
		return g;
	}

	#endregion

	#region Stage & Fixture Drawing

	// Haze-only stage, matching projector tint
	private static void DrawFlatStage(CanvasDrawingSession ds, float cx, float stageTopY, float stageCenterY,
		float radiusX, float radiusY, ColorTint tint)
	{
		float apparentRadiusY = radiusY * 0.85f;

		float hazeRadiusX = radiusX * 1.45f;
		float hazeRadiusY = apparentRadiusY * 2.6f;
		float hazeCenterY = stageCenterY + apparentRadiusY * 0.95f;

		CanvasGradientStop[] hazeStopsPrimary;
		CanvasGradientStop[] hazeStopsSecondary;

		if (tint == ColorTint.Pink)
		{
			hazeStopsPrimary =
			[
				new CanvasGradientStop { Color = Color.FromArgb( 80, 255, 140, 220), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb( 28, 200,  90, 205), Position = 0.40f },
				new CanvasGradientStop { Color = Color.FromArgb(  0,   0,   0,   0), Position = 1.00f }
			];
			hazeStopsSecondary =
			[
				new CanvasGradientStop { Color = Color.FromArgb(150, 255, 160, 235), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb(  0,   0,   0,   0), Position = 1.00f }
			];
		}
		else if (tint == ColorTint.Green)
		{
			hazeStopsPrimary =
			[
				new CanvasGradientStop { Color = Color.FromArgb( 80, 110, 235, 185), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb( 28,  70, 190, 155), Position = 0.40f },
				new CanvasGradientStop { Color = Color.FromArgb(  0,   0,   0,   0), Position = 1.00f }
			];
			hazeStopsSecondary =
			[
				new CanvasGradientStop { Color = Color.FromArgb(145, 120, 255, 190), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb(  0,   0,   0,   0), Position = 1.00f }
			];
		}
		else if (tint == ColorTint.LightBlue)
		{
			hazeStopsPrimary =
			[
				new CanvasGradientStop { Color = Color.FromArgb( 80, 150, 210, 255), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb( 28, 110, 180, 240), Position = 0.40f },
				new CanvasGradientStop { Color = Color.FromArgb(  0,   0,   0,   0), Position = 1.00f }
			];
			hazeStopsSecondary =
			[
				new CanvasGradientStop { Color = Color.FromArgb(140, 170, 225, 255), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb(  0,   0,   0,   0), Position = 1.00f }
			];
		}
		else
		{
			hazeStopsPrimary =
			[
				new CanvasGradientStop { Color = Color.FromArgb( 80, 255, 200, 120), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb( 26, 230, 165,  95), Position = 0.40f },
				new CanvasGradientStop { Color = Color.FromArgb(  0,   0,   0,   0), Position = 1.00f }
			];
			hazeStopsSecondary =
			[
				new CanvasGradientStop { Color = Color.FromArgb(135, 255, 210, 140), Position = 0.00f },
				new CanvasGradientStop { Color = Color.FromArgb(  0,   0,   0,   0), Position = 1.00f }
			];
		}

		using (CanvasRadialGradientBrush hazeBrushPrimary = new(ds, hazeStopsPrimary)
		{
			Center = new Vector2(cx, hazeCenterY),
			RadiusX = hazeRadiusX,
			RadiusY = hazeRadiusY
		})
		{
			ds.FillEllipse(cx, hazeCenterY, hazeRadiusX, hazeRadiusY, hazeBrushPrimary);
		}

		using CanvasRadialGradientBrush hazeBrushSecondary = new(ds, hazeStopsSecondary)
		{
			Center = new Vector2(cx, hazeCenterY + apparentRadiusY * 0.18f),
			RadiusX = hazeRadiusX * 0.72f,
			RadiusY = hazeRadiusY * 0.60f
		};
		ds.FillEllipse(cx, hazeCenterY + apparentRadiusY * 0.18f, hazeRadiusX * 0.72f, hazeRadiusY * 0.60f, hazeBrushSecondary);
	}

	// Projector fixture drawing
	private static void DrawSpotlightFixture(CanvasDrawingSession ds, float cx, float beamTopY, float topWidth, ColorTint tint)
	{
		float scale = topWidth / 100.0f;

		float baseRadius = 22.0f * scale;
		float frontCenterY = beamTopY - (baseRadius * 0.15f);
		float housingWidth = baseRadius * 4.4f;
		float housingHeight = baseRadius * 2.1f;
		float housingX = cx - housingWidth * 0.5f;
		float housingY = frontCenterY - housingHeight * 0.55f;

		float yokeThickness = 6.0f * scale;
		float yokeInset = 4.0f * scale;
		float yokeTopY = housingY - (10.0f * scale);
		CanvasGradientStop[] yokeStops =
		[
			new() { Color = Color.FromArgb(255, 50,50,50), Position = 0.0f },
			new() { Color = Color.FromArgb(255, 30,30,30), Position = 1.0f }
		];
		using (CanvasLinearGradientBrush yokeBrush = new(ds, yokeStops)
		{
			StartPoint = new Vector2(housingX, yokeTopY),
			EndPoint = new Vector2(housingX, yokeTopY + yokeThickness)
		})
		{
			ds.FillRoundedRectangle(new Rect(housingX + yokeInset, yokeTopY, housingWidth - yokeInset * 2.0f, yokeThickness),
				yokeThickness * 0.4f, yokeThickness * 0.4f, yokeBrush);
			ds.FillRoundedRectangle(new Rect(housingX + yokeInset, yokeTopY, yokeThickness, housingHeight + (10.0f * scale)),
				yokeThickness * 0.45f, yokeThickness * 0.45f, yokeBrush);
			ds.FillRoundedRectangle(new Rect(housingX + housingWidth - yokeInset - yokeThickness, yokeTopY, yokeThickness, housingHeight + (10.0f * scale)),
				yokeThickness * 0.45f, yokeThickness * 0.45f, yokeBrush);
		}

		CanvasGradientStop[] bodyStops =
		[
			new() { Color = Color.FromArgb(255, 32,32,32), Position = 0.0f },
			new() { Color = Color.FromArgb(255, 22,22,22), Position = 0.55f },
			new() { Color = Color.FromArgb(255, 16,16,16), Position = 1.0f }
		];
		using (CanvasLinearGradientBrush housingBrush = new(ds, bodyStops)
		{
			StartPoint = new Vector2(housingX, housingY),
			EndPoint = new Vector2(housingX, housingY + housingHeight)
		})
		{
			ds.FillRoundedRectangle(new Rect(housingX, housingY, housingWidth, housingHeight),
				8.0f * scale, 8.0f * scale, housingBrush);
		}

		int ventCount = 5;
		float ventMarginSide = 14.0f * scale;
		float ventTopStart = housingY + housingHeight * 0.20f;
		float ventSpacing = 9.0f * scale;
		float ventHeight = 3.0f * scale;
		float ventWidth = housingWidth - ventMarginSide * 2.0f;
		Color ventColor = Color.FromArgb(150, 70, 70, 70);
		for (int i = 0; i < ventCount; i++)
		{
			float vy = ventTopStart + i * ventSpacing;
			ds.FillRoundedRectangle(new Rect(housingX + ventMarginSide, vy, ventWidth, ventHeight),
				ventHeight * 0.5f, ventHeight * 0.5f, ventColor);
		}

		float barrelWidth = housingWidth * 0.62f;
		float barrelHeight = housingHeight * 0.70f;
		float barrelX = cx - barrelWidth * 0.5f;
		float barrelY = frontCenterY - barrelHeight * 0.50f;

		CanvasGradientStop[] barrelStops =
		[
			new() { Color = Color.FromArgb(255, 26,26,26), Position = 0.00f },
			new() { Color = Color.FromArgb(255, 46,46,46), Position = 0.40f },
			new() { Color = Color.FromArgb(255, 30,30,30), Position = 0.85f },
			new() { Color = Color.FromArgb(255, 22,22,22), Position = 1.00f }
		];
		using (CanvasLinearGradientBrush barrelBrush = new(ds, barrelStops)
		{
			StartPoint = new Vector2(barrelX, barrelY),
			EndPoint = new Vector2(barrelX + barrelWidth, barrelY)
		})
		{
			ds.FillRoundedRectangle(new Rect(barrelX, barrelY, barrelWidth, barrelHeight),
				6.0f * scale, 6.0f * scale, barrelBrush);
		}

		float plateInset = 6.0f * scale;
		float plateX = barrelX + plateInset;
		float plateY = barrelY + plateInset;
		float plateW = barrelWidth - plateInset * 2.0f;
		float plateH = barrelHeight - plateInset * 2.0f;

		CanvasGradientStop[] plateStops =
		[
			new() { Color = Color.FromArgb(255, 10,10,10), Position = 0.0f },
			new() { Color = Color.FromArgb(255, 16,16,16), Position = 0.7f },
			new() { Color = Color.FromArgb(255, 22,22,22), Position = 1.0f }
		];
		using (CanvasLinearGradientBrush plateBrush = new(ds, plateStops)
		{
			StartPoint = new Vector2(plateX, plateY),
			EndPoint = new Vector2(plateX, plateY + plateH)
		})
		{
			ds.FillRoundedRectangle(new Rect(plateX, plateY, plateW, plateH),
				4.0f * scale, 4.0f * scale, plateBrush);
		}

		float slitHeight = 4.0f * scale;
		float slitWidth = plateW * 0.74f;
		float slitX = cx - slitWidth * 0.5f;
		float slitY = plateY + plateH * 0.40f;

		Color slitCore = tint switch
		{
			ColorTint.Pink => Color.FromArgb(90, 255, 140, 210),
			ColorTint.Green => Color.FromArgb(85, 110, 235, 185),
			ColorTint.LightBlue => Color.FromArgb(85, 150, 210, 255),
			_ => Color.FromArgb(90, 255, 200, 120)
		};

		CanvasGradientStop[] slitStops =
		[
			new() { Color = slitCore, Position = 0.0f },
			new() { Color = Color.FromArgb(10, 255,255,255), Position = 0.5f },
			new() { Color = Color.FromArgb(0, 0,0,0), Position = 1.0f }
		];
		using (CanvasLinearGradientBrush slitBrush = new(ds, slitStops)
		{
			StartPoint = new Vector2(slitX, slitY),
			EndPoint = new Vector2(slitX, slitY + slitHeight)
		})
		{
			ds.FillRoundedRectangle(new Rect(slitX, slitY, slitWidth, slitHeight),
				slitHeight * 0.5f, slitHeight * 0.5f, slitBrush);
		}

		Color recessShadeTop = Color.FromArgb(60, 0, 0, 0);
		ds.DrawLine(new Vector2(plateX + 2.0f * scale, plateY + 2.0f * scale),
			new Vector2(plateX + plateW - 2.0f * scale, plateY + 2.0f * scale), recessShadeTop);

		Color recessShadeBottom = Color.FromArgb(50, 0, 0, 0);
		ds.DrawLine(new Vector2(plateX + 2.0f * scale, plateY + plateH - 2.0f * scale),
			new Vector2(plateX + plateW - 2.0f * scale, plateY + plateH - 2.0f * scale), recessShadeBottom);
	}

	#endregion

	#region Noise / Targets

	private void EnsureNoiseTexture(CanvasControl sender)
	{
		if (_noiseTexture != null)
		{
			return;
		}

		int size = 256;
		_noiseTexture = new CanvasRenderTarget(sender.Device, size, size, 96);
		using CanvasDrawingSession nds = _noiseTexture.CreateDrawingSession();
		nds.Clear(Color.FromArgb(0, 0, 0, 0));
		int particles = 1400;
		for (int i = 0; i < particles; i++)
		{
			float x = (float)_random.NextDouble() * size;
			float y = (float)_random.NextDouble() * size;
			byte a = (byte)_random.Next(4, 14);
			Color c = Color.FromArgb(a, 255, 255, 255);
			nds.FillRectangle(x, y, 1.0f, 1.0f, c);
		}
	}

	private void EnsurePenumbraTargets(CanvasControl sender, float width, float height)
	{
		EnsurePenumbraTarget(ref _penumbraWarm, sender, width, height);
		EnsurePenumbraTarget(ref _penumbraPink, sender, width, height);
		EnsurePenumbraTarget(ref _penumbraGreen, sender, width, height);
		EnsurePenumbraTarget(ref _penumbraBlue, sender, width, height);
	}

	private static void EnsurePenumbraTarget(ref CanvasRenderTarget? target, CanvasControl sender, float width, float height)
	{
		bool recreate = target == null ||
						Math.Abs(target.SizeInPixels.Width - width) > 0.5f ||
						Math.Abs(target.SizeInPixels.Height - height) > 0.5f;
		if (recreate)
		{
			target?.Dispose();
			target = new CanvasRenderTarget(sender.Device, width, height, 96);
		}
	}

	#endregion

	// Disposal guard to ensure owned resources are released exactly once
	private bool _disposed;

	// Safe to call multiple times, and also safe to call in addition to Unloaded cleanup.
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}
		_disposed = true;

		// This detaches render hooks, stops timers, and disposes all CanvasRenderTargets, etc.
		OnUnloadedDisposeResources(this, new RoutedEventArgs());
	}

}
