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
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.ViewModels;
using Microsoft.Graphics.Canvas;
using Microsoft.Graphics.Canvas.Effects;
using Microsoft.Graphics.Canvas.UI;
using Microsoft.Graphics.Canvas.UI.Xaml;
using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Shapes;
using Windows.Devices.Enumeration;
using Windows.Devices.Sensors;
using Windows.Foundation;
using Windows.Graphics;
using Windows.UI;

#pragma warning disable CA5394 // Random usage here is OK.

namespace AppControlManager.Pages;

internal sealed class WifiProfileRow
{
	internal string InterfaceDescription { get; init; } = string.Empty;
	internal string InterfaceGuid { get; init; } = string.Empty;
	internal string InterfaceState { get; init; } = string.Empty;
	internal string ProfileName { get; init; } = string.Empty;
	internal string ConnectionType { get; init; } = string.Empty;
	internal string ConnectionMode { get; init; } = string.Empty;
	internal string Authentication { get; init; } = string.Empty;
	internal string Encryption { get; init; } = string.Empty;
	internal string OneX { get; init; } = string.Empty;
	internal bool SharedKeyConfigured { get; init; }
	internal string KeyType { get; init; } = string.Empty;
	internal string Protected { get; init; } = string.Empty;
	internal string DisplayProfileName => string.IsNullOrWhiteSpace(ProfileName) ? "Unnamed profile" : ProfileName;

	internal string SecurityBadge
	{
		get
		{
			string authentication = string.IsNullOrWhiteSpace(Authentication) ? "Auth?" : Authentication;
			string encryption = string.IsNullOrWhiteSpace(Encryption) ? "Enc?" : Encryption;
			return authentication + " / " + encryption;
		}
	}

	internal string InterfaceBadge => string.IsNullOrWhiteSpace(InterfaceDescription) ? "Adapter" : InterfaceDescription;

	internal string ConnectionBadge
	{
		get
		{
			string connectionType = string.IsNullOrWhiteSpace(ConnectionType) ? "Type?" : ConnectionType;
			string connectionMode = string.IsNullOrWhiteSpace(ConnectionMode) ? "Mode?" : ConnectionMode;
			return connectionType + " • " + connectionMode;
		}
	}

	internal string OneXBadge => string.IsNullOrWhiteSpace(OneX) ? "802.1X: Unavailable" : "802.1X: " + OneX;
}
internal sealed partial class HomeLiveGraphsWindow : Window, IDisposable
{
	private const uint ErrorSuccess = 0U;
	private const uint PdhFormatDouble = 0x00000200U;
	private const string CpuUsageCounterPath = @"\Processor Information(_Total)\% Processor Time";
	private const int DiskActivityMaxSamples = 120;
	private const int HomeLiveMetricTimeWindowSeconds = 60;
	private const int HomeLiveMetricUpdateIntervalSeconds = 2;
	private const int HomeLiveMetricMaxSamples = (HomeLiveMetricTimeWindowSeconds / HomeLiveMetricUpdateIntervalSeconds) + 1;
	private const int ChartCount = 7;
	private const double AvailableWidthReserve = 18.0;
	private const float LiveGraphCardElevation = 32.0f;
	private const double LiveGraphCardGlowBleed = 24.0;
	private const double LiveGraphCardSpacing = 14.0;
	private const double LiveGraphCardGlowOpacity = 0.30;
	private const double BlackHoleFrameIntervalMilliseconds = 16.0;
	private const string BlackHoleShaderRelativePath = "Assets\\Shaders\\BlackHoleShader.bin";
	private const string HomeTitleText = "LIVE SYSTEM INTELLIGENCE";
	private const double HomeTitleLetterAnimationDelaySeconds = 0.015;
	private const double HomeTitleLetterAnimationDurationSeconds = 0.6;
	private const double HomeTitleLetterLineHeight = 31.0;
	private const double HomeTitleLetterSpacing = 1.9;
	private const double HomeTitleWordGap = 5.0;
	private const double HomeTitleFrameIntervalMilliseconds = 16.0;
	private const double HomeTitleFirstFrameLeadSeconds = 1.0 / 60.0;
	private readonly List<HomeTitleLetterState> _homeTitleLetterStates = new(HomeTitleText.Length);
	private DispatcherQueueTimer? _homeTitleAnimationTimer;
	private bool _homeTitleRollingAnimationActive;
	private double _homeTitleRollingAnimationStartSeconds;
	private double _homeTitlePulseStartSeconds;

	private enum LiveGraphSize
	{
		Small = 0,
		Medium = 1,
		Big = 2
	}

	private readonly DispatcherTimer _diskActivityTimer = new();
	private readonly DispatcherTimer _liveOnlyMetricTimer = new();
	private readonly DispatcherTimer _blackHoleRenderTimer = new();
	private readonly List<double> _diskReadMegabytesPerSecondSamples = new(DiskActivityMaxSamples);
	private readonly List<double> _diskWriteMegabytesPerSecondSamples = new(DiskActivityMaxSamples);
	private readonly List<double> _systemMemoryUtilizationSamples = new(HomeLiveMetricMaxSamples);
	private readonly List<double> _cpuUsageSamples = new(HomeLiveMetricMaxSamples);
	private readonly List<double> _networkUsageChartSamples = new(HomeLiveMetricMaxSamples);
	private readonly bool _isGraphLayoutReady;
	private bool _diskActivityCountersInitialized;
	private LiveGraphSize _currentGraphSize = LiveGraphSize.Medium;
	private IntPtr _diskActivityPdhQuery;
	private IntPtr _diskReadSpeedCounter;
	private IntPtr _diskWriteSpeedCounter;
	private double _lastDiskReadBytesPerSecond;
	private double _lastDiskWriteBytesPerSecond;
	private bool _cpuUsageCountersInitialized;
	private IntPtr _cpuUsagePdhQuery;
	private IntPtr _cpuUsageCounter;
	private uint _liveNetworkInterfaceIndex;
	private ulong _previousLiveNetworkInBytes;
	private ulong _previousLiveNetworkOutBytes;
	private long _previousLiveNetworkSampleTicks;
	private PixelShaderEffect? _blackHoleShaderEffect;
	private byte[]? _blackHoleShaderBytecode;
	private AnimatedTesseractBackground? _animatedTesseractBackground;
	private CanvasControl? _blackHoleCanvas;
	private bool _isDisposed;
	private DateTimeOffset _blackHoleStartTime;

	internal HomeVM ViewModel { get; }

	internal HomeLiveGraphsWindow(HomeVM viewModel)
	{
		ViewModel = viewModel;
		InitializeComponent();
		InitializeLiveGraphCardDepth();
		InitializeHomeTitleBadge();
		ExtendsContentIntoTitleBar = true;
		AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
		OverlappedPresenter presenter = OverlappedPresenter.Create();
		presenter.PreferredMinimumWidth = 800;
		presenter.PreferredMinimumHeight = 700;
		AppWindow.SetPresenter(presenter);
		_blackHoleStartTime = DateTimeOffset.UtcNow;
		_blackHoleRenderTimer.Interval = TimeSpan.FromMilliseconds(BlackHoleFrameIntervalMilliseconds);
		_blackHoleRenderTimer.Tick += OnBlackHoleRenderTimerTick;
		_isGraphLayoutReady = true;
		ApplyGraphSize(_currentGraphSize);
		UpdateEffectiveMaximumLabels();
		AppWindow.TitleBar.PreferredTheme = TitleBarTheme.Dark; // The window is designed to be used in Dark mode.
		AppWindow.ResizeClient(new SizeInt32(1120, 840));
		_liveOnlyMetricTimer.Interval = TimeSpan.FromSeconds(HomeLiveMetricUpdateIntervalSeconds);
		_liveOnlyMetricTimer.Tick += OnLiveOnlyMetricTimerTick;
		UpdateLiveOnlyMetrics(firstNetworkSample: true);
		_liveOnlyMetricTimer.Start();

		_diskActivityTimer.Interval = TimeSpan.FromSeconds(2.0);
		_diskActivityTimer.Tick += OnDiskActivityTimerTick;
		UpdateDiskActivity();
		_diskActivityTimer.Start();
		InitializeSensorsMonitoring();
		OnHeartPrivacyWindowInitialized();
	}

	private void InitializeHomeTitleBadge()
	{
		CreateHomeTitleLetters();
		_homeTitlePulseStartSeconds = GetHomeTitleAnimationSeconds();
		_homeTitleAnimationTimer = DispatcherQueue.CreateTimer();
		_homeTitleAnimationTimer.Interval = TimeSpan.FromMilliseconds(HomeTitleFrameIntervalMilliseconds);
		_homeTitleAnimationTimer.Tick += OnHomeTitleAnimationTimerTick;
		_homeTitleAnimationTimer.Start();
	}

	private void CreateHomeTitleLetters()
	{
		HomeTitleLettersPanel.Children.Clear();
		_homeTitleLetterStates.Clear();

		for (int index = 0; index < HomeTitleText.Length; index++)
		{
			char currentCharacter = HomeTitleText[index];
			bool isWordSeparator = char.IsWhiteSpace(currentCharacter);
			string characterText = isWordSeparator ? " " : currentCharacter.ToString();
			CompositeTransform letterTransform = new()
			{
				TranslateY = 0.0
			};
			StackPanel letterBlock = new()
			{
				Orientation = Orientation.Vertical,
				Height = HomeTitleLetterLineHeight * 2.0,
				Width = isWordSeparator ? HomeTitleWordGap : double.NaN,
				Margin = new Thickness(index == 0 ? 0.0 : HomeTitleLetterSpacing, 0.0, 0.0, 0.0),
				RenderTransform = letterTransform
			};

			TextBlock normalLetterTextBlock = CreateHomeTitleLetterTextBlock(characterText, new SolidColorBrush(Colors.White));
			TextBlock hoverLetterTextBlock = CreateHomeTitleLetterTextBlock(characterText, new SolidColorBrush(GetHomeTitleGoldenRodFadeColor(index, HomeTitleText.Length)));
			letterBlock.Children.Add(normalLetterTextBlock);
			letterBlock.Children.Add(hoverLetterTextBlock);
			HomeTitleLettersPanel.Children.Add(letterBlock);
			_homeTitleLetterStates.Add(new HomeTitleLetterState(letterTransform));
		}
	}

	private static TextBlock CreateHomeTitleLetterTextBlock(string text, Brush foregroundBrush) => new()
	{
		Text = text,
		Height = HomeTitleLetterLineHeight,
		LineHeight = HomeTitleLetterLineHeight,
		FontFamily = new FontFamily("Segoe UI Variable Display, Segoe UI Variable Text, Segoe UI"),
		FontSize = 18.0,
		Foreground = foregroundBrush,
		VerticalAlignment = VerticalAlignment.Center,
		TextAlignment = TextAlignment.Center
	};

	private static Color GetHomeTitleGoldenRodFadeColor(int letterIndex, int letterCount)
	{
		double progress = letterCount <= 1 ? 0.0 : letterIndex / (double)(letterCount - 1);
		Color goldenRodColor = Color.FromArgb(255, 218, 165, 32);
		Color softWhiteColor = Color.FromArgb(255, 255, 250, 235);
		return InterpolateHomeTitleColor(goldenRodColor, softWhiteColor, progress);
	}

	private static Color InterpolateHomeTitleColor(Color startColor, Color endColor, double progress)
	{
		double clampedProgress = Math.Clamp(progress, 0.0, 1.0);
		byte alpha = (byte)Math.Round(startColor.A + ((endColor.A - startColor.A) * clampedProgress));
		byte red = (byte)Math.Round(startColor.R + ((endColor.R - startColor.R) * clampedProgress));
		byte green = (byte)Math.Round(startColor.G + ((endColor.G - startColor.G) * clampedProgress));
		byte blue = (byte)Math.Round(startColor.B + ((endColor.B - startColor.B) * clampedProgress));
		return Color.FromArgb(alpha, red, green, blue);
	}

	private void OnHomeTitleBadgePointerEntered() => StartHomeTitleRollingAnimation(true);

	private void OnHomeTitleBadgePointerExited() => StartHomeTitleRollingAnimation(false);

	private void StartHomeTitleRollingAnimation(bool rollForward)
	{
		double targetTranslateY = rollForward ? -HomeTitleLetterLineHeight : 0.0;
		_homeTitleRollingAnimationStartSeconds = GetHomeTitleAnimationSeconds() - HomeTitleFirstFrameLeadSeconds;
		_homeTitleRollingAnimationActive = true;

		for (int index = 0; index < _homeTitleLetterStates.Count; index++)
		{
			HomeTitleLetterState letterState = _homeTitleLetterStates[index];
			letterState.StartTranslateY = letterState.Transform.TranslateY;
			letterState.TargetTranslateY = targetTranslateY;
		}

		UpdateHomeTitleRollingAnimation();
	}

	private void OnHomeTitleAnimationTimerTick(DispatcherQueueTimer sender, object args)
	{
		UpdateHomeTitlePulse();
		if (_homeTitleRollingAnimationActive)
		{
			UpdateHomeTitleRollingAnimation();
		}
	}

	private void UpdateHomeTitlePulse()
	{
		double elapsedSeconds = GetHomeTitleAnimationSeconds() - _homeTitlePulseStartSeconds;
		HomeTitlePulseDotEllipse.Opacity = 1.0;
		UpdateHomeTitlePulseRing(HomeTitlePulseRingOneEllipse, elapsedSeconds, 0.0);
		UpdateHomeTitlePulseRing(HomeTitlePulseRingTwoEllipse, elapsedSeconds, 2.27);
		UpdateHomeTitlePulseRing(HomeTitlePulseRingThreeEllipse, elapsedSeconds, 4.54);
	}

	private static void UpdateHomeTitlePulseRing(Ellipse pulseRing, double elapsedSeconds, double phaseOffsetSeconds)
	{
		const double pulseDurationSeconds = 6.8;
		const double minimumScale = 1.0;
		const double maximumScale = 3.35;
		double phaseSeconds = (elapsedSeconds + phaseOffsetSeconds) % pulseDurationSeconds;
		double progress = Math.Clamp(phaseSeconds / pulseDurationSeconds, 0.0, 1.0);
		double easedProgress = 1.0 - Math.Pow(1.0 - progress, 2.2);
		double scale = minimumScale + ((maximumScale - minimumScale) * easedProgress);
		double opacity = Math.Pow(1.0 - progress, 1.65) * 0.68;

		pulseRing.Opacity = opacity;
		if (pulseRing.RenderTransform is CompositeTransform pulseTransform)
		{
			pulseTransform.ScaleX = scale;
			pulseTransform.ScaleY = scale;
		}
	}

	private void UpdateHomeTitleRollingAnimation()
	{
		double nowSeconds = GetHomeTitleAnimationSeconds();
		bool allLettersCompleted = true;
		for (int index = 0; index < _homeTitleLetterStates.Count; index++)
		{
			HomeTitleLetterState letterState = _homeTitleLetterStates[index];
			double elapsedSeconds = nowSeconds - _homeTitleRollingAnimationStartSeconds - (HomeTitleLetterAnimationDelaySeconds * index);
			double rawProgress = elapsedSeconds / HomeTitleLetterAnimationDurationSeconds;
			if (rawProgress < 1.0)
			{
				allLettersCompleted = false;
			}
			double clampedProgress = Math.Clamp(rawProgress, 0.0, 1.0);
			double easedProgress = EvaluateHomeTitleCubicBezier(clampedProgress, 0.76, 0.0, 0.24, 1.0);
			letterState.Transform.TranslateY = letterState.StartTranslateY + ((letterState.TargetTranslateY - letterState.StartTranslateY) * easedProgress);
		}

		if (allLettersCompleted)
		{
			_homeTitleRollingAnimationActive = false;
			for (int index = 0; index < _homeTitleLetterStates.Count; index++)
			{
				HomeTitleLetterState letterState = _homeTitleLetterStates[index];
				letterState.Transform.TranslateY = letterState.TargetTranslateY;
			}
		}
	}

	private static double EvaluateHomeTitleCubicBezier(double progress, double controlPoint1X, double controlPoint1Y, double controlPoint2X, double controlPoint2Y)
	{
		double clampedProgress = Math.Clamp(progress, 0.0, 1.0);
		double parameter = clampedProgress;
		for (int iteration = 0; iteration < 8; iteration++)
		{
			double currentX = EvaluateHomeTitleBezier(parameter, 0.0, controlPoint1X, controlPoint2X, 1.0);
			double derivativeX = EvaluateHomeTitleBezierDerivative(parameter, 0.0, controlPoint1X, controlPoint2X, 1.0);
			if (Math.Abs(derivativeX) <= 0.000001)
			{
				break;
			}
			parameter -= (currentX - clampedProgress) / derivativeX;
			parameter = Math.Clamp(parameter, 0.0, 1.0);
		}
		return EvaluateHomeTitleBezier(parameter, 0.0, controlPoint1Y, controlPoint2Y, 1.0);
	}

	private static double EvaluateHomeTitleBezier(double parameter, double startValue, double controlPoint1Value, double controlPoint2Value, double endValue)
	{
		double inverseParameter = 1.0 - parameter;
		return (inverseParameter * inverseParameter * inverseParameter * startValue)
			+ (3.0 * inverseParameter * inverseParameter * parameter * controlPoint1Value)
			+ (3.0 * inverseParameter * parameter * parameter * controlPoint2Value)
			+ (parameter * parameter * parameter * endValue);
	}

	private static double EvaluateHomeTitleBezierDerivative(double parameter, double startValue, double controlPoint1Value, double controlPoint2Value, double endValue)
	{
		double inverseParameter = 1.0 - parameter;
		return (3.0 * inverseParameter * inverseParameter * (controlPoint1Value - startValue))
			+ (6.0 * inverseParameter * parameter * (controlPoint2Value - controlPoint1Value))
			+ (3.0 * parameter * parameter * (endValue - controlPoint2Value));
	}

	private static double GetHomeTitleAnimationSeconds() => Stopwatch.GetTimestamp() / (double)Stopwatch.Frequency;

	private sealed class HomeTitleLetterState(CompositeTransform transform)
	{
		internal CompositeTransform Transform => transform;
		internal double StartTranslateY { get; set; }
		internal double TargetTranslateY { get; set; }
	}

	private readonly struct GraphLayoutSettings(double itemWidth, double itemHeight, double cardWidth, double cardHeight, double graphHeight, double footerHeight, double valueMaxWidth, double valueFontSize, double labelFontSize)
	{
		internal double ItemWidth => itemWidth;
		internal double ItemHeight => itemHeight;
		internal double CardWidth => cardWidth;
		internal double CardHeight => cardHeight;
		internal double GraphHeight => graphHeight;
		internal double FooterHeight => footerHeight;
		internal double ValueMaxWidth => valueMaxWidth;
		internal double ValueFontSize => valueFontSize;
		internal double LabelFontSize => labelFontSize;
	}

	private void InitializeLiveGraphCardDepth()
	{
		ApplyLiveGraphCardDepth(AppRamCard, AppRamCardGlowReceiver);
		ApplyLiveGraphCardDepth(SystemMemoryUtilizationCard, SystemMemoryUtilizationCardGlowReceiver);
		ApplyLiveGraphCardDepth(StorageTemperatureCard, StorageTemperatureCardGlowReceiver);
		ApplyLiveGraphCardDepth(CpuTemperatureCard, CpuTemperatureCardGlowReceiver);
		ApplyLiveGraphCardDepth(CpuUsageCard, CpuUsageCardGlowReceiver);
		ApplyLiveGraphCardDepth(DiskActivityCard, DiskActivityCardGlowReceiver);
		ApplyLiveGraphCardDepth(NetworkUsageCard, NetworkUsageCardGlowReceiver);
	}

	private static void ApplyLiveGraphCardDepth(Border card, UIElement shadowReceiver)
	{
		ThemeShadow themeShadow = new();
		themeShadow.Receivers.Add(shadowReceiver);
		card.Shadow = themeShadow;
		card.Translation = new Vector3(0.0f, 0.0f, LiveGraphCardElevation);
	}

	private static Grid CreateLiveGraphCardFrame(Border card, Color firstGlowColor, Color secondGlowColor)
	{
		Grid cardFrame = new()
		{
			Width = 506.0 + (LiveGraphCardGlowBleed * 2.0),
			Height = 320.0 + (LiveGraphCardGlowBleed * 2.0),
			Margin = new Thickness(0.0, 0.0, LiveGraphCardSpacing, LiveGraphCardSpacing)
		};

		Border glowReceiver = CreateLiveGraphGlowLayer(firstGlowColor, secondGlowColor, 0.0, 34.0, LiveGraphCardGlowOpacity);
		Border innerGlow = CreateLiveGraphGlowLayer(secondGlowColor, firstGlowColor, 10.0, 30.0, 0.18);
		cardFrame.Children.Add(glowReceiver);
		cardFrame.Children.Add(innerGlow);

		card.Margin = new Thickness(LiveGraphCardGlowBleed);
		card.HorizontalAlignment = HorizontalAlignment.Stretch;
		card.VerticalAlignment = VerticalAlignment.Stretch;
		ApplyLiveGraphCardDepth(card, glowReceiver);
		cardFrame.Children.Add(card);
		return cardFrame;
	}

	private static Border CreateLiveGraphGlowLayer(Color firstColor, Color secondColor, double margin, double cornerRadius, double opacity)
	{
		LinearGradientBrush glowBrush = new()
		{
			StartPoint = new Point(0.0, 0.0),
			EndPoint = new Point(1.0, 1.0)
		};
		glowBrush.GradientStops.Add(new GradientStop() { Color = firstColor, Offset = 0.0 });
		glowBrush.GradientStops.Add(new GradientStop() { Color = Color.FromArgb(0, 16, 16, 16), Offset = 0.5 });
		glowBrush.GradientStops.Add(new GradientStop() { Color = secondColor, Offset = 1.0 });
		return new Border()
		{
			CornerRadius = new CornerRadius(cornerRadius),
			Margin = new Thickness(margin),
			Opacity = opacity,
			Background = glowBrush,
			IsHitTestVisible = false
		};
	}

	private void OnEffectiveMaximumChanged(object? sender, EventArgs args) => UpdateEffectiveMaximumLabels();

	private void UpdateEffectiveMaximumLabels()
	{
		AppRamChartMaxLabelTextBlock.Text = FormatMemoryRangeLabel(AppRamLiveGraph.EffectiveMaximum.ToString("0.##", CultureInfo.InvariantCulture));
		StorageTemperatureChartMaxLabelTextBlock.Text = FormatTemperatureRangeLabel(StorageTemperatureLiveGraph.EffectiveMaximum.ToString("0.##", CultureInfo.InvariantCulture));
		CpuTemperatureChartMaxLabelTextBlock.Text = FormatTemperatureRangeLabel(CpuTemperatureLiveGraph.EffectiveMaximum.ToString("0.##", CultureInfo.InvariantCulture));
	}

	private void OnBackgroundOpacitySliderValueChanged(object sender, RangeBaseValueChangedEventArgs args)
	{
		AnimatedBackgroundLayer.Opacity = args.NewValue;
		ApplySelectedBackgroundType();
	}

	private void OnBackgroundTypeComboBoxSelectionChanged()
	{
		if (_isGraphLayoutReady)
		{
			ApplySelectedBackgroundType();
		}
	}

	private void OnBackgroundPresetComboBoxSelectionChanged()
	{
		if (_isGraphLayoutReady)
		{
			ApplySelectedTesseractPreset();
		}
	}

	// If the opacity is 0, no background must consuming ANY system resources. Only 1 animated background must ever be consuming resources when opacity is bigger than 0.
	private void ApplySelectedBackgroundType()
	{
		bool shouldShowBackground = AnimatedBackgroundLayer.Opacity > 0.0;
		bool useBlackHoleBackground = shouldShowBackground && BackgroundTypeComboBox.SelectedIndex == 1;
		BackgroundPresetComboBox.Visibility = useBlackHoleBackground ? Visibility.Collapsed : Visibility.Visible;
		if (!shouldShowBackground)
		{
			StopBlackHoleBackground();
			RemoveBlackHoleBackground();
			RemoveAnimatedTesseractBackground();
			return;
		}
		if (useBlackHoleBackground)
		{
			RemoveAnimatedTesseractBackground();
			EnsureBlackHoleBackground();
			StartBlackHoleBackground();
			return;
		}
		StopBlackHoleBackground();
		RemoveBlackHoleBackground();
		EnsureAnimatedTesseractBackground();
		ApplySelectedTesseractPreset();
	}

	private void ApplySelectedTesseractPreset() => _animatedTesseractBackground?.ApplyPreset(BackgroundPresetComboBox.SelectedIndex == 1 ? AnimatedTesseractBackgroundPreset.BlueWhite : AnimatedTesseractBackgroundPreset.Green);

	private void EnsureAnimatedTesseractBackground()
	{
		if (_animatedTesseractBackground is not null)
		{
			return;
		}
		AnimatedTesseractBackground animatedTesseractBackground = new()
		{
			HorizontalAlignment = HorizontalAlignment.Stretch,
			VerticalAlignment = VerticalAlignment.Stretch
		};
		_animatedTesseractBackground = animatedTesseractBackground;
		AnimatedBackgroundLayer.Children.Add(animatedTesseractBackground);
	}

	private void RemoveAnimatedTesseractBackground()
	{
		if (_animatedTesseractBackground is not null)
		{
			_ = AnimatedBackgroundLayer.Children.Remove(_animatedTesseractBackground);
			_animatedTesseractBackground = null;
		}
	}

	private void EnsureBlackHoleBackground()
	{
		if (_blackHoleCanvas is null)
		{
			CanvasControl blackHoleCanvas = new()
			{
				ClearColor = Colors.Black,
				HorizontalAlignment = HorizontalAlignment.Stretch,
				VerticalAlignment = VerticalAlignment.Stretch
			};
			blackHoleCanvas.CreateResources += OnBlackHoleCanvasCreateResources;
			blackHoleCanvas.Draw += OnBlackHoleCanvasDraw;
			_blackHoleCanvas = blackHoleCanvas;
			AnimatedBackgroundLayer.Children.Add(blackHoleCanvas);
		}
	}

	private void RemoveBlackHoleBackground()
	{
		if (_blackHoleCanvas is null)
		{
			_blackHoleShaderEffect?.Dispose();
			_blackHoleShaderEffect = null;
			_blackHoleShaderBytecode = null;
			return;
		}
		_blackHoleCanvas.CreateResources -= OnBlackHoleCanvasCreateResources;
		_blackHoleCanvas.Draw -= OnBlackHoleCanvasDraw;
		_blackHoleCanvas.RemoveFromVisualTree();
		_ = AnimatedBackgroundLayer.Children.Remove(_blackHoleCanvas);
		_blackHoleCanvas = null;
		_blackHoleShaderEffect?.Dispose();
		_blackHoleShaderEffect = null;
		_blackHoleShaderBytecode = null;
	}

	private void OnBlackHoleCanvasCreateResources(CanvasControl sender, CanvasCreateResourcesEventArgs args) => EnsureBlackHoleShaderResources();

	private void OnBlackHoleRenderTimerTick(object? sender, object e) => _blackHoleCanvas?.Invalidate();

	private void StartBlackHoleBackground()
	{
		_blackHoleStartTime = DateTimeOffset.UtcNow;
		if (!_blackHoleRenderTimer.IsEnabled)
		{
			_blackHoleRenderTimer.Start();
		}
		_blackHoleCanvas?.Invalidate();
	}

	private void StopBlackHoleBackground()
	{
		if (_blackHoleRenderTimer.IsEnabled)
		{
			_blackHoleRenderTimer.Stop();
		}
	}

	private void OnBlackHoleCanvasDraw(CanvasControl sender, CanvasDrawEventArgs args)
	{
		EnsureBlackHoleShaderResources();
		if (_blackHoleShaderEffect is null)
		{
			return;
		}
		float width = (float)Math.Max(1.0, sender.ActualWidth);
		float height = (float)Math.Max(1.0, sender.ActualHeight);
		int physicalWidth = Math.Max(1, sender.ConvertDipsToPixels(width, CanvasDpiRounding.Round));
		int physicalHeight = Math.Max(1, sender.ConvertDipsToPixels(height, CanvasDpiRounding.Round));
		float elapsedSeconds = (float)(DateTimeOffset.UtcNow - _blackHoleStartTime).TotalSeconds;
		_blackHoleShaderEffect.Properties["t"] = elapsedSeconds;
		_blackHoleShaderEffect.Properties["r"] = new Vector2(physicalWidth, physicalHeight);
		args.DrawingSession.DrawImage(_blackHoleShaderEffect, new Windows.Foundation.Rect(0.0, 0.0, width, height), new Windows.Foundation.Rect(0.0, 0.0, width, height));
	}

	private void EnsureBlackHoleShaderResources()
	{
		if (_blackHoleShaderEffect is not null)
		{
			return;
		}
		if (_blackHoleShaderBytecode is null)
		{
			string shaderPath = System.IO.Path.Join(AppContext.BaseDirectory, BlackHoleShaderRelativePath);
			_blackHoleShaderBytecode = File.ReadAllBytes(shaderPath);
		}
		_blackHoleShaderEffect = new PixelShaderEffect(_blackHoleShaderBytecode);
	}

	public void Dispose()
	{
		if (_isDisposed)
		{
			return;
		}
		_isDisposed = true;
		ViewModel.OnLiveGraphsWindowClosed(this);
		_liveOnlyMetricTimer.Stop();
		_liveOnlyMetricTimer.Tick -= OnLiveOnlyMetricTimerTick;
		_diskActivityTimer.Stop();
		_diskActivityTimer.Tick -= OnDiskActivityTimerTick;
		_blackHoleRenderTimer.Stop();
		_blackHoleRenderTimer.Tick -= OnBlackHoleRenderTimerTick;
		StopSensorsMonitoring();
		if (_homeTitleAnimationTimer is not null)
		{
			_homeTitleAnimationTimer.Stop();
			_homeTitleAnimationTimer.Tick -= OnHomeTitleAnimationTimerTick;
			_homeTitleAnimationTimer = null;
		}
		StopBlackHoleBackground();
		RemoveBlackHoleBackground();
		RemoveAnimatedTesseractBackground();
		CloseCpuUsageCounters();
		CloseDiskActivityCounters();
		_gpuUsageTimer.Stop();
		if (_gpuUsageTimerSubscribed)
		{
			_gpuUsageTimer.Tick -= OnGpuUsageTimerTick;
			_gpuUsageTimerSubscribed = false;
		}

		CloseGpuCounters();
	}

	private void OnLiveOnlyMetricTimerTick(object? sender, object e) => UpdateLiveOnlyMetrics(firstNetworkSample: false);

	private void UpdateLiveOnlyMetrics(bool firstNetworkSample)
	{
		UpdateSystemMemoryUtilization();
		UpdateCpuUsage();
		UpdateNetworkUsage(firstNetworkSample);
	}

	private void UpdateSystemMemoryUtilization()
	{
		try
		{
			MEMORYSTATUSEX memoryStatus = default;
			memoryStatus.dwLength = (uint)Unsafe.SizeOf<MEMORYSTATUSEX>();
			if (!NativeMethods.GlobalMemoryStatusEx(ref memoryStatus) || memoryStatus.ullTotalPhys == 0UL)
			{
				SystemMemoryUtilizationValueTextBlock.Text = "Unavailable";
				return;
			}

			ulong availablePhysicalMemory = Math.Min(memoryStatus.ullAvailPhys, memoryStatus.ullTotalPhys);
			double memoryPercent = (memoryStatus.ullTotalPhys - availablePhysicalMemory) * 100.0 / memoryStatus.ullTotalPhys;
			memoryPercent = Math.Clamp(memoryPercent, 0.0, 100.0);
			SystemMemoryUtilizationValueTextBlock.Text = memoryPercent.ToString("0.0", CultureInfo.InvariantCulture) + " %";
			AddLiveMetricSample(_systemMemoryUtilizationSamples, memoryPercent);
			SystemMemoryUtilizationLiveGraph.Samples = _systemMemoryUtilizationSamples;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			SystemMemoryUtilizationValueTextBlock.Text = "Unavailable";
		}
	}

	private void UpdateCpuUsage()
	{
		try
		{
			if (!EnsureCpuUsageCountersInitialized())
			{
				CpuUsageValueTextBlock.Text = "Unavailable";
				return;
			}

			uint collectStatus = NativeMethods.PdhCollectQueryData(_cpuUsagePdhQuery);
			if (collectStatus != ErrorSuccess)
			{
				CpuUsageValueTextBlock.Text = "Unavailable";
				return;
			}

			double cpuPercent = Math.Clamp(GetFormattedCounterValue(_cpuUsageCounter), 0.0, 100.0);
			CpuUsageValueTextBlock.Text = cpuPercent.ToString("0.0", CultureInfo.InvariantCulture) + " %";
			AddLiveMetricSample(_cpuUsageSamples, cpuPercent);
			CpuUsageLiveGraph.Samples = _cpuUsageSamples;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			CpuUsageValueTextBlock.Text = "Unavailable";
		}
	}

	private bool EnsureCpuUsageCountersInitialized()
	{
		if (_cpuUsageCountersInitialized)
		{
			return true;
		}

		uint status = NativeMethods.PdhOpenQueryW(null, 0U, out _cpuUsagePdhQuery);
		if (status != ErrorSuccess || _cpuUsagePdhQuery == IntPtr.Zero)
		{
			return false;
		}

		status = NativeMethods.PdhAddEnglishCounterW(_cpuUsagePdhQuery, CpuUsageCounterPath, 0U, out _cpuUsageCounter);
		if (status != ErrorSuccess || _cpuUsageCounter == IntPtr.Zero)
		{
			CloseCpuUsageCounters();
			return false;
		}

		_ = NativeMethods.PdhCollectQueryData(_cpuUsagePdhQuery);
		_cpuUsageCountersInitialized = true;
		return true;
	}

	private void UpdateNetworkUsage(bool firstSample)
	{
		if (_liveNetworkInterfaceIndex == 0)
		{
			_liveNetworkInterfaceIndex = ResolveBestInterfaceIndex();
			if (_liveNetworkInterfaceIndex == 0)
			{
				NetworkUsageValueTextBlock.Text = "0.0 Mbps";
				AddNetworkUsageSample(0.0);
				return;
			}
		}

		MIB_IF_ROW2 row = default;
		row.InterfaceIndex = _liveNetworkInterfaceIndex;
		uint result = NativeMethods.GetIfEntry2(ref row);
		if (result != 0)
		{
			_liveNetworkInterfaceIndex = ResolveBestInterfaceIndex();
			if (_liveNetworkInterfaceIndex != 0)
			{
				row = default;
				row.InterfaceIndex = _liveNetworkInterfaceIndex;
				result = NativeMethods.GetIfEntry2(ref row);
			}
		}

		if (result != 0)
		{
			NetworkUsageValueTextBlock.Text = "0.0 Mbps";
			AddNetworkUsageSample(0.0);
			return;
		}

		long nowTicks = Environment.TickCount64;
		if (firstSample || _previousLiveNetworkSampleTicks == 0)
		{
			_previousLiveNetworkInBytes = row.InOctets;
			_previousLiveNetworkOutBytes = row.OutOctets;
			_previousLiveNetworkSampleTicks = nowTicks;
			NetworkUsageValueTextBlock.Text = "0.0 Mbps";
			AddNetworkUsageSample(0.0);
			return;
		}

		double elapsedSeconds = (nowTicks - _previousLiveNetworkSampleTicks) / 1000.0;
		if (elapsedSeconds <= 0.0)
		{
			return;
		}

		ulong currentInBytes = row.InOctets;
		ulong currentOutBytes = row.OutOctets;
		if (currentInBytes < _previousLiveNetworkInBytes || currentOutBytes < _previousLiveNetworkOutBytes)
		{
			_previousLiveNetworkInBytes = currentInBytes;
			_previousLiveNetworkOutBytes = currentOutBytes;
			_previousLiveNetworkSampleTicks = nowTicks;
			NetworkUsageValueTextBlock.Text = "0.0 Mbps";
			AddNetworkUsageSample(0.0);
			return;
		}

		ulong deltaInBytes = currentInBytes - _previousLiveNetworkInBytes;
		ulong deltaOutBytes = currentOutBytes - _previousLiveNetworkOutBytes;
		double bitsPerSecondDown = deltaInBytes * 8.0 / elapsedSeconds;
		double bitsPerSecondUp = deltaOutBytes * 8.0 / elapsedSeconds;
		_previousLiveNetworkInBytes = currentInBytes;
		_previousLiveNetworkOutBytes = currentOutBytes;
		_previousLiveNetworkSampleTicks = nowTicks;

		double totalMegabitsPerSecond = (bitsPerSecondDown + bitsPerSecondUp) / 1_000_000.0;
		NetworkUsageValueTextBlock.Text = totalMegabitsPerSecond.ToString("0.0", CultureInfo.InvariantCulture) + " Mbps";
		AddNetworkUsageSample(totalMegabitsPerSecond);
	}

	private static uint ResolveBestInterfaceIndex()
	{
		const uint destinationAddressNetworkOrder = (8 << 24) | (8 << 16) | (8 << 8) | 8;
		uint status = NativeMethods.GetBestInterface(destinationAddressNetworkOrder, out uint index);
		return status == 0 ? index : 0U;
	}

	private void AddNetworkUsageSample(double value)
	{
		AddLiveMetricSample(_networkUsageChartSamples, value);
		NetworkUsageLiveGraph.Samples = _networkUsageChartSamples;
		NetworkUsageChartMaxLabelTextBlock.Text = FormatThroughputRangeLabel(GetLiveMetricMaximumLabel(_networkUsageChartSamples));
	}

	private static void AddLiveMetricSample(List<double> samples, double value)
	{
		if (samples.Count >= HomeLiveMetricMaxSamples)
		{
			samples.RemoveAt(0);
		}
		samples.Add(Math.Max(0.0, value));
	}

	private static string GetLiveMetricMaximumLabel(List<double> samples)
	{
		if (samples.Count == 0)
		{
			return "0";
		}

		double maximum = samples[0];
		for (int index = 1; index < samples.Count; index++)
		{
			if (samples[index] > maximum)
			{
				maximum = samples[index];
			}
		}
		return maximum.ToString("0.#", CultureInfo.InvariantCulture);
	}

	private void OnDiskActivityTimerTick(object? sender, object e) => UpdateDiskActivity();

	private void OnLiveGraphsScrollViewerSizeChanged()
	{
		if (_isGraphLayoutReady)
		{
			ApplyGraphSize(_currentGraphSize);
			ApplyGpuGraphSizeFromCurrentSettings();
		}
	}

	private void OnGraphSizeComboBoxSelectionChanged()
	{
		if (!_isGraphLayoutReady)
		{
			return;
		}

		ApplyGraphSize((LiveGraphSize)GraphSizeComboBox.SelectedIndex);
		ApplyGpuGraphSizeFromCurrentSettings();
	}

	private static GraphLayoutSettings GetGraphLayoutSettings(LiveGraphSize graphSize) => graphSize switch
	{
		LiveGraphSize.Small => new GraphLayoutSettings(348.0, 234.0, 286.0, 172.0, 82.0, 26.0, 180.0, 10.0, 10.0),
		LiveGraphSize.Medium => new GraphLayoutSettings(438.0, 308.0, 376.0, 246.0, 158.0, 26.0, 190.0, 11.0, 11.0),
		_ => new GraphLayoutSettings(568.0, 382.0, 506.0, 320.0, 236.0, 28.0, 210.0, 12.0, 11.0)
	};

	private void ApplyGraphSize(LiveGraphSize graphSize)
	{
		if (!_isGraphLayoutReady)
		{
			return;
		}
		_currentGraphSize = graphSize;
		GraphLayoutSettings settings = GetGraphLayoutSettings(graphSize);
		double actualWidth = LiveGraphsScrollViewer.ActualWidth;
		double availableWrapWidth = double.IsNaN(actualWidth) || actualWidth <= 0.0 ? settings.ItemWidth : Math.Max(settings.ItemWidth, actualWidth - AvailableWidthReserve);
		int columns = Math.Clamp((int)Math.Floor(availableWrapWidth / settings.ItemWidth), 1, ChartCount);
		LiveGraphsWrapGrid.ItemWidth = settings.ItemWidth;
		LiveGraphsWrapGrid.ItemHeight = settings.ItemHeight;
		LiveGraphsWrapGrid.MaximumRowsOrColumns = columns;
		Grid[] cardFrames = [AppRamCardFrame, SystemMemoryUtilizationCardFrame, StorageTemperatureCardFrame, CpuTemperatureCardFrame, CpuUsageCardFrame, DiskActivityCardFrame, NetworkUsageCardFrame];
		Border[] cards = [AppRamCard, SystemMemoryUtilizationCard, StorageTemperatureCard, CpuTemperatureCard, CpuUsageCard, DiskActivityCard, NetworkUsageCard];
		RowDefinition[] graphRows = [AppRamGraphRow, SystemMemoryUtilizationGraphRow, StorageTemperatureGraphRow, CpuTemperatureGraphRow, CpuUsageGraphRow, DiskActivityGraphRow, NetworkUsageGraphRow];
		for (int index = 0; index < cards.Length; index++)
		{
			cardFrames[index].Width = settings.CardWidth + (LiveGraphCardGlowBleed * 2.0);
			cardFrames[index].Height = settings.CardHeight + (LiveGraphCardGlowBleed * 2.0);
			cards[index].Width = settings.CardWidth;
			cards[index].Height = settings.CardHeight;
			cards[index].Margin = new Thickness(LiveGraphCardGlowBleed);
			graphRows[index].Height = new GridLength(settings.GraphHeight);
		}
		ApplyFooterHeight(settings.FooterHeight);
		ApplyRangeLabelFontSize(settings.LabelFontSize);
		ApplyDiskActivityTextLayout(settings);
		UpdateDiskActivityValueText();
	}

	private void ApplyFooterHeight(double footerHeight)
	{
		RowDefinition[] footerRows = [AppRamGraphFooterRow, SystemMemoryUtilizationGraphFooterRow, StorageTemperatureGraphFooterRow, CpuTemperatureGraphFooterRow, CpuUsageGraphFooterRow, DiskActivityGraphFooterRow, NetworkUsageGraphFooterRow];
		for (int index = 0; index < footerRows.Length; index++)
		{
			footerRows[index].Height = new GridLength(footerHeight);
		}
	}

	private void ApplyDiskActivityTextLayout(GraphLayoutSettings settings)
	{
		DiskActivityValueTextBlock.MaxWidth = settings.ValueMaxWidth;
		DiskActivityValueTextBlock.FontSize = settings.ValueFontSize;
		DiskActivityValueTextBlock.LineHeight = 0.0;
		DiskActivityValueTextBlock.MaxHeight = double.PositiveInfinity;
	}

	private void ApplyRangeLabelFontSize(double fontSize)
	{
		TextBlock[] textBlocks = [AppRamChartMinLabelTextBlock, AppRamChartMaxLabelTextBlock, AppRamChartStartSecondsLabelTextBlock, SystemMemoryUtilizationChartMinLabelTextBlock, SystemMemoryUtilizationChartMaxLabelTextBlock, SystemMemoryUtilizationChartStartSecondsLabelTextBlock, StorageTemperatureChartMinLabelTextBlock, StorageTemperatureChartMaxLabelTextBlock, StorageTemperatureChartStartSecondsLabelTextBlock, CpuTemperatureChartMinLabelTextBlock, CpuTemperatureChartMaxLabelTextBlock, CpuTemperatureChartStartSecondsLabelTextBlock, CpuUsageChartMinLabelTextBlock, CpuUsageChartMaxLabelTextBlock, CpuUsageChartStartSecondsLabelTextBlock, DiskActivityMinLabelTextBlock, DiskActivityMaxLabelTextBlock, DiskActivityStartSecondsLabelTextBlock, NetworkUsageChartMinLabelTextBlock, NetworkUsageChartMaxLabelTextBlock, NetworkUsageChartStartSecondsLabelTextBlock];
		for (int index = 0; index < textBlocks.Length; index++)
		{
			textBlocks[index].FontSize = fontSize;
		}
	}

	private void UpdateDiskActivity()
	{
		if (!EnsureDiskActivityCountersInitialized())
		{
			DiskActivityValueTextBlock.Text = "Unavailable";
			return;
		}
		uint collectStatus = NativeMethods.PdhCollectQueryData(_diskActivityPdhQuery);
		if (collectStatus != ErrorSuccess)
		{
			DiskActivityValueTextBlock.Text = "Unavailable";
			return;
		}
		_lastDiskReadBytesPerSecond = GetFormattedCounterValue(_diskReadSpeedCounter);
		_lastDiskWriteBytesPerSecond = GetFormattedCounterValue(_diskWriteSpeedCounter);
		UpdateDiskActivityValueText();
		AddDiskActivitySample(_diskReadMegabytesPerSecondSamples, _lastDiskReadBytesPerSecond / 1024.0 / 1024.0);
		AddDiskActivitySample(_diskWriteMegabytesPerSecondSamples, _lastDiskWriteBytesPerSecond / 1024.0 / 1024.0);
		DiskActivityLiveGraph.Samples = _diskWriteMegabytesPerSecondSamples;
		DiskActivityLiveGraph.SecondarySamples = _diskReadMegabytesPerSecondSamples;
		UpdateDiskActivityLabels();
	}

	private void UpdateDiskActivityValueText()
	{
		string readText = FormatThroughput(_lastDiskReadBytesPerSecond);
		string writeText = FormatThroughput(_lastDiskWriteBytesPerSecond);
		DiskActivityValueTextBlock.Text = _currentGraphSize == LiveGraphSize.Big ? "R: " + readText + " - W: " + writeText : readText;
	}

	private bool EnsureDiskActivityCountersInitialized()
	{
		if (_diskActivityCountersInitialized)
		{
			return true;
		}
		uint status = NativeMethods.PdhOpenQueryW(null, 0U, out _diskActivityPdhQuery);
		if (status != ErrorSuccess || _diskActivityPdhQuery == IntPtr.Zero)
		{
			return false;
		}
		status = NativeMethods.PdhAddEnglishCounterW(_diskActivityPdhQuery, @"\PhysicalDisk(_Total)\Disk Read Bytes/sec", 0U, out _diskReadSpeedCounter);
		if (status != ErrorSuccess)
		{
			CloseDiskActivityCounters();
			return false;
		}
		status = NativeMethods.PdhAddEnglishCounterW(_diskActivityPdhQuery, @"\PhysicalDisk(_Total)\Disk Write Bytes/sec", 0U, out _diskWriteSpeedCounter);
		if (status != ErrorSuccess)
		{
			CloseDiskActivityCounters();
			return false;
		}
		_ = NativeMethods.PdhCollectQueryData(_diskActivityPdhQuery);
		_diskActivityCountersInitialized = true;
		return true;
	}

	private static double GetFormattedCounterValue(IntPtr counterHandle)
	{
		uint status = NativeMethods.PdhGetFormattedCounterValue(counterHandle, PdhFormatDouble, out uint _, out PDH_FMT_COUNTERVALUE_DOUBLE counterValue);
		return status == ErrorSuccess && counterValue.CStatus == ErrorSuccess ? Math.Max(0.0, counterValue.Value) : 0.0;
	}

	private static void AddDiskActivitySample(List<double> samples, double value)
	{
		if (samples.Count >= DiskActivityMaxSamples)
		{
			samples.RemoveAt(0);
		}
		samples.Add(Math.Max(0.0, value));
	}

	private void UpdateDiskActivityLabels()
	{
		double minimum = 0.0;
		double maximum = 0.0;
		bool hasValue = false;
		UpdateMinMax(_diskReadMegabytesPerSecondSamples, ref minimum, ref maximum, ref hasValue);
		UpdateMinMax(_diskWriteMegabytesPerSecondSamples, ref minimum, ref maximum, ref hasValue);
		DiskActivityMinLabelTextBlock.Text = "0 MB/s";
		DiskActivityMaxLabelTextBlock.Text = hasValue ? maximum.ToString("0.##", CultureInfo.InvariantCulture) + " MB/s" : "0 MB/s";
	}

	private static void UpdateMinMax(List<double> samples, ref double minimum, ref double maximum, ref bool hasValue)
	{
		for (int index = 0; index < samples.Count; index++)
		{
			double value = samples[index];
			if (!hasValue)
			{
				hasValue = true;
				minimum = value;
				maximum = value;
				continue;
			}
			if (value < minimum)
			{
				minimum = value;
			}
			if (value > maximum)
			{
				maximum = value;
			}
		}
	}

	private static string FormatThroughput(double bytesPerSecond)
	{
		string[] units = ["B/s", "KB/s", "MB/s", "GB/s"];
		double value = Math.Max(0.0, bytesPerSecond);
		int unitIndex = 0;
		while (value >= 1024.0 && unitIndex < units.Length - 1)
		{
			value /= 1024.0;
			unitIndex++;
		}
		return value.ToString(unitIndex == 0 ? "0" : "0.##", CultureInfo.InvariantCulture) + " " + units[unitIndex];
	}

	internal static string FormatMemoryRangeLabel(string? value) => AppendUnit(value, "MB");
	internal static string FormatTemperatureRangeLabel(string? value) => AppendUnit(value, "°C");
	internal static string FormatThroughputRangeLabel(string? value) => AppendUnit(value, "MB/s");

	private static string AppendUnit(string? value, string unit)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return "0 " + unit;
		}
		string trimmedValue = value.Trim();
		return trimmedValue.Contains('%', StringComparison.OrdinalIgnoreCase) || trimmedValue.Contains('°', StringComparison.OrdinalIgnoreCase) || trimmedValue.Contains('B', StringComparison.OrdinalIgnoreCase) || trimmedValue.Contains('C', StringComparison.OrdinalIgnoreCase) ? trimmedValue : trimmedValue + " " + unit;
	}

	private void CloseCpuUsageCounters()
	{
		if (_cpuUsageCounter != IntPtr.Zero)
		{
			_ = NativeMethods.PdhRemoveCounter(_cpuUsageCounter);
			_cpuUsageCounter = IntPtr.Zero;
		}

		if (_cpuUsagePdhQuery != IntPtr.Zero)
		{
			_ = NativeMethods.PdhCloseQuery(_cpuUsagePdhQuery);
			_cpuUsagePdhQuery = IntPtr.Zero;
		}

		_cpuUsageCountersInitialized = false;
	}

	private void CloseDiskActivityCounters()
	{
		if (_diskReadSpeedCounter != IntPtr.Zero)
		{
			_ = NativeMethods.PdhRemoveCounter(_diskReadSpeedCounter);
			_diskReadSpeedCounter = IntPtr.Zero;
		}
		if (_diskWriteSpeedCounter != IntPtr.Zero)
		{
			_ = NativeMethods.PdhRemoveCounter(_diskWriteSpeedCounter);
			_diskWriteSpeedCounter = IntPtr.Zero;
		}
		if (_diskActivityPdhQuery != IntPtr.Zero)
		{
			_ = NativeMethods.PdhCloseQuery(_diskActivityPdhQuery);
			_diskActivityPdhQuery = IntPtr.Zero;
		}
		_diskActivityCountersInitialized = false;
	}
}

internal enum AnimatedTesseractBackgroundPreset
{
	Green,
	BlueWhite
}

internal sealed partial class AnimatedTesseractBackground : Canvas
{
	private const int DotCount = 160;
	private const int RingOneSegments = 30;
	private const int RingTwoSegments = 20;
	private const double AssembleDurationSeconds = 12.0;
	private const double DotTargetEasing = 0.06;
	private const double ProjectionDistance = 200.0;
	private const double ProjectionDepthOffset = 4.0;
	private static readonly int[][] Edges = [[0, 1], [1, 2], [2, 3], [3, 0], [4, 5], [5, 6], [6, 7], [7, 4], [0, 4], [1, 5], [2, 6], [3, 7]];
	private static readonly double[][] CubeCoordinates = [[-1.0, -1.0, -1.0], [1.0, -1.0, -1.0], [1.0, 1.0, -1.0], [-1.0, 1.0, -1.0], [-1.0, -1.0, 1.0], [1.0, -1.0, 1.0], [1.0, 1.0, 1.0], [-1.0, 1.0, 1.0]];
	private readonly DispatcherQueueTimer _animationTimer;
	private readonly Random _random = new();
	private readonly DotState[] _dots = new DotState[DotCount];
	private readonly Ellipse[] _dotElements = new Ellipse[DotCount];
	private readonly Line[] _outerLines = new Line[12];
	private readonly Line[] _innerLines = new Line[12];
	private readonly Point2D[] _dotTesseractPoints = new Point2D[8];
	private readonly Point2D[] _outerTesseractLinePoints = new Point2D[8];
	private readonly Point2D[] _innerTesseractLinePoints = new Point2D[8];
	private readonly Point2D[] _ringOnePoints = new Point2D[RingOneSegments * 2];
	private readonly Point2D[] _ringTwoPoints = new Point2D[RingTwoSegments * 2];
	private readonly SolidColorBrush _backgroundBrush = new(Color.FromArgb(255, 0, 5, 3));
	private readonly SolidColorBrush _dotBrush = new(Color.FromArgb(255, 0, 255, 180));
	private readonly SolidColorBrush _lineBrush = new(Color.FromArgb(90, 0, 255, 180));
	private bool _isInitialized;
	private double _width;
	private double _height;
	private DateTimeOffset _startTime;

	internal AnimatedTesseractBackground()
	{
		IsHitTestVisible = false;
		Clip = new RectangleGeometry();
		Background = _backgroundBrush;
		SizeChanged += OnSizeChanged;
		Unloaded += OnUnloaded;
		CreateVisualChildren();
		ApplyPreset(AnimatedTesseractBackgroundPreset.Green);
		_animationTimer = DispatcherQueue.CreateTimer();
		_animationTimer.Interval = TimeSpan.FromMilliseconds(16.0);
		_animationTimer.Tick += OnAnimationTick;
	}

	internal void ApplyPreset(AnimatedTesseractBackgroundPreset preset)
	{
		if (preset == AnimatedTesseractBackgroundPreset.BlueWhite)
		{
			_backgroundBrush.Color = Color.FromArgb(255, 2, 7, 22);
			_dotBrush.Color = Color.FromArgb(255, 92, 180, 255);
			_lineBrush.Color = Color.FromArgb(120, 245, 250, 255);
			return;
		}
		_backgroundBrush.Color = Color.FromArgb(255, 0, 5, 3);
		_dotBrush.Color = Color.FromArgb(255, 0, 255, 180);
		_lineBrush.Color = Color.FromArgb(90, 0, 255, 180);
	}

	private struct DotState
	{
		internal double X { get; set; }
		internal double Y { get; set; }
		internal double TargetX { get; set; }
		internal double TargetY { get; set; }
		internal double Radius { get; set; }
	}

	private readonly struct Point2D(double x, double y)
	{
		internal double X => x;
		internal double Y => y;
	}

	private void CreateVisualChildren()
	{
		for (int index = 0; index < _outerLines.Length; index++)
		{
			Line outerLine = new() { Stroke = _lineBrush, StrokeThickness = 1.0, Opacity = 0.35 };
			Line innerLine = new() { Stroke = _lineBrush, StrokeThickness = 1.0, Opacity = 0.35 };
			_outerLines[index] = outerLine;
			_innerLines[index] = innerLine;
			Children.Add(outerLine);
			Children.Add(innerLine);
		}
		for (int index = 0; index < DotCount; index++)
		{
			Ellipse dotElement = new() { Fill = _dotBrush, Opacity = 0.18 };
			_dotElements[index] = dotElement;
			Children.Add(dotElement);
		}
	}

	private void OnSizeChanged(object sender, SizeChangedEventArgs args)
	{
		_width = Math.Max(1.0, args.NewSize.Width);
		_height = Math.Max(1.0, args.NewSize.Height);
		if (Clip is RectangleGeometry clipRectangle)
		{
			clipRectangle.Rect = new Windows.Foundation.Rect(0.0, 0.0, _width, _height);
		}
		InitializeDotsIfNeeded();
		if (!_animationTimer.IsRunning)
		{
			_startTime = DateTimeOffset.UtcNow;
			_animationTimer.Start();
		}
	}

	private void InitializeDotsIfNeeded()
	{
		if (_isInitialized)
		{
			return;
		}
		for (int index = 0; index < DotCount; index++)
		{
			_dots[index] = new DotState() { X = _random.NextDouble() * _width, Y = _random.NextDouble() * _height, TargetX = _width / 2.0, TargetY = _height / 2.0, Radius = _random.NextDouble() * 1.6 + 0.5 };
		}
		_isInitialized = true;
	}

	private void OnAnimationTick(DispatcherQueueTimer sender, object args)
	{
		if (_width <= 1.0 || _height <= 1.0)
		{
			return;
		}
		DateTimeOffset now = DateTimeOffset.UtcNow;
		double elapsedMilliseconds = (now - _startTime).TotalMilliseconds;
		double elapsedSeconds = elapsedMilliseconds / 1000.0;
		double assemble = Math.Min(1.0, elapsedSeconds / AssembleDurationSeconds);
		double pulse = 0.5 + (0.5 * Math.Sin(elapsedMilliseconds / 1000.0));
		double minimumDimension = Math.Min(_width, _height);
		FillTesseractPoints(_dotTesseractPoints, elapsedMilliseconds, 1.0 + (0.02 * pulse));
		FillRingPoints(_ringOnePoints, minimumDimension / 3.2 * (1.0 + (0.03 * Math.Sin(elapsedMilliseconds / 1200.0))), RingOneSegments);
		FillRingPoints(_ringTwoPoints, minimumDimension / 2.3 * (1.0 + (0.02 * Math.Cos(elapsedMilliseconds / 1500.0))), RingTwoSegments);
		UpdateDots(_dotTesseractPoints, _ringOnePoints, _ringTwoPoints, assemble, pulse);
		FillTesseractPoints(_outerTesseractLinePoints, elapsedMilliseconds, 1.0);
		FillTesseractPoints(_innerTesseractLinePoints, elapsedMilliseconds * 1.1, 0.6);
		UpdateTesseractLines(_outerTesseractLinePoints, _outerLines, pulse);
		UpdateTesseractLines(_innerTesseractLinePoints, _innerLines, pulse);
	}

	private void UpdateDots(Point2D[] tesseractPoints, Point2D[] ringOnePoints, Point2D[] ringTwoPoints, double assemble, double pulse)
	{
		int geometryLength = tesseractPoints.Length + ringOnePoints.Length + ringTwoPoints.Length;
		double movementEasing = 0.05 + (0.05 * assemble);
		double opacity = 0.18 + (0.3 * pulse);
		for (int index = 0; index < DotCount; index++)
		{
			Point2D target = GetGeometryPoint(index % geometryLength, tesseractPoints, ringOnePoints, ringTwoPoints);
			DotState dot = _dots[index];
			dot.TargetX += (target.X - dot.TargetX) * DotTargetEasing;
			dot.TargetY += (target.Y - dot.TargetY) * DotTargetEasing;
			dot.X += (dot.TargetX - dot.X) * movementEasing;
			dot.Y += (dot.TargetY - dot.Y) * movementEasing;
			_dots[index] = dot;
			double radius = dot.Radius * (1.0 + (0.4 * pulse));
			Ellipse dotElement = _dotElements[index];
			dotElement.Width = radius * 2.0;
			dotElement.Height = radius * 2.0;
			dotElement.Opacity = opacity;
			SetLeft(dotElement, dot.X - radius);
			SetTop(dotElement, dot.Y - radius);
		}
	}

	private static Point2D GetGeometryPoint(int geometryIndex, Point2D[] tesseractPoints, Point2D[] ringOnePoints, Point2D[] ringTwoPoints)
	{
		if (geometryIndex < tesseractPoints.Length)
		{
			return tesseractPoints[geometryIndex];
		}
		geometryIndex -= tesseractPoints.Length;
		if (geometryIndex < ringOnePoints.Length)
		{
			return ringOnePoints[geometryIndex];
		}
		geometryIndex -= ringOnePoints.Length;
		return ringTwoPoints[geometryIndex];
	}

	private void FillTesseractPoints(Point2D[] points, double elapsedMilliseconds, double scale)
	{
		double centerX = _width / 2.0;
		double centerY = _height / 2.0;
		double size = Math.Min(_width, _height) / 10.0 * scale;
		double rotation = elapsedMilliseconds / 4000.0;
		double cosRotation = Math.Cos(rotation);
		double sinRotation = Math.Sin(rotation);
		for (int index = 0; index < 8; index++)
		{
			double x = CubeCoordinates[index][0] * size;
			double y = CubeCoordinates[index][1] * size;
			double z = CubeCoordinates[index][2];
			double rotatedX = (x * cosRotation) - (y * sinRotation);
			double rotatedY = (x * sinRotation) + (y * cosRotation);
			double projectionScale = ProjectionDistance / (z + ProjectionDepthOffset);
			points[index] = new Point2D(centerX + rotatedX * projectionScale / size, centerY + rotatedY * projectionScale / size);
		}
	}

	private void FillRingPoints(Point2D[] points, double radius, int segments)
	{
		int pointCount = segments * 2;
		double centerX = _width / 2.0;
		double centerY = _height / 2.0;
		for (int index = 0; index < pointCount; index++)
		{
			double angle = index * Math.PI / segments;
			points[index] = new Point2D(centerX + (radius * Math.Cos(angle)), centerY + (radius * Math.Sin(angle)));
		}
	}

	private static void UpdateTesseractLines(Point2D[] points, Line[] lines, double pulse)
	{
		double opacity = 0.25 + (0.25 * pulse);
		for (int index = 0; index < lines.Length; index++)
		{
			int startIndex = Edges[index][0];
			int endIndex = Edges[index][1];
			Line line = lines[index];
			line.X1 = points[startIndex].X;
			line.Y1 = points[startIndex].Y;
			line.X2 = points[endIndex].X;
			line.Y2 = points[endIndex].Y;
			line.Opacity = opacity;
		}
	}

	private void OnUnloaded(object sender, RoutedEventArgs args)
	{
		_animationTimer.Stop();
		_animationTimer.Tick -= OnAnimationTick;
		SizeChanged -= OnSizeChanged;
		Unloaded -= OnUnloaded;
	}
}

internal sealed partial class HomeLiveGraphsWindow
{
	private const int GpuUsageMaxSamples = 120;
	private const uint GpuPdhMoreData = 0x800007D2U;
	private const uint GpuPdhFormatDouble = 0x00000200U;
	private const uint GpuErrorSuccess = 0U;
	private const int GpuComSuccess = 0;
	private const uint GpuDxgiAdapterFlagSoftware = 2U;
	private const string GpuEngineUtilizationWildcardPath = @"\GPU Engine(*)\Utilization Percentage";
	private const string GpuLuidToken = "luid_";
	private const string GpuPhysicalToken = "_phys_";
	private const string GpuEngineToken = "_eng_";
	private const string DisplayAdapterAqsFilter = "System.Devices.ClassGuid:=\"{4d36e968-e325-11ce-bfc1-08002be10318}\"";

	private readonly DispatcherTimer _gpuUsageTimer = new();
	private readonly Dictionary<string, GpuChartState> _gpuChartStates = new(StringComparer.OrdinalIgnoreCase);
	private IntPtr _gpuEngineUtilizationCounter;
	private readonly List<string> _gpuDisplayNames = new();
	private readonly Dictionary<string, GpuDxgiAdapterDescriptor> _gpuDxgiAdaptersByLuid = new(StringComparer.OrdinalIgnoreCase);
	private readonly Dictionary<string, string> _gpuDxgiDisplayNamesByGroupKey = new(StringComparer.OrdinalIgnoreCase);
	private readonly Dictionary<string, int> _gpuDxgiDisplayIndexesByGroupKey = new(StringComparer.OrdinalIgnoreCase);
	// Reused on each GPU poll to avoid allocating a totals dictionary every tick.
	private readonly Dictionary<string, double> _gpuAdapterTotals = new(StringComparer.OrdinalIgnoreCase);
	private bool _gpuUsageInitialized;
	private bool _gpuUsageTimerSubscribed;
	private IntPtr _gpuPdhQuery;


	private sealed class GpuChartState(int displayIndex, Grid cardFrame, Border card, RowDefinition graphRow, RowDefinition footerRow, HomeLiveLineGraph graph, TextBlock titleTextBlock, TextBlock valueTextBlock, TextBlock maxLabelTextBlock, TextBlock minLabelTextBlock, TextBlock startSecondsLabelTextBlock)
	{
		internal int DisplayIndex => displayIndex;
		internal Grid CardFrame => cardFrame;
		internal Border Card => card;
		internal RowDefinition GraphRow => graphRow;
		internal RowDefinition FooterRow => footerRow;
		internal HomeLiveLineGraph Graph => graph;
		internal TextBlock TitleTextBlock => titleTextBlock;
		internal TextBlock ValueTextBlock => valueTextBlock;
		internal TextBlock MaxLabelTextBlock => maxLabelTextBlock;
		internal TextBlock MinLabelTextBlock => minLabelTextBlock;
		internal TextBlock StartSecondsLabelTextBlock => startSecondsLabelTextBlock;
		internal readonly List<double> Samples = new(GpuUsageMaxSamples);
	}


	private sealed class GpuDxgiAdapterDescriptor(string groupKey, string displayName, int displayIndex)
	{
		internal string GroupKey => groupKey;
		internal string DisplayName => displayName;
		internal int DisplayIndex => displayIndex;
	}

	private void OnRootGridLoaded(object sender, RoutedEventArgs e)
	{
		// The window is created to be used in Dark mode.
		if (sender is Grid grid)
		{
			grid.RequestedTheme = ElementTheme.Dark;
		}

		ApplySelectedBackgroundType();
		InitializeGpuUsageCharts();
		_ = UpdateGpuDisplayNamesAsync();
	}

	private void ApplyGpuGraphSizeFromCurrentSettings()
	{
		if (!_isGraphLayoutReady || _gpuChartStates.Count == 0)
		{
			return;
		}

		GraphLayoutSettings settings = GetGraphLayoutSettings(_currentGraphSize);
		foreach (KeyValuePair<string, GpuChartState> chartStatePair in _gpuChartStates)
		{
			GpuChartState chartState = chartStatePair.Value;
			chartState.CardFrame.Width = settings.CardWidth + (LiveGraphCardGlowBleed * 2.0);
			chartState.CardFrame.Height = settings.CardHeight + (LiveGraphCardGlowBleed * 2.0);
			chartState.Card.Width = settings.CardWidth;
			chartState.Card.Height = settings.CardHeight;
			chartState.Card.Margin = new Thickness(LiveGraphCardGlowBleed);
			chartState.GraphRow.Height = new GridLength(settings.GraphHeight);
			chartState.FooterRow.Height = new GridLength(settings.FooterHeight);
			chartState.ValueTextBlock.MaxWidth = settings.ValueMaxWidth;
			chartState.ValueTextBlock.FontSize = settings.ValueFontSize;
			chartState.MaxLabelTextBlock.FontSize = settings.LabelFontSize;
			chartState.MinLabelTextBlock.FontSize = settings.LabelFontSize;
			chartState.StartSecondsLabelTextBlock.FontSize = settings.LabelFontSize;
			chartState.TitleTextBlock.MaxWidth = Math.Max(120.0, settings.CardWidth - 120.0);
		}
	}

	private async Task UpdateGpuDisplayNamesAsync()
	{
		try
		{
			string[] requestedProperties = ["System.ItemNameDisplay"];
			DeviceInformationCollection displayAdapters = await DeviceInformation.FindAllAsync(DisplayAdapterAqsFilter, requestedProperties, DeviceInformationKind.Device);
			_gpuDisplayNames.Clear();
			for (int index = 0; index < displayAdapters.Count; index++)
			{
				DeviceInformation displayAdapter = displayAdapters[index];
				string displayName = GetBestDisplayAdapterName(displayAdapter);
				if (string.IsNullOrWhiteSpace(displayName) || ContainsGpuDisplayName(displayName))
				{
					continue;
				}

				_gpuDisplayNames.Add(displayName);
			}

			ApplyGpuDisplayNames();
			EnsureGpuUsageTimerStarted();
		}
		catch (Exception)
		{
			_gpuDisplayNames.Clear();
		}
	}

	private static string GetBestDisplayAdapterName(DeviceInformation displayAdapter)
	{
		if (displayAdapter.Properties.TryGetValue("System.ItemNameDisplay", out object? displayNameProperty) && displayNameProperty is string displayNameText && !string.IsNullOrWhiteSpace(displayNameText))
		{
			return displayNameText.Trim();
		}

		return string.IsNullOrWhiteSpace(displayAdapter.Name) ? string.Empty : displayAdapter.Name.Trim();
	}

	private bool ContainsGpuDisplayName(string displayName)
	{
		for (int index = 0; index < _gpuDisplayNames.Count; index++)
		{
			if (string.Equals(_gpuDisplayNames[index], displayName, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		return false;
	}

	private void ApplyGpuDisplayNames()
	{
		foreach (KeyValuePair<string, GpuChartState> chartStatePair in _gpuChartStates)
		{
			GpuChartState chartState = chartStatePair.Value;
			string displayName = GetGpuDisplayName(chartState.DisplayIndex);
			chartState.TitleTextBlock.Text = displayName;
			chartState.Graph.PrimarySeriesName = displayName;
		}
	}

	private string GetGpuAdapterDisplayName(string adapterKey, int displayIndex)
	{
		string? privacyDisplayName = null;
		ApplyPrivacyModeGpuDisplayNameOverride(displayIndex, ref privacyDisplayName);
		if (!string.IsNullOrWhiteSpace(privacyDisplayName))
		{
			return privacyDisplayName;
		}

		return _gpuDxgiDisplayNamesByGroupKey.TryGetValue(adapterKey, out string? dxgiDisplayName) ? dxgiDisplayName : GetGpuDisplayName(displayIndex);
	}

	private int GetGpuAdapterDisplayIndex(string adapterKey, int fallbackIndex)
	{
		return _gpuDxgiDisplayIndexesByGroupKey.TryGetValue(adapterKey, out int displayIndex) ? displayIndex : fallbackIndex;
	}

	private string GetGpuDisplayName(int displayIndex)
	{
		string? privacyDisplayName = null;
		ApplyPrivacyModeGpuDisplayNameOverride(displayIndex, ref privacyDisplayName);
		if (!string.IsNullOrWhiteSpace(privacyDisplayName))
		{
			return privacyDisplayName;
		}

		if (displayIndex >= 0 && displayIndex < _gpuDisplayNames.Count)
		{
			return _gpuDisplayNames[displayIndex];
		}

		return "GPU " + displayIndex.ToString(CultureInfo.InvariantCulture) + " Usage";
	}

	private void InitializeGpuUsageCharts()
	{
		if (_gpuUsageInitialized)
		{
			return;
		}

		_gpuUsageInitialized = true;
		InitializeGpuCounters();
		EnsureGpuUsageTimerStarted();
	}

	private void EnsureGpuUsageTimerStarted()
	{
		if (_gpuPdhQuery == IntPtr.Zero || _gpuEngineUtilizationCounter == IntPtr.Zero)
		{
			return;
		}

		if (!_gpuUsageTimerSubscribed)
		{
			_gpuUsageTimer.Interval = TimeSpan.FromSeconds(2.0);
			_gpuUsageTimer.Tick += OnGpuUsageTimerTick;
			_gpuUsageTimerSubscribed = true;
		}

		UpdateGpuUsage();

		if (!_gpuUsageTimer.IsEnabled)
		{
			_gpuUsageTimer.Start();
		}
	}

	private void OnGpuUsageTimerTick(object? sender, object e) => UpdateGpuUsage();

	private void InitializeGpuCounters()
	{
		RefreshDxgiGpuAdapterMap();

		uint openStatus = NativeMethods.PdhOpenQueryW(null, 0U, out _gpuPdhQuery);
		if (openStatus != GpuErrorSuccess || _gpuPdhQuery == IntPtr.Zero)
		{
			return;
		}

		uint addStatus = NativeMethods.PdhAddEnglishCounterW(_gpuPdhQuery, GpuEngineUtilizationWildcardPath, 0U, out _gpuEngineUtilizationCounter);
		if (addStatus != GpuErrorSuccess || _gpuEngineUtilizationCounter == IntPtr.Zero)
		{
			CloseGpuCounters();
			return;
		}

		_ = NativeMethods.PdhCollectQueryData(_gpuPdhQuery);
	}

	private unsafe void RefreshDxgiGpuAdapterMap()
	{
		_gpuDxgiAdaptersByLuid.Clear();
		_gpuDxgiDisplayNamesByGroupKey.Clear();
		_gpuDxgiDisplayIndexesByGroupKey.Clear();

		Guid dxgiFactory1Id = new("770aae78-f26f-4dba-a829-253c83d1b387");
		int createStatus = NativeMethods.CreateDXGIFactory1(in dxgiFactory1Id, out IntPtr dxgiFactory);
		if (createStatus != GpuComSuccess || dxgiFactory == IntPtr.Zero)
		{
			return;
		}

		try
		{
			IntPtr* factoryVTable = *(IntPtr**)dxgiFactory;
			delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr*, int> enumAdapters1 = (delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr*, int>)factoryVTable[12];

			for (uint adapterIndex = 0U; ; adapterIndex++)
			{
				IntPtr dxgiAdapter = IntPtr.Zero;
				int enumStatus = enumAdapters1(dxgiFactory, adapterIndex, &dxgiAdapter);

				// IDXGIFactory1::EnumAdapters1 writes the adapter pointer through an unmanaged output pointer.
				// Reload the value so CA1508 does not treat the original zero initialization as unchanged.
				dxgiAdapter = Volatile.Read(ref dxgiAdapter);

				if (enumStatus != GpuComSuccess || dxgiAdapter == IntPtr.Zero)
				{
					break;
				}

				try
				{
					AddDxgiAdapterToGpuMap(dxgiAdapter);
				}
				finally
				{
					ReleaseComObject(dxgiAdapter);
				}
			}
		}
		finally
		{
			ReleaseComObject(dxgiFactory);
		}
	}

	private unsafe void AddDxgiAdapterToGpuMap(IntPtr dxgiAdapter)
	{
		IntPtr* adapterVTable = *(IntPtr**)dxgiAdapter;
		delegate* unmanaged[Stdcall]<IntPtr, DXGI_ADAPTER_DESC1*, int> getDesc1 = (delegate* unmanaged[Stdcall]<IntPtr, DXGI_ADAPTER_DESC1*, int>)adapterVTable[10];
		DXGI_ADAPTER_DESC1 adapterDescription = default;
		int getDescStatus = getDesc1(dxgiAdapter, &adapterDescription);
		if (getDescStatus != GpuComSuccess || (adapterDescription.Flags & GpuDxgiAdapterFlagSoftware) != 0U)
		{
			return;
		}

		string luidKey = CreateGpuLuidAdapterKey(adapterDescription.AdapterLuid);
		string groupKey = CreateGpuDxgiAdapterGroupKey(adapterDescription);
		if (string.IsNullOrWhiteSpace(luidKey) || string.IsNullOrWhiteSpace(groupKey))
		{
			return;
		}

		if (!_gpuDxgiDisplayNamesByGroupKey.TryGetValue(groupKey, out string? displayName))
		{
			displayName = GetDxgiAdapterDescription(adapterDescription);
			if (string.IsNullOrWhiteSpace(displayName))
			{
				displayName = "GPU " + _gpuDxgiDisplayNamesByGroupKey.Count.ToString(CultureInfo.InvariantCulture) + " Usage";
			}

			_gpuDxgiDisplayNamesByGroupKey.Add(groupKey, displayName);
			_gpuDxgiDisplayIndexesByGroupKey.Add(groupKey, _gpuDxgiDisplayIndexesByGroupKey.Count);
		}

		int displayIndex = _gpuDxgiDisplayIndexesByGroupKey[groupKey];
		_gpuDxgiAdaptersByLuid[luidKey] = new GpuDxgiAdapterDescriptor(groupKey, displayName, displayIndex);
	}

	private static string CreateGpuLuidAdapterKey(LUID luid) =>
		 "luid_0x" + luid.HighPart.ToString("X8", CultureInfo.InvariantCulture) + "_0x" + luid.LowPart.ToString("X8", CultureInfo.InvariantCulture);

	private static string CreateGpuDxgiAdapterGroupKey(DXGI_ADAPTER_DESC1 adapterDescription) =>
		"dxgi_" + adapterDescription.VendorId.ToString("X8", CultureInfo.InvariantCulture) + "_" + adapterDescription.DeviceId.ToString("X8", CultureInfo.InvariantCulture) + "_" + adapterDescription.SubSysId.ToString("X8", CultureInfo.InvariantCulture) + "_" + adapterDescription.Revision.ToString("X8", CultureInfo.InvariantCulture) + "_" + adapterDescription.DedicatedVideoMemory.ToString("X", CultureInfo.InvariantCulture);

	private unsafe static string GetDxgiAdapterDescription(DXGI_ADAPTER_DESC1 adapterDescription) =>
		new string(adapterDescription.Description).TrimEnd('\0');

	private unsafe static void ReleaseComObject(IntPtr comObject)
	{
		if (comObject == IntPtr.Zero)
		{
			return;
		}

		IntPtr* objectVTable = *(IntPtr**)comObject;
		delegate* unmanaged[Stdcall]<IntPtr, uint> release = (delegate* unmanaged[Stdcall]<IntPtr, uint>)objectVTable[2];
		_ = release(comObject);
	}

	private string TryGetGpuAdapterGroupKey(string counterPath)
	{
		string luidKey = TryGetGpuLuidAdapterKey(counterPath);
		if (string.IsNullOrWhiteSpace(luidKey))
		{
			return string.Empty;
		}

		return _gpuDxgiAdaptersByLuid.TryGetValue(luidKey, out GpuDxgiAdapterDescriptor? adapterDescriptor) ? adapterDescriptor.GroupKey : string.Empty;
	}

	private static string TryGetGpuLuidAdapterKey(string counterPath)
	{
		int luidIndex = counterPath.IndexOf(GpuLuidToken, StringComparison.OrdinalIgnoreCase);
		if (luidIndex < 0)
		{
			return string.Empty;
		}

		int valueStart = luidIndex + GpuLuidToken.Length;
		int valueEnd = counterPath.IndexOf(GpuPhysicalToken, valueStart, StringComparison.OrdinalIgnoreCase);
		if (valueEnd <= valueStart)
		{
			valueEnd = counterPath.IndexOf(GpuEngineToken, valueStart, StringComparison.OrdinalIgnoreCase);
		}

		if (valueEnd <= valueStart)
		{
			return string.Empty;
		}

		string luidText = counterPath[valueStart..valueEnd];
		return string.IsNullOrWhiteSpace(luidText) ? string.Empty : "luid_" + luidText;
	}

	private void EnsureGpuChart(string adapterKey)
	{
		if (_gpuChartStates.ContainsKey(adapterKey))
		{
			return;
		}

		int displayIndex = GetGpuAdapterDisplayIndex(adapterKey, _gpuChartStates.Count);
		string displayName = GetGpuAdapterDisplayName(adapterKey, displayIndex);
		TextBlock maxLabelTextBlock = CreateGpuLabelTextBlock("100%", HorizontalAlignment.Left);
		TextBlock titleTextBlock = CreateGpuTitleTextBlock(displayName);
		TextBlock valueTextBlock = CreateGpuLabelTextBlock("0%", HorizontalAlignment.Right);
		valueTextBlock.MaxWidth = 150.0;
		Grid headerGrid = new();
		headerGrid.Children.Add(maxLabelTextBlock);
		headerGrid.Children.Add(titleTextBlock);
		headerGrid.Children.Add(valueTextBlock);

		HomeLiveLineGraph graph = new()
		{
			PrimarySeriesName = displayName,
			ValueUnit = "%",
			UseFixedMinimum = true,
			FixedMinimum = 0.0,
			UseFixedMaximum = true,
			FixedMaximum = 100.0,
			StrokeColor = GetGpuChartColor(displayIndex),
			GridColor = GetGpuGridColor(displayIndex)
		};

		TextBlock minLabelTextBlock = CreateGpuLabelTextBlock("0%", HorizontalAlignment.Left);
		TextBlock startSecondsLabelTextBlock = CreateGpuLabelTextBlock(ViewModel.HomeChartStartSecondsLabel, HorizontalAlignment.Center);
		Grid footerGrid = new() { MinHeight = 24.0, VerticalAlignment = VerticalAlignment.Stretch };
		footerGrid.Children.Add(minLabelTextBlock);
		footerGrid.Children.Add(startSecondsLabelTextBlock);

		RowDefinition graphRow = new() { Height = new GridLength(236.0) };
		RowDefinition footerRow = new() { Height = new GridLength(24.0) };
		Grid cardGrid = new() { RowSpacing = 8.0 };
		cardGrid.RowDefinitions.Add(new RowDefinition() { Height = GridLength.Auto });
		cardGrid.RowDefinitions.Add(graphRow);
		cardGrid.RowDefinitions.Add(footerRow);
		cardGrid.Children.Add(headerGrid);
		Grid.SetRow(graph, 1);
		cardGrid.Children.Add(graph);
		Grid.SetRow(footerGrid, 2);
		cardGrid.Children.Add(footerGrid);

		Border card = new()
		{
			CornerRadius = new CornerRadius(10.0),
			Padding = new Thickness(12.0),
			Width = 506.0,
			Height = 320.0,
			Background = new SolidColorBrush(Color.FromArgb(217, 20, 16, 34)),
			BorderBrush = new SolidColorBrush(Color.FromArgb(38, 255, 255, 255)),
			BorderThickness = new Thickness(1.0),
			Child = cardGrid
		};
		Color gpuChartColor = GetGpuChartColor(displayIndex);
		Color gpuGridColor = GetGpuGridColor(displayIndex);
		Grid cardFrame = CreateLiveGraphCardFrame(card, Color.FromArgb(102, gpuChartColor.R, gpuChartColor.G, gpuChartColor.B), Color.FromArgb(102, gpuGridColor.R, gpuGridColor.G, gpuGridColor.B));
		_gpuChartStates.Add(adapterKey, new GpuChartState(displayIndex, cardFrame, card, graphRow, footerRow, graph, titleTextBlock, valueTextBlock, maxLabelTextBlock, minLabelTextBlock, startSecondsLabelTextBlock));
		LiveGraphsWrapGrid.Children.Add(cardFrame);
		ApplyGpuGraphSizeFromCurrentSettings();
	}

	private static TextBlock CreateGpuTitleTextBlock(string text) => new()
	{
		Text = text,
		FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
		HorizontalAlignment = HorizontalAlignment.Center,
		VerticalAlignment = VerticalAlignment.Center,
		TextAlignment = TextAlignment.Center,
		TextWrapping = TextWrapping.NoWrap,
		MaxWidth = 250.0,
		TextTrimming = TextTrimming.CharacterEllipsis
	};

	private static TextBlock CreateGpuLabelTextBlock(string text, HorizontalAlignment horizontalAlignment) => new()
	{
		HorizontalAlignment = horizontalAlignment,
		VerticalAlignment = VerticalAlignment.Center,
		FontSize = 11.0,
		TextTrimming = TextTrimming.CharacterEllipsis,
		Text = text
	};

	private static Color GetGpuChartColor(int displayIndex)
	{
		Color[] colors = [Color.FromArgb(255, 255, 99, 146), Color.FromArgb(255, 130, 207, 255), Color.FromArgb(255, 255, 204, 77), Color.FromArgb(255, 167, 139, 250)];
		return colors[displayIndex % colors.Length];
	}

	private static Color GetGpuGridColor(int displayIndex)
	{
		Color[] colors = [Color.FromArgb(255, 189, 52, 96), Color.FromArgb(255, 0, 120, 212), Color.FromArgb(255, 181, 126, 0), Color.FromArgb(255, 115, 70, 180)];
		return colors[displayIndex % colors.Length];
	}

	private void UpdateGpuUsage()
	{
		Dictionary<string, double> totals = _gpuAdapterTotals;
		totals.Clear();

		if (_gpuPdhQuery != IntPtr.Zero && _gpuEngineUtilizationCounter != IntPtr.Zero && NativeMethods.PdhCollectQueryData(_gpuPdhQuery) == GpuErrorSuccess)
		{
			AddCurrentGpuCounterArrayValuesToTotals(totals);
		}

		foreach (KeyValuePair<string, double> totalPair in totals)
		{
			EnsureGpuChart(totalPair.Key);
		}

		foreach (KeyValuePair<string, GpuChartState> chartStatePair in _gpuChartStates)
		{
			double utilization = totals.TryGetValue(chartStatePair.Key, out double rawUtilization) ? Math.Clamp(rawUtilization, 0.0, 100.0) : 0.0;
			GpuChartState chartState = chartStatePair.Value;
			AddGpuSample(chartState.Samples, utilization);
			chartState.Graph.Samples = chartState.Samples;
			chartState.ValueTextBlock.Text = utilization.ToString("0.##", CultureInfo.InvariantCulture) + "%";
			chartState.MaxLabelTextBlock.Text = "100%";
			chartState.MinLabelTextBlock.Text = "0%";
			chartState.StartSecondsLabelTextBlock.Text = ViewModel.HomeChartStartSecondsLabel;
		}
	}

	private unsafe void AddCurrentGpuCounterArrayValuesToTotals(Dictionary<string, double> totals)
	{
		uint bufferSize = 0U;
		uint itemCount = 0U;
		uint status = NativeMethods.PdhGetFormattedCounterArrayW(_gpuEngineUtilizationCounter, GpuPdhFormatDouble, ref bufferSize, ref itemCount, IntPtr.Zero);
		if (status != GpuPdhMoreData || bufferSize == 0U || itemCount == 0U || bufferSize > int.MaxValue || itemCount > int.MaxValue)
		{
			return;
		}

		IntPtr itemBuffer = Marshal.AllocHGlobal((int)bufferSize);
		try
		{
			status = NativeMethods.PdhGetFormattedCounterArrayW(_gpuEngineUtilizationCounter, GpuPdhFormatDouble, ref bufferSize, ref itemCount, itemBuffer);
			if (status != GpuErrorSuccess)
			{
				return;
			}

			PDH_FMT_COUNTERVALUE_ITEM_DOUBLE* counterItems = (PDH_FMT_COUNTERVALUE_ITEM_DOUBLE*)itemBuffer;
			int count = (int)itemCount;
			for (int index = 0; index < count; index++)
			{
				PDH_FMT_COUNTERVALUE_ITEM_DOUBLE counterItem = counterItems[index];
				if (counterItem.NamePtr == IntPtr.Zero || counterItem.Value.CStatus != GpuErrorSuccess)
				{
					continue;
				}

				string instanceName = Marshal.PtrToStringUni(counterItem.NamePtr) ?? string.Empty;
				string adapterKey = TryGetGpuAdapterGroupKey(instanceName);
				if (string.IsNullOrWhiteSpace(adapterKey))
				{
					continue;
				}

				double counterValue = Math.Max(0.0, counterItem.Value.Value);
				if (!totals.TryAdd(adapterKey, counterValue))
				{
					totals[adapterKey] += counterValue;
				}
			}
		}
		finally
		{
			Marshal.FreeHGlobal(itemBuffer);
		}
	}

	private static void AddGpuSample(List<double> samples, double value)
	{
		if (samples.Count >= GpuUsageMaxSamples)
		{
			samples.RemoveAt(0);
		}

		samples.Add(Math.Clamp(value, 0.0, 100.0));
	}

	private void CloseGpuCounters()
	{
		if (_gpuEngineUtilizationCounter != IntPtr.Zero)
		{
			_ = NativeMethods.PdhRemoveCounter(_gpuEngineUtilizationCounter);
			_gpuEngineUtilizationCounter = IntPtr.Zero;
		}

		if (_gpuPdhQuery != IntPtr.Zero)
		{
			_ = NativeMethods.PdhCloseQuery(_gpuPdhQuery);
			_gpuPdhQuery = IntPtr.Zero;
		}
	}
}

internal sealed partial class HomeLiveGraphsWindow
{
	private const int NetworkOpennessRequestTimeoutSeconds = 20;
	private static readonly HttpClient NetworkOpennessHttpClient = CreateNetworkOpennessHttpClient();
	private readonly StringBuilder _networkOpennessDetailsBuilder = new(16_384);
	private readonly StringBuilder _networkOpennessCategoryBuilder = new(1024);
	private readonly Dictionary<string, NetworkOpennessCategoryStats> _networkOpennessCategoryStats = new(StringComparer.OrdinalIgnoreCase);
	private int _networkOpennessReachableCount;
	private int _networkOpennessUnreachableCount;
	private int _networkOpennessInconclusiveCount;

	private static HttpClient CreateNetworkOpennessHttpClient()
	{
		HttpClient? httpClient = null;

		try
		{
			httpClient = new HttpClient()
			{
				Timeout = TimeSpan.FromSeconds(NetworkOpennessRequestTimeoutSeconds)
			};

			httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(Atlas.UserAgent);

			HttpClient result = httpClient;
			httpClient = null;
			return result;
		}
		finally
		{
			httpClient?.Dispose();
		}
	}

	private sealed class NetworkOpennessTarget(string category, string url)
	{
		internal string Category => category;
		internal string Url => url;
	}

	private sealed class NetworkOpennessResult(NetworkOpennessTarget target, bool reachable, bool conclusive, string status, long elapsedMilliseconds)
	{
		internal NetworkOpennessTarget Target => target;
		internal bool Reachable => reachable;
		internal bool Conclusive => conclusive;
		internal string Status => status;
		internal long ElapsedMilliseconds => elapsedMilliseconds;
	}

	private struct NetworkOpennessCategoryStats
	{
		internal int Reachable { get; set; }
		internal int Unreachable { get; set; }
		internal int Inconclusive { get; set; }

		internal readonly int Conclusive => Reachable + Unreachable;
	}

	private async void OnNetworkOpennessRunButtonClick()
	{
		List<Task<NetworkOpennessResult>> pendingTasks = new(NetworkOpennessTargets.Value.Count);

		NetworkOpennessRunButton.IsEnabled = false;
		NetworkOpennessProgressRing.Visibility = Visibility.Visible;
		NetworkOpennessProgressRing.IsActive = true;
		NetworkOpennessProgressBar.Visibility = Visibility.Visible;
		NetworkOpennessProgressBar.Value = 0.0;
		NetworkOpennessStatusTextBlock.Text = "Testing selected endpoints in parallel...";
		NetworkOpennessCategoryResultsTextBlock.Text = string.Empty;
		_networkOpennessCategoryStats.Clear();
		_networkOpennessReachableCount = 0;
		_networkOpennessUnreachableCount = 0;
		_networkOpennessInconclusiveCount = 0;
		_ = _networkOpennessDetailsBuilder.Clear().Append("Starting network openness checks...").AppendLine();
		NetworkOpennessDetailsTextBox.Text = _networkOpennessDetailsBuilder.ToString();
		UpdateNetworkOpennessScorePill(-1);

		foreach (NetworkOpennessTarget item in CollectionsMarshal.AsSpan(NetworkOpennessTargets.Value))
		{
			pendingTasks.Add(TestNetworkOpennessTargetAsync(item));
		}

		int completedCount = 0;
		while (pendingTasks.Count > 0)
		{
			Task<NetworkOpennessResult> completedTask = await Task.WhenAny(pendingTasks);
			_ = pendingTasks.Remove(completedTask);
			NetworkOpennessResult result = await completedTask;
			completedCount++;

			NetworkOpennessProgressBar.Value = (double)completedCount / NetworkOpennessTargets.Value.Count * 100.0;
			NetworkOpennessStatusTextBlock.Text = "Completed " + completedCount.ToString(CultureInfo.InvariantCulture) + " of " + NetworkOpennessTargets.Value.Count.ToString(CultureInfo.InvariantCulture) + " checks.";
			long displayedElapsedMilliseconds = result.ElapsedMilliseconds;
			ApplyPrivacyModeNetworkDelayOverride(ref displayedElapsedMilliseconds);
			AppendNetworkOpennessDetailLine(result.Target.Url + "   " + result.Status + "   " + displayedElapsedMilliseconds.ToString(CultureInfo.InvariantCulture) + " ms");
			ApplyNetworkOpennessResult(result);
			ApplyNetworkOpennessResults(false);
		}

		ApplyNetworkOpennessResults(true);

		NetworkOpennessProgressRing.IsActive = false;
		NetworkOpennessProgressRing.Visibility = Visibility.Collapsed;
		NetworkOpennessRunButton.IsEnabled = true;
	}

	private static async Task<NetworkOpennessResult> TestNetworkOpennessTargetAsync(NetworkOpennessTarget target)
	{
		Stopwatch stopwatch = Stopwatch.StartNew();
		try
		{
			using CancellationTokenSource cancellationTokenSource = new(TimeSpan.FromSeconds(NetworkOpennessRequestTimeoutSeconds));
			using HttpRequestMessage request = new(HttpMethod.Get, target.Url);
			using HttpResponseMessage response = await NetworkOpennessHttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationTokenSource.Token);
			stopwatch.Stop();

			int statusCode = (int)response.StatusCode;
			if (statusCode >= 200 && statusCode < 500)
			{
				return new NetworkOpennessResult(target, true, true, "Reachable", stopwatch.ElapsedMilliseconds);
			}

			return new NetworkOpennessResult(target, false, false, "HTTP " + statusCode.ToString(CultureInfo.InvariantCulture), stopwatch.ElapsedMilliseconds);
		}
		catch (TaskCanceledException)
		{
			stopwatch.Stop();
			return new NetworkOpennessResult(target, false, true, "Timeout", stopwatch.ElapsedMilliseconds);
		}
		catch (HttpRequestException)
		{
			stopwatch.Stop();
			return new NetworkOpennessResult(target, false, true, "Blocked or unreachable", stopwatch.ElapsedMilliseconds);
		}
		catch (Exception)
		{
			stopwatch.Stop();
			return new NetworkOpennessResult(target, false, false, "Inconclusive", stopwatch.ElapsedMilliseconds);
		}
	}

	private void ApplyNetworkOpennessResult(NetworkOpennessResult result)
	{
		if (!_networkOpennessCategoryStats.TryGetValue(result.Target.Category, out NetworkOpennessCategoryStats stats))
		{
			stats = new NetworkOpennessCategoryStats();
		}

		if (!result.Conclusive)
		{
			_networkOpennessInconclusiveCount++;
			stats.Inconclusive++;
		}
		else if (result.Reachable)
		{
			_networkOpennessReachableCount++;
			stats.Reachable++;
		}
		else
		{
			_networkOpennessUnreachableCount++;
			stats.Unreachable++;
		}

		_networkOpennessCategoryStats[result.Target.Category] = stats;
	}

	private void ApplyNetworkOpennessResults(bool finalResult)
	{
		int reachableCount = _networkOpennessReachableCount;
		int unreachableCount = _networkOpennessUnreachableCount;
		int inconclusiveCount = _networkOpennessInconclusiveCount;
		int conclusiveCount = reachableCount + unreachableCount;
		int score = conclusiveCount > 0 ? (int)Math.Round((double)reachableCount / conclusiveCount * 100.0) : 0;
		UpdateNetworkOpennessScorePill(score);

		_ = NetworkOpennessSummaryTextBlock.Text = "Reachable: " + reachableCount.ToString(CultureInfo.InvariantCulture) + " / " + conclusiveCount.ToString(CultureInfo.InvariantCulture) + " conclusive checks";

		if (finalResult)
		{
			NetworkOpennessStatusTextBlock.Text = "Completed. Blocked or unreachable: " + unreachableCount.ToString(CultureInfo.InvariantCulture) + "   Inconclusive: " + inconclusiveCount.ToString(CultureInfo.InvariantCulture);
		}

		ApplyNetworkOpennessCategoryResults(_networkOpennessCategoryStats);
	}

	private void UpdateNetworkOpennessScorePill(int score)
	{
		if (score < 0)
		{
			NetworkOpennessScoreTextBlock.Text = "...";
			NetworkOpennessScoreCaptionTextBlock.Text = "Testing";
			NetworkOpennessScorePillBorder.Background = new SolidColorBrush(Color.FromArgb(48, 128, 128, 128));
			NetworkOpennessScorePillBorder.BorderBrush = new SolidColorBrush(Color.FromArgb(120, 160, 160, 160));
			return;
		}

		NetworkOpennessScoreTextBlock.Text = score.ToString(CultureInfo.InvariantCulture) + "%";
		NetworkOpennessScoreCaptionTextBlock.Text = score >= 85 ? "Open" : score >= 65 ? "Mixed" : "Restricted";

		if (score >= 85)
		{
			NetworkOpennessScorePillBorder.Background = new SolidColorBrush(Color.FromArgb(54, 46, 204, 113));
			NetworkOpennessScorePillBorder.BorderBrush = new SolidColorBrush(Color.FromArgb(150, 46, 204, 113));
		}
		else if (score >= 65)
		{
			NetworkOpennessScorePillBorder.Background = new SolidColorBrush(Color.FromArgb(54, 255, 193, 7));
			NetworkOpennessScorePillBorder.BorderBrush = new SolidColorBrush(Color.FromArgb(150, 255, 193, 7));
		}
		else
		{
			NetworkOpennessScorePillBorder.Background = new SolidColorBrush(Color.FromArgb(54, 244, 67, 54));
			NetworkOpennessScorePillBorder.BorderBrush = new SolidColorBrush(Color.FromArgb(150, 244, 67, 54));
		}
	}

	private void ApplyNetworkOpennessCategoryResults(Dictionary<string, NetworkOpennessCategoryStats> categoryStats)
	{
		StringBuilder categoryBuilder = _networkOpennessCategoryBuilder;
		_ = categoryBuilder.Clear();

		foreach (KeyValuePair<string, NetworkOpennessCategoryStats> categoryStatPair in categoryStats)
		{
			NetworkOpennessCategoryStats stats = categoryStatPair.Value;
			int score = stats.Conclusive > 0 ? (int)Math.Round((double)stats.Reachable / stats.Conclusive * 100.0) : 0;
			_ = categoryBuilder.Append(categoryStatPair.Key)
				.Append(": ")
				.Append(score.ToString(CultureInfo.InvariantCulture))
				.Append("%  (")
				.Append(stats.Reachable.ToString(CultureInfo.InvariantCulture))
				.Append(" / ")
				.Append(stats.Conclusive.ToString(CultureInfo.InvariantCulture))
				.Append(')')
				.AppendLine();
		}

		NetworkOpennessCategoryResultsTextBlock.Text = categoryBuilder.ToString();
	}

	private void AppendNetworkOpennessDetailLine(string text)
	{
		_ = _networkOpennessDetailsBuilder.Append(text).AppendLine();
		NetworkOpennessDetailsTextBox.Text = _networkOpennessDetailsBuilder.ToString();
		NetworkOpennessDetailsTextBox.SelectionStart = NetworkOpennessDetailsTextBox.Text.Length;
	}

	private static readonly Lazy<List<NetworkOpennessTarget>> NetworkOpennessTargets = new(() => [
			new NetworkOpennessTarget("Social Media", "https://x.com"),
			new NetworkOpennessTarget("Social Media", "https://youtube.com"),
			new NetworkOpennessTarget("Social Media", "https://reddit.com"),
			new NetworkOpennessTarget("Social Media", "https://instagram.com"),
			new NetworkOpennessTarget("Social Media", "https://facebook.com"),
			new NetworkOpennessTarget("Social Media", "https://tiktok.com"),
			new NetworkOpennessTarget("Social Media", "https://linkedin.com"),
			new NetworkOpennessTarget("Social Media", "https://snapchat.com"),
			new NetworkOpennessTarget("Social Media", "https://xbox.com"),

			new NetworkOpennessTarget("Messaging", "https://telegram.org"),
			new NetworkOpennessTarget("Messaging", "https://web.telegram.org"),
			new NetworkOpennessTarget("Messaging", "https://signal.org"),
			new NetworkOpennessTarget("Messaging", "https://whatsapp.com"),
			new NetworkOpennessTarget("Messaging", "https://web.whatsapp.com"),
			new NetworkOpennessTarget("Messaging", "https://discord.com"),

			new NetworkOpennessTarget("News / Information", "https://wikipedia.org"),
			new NetworkOpennessTarget("News / Information", "https://archive.org"),
			new NetworkOpennessTarget("News / Information", "https://apnews.com"),
			new NetworkOpennessTarget("News / Information", "https://dw.com"),
			new NetworkOpennessTarget("News / Information", "https://babylonbee.com"),
			new NetworkOpennessTarget("News / Information", "https://rumble.com"),
			new NetworkOpennessTarget("News / Information", "https://truthsocial.com"),
			new NetworkOpennessTarget("News / Information", "https://tpusa.com"),

			new NetworkOpennessTarget("Search / Knowledge", "https://google.com"),
			new NetworkOpennessTarget("Search / Knowledge", "https://bing.com"),
			new NetworkOpennessTarget("Search / Knowledge", "https://duckduckgo.com"),
			new NetworkOpennessTarget("Search / Knowledge", "https://learn.microsoft.com"),
			new NetworkOpennessTarget("Search / Knowledge", "https://microsoft.com"),
			new NetworkOpennessTarget("Search / Knowledge", "https://medium.com"),
			new NetworkOpennessTarget("Search / Knowledge", "https://grokipedia.com"),

			new NetworkOpennessTarget("Developer / Internet Tools", "https://github.com"),
			new NetworkOpennessTarget("Developer / Internet Tools", "https://stackoverflow.com"),
			new NetworkOpennessTarget("Developer / Internet Tools", "https://cloudflare.com"),
			new NetworkOpennessTarget("Developer / Internet Tools", "https://mozilla.org"),
			new NetworkOpennessTarget("Developer / Internet Tools", "https://apps.microsoft.com"),

			new NetworkOpennessTarget("Privacy / Circumvention Tools", "https://torproject.org"),
			new NetworkOpennessTarget("Privacy / Circumvention Tools", "https://bridges.torproject.org"),
			new NetworkOpennessTarget("Privacy / Circumvention Tools", "https://psiphon.ca"),
			new NetworkOpennessTarget("Privacy / Circumvention Tools", "https://protonvpn.com"),
			new NetworkOpennessTarget("Privacy / Circumvention Tools", "https://mullvad.net"),
			new NetworkOpennessTarget("Privacy / Circumvention Tools", "https://wireguard.com"),
			new NetworkOpennessTarget("Privacy / Circumvention Tools", "https://nextdns.io"),
			new NetworkOpennessTarget("Privacy / Circumvention Tools", "https://vpngate.net")
		], LazyThreadSafetyMode.None);
}

internal sealed partial class HomeLiveGraphsWindow
{
	private const double HeartAnimationDurationSeconds = 1.4;
	private const double HeartOpacityFullyVisibleSeconds = 0.7;
	private const double HeartOpacityHoldSeconds = 0.91;
	private const double HeartTravelCompleteSeconds = 1.26;
	private const double HeartTravelViewportMultiplier = 0.35;
	private const double HeartFirstSize = 44.0;
	private const double HeartSecondSize = 39.0;
	private const double HeartThirdSize = 38.0;
	private const double HeartFirstLeftOffset = 0.0;
	private const double HeartSecondLeftOffset = 9.0;
	private const double HeartThirdLeftOffset = 4.5;
	private const double HeartContainerSize = 56.0;
	private const double HeartBaseRightOffset = 86.0;
	private const double HeartBaseBottomOffset = 96.0;
	private const double HeartSecondDelaySeconds = 0.3;
	private const double HeartThirdDelaySeconds = 0.6;
	private static readonly Color HeartFillColor = Color.FromArgb(255, 245, 141, 156);

	private void OnHeartBurstButtonClick()
	{
		OnHeartPrivacyClickRequested();

		double canvasWidth = Math.Max(1.0, HeartAnimationCanvas.ActualWidth);
		double canvasHeight = Math.Max(1.0, HeartAnimationCanvas.ActualHeight);
		double baseLeft = Math.Max(0.0, canvasWidth - HeartBaseRightOffset);
		double baseTop = Math.Max(0.0, canvasHeight - HeartBaseBottomOffset);
		double travelDistance = canvasHeight * HeartTravelViewportMultiplier;
		Canvas heartContainer = new()
		{
			Width = HeartContainerSize,
			Height = HeartContainerSize,
			IsHitTestVisible = false
		};
		Canvas.SetLeft(heartContainer, baseLeft);
		Canvas.SetTop(heartContainer, baseTop);
		HeartAnimationCanvas.Children.Add(heartContainer);
		Storyboard storyboard = new();
		AddHeart(heartContainer, storyboard, HeartFirstSize, HeartFirstLeftOffset, 0.0, travelDistance);
		AddHeart(heartContainer, storyboard, HeartSecondSize, HeartSecondLeftOffset, HeartSecondDelaySeconds, travelDistance);
		AddHeart(heartContainer, storyboard, HeartThirdSize, HeartThirdLeftOffset, HeartThirdDelaySeconds, travelDistance);
		storyboard.Completed += delegate
		{
			_ = HeartAnimationCanvas.Children.Remove(heartContainer);
		};
		storyboard.Begin();
	}

	private static void AddHeart(Canvas heartContainer, Storyboard storyboard, double size, double leftOffset, double delaySeconds, double travelDistance)
	{
		CompositeTransform heartTransform = new()
		{
			CenterX = size / 2.0,
			CenterY = size / 2.0,
			Rotation = 10.0,
			ScaleX = 1.0,
			ScaleY = 1.0,
			TranslateY = 0.0
		};
		Microsoft.UI.Xaml.Shapes.Path heartPath = new()
		{
			Width = size,
			Height = size,
			Stretch = Stretch.Uniform,
			Fill = new SolidColorBrush(HeartFillColor),
			Data = CreateHeartGeometry(),
			Opacity = 0.0,
			RenderTransform = heartTransform,
			RenderTransformOrigin = new Point(0.5, 0.5),
			IsHitTestVisible = false
		};
		Canvas.SetLeft(heartPath, leftOffset);
		Canvas.SetTop(heartPath, 0.0);
		heartContainer.Children.Add(heartPath);
		TimeSpan beginTime = TimeSpan.FromSeconds(delaySeconds);
		QuadraticEase easeIn = new()
		{
			EasingMode = EasingMode.EaseIn
		};
		AddOpacityAnimation(storyboard, heartPath, beginTime);
		AddTransformAnimation(storyboard, heartPath, "(UIElement.RenderTransform).(CompositeTransform.TranslateY)", 0.0, -travelDistance, beginTime, easeIn);
		AddTransformAnimation(storyboard, heartPath, "(UIElement.RenderTransform).(CompositeTransform.ScaleX)", 1.0, 1.2, beginTime, easeIn);
		AddTransformAnimation(storyboard, heartPath, "(UIElement.RenderTransform).(CompositeTransform.ScaleY)", 1.0, 1.2, beginTime, easeIn);
		AddTransformAnimation(storyboard, heartPath, "(UIElement.RenderTransform).(CompositeTransform.Rotation)", 10.0, -10.0, beginTime, easeIn);
	}

	private static void AddOpacityAnimation(Storyboard storyboard, Microsoft.UI.Xaml.Shapes.Path heartPath, TimeSpan beginTime)
	{
		DoubleAnimationUsingKeyFrames opacityAnimation = new()
		{
			BeginTime = beginTime,
			Duration = TimeSpan.FromSeconds(HeartAnimationDurationSeconds)
		};
		opacityAnimation.KeyFrames.Add(new LinearDoubleKeyFrame()
		{
			KeyTime = KeyTime.FromTimeSpan(TimeSpan.Zero),
			Value = 0.0
		});
		opacityAnimation.KeyFrames.Add(new LinearDoubleKeyFrame()
		{
			KeyTime = KeyTime.FromTimeSpan(TimeSpan.FromSeconds(HeartOpacityFullyVisibleSeconds)),
			Value = 1.0
		});
		opacityAnimation.KeyFrames.Add(new LinearDoubleKeyFrame()
		{
			KeyTime = KeyTime.FromTimeSpan(TimeSpan.FromSeconds(HeartOpacityHoldSeconds)),
			Value = 1.0
		});
		opacityAnimation.KeyFrames.Add(new LinearDoubleKeyFrame()
		{
			KeyTime = KeyTime.FromTimeSpan(TimeSpan.FromSeconds(HeartTravelCompleteSeconds)),
			Value = 0.0
		});
		opacityAnimation.KeyFrames.Add(new LinearDoubleKeyFrame()
		{
			KeyTime = KeyTime.FromTimeSpan(TimeSpan.FromSeconds(HeartAnimationDurationSeconds)),
			Value = 0.0
		});
		Storyboard.SetTarget(opacityAnimation, heartPath);
		Storyboard.SetTargetProperty(opacityAnimation, "Opacity");
		storyboard.Children.Add(opacityAnimation);
	}

	private static void AddTransformAnimation(Storyboard storyboard, Microsoft.UI.Xaml.Shapes.Path heartPath, string targetProperty, double from, double to, TimeSpan beginTime, EasingFunctionBase easingFunction)
	{
		DoubleAnimationUsingKeyFrames transformAnimation = new()
		{
			BeginTime = beginTime,
			Duration = TimeSpan.FromSeconds(HeartAnimationDurationSeconds)
		};
		transformAnimation.KeyFrames.Add(new LinearDoubleKeyFrame()
		{
			KeyTime = KeyTime.FromTimeSpan(TimeSpan.Zero),
			Value = from
		});
		transformAnimation.KeyFrames.Add(new EasingDoubleKeyFrame()
		{
			KeyTime = KeyTime.FromTimeSpan(TimeSpan.FromSeconds(HeartTravelCompleteSeconds)),
			Value = to,
			EasingFunction = easingFunction
		});
		transformAnimation.KeyFrames.Add(new LinearDoubleKeyFrame()
		{
			KeyTime = KeyTime.FromTimeSpan(TimeSpan.FromSeconds(HeartAnimationDurationSeconds)),
			Value = to
		});
		Storyboard.SetTarget(transformAnimation, heartPath);
		Storyboard.SetTargetProperty(transformAnimation, targetProperty);
		storyboard.Children.Add(transformAnimation);
	}

	private static PathGeometry CreateHeartGeometry()
	{
		PathFigure heartFigure = new()
		{
			StartPoint = new Point(263.42, 235.15),
			IsClosed = true,
			IsFilled = true
		};
		heartFigure.Segments.Add(new BezierSegment()
		{
			Point1 = new Point(197.18, 235.15),
			Point2 = new Point(143.42, 288.91),
			Point3 = new Point(143.42, 355.15)
		});
		heartFigure.Segments.Add(new BezierSegment()
		{
			Point1 = new Point(143.42, 489.91),
			Point2 = new Point(279.35, 525.24),
			Point3 = new Point(371.98, 658.46)
		});
		heartFigure.Segments.Add(new BezierSegment()
		{
			Point1 = new Point(459.554, 526.06),
			Point2 = new Point(600.54, 485.6),
			Point3 = new Point(600.54, 355.15)
		});
		heartFigure.Segments.Add(new BezierSegment()
		{
			Point1 = new Point(600.54, 288.91),
			Point2 = new Point(546.78, 235.15),
			Point3 = new Point(480.54, 235.15)
		});
		heartFigure.Segments.Add(new BezierSegment()
		{
			Point1 = new Point(432.492, 235.15),
			Point2 = new Point(391.138, 263.52),
			Point3 = new Point(371.98, 304.338)
		});
		heartFigure.Segments.Add(new BezierSegment()
		{
			Point1 = new Point(352.819, 263.521),
			Point2 = new Point(311.466, 235.15),
			Point3 = new Point(263.42, 235.15)
		});
		PathGeometry heartGeometry = new();
		heartGeometry.Figures.Add(heartFigure);
		return heartGeometry;
	}

	#region Wi-Fi Profiles

	private const uint WifiWlanErrorSuccess = 0U;
	private const uint WifiWlanClientVersionLonghorn = 2U;
	private const int WifiWlanMaxNameLength = 256;

	internal readonly ObservableCollection<WifiProfileRow> WifiProfilesItems = new();
	private bool _wifiProfilesLoaded;
	private bool _wifiProfilesRetrievalInProgress;

	private enum SelectorBarCurrentItem
	{
		NetworkOpennes,
		PhysicalOrientation,
		Compass,
		LightSensor,
		WifiProfilesDiagnostics
	}

	// Used to determine which SelectorBar tab is currently user viewing.
	// Only set by the "OnDiagnosticsSelectorBarSelectionChanged" method.
	private SelectorBarCurrentItem _SelectorBarSelectedItem;

	private async void OnDiagnosticsSelectorBarSelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
	{
		if (sender.SelectedItem == NetworkOpennessSelectorBarItem)
		{
			_SelectorBarSelectedItem = SelectorBarCurrentItem.NetworkOpennes;

			NetworkOpennessDiagnosticsGrid.Visibility = Visibility.Visible;
			WifiProfilesDiagnosticsGrid.Visibility = Visibility.Collapsed;
			PhysicalOrientationDiagnosticsGrid.Visibility = Visibility.Collapsed;
			CompassDiagnosticsGrid.Visibility = Visibility.Collapsed;
			LightSensorDiagnosticsGrid.Visibility = Visibility.Collapsed;
			return;
		}

		if (sender.SelectedItem == PhysicalOrientationSelectorBarItem)
		{
			_SelectorBarSelectedItem = SelectorBarCurrentItem.PhysicalOrientation;

			NetworkOpennessDiagnosticsGrid.Visibility = Visibility.Collapsed;
			WifiProfilesDiagnosticsGrid.Visibility = Visibility.Collapsed;
			PhysicalOrientationDiagnosticsGrid.Visibility = Visibility.Visible;
			CompassDiagnosticsGrid.Visibility = Visibility.Collapsed;
			LightSensorDiagnosticsGrid.Visibility = Visibility.Collapsed;
			UpdatePhysicalOrientationSnapshot();
			return;
		}

		if (sender.SelectedItem == CompassSelectorBarItem)
		{
			_SelectorBarSelectedItem = SelectorBarCurrentItem.Compass;

			NetworkOpennessDiagnosticsGrid.Visibility = Visibility.Collapsed;
			WifiProfilesDiagnosticsGrid.Visibility = Visibility.Collapsed;
			PhysicalOrientationDiagnosticsGrid.Visibility = Visibility.Collapsed;
			CompassDiagnosticsGrid.Visibility = Visibility.Visible;
			LightSensorDiagnosticsGrid.Visibility = Visibility.Collapsed;
			UpdateCompassSnapshot();
			return;
		}

		if (sender.SelectedItem == LightSensorSelectorBarItem)
		{
			_SelectorBarSelectedItem = SelectorBarCurrentItem.LightSensor;

			NetworkOpennessDiagnosticsGrid.Visibility = Visibility.Collapsed;
			WifiProfilesDiagnosticsGrid.Visibility = Visibility.Collapsed;
			PhysicalOrientationDiagnosticsGrid.Visibility = Visibility.Collapsed;
			CompassDiagnosticsGrid.Visibility = Visibility.Collapsed;
			LightSensorDiagnosticsGrid.Visibility = Visibility.Visible;
			UpdateLightSensorSnapshot();
			return;
		}

		_SelectorBarSelectedItem = SelectorBarCurrentItem.WifiProfilesDiagnostics;

		NetworkOpennessDiagnosticsGrid.Visibility = Visibility.Collapsed;
		WifiProfilesDiagnosticsGrid.Visibility = Visibility.Visible;
		PhysicalOrientationDiagnosticsGrid.Visibility = Visibility.Collapsed;
		CompassDiagnosticsGrid.Visibility = Visibility.Collapsed;
		LightSensorDiagnosticsGrid.Visibility = Visibility.Collapsed;
		bool privacyHandled = false;
		ApplyPrivacyModeWifiProfilesOverride(selectFirst: true, ref privacyHandled);
		if (privacyHandled)
		{
			return;
		}
		// Auto-retrieve when the Wi-Fi diagnostics page is selected. Do this only once per session unless the list is empty.
		if (_wifiProfilesLoaded && WifiProfilesItems.Count > 0)
		{
			EnsureWifiSelection();
			return;
		}
		await RetrieveWifiProfilesAsync(selectFirst: true);
	}

	private async void OnWifiProfilesRunButtonClick()
	{
		bool privacyHandled = false;
		ApplyPrivacyModeWifiProfilesOverride(selectFirst: true, ref privacyHandled);
		if (privacyHandled)
		{
			return;
		}

		await RetrieveWifiProfilesAsync(selectFirst: true);
	}

	private void OnWifiProfilesItemClick(object sender, ItemClickEventArgs args)
	{
		if (args.ClickedItem is not WifiProfileRow row)
		{
			return;
		}

		WifiProfilesListView.SelectedItem = row;
		ApplyWifiSelection(row);
	}

	private async Task RetrieveWifiProfilesAsync(bool selectFirst)
	{
		bool privacyHandled = false;
		ApplyPrivacyModeWifiProfilesOverride(selectFirst, ref privacyHandled);
		if (privacyHandled)
		{
			return;
		}

		if (_wifiProfilesRetrievalInProgress)
		{
			return;
		}

		_wifiProfilesRetrievalInProgress = true;
		WifiProfilesRunButton.IsEnabled = false;
		WifiProfilesProgressRing.Visibility = Visibility.Visible;
		WifiProfilesProgressRing.IsActive = true;
		WifiProfilesItems.Clear();
		ClearWifiSelectionDetails();

		try
		{
			List<WifiProfileRow> rows = await Task.Run(GetSavedWifiProfiles);

			foreach (WifiProfileRow itme in CollectionsMarshal.AsSpan(rows))
			{
				WifiProfilesItems.Add(itme);
			}

			_wifiProfilesLoaded = true;

			if (selectFirst)
			{
				EnsureWifiSelection();
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
		finally
		{
			WifiProfilesProgressRing.IsActive = false;
			WifiProfilesProgressRing.Visibility = Visibility.Collapsed;
			WifiProfilesRunButton.IsEnabled = true;
			_wifiProfilesRetrievalInProgress = false;
		}
	}

	private void EnsureWifiSelection()
	{
		if (WifiProfilesItems.Count < 1)
		{
			return;
		}

		if (WifiProfilesListView.SelectedItem is WifiProfileRow selected)
		{
			ApplyWifiSelection(selected);
			return;
		}

		WifiProfilesListView.SelectedIndex = 0;
		if (WifiProfilesListView.SelectedItem is WifiProfileRow row)
		{
			ApplyWifiSelection(row);
			WifiProfilesListView.ScrollIntoView(row);
		}
	}

	private void ApplyWifiSelection(WifiProfileRow row)
	{
		WifiSelectedTitleTextBlock.Text = row.DisplayProfileName;
		WifiSelectedInterfaceTextBlock.Text = row.InterfaceDescription + " (" + row.InterfaceGuid + ")";
		WifiSelectedInterfaceStateTextBlock.Text = row.InterfaceState;
		WifiSelectedAuthenticationTextBlock.Text = ValueOrUnavailable(row.Authentication);
		WifiSelectedEncryptionTextBlock.Text = ValueOrUnavailable(row.Encryption);
		WifiSelectedConnectionTextBlock.Text = ValueOrUnavailable(row.ConnectionType) + " / " + ValueOrUnavailable(row.ConnectionMode);
		WifiSelectedOneXTextBlock.Text = ValueOrUnavailable(row.OneX);
		WifiSelectedSharedKeyTextBlock.Text = row.SharedKeyConfigured ? ("Configured (Type: " + ValueOrUnavailable(row.KeyType) + ", Protected: " + ValueOrUnavailable(row.Protected) + ")") : "Not configured";
	}

	private void ClearWifiSelectionDetails()
	{
		WifiSelectedTitleTextBlock.Text = "Select a profile";
		WifiSelectedInterfaceTextBlock.Text = string.Empty;
		WifiSelectedInterfaceStateTextBlock.Text = string.Empty;
		WifiSelectedAuthenticationTextBlock.Text = string.Empty;
		WifiSelectedEncryptionTextBlock.Text = string.Empty;
		WifiSelectedConnectionTextBlock.Text = string.Empty;
		WifiSelectedOneXTextBlock.Text = string.Empty;
		WifiSelectedSharedKeyTextBlock.Text = string.Empty;
	}

	private unsafe List<WifiProfileRow> GetSavedWifiProfiles()
	{
		List<WifiProfileRow> rows = new(64);
		uint openResult = NativeMethods.WlanOpenHandle(WifiWlanClientVersionLonghorn, IntPtr.Zero, out uint negotiatedVersion, out nint clientHandle);
		if (openResult != WifiWlanErrorSuccess || clientHandle == IntPtr.Zero)
		{
			return rows;
		}

		try
		{
			uint enumResult = NativeMethods.WlanEnumInterfaces(clientHandle, IntPtr.Zero, out nint interfaceListPointer);
			if (enumResult != WifiWlanErrorSuccess || interfaceListPointer == IntPtr.Zero)
			{
				return rows;
			}

			try
			{
				WLAN_INTERFACE_INFO_LIST* interfaceList = (WLAN_INTERFACE_INFO_LIST*)interfaceListPointer;
				uint interfaceCount = interfaceList->NumberOfItems;
				byte* firstInterfaceAddress = (byte*)interfaceListPointer + sizeof(uint) + sizeof(uint);
				for (uint interfaceIndex = 0; interfaceIndex < interfaceCount; interfaceIndex++)
				{
					nuint interfaceOffset = interfaceIndex * (nuint)sizeof(WLAN_INTERFACE_INFO);
					WLAN_INTERFACE_INFO* interfaceInfo = (WLAN_INTERFACE_INFO*)(firstInterfaceAddress + interfaceOffset);
					AppendInterfaceProfiles(clientHandle, interfaceInfo, rows);
				}
			}
			finally
			{
				NativeMethods.WlanFreeMemory(interfaceListPointer);
			}
		}
		finally
		{
			_ = NativeMethods.WlanCloseHandle(clientHandle, IntPtr.Zero);
		}

		return rows;
	}

	private static unsafe void AppendInterfaceProfiles(IntPtr clientHandle, WLAN_INTERFACE_INFO* interfaceInfo, List<WifiProfileRow> rows)
	{
		string interfaceDescription = FixedCharBufferToString(interfaceInfo->InterfaceDescription, WifiWlanMaxNameLength);
		string interfaceGuidText = interfaceInfo->InterfaceGuid.ToString();
		string interfaceStateText = FormatWifiInterfaceState(interfaceInfo->InterfaceState);

		Guid interfaceGuid = interfaceInfo->InterfaceGuid;
		uint result = NativeMethods.WlanGetProfileList(clientHandle, ref interfaceGuid, IntPtr.Zero, out nint profileListPointer);
		if (result != WifiWlanErrorSuccess || profileListPointer == IntPtr.Zero)
		{
			return;
		}

		try
		{
			WLAN_PROFILE_INFO_LIST* profileList = (WLAN_PROFILE_INFO_LIST*)profileListPointer;
			uint profileCount = profileList->NumberOfItems;
			byte* firstProfileAddress = (byte*)profileListPointer + sizeof(uint) + sizeof(uint);
			for (uint profileIndex = 0; profileIndex < profileCount; profileIndex++)
			{
				nuint profileOffset = profileIndex * (nuint)sizeof(WLAN_PROFILE_INFO);
				WLAN_PROFILE_INFO* profileInfo = (WLAN_PROFILE_INFO*)(firstProfileAddress + profileOffset);
				AppendProfile(clientHandle, ref interfaceGuid, profileInfo, interfaceDescription, interfaceGuidText, interfaceStateText, rows);
			}
		}
		finally
		{
			NativeMethods.WlanFreeMemory(profileListPointer);
		}
	}

	private static unsafe void AppendProfile(IntPtr clientHandle, ref Guid interfaceGuid, WLAN_PROFILE_INFO* profileInfo, string interfaceDescription, string interfaceGuidText, string interfaceStateText, List<WifiProfileRow> rows)
	{
		string profileName = FixedCharBufferToString(profileInfo->ProfileName, WifiWlanMaxNameLength);
		if (string.IsNullOrWhiteSpace(profileName))
		{
			profileName = "Unnamed profile";
		}

		uint getResult = NativeMethods.WlanGetProfile(clientHandle, ref interfaceGuid, profileName, IntPtr.Zero, out nint profileXmlPointer, out uint profileFlags, out uint grantedAccess);
		if (getResult != WifiWlanErrorSuccess || profileXmlPointer == IntPtr.Zero)
		{
			return;
		}

		try
		{
			string profileXml = Marshal.PtrToStringUni(profileXmlPointer) ?? string.Empty;
			WifiProfileDetails details = ParseWifiProfileDetails(profileXml);

			rows.Add(new WifiProfileRow
			{
				InterfaceDescription = interfaceDescription,
				InterfaceGuid = interfaceGuidText,
				InterfaceState = interfaceStateText,
				ProfileName = profileName,
				ConnectionType = details.ConnectionType,
				ConnectionMode = details.ConnectionMode,
				Authentication = details.Authentication,
				Encryption = details.Encryption,
				OneX = details.UseOneX,
				SharedKeyConfigured = details.SharedKeyConfigured,
				KeyType = details.KeyType,
				Protected = details.Protected
			});
		}
		finally
		{
			NativeMethods.WlanFreeMemory(profileXmlPointer);
		}
	}

	private static WifiProfileDetails ParseWifiProfileDetails(string profileXml)
	{
		string connectionType = ExtractWifiElementValue(profileXml, "connectionType");
		string connectionMode = ExtractWifiElementValue(profileXml, "connectionMode");
		string authentication = ExtractWifiElementValue(profileXml, "authentication");
		string encryption = ExtractWifiElementValue(profileXml, "encryption");
		string useOneX = ExtractWifiElementValue(profileXml, "useOneX");
		string keyType = ExtractWifiElementValue(profileXml, "keyType");
		string protectedValue = ExtractWifiElementValue(profileXml, "protected");
		bool sharedKeyConfigured = ContainsWifiElement(profileXml, "sharedKey");

		return new WifiProfileDetails(connectionType, connectionMode, authentication, encryption, useOneX, sharedKeyConfigured, keyType, protectedValue);
	}

	private static string ExtractWifiElementValue(string xml, string elementName)
	{
		string startTag = "<" + elementName + ">";
		string endTag = "</" + elementName + ">";

		int startIndex = xml.IndexOf(startTag, StringComparison.OrdinalIgnoreCase);
		if (startIndex < 0)
		{
			return string.Empty;
		}

		startIndex += startTag.Length;
		int endIndex = xml.IndexOf(endTag, startIndex, StringComparison.OrdinalIgnoreCase);
		if (endIndex < 0)
		{
			return string.Empty;
		}

		return xml[startIndex..endIndex].Trim();
	}

	private static bool ContainsWifiElement(string xml, string elementName) => xml.Contains("<" + elementName + ">", StringComparison.OrdinalIgnoreCase);

	private static string ValueOrUnavailable(string value) => string.IsNullOrWhiteSpace(value) ? "Unavailable" : value;

	private static unsafe string FixedCharBufferToString(char* buffer, int maxLength)
	{
		int length = 0;
		while (length < maxLength && buffer[length] != (char)0)
		{
			length++;
		}
		return new string(buffer, 0, length);
	}

	private static string FormatWifiInterfaceState(WLAN_INTERFACE_STATE state) => state switch
	{
		WLAN_INTERFACE_STATE.NotReady => "Not ready",
		WLAN_INTERFACE_STATE.Connected => "Connected",
		WLAN_INTERFACE_STATE.AdHocNetworkFormed => "Ad hoc network formed",
		WLAN_INTERFACE_STATE.Disconnecting => "Disconnecting",
		WLAN_INTERFACE_STATE.Disconnected => "Disconnected",
		WLAN_INTERFACE_STATE.Associating => "Associating",
		WLAN_INTERFACE_STATE.Discovering => "Discovering",
		WLAN_INTERFACE_STATE.Authenticating => "Authenticating",
		_ => "Unknown"
	};

	private readonly struct WifiProfileDetails(
		string connectionType,
		string connectionMode,
		string authentication,
		string encryption,
		string useOneX,
		bool sharedKeyConfigured,
		string keyType,
		string protectedValue)
	{
		internal string ConnectionType => connectionType;
		internal string ConnectionMode => connectionMode;
		internal string Authentication => authentication;
		internal string Encryption => encryption;
		internal string UseOneX => useOneX;
		internal bool SharedKeyConfigured => sharedKeyConfigured;
		internal string KeyType => keyType;
		internal string Protected => protectedValue;
	}

	#endregion

}

// This class is responsible primarily for providing demo data.
// These are provided when the heart button is pressed more than 30 times.
internal sealed partial class HomeLiveGraphsWindow
{
	partial void OnHeartPrivacyWindowInitialized();
	partial void OnHeartPrivacyClickRequested();
	partial void ApplyPrivacyModeGpuDisplayNameOverride(int displayIndex, ref string? displayName);
	partial void ApplyPrivacyModeNetworkDelayOverride(ref long displayedElapsedMilliseconds);
	partial void ApplyPrivacyModeWifiProfilesOverride(bool selectFirst, ref bool handled);
	private const int HeartPrivacyModeActivationClickCount = 30;
	private const long PrivacyModeDisplayedNetworkDelayMilliseconds = 5L;
	private const string PrivacyModeSystemRamText = "128.0 GB - DDR5 5600 MT/s";
	private const string PrivacyModeDiskSizeText = "5.0 TB";
	private const string PrivacyModeCpuDetailsText = "Intel(R) Core(TM) Ultra 9 285H - 16 Core / 22 Thread - X64 - 2.9 GHz - 24 MB L3 Cache - 1 Socket";
	private const string PrivacyModeComputerNameText = "DESKTOP-9XQ9V2M";
	private const string PrivacyModeSystemInfoText = "Lenovo - ThinkPad P1 Gen 7";
	private static readonly string[] PrivacyModeGpuDisplayNames = ["AMD Radeon RX 7900 XTX", "NVIDIA RTX 6000 Ada Generation", "Intel(R) Arc(TM) Pro A60 Graphics"];
	private static readonly ConditionalWeakTable<HomeVM, HeartPrivacyModeState> HeartPrivacyModeStates = new();

	private sealed class HeartPrivacyModeState
	{
		internal int ClickCount { get; set; }
		internal bool IsEnabled { get; set; }
	}

	private HeartPrivacyModeState PrivacyModeState => HeartPrivacyModeStates.GetValue(ViewModel, static _ => new HeartPrivacyModeState());

	partial void OnHeartPrivacyWindowInitialized()
	{
		if (!PrivacyModeState.IsEnabled)
		{
			return;
		}

		ApplyHeartPrivacyModeData();
	}

	partial void OnHeartPrivacyClickRequested()
	{
		HeartPrivacyModeState privacyModeState = PrivacyModeState;
		privacyModeState.ClickCount++;
		ApplyHeartPrivacyModeIfNeeded();
	}
	partial void ApplyPrivacyModeGpuDisplayNameOverride(int displayIndex, ref string? displayName)
	{
		if (!PrivacyModeState.IsEnabled)
		{
			return;
		}

		displayName = GetPrivacyModeGpuDisplayName(displayIndex);
	}

	partial void ApplyPrivacyModeNetworkDelayOverride(ref long displayedElapsedMilliseconds)
	{
		if (!PrivacyModeState.IsEnabled)
		{
			return;
		}

		displayedElapsedMilliseconds = PrivacyModeDisplayedNetworkDelayMilliseconds;
	}

	partial void ApplyPrivacyModeWifiProfilesOverride(bool selectFirst, ref bool handled)
	{
		if (!PrivacyModeState.IsEnabled)
		{
			return;
		}

		ApplyPrivacyModeWifiProfiles(selectFirst);
		handled = true;
	}

	private void ApplyHeartPrivacyModeIfNeeded()
	{
		HeartPrivacyModeState privacyModeState = PrivacyModeState;
		if (privacyModeState.IsEnabled || privacyModeState.ClickCount < HeartPrivacyModeActivationClickCount)
		{
			return;
		}

		privacyModeState.IsEnabled = true;
		ApplyHeartPrivacyModeData();
	}

	private void ApplyHeartPrivacyModeData()
	{
		SetHomeVmSystemRamText(ViewModel, PrivacyModeSystemRamText);
		SetHomeVmDiskSizeText(ViewModel, PrivacyModeDiskSizeText);
		SetHomeVmCpuDetailsText(ViewModel, PrivacyModeCpuDetailsText);
		SetHomeVmGpuNamesText(ViewModel, GetPrivacyModeCombinedGpuNames());
		SetHomeVmComputerNameText(ViewModel, PrivacyModeComputerNameText);
		SetHomeVmSystemInfoText(ViewModel, PrivacyModeSystemInfoText);
		ApplyGpuDisplayNames();
		ApplyPrivacyModeWifiProfiles(selectFirst: true);
	}

	private static string GetPrivacyModeCombinedGpuNames() => string.Join(" - ", PrivacyModeGpuDisplayNames);

	private static string GetPrivacyModeGpuDisplayName(int displayIndex)
	{
		int normalizedIndex = displayIndex < 0 ? 0 : displayIndex % PrivacyModeGpuDisplayNames.Length;
		return PrivacyModeGpuDisplayNames[normalizedIndex];
	}

	private void ApplyPrivacyModeWifiProfiles(bool selectFirst)
	{
		_wifiProfilesRetrievalInProgress = false;
		WifiProfilesProgressRing.IsActive = false;
		WifiProfilesProgressRing.Visibility = Visibility.Collapsed;
		WifiProfilesRunButton.IsEnabled = true;
		WifiProfilesListView.SelectedItem = null;
		WifiProfilesItems.Clear();
		ClearWifiSelectionDetails();

		List<WifiProfileRow> rows = GetPrivacyModeWifiProfiles();
		foreach (WifiProfileRow row in CollectionsMarshal.AsSpan(rows))
		{
			WifiProfilesItems.Add(row);
		}

		_wifiProfilesLoaded = true;
		if (selectFirst)
		{
			EnsureWifiSelection();
		}
	}

	private static List<WifiProfileRow> GetPrivacyModeWifiProfiles()
	{
		const string InterfaceDescription = "Intel(R) Wi-Fi 7 BE200 320MHz";
		const string InterfaceGuid = "7f5d5b4a-20c1-4e5b-9b0a-2f4e28b89160";
		const string InterfaceState = "Disconnected";

		List<WifiProfileRow> rows = new(15)
		{
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "ATT-WiFi-5G", "ESS", "auto", "WPA2PSK", "AES", "false", true, "passPhrase", "true"),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "xfinitywifi", "ESS", "auto", "open", "none", "false", false, string.Empty, string.Empty),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "Starbucks WiFi", "ESS", "manual", "open", "none", "false", false, string.Empty, string.Empty),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "Hilton Honors", "ESS", "manual", "open", "none", "false", false, string.Empty, string.Empty),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "eduroam", "ESS", "manual", "WPA2", "AES", "true", false, string.Empty, string.Empty),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "SpectrumSetup-7C", "ESS", "auto", "WPA2PSK", "AES", "false", true, "passPhrase", "true"),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "NETGEAR36-5G", "ESS", "auto", "WPA2PSK", "AES", "false", true, "passPhrase", "true"),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "TP-Link_5G_8A2C", "ESS", "auto", "WPA2PSK", "AES", "false", true, "passPhrase", "true"),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "Linksys-Guest", "ESS", "manual", "open", "none", "false", false, string.Empty, string.Empty),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "MarriottBonvoy_Guest", "ESS", "manual", "open", "none", "false", false, string.Empty, string.Empty),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "DeltaSkyClub", "ESS", "manual", "WPA2PSK", "AES", "false", true, "passPhrase", "true"),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "United_Wi-Fi", "ESS", "manual", "open", "none", "false", false, string.Empty, string.Empty),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "Google Fiber Setup", "ESS", "manual", "WPA2PSK", "AES", "false", true, "passPhrase", "true"),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "ASUS_88_5G", "ESS", "auto", "WPA2PSK", "AES", "false", true, "passPhrase", "true"),
			CreatePrivacyModeWifiProfile(InterfaceDescription, InterfaceGuid, InterfaceState, "Verizon_5G_Home", "ESS", "auto", "WPA3SAE", "AES", "false", true, "passPhrase", "true")
		};

		return rows;
	}

	private static WifiProfileRow CreatePrivacyModeWifiProfile(string interfaceDescription, string interfaceGuid, string interfaceState, string profileName, string connectionType, string connectionMode, string authentication, string encryption, string oneX, bool sharedKeyConfigured, string keyType, string protectedValue)
	{
		return new WifiProfileRow
		{
			InterfaceDescription = interfaceDescription,
			InterfaceGuid = interfaceGuid,
			InterfaceState = interfaceState,
			ProfileName = profileName,
			ConnectionType = connectionType,
			ConnectionMode = connectionMode,
			Authentication = authentication,
			Encryption = encryption,
			OneX = oneX,
			SharedKeyConfigured = sharedKeyConfigured,
			KeyType = keyType,
			Protected = protectedValue
		};
	}

	[UnsafeAccessor(UnsafeAccessorKind.Method, Name = "set_SystemRamText")]
	private static extern void SetHomeVmSystemRamText(HomeVM viewModel, string? value);

	[UnsafeAccessor(UnsafeAccessorKind.Method, Name = "set_DiskSizeText")]
	private static extern void SetHomeVmDiskSizeText(HomeVM viewModel, string? value);

	[UnsafeAccessor(UnsafeAccessorKind.Method, Name = "set_CpuDetailsText")]
	private static extern void SetHomeVmCpuDetailsText(HomeVM viewModel, string? value);

	[UnsafeAccessor(UnsafeAccessorKind.Method, Name = "set_GpuNamesText")]
	private static extern void SetHomeVmGpuNamesText(HomeVM viewModel, string? value);

	[UnsafeAccessor(UnsafeAccessorKind.Method, Name = "set_ComputerNameText")]
	private static extern void SetHomeVmComputerNameText(HomeVM viewModel, string? value);

	[UnsafeAccessor(UnsafeAccessorKind.Method, Name = "set_SystemInfoText")]
	private static extern void SetHomeVmSystemInfoText(HomeVM viewModel, string? value);
}

internal sealed partial class HomeLiveGraphsWindow
{
	private const double LightSensorMaximumVisualLux = 100000.0;
	private readonly DispatcherTimer SensorsTimer = new();
	private Accelerometer? _Accelerometer;
	private Inclinometer? _Inclinometer;
	private SimpleOrientationSensor? _SimpleOrientationSensor;
	private Gyrometer? _Gyrometer;
	private Compass? _Compass;
	private LightSensor? _LightSensor;
	private double _lightSensorSessionMinimumLux = double.PositiveInfinity;
	private double _lightSensorSessionMaximumLux;

	private static uint GetSensorsReportInterval(Accelerometer? accelerometer, Inclinometer? inclinometer, Gyrometer? gyrometer, Compass? compass, LightSensor? lightSensor)
	{
		const uint DesiredMilliseconds = 100U;
		uint minimumInterval = 0U;
		if (accelerometer is not null)
		{
			minimumInterval = Math.Max(minimumInterval, accelerometer.MinimumReportInterval);
		}
		if (inclinometer is not null)
		{
			minimumInterval = Math.Max(minimumInterval, inclinometer.MinimumReportInterval);
		}
		if (gyrometer is not null)
		{
			minimumInterval = Math.Max(minimumInterval, gyrometer.MinimumReportInterval);
		}
		if (compass is not null)
		{
			minimumInterval = Math.Max(minimumInterval, compass.MinimumReportInterval);
		}
		if (lightSensor is not null)
		{
			minimumInterval = Math.Max(minimumInterval, lightSensor.MinimumReportInterval);
		}
		return Math.Max(DesiredMilliseconds, minimumInterval);
	}

	private void InitializeSensorsMonitoring()
	{
		try
		{
			_Accelerometer = Accelerometer.GetDefault();
			_Inclinometer = Inclinometer.GetDefault();
			_SimpleOrientationSensor = SimpleOrientationSensor.GetDefault();
			_Gyrometer = Gyrometer.GetDefault();
			_Compass = Compass.GetDefault();
			_LightSensor = LightSensor.GetDefault();
			uint reportInterval = GetSensorsReportInterval(_Accelerometer, _Inclinometer, _Gyrometer, _Compass, _LightSensor);
			ApplySensorsReportInterval(reportInterval);
			_LightSensor?.ReadingChanged += OnLightSensorReadingChanged;
			SensorsTimer.Interval = TimeSpan.FromMilliseconds(reportInterval);
			SensorsTimer.Tick += OnSensorsTimerTick;
			SensorsTimer.Start();
			UpdatePhysicalOrientationSnapshot();
			UpdateCompassSnapshot();
			UpdateLightSensorSnapshot();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			PhysicalOrientationStatusTextBlock.Text = "Sensor initialization failed.";
		}
	}

	private void ApplySensorsReportInterval(uint reportInterval)
	{
		_ = (_Accelerometer?.ReportInterval = reportInterval);
		_ = (_Inclinometer?.ReportInterval = reportInterval);
		_ = (_Gyrometer?.ReportInterval = reportInterval);
		_ = (_Compass?.ReportInterval = reportInterval);
		_ = (_LightSensor?.ReportInterval = reportInterval);
	}

	private void StopSensorsMonitoring()
	{
		SensorsTimer.Stop();
		SensorsTimer.Tick -= OnSensorsTimerTick;
		_LightSensor?.ReadingChanged -= OnLightSensorReadingChanged;
		ApplySensorsReportInterval(0U);
	}

	private void OnSensorsTimerTick(object? sender, object e)
	{
		// Poll only the visible sensor diagnostics page to avoid updating hidden UI elements on every tick.
		switch (_SelectorBarSelectedItem)
		{
			case SelectorBarCurrentItem.PhysicalOrientation:
				{
					UpdatePhysicalOrientationSnapshot();
					break;
				}
			case SelectorBarCurrentItem.Compass:
				{
					UpdateCompassSnapshot();
					break;
				}
			case SelectorBarCurrentItem.LightSensor:
				{
					break;
				}

			// Things that don't have real-time updates
			case SelectorBarCurrentItem.NetworkOpennes:
			case SelectorBarCurrentItem.WifiProfilesDiagnostics:
			default:
				break;
		}
	}

	private void UpdatePhysicalOrientationSnapshot()
	{
		try
		{
			double pitch = 0.0;
			double roll = 0.0;
			double yaw = 0.0;
			bool hasInclinometerReading = false;
			InclinometerReading? inclinometerReading = _Inclinometer?.GetCurrentReading();
			if (inclinometerReading is not null)
			{
				pitch = inclinometerReading.PitchDegrees;
				roll = inclinometerReading.RollDegrees;
				yaw = inclinometerReading.YawDegrees;
				hasInclinometerReading = true;
			}
			double accelerationX = 0.0;
			double accelerationY = 0.0;
			double accelerationZ = 0.0;
			string motionState = "No accelerometer reading";
			AccelerometerReading? accelerometerReading = _Accelerometer?.GetCurrentReading();
			if (accelerometerReading is not null)
			{
				accelerationX = accelerometerReading.AccelerationX;
				accelerationY = accelerometerReading.AccelerationY;
				accelerationZ = accelerometerReading.AccelerationZ;
				motionState = ClassifyPhysicalOrientationState(accelerationX, accelerationY, accelerationZ);
				if (!hasInclinometerReading)
				{
					pitch = Math.Atan2(-accelerationX, Math.Sqrt((accelerationY * accelerationY) + (accelerationZ * accelerationZ))) * 180.0 / Math.PI;
					roll = Math.Atan2(accelerationY, accelerationZ) * 180.0 / Math.PI;
				}
			}
			double angularVelocityX = 0.0;
			double angularVelocityY = 0.0;
			double angularVelocityZ = 0.0;
			string gyrometerText = "Gyro unavailable";
			GyrometerReading? gyrometerReading = _Gyrometer?.GetCurrentReading();
			if (gyrometerReading is not null)
			{
				angularVelocityX = gyrometerReading.AngularVelocityX;
				angularVelocityY = gyrometerReading.AngularVelocityY;
				angularVelocityZ = gyrometerReading.AngularVelocityZ;
				gyrometerText = "Gyro X " + angularVelocityX.ToString("0.0", CultureInfo.InvariantCulture) + "°/s  Y " + angularVelocityY.ToString("0.0", CultureInfo.InvariantCulture) + "°/s  Z " + angularVelocityZ.ToString("0.0", CultureInfo.InvariantCulture) + "°/s";
			}
			SimpleOrientation simpleOrientation = _SimpleOrientationSensor?.GetCurrentOrientation() ?? SimpleOrientation.NotRotated;
			string simpleOrientationText = _SimpleOrientationSensor is null ? "Unavailable" : simpleOrientation.ToString();
			string physicalOrientationStatusText = BuildPhysicalOrientationAvailabilityText(motionState);
			PhysicalOrientationView.ApplyOrientationSnapshot(
				pitch,
				roll,
				yaw,
				accelerationX,
				accelerationY,
				accelerationZ,
				angularVelocityX,
				angularVelocityY,
				angularVelocityZ,
				gyrometerText,
				simpleOrientationText,
				physicalOrientationStatusText);
			PhysicalOrientationPitchTextBlock.Text = pitch.ToString("0.0", CultureInfo.InvariantCulture) + "°";
			PhysicalOrientationRollTextBlock.Text = roll.ToString("0.0", CultureInfo.InvariantCulture) + "°";
			PhysicalOrientationYawTextBlock.Text = yaw.ToString("0.0", CultureInfo.InvariantCulture) + "°";
			PhysicalOrientationSimpleTextBlock.Text = simpleOrientationText;
			PhysicalOrientationGyroTextBlock.Text = gyrometerText;
			PhysicalOrientationStatusTextBlock.Text = physicalOrientationStatusText;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			PhysicalOrientationStatusTextBlock.Text = "Orientation reading failed.";
		}
	}

	private void UpdateCompassSnapshot()
	{
		try
		{
			CompassReading? compassReading = _Compass?.GetCurrentReading();
			if (compassReading is null)
			{
				CompassView.HeadingDegrees = 0.0;
				CompassHeadingTextBlock.Text = "Unavailable";
				CompassDirectionTextBlock.Text = "No compass reading";
				CompassMagneticNorthTextBlock.Text = "Unavailable";
				CompassTrueNorthTextBlock.Text = "Unavailable";
				CompassAccuracyTextBlock.Text = "Unavailable";
				CompassAdviceTextBlock.Text = "Move the device away from magnets, speakers, and metal surfaces if the compass heading looks unstable.";
				return;
			}
			double magneticHeading = NormalizeHeading(compassReading.HeadingMagneticNorth);
			double? trueHeading = compassReading.HeadingTrueNorth;
			CompassView.HeadingDegrees = magneticHeading;
			CompassHeadingTextBlock.Text = magneticHeading.ToString("0.0", CultureInfo.InvariantCulture) + "°";
			CompassDirectionTextBlock.Text = GetCompassDirectionName(magneticHeading);
			CompassMagneticNorthTextBlock.Text = magneticHeading.ToString("0.0", CultureInfo.InvariantCulture) + "° magnetic north";
			CompassTrueNorthTextBlock.Text = trueHeading.HasValue ? NormalizeHeading(trueHeading.Value).ToString("0.0", CultureInfo.InvariantCulture) + "° true north" : "Unavailable on this device";
			CompassAccuracyTextBlock.Text = compassReading.HeadingAccuracy.ToString();
			CompassAdviceTextBlock.Text = GetCompassAccuracyAdvice(compassReading.HeadingAccuracy);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			CompassHeadingTextBlock.Text = "Compass reading failed";
		}
	}

	private void UpdateLightSensorSnapshot(LightSensorReading? currentReading = null)
	{
		try
		{
			LightSensorReading? lightReading = currentReading ?? _LightSensor?.GetCurrentReading();
			if (lightReading is null)
			{
				LightSensorMeterView.Lux = 0.0;
				LightSensorLuxTextBlock.Text = "Unavailable";
				LightSensorRatingTextBlock.Text = "No light sensor reading";
				LightSensorAdviceTextBlock.Text = "The light sensor is unavailable or has not produced a reading yet.";
				LightSensorMinMaxTextBlock.Text = "Session min: unavailable   Session max: unavailable";
				LightSensorMeterCaptionTextBlock.Text = "0 lux";
				return;
			}
			double lux = Math.Max(0.0, lightReading.IlluminanceInLux);
			_lightSensorSessionMinimumLux = Math.Min(_lightSensorSessionMinimumLux, lux);
			_lightSensorSessionMaximumLux = Math.Max(_lightSensorSessionMaximumLux, lux);
			LightSensorMeterView.Lux = lux;
			LightSensorLuxTextBlock.Text = lux.ToString("0.0", CultureInfo.InvariantCulture) + " lux";
			(string lightSensorRating, string lightSensorAdvice) = lux switch
			{
				<= 10.0 => ("Pitch Black", "Extremely low light. Dark UI, reduced glare, and lower display brightness are usually more comfortable."),
				<= 50.0 => ("Very Dark", "Very dark environment. A dark theme and low brightness can reduce eye strain."),
				<= 200.0 => ("Dark Indoors", "Dark indoor lighting. Consider a softer UI with readable contrast."),
				<= 400.0 => ("Dim Indoors", "Dim indoor lighting. Normal UI contrast is usually readable, but avoid very bright surfaces."),
				<= 1000.0 => ("Normal Indoors", "Normal indoor lighting. This is generally comfortable for typical desktop use."),
				<= 5000.0 => ("Bright Indoors", "Bright indoor lighting. Higher display brightness and stronger contrast can improve readability."),
				<= 10000.0 => ("Dim Outdoors", "Outdoor shade or dim outdoor light. Glare may begin to affect readability."),
				<= 30000.0 => ("Cloudy Outdoors", "Cloudy outdoor light. Use high contrast UI and expect reflections on glossy displays."),
				_ => ("Direct Sunlight", "Direct sunlight. Maximum readability usually needs high brightness, strong contrast, and reduced visual clutter.")
			};
			LightSensorRatingTextBlock.Text = lightSensorRating;
			LightSensorAdviceTextBlock.Text = lightSensorAdvice;
			LightSensorMinMaxTextBlock.Text = "Session min: " + _lightSensorSessionMinimumLux.ToString("0.0", CultureInfo.InvariantCulture) + " lux   Session max: " + _lightSensorSessionMaximumLux.ToString("0.0", CultureInfo.InvariantCulture) + " lux";
			LightSensorMeterCaptionTextBlock.Text = "Microsoft lux rating: " + lightSensorRating + "   Visual meter uses a log scale from 0 to " + LightSensorMaximumVisualLux.ToString("0", CultureInfo.InvariantCulture) + " lux.";
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			LightSensorLuxTextBlock.Text = "Light sensor reading failed";
		}
	}

	private void OnLightSensorReadingChanged(LightSensor sender, LightSensorReadingChangedEventArgs args) => _ = DispatcherQueue.TryEnqueue(() => { if (_SelectorBarSelectedItem == SelectorBarCurrentItem.LightSensor) { UpdateLightSensorSnapshot(args.Reading); } });

	private string BuildPhysicalOrientationAvailabilityText(string motionState)
	{
		bool hasMotionSensor = _Accelerometer is not null || _Inclinometer is not null || _SimpleOrientationSensor is not null || _Gyrometer is not null;
		return hasMotionSensor ? motionState : "No motion or orientation sensors are exposed by Windows on this device.";
	}

	private static string ClassifyPhysicalOrientationState(double x, double y, double z)
	{
		double absX = Math.Abs(x);
		double absY = Math.Abs(y);
		double absZ = Math.Abs(z);
		if (absZ >= 0.85 && absX <= 0.35 && absY <= 0.35)
		{
			return z < 0.0 ? "Flat, face up" : "Flat, face down";
		}
		if (absX >= 0.75 || absY >= 0.75)
		{
			return "Tilted or upright";
		}
		return "Partly tilted or moving";
	}

	private static double NormalizeHeading(double heading)
	{
		double normalizedHeading = heading % 360.0;
		if (normalizedHeading < 0.0)
		{
			normalizedHeading += 360.0;
		}
		return normalizedHeading;
	}

	private static string GetCompassDirectionName(double heading)
	{
		int index = (int)Math.Round(NormalizeHeading(heading) / 45.0, MidpointRounding.AwayFromZero) % HomeCompassView.CompassLabels.Length;
		return HomeCompassView.CompassLabels[index];
	}

	private static string GetCompassAccuracyAdvice(MagnetometerAccuracy accuracy) => accuracy switch
	{
		MagnetometerAccuracy.High => "High accuracy. The heading should be suitable for live directional display.",
		MagnetometerAccuracy.Approximate => "Approximate accuracy. The heading is usable but may drift near magnetic interference.",
		MagnetometerAccuracy.Unreliable => "Unreliable accuracy. Move away from magnets, speakers, power adapters, and large metal surfaces.",
		_ => "Accuracy is unknown. If the heading looks wrong, rotate the device slowly to let Windows recalibrate the magnetometer."
	};

}
