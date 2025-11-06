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

using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.Foundation;
using Windows.UI;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// Status states for the status indicator.
/// </summary>
internal enum StatusState
{
	Undetermined,
	Applied,
	NotApplied
}

/// <summary>
/// A custom UserControl that shows status with sliding door animation on hover, used by ListViews and MUnit.
/// Stretches to the available width from the parent (no fixed width).
/// Uses MinWidth based on localized text so long strings are never cut.
/// Sizes the left/right panels based on the actual width given by the parent, so edges remain visible even when the localized label string is longer than usual.
/// </summary>
internal sealed partial class StatusIndicatorV2 : UserControl, IDisposable, IExplicitDisposalOptIn
{
	// Visual sizing constants
	private const double MinBadgeWidth = 80.0;     // Minimal visual width to keep badge shape
	private const double TextPadding = 16.0;       // Horizontal padding to measured text width
	private const double IndicatorHeight = 24.0;   // Fixed height of the badge
	private new const double CornerRadius = 12.0;  // Rounded corners

	// Animation constants
	private const double SlideDistance = 15.0;
	private static readonly TimeSpan AnimationDuration = TimeSpan.FromMilliseconds(300);

	// Colors
	private static readonly Color YellowColor = Color.FromArgb(255, 255, 193, 7);
	private static readonly Color GreenColor = Color.FromArgb(255, 40, 167, 69);
	private static readonly Color RedColor = Color.FromArgb(255, 220, 53, 69);
	private static readonly Color TextColor = Color.FromArgb(255, 33, 37, 41);

	// Visual elements
	private Border? _mainBorder;
	private Grid? _contentGrid;
	private Border? _leftPanel;
	private Border? _rightPanel;
	private TextBlock? _statusText;

	// Animations
	private Storyboard? _hoverInStoryboard;
	private Storyboard? _hoverOutStoryboard;

	// Brushes
	private SolidColorBrush? _currentBrush;
	private SolidColorBrush? _textBrush;

	// State
	private bool _isDisposed;

	// Reusable TextBlock to measure localized strings with the same typography as the visible one
	private static readonly TextBlock MeasurementTextBlock = new()
	{
		FontSize = 11,
		FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
		Visibility = Visibility.Collapsed,
		TextWrapping = TextWrapping.NoWrap
	};

	internal static readonly DependencyProperty StatusProperty =
		DependencyProperty.Register(
			nameof(Status),
			typeof(StatusState),
			typeof(StatusIndicatorV2),
			new PropertyMetadata(StatusState.Undetermined, OnStatusChanged));

	internal StatusState Status
	{
		get => (StatusState)GetValue(StatusProperty);
		set => SetValue(StatusProperty, value);
	}

	// Explicit disposal opt-in DP (shared pattern)
	internal static readonly DependencyProperty DisposeOnlyOnExplicitCallProperty =
		DependencyProperty.Register(
			nameof(DisposeOnlyOnExplicitCall),
			typeof(bool),
			typeof(StatusIndicatorV2),
			new PropertyMetadata(false));

	/// <summary>
	/// When true, skips automatic disposal on transient Unloaded events.
	/// </summary>
	public bool DisposeOnlyOnExplicitCall
	{
		get => (bool)GetValue(DisposeOnlyOnExplicitCallProperty);
		set => SetValue(DisposeOnlyOnExplicitCallProperty, value);
	}

	internal StatusIndicatorV2()
	{
		// Allow the control to take all the horizontal space given by the parent
		HorizontalAlignment = HorizontalAlignment.Stretch;
		VerticalAlignment = VerticalAlignment.Center;

		// We never set Width; we let the parent provide the width; we only set MinWidth.
		Height = IndicatorHeight;
		Background = new SolidColorBrush(Colors.Transparent);
		IsTabStop = true;

		CreateBrushes();
		CreateVisualStructure();
		UpdateStatusAppearance();

		Loaded += StatusIndicatorV2_Loaded;
		Unloaded += StatusIndicatorV2_Unloaded;
		PointerEntered += StatusIndicatorV2_PointerEntered;
		PointerExited += StatusIndicatorV2_PointerExited;
		SizeChanged += StatusIndicatorV2_SizeChanged;
	}

	private static void OnStatusChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is StatusIndicatorV2 indicator)
		{
			indicator.UpdateStatusAppearance();
		}
	}

	/// <summary>
	/// Measures the localized status text and returns a suitable MinWidth for the badge.
	/// </summary>
	private static double CalculateMinWidthForText(string statusText)
	{
		if (string.IsNullOrEmpty(statusText))
			return MinBadgeWidth;

		MeasurementTextBlock.Text = statusText;
		MeasurementTextBlock.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
		double textWidth = MeasurementTextBlock.DesiredSize.Width;
		double needed = textWidth + TextPadding;

		return needed < MinBadgeWidth ? MinBadgeWidth : needed;
	}

	private void CreateBrushes()
	{
		try
		{
			_textBrush = new SolidColorBrush(TextColor);
		}
		catch (Exception ex)
		{
			Logger.Write($"StatusIndicatorV2 brush creation failed: {ex.Message}");
		}
	}

	private void CreateVisualStructure()
	{
		try
		{
			_contentGrid = new Grid
			{
				// Stretch to fill the width we are arranged with by the parent.
				HorizontalAlignment = HorizontalAlignment.Stretch,
				VerticalAlignment = VerticalAlignment.Center,
				Height = IndicatorHeight,
				// Shouldn't set Width here; we let Arrange pass control the width.
			};

			_mainBorder = new Border
			{
				CornerRadius = new CornerRadius(CornerRadius),
				HorizontalAlignment = HorizontalAlignment.Stretch,
				VerticalAlignment = VerticalAlignment.Stretch,
				// Height is inherited through the layout; no explicit width here.
			};

			_leftPanel = new Border
			{
				CornerRadius = new CornerRadius(CornerRadius, 0, 0, CornerRadius),
				HorizontalAlignment = HorizontalAlignment.Left,
				VerticalAlignment = VerticalAlignment.Stretch,
				RenderTransform = new TranslateTransform(),
				RenderTransformOrigin = new Point(0.5, 0.5)
			};

			_rightPanel = new Border
			{
				CornerRadius = new CornerRadius(0, CornerRadius, CornerRadius, 0),
				HorizontalAlignment = HorizontalAlignment.Right,
				VerticalAlignment = VerticalAlignment.Stretch,
				RenderTransform = new TranslateTransform(),
				RenderTransformOrigin = new Point(0.5, 0.5)
			};

			_statusText = new TextBlock
			{
				Text = "N/A",
				FontSize = 11,
				FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
				Foreground = _textBrush,
				HorizontalAlignment = HorizontalAlignment.Center,
				VerticalAlignment = VerticalAlignment.Center,
				Opacity = 0,                  // Fades in on hover
				IsHitTestVisible = false,
				TextWrapping = TextWrapping.NoWrap
			};

			_contentGrid.Children.Add(_mainBorder);
			_contentGrid.Children.Add(_leftPanel);
			_contentGrid.Children.Add(_rightPanel);
			_contentGrid.Children.Add(_statusText);

			Content = _contentGrid;
		}
		catch (Exception ex)
		{
			Logger.Write($"StatusIndicatorV2 visual structure creation failed: {ex.Message}");
		}
	}

	/// <summary>
	/// Updates colors, text, and MinWidth based on the Status.
	/// Sizing of the panels is handled in SizeChanged using ActualWidth to ensure we use all available space.
	/// </summary>
	private void UpdateStatusAppearance()
	{
		if (_isDisposed) return;

		try
		{
			Color statusColor = Status switch
			{
				StatusState.Applied => GreenColor,
				StatusState.NotApplied => RedColor,
				_ => YellowColor
			};

			string statusText = Status switch
			{
				StatusState.Applied => GlobalVars.GetStr("AppliedText"),
				StatusState.NotApplied => GlobalVars.GetStr("NotAppliedText"),
				_ => GlobalVars.GetStr("NAText")
			};

			// Ensure long localized strings are never cut off by setting MinWidth accordingly.
			double minWidth = CalculateMinWidthForText(statusText);
			MinWidth = minWidth;        // Let parent arrange us wider if it wants; we just enforce a minimum.
			Height = IndicatorHeight;

			_currentBrush = new SolidColorBrush(statusColor);

			_ = _mainBorder?.Background = _currentBrush;
			_ = _leftPanel?.Background = _currentBrush;
			_ = _rightPanel?.Background = _currentBrush;
			_ = _statusText?.Text = statusText;

			UpdateTooltip();

			// After changing MinWidth/Text, re-apply sizes based on the current ActualWidth
			ApplyActualWidthToPanels();
		}
		catch (Exception ex)
		{
			Logger.Write($"StatusIndicatorV2 status appearance update failed: {ex.Message}");
		}
	}

	/// <summary>
	/// Uses the ActualWidth we are given by the parent to size panels so the badge spans the available space.
	/// This ensures we use all the column width (if provided) and edges remain visible.
	/// </summary>
	private void ApplyActualWidthToPanels()
	{
		if (_isDisposed) return;

		try
		{
			double width = ActualWidth;

			// If we haven't been measured/arranged yet, skip; SizeChanged will call us again.
			if (width <= 0.0)
				return;

			// Main container is already Stretch; just make sure child elements respect the full width
			_ = (_contentGrid?.Height = IndicatorHeight);

			// Each sliding panel occupies half of the available width (+1px overlap for the seam).
			double panelWidth = (width / 2.0) + 1.0;

			if (_leftPanel != null)
			{
				_leftPanel.Width = panelWidth;
				_leftPanel.Height = IndicatorHeight;
			}

			if (_rightPanel != null)
			{
				_rightPanel.Width = panelWidth;
				_rightPanel.Height = IndicatorHeight;
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"StatusIndicatorV2 panel sizing failed: {ex.Message}");
		}
	}

	private void UpdateTooltip()
	{
		string tooltipText = Status switch
		{
			StatusState.Applied => GlobalVars.GetStr("StatusAppliedText"),
			StatusState.NotApplied => GlobalVars.GetStr("StatusNotAppliedText"),
			_ => GlobalVars.GetStr("StatusUndeterminedText")
		};

		ToolTipService.SetToolTip(this, tooltipText);
	}

	private void StatusIndicatorV2_Loaded(object? sender, RoutedEventArgs e)
	{
		if (_isDisposed) return;

		try
		{
			CreateAnimations();
			// On load, ensure we size panels to the currently arranged width
			ApplyActualWidthToPanels();
		}
		catch (Exception ex)
		{
			Logger.Write($"StatusIndicatorV2 loading failed: {ex.Message}");
		}
	}

	private void CreateAnimations()
	{
		if (_isDisposed || _leftPanel == null || _rightPanel == null || _statusText == null) return;

		try
		{
			_hoverInStoryboard = new Storyboard();

			// Left panel slides out to the left
			DoubleAnimation leftSlideOut = new()
			{
				Duration = new Duration(AnimationDuration),
				From = 0,
				To = -SlideDistance,
				EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
			};

			// Right panel slides out to the right
			DoubleAnimation rightSlideOut = new()
			{
				Duration = new Duration(AnimationDuration),
				From = 0,
				To = SlideDistance,
				EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
			};

			// Text fades in
			DoubleAnimation textFadeIn = new()
			{
				Duration = new Duration(AnimationDuration),
				From = 0,
				To = 1,
				EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
			};

			Storyboard.SetTarget(leftSlideOut, _leftPanel);
			Storyboard.SetTargetProperty(leftSlideOut, "(UIElement.RenderTransform).(TranslateTransform.X)");

			Storyboard.SetTarget(rightSlideOut, _rightPanel);
			Storyboard.SetTargetProperty(rightSlideOut, "(UIElement.RenderTransform).(TranslateTransform.X)");

			Storyboard.SetTarget(textFadeIn, _statusText);
			Storyboard.SetTargetProperty(textFadeIn, "Opacity");

			_hoverInStoryboard.Children.Add(leftSlideOut);
			_hoverInStoryboard.Children.Add(rightSlideOut);
			_hoverInStoryboard.Children.Add(textFadeIn);

			_hoverOutStoryboard = new Storyboard();

			// Left panel slides back
			DoubleAnimation leftSlideBack = new()
			{
				Duration = new Duration(AnimationDuration),
				From = -SlideDistance,
				To = 0,
				EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
			};

			// Right panel slides back
			DoubleAnimation rightSlideBack = new()
			{
				Duration = new Duration(AnimationDuration),
				From = SlideDistance,
				To = 0,
				EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
			};

			// Text fades out
			DoubleAnimation textFadeOut = new()
			{
				Duration = new Duration(AnimationDuration),
				From = 1,
				To = 0,
				EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
			};

			Storyboard.SetTarget(leftSlideBack, _leftPanel);
			Storyboard.SetTargetProperty(leftSlideBack, "(UIElement.RenderTransform).(TranslateTransform.X)");

			Storyboard.SetTarget(rightSlideBack, _rightPanel);
			Storyboard.SetTargetProperty(rightSlideBack, "(UIElement.RenderTransform).(TranslateTransform.X)");

			Storyboard.SetTarget(textFadeOut, _statusText);
			Storyboard.SetTargetProperty(textFadeOut, "Opacity");

			_hoverOutStoryboard.Children.Add(leftSlideBack);
			_hoverOutStoryboard.Children.Add(rightSlideBack);
			_hoverOutStoryboard.Children.Add(textFadeOut);
		}
		catch (Exception ex)
		{
			Logger.Write($"StatusIndicatorV2 animation creation failed: {ex.Message}");
		}
	}

	private void StatusIndicatorV2_PointerEntered(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;

		try
		{
			_hoverOutStoryboard?.Stop();
			_hoverInStoryboard?.Begin();
		}
		catch (Exception ex)
		{
			Logger.Write($"StatusIndicatorV2 pointer entered failed: {ex.Message}");
		}
	}

	private void StatusIndicatorV2_PointerExited(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;

		try
		{
			_hoverInStoryboard?.Stop();
			_hoverOutStoryboard?.Begin();
		}
		catch (Exception ex)
		{
			Logger.Write($"StatusIndicatorV2 pointer exited failed: {ex.Message}");
		}
	}

	private void StatusIndicatorV2_SizeChanged(object sender, SizeChangedEventArgs e)
	{
		// Each time parent arranges us differently, ensure panels span the available width
		ApplyActualWidthToPanels();
	}

	private void StatusIndicatorV2_Unloaded(object sender, RoutedEventArgs e)
	{
		// Skip disposal if explicit-only flag is set.
		if (DisposeOnlyOnExplicitCall)
		{
			return;
		}
		if (_isDisposed) return;
		PerformCleanup();
	}

	private void PerformCleanup()
	{
		try
		{
			_hoverInStoryboard?.Stop();
			_hoverOutStoryboard?.Stop();

			_hoverInStoryboard?.Children.Clear();
			_hoverOutStoryboard?.Children.Clear();
			_hoverInStoryboard = null;
			_hoverOutStoryboard = null;

			_mainBorder = null;
			_contentGrid = null;
			_leftPanel = null;
			_rightPanel = null;
			_statusText = null;
			_currentBrush = null;
			_textBrush = null;

			Loaded -= StatusIndicatorV2_Loaded;
			Unloaded -= StatusIndicatorV2_Unloaded;
			PointerEntered -= StatusIndicatorV2_PointerEntered;
			PointerExited -= StatusIndicatorV2_PointerExited;
			SizeChanged -= StatusIndicatorV2_SizeChanged;

			_isDisposed = true;
		}
		catch (Exception ex)
		{
			Logger.Write($"StatusIndicatorV2 cleanup failed: {ex.Message}");
		}
	}

	public void Dispose()
	{
		if (_isDisposed) return;
		PerformCleanup();
	}
}
