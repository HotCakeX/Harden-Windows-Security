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
using AppControlManager.Others;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.UI;

#pragma warning disable CA1812

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
/// A custom UserControl that shows status with sliding door animation on hover, used by ListViews and MUnit./>
/// </summary>
internal sealed partial class StatusIndicatorV2 : UserControl, IDisposable
{
	private const double IndicatorWidth = 80.0;
	private const double IndicatorHeight = 24.0;
	private new const double CornerRadius = 12.0;
	private const double SlideDistance = 15.0;
	private static readonly TimeSpan AnimationDuration = TimeSpan.FromMilliseconds(300);

	private static readonly Color YellowColor = Color.FromArgb(255, 255, 193, 7);
	private static readonly Color GreenColor = Color.FromArgb(255, 40, 167, 69);
	private static readonly Color RedColor = Color.FromArgb(255, 220, 53, 69);
	private static readonly Color TextColor = Color.FromArgb(255, 33, 37, 41);

	private Border? _mainBorder;
	private Grid? _contentGrid;
	private Border? _leftPanel;
	private Border? _rightPanel;
	private TextBlock? _statusText;
	private Storyboard? _hoverInStoryboard;
	private Storyboard? _hoverOutStoryboard;
	private SolidColorBrush? _currentBrush;
	private SolidColorBrush? _textBrush;
	private bool _isDisposed;

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

	internal StatusIndicatorV2()
	{
		Width = IndicatorWidth;
		Height = IndicatorHeight;
		HorizontalAlignment = HorizontalAlignment.Center;
		VerticalAlignment = VerticalAlignment.Center;
		Background = new SolidColorBrush(Colors.Transparent);
		IsTabStop = true;

		CreateBrushes();
		CreateVisualStructure();
		UpdateStatusAppearance();

		Loaded += StatusIndicatorV2_Loaded;
		Unloaded += StatusIndicatorV2_Unloaded;
		PointerEntered += StatusIndicatorV2_PointerEntered;
		PointerExited += StatusIndicatorV2_PointerExited;
	}

	private static void OnStatusChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is StatusIndicatorV2 indicator)
		{
			indicator.UpdateStatusAppearance();
		}
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
				Width = IndicatorWidth,
				Height = IndicatorHeight,
				HorizontalAlignment = HorizontalAlignment.Center,
				VerticalAlignment = VerticalAlignment.Center
			};

			_mainBorder = new Border
			{
				Width = IndicatorWidth,
				Height = IndicatorHeight,
				CornerRadius = new CornerRadius(CornerRadius),
				HorizontalAlignment = HorizontalAlignment.Stretch,
				VerticalAlignment = VerticalAlignment.Stretch
			};

			_leftPanel = new Border
			{
				Width = IndicatorWidth / 2 + 2,
				Height = IndicatorHeight,
				CornerRadius = new CornerRadius(CornerRadius, 0, 0, CornerRadius),
				HorizontalAlignment = HorizontalAlignment.Left,
				VerticalAlignment = VerticalAlignment.Stretch,
				RenderTransform = new TranslateTransform(),
				RenderTransformOrigin = new Windows.Foundation.Point(0.5, 0.5)
			};

			_rightPanel = new Border
			{
				Width = IndicatorWidth / 2 + 2,
				Height = IndicatorHeight,
				CornerRadius = new CornerRadius(0, CornerRadius, CornerRadius, 0),
				HorizontalAlignment = HorizontalAlignment.Right,
				VerticalAlignment = VerticalAlignment.Stretch,
				RenderTransform = new TranslateTransform(),
				RenderTransformOrigin = new Windows.Foundation.Point(0.5, 0.5)
			};

			_statusText = new TextBlock
			{
				Text = "N/A",
				FontSize = 11,
				FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
				Foreground = _textBrush,
				HorizontalAlignment = HorizontalAlignment.Center,
				VerticalAlignment = VerticalAlignment.Center,
				Opacity = 0,
				IsHitTestVisible = false
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

			_currentBrush = new SolidColorBrush(statusColor);

			_ = _mainBorder?.Background = _currentBrush;
			_ = _leftPanel?.Background = _currentBrush;
			_ = _rightPanel?.Background = _currentBrush;
			_ = _statusText?.Text = statusText;

			UpdateTooltip();
		}
		catch (Exception ex)
		{
			Logger.Write($"StatusIndicatorV2 status appearance update failed: {ex.Message}");
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

	private void StatusIndicatorV2_Loaded(object sender, RoutedEventArgs e)
	{
		if (_isDisposed) return;

		try
		{
			CreateAnimations();
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

	private void StatusIndicatorV2_Unloaded(object sender, RoutedEventArgs e)
	{
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
