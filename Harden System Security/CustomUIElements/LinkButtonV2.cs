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
using System.Threading.Tasks;
using AppControlManager.Others;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.System;
using Windows.UI;

#pragma warning disable CA1812

namespace AppControlManager.CustomUIElements;

/// <summary>
/// A custom UserControl with circular border, animation on hover, acts as a HyperLinkButton.
/// </summary>
internal sealed partial class LinkButtonV2 : UserControl, IDisposable
{
	private const string LinkIconGlyph = "\uE71B";
	private new const double BorderThickness = 2.0;
	private const double IconSize = 14.0;
	private const double ButtonSize = 32.0;
	private new const double CornerRadius = 16.0;
	private static readonly TimeSpan AnimationDuration = TimeSpan.FromMilliseconds(1000);

	private static readonly Color GradientColor1 = Color.FromArgb(255, 238, 156, 167);
	private static readonly Color GradientColor2 = Color.FromArgb(255, 255, 221, 225);
	private static readonly Color GrayColor = Color.FromArgb(255, 128, 128, 128);

	private Border? _borderElement;
	private FontIcon? _linkIcon;
	private Storyboard? _hoverInStoryboard;
	private Storyboard? _hoverOutStoryboard;
	private LinearGradientBrush? _gradientBrush;
	private SolidColorBrush? _grayBrush;
	private SolidColorBrush? _hotPinkBrush;
	private bool _isDisposed;
	private bool _isPointerOver;

	internal static readonly DependencyProperty LinkUrlProperty =
		DependencyProperty.Register(
			nameof(LinkUrl),
			typeof(string),
			typeof(LinkButtonV2),
			new PropertyMetadata(string.Empty, OnLinkUrlChanged));

	internal string LinkUrl
	{
		get => (string)GetValue(LinkUrlProperty);
		set => SetValue(LinkUrlProperty, value);
	}

	internal event RoutedEventHandler? Click;

	internal LinkButtonV2()
	{
		Width = ButtonSize;
		Height = ButtonSize;
		HorizontalAlignment = HorizontalAlignment.Center;
		VerticalAlignment = VerticalAlignment.Center;
		Background = new SolidColorBrush(Colors.Transparent);
		IsTabStop = true;

		CreateBrushes();
		CreateVisualStructure();
		UpdateEnabledState();

		Loaded += LinkButtonV2_Loaded;
		Unloaded += LinkButtonV2_Unloaded;
		PointerEntered += LinkButtonV2_PointerEntered;
		PointerExited += LinkButtonV2_PointerExited;
		PointerPressed += LinkButtonV2_PointerPressed;
		PointerReleased += LinkButtonV2_PointerReleased;
		PointerCanceled += LinkButtonV2_PointerCanceled;
		PointerCaptureLost += LinkButtonV2_PointerCaptureLost;
		Tapped += LinkButtonV2_Tapped;
	}

	private static void OnLinkUrlChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is LinkButtonV2 linkButton)
		{
			linkButton.UpdateEnabledState();
			linkButton.UpdateTooltipAndHelpText();
		}
	}

	private void UpdateEnabledState()
	{
		IsEnabled = !string.IsNullOrWhiteSpace(LinkUrl);
	}

	private void UpdateTooltipAndHelpText()
	{
		if (string.IsNullOrWhiteSpace(LinkUrl))
		{
			ToolTipService.SetToolTip(this, null);
			AutomationProperties.SetHelpText(this, string.Empty);
		}
		else
		{
			string tmp = string.Format(GlobalVars.GetStr("OpenTheFollowingLinkInBrowser"), LinkUrl);
			string tooltipText = tmp;
			string helpText = tmp;
			ToolTipService.SetToolTip(this, tooltipText);
			AutomationProperties.SetHelpText(this, helpText);
		}
	}

	private void CreateBrushes()
	{
		try
		{
			_gradientBrush = new LinearGradientBrush
			{
				StartPoint = new Windows.Foundation.Point(0, 0),
				EndPoint = new Windows.Foundation.Point(1, 1),
				GradientStops =
				{
					new GradientStop { Color = GradientColor1, Offset = 0.0 },
					new GradientStop { Color = GradientColor2, Offset = 1.0 }
				}
			};

			_grayBrush = new SolidColorBrush(GrayColor);
			_hotPinkBrush = new SolidColorBrush(Colors.HotPink);
		}
		catch (Exception ex)
		{
			Logger.Write($"LinkButtonV2 brush creation failed: {ex.Message}");
		}
	}

	private void CreateVisualStructure()
	{
		try
		{
			_borderElement = new Border
			{
				Width = ButtonSize - 4,
				Height = ButtonSize - 4,
				CornerRadius = new CornerRadius(CornerRadius - 2),
				BorderBrush = _grayBrush,
				Background = new SolidColorBrush(Colors.Transparent),
				HorizontalAlignment = HorizontalAlignment.Center,
				VerticalAlignment = VerticalAlignment.Center,
				RenderTransform = new CompositeTransform(),
				RenderTransformOrigin = new Windows.Foundation.Point(0.5, 0.5)
			};

			_borderElement.SetValue(Border.BorderThicknessProperty, new Thickness(BorderThickness));

			_linkIcon = new FontIcon
			{
				Glyph = LinkIconGlyph,
				FontSize = IconSize,
				Foreground = new SolidColorBrush(Colors.Gray),
				HorizontalAlignment = HorizontalAlignment.Center,
				VerticalAlignment = VerticalAlignment.Center,
				IsHitTestVisible = false
			};

			_borderElement.Child = _linkIcon;
			Content = _borderElement;
		}
		catch (Exception ex)
		{
			Logger.Write($"LinkButtonV2 visual structure creation failed: {ex.Message}");
		}
	}

	private void LinkButtonV2_Loaded(object sender, RoutedEventArgs e)
	{
		if (_isDisposed) return;

		try
		{
			CreateAnimations();
			UpdateTooltipAndHelpText();
		}
		catch (Exception ex)
		{
			Logger.Write($"LinkButtonV2 loading failed: {ex.Message}");
		}
	}

	private void CreateAnimations()
	{
		if (_isDisposed || _borderElement == null) return;

		try
		{
			_hoverInStoryboard = new Storyboard();

			// Pulsating animation for both X and Y axis
			DoubleAnimationUsingKeyFrames scaleXAnimation = new()
			{
				Duration = new Duration(AnimationDuration),
				RepeatBehavior = RepeatBehavior.Forever
			};

			DoubleAnimationUsingKeyFrames scaleYAnimation = new()
			{
				Duration = new Duration(AnimationDuration),
				RepeatBehavior = RepeatBehavior.Forever
			};

			// Heartbeat pattern: normal -> bigger -> normal -> slightly bigger -> normal
			scaleXAnimation.KeyFrames.Add(new EasingDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(0), Value = 1.0, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut } });
			scaleXAnimation.KeyFrames.Add(new EasingDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(200), Value = 1.15, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut } });
			scaleXAnimation.KeyFrames.Add(new EasingDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(400), Value = 1.0, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut } });
			scaleXAnimation.KeyFrames.Add(new EasingDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(600), Value = 1.08, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut } });
			scaleXAnimation.KeyFrames.Add(new EasingDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(800), Value = 1.0, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut } });
			scaleXAnimation.KeyFrames.Add(new EasingDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(1000), Value = 1.0, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut } });

			scaleYAnimation.KeyFrames.Add(new EasingDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(0), Value = 1.0, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut } });
			scaleYAnimation.KeyFrames.Add(new EasingDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(200), Value = 1.15, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut } });
			scaleYAnimation.KeyFrames.Add(new EasingDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(400), Value = 1.0, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut } });
			scaleYAnimation.KeyFrames.Add(new EasingDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(600), Value = 1.08, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut } });
			scaleYAnimation.KeyFrames.Add(new EasingDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(800), Value = 1.0, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut } });
			scaleYAnimation.KeyFrames.Add(new EasingDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(1000), Value = 1.0, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut } });

			Storyboard.SetTarget(scaleXAnimation, _borderElement);
			Storyboard.SetTargetProperty(scaleXAnimation, "(UIElement.RenderTransform).(CompositeTransform.ScaleX)");

			Storyboard.SetTarget(scaleYAnimation, _borderElement);
			Storyboard.SetTargetProperty(scaleYAnimation, "(UIElement.RenderTransform).(CompositeTransform.ScaleY)");

			_hoverInStoryboard.Children.Add(scaleXAnimation);
			_hoverInStoryboard.Children.Add(scaleYAnimation);

			_hoverOutStoryboard = new Storyboard();

			DoubleAnimation scaleOutX = new()
			{
				Duration = new Duration(TimeSpan.FromMilliseconds(300)),
				From = 1.0,
				To = 1.0,
				EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
			};

			DoubleAnimation scaleOutY = new()
			{
				Duration = new Duration(TimeSpan.FromMilliseconds(300)),
				From = 1.0,
				To = 1.0,
				EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
			};

			Storyboard.SetTarget(scaleOutX, _borderElement);
			Storyboard.SetTargetProperty(scaleOutX, "(UIElement.RenderTransform).(CompositeTransform.ScaleX)");

			Storyboard.SetTarget(scaleOutY, _borderElement);
			Storyboard.SetTargetProperty(scaleOutY, "(UIElement.RenderTransform).(CompositeTransform.ScaleY)");

			_hoverOutStoryboard.Children.Add(scaleOutX);
			_hoverOutStoryboard.Children.Add(scaleOutY);
		}
		catch (Exception ex)
		{
			Logger.Write($"LinkButtonV2 animation creation failed: {ex.Message}");
		}
	}

	private void LinkButtonV2_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;

		try
		{
			_isPointerOver = true;
			_hoverOutStoryboard?.Stop();

			_ = (_borderElement?.BorderBrush = _gradientBrush);

			_ = (_linkIcon?.Foreground = _hotPinkBrush);

			_hoverInStoryboard?.Begin();
		}
		catch (Exception ex)
		{
			Logger.Write($"LinkButtonV2 pointer entered failed: {ex.Message}");
		}
	}

	private void LinkButtonV2_PointerExited(object sender, PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;

		try
		{
			_isPointerOver = false;
			_hoverInStoryboard?.Stop();

			// Revert to gray brush
			if (_borderElement != null)
			{
				_borderElement.BorderBrush = _grayBrush;
				_borderElement.Opacity = 1.0;
			}

			// Revert icon color
			_ = (_linkIcon?.Foreground = new SolidColorBrush(Colors.Gray));

			_hoverOutStoryboard?.Begin();
		}
		catch (Exception ex)
		{
			Logger.Write($"LinkButtonV2 pointer exited failed: {ex.Message}");
		}
	}

	private void LinkButtonV2_PointerPressed(object sender, PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;

		try
		{
			_ = (_borderElement?.Opacity = 0.7);
		}
		catch (Exception ex)
		{
			Logger.Write($"LinkButtonV2 pointer pressed failed: {ex.Message}");
		}
	}

	private void LinkButtonV2_PointerReleased(object sender, PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;

		try
		{
			_ = (_borderElement?.Opacity = 1.0);

			// Reset to normal state if pointer is no longer over
			if (!_isPointerOver)
			{
				ResetToNormalState();
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"LinkButtonV2 pointer released failed: {ex.Message}");
		}
	}

	private void LinkButtonV2_PointerCanceled(object sender, PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;
		ResetToNormalState();
	}

	private void LinkButtonV2_PointerCaptureLost(object sender, PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;
		ResetToNormalState();
	}

	private void ResetToNormalState()
	{
		try
		{
			_isPointerOver = false;
			_hoverInStoryboard?.Stop();

			if (_borderElement != null)
			{
				_borderElement.BorderBrush = _grayBrush;
				_borderElement.Opacity = 1.0;
			}

			_ = (_linkIcon?.Foreground = new SolidColorBrush(Colors.Gray));

			_hoverOutStoryboard?.Begin();
		}
		catch (Exception ex)
		{
			Logger.Write($"LinkButtonV2 reset to normal state failed: {ex.Message}");
		}
	}

	private async void LinkButtonV2_Tapped(object sender, TappedRoutedEventArgs e)
	{
		if (_isDisposed) return;

		try
		{
			Click?.Invoke(this, new RoutedEventArgs());

			if (!string.IsNullOrWhiteSpace(LinkUrl))
			{
				await OpenUrlInDefaultBrowser(LinkUrl);
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"LinkButtonV2 tapped failed: {ex.Message}");
		}
	}

	private static async Task OpenUrlInDefaultBrowser(string url)
	{
		try
		{
			if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri))
			{
				Logger.Write($"LinkButtonV2: Invalid URL format: {url}");
				return;
			}

			bool success = await Launcher.LaunchUriAsync(uri);
			if (!success)
			{
				Logger.Write($"LinkButtonV2: Failed to open URL: {url}");
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"LinkButtonV2: Error opening URL {url}: {ex.Message}");
		}
	}

	private void LinkButtonV2_Unloaded(object sender, RoutedEventArgs e)
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

			_borderElement = null;
			_linkIcon = null;
			_gradientBrush = null;
			_grayBrush = null;
			_hotPinkBrush = null;

			Loaded -= LinkButtonV2_Loaded;
			Unloaded -= LinkButtonV2_Unloaded;
			PointerEntered -= LinkButtonV2_PointerEntered;
			PointerExited -= LinkButtonV2_PointerExited;
			PointerPressed -= LinkButtonV2_PointerPressed;
			PointerReleased -= LinkButtonV2_PointerReleased;
			PointerCanceled -= LinkButtonV2_PointerCanceled;
			PointerCaptureLost -= LinkButtonV2_PointerCaptureLost;
			Tapped -= LinkButtonV2_Tapped;

			_isDisposed = true;
		}
		catch (Exception ex)
		{
			Logger.Write($"LinkButtonV2 cleanup failed: {ex.Message}");
		}
	}

	public void Dispose()
	{
		if (_isDisposed) return;
		PerformCleanup();
	}
}
