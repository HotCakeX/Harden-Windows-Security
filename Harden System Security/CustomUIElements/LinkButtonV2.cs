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

using System.Threading.Tasks;
using AppControlManager.Pages;
using HardenSystemSecurity;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.System;
using Windows.UI;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// A custom UserControl with circular border, animation on hover, acts as a HyperLinkButton.
/// </summary>
internal sealed partial class LinkButtonV2 : UserControl, IDisposable, IExplicitDisposalOptIn
{
	private const string LinkIconGlyph = "\uE71B";
	private new const double BorderThickness = 2.0;
	private const double IconSize = 14.0;
	private const double ButtonSize = 32.0;
	private new const double CornerRadius = 16.0;
	private static readonly TimeSpan AnimationDuration = TimeSpan.FromMilliseconds(1000);
	private static readonly TimeSpan HoverDelay = TimeSpan.FromMilliseconds(500);

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
	private Flyout? _previewFlyout;
	private DispatcherTimer? _hoverTimer;
	private Frame? _currentPreviewFrame; // Track current frame for proper disposal
	private bool _isDisposed;
	private bool _isPointerOver;
	private bool _isFlyoutOpen;

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

	// Explicit disposal opt-in DP
	internal static readonly DependencyProperty DisposeOnlyOnExplicitCallProperty =
		DependencyProperty.Register(
			nameof(DisposeOnlyOnExplicitCall),
			typeof(bool),
			typeof(LinkButtonV2),
			new PropertyMetadata(false));

	/// <summary>
	/// When true, skips disposal on Unloaded (parent will dispose explicitly).
	/// </summary>
	public bool DisposeOnlyOnExplicitCall
	{
		get => (bool)GetValue(DisposeOnlyOnExplicitCallProperty);
		set => SetValue(DisposeOnlyOnExplicitCallProperty, value);
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
		CreateFlyout();
		CreateHoverTimer();
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

	/// <summary>
	/// Creates the flyout for link preview functionality only if enabled in settings
	/// </summary>
	private void CreateFlyout()
	{
		// Only create flyout if link previews are enabled in settings
		if (!App.Settings.LinkPreviewsForSecurityMeasure)
		{
			return;
		}

		_previewFlyout = new Flyout
		{
			Placement = FlyoutPlacementMode.Bottom,
			ShouldConstrainToRootBounds = false,
			AreOpenCloseAnimationsEnabled = false,

			// Adjusts the flyout's default padding and margin
			FlyoutPresenterStyle = new Style(typeof(FlyoutPresenter))
			{
				Setters =   {
								new Setter(MarginProperty, new Thickness(0)),
								new Setter(PaddingProperty, new Thickness(4)),
								new Setter(CornerRadiusProperty, new CornerRadius(15))
							}
			}
		};

		_previewFlyout.Opened += PreviewFlyout_Opened;
		_previewFlyout.Closed += PreviewFlyout_Closed;
	}

	/// <summary>
	/// Creates the hover timer for delayed flyout display
	/// </summary>
	private void CreateHoverTimer()
	{
		_hoverTimer = new DispatcherTimer
		{
			Interval = HoverDelay
		};
		_hoverTimer.Tick += HoverTimer_Tick;
	}

	/// <summary>
	/// Handles hover timer tick to show flyout after delay
	/// </summary>
	private void HoverTimer_Tick(object? sender, object e)
	{
		if (_isDisposed) return;

		_hoverTimer?.Stop();

		if (_isPointerOver && !_isFlyoutOpen && !string.IsNullOrWhiteSpace(LinkUrl))
		{
			ShowPreviewFlyout();
		}
	}

	/// <summary>
	/// Shows the preview flyout in a frame only if enabled in settings
	/// </summary>
	private void ShowPreviewFlyout()
	{
		// Check if link previews are enabled in settings before showing flyout
		if (_isDisposed || _previewFlyout == null || !App.Settings.LinkPreviewsForSecurityMeasure)
			return;

		try
		{
			// Clean up any existing frame first
			CleanupCurrentFrame();

			_currentPreviewFrame = new Frame
			{
				Width = 400,
				Height = 300,
				HorizontalAlignment = HorizontalAlignment.Stretch,
				VerticalAlignment = VerticalAlignment.Stretch
			};

			// Navigate to LinkPreview page
			bool navigationSucceeded = _currentPreviewFrame.Navigate(typeof(LinkPreview));

			if (!navigationSucceeded)
			{
				// Clean up frame if navigation failed
				CleanupCurrentFrame();
				return;
			}

			// Set the URL on the preview page
			if (_currentPreviewFrame.Content is LinkPreview previewPage)
			{
				previewPage.PreviewUrl = LinkUrl;
				_previewFlyout.Content = _currentPreviewFrame;
				_previewFlyout.ShowAt(this);
			}
			else
			{
				// Clean up frame if we couldn't get the preview page
				CleanupCurrentFrame();
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"LinkButtonV2 show preview flyout failed: {ex.Message}");
			_isFlyoutOpen = false;
			// Clean up frame on error
			CleanupCurrentFrame();
		}
	}

	/// <summary>
	/// Properly cleans up the current preview frame and its content
	/// </summary>
	private void CleanupCurrentFrame()
	{
		if (_currentPreviewFrame != null)
		{
			// If the frame has content that implements IDisposable, dispose it
			if (_currentPreviewFrame.Content is IDisposable disposableContent)
			{
				try
				{
					disposableContent.Dispose();
				}
				catch (Exception ex)
				{
					Logger.Write($"LinkButtonV2 frame content disposal failed: {ex.Message}");
				}
			}

			// Clear the content and nullify the frame
			_currentPreviewFrame.Content = null;
			_currentPreviewFrame = null;
		}
	}

	/// <summary>
	/// Handles flyout opened event
	/// </summary>
	private void PreviewFlyout_Opened(object? sender, object e)
	{
		_isFlyoutOpen = true;
	}

	/// <summary>
	/// Handles flyout closed event to reset state and clean up resources
	/// </summary>
	private void PreviewFlyout_Closed(object? sender, object e)
	{
		_isFlyoutOpen = false;

		// Clean up the flyout content and current frame
		_ = (_previewFlyout?.Content = null);

		CleanupCurrentFrame();
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

			// Start hover timer for Flyout only if enabled in settings
			if (!string.IsNullOrWhiteSpace(LinkUrl) && !_isFlyoutOpen && App.Settings.LinkPreviewsForSecurityMeasure)
			{
				_hoverTimer?.Start();
			}
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
			_hoverTimer?.Stop();
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
			_hoverTimer?.Stop();
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
			// Stop and dispose timer
			if (_hoverTimer != null)
			{
				_hoverTimer.Stop();
				_hoverTimer.Tick -= HoverTimer_Tick;
				_hoverTimer = null;
			}

			// Stop animations
			_hoverInStoryboard?.Stop();
			_hoverOutStoryboard?.Stop();

			// Clear animation children and dispose
			_hoverInStoryboard?.Children.Clear();
			_hoverOutStoryboard?.Children.Clear();
			_hoverInStoryboard = null;
			_hoverOutStoryboard = null;

			// Clean up flyout and its content
			if (_previewFlyout != null)
			{
				_previewFlyout.Opened -= PreviewFlyout_Opened;
				_previewFlyout.Closed -= PreviewFlyout_Closed;
				_previewFlyout.Content = null;
				_previewFlyout = null;
			}

			// Clean up current frame and its content
			CleanupCurrentFrame();

			// Clear references to UI elements
			_borderElement = null;
			_linkIcon = null;
			_gradientBrush = null;
			_grayBrush = null;
			_hotPinkBrush = null;

			// Unsubscribe from all events
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
