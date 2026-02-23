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
using System.Numerics;
using CommonCore.GroupPolicy;
using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Shapes;
using Microsoft.UI.Xaml.Media.Imaging;

namespace AppControlManager.CustomUIElements;

internal sealed partial class IntentCircles : UserControl, IDisposable, IExplicitDisposalOptIn
{
	/// <summary>
	/// Visual sizing.
	/// </summary>
	private const double CircleSize = 20.0;

	/// <summary>
	/// Overlapped/stacked
	/// </summary>
	private const double CollapsedSpacing = 10.0;

	/// <summary>
	/// Fully visible.
	/// </summary>
	private const double ExpandedSpacing = 24.0;

	// Animation durations
	private static readonly TimeSpan ExpandDuration = TimeSpan.FromMilliseconds(220);
	private static readonly TimeSpan CollapseDuration = TimeSpan.FromMilliseconds(200);
	private static readonly TimeSpan ScaleDuration = TimeSpan.FromMilliseconds(170);

	// Cached easing function (CompositionObject implements IDisposable) and owning compositor
	private CubicBezierEasingFunction? _hoverEase;
	private Compositor? _hoverEaseCompositor;

	/// <summary>
	/// Hover scale
	/// </summary>
	private const float HoverScale = 1.15f;

	private readonly SolidColorBrush _fallbackCircleFill = new(Colors.LightGray);

	// Static image cache to prevent the UI Asynchronous Image Decoder from dropping images during ListView virtualization
	// Also improves the overall performance since it's static and all pages use the same cache instead of recreating the images.
	private static readonly BitmapImage[] ImageCache = [
		new(new("ms-appx:///Assets/DeviceIntents/Development.png")), // 0
		new(new("ms-appx:///Assets/DeviceIntents/Gaming.png")), // 1
		new(new("ms-appx:///Assets/DeviceIntents/School.png")), // 2
		new(new("ms-appx:///Assets/DeviceIntents/Business.png")), // 3
		new(new("ms-appx:///Assets/DeviceIntents/Specialized.png")), // 4
		new(new("ms-appx:///Assets/DeviceIntents/Privileged.png")) // 5
	];

	private static readonly string[] TitleCache = [
		GlobalVars.GetStr("DeviceUsageIntent-Development-Title"), // 0
		GlobalVars.GetStr("DeviceUsageIntent-Gaming-Title"), // 1
		GlobalVars.GetStr("DeviceUsageIntent-School-Title"), // 2
		GlobalVars.GetStr("DeviceUsageIntent-Business-Title"), // 3
		GlobalVars.GetStr("DeviceUsageIntent-SpecializedAccessWorkstation-Title"), // 4
		GlobalVars.GetStr("DeviceUsageIntent-PrivilegedAccessWorkstation-Title") // 5
		];

	// State for layout animation
	private readonly List<FrameworkElement> _circleElements = [];
	private bool _isDisposed;
	private double _currentSpacing = CollapsedSpacing;
	private int _itemCount;

	// State for composition scaling animation per element
	private readonly Dictionary<FrameworkElement, Visual> _elementVisuals = [];
	private readonly HashSet<FrameworkElement> _pointerOverElements = [];

	/// <summary>
	/// Explicit disposal opt-in DP
	/// </summary>
	internal static readonly DependencyProperty DisposeOnlyOnExplicitCallProperty =
		DependencyProperty.Register(
			nameof(DisposeOnlyOnExplicitCall),
			typeof(bool),
			typeof(IntentCircles),
			new PropertyMetadata(false));

	/// <summary>
	/// When true, skips disposal on Unloaded (parent will dispose explicitly).
	/// </summary>
	public bool DisposeOnlyOnExplicitCall
	{
		get => (bool)GetValue(DisposeOnlyOnExplicitCallProperty);
		set => SetValue(DisposeOnlyOnExplicitCallProperty, value);
	}

	/// <summary>
	/// ItemsSource DP (public so XAML can bind)
	/// </summary>
	public static readonly DependencyProperty ItemsSourceProperty =
		DependencyProperty.Register(
			nameof(ItemsSource),
			typeof(IEnumerable<Intent>),
			typeof(IntentCircles),
			new PropertyMetadata(null, OnItemsSourceChanged));

	/// <summary>
	/// The intents to visualize for this MUnit.
	/// </summary>
	public IEnumerable<Intent>? ItemsSource
	{
		get => (IEnumerable<Intent>?)GetValue(ItemsSourceProperty);
		set => SetValue(ItemsSourceProperty, value);
	}

	internal IntentCircles()
	{
		InitializeComponent();

		HorizontalAlignment = HorizontalAlignment.Left;
		VerticalAlignment = VerticalAlignment.Center;

		Loaded += IntentCircles_Loaded;
		Unloaded += IntentCircles_Unloaded;
		PointerEntered += IntentCircles_PointerEntered;
		PointerExited += IntentCircles_PointerExited;
	}

	private static void OnItemsSourceChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is IntentCircles control && !control._isDisposed)
		{
			control.RebuildCircles();
		}
	}

	private void IntentCircles_Loaded(object sender, RoutedEventArgs e)
	{
		if (_isDisposed) return;
		RebuildCircles();
	}

	private void IntentCircles_Unloaded(object sender, RoutedEventArgs e)
	{
		// Skip disposal if explicit-only flag is set.
		if (DisposeOnlyOnExplicitCall) return;
		if (_isDisposed) return;
		PerformCleanup();
	}

	/// <summary>
	/// Control-level hover (keeps stacked -> expanded spacing)
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void IntentCircles_PointerEntered(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;
		AnimateSpacing(toExpanded: true);
	}

	private void IntentCircles_PointerExited(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;
		AnimateSpacing(toExpanded: false);
	}

	/// <summary>
	/// Build visuals
	/// </summary>
	private void RebuildCircles()
	{
		try
		{
			if (_isDisposed || PART_Canvas == null)
			{
				return;
			}

			// Clear old visuals and state
			foreach (FrameworkElement elem in _circleElements)
			{
				DetachPerItemHandlers(elem);
			}
			PART_Canvas.Children.Clear();
			_circleElements.Clear();
			_elementVisuals.Clear();
			_pointerOverElements.Clear();

			List<Intent> intentsToShow = ComputeIntentsToShow(ItemsSource);

			_itemCount = intentsToShow.Count;

			Visibility = _itemCount == 0 ? Visibility.Collapsed : Visibility.Visible;

			double expandedWidth = ComputeTotalWidth(ExpandedSpacing, _itemCount);
			double collapsedWidth = ComputeTotalWidth(CollapsedSpacing, _itemCount);

			PART_Canvas.Width = expandedWidth;
			PART_Canvas.Height = CircleSize;

			_currentSpacing = CollapsedSpacing;

			for (int i = 0; i < intentsToShow.Count; i++)
			{
				FrameworkElement circle = CreateCircleForIntent(intentsToShow[i]);

				// Position on canvas (stacked spacing by default)
				Canvas.SetLeft(circle, i * _currentSpacing);
				Canvas.SetTop(circle, 0);

				PART_Canvas.Children.Add(circle);
				_circleElements.Add(circle);
				Canvas.SetZIndex(circle, i);

				// Prepare composition scaling animation for this element
				PrepareElementComposition(circle);
				AttachPerItemHandlers(circle);
			}

			MinWidth = collapsedWidth;
		}
		catch (Exception ex)
		{
			Logger.Write($"IntentCircles rebuild failed: {ex.Message}");
		}
	}

	private static List<Intent> ComputeIntentsToShow(IEnumerable<Intent>? source)
	{
		if (source == null)
		{
			return [];
		}

		HashSet<Intent> set = [.. source];

		if (set.Count == 0)
		{
			return [];
		}

		// All => show all 6
		if (set.Contains(Intent.All))
		{
			return new List<Intent>
			{
				Intent.Development,
				Intent.Gaming,
				Intent.School,
				Intent.Business,
				Intent.SpecializedAccessWorkstation,
				Intent.PrivilegedAccessWorkstation
			};
		}

		// Stable order regardless of input order
		Intent[] order =
		[
			Intent.Development,
			Intent.Gaming,
			Intent.School,
			Intent.Business,
			Intent.SpecializedAccessWorkstation,
			Intent.PrivilegedAccessWorkstation
		];

		List<Intent> result = new(capacity: set.Count);
		for (int i = 0; i < order.Length; i++)
		{
			if (set.Contains(order[i]))
			{
				result.Add(order[i]);
			}
		}
		return result;
	}

	/// <summary>
	/// Returns a cached easing function for the specified compositor; disposes/recreates if compositor changed.
	/// </summary>
	/// <param name="compositor"></param>
	/// <returns></returns>
	private CubicBezierEasingFunction GetOrCreateHoverEase(Compositor compositor)
	{
		// If not created yet, or compositor changed (e.g., control recreated), (re)create the easing.
		if (_hoverEase is null || !ReferenceEquals(_hoverEaseCompositor, compositor))
		{
			// Dispose previous instance to free composition resource
			if (_hoverEase is not null)
			{
				try { _hoverEase.Dispose(); } catch { }
			}

			_hoverEase = CreateEase(compositor);
			_hoverEaseCompositor = compositor;
		}

		return _hoverEase;
	}


	/// <summary>
	/// Creates a circular icon using an Ellipse filled with an ImageBrush (no halo).
	/// Adds a tooltip and accessibility HelpText/Name.
	/// </summary>
	private Ellipse CreateCircleForIntent(Intent intent)
	{
		Brush fillBrush;

		try
		{
			ImageBrush imageBrush = new()
			{
				ImageSource = ImageCache[(int)intent],
				Stretch = Stretch.UniformToFill,
				AlignmentX = AlignmentX.Center,
				AlignmentY = AlignmentY.Center
			};
			fillBrush = imageBrush;
		}
		catch
		{
			fillBrush = _fallbackCircleFill;
		}

		Ellipse ellipse = new()
		{
			Width = CircleSize,
			Height = CircleSize,
			StrokeThickness = 0,
			Fill = fillBrush
		};

		// Accessibility + tooltip content
		string title = TitleCache[(int)intent];

		// Name is what screen readers announce as the control name.
		AutomationProperties.SetName(ellipse, title);

		// HelpText provides additional context to assistive tech.
		AutomationProperties.SetHelpText(ellipse, title);

		// Tooltip
		ToolTipService.SetToolTip(ellipse, title);

		return ellipse;
	}

	// Per-item hover/touch scaling (Composition)

	private void PrepareElementComposition(FrameworkElement element)
	{
		try
		{
			Visual visual = ElementCompositionPreview.GetElementVisual(element);
			visual.CenterPoint = new Vector3((float)CircleSize / 2.0f, (float)CircleSize / 2.0f, 0.0f);
			visual.Scale = new Vector3(1.0f, 1.0f, 1.0f);

			if (!_elementVisuals.TryAdd(element, visual))
			{
				_elementVisuals[element] = visual;
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"IntentCircles composition prepare failed: {ex.Message}");
		}
	}

	private void AttachPerItemHandlers(FrameworkElement element)
	{
		element.PointerEntered += Item_PointerEntered;
		element.PointerExited += Item_PointerExited;
		element.PointerPressed += Item_PointerPressed;
		element.PointerReleased += Item_PointerReleased;
		element.PointerCanceled += Item_PointerCanceled;
		element.PointerCaptureLost += Item_PointerCaptureLost;
	}

	private void DetachPerItemHandlers(FrameworkElement element)
	{
		element.PointerEntered -= Item_PointerEntered;
		element.PointerExited -= Item_PointerExited;
		element.PointerPressed -= Item_PointerPressed;
		element.PointerReleased -= Item_PointerReleased;
		element.PointerCanceled -= Item_PointerCanceled;
		element.PointerCaptureLost -= Item_PointerCaptureLost;
	}

	private void Item_PointerEntered(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;
		if (sender is FrameworkElement fe && _elementVisuals.TryGetValue(fe, out Visual? visual))
		{
			_ = _pointerOverElements.Add(fe);
			StartScaleAnimation(visual, HoverScale);
		}
	}

	private void Item_PointerExited(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;
		if (sender is FrameworkElement fe && _elementVisuals.TryGetValue(fe, out Visual? visual))
		{
			_ = _pointerOverElements.Remove(fe);
			StartScaleAnimation(visual, 1.0f);
		}
	}

	private void Item_PointerPressed(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;
		if (sender is FrameworkElement fe && _elementVisuals.TryGetValue(fe, out Visual? visual))
		{
			// Ensure it scales up on touch as well
			_ = _pointerOverElements.Add(fe);
			StartScaleAnimation(visual, HoverScale);
		}
	}

	private void Item_PointerReleased(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;
		if (sender is FrameworkElement fe && _elementVisuals.TryGetValue(fe, out Visual? visual))
		{
			// If still hovering, keep hover scale; otherwise revert
			float target = _pointerOverElements.Contains(fe) ? HoverScale : 1.0f;
			StartScaleAnimation(visual, target);
		}
	}

	private void Item_PointerCanceled(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;
		if (sender is FrameworkElement fe && _elementVisuals.TryGetValue(fe, out Visual? visual))
		{
			_ = _pointerOverElements.Remove(fe);
			StartScaleAnimation(visual, 1.0f);
		}
	}

	private void Item_PointerCaptureLost(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
	{
		if (_isDisposed) return;
		if (sender is FrameworkElement fe && _elementVisuals.TryGetValue(fe, out Visual? visual))
		{
			_ = _pointerOverElements.Remove(fe);
			StartScaleAnimation(visual, 1.0f);
		}
	}

	private static CubicBezierEasingFunction CreateEase(Compositor compositor)
	{
		// Slight ease for a pleasant pop effect
		return compositor.CreateCubicBezierEasingFunction(new Vector2(0.2f, 0.0f), new Vector2(0.2f, 1.0f));
	}

	private void StartScaleAnimation(Visual visual, float targetScale)
	{
		try
		{
			Compositor compositor = visual.Compositor;

			Vector3KeyFrameAnimation anim = compositor.CreateVector3KeyFrameAnimation();
			anim.Duration = ScaleDuration;
			anim.InsertKeyFrame(1.0f, new Vector3(targetScale, targetScale, 1.0f), GetOrCreateHoverEase(compositor));
			visual.StartAnimation("Scale", anim);
		}
		catch (Exception ex)
		{
			Logger.Write($"IntentCircles scale animation failed: {ex.Message}");
		}
	}

	/// <summary>
	/// Spacing animation
	/// </summary>
	/// <param name="toExpanded"></param>
	private void AnimateSpacing(bool toExpanded)
	{
		if (_isDisposed) return;
		if (_itemCount <= 1) return;

		double targetSpacing = toExpanded ? ExpandedSpacing : CollapsedSpacing;
		if (Math.Abs(targetSpacing - _currentSpacing) < 0.1)
		{
			return;
		}

		try
		{
			for (int i = 0; i < _circleElements.Count; i++)
			{
				FrameworkElement element = _circleElements[i];
				double to = i * targetSpacing;

				DoubleAnimation da = new()
				{
					Duration = new Duration(toExpanded ? ExpandDuration : CollapseDuration),
					To = to,
					EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
				};

				Storyboard sb = new();
				Storyboard.SetTarget(da, element);
				Storyboard.SetTargetProperty(da, "(Canvas.Left)");
				sb.Children.Add(da);
				sb.Begin();
			}

			_currentSpacing = targetSpacing;
		}
		catch (Exception ex)
		{
			Logger.Write($"IntentCircles spacing animation failed: {ex.Message}");
		}
	}

	private static double ComputeTotalWidth(double spacing, int count)
	{
		if (count <= 0) return 0.0;
		double lastLeft = (count - 1) * spacing;
		return lastLeft + CircleSize;
	}

	/// <summary>
	/// Cleanup
	/// </summary>
	private void PerformCleanup()
	{
		try
		{
			Loaded -= IntentCircles_Loaded;
			Unloaded -= IntentCircles_Unloaded;
			PointerEntered -= IntentCircles_PointerEntered;
			PointerExited -= IntentCircles_PointerExited;

			foreach (FrameworkElement elem in _circleElements)
			{
				DetachPerItemHandlers(elem);
			}

			PART_Canvas?.Children.Clear();

			_circleElements.Clear();
			_elementVisuals.Clear();
			_pointerOverElements.Clear();

			// Dispose cached easing function (CompositionObject) to release compositor resource
			if (_hoverEase is not null)
			{
				try { _hoverEase.Dispose(); } catch { }
				_hoverEase = null;
				_hoverEaseCompositor = null;
			}

			_isDisposed = true;
		}
		catch (Exception ex)
		{
			Logger.Write($"IntentCircles cleanup failed: {ex.Message}");
		}
	}

	public void Dispose()
	{
		if (_isDisposed) return;
		PerformCleanup();
	}
}
