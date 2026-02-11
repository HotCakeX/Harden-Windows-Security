// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// Source: https://github.com/CommunityToolkit/Windows/tree/main/components/RadialGauge/src
// License: https://github.com/CommunityToolkit/Windows/blob/main/License.md
// It's been modified to meet the Harden Windows Security repository's requirements.

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

using System.Numerics;
using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;

namespace CommonCore.ToolKits;

internal sealed partial class RadialGauge : UserControl
{
	private const double InternalSize = 200.0;
	private const double CenterPt = 100.0;
	private const double Degrees2Radians = Math.PI / 180.0;
	private const double ArcScaleFactor = 1.7;
	private const double DotScaleFactor = 0.7;

	// Gradient Colors
	private static readonly Color Segment1Color = Color.FromArgb(255, 255, 182, 193); // LightPink
	private static readonly Color Segment2Color = Color.FromArgb(255, 255, 192, 203); // Pink
	private static readonly Color Segment3Color = Color.FromArgb(255, 255, 105, 180); // HotPink
	private static readonly Color Segment4Color = Color.FromArgb(255, 238, 130, 238); // Violet
	private static readonly Color Segment5Color = Color.FromArgb(255, 138, 43, 226);  // BlueViolet

	private readonly Grid _rootGrid;
	private readonly Viewbox _viewbox;

	// Visual Parts
	private readonly Path _scalePath; // The background track
	private readonly Path _segment1Path;
	private readonly Path _segment2Path;
	private readonly Path _segment3Path;
	private readonly Path _segment4Path;
	private readonly Path _segment5Path;
	private readonly Ellipse _indicatorDot;

	// Center Display Parts
	private readonly TextBlock _centerValueText;
	private readonly Rectangle _fillRect;
	private readonly Grid _innerCenterGrid;
	private readonly Border _centerBorder;
	private readonly TextBlock _labelTextBlock;

	// Composition (for Ticks)
	private Compositor? _compositor;
	private ContainerVisual? _ticksContainer;

	// Internal State
	private double _normalizedMinAngle;
	private double _normalizedMaxAngle;
	private double _radius;
	private bool _isDragging;

	internal RadialGauge()
	{
		// Setup Container
		_rootGrid = new()
		{
			Width = InternalSize,
			Height = InternalSize,
			Background = new SolidColorBrush(Colors.Transparent) // Hit target for input
		};

		// Setup Scale Path (Background Track)
		_scalePath = new()
		{
			Stroke = new SolidColorBrush(Color.FromArgb(255, 220, 220, 220)), // Light Gray default
			StrokeStartLineCap = PenLineCap.Round,
			StrokeEndLineCap = PenLineCap.Round,
			StrokeLineJoin = PenLineJoin.Round
		};
		_rootGrid.Children.Add(_scalePath);

		// Setup Colored Segments
		_segment1Path = CreateSegmentPath(Segment1Color, Segment2Color);
		_segment2Path = CreateSegmentPath(Segment2Color, Segment3Color);
		_segment3Path = CreateSegmentPath(Segment3Color, Segment4Color);
		_segment4Path = CreateSegmentPath(Segment4Color, Segment5Color);
		_segment5Path = CreateSegmentPath(Segment5Color, Segment5Color, isSolid: true);

		_rootGrid.Children.Add(_segment1Path);
		_rootGrid.Children.Add(_segment2Path);
		_rootGrid.Children.Add(_segment3Path);
		_rootGrid.Children.Add(_segment4Path);
		_rootGrid.Children.Add(_segment5Path);

		// Setup Indicator Dot
		_indicatorDot = new()
		{
			Fill = new SolidColorBrush(Colors.White),
			IsHitTestVisible = false,
			HorizontalAlignment = HorizontalAlignment.Left,
			VerticalAlignment = VerticalAlignment.Top,
			Visibility = Visibility.Collapsed
		};
		_rootGrid.Children.Add(_indicatorDot);

		// Setup Center Display
		StackPanel centerStack = new()
		{
			Orientation = Orientation.Vertical,
			HorizontalAlignment = HorizontalAlignment.Center,
			VerticalAlignment = VerticalAlignment.Center,
			Spacing = 4
		};

		_centerValueText = new()
		{
			TextAlignment = TextAlignment.Center,
			Foreground = new SolidColorBrush(Colors.Black) // Default, updated by theme
		};

		_fillRect = new()
		{
			Fill = new LinearGradientBrush
			{
				MappingMode = BrushMappingMode.RelativeToBoundingBox,
				StartPoint = new(0, 1),
				EndPoint = new(0, 0),
				GradientStops =
				{
					new GradientStop { Color = Colors.HotPink, Offset = 0.0 },
					new GradientStop { Color = Colors.Pink, Offset = 1.0 }
				}
			},
			HorizontalAlignment = HorizontalAlignment.Stretch,
			VerticalAlignment = VerticalAlignment.Bottom
		};

		_innerCenterGrid = new();
		_innerCenterGrid.Children.Add(_fillRect);
		_innerCenterGrid.Children.Add(_centerValueText);

		// Update clip when size changes
		_innerCenterGrid.SizeChanged += (s, e) =>
		{
			_innerCenterGrid.Clip = new RectangleGeometry { Rect = new(0, 0, e.NewSize.Width, e.NewSize.Height) };
			UpdateFillRect();
		};

		_centerBorder = new()
		{
			BorderThickness = new(2),
			CornerRadius = new(4),
			Padding = new(3),
			Child = _innerCenterGrid
		};

		_labelTextBlock = new()
		{
			Text = "Threads",
			TextAlignment = TextAlignment.Center,
			Margin = new(0, 5, 0, 0),
			Foreground = new SolidColorBrush(Colors.Black) // Default, updated by theme
		};

		centerStack.Children.Add(_centerBorder);
		centerStack.Children.Add(_labelTextBlock);
		_rootGrid.Children.Add(centerStack);

		// Wrap in Viewbox
		_viewbox = new Viewbox { Child = _rootGrid };
		Content = _viewbox;

		// Event Subscriptions
		Loaded += OnLoaded;
		Unloaded += OnUnloaded;
		ActualThemeChanged += OnActualThemeChanged;

		_rootGrid.PointerPressed += OnPointerPressed;
		_rootGrid.PointerMoved += OnPointerMoved;
		_rootGrid.PointerReleased += OnPointerReleased;
		_rootGrid.PointerCanceled += OnPointerReleased;
		_rootGrid.PointerCaptureLost += OnPointerReleased;

		// Initial Draw
		UpdateThemeColors();
		UpdateNormalizedAngles();
		UpdateVisuals(); // Ensure visuals are calculated immediately
	}

	public static readonly DependencyProperty MinimumProperty = DependencyProperty.Register(
		nameof(Minimum), typeof(double), typeof(RadialGauge), new PropertyMetadata(0.0, OnRangeChanged));

	public static readonly DependencyProperty MaximumProperty = DependencyProperty.Register(
		nameof(Maximum), typeof(double), typeof(RadialGauge), new PropertyMetadata(100.0, OnRangeChanged));

	public static readonly DependencyProperty ValueProperty = DependencyProperty.Register(
		nameof(Value), typeof(double), typeof(RadialGauge), new PropertyMetadata(0.0, OnValueChanged));

	public static readonly DependencyProperty StepSizeProperty = DependencyProperty.Register(
		nameof(StepSize), typeof(double), typeof(RadialGauge), new PropertyMetadata(1.0));

	public static readonly DependencyProperty TickSpacingProperty = DependencyProperty.Register(
		nameof(TickSpacing), typeof(int), typeof(RadialGauge), new PropertyMetadata(10, OnAppearanceChanged));

	public static readonly DependencyProperty ScaleWidthProperty = DependencyProperty.Register(
		nameof(ScaleWidth), typeof(double), typeof(RadialGauge), new PropertyMetadata(12.0, OnAppearanceChanged));

	public static readonly DependencyProperty ScalePaddingProperty = DependencyProperty.Register(
		nameof(ScalePadding), typeof(double), typeof(RadialGauge), new PropertyMetadata(10.0, OnAppearanceChanged));

	public static readonly DependencyProperty TickWidthProperty = DependencyProperty.Register(
		nameof(TickWidth), typeof(double), typeof(RadialGauge), new PropertyMetadata(2.0, OnAppearanceChanged));

	public static readonly DependencyProperty TickLengthProperty = DependencyProperty.Register(
		nameof(TickLength), typeof(double), typeof(RadialGauge), new PropertyMetadata(6.0, OnAppearanceChanged));

	public static readonly DependencyProperty TickPaddingProperty = DependencyProperty.Register(
		nameof(TickPadding), typeof(double), typeof(RadialGauge), new PropertyMetadata(20.0, OnAppearanceChanged));

	public static readonly DependencyProperty ValueStringFormatProperty = DependencyProperty.Register(
		nameof(ValueStringFormat), typeof(string), typeof(RadialGauge), new PropertyMetadata("N0", OnValueChanged));

	public static readonly DependencyProperty IsInteractiveProperty = DependencyProperty.Register(
		nameof(IsInteractive), typeof(bool), typeof(RadialGauge), new PropertyMetadata(true));

	public static readonly DependencyProperty UnitProperty = DependencyProperty.Register(
		nameof(Unit), typeof(string), typeof(RadialGauge), new PropertyMetadata("Threads", OnUnitChanged));

	public static readonly DependencyProperty ScaleBrushProperty = DependencyProperty.Register(
		nameof(ScaleBrush), typeof(Brush), typeof(RadialGauge), new PropertyMetadata(null, OnAppearanceChanged));

	public static readonly DependencyProperty MinAngleProperty = DependencyProperty.Register(
		nameof(MinAngle), typeof(int), typeof(RadialGauge), new PropertyMetadata(-150, OnAngleChanged));

	public static readonly DependencyProperty MaxAngleProperty = DependencyProperty.Register(
		nameof(MaxAngle), typeof(int), typeof(RadialGauge), new PropertyMetadata(150, OnAngleChanged));

	public double Minimum
	{
		get => (double)GetValue(MinimumProperty);
		set => SetValue(MinimumProperty, value);
	}

	public double Maximum
	{
		get => (double)GetValue(MaximumProperty);
		set => SetValue(MaximumProperty, value);
	}

	public double Value
	{
		get => (double)GetValue(ValueProperty);
		set => SetValue(ValueProperty, value);
	}

	public double StepSize
	{
		get => (double)GetValue(StepSizeProperty);
		set => SetValue(StepSizeProperty, value);
	}

	public int TickSpacing
	{
		get => (int)GetValue(TickSpacingProperty);
		set => SetValue(TickSpacingProperty, value);
	}

	public double ScaleWidth
	{
		get => (double)GetValue(ScaleWidthProperty);
		set => SetValue(ScaleWidthProperty, value);
	}

	public double ScalePadding
	{
		get => (double)GetValue(ScalePaddingProperty);
		set => SetValue(ScalePaddingProperty, value);
	}

	public double TickWidth
	{
		get => (double)GetValue(TickWidthProperty);
		set => SetValue(TickWidthProperty, value);
	}

	public double TickLength
	{
		get => (double)GetValue(TickLengthProperty);
		set => SetValue(TickLengthProperty, value);
	}

	public double TickPadding
	{
		get => (double)GetValue(TickPaddingProperty);
		set => SetValue(TickPaddingProperty, value);
	}

	public string ValueStringFormat
	{
		get => (string)GetValue(ValueStringFormatProperty);
		set => SetValue(ValueStringFormatProperty, value);
	}

	public bool IsInteractive
	{
		get => (bool)GetValue(IsInteractiveProperty);
		set => SetValue(IsInteractiveProperty, value);
	}

	public string Unit
	{
		get => (string)GetValue(UnitProperty);
		set => SetValue(UnitProperty, value);
	}

	public Brush ScaleBrush
	{
		get => (Brush)GetValue(ScaleBrushProperty);
		set => SetValue(ScaleBrushProperty, value);
	}

	public int MinAngle { get => (int)GetValue(MinAngleProperty); set => SetValue(MinAngleProperty, value); }
	public int MaxAngle { get => (int)GetValue(MaxAngleProperty); set => SetValue(MaxAngleProperty, value); }

	private static void OnRangeChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is RadialGauge gauge)
		{
			// Clamp value if outside new range
			double val = gauge.Value;
			bool changed = false;
			if (val < gauge.Minimum) { gauge.Value = gauge.Minimum; changed = true; }
			if (val > gauge.Maximum) { gauge.Value = gauge.Maximum; changed = true; }

			if (!changed) gauge.UpdateVisuals();
			gauge.UpdateTicks();
		}
	}

	private static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is RadialGauge gauge)
		{
			gauge.UpdateVisuals();
		}
	}

	private static void OnAppearanceChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is RadialGauge gauge)
		{
			gauge.UpdateVisuals();
			gauge.UpdateTicks();
		}
	}

	private static void OnAngleChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is RadialGauge gauge)
		{
			gauge.UpdateNormalizedAngles();
			gauge.UpdateVisuals();
			gauge.UpdateTicks();
		}
	}

	private static void OnUnitChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is RadialGauge gauge)
		{
			gauge._labelTextBlock.Text = gauge.Unit ?? string.Empty;
		}
	}

	private void OnLoaded(object sender, RoutedEventArgs e)
	{
		SetupComposition();
		UpdateThemeColors();
		UpdateVisuals();
		UpdateTicks();
	}

	private void OnUnloaded(object sender, RoutedEventArgs e)
	{
		if (_ticksContainer != null)
		{
			_ticksContainer.Children.RemoveAll();
			_ticksContainer.Dispose();
			_ticksContainer = null;
			_compositor = null;
		}
	}

	private void OnActualThemeChanged(FrameworkElement sender, object args) => UpdateThemeColors();


	private void UpdateThemeColors()
	{
		// Native theme awareness for standalone control
		bool isDark = ActualTheme == ElementTheme.Dark ||
					  (ActualTheme == ElementTheme.Default && Application.Current.RequestedTheme == ApplicationTheme.Dark);

		SolidColorBrush textBrush = new(isDark ? Colors.White : Colors.Black);
		_centerValueText.Foreground = textBrush;
		_labelTextBlock.Foreground = textBrush;
		_centerBorder.BorderBrush = textBrush;

		// Set default scale brush if not provided by user
		if (ScaleBrush == null)
		{
			Color scaleColor = isDark ? Color.FromArgb(255, 60, 60, 60) : Color.FromArgb(255, 220, 220, 220);
			_scalePath.Stroke = new SolidColorBrush(scaleColor);
		}
		else
		{
			_scalePath.Stroke = ScaleBrush;
		}
	}

	private void SetupComposition()
	{
		// Get the hosting visual for the grid to attach ticks
		Visual visual = ElementCompositionPreview.GetElementVisual(_rootGrid);
		_compositor = visual.Compositor;
		_ticksContainer = _compositor.CreateContainerVisual();
		// Set Child Visual places the ticks "behind" the XAML children (Paths) in rendering order for Grid
		ElementCompositionPreview.SetElementChildVisual(_rootGrid, _ticksContainer);
	}

	private void UpdateTicks()
	{
		if (_compositor == null || _ticksContainer == null) return;

		_ticksContainer.Children.RemoveAll();

		if (TickSpacing <= 0 || TickWidth <= 0) return; // don't draw if invisible

		// Determine tick color
		Color tickColor = Colors.Gray;
		if (ActualTheme == ElementTheme.Dark) tickColor = Colors.LightGray;

		CompositionColorBrush tickBrush = _compositor.CreateColorBrush(tickColor);

		float tickW = (float)TickWidth;
		float tickL = (float)TickLength;
		float tickCorner = tickW / 2.0f;

		CompositionRoundedRectangleGeometry roundedTickGeometry = _compositor.CreateRoundedRectangleGeometry();
		roundedTickGeometry.Size = new Vector2(tickW, tickL);
		roundedTickGeometry.CornerRadius = new Vector2(tickCorner, tickCorner);

		double range = Maximum - Minimum;
		if (range <= 0) return;

		for (double v = Minimum; v <= Maximum; v += TickSpacing)
		{
			// Avoid floating point overshoot
			if (v > Maximum + 0.001) break;

			CompositionSpriteShape tickShape = _compositor.CreateSpriteShape(roundedTickGeometry);
			tickShape.FillBrush = tickBrush;

			// Position: 
			// 1. Center at top center of shape
			// 2. Offset to top middle of gauge (relative to rotation center 100,100)
			// 3. Rotate

			float tickPad = (float)TickPadding;

			// Ticks are drawn at 12 o'clock relative to center, then rotated.
			// Center of gauge is 100,100.
			// We want the tick to be at 'TickPadding' from the top edge.
			// X = 100 - (Width/2)
			// Y = TickPadding

			tickShape.Offset = new Vector2(100f - (tickW / 2.0f), tickPad);
			tickShape.CenterPoint = new Vector2(tickW / 2.0f, 100f - tickPad);

			double angle = ValueToAngle(v);
			tickShape.RotationAngleInDegrees = (float)angle;

			ShapeVisual shapeVisual = _compositor.CreateShapeVisual();
			shapeVisual.Size = new Vector2((float)InternalSize, (float)InternalSize);
			shapeVisual.Shapes.Add(tickShape);
			_ticksContainer.Children.InsertAtTop(shapeVisual);
		}
	}

	private void UpdateVisuals()
	{
		// 1. Calculations
		_radius = CenterPt - ScalePadding - (ScaleWidth / 2.0);
		if (_radius <= 0) _radius = 1;

		double currentScaleWidth = ScaleWidth;

		// Update Fonts
		_centerValueText.FontSize = Math.Max(10, currentScaleWidth * 2.0);
		_labelTextBlock.FontSize = Math.Max(8, currentScaleWidth * 0.8);

		// Update Background Scale Path (The track)
		_scalePath.StrokeThickness = currentScaleWidth;
		_scalePath.Data = BuildArcGeometry(_normalizedMinAngle, _normalizedMaxAngle, _radius);

		// Update Colored Segments
		double strokeThickness = currentScaleWidth * ArcScaleFactor;

		_segment1Path.StrokeThickness = strokeThickness;
		_segment2Path.StrokeThickness = strokeThickness;
		_segment3Path.StrokeThickness = strokeThickness;
		_segment4Path.StrokeThickness = strokeThickness;
		_segment5Path.StrokeThickness = strokeThickness;

		double range = Maximum - Minimum;
		if (range <= 0) range = 1;

		// Divide range into 5 colored zones
		double v1 = Minimum + range * 0.2;
		double v2 = Minimum + range * 0.4;
		double v3 = Minimum + range * 0.6;
		double v4 = Minimum + range * 0.8;

		double startAngle = _normalizedMinAngle;
		double a1 = ValueToAngle(v1);
		double a2 = ValueToAngle(v2);
		double a3 = ValueToAngle(v3);
		double a4 = ValueToAngle(v4);
		double currentAngle = ValueToAngle(Value);

		// Helper to update segment visibility
		void UpdateSeg(Path seg, double sAngle, double eAngle)
		{
			if (currentAngle > sAngle)
			{
				seg.Visibility = Visibility.Visible;
				double end = Math.Min(currentAngle, eAngle);
				seg.Data = BuildArcGeometry(sAngle, end, _radius);
			}
			else
			{
				seg.Visibility = Visibility.Collapsed;
			}
		}

		UpdateSeg(_segment1Path, startAngle, a1);
		UpdateSeg(_segment2Path, a1, a2);
		UpdateSeg(_segment3Path, a2, a3);
		UpdateSeg(_segment4Path, a3, a4);
		UpdateSeg(_segment5Path, a4, currentAngle);

		// Update Dot
		double dotSize = strokeThickness * DotScaleFactor;

		if (currentAngle >= startAngle && (Value > Minimum || Minimum == Maximum))
		{
			_indicatorDot.Visibility = Visibility.Visible;
			_indicatorDot.Width = dotSize;
			_indicatorDot.Height = dotSize;

			Point dotCenter = ScalePoint(currentAngle, _radius);
			_indicatorDot.Margin = new(
				dotCenter.X - (dotSize / 2.0),
				dotCenter.Y - (dotSize / 2.0),
				0, 0);
		}
		else if (Value <= Minimum)
		{
			// Show dot at startAngle so it's visible.
			_indicatorDot.Visibility = Visibility.Visible;
			_indicatorDot.Width = dotSize;
			_indicatorDot.Height = dotSize;
			Point dotCenter = ScalePoint(startAngle, _radius);
			_indicatorDot.Margin = new(
				dotCenter.X - (dotSize / 2.0),
				dotCenter.Y - (dotSize / 2.0),
				0, 0);
		}
		else
		{
			_indicatorDot.Visibility = Visibility.Collapsed;
		}

		// Update Text
		_centerValueText.Text = Value.ToString(ValueStringFormat);

		// Update Fill Rect (Glass Effect)
		UpdateFillRect();
	}

	private void UpdateFillRect()
	{
		double pct = (Value - Minimum) / (Maximum - Minimum);
		if (double.IsNaN(pct)) pct = 0;

		double availH = _innerCenterGrid.ActualHeight;
		if (availH > 0)
		{
			_fillRect.Height = Math.Max(0, Math.Min(1, pct)) * availH;
		}
	}

	private Geometry BuildArcGeometry(double startAngle, double endAngle, double radius)
	{
		// Normalize for full circle check
		if (Math.Abs(endAngle - startAngle - 360.0) < 0.0001)
		{
			return new EllipseGeometry
			{
				Center = new Point(CenterPt, CenterPt),
				RadiusX = radius,
				RadiusY = radius
			};
		}

		PathGeometry pg = new();
		PathFigure pf = new()
		{
			IsClosed = false,
			StartPoint = ScalePoint(startAngle, radius)
		};

		ArcSegment seg = new()
		{
			Point = ScalePoint(endAngle, radius),
			Size = new Size(radius, radius),
			SweepDirection = SweepDirection.Clockwise,
			IsLargeArc = (endAngle - startAngle) > 180.0
		};

		pf.Segments.Add(seg);
		pg.Figures.Add(pf);
		return pg;
	}

	private Path CreateSegmentPath(Color startColor, Color endColor, bool isSolid = false)
	{
		Brush brush;
		if (isSolid)
		{
			brush = new SolidColorBrush(startColor);
		}
		else
		{
			LinearGradientBrush lgb = new()
			{
				MappingMode = BrushMappingMode.RelativeToBoundingBox,
				StartPoint = new Point(0, 0),
				EndPoint = new Point(1, 0)
			};
			lgb.GradientStops.Add(new GradientStop { Color = startColor, Offset = 0.0 });
			lgb.GradientStops.Add(new GradientStop { Color = endColor, Offset = 1.0 });
			brush = lgb;
		}

		return new()
		{
			StrokeThickness = 10,
			StrokeStartLineCap = PenLineCap.Round,
			StrokeEndLineCap = PenLineCap.Round,
			StrokeLineJoin = PenLineJoin.Round,
			Visibility = Visibility.Collapsed,
			Stroke = brush
		};
	}

	private void UpdateNormalizedAngles()
	{
		double result = Mod(MinAngle, 360);

		if (result >= 180)
		{
			result -= 360;
		}
		_normalizedMinAngle = result;

		result = Mod(MaxAngle, 360);

		if (result < 180)
		{
			result += 360;
		}
		if (result > _normalizedMinAngle + 360)
		{
			result -= 360;
		}
		_normalizedMaxAngle = result;
	}

	private double ValueToAngle(double value)
	{
		if (value < Minimum) return MinAngle;
		if (value > Maximum) return MaxAngle;

		double range = Maximum - Minimum;
		if (range == 0) return _normalizedMinAngle;

		return ((value - Minimum) / range
				* (_normalizedMaxAngle - _normalizedMinAngle))
			   + _normalizedMinAngle;
	}

	private Point ScalePoint(double angle, double radius)
	{
		double rad = angle * Degrees2Radians;
		return new Point(
			CenterPt + Math.Sin(rad) * radius,
			CenterPt - Math.Cos(rad) * radius);
	}

	private static double Mod(double number, double divider)
	{
		double result = number % divider;
		result = result < 0 ? result + divider : result;
		return result;
	}

	private void OnPointerPressed(object sender, PointerRoutedEventArgs e)
	{
		if (!IsInteractive) return;

		// Capture pointer to track dragging outside bounds
		if (_rootGrid.CapturePointer(e.Pointer))
		{
			_isDragging = true;
			SetGaugeValueFromPoint(e.GetCurrentPoint(_rootGrid).Position);
		}
	}

	private void OnPointerMoved(object sender, PointerRoutedEventArgs e)
	{
		if (!IsInteractive || !_isDragging) return;

		SetGaugeValueFromPoint(e.GetCurrentPoint(_rootGrid).Position);
	}

	private void OnPointerReleased(object sender, PointerRoutedEventArgs e)
	{
		if (!IsInteractive) return;

		_isDragging = false;
		_rootGrid.ReleasePointerCapture(e.Pointer);
	}

	private void SetGaugeValueFromPoint(Point p)
	{
		// 1. Convert to relative coordinates from center
		Point pt = new(p.X - CenterPt, -p.Y + CenterPt);

		// 2. Calculate angle
		double angle = Math.Atan2(pt.X, pt.Y) / Degrees2Radians;
		double divider = Mod(_normalizedMaxAngle - _normalizedMinAngle, 360);
		if (divider == 0) divider = 360;

		// 3. Map angle to value
		double rawValue = Minimum + ((Maximum - Minimum) * Mod(angle - _normalizedMinAngle, 360) / divider);

		// 4. Basic clamping/Validation (prevents jumping across the gap)
		if (rawValue < Minimum || rawValue > Maximum) return;

		// 5. Apply StepSize
		if (StepSize > 0)
		{
			double remainder = rawValue % StepSize;
			// Floating point tolerance check
			if (Math.Abs(remainder) > 0.0001)
			{
				if (remainder >= StepSize / 2.0)
					rawValue += StepSize - remainder;
				else
					rawValue -= remainder;
			}
		}

		// 6. Final clamp
		Value = Math.Clamp(rawValue, Minimum, Maximum);
	}
}
