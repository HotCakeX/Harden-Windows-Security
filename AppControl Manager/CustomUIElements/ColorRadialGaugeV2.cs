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

using CommunityToolkit.WinUI.Controls;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;

#if HARDEN_SYSTEM_SECURITY
using HardenSystemSecurity;
#endif

namespace AppControlManager.CustomUIElements;

/// <summary>
/// A RadialGauge subclass that splits its value‐arc into five
/// smoothly‐blended color zones. As Value grows, each zone
/// lights up in a gradient from its start color into the next color,
/// and a white dot marks the moving end of the arc.
/// </summary>
internal sealed partial class ColorRadialGaugeV2 : RadialGauge
{
	private const string TrailPartName = "PART_Trail";
	private const string ContainerPartName = "PART_Container";

	private Path? _backgroundTrail;
	private Path? _segment1Path;
	private Path? _segment2Path;
	private Path? _segment3Path;
	private Path? _segment4Path;
	private Path? _segment5Path;
	private Ellipse? _indicatorDot;
	private Grid? _containerGrid;

	// Center text, border and fill rectangle
	private TextBlock? _centerText;
	private Border? _centerBorder;
	private Rectangle? _fillRect;
	private Grid? _innerGrid; // for clipping and measuring fill bounds

	// Center and radius computed from the container size
	private double _centerX;
	private double _centerY;
	private double _radius;

	private static readonly Color Segment1Color = Color.FromArgb(255, 255, 182, 193); // LightPink
	private static readonly Color Segment2Color = Color.FromArgb(255, 255, 192, 203); // Pink
	private static readonly Color Segment3Color = Color.FromArgb(255, 255, 105, 180); // HotPink
	private static readonly Color Segment4Color = Color.FromArgb(255, 238, 130, 238); // Violet
	private static readonly Color Segment5Color = Color.FromArgb(255, 138, 43, 226);   // BlueViolet

	// How much larger the placeholder track is compared to the base ScaleWidth
	private const double PlaceholderScaleFactor = 0.2;

	// How much larger the colored arc is compared to the base ScaleWidth
	private const double ArcScaleFactor = 1.7;

	// How much larger the dot is compared to the arc stroke width
	private const double DotScaleFactor = 0.7;

	// For angle→radians conversion
	private const double Degrees2Radians = Math.PI / 180.0;

	protected override void OnApplyTemplate()
	{
		base.OnApplyTemplate();

		// hide default bottom text
		if (GetTemplateChild("PART_ValueText") is TextBlock defaultValueText)
			defaultValueText.Visibility = Visibility.Collapsed;
		if (GetTemplateChild("PART_UnitText") is TextBlock defaultUnitText)
			defaultUnitText.Visibility = Visibility.Collapsed;

		// 1) Get the placeholder trail path
		_backgroundTrail = GetTemplateChild(TrailPartName) as Path;
		if (_backgroundTrail == null)
			return;
		_backgroundTrail.Stroke = new SolidColorBrush(Colors.Transparent);
		_backgroundTrail.StrokeThickness = ScaleWidth * PlaceholderScaleFactor;
		_backgroundTrail.StrokeStartLineCap = PenLineCap.Round;
		_backgroundTrail.StrokeEndLineCap = PenLineCap.Round;
		_backgroundTrail.StrokeLineJoin = PenLineJoin.Round;

		// 2) Get the container grid
		_containerGrid = GetTemplateChild(ContainerPartName) as Grid;
		if (_containerGrid == null)
			return;

		// Compute center and radius
		double width = _containerGrid.Width;
		double height = _containerGrid.Height;
		if (double.IsNaN(width) || width <= 0) width = _containerGrid.ActualWidth;
		if (double.IsNaN(height) || height <= 0) height = _containerGrid.ActualHeight;
		_centerX = width / 2.0;
		_centerY = height / 2.0;
		_radius = _centerX - ScalePadding - (ScaleWidth / 2.0);

		// 3) Create segment paths
		_segment1Path = new Path
		{
			StrokeThickness = ScaleWidth * ArcScaleFactor,
			StrokeStartLineCap = PenLineCap.Round,
			StrokeEndLineCap = PenLineCap.Round,
			StrokeLineJoin = PenLineJoin.Round,
			Visibility = Visibility.Collapsed,
			Stroke = new LinearGradientBrush
			{
				MappingMode = BrushMappingMode.RelativeToBoundingBox,
				StartPoint = new Point(0, 0),
				EndPoint = new Point(1, 0),
				GradientStops =
				{
					new GradientStop { Color = Segment1Color, Offset = 0.0 },
					new GradientStop { Color = Segment2Color, Offset = 1.0 }
				}
			}
		};
		_segment2Path = new Path
		{
			StrokeThickness = ScaleWidth * ArcScaleFactor,
			StrokeStartLineCap = PenLineCap.Round,
			StrokeEndLineCap = PenLineCap.Round,
			StrokeLineJoin = PenLineJoin.Round,
			Visibility = Visibility.Collapsed,
			Stroke = new LinearGradientBrush
			{
				MappingMode = BrushMappingMode.RelativeToBoundingBox,
				StartPoint = new Point(0, 0),
				EndPoint = new Point(1, 0),
				GradientStops =
				{
					new GradientStop { Color = Segment2Color, Offset = 0.0 },
					new GradientStop { Color = Segment3Color, Offset = 1.0 }
				}
			}
		};
		_segment3Path = new Path
		{
			StrokeThickness = ScaleWidth * ArcScaleFactor,
			StrokeStartLineCap = PenLineCap.Round,
			StrokeEndLineCap = PenLineCap.Round,
			StrokeLineJoin = PenLineJoin.Round,
			Visibility = Visibility.Collapsed,
			Stroke = new LinearGradientBrush
			{
				MappingMode = BrushMappingMode.RelativeToBoundingBox,
				StartPoint = new Point(0, 0),
				EndPoint = new Point(1, 0),
				GradientStops =
				{
					new GradientStop { Color = Segment3Color, Offset = 0.0 },
					new GradientStop { Color = Segment4Color, Offset = 1.0 }
				}
			}
		};
		_segment4Path = new Path
		{
			StrokeThickness = ScaleWidth * ArcScaleFactor,
			StrokeStartLineCap = PenLineCap.Round,
			StrokeEndLineCap = PenLineCap.Round,
			StrokeLineJoin = PenLineJoin.Round,
			Visibility = Visibility.Collapsed,
			Stroke = new LinearGradientBrush
			{
				MappingMode = BrushMappingMode.RelativeToBoundingBox,
				StartPoint = new Point(0, 0),
				EndPoint = new Point(1, 0),
				GradientStops =
				{
					new GradientStop { Color = Segment4Color, Offset = 0.0 },
					new GradientStop { Color = Segment5Color, Offset = 1.0 }
				}
			}
		};
		_segment5Path = new Path
		{
			StrokeThickness = ScaleWidth * ArcScaleFactor,
			StrokeStartLineCap = PenLineCap.Round,
			StrokeEndLineCap = PenLineCap.Round,
			StrokeLineJoin = PenLineJoin.Round,
			Visibility = Visibility.Collapsed,
			Stroke = new SolidColorBrush(Segment5Color)
		};

		// 4) Insert segment paths above trail
		int baseIndex = _containerGrid.Children.IndexOf(_backgroundTrail);
		_containerGrid.Children.Insert(baseIndex + 1, _segment1Path!);
		_containerGrid.Children.Insert(baseIndex + 2, _segment2Path!);
		_containerGrid.Children.Insert(baseIndex + 3, _segment3Path!);
		_containerGrid.Children.Insert(baseIndex + 4, _segment4Path!);
		_containerGrid.Children.Insert(baseIndex + 5, _segment5Path!);

		// 5) Create and insert moving dot
		double initialDotSize = ScaleWidth * ArcScaleFactor * DotScaleFactor;
		_indicatorDot = new Ellipse
		{
			Fill = new SolidColorBrush(Colors.White),
			Width = initialDotSize,
			Height = initialDotSize,
			Visibility = Visibility.Visible,
			IsHitTestVisible = false,
			HorizontalAlignment = HorizontalAlignment.Left,
			VerticalAlignment = VerticalAlignment.Top
		};
		_containerGrid.Children.Insert(baseIndex + 6, _indicatorDot);

		// 6) Hook ValueChanged
		ValueChanged += OnValueChanged;

		// 7) Initial draw
		UpdateSegments(Value);

		// 8) Build the center display (original size), with clipping and fill
		StackPanel stack = new()
		{
			Orientation = Orientation.Vertical,
			HorizontalAlignment = HorizontalAlignment.Center,
			VerticalAlignment = VerticalAlignment.Center,
			Spacing = 4
		};

		// center text
		_centerText = new TextBlock
		{
			FontSize = ScaleWidth * 2.0,
			Text = Value.ToString(),
			TextAlignment = TextAlignment.Center
		};

		// fill rectangle (glass effect)
		_fillRect = new Rectangle
		{
			Fill = new LinearGradientBrush
			{
				MappingMode = BrushMappingMode.RelativeToBoundingBox,
				StartPoint = new Point(0, 1),
				EndPoint = new Point(0, 0),
				GradientStops =
				{
					new GradientStop { Color = Colors.HotPink, Offset = 0.0 },
					new GradientStop { Color = Colors.Pink, Offset = 1.0 }
				}
			},
			HorizontalAlignment = HorizontalAlignment.Stretch,
			VerticalAlignment = VerticalAlignment.Bottom
		};

		// inner grid for layering and clipping
		_innerGrid = new Grid
		{
			// assign clip and update it on size change
			Clip = new RectangleGeometry()
		};
		_innerGrid.SizeChanged += (s, e) =>
		{
			if (_innerGrid.Clip is RectangleGeometry rg)
			{
				rg.Rect = new Rect(0, 0, e.NewSize.Width, e.NewSize.Height);
			}
		};
		_innerGrid.Children.Add(_fillRect);
		_innerGrid.Children.Add(_centerText);

		// border wraps the inner grid
		_centerBorder = new Border
		{
			BorderBrush = string.Equals(App.Settings.AppTheme, "Light", StringComparison.OrdinalIgnoreCase) ? new SolidColorBrush(Colors.Black) : new SolidColorBrush(Colors.White),
			BorderThickness = new Thickness(2),
			CornerRadius = new CornerRadius(4),
			Padding = new Thickness(3),
			Child = _innerGrid
		};

		TextBlock threadsLabel = new()
		{
			Text = "Threads",
			FontSize = ScaleWidth * 0.8,
			TextAlignment = TextAlignment.Center,
			Margin = new Thickness(0, 5, 0, 0)
		};

		stack.Children.Add(_centerBorder);
		stack.Children.Add(threadsLabel);
		_containerGrid.Children.Add(stack);
	}

	private void OnValueChanged(object sender, RangeBaseValueChangedEventArgs e)
	{
		UpdateSegments(e.NewValue);
	}

	private void UpdateSegments(double value)
	{
		if (_backgroundTrail == null ||
			_segment1Path == null ||
			_segment2Path == null ||
			_segment3Path == null ||
			_segment4Path == null ||
			_segment5Path == null ||
			_indicatorDot == null)
			return;

		// redraw gauge segments
		double radius = _radius;
		double startAngle = NormalizedMinAngle;
		double endAngle = NormalizedMaxAngle;
		double range = Maximum - Minimum;
		double v1 = Minimum + range * 1.0 / 5.0;
		double v2 = Minimum + range * 2.0 / 5.0;
		double v3 = Minimum + range * 3.0 / 5.0;
		double v4 = Minimum + range * 4.0 / 5.0;
		double a1 = ValueToAngle(v1);
		double a2 = ValueToAngle(v2);
		double a3 = ValueToAngle(v3);
		double a4 = ValueToAngle(v4);
		double vAngle = ValueToAngle(value);

		_backgroundTrail.Data = BuildArcGeometry(startAngle, endAngle, radius);

		void UpdateSeg(Path seg, double segStart, double segEnd)
		{
			if (vAngle > segStart)
			{
				seg.Visibility = Visibility.Visible;
				double end = Math.Min(vAngle, segEnd);
				seg.Data = BuildArcGeometry(segStart, end, radius);
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
		UpdateSeg(_segment5Path, a4, vAngle);

		// reposition the dot
		double dotSize = ScaleWidth * ArcScaleFactor * DotScaleFactor;
		Point dotCenter = ScalePoint(vAngle, radius);
		_indicatorDot.Width = dotSize;
		_indicatorDot.Height = dotSize;
		_indicatorDot.Margin = new Thickness(
			dotCenter.X - (dotSize / 2.0),
			dotCenter.Y - (dotSize / 2.0), 0, 0);

		// update center text
		_ = (_centerText?.Text = value.ToString());

		// update fill rectangle height (clamped to inner grid height)
		if (_fillRect != null && _innerGrid != null)
		{
			double pct = (value - Minimum) / (Maximum - Minimum);
			double availH = _innerGrid.ActualHeight;
			_fillRect.Height = Math.Max(0, Math.Min(1, pct)) * availH;
		}
	}

	private Geometry BuildArcGeometry(double startAngle, double endAngle, double radius)
	{
		if (Math.Abs(endAngle - startAngle - 360.0) < 0.0001)
		{
			return new EllipseGeometry
			{
				Center = new Point(_centerX, _centerY),
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

	private double ValueToAngle(double value)
	{
		if (value < Minimum) return MinAngle;
		if (value > Maximum) return MaxAngle;
		return ((value - Minimum) / (Maximum - Minimum)
				* (NormalizedMaxAngle - NormalizedMinAngle))
			   + NormalizedMinAngle;
	}

	private Point ScalePoint(double angle, double radius)
	{
		double rad = angle * Degrees2Radians;
		return new Point(
			_centerX + Math.Sin(rad) * radius,
			_centerY - Math.Cos(rad) * radius);
	}
}
