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
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;

namespace AppControlManager.CustomUIElements;

internal sealed partial class HomeLiveLineGraph : Grid
{
	private const int HorizontalGridLineCount = 7;
	private const int VerticalGridLineCount = 7;
	private const double PrimaryFillOpacity = 0.18;
	private const double SecondaryFillOpacity = 0.12;
	private const double SeriesAnimationDurationSeconds = 0.42;
	private readonly Canvas _canvas = new();
	private readonly Line _hoverLine = new()
	{
		StrokeThickness = 1.5,
		Visibility = Visibility.Collapsed
	};
	private readonly Ellipse _hoverPoint = new()
	{
		Width = 7.0,
		Height = 7.0,
		Stroke = new SolidColorBrush(Color.FromArgb(255, 0, 0, 0)),
		StrokeThickness = 1.0,
		Visibility = Visibility.Collapsed
	};
	private readonly ToolTip _hoverToolTip = new()
	{
		Placement = Microsoft.UI.Xaml.Controls.Primitives.PlacementMode.Mouse
	};

	private readonly Line[] _horizontalGridLines = new Line[HorizontalGridLineCount];
	private readonly Line[] _verticalGridLines = new Line[VerticalGridLineCount];
	private readonly Polyline _primarySeriesLine = new()
	{
		StrokeThickness = 2.0,
		StrokeLineJoin = PenLineJoin.Round
	};
	private readonly Polyline _secondarySeriesLine = new()
	{
		StrokeThickness = 2.0,
		StrokeLineJoin = PenLineJoin.Round
	};
	private readonly Polygon _primarySeriesFill = new();
	private readonly Polygon _secondarySeriesFill = new();
	private readonly SolidColorBrush _gridBrush = new(Color.FromArgb(255, 96, 96, 96))
	{
		Opacity = 0.42
	};
	private readonly SolidColorBrush _primaryStrokeBrush = new(Color.FromArgb(255, 0, 120, 212));
	private readonly SolidColorBrush _secondaryStrokeBrush = new(Color.FromArgb(255, 16, 137, 62));
	private readonly LinearGradientBrush _primaryFillBrush = CreateAreaFillBrush(Color.FromArgb(255, 0, 120, 212), PrimaryFillOpacity);
	private readonly LinearGradientBrush _secondaryFillBrush = CreateAreaFillBrush(Color.FromArgb(255, 16, 137, 62), SecondaryFillOpacity);
	private readonly SeriesAnimationState _primaryAnimationState = new();
	private readonly SeriesAnimationState _secondaryAnimationState = new();
	private bool _isSeriesAnimationRendering;
	private long _seriesAnimationStartTimestamp;

	internal HomeLiveLineGraph()
	{
		Background = new SolidColorBrush(Colors.Transparent);
		Children.Add(_canvas);
		CreateGraphVisuals();
		ToolTipService.SetToolTip(this, _hoverToolTip);
		PointerPressed += OnPointerPressed;
		PointerMoved += OnPointerMoved;
		PointerReleased += OnPointerReleased;
		PointerCanceled += OnPointerCanceled;
		PointerCaptureLost += OnPointerCaptureLost;
		PointerExited += OnPointerExited;
		SizeChanged += OnSizeChanged;
		Unloaded += OnGraphUnloaded;
		ApplyHoverTheme();
	}

	public event EventHandler? EffectiveMaximumChanged;

	public double EffectiveMaximum
	{
		get; private set
		{
			if (Math.Abs(field - value) <= 0.000001)
			{
				return;
			}
			field = value;
			EffectiveMaximumChanged?.Invoke(this, EventArgs.Empty);
		}
	}

	public IReadOnlyList<double> Samples
	{
		get => (IReadOnlyList<double>)GetValue(SamplesProperty);
		set
		{
			IReadOnlyList<double> previousValue = Samples;
			SetValue(SamplesProperty, value);
			if (ReferenceEquals(previousValue, value))
			{
				RenderGraph();
			}
		}
	}

	public static readonly DependencyProperty SamplesProperty = DependencyProperty.Register(nameof(Samples), typeof(IReadOnlyList<double>), typeof(HomeLiveLineGraph), new PropertyMetadata(Array.Empty<double>(), OnGraphPropertyChanged));

	public IReadOnlyList<double> SecondarySamples
	{
		get => (IReadOnlyList<double>)GetValue(SecondarySamplesProperty);
		set
		{
			IReadOnlyList<double> previousValue = SecondarySamples;
			SetValue(SecondarySamplesProperty, value);
			if (ReferenceEquals(previousValue, value))
			{
				RenderGraph();
			}
		}
	}

	public static readonly DependencyProperty SecondarySamplesProperty = DependencyProperty.Register(nameof(SecondarySamples), typeof(IReadOnlyList<double>), typeof(HomeLiveLineGraph), new PropertyMetadata(Array.Empty<double>(), OnGraphPropertyChanged));

	public Color StrokeColor
	{
		get => (Color)GetValue(StrokeColorProperty);
		set => SetValue(StrokeColorProperty, value);
	}

	public static readonly DependencyProperty StrokeColorProperty = DependencyProperty.Register(nameof(StrokeColor), typeof(Color), typeof(HomeLiveLineGraph), new PropertyMetadata(Color.FromArgb(255, 0, 120, 212), OnGraphPropertyChanged));

	public Color SecondaryStrokeColor
	{
		get => (Color)GetValue(SecondaryStrokeColorProperty);
		set => SetValue(SecondaryStrokeColorProperty, value);
	}

	public static readonly DependencyProperty SecondaryStrokeColorProperty = DependencyProperty.Register(nameof(SecondaryStrokeColor), typeof(Color), typeof(HomeLiveLineGraph), new PropertyMetadata(Color.FromArgb(255, 16, 137, 62), OnGraphPropertyChanged));

	public Color GridColor
	{
		get => (Color)GetValue(GridColorProperty);
		set => SetValue(GridColorProperty, value);
	}

	public static readonly DependencyProperty GridColorProperty = DependencyProperty.Register(nameof(GridColor), typeof(Color), typeof(HomeLiveLineGraph), new PropertyMetadata(Color.FromArgb(255, 96, 96, 96), OnGraphPropertyChanged));

	public string PrimarySeriesName
	{
		get => (string)GetValue(PrimarySeriesNameProperty);
		set => SetValue(PrimarySeriesNameProperty, value);
	}

	public static readonly DependencyProperty PrimarySeriesNameProperty = DependencyProperty.Register(nameof(PrimarySeriesName), typeof(string), typeof(HomeLiveLineGraph), new PropertyMetadata(string.Empty));

	public string SecondarySeriesName
	{
		get => (string)GetValue(SecondarySeriesNameProperty);
		set => SetValue(SecondarySeriesNameProperty, value);
	}

	public static readonly DependencyProperty SecondarySeriesNameProperty = DependencyProperty.Register(nameof(SecondarySeriesName), typeof(string), typeof(HomeLiveLineGraph), new PropertyMetadata(string.Empty));

	public string ValueUnit
	{
		get => (string)GetValue(ValueUnitProperty);
		set => SetValue(ValueUnitProperty, value);
	}

	public static readonly DependencyProperty ValueUnitProperty = DependencyProperty.Register(nameof(ValueUnit), typeof(string), typeof(HomeLiveLineGraph), new PropertyMetadata(string.Empty));

	public bool UseFixedMinimum
	{
		get => (bool)GetValue(UseFixedMinimumProperty);
		set => SetValue(UseFixedMinimumProperty, value);
	}

	public static readonly DependencyProperty UseFixedMinimumProperty = DependencyProperty.Register(nameof(UseFixedMinimum), typeof(bool), typeof(HomeLiveLineGraph), new PropertyMetadata(false, OnGraphPropertyChanged));

	public double FixedMinimum
	{
		get => (double)GetValue(FixedMinimumProperty);
		set => SetValue(FixedMinimumProperty, value);
	}

	public static readonly DependencyProperty FixedMinimumProperty = DependencyProperty.Register(nameof(FixedMinimum), typeof(double), typeof(HomeLiveLineGraph), new PropertyMetadata(0.0, OnGraphPropertyChanged));

	public bool UseFixedMaximum
	{
		get => (bool)GetValue(UseFixedMaximumProperty);
		set => SetValue(UseFixedMaximumProperty, value);
	}

	public static readonly DependencyProperty UseFixedMaximumProperty = DependencyProperty.Register(nameof(UseFixedMaximum), typeof(bool), typeof(HomeLiveLineGraph), new PropertyMetadata(false, OnGraphPropertyChanged));

	public double FixedMaximum
	{
		get => (double)GetValue(FixedMaximumProperty);
		set => SetValue(FixedMaximumProperty, value);
	}

	public static readonly DependencyProperty FixedMaximumProperty = DependencyProperty.Register(nameof(FixedMaximum), typeof(double), typeof(HomeLiveLineGraph), new PropertyMetadata(100.0, OnGraphPropertyChanged));

	private void CreateGraphVisuals()
	{
		for (int index = 0; index < HorizontalGridLineCount; index++)
		{
			Line horizontalLine = new()
			{
				Stroke = _gridBrush
			};
			_horizontalGridLines[index] = horizontalLine;
			_canvas.Children.Add(horizontalLine);
		}

		for (int index = 0; index < VerticalGridLineCount; index++)
		{
			Line verticalLine = new()
			{
				Stroke = _gridBrush
			};
			_verticalGridLines[index] = verticalLine;
			_canvas.Children.Add(verticalLine);
		}

		_primarySeriesLine.Stroke = _primaryStrokeBrush;
		_secondarySeriesLine.Stroke = _secondaryStrokeBrush;
		_secondarySeriesLine.StrokeDashArray.Add(2.0);
		_secondarySeriesLine.StrokeDashArray.Add(2.0);
		_primarySeriesFill.Fill = _primaryFillBrush;
		_secondarySeriesFill.Fill = _secondaryFillBrush;
		_canvas.Children.Add(_primarySeriesFill);
		_canvas.Children.Add(_primarySeriesLine);
		_canvas.Children.Add(_secondarySeriesFill);
		_canvas.Children.Add(_secondarySeriesLine);
		_canvas.Children.Add(_hoverLine);
		_canvas.Children.Add(_hoverPoint);
	}

	private static void OnGraphPropertyChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs args)
	{
		HomeLiveLineGraph graph = (HomeLiveLineGraph)dependencyObject;
		graph.ApplyHoverTheme();
		graph.RenderGraph();
	}

	private void ApplyHoverTheme()
	{
		Color strokeColor = StrokeColor;
		Color hoverColor = Color.FromArgb(230, strokeColor.R, strokeColor.G, strokeColor.B);
		_hoverLine.Stroke = new SolidColorBrush(hoverColor);
		_hoverPoint.Fill = new SolidColorBrush(hoverColor);
	}

	private void OnSizeChanged(object sender, SizeChangedEventArgs args) => RenderGraph();

	private void RenderGraph()
	{
		double width = ActualWidth;
		double height = ActualHeight;
		if (width <= 0.0 || height <= 0.0)
		{
			return;
		}

		UpdateGrid(width, height);
		double minimum = UseFixedMinimum ? FixedMinimum : GetMinimum(Samples, SecondarySamples);
		double maximum = GetEffectiveMaximum(Samples, SecondarySamples);
		if (maximum <= minimum)
		{
			maximum = minimum + 1.0;
		}
		EffectiveMaximum = maximum;
		UpdateSeries(_primarySeriesLine, _primarySeriesFill, _primaryStrokeBrush, _primaryFillBrush, _primaryAnimationState, Samples, StrokeColor, PrimaryFillOpacity, width, height, minimum, maximum);
		UpdateSeries(_secondarySeriesLine, _secondarySeriesFill, _secondaryStrokeBrush, _secondaryFillBrush, _secondaryAnimationState, SecondarySamples, SecondaryStrokeColor, SecondaryFillOpacity, width, height, minimum, maximum);
		StartSeriesAnimationIfNeeded();
	}

	private void UpdateGrid(double width, double height)
	{
		_gridBrush.Color = GridColor;
		for (int index = 0; index < HorizontalGridLineCount; index++)
		{
			double rawY = height * index / (HorizontalGridLineCount - 1.0);
			double y = Math.Clamp(rawY, 0.5, Math.Max(0.5, height - 0.5));
			Line horizontalLine = _horizontalGridLines[index];
			horizontalLine.X1 = 0.0;
			horizontalLine.Y1 = y;
			horizontalLine.X2 = width;
			horizontalLine.Y2 = y;
			horizontalLine.StrokeThickness = index == 0 || index == HorizontalGridLineCount - 1 ? 1.25 : 1.0;
		}

		for (int index = 0; index < VerticalGridLineCount; index++)
		{
			double rawX = width * index / (VerticalGridLineCount - 1.0);
			double x = Math.Clamp(rawX, 0.5, Math.Max(0.5, width - 0.5));
			Line verticalLine = _verticalGridLines[index];
			verticalLine.X1 = x;
			verticalLine.Y1 = 0.0;
			verticalLine.X2 = x;
			verticalLine.Y2 = height;
			verticalLine.StrokeThickness = index == 0 || index == VerticalGridLineCount - 1 ? 1.25 : 1.0;
		}
	}

	private static void UpdateSeries(Polyline polyline, Polygon fillPolygon, SolidColorBrush strokeBrush, LinearGradientBrush fillBrush, SeriesAnimationState animationState, IReadOnlyList<double> samples, Color color, double fillOpacity, double width, double height, double minimum, double maximum)
	{
		strokeBrush.Color = color;
		ApplyAreaFillGradient(fillBrush, color, fillOpacity);
		if (samples.Count == 0)
		{
			polyline.Points.Clear();
			fillPolygon.Points.Clear();
			animationState.Clear();
			polyline.Visibility = Visibility.Collapsed;
			fillPolygon.Visibility = Visibility.Collapsed;
			return;
		}

		polyline.Visibility = Visibility.Visible;
		fillPolygon.Visibility = Visibility.Visible;
		BuildSeriesPoints(samples, animationState.TargetLinePoints, animationState.TargetFillPoints, width, height, minimum, maximum);
		if (!animationState.HasRenderedOnce)
		{
			ApplyPoints(polyline.Points, animationState.TargetLinePoints);
			ApplyPoints(fillPolygon.Points, animationState.TargetFillPoints);
			animationState.HasRenderedOnce = true;
			animationState.IsAnimating = false;
			return;
		}

		CaptureStartPoints(polyline.Points, animationState.StartLinePoints, animationState.TargetLinePoints);
		CaptureStartPoints(fillPolygon.Points, animationState.StartFillPoints, animationState.TargetFillPoints);
		animationState.IsAnimating = true;
	}

	private static void BuildSeriesPoints(IReadOnlyList<double> samples, List<Point> linePoints, List<Point> fillPoints, double width, double height, double minimum, double maximum)
	{
		linePoints.Clear();
		fillPoints.Clear();
		double denominator = Math.Max(1.0, samples.Count - 1.0);
		double range = maximum - minimum;
		double lastX = 0.0;
		fillPoints.Add(new Point(0.0, height));
		for (int index = 0; index < samples.Count; index++)
		{
			double normalizedValue = Math.Clamp((samples[index] - minimum) / range, 0.0, 1.0);
			double x = width * index / denominator;
			double y = height - (normalizedValue * height);
			Point point = new(x, y);
			linePoints.Add(point);
			fillPoints.Add(point);
			lastX = x;
		}
		fillPoints.Add(new Point(lastX, height));
	}

	private static LinearGradientBrush CreateAreaFillBrush(Color color, double fillOpacity)
	{
		LinearGradientBrush fillBrush = new();
		fillBrush.GradientStops.Add(new GradientStop());
		fillBrush.GradientStops.Add(new GradientStop());
		fillBrush.GradientStops.Add(new GradientStop());
		ApplyAreaFillGradient(fillBrush, color, fillOpacity);
		return fillBrush;
	}

	private static void ApplyAreaFillGradient(LinearGradientBrush fillBrush, Color color, double fillOpacity)
	{
		// Keep the area color visible through the upper half, then fade it to transparent toward the bottom.
		byte visibleAlpha = (byte)Math.Clamp((int)Math.Round(color.A * Math.Clamp(fillOpacity, 0.0, 1.0)), 0, 255);
		Color visibleColor = Color.FromArgb(visibleAlpha, color.R, color.G, color.B);
		Color transparentColor = Color.FromArgb(0, color.R, color.G, color.B);
		fillBrush.StartPoint = new Point(0.0, 0.0);
		fillBrush.EndPoint = new Point(0.0, 1.0);
		fillBrush.GradientStops[0].Offset = 0.0;
		fillBrush.GradientStops[0].Color = visibleColor;
		fillBrush.GradientStops[1].Offset = 0.5;
		fillBrush.GradientStops[1].Color = visibleColor;
		fillBrush.GradientStops[2].Offset = 1.0;
		fillBrush.GradientStops[2].Color = transparentColor;
	}

	private void StartSeriesAnimationIfNeeded()
	{
		if (!_primaryAnimationState.IsAnimating && !_secondaryAnimationState.IsAnimating)
		{
			StopSeriesAnimationRendering();
			return;
		}

		_seriesAnimationStartTimestamp = Stopwatch.GetTimestamp();
		if (_isSeriesAnimationRendering)
		{
			ApplyAnimatedSeries(0.0);
			return;
		}

		_isSeriesAnimationRendering = true;
		CompositionTarget.Rendering += OnSeriesAnimationRendering;
		ApplyAnimatedSeries(0.0);
	}

	private void OnSeriesAnimationRendering(object? sender, object args)
	{
		double elapsedSeconds = (Stopwatch.GetTimestamp() - _seriesAnimationStartTimestamp) / (double)Stopwatch.Frequency;
		double progress = Math.Clamp(elapsedSeconds / SeriesAnimationDurationSeconds, 0.0, 1.0);
		double easedProgress = EaseOutCubic(progress);
		ApplyAnimatedSeries(easedProgress);
		if (progress >= 1.0)
		{
			_primaryAnimationState.IsAnimating = false;
			_secondaryAnimationState.IsAnimating = false;
			StopSeriesAnimationRendering();
		}
	}

	private void ApplyAnimatedSeries(double progress)
	{
		ApplyAnimatedSeries(_primarySeriesLine.Points, _primarySeriesFill.Points, _primaryAnimationState, progress);
		ApplyAnimatedSeries(_secondarySeriesLine.Points, _secondarySeriesFill.Points, _secondaryAnimationState, progress);
	}

	private static void ApplyAnimatedSeries(PointCollection linePoints, PointCollection fillPoints, SeriesAnimationState animationState, double progress)
	{
		if (!animationState.IsAnimating)
		{
			return;
		}

		ApplyInterpolatedPoints(linePoints, animationState.StartLinePoints, animationState.TargetLinePoints, progress);
		ApplyInterpolatedPoints(fillPoints, animationState.StartFillPoints, animationState.TargetFillPoints, progress);
		if (progress >= 1.0)
		{
			animationState.IsAnimating = false;
		}
	}

	private static void ApplyInterpolatedPoints(PointCollection destination, List<Point> startPoints, List<Point> targetPoints, double progress)
	{
		destination.Clear();
		for (int index = 0; index < targetPoints.Count; index++)
		{
			Point startPoint = startPoints[index];
			Point targetPoint = targetPoints[index];
			destination.Add(new Point(startPoint.X + ((targetPoint.X - startPoint.X) * progress), startPoint.Y + ((targetPoint.Y - startPoint.Y) * progress)));
		}
	}

	private static void ApplyPoints(PointCollection destination, List<Point> source)
	{
		destination.Clear();
		for (int index = 0; index < source.Count; index++)
		{
			destination.Add(source[index]);
		}
	}

	private static void CaptureStartPoints(PointCollection source, List<Point> destination, List<Point> targetPoints)
	{
		destination.Clear();
		int targetCount = targetPoints.Count;
		if (targetCount == 0)
		{
			return;
		}

		int sourceCount = source.Count;
		if (sourceCount == targetCount)
		{
			for (int index = 0; index < sourceCount; index++)
			{
				destination.Add(source[index]);
			}
			return;
		}

		if (sourceCount == 0)
		{
			for (int index = 0; index < targetCount; index++)
			{
				destination.Add(targetPoints[index]);
			}
			return;
		}

		for (int index = 0; index < targetCount; index++)
		{
			int sourceIndex = targetCount == 1 ? 0 : (int)Math.Round(index * (sourceCount - 1.0) / (targetCount - 1.0), MidpointRounding.AwayFromZero);
			destination.Add(source[Math.Clamp(sourceIndex, 0, sourceCount - 1)]);
		}
	}

	private void StopSeriesAnimationRendering()
	{
		if (!_isSeriesAnimationRendering)
		{
			return;
		}

		CompositionTarget.Rendering -= OnSeriesAnimationRendering;
		_isSeriesAnimationRendering = false;
	}

	private void OnGraphUnloaded(object sender, RoutedEventArgs args)
	{
		StopSeriesAnimationRendering();
		Unloaded -= OnGraphUnloaded;
	}

	private static double EaseOutCubic(double progress)
	{
		double inverse = 1.0 - progress;
		return 1.0 - (inverse * inverse * inverse);
	}

	private sealed class SeriesAnimationState
	{
		internal readonly List<Point> StartLinePoints = new(128);
		internal readonly List<Point> TargetLinePoints = new(128);
		internal readonly List<Point> StartFillPoints = new(130);
		internal readonly List<Point> TargetFillPoints = new(130);
		internal bool HasRenderedOnce;
		internal bool IsAnimating;

		internal void Clear()
		{
			StartLinePoints.Clear();
			TargetLinePoints.Clear();
			StartFillPoints.Clear();
			TargetFillPoints.Clear();
			HasRenderedOnce = false;
			IsAnimating = false;
		}
	}

	private void OnPointerPressed(object sender, PointerRoutedEventArgs args)
	{
		_ = CapturePointer(args.Pointer);
		UpdateHoverVisual(args);
	}

	private void OnPointerMoved(object sender, PointerRoutedEventArgs args) => UpdateHoverVisual(args);

	private void OnPointerReleased(object sender, PointerRoutedEventArgs args)
	{
		ReleasePointerCapture(args.Pointer);
		HideHoverVisual();
	}

	private void OnPointerCanceled(object sender, PointerRoutedEventArgs args) => HideHoverVisual();

	private void OnPointerCaptureLost(object sender, PointerRoutedEventArgs args) => HideHoverVisual();

	private void OnPointerExited(object sender, PointerRoutedEventArgs args)
	{
		if (!args.Pointer.IsInContact)
		{
			HideHoverVisual();
		}
	}

	private void UpdateHoverVisual(PointerRoutedEventArgs args)
	{
		double width = ActualWidth;
		double height = ActualHeight;
		IReadOnlyList<double> primarySamples = Samples;
		if (width <= 0.0 || height <= 0.0 || primarySamples.Count == 0)
		{
			return;
		}
		Point pointerPosition = args.GetCurrentPoint(this).Position;
		int sampleIndex = GetNearestSampleIndex(pointerPosition.X, width, primarySamples.Count);
		double minimum = UseFixedMinimum ? FixedMinimum : GetMinimum(primarySamples, SecondarySamples);
		double maximum = GetEffectiveMaximum(primarySamples, SecondarySamples);
		if (maximum <= minimum)
		{
			maximum = minimum + 1.0;
		}
		double primaryValue = primarySamples[sampleIndex];
		double x = width * sampleIndex / Math.Max(1.0, primarySamples.Count - 1.0);
		double normalizedValue = Math.Clamp((primaryValue - minimum) / (maximum - minimum), 0.0, 1.0);
		double y = height - (normalizedValue * height);
		_hoverLine.X1 = x;
		_hoverLine.X2 = x;
		_hoverLine.Y1 = y;
		_hoverLine.Y2 = height;
		_hoverLine.Visibility = Visibility.Visible;
		Canvas.SetLeft(_hoverPoint, x - (_hoverPoint.Width / 2.0));
		Canvas.SetTop(_hoverPoint, y - (_hoverPoint.Height / 2.0));
		_hoverPoint.Visibility = Visibility.Visible;
		_hoverToolTip.Content = BuildHoverText(sampleIndex, primaryValue);
		_hoverToolTip.IsOpen = true;
	}

	private void HideHoverVisual()
	{
		_hoverLine.Visibility = Visibility.Collapsed;
		_hoverPoint.Visibility = Visibility.Collapsed;
		_hoverToolTip.IsOpen = false;
	}

	private string BuildHoverText(int sampleIndex, double primaryValue)
	{
		string primarySeriesName = string.IsNullOrWhiteSpace(PrimarySeriesName) ? "Value" : PrimarySeriesName;
		string text = primarySeriesName + ": " + FormatValue(primaryValue);
		IReadOnlyList<double> secondarySamples = SecondarySamples;
		if (secondarySamples.Count > 0)
		{
			int secondaryIndex = Math.Clamp(sampleIndex, 0, secondarySamples.Count - 1);
			string secondarySeriesName = string.IsNullOrWhiteSpace(SecondarySeriesName) ? "Secondary" : SecondarySeriesName;
			text += "\n" + secondarySeriesName + ": " + FormatValue(secondarySamples[secondaryIndex]);
		}
		return text;
	}

	private string FormatValue(double value)
	{
		string formattedValue = value.ToString("0.##", CultureInfo.InvariantCulture);
		return string.IsNullOrWhiteSpace(ValueUnit) ? formattedValue : formattedValue + " " + ValueUnit;
	}

	private double GetEffectiveMaximum(IReadOnlyList<double> primarySamples, IReadOnlyList<double> secondarySamples)
	{
		double dynamicMaximum = GetMaximum(primarySamples, secondarySamples);
		return UseFixedMaximum ? Math.Max(FixedMaximum, dynamicMaximum) : dynamicMaximum;
	}

	private static int GetNearestSampleIndex(double pointerX, double width, int sampleCount)
	{
		if (sampleCount <= 1)
		{
			return 0;
		}
		double clampedX = Math.Clamp(pointerX, 0.0, width);
		double ratio = clampedX / Math.Max(1.0, width);
		int index = (int)Math.Round(ratio * (sampleCount - 1), MidpointRounding.AwayFromZero);
		return Math.Clamp(index, 0, sampleCount - 1);
	}

	private static double GetMinimum(IReadOnlyList<double> primarySamples, IReadOnlyList<double> secondarySamples)
	{
		bool hasValue = false;
		double minimum = 0.0;
		UpdateMinimum(primarySamples, ref minimum, ref hasValue);
		UpdateMinimum(secondarySamples, ref minimum, ref hasValue);
		return hasValue ? minimum : 0.0;
	}

	private static double GetMaximum(IReadOnlyList<double> primarySamples, IReadOnlyList<double> secondarySamples)
	{
		bool hasValue = false;
		double maximum = 0.0;
		UpdateMaximum(primarySamples, ref maximum, ref hasValue);
		UpdateMaximum(secondarySamples, ref maximum, ref hasValue);
		return hasValue ? maximum : 1.0;
	}

	private static void UpdateMinimum(IReadOnlyList<double> samples, ref double minimum, ref bool hasValue)
	{
		for (int index = 0; index < samples.Count; index++)
		{
			double value = samples[index];
			if (!hasValue || value < minimum)
			{
				minimum = value;
				hasValue = true;
			}
		}
	}

	private static void UpdateMaximum(IReadOnlyList<double> samples, ref double maximum, ref bool hasValue)
	{
		for (int index = 0; index < samples.Count; index++)
		{
			double value = samples[index];
			if (!hasValue || value > maximum)
			{
				maximum = value;
				hasValue = true;
			}
		}
	}
}
