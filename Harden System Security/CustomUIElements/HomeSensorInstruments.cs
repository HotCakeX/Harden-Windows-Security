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

using System.Globalization;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;

namespace AppControlManager.CustomUIElements;

internal sealed partial class HomeCompassView : Grid
{
	private const int MinorTickCount = 72;
	private readonly Canvas _canvas = new();
	private readonly Ellipse _outerRing = new();
	private readonly Ellipse _innerRing = new();
	private readonly Line[] _minorTicks = new Line[MinorTickCount];
	private readonly TextBlock[] _cardinalLabels = new TextBlock[8];
	private readonly Polygon _northNeedle = new();
	private readonly Polygon _southNeedle = new();
	private readonly Ellipse _centerDot = new();
	private readonly TextBlock _headingTextBlock = new();
	private readonly SolidColorBrush _accentBrush = new(Color.FromArgb(255, 75, 216, 182));
	private readonly SolidColorBrush _ringBrush = new(Color.FromArgb(185, 8, 16, 30));
	private readonly SolidColorBrush _tickBrush = new(Color.FromArgb(180, 230, 245, 255));
	private readonly SolidColorBrush _northBrush = new(Color.FromArgb(255, 255, 82, 82));
	private readonly SolidColorBrush _southBrush = new(Color.FromArgb(255, 75, 216, 182));

	internal HomeCompassView()
	{
		Background = new SolidColorBrush(Colors.Transparent);
		Children.Add(_canvas);
		CreateVisuals();
		SizeChanged += OnSizeChanged;
	}

	internal double HeadingDegrees
	{
		get => (double)GetValue(HeadingDegreesProperty);
		set => SetValue(HeadingDegreesProperty, value);
	}

	internal static readonly DependencyProperty HeadingDegreesProperty = DependencyProperty.Register(nameof(HeadingDegrees), typeof(double), typeof(HomeCompassView), new PropertyMetadata(0.0, OnHeadingChanged));

	internal static readonly string[] CompassLabels = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"];

	private void CreateVisuals()
	{
		_outerRing.Fill = _ringBrush;
		_outerRing.Stroke = _accentBrush;
		_outerRing.StrokeThickness = 2.0;
		_innerRing.Fill = new SolidColorBrush(Color.FromArgb(90, 20, 35, 54));
		_innerRing.Stroke = new SolidColorBrush(Color.FromArgb(110, 255, 255, 255));
		_innerRing.StrokeThickness = 1.0;
		_canvas.Children.Add(_outerRing);
		_canvas.Children.Add(_innerRing);

		for (int index = 0; index < _minorTicks.Length; index++)
		{
			Line tick = new() { Stroke = _tickBrush, StrokeThickness = index % 6 == 0 ? 2.0 : 1.0, Opacity = index % 6 == 0 ? 0.95 : 0.45 };
			_minorTicks[index] = tick;
			_canvas.Children.Add(tick);
		}

		for (int index = 0; index < CompassLabels.Length; index++)
		{
			TextBlock label = new()
			{
				Text = CompassLabels[index],
				FontSize = index % 2 == 0 ? 20.0 : 13.0,
				FontWeight = index == 0 ? Microsoft.UI.Text.FontWeights.Bold : Microsoft.UI.Text.FontWeights.SemiBold,
				Foreground = index == 0 ? _northBrush : new SolidColorBrush(Colors.White),
				TextAlignment = TextAlignment.Center
			};
			_cardinalLabels[index] = label;
			_canvas.Children.Add(label);
		}

		_northNeedle.Fill = _northBrush;
		_southNeedle.Fill = _southBrush;
		_centerDot.Fill = _accentBrush;
		_centerDot.Width = 14.0;
		_centerDot.Height = 14.0;
		_headingTextBlock.FontSize = 15.0;
		_headingTextBlock.FontWeight = Microsoft.UI.Text.FontWeights.SemiBold;
		_headingTextBlock.Foreground = new SolidColorBrush(Colors.White);
		_headingTextBlock.TextAlignment = TextAlignment.Center;
		_canvas.Children.Add(_southNeedle);
		_canvas.Children.Add(_northNeedle);
		_canvas.Children.Add(_centerDot);
		_canvas.Children.Add(_headingTextBlock);
	}

	private static void OnHeadingChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs args)
	{
		HomeCompassView compassView = (HomeCompassView)dependencyObject;
		compassView.RenderCompass();
	}

	private void OnSizeChanged(object sender, SizeChangedEventArgs args) => RenderCompass();

	private void RenderCompass()
	{
		double width = ActualWidth;
		double height = ActualHeight;
		if (width <= 0.0 || height <= 0.0)
		{
			return;
		}

		double size = Math.Max(140.0, Math.Min(width, height) - 12.0);
		double radius = size / 2.0;
		double centerX = width / 2.0;
		double centerY = height / 2.0;
		SetEllipse(_outerRing, centerX, centerY, size, size);
		SetEllipse(_innerRing, centerX, centerY, size - 30.0, size - 30.0);

		for (int index = 0; index < _minorTicks.Length; index++)
		{
			double angle = index * 360.0 / _minorTicks.Length;
			double angleRadians = (angle - 90.0) * Math.PI / 180.0;
			double outer = radius - 12.0;
			double inner = radius - (index % 6 == 0 ? 28.0 : 20.0);
			Line tick = _minorTicks[index];
			tick.X1 = centerX + (Math.Cos(angleRadians) * inner);
			tick.Y1 = centerY + (Math.Sin(angleRadians) * inner);
			tick.X2 = centerX + (Math.Cos(angleRadians) * outer);
			tick.Y2 = centerY + (Math.Sin(angleRadians) * outer);
		}

		for (int index = 0; index < _cardinalLabels.Length; index++)
		{
			double angle = index * 45.0 - 90.0;
			double angleRadians = angle * Math.PI / 180.0;
			TextBlock label = _cardinalLabels[index];
			label.Width = 44.0;
			label.Height = 28.0;
			Canvas.SetLeft(label, centerX + (Math.Cos(angleRadians) * (radius - 53.0)) - 22.0);
			Canvas.SetTop(label, centerY + (Math.Sin(angleRadians) * (radius - 53.0)) - 14.0);
		}

		double heading = NormalizeHeading(HeadingDegrees);
		double needleRadians = (heading - 90.0) * Math.PI / 180.0;
		double perpendicularRadians = needleRadians + (Math.PI / 2.0);
		SetNeedle(_northNeedle, centerX, centerY, needleRadians, perpendicularRadians, radius * 0.66, 12.0);
		SetNeedle(_southNeedle, centerX, centerY, needleRadians + Math.PI, perpendicularRadians, radius * 0.50, 9.0);
		SetEllipse(_centerDot, centerX, centerY, 14.0, 14.0);
		_headingTextBlock.Text = heading.ToString("0.0", CultureInfo.InvariantCulture) + "°";
		_headingTextBlock.Width = 120.0;
		Canvas.SetLeft(_headingTextBlock, centerX - 60.0);
		Canvas.SetTop(_headingTextBlock, centerY + 22.0);
	}

	private static void SetNeedle(Polygon needle, double centerX, double centerY, double angleRadians, double perpendicularRadians, double length, double halfWidth)
	{
		needle.Points.Clear();
		needle.Points.Add(new Point(centerX + (Math.Cos(angleRadians) * length), centerY + (Math.Sin(angleRadians) * length)));
		needle.Points.Add(new Point(centerX + (Math.Cos(perpendicularRadians) * halfWidth), centerY + (Math.Sin(perpendicularRadians) * halfWidth)));
		needle.Points.Add(new Point(centerX - (Math.Cos(angleRadians) * 18.0), centerY - (Math.Sin(angleRadians) * 18.0)));
		needle.Points.Add(new Point(centerX - (Math.Cos(perpendicularRadians) * halfWidth), centerY - (Math.Sin(perpendicularRadians) * halfWidth)));
	}

	private static void SetEllipse(Ellipse ellipse, double centerX, double centerY, double width, double height)
	{
		ellipse.Width = width;
		ellipse.Height = height;
		Canvas.SetLeft(ellipse, centerX - (width / 2.0));
		Canvas.SetTop(ellipse, centerY - (height / 2.0));
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
}

internal sealed partial class HomeLightSensorMeterView : Grid
{
	private const double MaximumLux = 100000.0;
	private readonly Canvas _canvas = new();
	private readonly Rectangle[] _segments = new Rectangle[9];
	private readonly Rectangle _marker = new();
	private readonly TextBlock _luxTextBlock = new();
	private readonly Color[] _segmentColors =
	[
		Color.FromArgb(255, 15, 23, 42),
		Color.FromArgb(255, 30, 41, 59),
		Color.FromArgb(255, 51, 65, 85),
		Color.FromArgb(255, 8, 145, 178),
		Color.FromArgb(255, 20, 184, 166),
		Color.FromArgb(255, 132, 204, 22),
		Color.FromArgb(255, 250, 204, 21),
		Color.FromArgb(255, 249, 115, 22),
		Color.FromArgb(255, 255, 255, 255)
	];

	internal HomeLightSensorMeterView()
	{
		Background = new SolidColorBrush(Colors.Transparent);
		Children.Add(_canvas);
		CreateVisuals();
		SizeChanged += OnSizeChanged;
	}

	internal double Lux
	{
		get => (double)GetValue(LuxProperty);
		set => SetValue(LuxProperty, value);
	}

	internal static readonly DependencyProperty LuxProperty = DependencyProperty.Register(nameof(Lux), typeof(double), typeof(HomeLightSensorMeterView), new PropertyMetadata(0.0, OnLuxChanged));

	private void CreateVisuals()
	{
		for (int index = 0; index < _segments.Length; index++)
		{
			Rectangle segment = new()
			{
				Fill = new SolidColorBrush(_segmentColors[index]),
				RadiusX = 4.0,
				RadiusY = 4.0
			};
			_segments[index] = segment;
			_canvas.Children.Add(segment);
		}
		_marker.Fill = new SolidColorBrush(Colors.White);
		_marker.RadiusX = 3.0;
		_marker.RadiusY = 3.0;
		_luxTextBlock.FontSize = 15.0;
		_luxTextBlock.FontWeight = Microsoft.UI.Text.FontWeights.SemiBold;
		_luxTextBlock.Foreground = new SolidColorBrush(Colors.White);
		_canvas.Children.Add(_marker);
		_canvas.Children.Add(_luxTextBlock);
	}

	private static void OnLuxChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs args)
	{
		HomeLightSensorMeterView meterView = (HomeLightSensorMeterView)dependencyObject;
		meterView.RenderMeter();
	}

	private void OnSizeChanged(object sender, SizeChangedEventArgs args) => RenderMeter();

	private void RenderMeter()
	{
		double width = ActualWidth;
		double height = ActualHeight;
		if (width <= 0.0 || height <= 0.0)
		{
			return;
		}

		double left = 18.0;
		double top = Math.Max(20.0, height / 2.0 - 22.0);
		double meterWidth = Math.Max(120.0, width - 36.0);
		double segmentWidth = meterWidth / _segments.Length;
		for (int index = 0; index < _segments.Length; index++)
		{
			Rectangle segment = _segments[index];
			segment.Width = Math.Max(4.0, segmentWidth - 4.0);
			segment.Height = 42.0;
			Canvas.SetLeft(segment, left + (index * segmentWidth));
			Canvas.SetTop(segment, top);
		}

		double normalized = Math.Log10(Math.Max(1.0, Lux) + 1.0) / Math.Log10(MaximumLux + 1.0);
		normalized = Math.Clamp(normalized, 0.0, 1.0);
		_marker.Width = 8.0;
		_marker.Height = 62.0;
		Canvas.SetLeft(_marker, left + (meterWidth * normalized) - 4.0);
		Canvas.SetTop(_marker, top - 10.0);
		_luxTextBlock.Text = Lux.ToString("0.0", CultureInfo.InvariantCulture) + " lux";
		_luxTextBlock.Width = meterWidth;
		_luxTextBlock.TextAlignment = TextAlignment.Center;
		Canvas.SetLeft(_luxTextBlock, left);
		Canvas.SetTop(_luxTextBlock, top + 52.0);
	}
}
