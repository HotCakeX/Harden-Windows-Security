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
using System.Globalization;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;

namespace AppControlManager.CustomUIElements;

internal sealed partial class HomePhysicalOrientationView : Grid
{
	private const double MaximumVisualTiltDegrees = 75.0;
	private const double LaptopWidth = 250.0;
	private const double BaseFrontDepth = 74.0;
	private const double BaseBackDepth = 34.0;
	private const double ScreenHeight = 128.0;
	private const double KeyboardTopOffset = 14.0;
	private const double KeyWidth = 18.0;
	private const double KeyHeight = 7.0;
	private const double KeySpacing = 5.0;
	private const double BottomTextReservedHeight = 92.0;
	private const double BottomTextPadding = 14.0;

	private readonly Canvas _canvas = new();
	private readonly Line _horizonLine = new();
	private readonly Line _verticalLine = new();
	private readonly Ellipse _centerDot = new();
	private readonly Polygon _groundShadow = new();
	private readonly Polygon _screenLid = new();
	private readonly Polygon _screenPanel = new();
	private readonly Polygon _hinge = new();
	private readonly Polygon _baseTop = new();
	private readonly Polygon _baseFront = new();
	private readonly Rectangle _trackpad = new();
	private readonly List<Rectangle> _keys = new(36);
	private readonly TextBlock _titleTextBlock = new();
	private readonly TextBlock _statusTextBlock = new();
	private readonly TextBlock _accelerationTextBlock = new();
	private readonly SolidColorBrush _gridBrush = new(Color.FromArgb(70, 75, 216, 182));
	private readonly SolidColorBrush _accentBrush = new(Color.FromArgb(255, 75, 216, 182));
	private readonly SolidColorBrush _screenShellBrush = new(Color.FromArgb(235, 18, 27, 46));
	private readonly SolidColorBrush _screenPanelBrush = new(Color.FromArgb(235, 8, 16, 30));
	private readonly SolidColorBrush _baseTopBrush = new(Color.FromArgb(240, 24, 34, 54));
	private readonly SolidColorBrush _baseFrontBrush = new(Color.FromArgb(240, 14, 20, 34));
	private readonly SolidColorBrush _keyboardBrush = new(Color.FromArgb(230, 5, 10, 18));
	private readonly SolidColorBrush _trackpadBrush = new(Color.FromArgb(210, 38, 52, 78));
	private readonly SolidColorBrush _shadowBrush = new(Color.FromArgb(82, 0, 0, 0));

	internal HomePhysicalOrientationView()
	{
		Background = new SolidColorBrush(Colors.Transparent);
		Children.Add(_canvas);
		CreateVisuals();
		SizeChanged += OnSizeChanged;
	}

	internal double PitchDegrees
	{
		get => (double)GetValue(PitchDegreesProperty);
		set => SetValue(PitchDegreesProperty, value);
	}

	internal static readonly DependencyProperty PitchDegreesProperty = DependencyProperty.Register(nameof(PitchDegrees), typeof(double), typeof(HomePhysicalOrientationView), new PropertyMetadata(0.0, OnOrientationPropertyChanged));

	internal double RollDegrees
	{
		get => (double)GetValue(RollDegreesProperty);
		set => SetValue(RollDegreesProperty, value);
	}

	internal static readonly DependencyProperty RollDegreesProperty = DependencyProperty.Register(nameof(RollDegrees), typeof(double), typeof(HomePhysicalOrientationView), new PropertyMetadata(0.0, OnOrientationPropertyChanged));

	internal double YawDegrees
	{
		get => (double)GetValue(YawDegreesProperty);
		set => SetValue(YawDegreesProperty, value);
	}

	internal static readonly DependencyProperty YawDegreesProperty = DependencyProperty.Register(nameof(YawDegrees), typeof(double), typeof(HomePhysicalOrientationView), new PropertyMetadata(0.0, OnOrientationPropertyChanged));

	internal double AccelerationX { get; set; }
	internal double AccelerationY { get; set; }
	internal double AccelerationZ { get; set; }
	internal double AngularVelocityX { get; set; }
	internal double AngularVelocityY { get; set; }
	internal double AngularVelocityZ { get; set; }
	internal string GyrometerText { get; set; } = "Gyro unavailable";
	internal string OrientationText { get; set; } = "Unavailable";
	internal string StatusText { get; set; } = "Initializing sensors...";

	private void CreateVisuals()
	{
		_horizonLine.Stroke = _gridBrush;
		_horizonLine.StrokeThickness = 1.0;
		_verticalLine.Stroke = _gridBrush;
		_verticalLine.StrokeThickness = 1.0;
		_groundShadow.Fill = _shadowBrush;
		_screenLid.Fill = _screenShellBrush;
		_screenLid.Stroke = _accentBrush;
		_screenLid.StrokeThickness = 1.4;
		_screenPanel.Fill = _screenPanelBrush;
		_screenPanel.Stroke = new SolidColorBrush(Color.FromArgb(120, 75, 216, 182));
		_screenPanel.StrokeThickness = 1.0;
		_hinge.Fill = _accentBrush;
		_hinge.Opacity = 0.72;
		_baseTop.Fill = _baseTopBrush;
		_baseTop.Stroke = _accentBrush;
		_baseTop.StrokeThickness = 1.4;
		_baseFront.Fill = _baseFrontBrush;
		_baseFront.Stroke = new SolidColorBrush(Color.FromArgb(130, 75, 216, 182));
		_baseFront.StrokeThickness = 1.0;
		_centerDot.Width = 8.0;
		_centerDot.Height = 8.0;
		_centerDot.Fill = _accentBrush;
		_trackpad.Fill = _trackpadBrush;
		_trackpad.Stroke = new SolidColorBrush(Color.FromArgb(140, 75, 216, 182));
		_trackpad.StrokeThickness = 1.0;
		_trackpad.RadiusX = 4.0;
		_trackpad.RadiusY = 4.0;
		_titleTextBlock.Text = "Laptop attitude";
		_titleTextBlock.FontSize = 16.0;
		_titleTextBlock.FontWeight = Microsoft.UI.Text.FontWeights.SemiBold;
		_statusTextBlock.TextWrapping = TextWrapping.Wrap;
		_statusTextBlock.Opacity = 0.84;
		_accelerationTextBlock.FontSize = 12.0;
		_accelerationTextBlock.Opacity = 0.72;

		_canvas.Children.Add(_horizonLine);
		_canvas.Children.Add(_verticalLine);
		_canvas.Children.Add(_groundShadow);
		_canvas.Children.Add(_screenLid);
		_canvas.Children.Add(_screenPanel);
		_canvas.Children.Add(_hinge);
		_canvas.Children.Add(_baseTop);
		_canvas.Children.Add(_baseFront);
		CreateKeyboardKeys();
		_canvas.Children.Add(_trackpad);
		_canvas.Children.Add(_centerDot);
		_canvas.Children.Add(_titleTextBlock);
		_canvas.Children.Add(_statusTextBlock);
		_canvas.Children.Add(_accelerationTextBlock);
	}

	private void CreateKeyboardKeys()
	{
		for (int row = 0; row < 4; row++)
		{
			int keysInRow = row == 3 ? 6 : 10;
			for (int column = 0; column < keysInRow; column++)
			{
				Rectangle key = new()
				{
					Fill = _keyboardBrush,
					RadiusX = 2.0,
					RadiusY = 2.0,
					Width = row == 3 && column == 2 ? 58.0 : KeyWidth,
					Height = KeyHeight,
					Opacity = 0.9
				};
				_keys.Add(key);
				_canvas.Children.Add(key);
			}
		}
	}

	private static void OnOrientationPropertyChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs args)
	{
		HomePhysicalOrientationView view = (HomePhysicalOrientationView)dependencyObject;
		view.RenderOrientation();
	}

	private void OnSizeChanged(object sender, SizeChangedEventArgs args) => RenderOrientation();

	private void RenderOrientation()
	{
		double width = ActualWidth;
		double height = ActualHeight;
		if (width <= 0.0 || height <= 0.0)
		{
			return;
		}

		double centerX = width / 2.0;
		double drawableHeight = Math.Max(180.0, height - BottomTextReservedHeight);
		double centerY = (drawableHeight / 2.0) + 24.0;
		double scale = Math.Max(0.74, Math.Min(width, drawableHeight) / 420.0);
		double pitch = Math.Clamp(PitchDegrees, -MaximumVisualTiltDegrees, MaximumVisualTiltDegrees);
		double roll = Math.Clamp(RollDegrees, -MaximumVisualTiltDegrees, MaximumVisualTiltDegrees);
		double yaw = NormalizeYaw(YawDegrees);
		double rollRadians = roll * Math.PI / 180.0;
		double yawRadians = yaw * Math.PI / 180.0;
		double yawSkew = Math.Sin(yawRadians) * 32.0 * scale;
		double pitchOffset = Math.Clamp(pitch / MaximumVisualTiltDegrees, -1.0, 1.0) * 58.0 * scale;

		_horizonLine.X1 = 24.0;
		_horizonLine.Y1 = centerY;
		_horizonLine.X2 = width - 24.0;
		_horizonLine.Y2 = centerY;
		_verticalLine.X1 = centerX;
		_verticalLine.Y1 = 58.0;
		_verticalLine.X2 = centerX;
		_verticalLine.Y2 = Math.Max(58.0, drawableHeight - 8.0);

		SetPolygon(_groundShadow, TransformPoints(centerX, centerY + 62.0 * scale, scale, rollRadians, pitchOffset, yawSkew * 0.35, new Point(-122.0, 32.0), new Point(122.0, 32.0), new Point(152.0, 82.0), new Point(-152.0, 82.0)));
		SetPolygon(_screenLid, TransformPoints(centerX, centerY, scale, rollRadians, pitchOffset, yawSkew, new Point(-122.0, -158.0), new Point(122.0, -158.0), new Point(112.0, -28.0), new Point(-112.0, -28.0)));
		SetPolygon(_screenPanel, TransformPoints(centerX, centerY, scale, rollRadians, pitchOffset, yawSkew, new Point(-102.0, -144.0), new Point(102.0, -144.0), new Point(94.0, -44.0), new Point(-94.0, -44.0)));
		SetPolygon(_hinge, TransformPoints(centerX, centerY, scale, rollRadians, pitchOffset, yawSkew * 0.45, new Point(-98.0, -24.0), new Point(98.0, -24.0), new Point(106.0, -14.0), new Point(-106.0, -14.0)));
		SetPolygon(_baseTop, TransformPoints(centerX, centerY, scale, rollRadians, pitchOffset, yawSkew, new Point(-LaptopWidth / 2.0, -10.0), new Point(LaptopWidth / 2.0, -10.0), new Point(LaptopWidth / 2.0 + 35.0, BaseFrontDepth), new Point(-LaptopWidth / 2.0 - 35.0, BaseFrontDepth)));
		SetPolygon(_baseFront, TransformPoints(centerX, centerY, scale, rollRadians, pitchOffset, yawSkew, new Point(-LaptopWidth / 2.0 - 35.0, BaseFrontDepth), new Point(LaptopWidth / 2.0 + 35.0, BaseFrontDepth), new Point(LaptopWidth / 2.0 + 18.0, BaseFrontDepth + 18.0), new Point(-LaptopWidth / 2.0 - 18.0, BaseFrontDepth + 18.0)));
		RenderKeyboard(centerX, centerY, scale, rollRadians, pitchOffset, yawSkew);
		RenderTrackpad(centerX, centerY, scale, rollRadians, pitchOffset, yawSkew);

		Canvas.SetLeft(_centerDot, centerX - 4.0);
		Canvas.SetTop(_centerDot, centerY - 4.0);
		Canvas.SetLeft(_titleTextBlock, 16.0);
		Canvas.SetTop(_titleTextBlock, 12.0);
		_accelerationTextBlock.Text = "G vector X " + AccelerationX.ToString("0.000", CultureInfo.InvariantCulture) + "  Y " + AccelerationY.ToString("0.000", CultureInfo.InvariantCulture) + "  Z " + AccelerationZ.ToString("0.000", CultureInfo.InvariantCulture);
		Canvas.SetLeft(_accelerationTextBlock, BottomTextPadding);
		Canvas.SetTop(_accelerationTextBlock, height - 48.0);
		_statusTextBlock.Text = StatusText + "   Pitch " + pitch.ToString("0.0", CultureInfo.InvariantCulture) + "°   Roll " + roll.ToString("0.0", CultureInfo.InvariantCulture) + "°   Yaw " + yaw.ToString("0.0", CultureInfo.InvariantCulture) + "°   " + GyrometerText + "   " + OrientationText;
		_statusTextBlock.Width = Math.Max(120.0, width - (BottomTextPadding * 2.0));
		Canvas.SetLeft(_statusTextBlock, BottomTextPadding);
		Canvas.SetTop(_statusTextBlock, height - 27.0);
	}

	private void RenderKeyboard(double centerX, double centerY, double scale, double rollRadians, double pitchOffset, double yawSkew)
	{
		int keyIndex = 0;
		for (int row = 0; row < 4; row++)
		{
			int keysInRow = row == 3 ? 6 : 10;
			double rowWidth = row == 3 ? 162.0 : (keysInRow * KeyWidth) + ((keysInRow - 1) * KeySpacing);
			double startX = -rowWidth / 2.0 + (row % 2 == 0 ? 0.0 : 8.0);
			double y = KeyboardTopOffset + (row * 13.0);
			for (int column = 0; column < keysInRow; column++)
			{
				Rectangle key = _keys[keyIndex];
				double keyWidth = row == 3 && column == 2 ? 58.0 : KeyWidth;
				Point position = TransformPoint(centerX, centerY, scale, rollRadians, pitchOffset, yawSkew, new Point(startX + (keyWidth / 2.0), y));
				key.Width = Math.Max(3.0, keyWidth * scale);
				key.Height = Math.Max(2.0, KeyHeight * scale);
				key.RenderTransformOrigin = new Point(0.5, 0.5);
				key.RenderTransform = new RotateTransform { Angle = RollDegrees };
				Canvas.SetLeft(key, position.X - (key.Width / 2.0));
				Canvas.SetTop(key, position.Y - (key.Height / 2.0));
				startX += keyWidth + KeySpacing;
				keyIndex++;
			}
		}
	}

	private void RenderTrackpad(double centerX, double centerY, double scale, double rollRadians, double pitchOffset, double yawSkew)
	{
		Point position = TransformPoint(centerX, centerY, scale, rollRadians, pitchOffset, yawSkew, new Point(0.0, 58.0));
		_trackpad.Width = 62.0 * scale;
		_trackpad.Height = 28.0 * scale;
		_trackpad.RenderTransformOrigin = new Point(0.5, 0.5);
		_trackpad.RenderTransform = new RotateTransform { Angle = RollDegrees };
		Canvas.SetLeft(_trackpad, position.X - (_trackpad.Width / 2.0));
		Canvas.SetTop(_trackpad, position.Y - (_trackpad.Height / 2.0));
	}

	private static double NormalizeYaw(double yaw)
	{
		double normalizedYaw = yaw % 360.0;
		if (normalizedYaw > 180.0)
		{
			normalizedYaw -= 360.0;
		}
		else if (normalizedYaw < -180.0)
		{
			normalizedYaw += 360.0;
		}
		return normalizedYaw;
	}

	private static Point[] TransformPoints(double centerX, double centerY, double scale, double rollRadians, double pitchOffset, double yawSkew, params Point[] points)
	{
		Point[] result = new Point[points.Length];
		for (int index = 0; index < points.Length; index++)
		{
			result[index] = TransformPoint(centerX, centerY, scale, rollRadians, pitchOffset, yawSkew, points[index]);
		}
		return result;
	}

	private static Point TransformPoint(double centerX, double centerY, double scale, double rollRadians, double pitchOffset, double yawSkew, Point point)
	{
		double depthRatio = Math.Clamp((point.Y + ScreenHeight) / (ScreenHeight + BaseFrontDepth + BaseBackDepth), 0.0, 1.0);
		double x = (point.X * scale) + (yawSkew * depthRatio);
		double y = (point.Y * scale) + pitchOffset;
		double cos = Math.Cos(rollRadians);
		double sin = Math.Sin(rollRadians);
		return new Point(centerX + (x * cos) - (y * sin), centerY + (x * sin) + (y * cos));
	}

	private static void SetPolygon(Polygon polygon, Point[] points)
	{
		polygon.Points.Clear();
		for (int index = 0; index < points.Length; index++)
		{
			polygon.Points.Add(points[index]);
		}
	}
}
