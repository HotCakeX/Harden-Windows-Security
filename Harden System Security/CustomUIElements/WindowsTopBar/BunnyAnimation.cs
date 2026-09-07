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

using System.Diagnostics;
using System.Numerics;
using Microsoft.Graphics.Canvas;
using Microsoft.Graphics.Canvas.Geometry;
using Microsoft.Graphics.Canvas.UI.Xaml;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Windows.UI;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

// A self-contained bunny animation control. While loaded, the XAML composition callback invalidates
// its CanvasControl and its Stopwatch supplies animation time. Unloading stops callbacks and releases
// the canvas and cached geometry resources.
internal sealed partial class BunnyAnimation : UserControl
{
	private const double BunnyCycleSeconds = 2.0;
	private const float BunnyFineDetailScale = 0.15f;
	private CanvasControl? _bunnyCanvas;
	private readonly Stopwatch _animationClock = new();
	private static readonly Color LightPink = Color.FromArgb(255, 255, 221, 226);
	private static readonly Color Beige = Color.FromArgb(255, 246, 232, 230);
	private static readonly Color Grey = Color.FromArgb(255, 129, 129, 129);
	private static readonly Color White = Color.FromArgb(255, 255, 255, 255);

	// Cached device geometry. The ear arch and inner ear never change shape
	// (only their rotation transform does), so they are built once per device
	// and reused, leaving the per-frame work to a couple of matrix sets and
	// FillGeometry calls. Everything else is a cheap primitive (ellipse/rect).
	private CanvasDevice? _bunnyResourceDevice;
	private CanvasGeometry? _earGeometry;
	private CanvasGeometry? _innerEarGeometry;

	internal BunnyAnimation()
	{
		IsTabStop = false;
		Loaded += OnBunnyLoaded;
		Unloaded += OnBunnyUnloaded;
	}

	// Lazily create the canvas and subscribe to XAML composition frames while loaded.
	private void OnBunnyLoaded(object sender, RoutedEventArgs e)
	{
		if (!_animationClock.IsRunning)
		{
			_animationClock.Start();
			CompositionTarget.Rendering += OnAnimationRendering;
		}
		if (_bunnyCanvas is null)
		{
			_bunnyCanvas = CreateBunnyCanvas();
			Content = _bunnyCanvas;
		}
	}

	// Stop frame callbacks and release the CanvasControl and cached geometry when disconnected from XAML.
	private void OnBunnyUnloaded(object sender, RoutedEventArgs e)
	{
		CompositionTarget.Rendering -= OnAnimationRendering;
		_animationClock.Stop();
		DisposeBunnyGeometries();

		if (_bunnyCanvas is not null)
		{
			_bunnyCanvas.Draw -= OnBunnyCanvasDraw;
			_bunnyCanvas.RemoveFromVisualTree();
			_bunnyCanvas = null;
		}

		Content = null;
	}

	private void OnAnimationRendering(object? sender, object e) => _bunnyCanvas?.Invalidate();

	private CanvasControl CreateBunnyCanvas()
	{
		CanvasControl canvas = new()
		{
			ClearColor = Color.FromArgb(0, 0, 0, 0),
			Background = null,
			// Force LTR so an RTL host does not mirror the Win2D coordinate space.
			FlowDirection = FlowDirection.LeftToRight,
			HorizontalAlignment = HorizontalAlignment.Stretch,
			VerticalAlignment = VerticalAlignment.Stretch,
			IsHitTestVisible = false
		};

		canvas.Draw += OnBunnyCanvasDraw;
		return canvas;
	}

	// Draw the current frame using elapsed time from the control-owned Stopwatch.
	private void OnBunnyCanvasDraw(CanvasControl sender, CanvasDrawEventArgs args)
	{
		float width = (float)sender.Size.Width;
		float height = (float)sender.Size.Height;

		if (width < 2.0f || height < 2.0f)
		{
			return;
		}

		EnsureBunnyResources(sender);

		// Fit the character bounds.
		const float artworkLeft = 180.0f;
		const float artworkTop = 28.0f;
		const float artworkWidth = 198.0f;
		const float artworkHeight = 288.0f;
		float scale = MathF.Min(width / artworkWidth, height / artworkHeight);
		float offsetX = ((width - artworkWidth * scale) * 0.5f) - artworkLeft * scale;
		float offsetY = ((height - artworkHeight * scale) * 0.5f) - artworkTop * scale;
		bool showFineDetails = scale >= BunnyFineDetailScale;

		CanvasDrawingSession drawingSession = args.DrawingSession;
		Matrix3x2 baseTransform = Matrix3x2.CreateScale(scale) * Matrix3x2.CreateTranslation(offsetX, offsetY);
		drawingSession.Transform = baseTransform;

		float progress = (float)(_animationClock.Elapsed.TotalSeconds % BunnyCycleSeconds / BunnyCycleSeconds);

		drawingSession.FillEllipse(new Vector2(279.0f, 231.0f), 99.0f, 84.0f, Beige);

		DrawEar(drawingSession, baseTransform, true, progress);
		DrawEar(drawingSession, baseTransform, false, progress);

		DrawNose(drawingSession, showFineDetails);
		DrawBlushes(drawingSession);
		DrawEyes(drawingSession, showFineDetails);
	}

	// Lazily builds the cached geometry for the current device and rebuilds it if the device is
	// lost and replaced. The geometry is disposed on unload; on a later reload the next Draw
	// rebuilds it here transparently.
	private void EnsureBunnyResources(CanvasControl sender)
	{
		CanvasDevice device = sender.Device;

		if (_bunnyResourceDevice == device && _earGeometry != null)
		{
			return;
		}

		DisposeBunnyGeometries();
		_bunnyResourceDevice = device;
		BuildBunnyGeometries(sender);
	}

	private void BuildBunnyGeometries(ICanvasResourceCreator resourceCreator)
	{
		_earGeometry = BuildEar(resourceCreator);
		_innerEarGeometry = BuildInnerEar(resourceCreator);
	}

	private void DisposeBunnyGeometries()
	{
		_earGeometry?.Dispose();
		_earGeometry = null;
		_innerEarGeometry?.Dispose();
		_innerEarGeometry = null;
		_bunnyResourceDevice = null;
	}

	private static CanvasGeometry BuildEar(ICanvasResourceCreator resourceCreator)
	{
		const float w = 65.34f;
		const float h = 134.4f;
		const float rx = 32.67f;
		const float ry = 67.2f;

		using CanvasPathBuilder pathBuilder = new(resourceCreator);
		pathBuilder.BeginFigure(0.0f, h);
		pathBuilder.AddLine(0.0f, ry);
		pathBuilder.AddArc(new Vector2(rx, 0.0f), rx, ry, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.AddArc(new Vector2(w, ry), rx, ry, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.AddLine(w, h);
		pathBuilder.EndFigure(CanvasFigureLoop.Closed);

		return CanvasGeometry.CreatePath(pathBuilder);
	}

	private static CanvasGeometry BuildInnerEar(ICanvasResourceCreator resourceCreator)
	{
		const float x = 9.801f;
		const float y = 16.128f;
		const float w = 45.738f;
		const float h = 103.488f;
		const float topRx = 22.869f;
		const float topRy = 51.744f;
		const float botRx = 4.5738f;
		const float botRy = 10.3488f;

		using CanvasPathBuilder pathBuilder = new(resourceCreator);
		pathBuilder.BeginFigure(x, y + topRy);
		pathBuilder.AddArc(new Vector2(x + topRx, y), topRx, topRy, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.AddArc(new Vector2(x + w, y + topRy), topRx, topRy, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.AddLine(x + w, y + h - botRy);
		pathBuilder.AddArc(new Vector2(x + w - botRx, y + h), botRx, botRy, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.AddLine(x + botRx, y + h);
		pathBuilder.AddArc(new Vector2(x, y + h - botRy), botRx, botRy, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.EndFigure(CanvasFigureLoop.Closed);

		return CanvasGeometry.CreatePath(pathBuilder);
	}

	private void DrawEar(CanvasDrawingSession drawingSession, Matrix3x2 baseTransform, bool left, float progress)
	{
		const float earWidth = 65.34f;
		const float earHeight = 134.4f;
		float earPosX = left ? 199.8f : 292.86f;
		const float earPosY = 46.2f;

		EarTransform earTransform = GetEarTransform(progress, left);
		Vector2 originLocal = new(earTransform.OriginX, earHeight);

		drawingSession.Transform =
			Matrix3x2.CreateRotation(earTransform.RotationRadians, originLocal) *
			Matrix3x2.CreateTranslation(earPosX, earPosY) *
			baseTransform;

		drawingSession.FillGeometry(_earGeometry, Beige);

		if (left)
		{
			drawingSession.FillGeometry(_innerEarGeometry, LightPink);
		}
		else
		{
			Matrix3x2 mirror = Matrix3x2.CreateScale(-1.0f, 1.0f, new Vector2(earWidth * 0.5f, 0.0f));
			drawingSession.Transform =
				mirror *
				Matrix3x2.CreateRotation(earTransform.RotationRadians, originLocal) *
				Matrix3x2.CreateTranslation(earPosX, earPosY) *
				baseTransform;
			drawingSession.FillGeometry(_innerEarGeometry, LightPink);
		}

		drawingSession.Transform = baseTransform;
	}

	private static void DrawNose(CanvasDrawingSession drawingSession, bool showFineDetails)
	{
		drawingSession.FillEllipse(new Vector2(278.58f, 252.8f), 7.5f, 5.0f, Grey);

		if (showFineDetails)
		{
			drawingSession.FillRectangle(new Rect(276.63, 249.8, 4.0, 20.0), Grey);
		}
	}

	private static void DrawBlushes(CanvasDrawingSession drawingSession)
	{
		drawingSession.FillEllipse(new Vector2(220.59f, 257.88f), 14.85f, 11.76f, LightPink);
		drawingSession.FillEllipse(new Vector2(337.41f, 257.88f), 14.85f, 11.76f, LightPink);
	}

	private static void DrawEyes(CanvasDrawingSession drawingSession, bool showFineDetails)
	{
		drawingSession.FillEllipse(new Vector2(229.6f, 241.0f), 10.0f, 10.0f, Grey);
		drawingSession.FillEllipse(new Vector2(328.4f, 241.0f), 10.0f, 10.0f, Grey);

		if (showFineDetails)
		{
			drawingSession.FillEllipse(new Vector2(228.2f, 238.0f), 4.0f, 4.0f, White);
			drawingSession.FillEllipse(new Vector2(327.0f, 238.0f), 4.0f, 4.0f, White);
		}
	}

	private readonly struct EarTransform(float rotationRadians, float originX)
	{
		internal float RotationRadians => rotationRadians;
		internal float OriginX => originX;
	}

	private static EarTransform GetEarTransform(float progress, bool left)
	{
		const float earWidth = 65.34f;
		ReadOnlySpan<float> times = [0.0f, 0.5f, 1.0f];

		if (left)
		{
			ReadOnlySpan<float> angles = [-20.0f, -25.0f, -20.0f];
			ReadOnlySpan<float> originsX = [0.0f, earWidth * 0.5f, 0.0f];
			return new EarTransform(SampleKeyframes(progress, times, angles) * MathF.PI / 180.0f, SampleKeyframes(progress, times, originsX));
		}

		ReadOnlySpan<float> anglesRight = [20.0f, 25.0f, 20.0f];
		ReadOnlySpan<float> originsXRight = [earWidth, earWidth * 0.5f, earWidth];
		return new EarTransform(SampleKeyframes(progress, times, anglesRight) * MathF.PI / 180.0f, SampleKeyframes(progress, times, originsXRight));
	}

	private static float SampleKeyframes(float progress, ReadOnlySpan<float> times, ReadOnlySpan<float> values)
	{
		int upperIndex = 1;
		while (upperIndex < times.Length && progress > times[upperIndex]) upperIndex++;
		if (upperIndex >= times.Length) return values[^1];
		int lowerIndex = upperIndex - 1;
		float duration = times[upperIndex] - times[lowerIndex];
		float localProgress = duration > 0.0f ? (progress - times[lowerIndex]) / duration : 0.0f;
		return Lerp(values[lowerIndex], values[upperIndex], Ease(localProgress));
	}

	private static float Ease(float value)
	{
		float x = Math.Clamp(value, 0.0f, 1.0f);
		float parameter = x;
		for (int index = 0; index < 6; index++)
		{
			float inverse = 1.0f - parameter;
			float estimate = 3.0f * inverse * inverse * parameter * 0.25f +
							 3.0f * inverse * parameter * parameter * 0.25f +
							 parameter * parameter * parameter;
			float derivative = 3.0f * inverse * inverse * 0.25f +
							   6.0f * inverse * parameter * (0.25f - 0.25f) +
							   3.0f * parameter * parameter * (1.0f - 0.25f);
			if (MathF.Abs(derivative) < 0.0001f) break;
			parameter = Math.Clamp(parameter - (estimate - x) / derivative, 0.0f, 1.0f);
		}

		float remaining = 1.0f - parameter;
		return 3.0f * remaining * remaining * parameter * 0.1f +
			   3.0f * remaining * parameter * parameter +
			   parameter * parameter * parameter;
	}

	private static float Lerp(float start, float end, float amount) => start + (end - start) * amount;
}
