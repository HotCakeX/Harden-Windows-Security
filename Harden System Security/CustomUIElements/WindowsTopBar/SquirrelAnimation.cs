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

// A self-contained animation control. While loaded, the XAML composition callback invalidates
// its CanvasControl and its Stopwatch supplies animation time. Unloading stops callbacks and releases
// the canvas and cached geometry resources.
internal sealed partial class SquirrelAnimation : UserControl
{
	private const double SquirrelCycleSeconds = 5.0;

	// Below this design-to-DIP scale the hairline decorative accents are skipped (invisible there).
	private const float SquirrelFineDetailScale = 0.28f;

	private CanvasControl? _squirrelCanvas;
	private readonly Stopwatch _animationClock = new();
	private static readonly Color Tan = Color.FromArgb(255, 204, 133, 53);
	private static readonly Color TailBrown = Color.FromArgb(255, 124, 83, 39);
	private static readonly Color LogBrown = Color.FromArgb(255, 121, 63, 26);
	private static readonly Color Black = Color.FromArgb(255, 0, 0, 0);
	private static readonly Color White = Color.FromArgb(255, 255, 255, 255);
	private static readonly Color BodyTopEdge = Color.FromArgb(255, 125, 77, 31);
	private static readonly Color HighlightLight = Color.FromArgb(255, 224, 170, 96);
	private static readonly Color EarShade = Color.FromArgb(255, 124, 77, 31);
	private static readonly Color EarLight = Color.FromArgb(255, 230, 178, 105);
	private static readonly Color TailHair = Color.FromArgb(255, 219, 179, 128);
	private static readonly Color LogKnot = Color.FromArgb(255, 222, 178, 107);
	private static readonly Color LogLine = Color.FromArgb(255, 52, 33, 19);
	private static readonly Color EyeGrey = Color.FromArgb(255, 114, 108, 108);
	private static readonly Color HeadBottomShade = Color.FromArgb(255, 127, 82, 43);
	private static readonly Color LogRim = Color.FromArgb(255, 34, 34, 34);

	// Cached device geometry (built once per device, reused every frame).
	private CanvasDevice? _squirrelResourceDevice;
	private CanvasGeometry? _bodyGeometry;
	private CanvasGeometry? _headGeometry;
	private CanvasGeometry? _logGeometry;
	private CanvasGeometry? _footGeometry;
	private CanvasGeometry? _tailGeometry;
	private CanvasGeometry? _mouthGeometry;
	private CanvasGeometry? _mouthBeforeGeometry;
	private CanvasGeometry? _mouthBeforeOutline;
	private CanvasGeometry? _mouthAfterGeometry;
	private CanvasGeometry? _mouthAfterOutline;
	private CanvasGeometry? _pawFill;
	private CanvasGeometry? _paw2Fill;
	private CanvasGeometry? _paw2Outline;
	private CanvasGeometry? _eyeLeftClip;
	private CanvasGeometry? _eyeRightClip;

	internal SquirrelAnimation()
	{
		IsTabStop = false;
		Loaded += OnSquirrelLoaded;
		Unloaded += OnSquirrelUnloaded;
	}

	private void OnSquirrelLoaded(object sender, RoutedEventArgs e)
	{
		if (!_animationClock.IsRunning)
		{
			_animationClock.Start();
			CompositionTarget.Rendering += OnAnimationRendering;
		}
		if (_squirrelCanvas is null)
		{
			_squirrelCanvas = CreateSquirrelCanvas();
			Content = _squirrelCanvas;
		}
	}

	private void OnSquirrelUnloaded(object sender, RoutedEventArgs e)
	{
		CompositionTarget.Rendering -= OnAnimationRendering;
		_animationClock.Stop();
		DisposeSquirrelGeometries();

		if (_squirrelCanvas is not null)
		{
			_squirrelCanvas.Draw -= OnSquirrelCanvasDraw;
			_squirrelCanvas.RemoveFromVisualTree();
			_squirrelCanvas = null;
		}

		Content = null;
	}

	private void OnAnimationRendering(object? sender, object e) => _squirrelCanvas?.Invalidate();

	private CanvasControl CreateSquirrelCanvas()
	{
		CanvasControl canvas = new()
		{
			ClearColor = Color.FromArgb(0, 0, 0, 0),
			Background = null,
			FlowDirection = FlowDirection.LeftToRight,
			HorizontalAlignment = HorizontalAlignment.Stretch,
			VerticalAlignment = VerticalAlignment.Stretch,
			IsHitTestVisible = false
		};

		canvas.Draw += OnSquirrelCanvasDraw;
		return canvas;
	}

	private void OnSquirrelCanvasDraw(CanvasControl sender, CanvasDrawEventArgs args)
	{
		float width = (float)sender.Size.Width;
		float height = (float)sender.Size.Height;

		if (width < 2.0f || height < 2.0f)
		{
			return;
		}

		EnsureSquirrelResources(sender);

		const float artworkLeft = 0.0f;
		const float artworkTop = 27.0f;
		const float artworkWidth = 250.0f;
		const float artworkHeight = 160.0f;
		float scale = MathF.Min(width / artworkWidth, height / artworkHeight);
		float offsetX = ((width - artworkWidth * scale) * 0.5f) - artworkLeft * scale;
		float offsetY = ((height - artworkHeight * scale) * 0.5f) - artworkTop * scale;
		bool showFineDetails = scale >= SquirrelFineDetailScale;

		CanvasDrawingSession drawingSession = args.DrawingSession;
		Matrix3x2 baseTransform = Matrix3x2.CreateScale(scale) * Matrix3x2.CreateTranslation(offsetX, offsetY);
		drawingSession.Transform = baseTransform;

		float progress = (float)(_animationClock.Elapsed.TotalSeconds % SquirrelCycleSeconds / SquirrelCycleSeconds);

		DrawTail(drawingSession, baseTransform, showFineDetails);
		DrawBody(drawingSession, showFineDetails);
		DrawLog(drawingSession, baseTransform, showFineDetails);
		DrawArm(drawingSession, baseTransform);
		DrawEarRight(drawingSession, showFineDetails);
		DrawHead(drawingSession, baseTransform, progress, showFineDetails);
		DrawFoot(drawingSession, baseTransform, showFineDetails);
	}

	private void EnsureSquirrelResources(CanvasControl sender)
	{
		CanvasDevice device = sender.Device;

		if (_squirrelResourceDevice == device && _bodyGeometry != null)
		{
			return;
		}

		DisposeSquirrelGeometries();
		_squirrelResourceDevice = device;
		BuildSquirrelGeometries(sender);
	}

	private void BuildSquirrelGeometries(ICanvasResourceCreator resourceCreator)
	{
		_bodyGeometry = CreateRoundedRectXY(resourceCreator, 50.0f, 42.0f, 150.0f, 130.0f,
			75.0f, 65.0f, 75.0f, 65.0f, 60.0f, 52.0f, 52.5f, 45.5f);

		_headGeometry = CanvasGeometry.CreateEllipse(resourceCreator, 173.75f, 84.25f, 56.25f, 55.25f);

		_logGeometry = CreateRoundedRectXY(resourceCreator, 0.0f, 0.0f, 90.0f, 28.6f,
			0.0f, 0.0f, 9.0f, 2.86f, 9.0f, 2.86f, 0.0f, 0.0f);

		_footGeometry = CreateRoundedRectXY(resourceCreator, 0.0f, 0.0f, 60.0f, 26.0f,
			30.0f, 13.0f, 24.0f, 10.4f, 30.0f, 13.0f, 24.0f, 10.4f);

		_tailGeometry = CreateRoundedRectXY(resourceCreator, 0.0f, 0.0f, 75.0f, 30.0f,
			15.0f, 15.0f, 15.0f, 15.0f, 15.0f, 15.0f, 15.0f, 15.0f);

		_mouthGeometry = CreateRoundedRectXY(resourceCreator, 0.0f, 0.0f, 10.125f, 11.05f,
			0.0f, 0.0f, 0.0f, 0.0f, 3.0375f, 3.315f, 4.05f, 4.42f);

		_mouthBeforeGeometry = CreateRoundedRectXY(resourceCreator, 0.0f, 0.0f, 8.1f, 8.84f,
			4.05f, 4.42f, 4.05f, 4.42f, 4.05f, 4.42f, 2.43f, 2.652f);
		_mouthBeforeOutline = CreateRightBottomOutline(
			resourceCreator, 8.1f, 8.84f, 4.05f, 4.42f, 4.05f, 4.42f, 2.43f, 2.652f);

		_mouthAfterGeometry = CreateRoundedRectXY(resourceCreator, 0.0f, 0.0f, 9.1125f, 9.945f,
			4.55625f, 4.9725f, 4.55625f, 4.9725f, 2.73375f, 2.9835f, 4.55625f, 4.9725f);
		_mouthAfterOutline = CreateBottomLeftOutline(
			resourceCreator, 9.1125f, 9.945f, 2.73375f, 2.9835f, 4.55625f, 4.9725f, 4.55625f, 4.9725f);

		_pawFill = CreateRoundedRectXY(resourceCreator, 0.0f, 0.0f, 30.0f, 13.0f,
			0.0f, 0.0f, 15.0f, 6.5f, 12.0f, 5.2f, 0.0f, 0.0f);
		_paw2Fill = CreateRoundedRectXY(resourceCreator, 0.0f, 0.0f, 21.0f, 13.0f,
			0.0f, 0.0f, 10.5f, 6.5f, 8.4f, 5.2f, 0.0f, 0.0f);
		_paw2Outline = CreateDOutlineOpen(resourceCreator, 21.0f, 13.0f, 10.5f, 6.5f, 8.4f, 5.2f);

		_eyeLeftClip = CanvasGeometry.CreateEllipse(resourceCreator, 170.94f, 66.02f, 8.44f, 8.29f);
		_eyeRightClip = CanvasGeometry.CreateEllipse(resourceCreator, 221.56f, 61.6f, 8.44f, 8.29f);
	}

	private void DisposeSquirrelGeometries()
	{
		_bodyGeometry?.Dispose();
		_bodyGeometry = null;
		_headGeometry?.Dispose();
		_headGeometry = null;
		_logGeometry?.Dispose();
		_logGeometry = null;
		_footGeometry?.Dispose();
		_footGeometry = null;
		_tailGeometry?.Dispose();
		_tailGeometry = null;
		_mouthGeometry?.Dispose();
		_mouthGeometry = null;
		_mouthBeforeGeometry?.Dispose();
		_mouthBeforeGeometry = null;
		_mouthBeforeOutline?.Dispose();
		_mouthBeforeOutline = null;
		_mouthAfterGeometry?.Dispose();
		_mouthAfterGeometry = null;
		_mouthAfterOutline?.Dispose();
		_mouthAfterOutline = null;
		_pawFill?.Dispose();
		_pawFill = null;
		_paw2Fill?.Dispose();
		_paw2Fill = null;
		_paw2Outline?.Dispose();
		_paw2Outline = null;
		_eyeLeftClip?.Dispose();
		_eyeLeftClip = null;
		_eyeRightClip?.Dispose();
		_eyeRightClip = null;
		_squirrelResourceDevice = null;
	}

	private void DrawTail(CanvasDrawingSession drawingSession, Matrix3x2 baseTransform, bool showFineDetails)
	{
		Vector2 center = new(37.5f, 155.0f);
		drawingSession.Transform = Matrix3x2.CreateRotation(0.0872665f, center) * Matrix3x2.CreateTranslation(0.0f, 140.0f) * baseTransform;
		drawingSession.FillGeometry(_tailGeometry, TailBrown);
		drawingSession.DrawGeometry(_tailGeometry, Black, 3.0f);

		if (showFineDetails)
		{
			DrawArc(drawingSession, new Vector2(20.0f, 15.0f), 12.0f, 11.0f, -2.4f, 2.0f, TailHair, 2.0f);
			drawingSession.DrawLine(new Vector2(24.0f, 8.0f), new Vector2(38.0f, 22.0f), Black, 2.0f);
			drawingSession.DrawLine(new Vector2(38.0f, 8.0f), new Vector2(24.0f, 22.0f), Black, 2.0f);
		}

		drawingSession.Transform = baseTransform;
	}

	private void DrawBody(CanvasDrawingSession drawingSession, bool showFineDetails)
	{
		drawingSession.FillGeometry(_bodyGeometry, Tan);
		drawingSession.DrawGeometry(_bodyGeometry, Black, 3.0f);

		if (showFineDetails)
		{
			DrawArc(drawingSession, new Vector2(125.0f, 107.0f), 71.0f, 62.0f, 3.35f, 2.6f, BodyTopEdge, 8.0f);
		}
	}

	private void DrawLog(CanvasDrawingSession drawingSession, Matrix3x2 baseTransform, bool showFineDetails)
	{
		Vector2 center = new(45.0f, 14.3f);
		drawingSession.Transform = Matrix3x2.CreateRotation(-0.0872665f, center) * Matrix3x2.CreateTranslation(140.0f, 152.5f) * baseTransform;

		drawingSession.FillGeometry(_logGeometry, LogBrown);
		drawingSession.DrawGeometry(_logGeometry, Black, 3.0f);

		drawingSession.FillEllipse(new Vector2(6.0f, 14.3f), 8.0f, 14.3f, LogKnot);
		drawingSession.DrawEllipse(new Vector2(6.0f, 14.3f), 8.0f, 14.3f, Black, 3.0f);

		if (showFineDetails)
		{
			drawingSession.FillEllipse(new Vector2(37.0f, 20.0f), 22.0f, 1.6f, LogLine);
			drawingSession.FillEllipse(new Vector2(64.0f, 9.0f), 24.0f, 1.6f, LogLine);
			DrawArc(drawingSession, new Vector2(6.0f, 14.3f), 8.0f, 12.0f, 3.4f, 1.6f, LogRim, 2.0f);
		}

		drawingSession.Transform = baseTransform;
	}

	private void DrawArm(CanvasDrawingSession drawingSession, Matrix3x2 baseTransform)
	{
		drawingSession.Transform = Matrix3x2.CreateRotation(0.349066f, new Vector2(15.0f, 6.5f)) * Matrix3x2.CreateTranslation(180.5f, 142.8f) * baseTransform;
		drawingSession.FillGeometry(_pawFill, Tan);
		drawingSession.DrawGeometry(_pawFill, Black, 2.5f);
		drawingSession.Transform = Matrix3x2.CreateRotation(0.349066f, new Vector2(10.5f, 6.5f)) * Matrix3x2.CreateTranslation(171.5f, 147.3f) * baseTransform;
		drawingSession.FillGeometry(_paw2Fill, Tan);
		drawingSession.DrawGeometry(_paw2Outline, Black, 2.5f);

		drawingSession.Transform = baseTransform;
	}

	private void DrawEarRight(CanvasDrawingSession drawingSession, bool showFineDetails)
	{
		drawingSession.FillEllipse(new Vector2(204.5f, 42.0f), 15.0f, 13.0f, Tan);
		drawingSession.DrawEllipse(new Vector2(204.5f, 42.0f), 15.0f, 13.0f, Black, 3.0f);

		if (showFineDetails)
		{
			DrawArc(drawingSession, new Vector2(204.5f, 42.0f), 11.0f, 9.5f, 2.4f, 1.4f, EarShade, 3.0f);
			DrawArc(drawingSession, new Vector2(204.5f, 42.0f), 11.0f, 9.5f, -1.0f, 1.4f, EarLight, 3.0f);
		}
	}

	private void DrawHead(CanvasDrawingSession drawingSession, Matrix3x2 baseTransform, float progress, bool showFineDetails)
	{
		drawingSession.FillEllipse(new Vector2(137.19f, 48.34f), 19.69f, 19.34f, Tan);
		drawingSession.DrawEllipse(new Vector2(137.19f, 48.34f), 19.69f, 19.34f, Black, 3.0f);
		if (showFineDetails)
		{
			DrawArc(drawingSession, new Vector2(137.19f, 48.34f), 15.0f, 14.5f, 2.9f, 1.6f, EarShade, 3.0f);
		}

		drawingSession.FillGeometry(_headGeometry, Tan);
		drawingSession.DrawGeometry(_headGeometry, Black, 3.0f);

		if (showFineDetails)
		{
			DrawArc(drawingSession, new Vector2(173.75f, 84.25f), 54.0f, 53.0f, -0.9f, 1.7f, HighlightLight, 3.0f);
			DrawArc(drawingSession, new Vector2(150.0f, 118.0f), 12.0f, 8.0f, 0.4f, 1.5f, HeadBottomShade, 3.0f);
		}

		DrawEyes(drawingSession, progress, showFineDetails);
		DrawMouth(drawingSession, baseTransform);
	}

	private void DrawEyes(CanvasDrawingSession drawingSession, float progress, bool showFineDetails)
	{
		DrawEye(drawingSession, new Vector2(170.94f, 66.02f), _eyeLeftClip!, progress, showFineDetails);
		DrawEye(drawingSession, new Vector2(221.56f, 61.6f), _eyeRightClip!, progress, showFineDetails);
	}

	private static void DrawEye(CanvasDrawingSession drawingSession, Vector2 center, CanvasGeometry clip, float progress, bool showFineDetails)
	{
		const float rx = 8.44f;
		const float ry = 8.29f;

		drawingSession.FillEllipse(center, rx, ry, Black);

		if (showFineDetails)
		{
			drawingSession.FillEllipse(new Vector2(center.X + rx * 0.45f, center.Y - ry * 0.35f), rx * 0.28f, ry * 0.28f, White);
			DrawArc(drawingSession, center, rx * 0.8f, ry * 0.8f, 2.2f, 1.8f, EyeGrey, 1.5f);
		}

		float coverFraction = GetBlinkCover(progress);
		if (coverFraction > 0.0f)
		{
			float lidY = center.Y - ry - (1.0f - coverFraction) * 2.0f * ry;
			using (drawingSession.CreateLayer(1.0f, clip))
			{
				drawingSession.FillRectangle(new Rect(center.X - rx, lidY, rx * 2.0f, ry * 2.0f), Tan);
				drawingSession.FillRectangle(new Rect(center.X - rx, lidY + ry * 2.0f - 1.5f, rx * 2.0f, 1.5f), Black);
			}
		}
	}

	private void DrawMouth(CanvasDrawingSession drawingSession, Matrix3x2 baseTransform)
	{
		drawingSession.FillEllipse(new Vector2(205.81f, 72.1f), 2.3f, 2.7f, White);
		drawingSession.DrawEllipse(new Vector2(205.81f, 72.1f), 2.3f, 2.7f, Black, 2.0f);

		Matrix3x2 mouthTransform =
			Matrix3x2.CreateRotation(-0.0872665f, new Vector2(5.0625f, 5.525f)) *
			Matrix3x2.CreateTranslation(197.375f, 84.25f) *
			baseTransform;

		drawingSession.Transform = mouthTransform;
		drawingSession.FillGeometry(_mouthGeometry, White);
		drawingSession.DrawGeometry(_mouthGeometry, Black, 2.0f);

		drawingSession.Transform =
			Matrix3x2.CreateRotation(0.698132f, new Vector2(4.05f, 4.42f)) *
			Matrix3x2.CreateTranslation(9.1125f, -8.2875f) *
			mouthTransform;
		drawingSession.FillGeometry(_mouthBeforeGeometry, Tan);
		drawingSession.DrawGeometry(_mouthBeforeOutline, Black, 2.0f);

		drawingSession.Transform = mouthTransform;
		drawingSession.DrawLine(new Vector2(6.78375f, 0.0f), new Vector2(6.78375f, 11.05f), Black, 2.0f);

		drawingSession.Transform =
			Matrix3x2.CreateRotation(-0.698132f, new Vector2(4.55625f, 4.9725f)) *
			Matrix3x2.CreateTranslation(-7.0875f, -7.735f) *
			mouthTransform;
		drawingSession.FillGeometry(_mouthAfterGeometry, Tan);
		drawingSession.DrawGeometry(_mouthAfterOutline, Black, 2.0f);

		drawingSession.Transform = baseTransform;
	}

	private void DrawFoot(CanvasDrawingSession drawingSession, Matrix3x2 baseTransform, bool showFineDetails)
	{
		Vector2 center = new(30.0f, 13.0f);
		drawingSession.Transform = Matrix3x2.CreateRotation(0.436332f, center) * Matrix3x2.CreateTranslation(65.0f, 152.5f) * baseTransform;

		drawingSession.FillRectangle(new Rect(2.0, -7.0, 44.0, 18.0), Tan);
		drawingSession.FillGeometry(_footGeometry, Tan);
		DrawArc(drawingSession, new Vector2(30.0f, 13.0f), 30.0f, 13.0f, 3.64f, 5.28f, Black, 3.0f);

		if (showFineDetails)
		{
			DrawArc(drawingSession, new Vector2(31.0f, 14.0f), 25.0f, 10.0f, -0.8f, 1.7f, HighlightLight, 3.0f);
		}

		drawingSession.Transform = baseTransform;
	}

	private static float GetBlinkCover(float progress)
	{
		if (progress <= 0.03f)
		{
			return 1.0f - progress / 0.03f;
		}

		if (progress >= 0.97f)
		{
			return (progress - 0.97f) / 0.03f;
		}

		return 0.0f;
	}

	private static void DrawArc(
		CanvasDrawingSession drawingSession,
		Vector2 centerPoint,
		float radiusX,
		float radiusY,
		float startAngle,
		float sweepAngle,
		Color color,
		float strokeWidth)
	{
		Vector2 startPoint = new(
			centerPoint.X + radiusX * MathF.Cos(startAngle),
			centerPoint.Y + radiusY * MathF.Sin(startAngle));

		using CanvasPathBuilder pathBuilder = new(drawingSession);
		pathBuilder.BeginFigure(startPoint);
		pathBuilder.AddArc(centerPoint, radiusX, radiusY, startAngle, sweepAngle);
		pathBuilder.EndFigure(CanvasFigureLoop.Open);

		using CanvasGeometry geometry = CanvasGeometry.CreatePath(pathBuilder);
		drawingSession.DrawGeometry(geometry, color, strokeWidth);
	}

	private static CanvasGeometry CreateRightBottomOutline(
		ICanvasResourceCreator resourceCreator,
		float width,
		float height,
		float topRightRx,
		float topRightRy,
		float bottomRightRx,
		float bottomRightRy,
		float bottomLeftRx,
		float bottomLeftRy)
	{
		using CanvasPathBuilder pathBuilder = new(resourceCreator);
		pathBuilder.BeginFigure(width - topRightRx, 0.0f);
		pathBuilder.AddArc(new Vector2(width, topRightRy), topRightRx, topRightRy, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.AddLine(width, height - bottomRightRy);
		pathBuilder.AddArc(new Vector2(width - bottomRightRx, height), bottomRightRx, bottomRightRy, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.AddLine(bottomLeftRx, height);
		pathBuilder.AddArc(new Vector2(0.0f, height - bottomLeftRy), bottomLeftRx, bottomLeftRy, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.EndFigure(CanvasFigureLoop.Open);
		return CanvasGeometry.CreatePath(pathBuilder);
	}

	private static CanvasGeometry CreateBottomLeftOutline(
		ICanvasResourceCreator resourceCreator,
		float width,
		float height,
		float bottomRightRx,
		float bottomRightRy,
		float bottomLeftRx,
		float bottomLeftRy,
		float topLeftRx,
		float topLeftRy)
	{
		using CanvasPathBuilder pathBuilder = new(resourceCreator);
		pathBuilder.BeginFigure(width, height - bottomRightRy);
		pathBuilder.AddArc(new Vector2(width - bottomRightRx, height), bottomRightRx, bottomRightRy, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.AddLine(bottomLeftRx, height);
		pathBuilder.AddArc(new Vector2(0.0f, height - bottomLeftRy), bottomLeftRx, bottomLeftRy, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.AddLine(0.0f, topLeftRy);
		pathBuilder.AddArc(new Vector2(topLeftRx, 0.0f), topLeftRx, topLeftRy, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.EndFigure(CanvasFigureLoop.Open);
		return CanvasGeometry.CreatePath(pathBuilder);
	}

	private static CanvasGeometry CreateDOutlineOpen(
		ICanvasResourceCreator resourceCreator,
		float width,
		float height,
		float rxTopRight,
		float ryTopRight,
		float rxBottomRight,
		float ryBottomRight)
	{
		using CanvasPathBuilder pathBuilder = new(resourceCreator);
		pathBuilder.BeginFigure(0.0f, 0.0f);
		pathBuilder.AddLine(width - rxTopRight, 0.0f);
		pathBuilder.AddArc(new Vector2(width, ryTopRight), rxTopRight, ryTopRight, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.AddLine(width, height - ryBottomRight);
		pathBuilder.AddArc(new Vector2(width - rxBottomRight, height), rxBottomRight, ryBottomRight, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.AddLine(0.0f, height);
		pathBuilder.EndFigure(CanvasFigureLoop.Open);
		return CanvasGeometry.CreatePath(pathBuilder);
	}

	private static CanvasGeometry CreateRoundedRectXY(
		ICanvasResourceCreator resourceCreator,
		float x,
		float y,
		float width,
		float height,
		float rxTopLeft,
		float ryTopLeft,
		float rxTopRight,
		float ryTopRight,
		float rxBottomRight,
		float ryBottomRight,
		float rxBottomLeft,
		float ryBottomLeft)
	{
		using CanvasPathBuilder pathBuilder = new(resourceCreator);

		pathBuilder.BeginFigure(x + rxTopLeft, y);
		pathBuilder.AddLine(x + width - rxTopRight, y);
		if (rxTopRight > 0.0f || ryTopRight > 0.0f)
		{
			pathBuilder.AddArc(new Vector2(x + width, y + ryTopRight), rxTopRight, ryTopRight, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		}

		pathBuilder.AddLine(x + width, y + height - ryBottomRight);
		if (rxBottomRight > 0.0f || ryBottomRight > 0.0f)
		{
			pathBuilder.AddArc(new Vector2(x + width - rxBottomRight, y + height), rxBottomRight, ryBottomRight, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		}

		pathBuilder.AddLine(x + rxBottomLeft, y + height);
		if (rxBottomLeft > 0.0f || ryBottomLeft > 0.0f)
		{
			pathBuilder.AddArc(new Vector2(x, y + height - ryBottomLeft), rxBottomLeft, ryBottomLeft, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		}

		pathBuilder.AddLine(x, y + ryTopLeft);
		if (rxTopLeft > 0.0f || ryTopLeft > 0.0f)
		{
			pathBuilder.AddArc(new Vector2(x + rxTopLeft, y), rxTopLeft, ryTopLeft, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		}

		pathBuilder.EndFigure(CanvasFigureLoop.Closed);
		return CanvasGeometry.CreatePath(pathBuilder);
	}
}
