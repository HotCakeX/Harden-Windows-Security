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
internal sealed partial class PopForgeAnimation : UserControl
{
	private const double PopForgeCycleSeconds = 8.0;

	// Below this design-to-DIP scale (roughly 86px tall or smaller), fine sub-pixel details are
	// skipped: they are invisible at that size and skipping them saves overdraw and avoids shimmer.
	private const float PopForgeFineDetailScale = 0.20f;

	// The owned render surface is created on Loaded and released on Unloaded.
	private CanvasControl? _popForgeCanvas;
	private readonly Stopwatch _animationClock = new();

	private static readonly Color PopForgeRed = Color.FromArgb(255, 246, 43, 65);
	private static readonly Color PopForgeRedDark = Color.FromArgb(255, 220, 12, 36);
	private static readonly Color PopForgeShadow = Color.FromArgb(255, 194, 0, 73);
	private static readonly Color PopForgeShadowDark = Color.FromArgb(255, 156, 0, 48);
	private static readonly Color PopForgeLightShadow = Color.FromArgb(255, 196, 48, 62);
	private static readonly Color White = Color.FromArgb(255, 255, 255, 255);
	private static readonly Color WhiteShadow = Color.FromArgb(255, 223, 175, 191);
	private static readonly Color Handler = Color.FromArgb(255, 240, 196, 223);
	private static readonly Color HandlerShadow = Color.FromArgb(255, 204, 152, 184);
	private static readonly Color Black = Color.FromArgb(255, 43, 51, 53);
	private static readonly Color Grey = Color.FromArgb(255, 65, 50, 57);
	private static readonly Color MouthUp = Color.FromArgb(255, 127, 27, 51);
	private static readonly Color MouthTongue = Color.FromArgb(255, 195, 0, 75);
	private static readonly Color SwitchHole = Color.FromArgb(255, 156, 7, 73);
	private static readonly Color Blush = Color.FromArgb(255, 197, 11, 34);
	private static readonly Color Bread = Color.FromArgb(255, 255, 176, 113);
	private static readonly Color BreadPicture = Color.FromArgb(255, 220, 131, 65);
	private static readonly Color BreadShadow = Color.FromArgb(255, 182, 81, 25);
	private static readonly Color BreadBubble = Color.FromArgb(255, 251, 164, 95);
	private static readonly Color BreadBubbleShadow = Color.FromArgb(255, 238, 144, 80);

	// Cached device geometry. Every shape here is invariant across frames
	// (only its color and/or transform changes), so it is built once per
	// device and reused. This removes all per-frame geometry allocation,
	// boolean combines and the ball's clip layer.
	private CanvasDevice? _popForgeResourceDevice;
	private CanvasGeometry? _bodyGeometry;
	private CanvasGeometry? _bodyBandGeometry;
	private CanvasGeometry? _legGeometry;
	private CanvasGeometry? _legDarkGeometry;
	private CanvasGeometry? _mouthGeometry;
	private CanvasGeometry? _mouthShadowGeometry;
	private CanvasGeometry? _teethGeometry;
	private CanvasGeometry? _teethInsetGeometry;
	private CanvasGeometry? _tongueGeometry;
	private CanvasGeometry? _palateGeometry;
	private CanvasGeometry? _tenseMouthGeometry;
	private CanvasGeometry? _heartGeometry;
	private CanvasGeometry? _ballGeometry;

	internal PopForgeAnimation()
	{
		IsTabStop = false;
		Loaded += OnPopForgeLoaded;
		Unloaded += OnPopForgeUnloaded;
	}

	// Lazily create the canvas and subscribe to XAML composition frames while loaded.
	private void OnPopForgeLoaded(object sender, RoutedEventArgs e)
	{
		if (!_animationClock.IsRunning)
		{
			_animationClock.Start();
			CompositionTarget.Rendering += OnAnimationRendering;
		}
		if (_popForgeCanvas is null)
		{
			_popForgeCanvas = CreatePopForgeCanvas();
			Content = _popForgeCanvas;
		}
	}

	// Stop frame callbacks and release the CanvasControl and cached geometry when disconnected from XAML.
	private void OnPopForgeUnloaded(object sender, RoutedEventArgs e)
	{
		CompositionTarget.Rendering -= OnAnimationRendering;
		_animationClock.Stop();
		DisposePopForgeGeometries();

		if (_popForgeCanvas is not null)
		{
			_popForgeCanvas.Draw -= OnPopForgeCanvasDraw;
			_popForgeCanvas.RemoveFromVisualTree();
			_popForgeCanvas = null;
		}

		Content = null;
	}

	private void OnAnimationRendering(object? sender, object e) => _popForgeCanvas?.Invalidate();

	private CanvasControl CreatePopForgeCanvas()
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

		canvas.Draw += OnPopForgeCanvasDraw;
		return canvas;
	}

	// Draw the current frame using elapsed time from the control-owned Stopwatch.
	private void OnPopForgeCanvasDraw(CanvasControl sender, CanvasDrawEventArgs args)
	{
		float width = (float)sender.Size.Width;
		float height = (float)sender.Size.Height;

		if (width < 2.0f || height < 2.0f)
		{
			return;
		}

		EnsurePopForgeResources(sender);

		// Fit the complete animated artwork extents instead of the padded 632 by 430 design canvas.
		// The negative top bound leaves room for the bread at the highest point of its animation.
		const float artworkLeft = 84.0f;
		const float artworkTop = -94.0f;
		const float artworkWidth = 466.0f;
		const float artworkHeight = 478.0f;
		float scale = MathF.Min(width / artworkWidth, height / artworkHeight);
		float offsetX = ((width - artworkWidth * scale) * 0.5f) - artworkLeft * scale;
		float offsetY = ((height - artworkHeight * scale) * 0.5f) - artworkTop * scale;
		bool showFineDetails = scale >= PopForgeFineDetailScale;

		CanvasDrawingSession drawingSession = args.DrawingSession;
		drawingSession.Transform = Matrix3x2.CreateScale(scale) * Matrix3x2.CreateTranslation(offsetX, offsetY);

		float progress = (float)(_animationClock.Elapsed.TotalSeconds % PopForgeCycleSeconds / PopForgeCycleSeconds);

		const float popForgeCanvasTop = 168.0f;

		DrawBread(drawingSession, 229.0f, popForgeCanvasTop + BreadHeartOffset(progress), true, showFineDetails);
		DrawBread(drawingSession, 327.0f, popForgeCanvasTop + BreadBallOffset(progress), false, showFineDetails);
		DrawPopForge(drawingSession, progress, showFineDetails);
	}

	// Lazily builds the cached geometry for the current device and rebuilds it if the device is
	// lost and replaced. The geometry is disposed on unload; on a later reload the next Draw
	// rebuilds it here transparently.
	private void EnsurePopForgeResources(CanvasControl sender)
	{
		CanvasDevice device = sender.Device;

		if (_popForgeResourceDevice == device && _bodyGeometry != null)
		{
			return;
		}

		DisposePopForgeGeometries();
		_popForgeResourceDevice = device;
		BuildPopForgeGeometries(sender);
	}

	private void BuildPopForgeGeometries(ICanvasResourceCreator resourceCreator)
	{
		Matrix3x2 identity = Matrix3x2.Identity;

		_bodyGeometry = CreateBodyGeometry(resourceCreator, 0.0f, 175.0f, 61.0f);
		using (CanvasGeometry bandRect = CanvasGeometry.CreateRectangle(resourceCreator, 0.0f, 0.0f, 77.0f, 175.0f))
		{
			_bodyBandGeometry = _bodyGeometry.CombineWith(bandRect, identity, CanvasGeometryCombine.Intersect);
		}

		_legGeometry = CreateRoundedRectGeometry(resourceCreator, 0.0f, 0.0f, 69.0f, 22.0f, 0.0f, 0.0f, 15.0f, 15.0f);
		using (CanvasGeometry legDarkRect = CanvasGeometry.CreateRectangle(resourceCreator, 0.0f, 0.0f, 23.0f, 22.0f))
		{
			_legDarkGeometry = _legGeometry.CombineWith(legDarkRect, identity, CanvasGeometryCombine.Intersect);
		}

		_mouthGeometry = CreateRoundedRectGeometry(resourceCreator, 180.0f, 113.0f, 76.0f, 39.0f, 6.5f, 6.5f, 32.5f, 32.5f);
		_mouthShadowGeometry = CreateRoundedRectGeometry(resourceCreator, 177.0f, 115.0f, 76.0f, 39.0f, 6.5f, 6.5f, 32.5f, 32.5f);

		// Teeth (both clipped to the mouth) and their white-shadow inset, unioned into one fill each.
		using (CanvasGeometry tooth0 = CreateRoundedRectGeometry(resourceCreator, 204.0f, 113.0f, 10.0f, 16.0f, 6.0f, 6.0f, 6.0f, 6.0f))
		using (CanvasGeometry tooth1 = CreateRoundedRectGeometry(resourceCreator, 221.0f, 113.0f, 10.0f, 16.0f, 6.0f, 6.0f, 6.0f, 6.0f))
		using (CanvasGeometry tooth0Clipped = _mouthGeometry.CombineWith(tooth0, identity, CanvasGeometryCombine.Intersect))
		using (CanvasGeometry tooth1Clipped = _mouthGeometry.CombineWith(tooth1, identity, CanvasGeometryCombine.Intersect))
		using (CanvasGeometry inset0Rect = CanvasGeometry.CreateRectangle(resourceCreator, 204.0f, 113.0f, 3.0f, 16.0f))
		using (CanvasGeometry inset1Rect = CanvasGeometry.CreateRectangle(resourceCreator, 221.0f, 113.0f, 3.0f, 16.0f))
		using (CanvasGeometry inset0 = tooth0Clipped.CombineWith(inset0Rect, identity, CanvasGeometryCombine.Intersect))
		using (CanvasGeometry inset1 = tooth1Clipped.CombineWith(inset1Rect, identity, CanvasGeometryCombine.Intersect))
		{
			_teethGeometry = tooth0Clipped.CombineWith(tooth1Clipped, identity, CanvasGeometryCombine.Union);
			_teethInsetGeometry = inset0.CombineWith(inset1, identity, CanvasGeometryCombine.Union);
		}

		// Tongue and palate ellipses, each clipped to the mouth
		using (CanvasGeometry tongueEllipse = CanvasGeometry.CreateEllipse(resourceCreator, 217.5f, 147.0f, 30.5f, 14.0f))
		{
			_tongueGeometry = _mouthGeometry.CombineWith(tongueEllipse, identity, CanvasGeometryCombine.Intersect);
		}

		using (CanvasGeometry palateEllipse = CanvasGeometry.CreateEllipse(resourceCreator, 218.0f, 107.0f, 23.0f, 14.0f))
		{
			_palateGeometry = _mouthGeometry.CombineWith(palateEllipse, identity, CanvasGeometryCombine.Intersect);
		}

		// Tense mouth: the bottom quarter arc, pre-stroked to a fill so no runtime stroking is needed.
		_tenseMouthGeometry = BuildStrokedArc(resourceCreator, new Vector2(220.5f, 111.5f), 21.5f, 0.785398f, 1.570796f, 10.0f);

		// Bread icons in bread-local coordinates, pre-stroked to fills.
		_heartGeometry = BuildHeart(resourceCreator);
		_ballGeometry = BuildBall(resourceCreator);
	}

	private void DisposePopForgeGeometries()
	{
		_bodyGeometry?.Dispose();
		_bodyGeometry = null;
		_bodyBandGeometry?.Dispose();
		_bodyBandGeometry = null;
		_legGeometry?.Dispose();
		_legGeometry = null;
		_legDarkGeometry?.Dispose();
		_legDarkGeometry = null;
		_mouthGeometry?.Dispose();
		_mouthGeometry = null;
		_mouthShadowGeometry?.Dispose();
		_mouthShadowGeometry = null;
		_teethGeometry?.Dispose();
		_teethGeometry = null;
		_teethInsetGeometry?.Dispose();
		_teethInsetGeometry = null;
		_tongueGeometry?.Dispose();
		_tongueGeometry = null;
		_palateGeometry?.Dispose();
		_palateGeometry = null;
		_tenseMouthGeometry?.Dispose();
		_tenseMouthGeometry = null;
		_heartGeometry?.Dispose();
		_heartGeometry = null;
		_ballGeometry?.Dispose();
		_ballGeometry = null;
		_popForgeResourceDevice = null;
	}

	private void DrawPopForge(CanvasDrawingSession drawingSession, float progress, bool showFineDetails)
	{
		PopForgeTransform popForgeTransform = GetPopForgeTransform(progress);

		float bodyScaleY = BodyScale(progress);
		float darkFactor = GetBodyDarkFactor(progress);
		Color bodyColor = LerpColor(PopForgeRed, PopForgeRedDark, darkFactor);
		Color shadowColor = LerpColor(PopForgeShadow, PopForgeShadowDark, darkFactor);

		Matrix3x2 oldTransform = drawingSession.Transform;

		Vector2 popForgeCenter = new(172.0f, 113.5f);
		Matrix3x2 popForgeLocalTransform =
			Matrix3x2.CreateRotation(popForgeTransform.RotationRadians, popForgeCenter) *
			Matrix3x2.CreateTranslation(150.0f + popForgeTransform.X, 168.0f + popForgeTransform.Y) *
			oldTransform;

		drawingSession.Transform = Matrix3x2.CreateScale(1.0f, bodyScaleY, new Vector2(0.0f, 175.0f)) * popForgeLocalTransform;
		drawingSession.FillGeometry(_bodyGeometry, bodyColor);
		drawingSession.FillGeometry(_bodyBandGeometry, shadowColor);

		drawingSession.Transform = popForgeLocalTransform;

		DrawSwitch(drawingSession, progress);
		DrawFace(drawingSession, progress, bodyColor, showFineDetails);

		drawingSession.FillRoundedRectangle(new Rect(-14.0, 175.0, 372.0, 30.0), 15.0f, 15.0f, White);
		drawingSession.FillRoundedRectangle(new Rect(-14.0, 175.0, 125.0, 30.0), 15.0f, 15.0f, WhiteShadow);
		DrawLeg(drawingSession, 23.0f, popForgeLocalTransform);
		DrawLeg(drawingSession, 255.0f, popForgeLocalTransform);

		drawingSession.Transform = oldTransform;
	}

	private void DrawLeg(CanvasDrawingSession drawingSession, float x, Matrix3x2 popForgeLocalTransform)
	{
		drawingSession.Transform = Matrix3x2.CreateTranslation(x, 205.0f) * popForgeLocalTransform;
		drawingSession.FillGeometry(_legGeometry, Grey);
		drawingSession.FillGeometry(_legDarkGeometry, Black);
		drawingSession.Transform = popForgeLocalTransform;
	}

	private static void DrawSwitch(CanvasDrawingSession drawingSession, float progress)
	{
		drawingSession.FillRoundedRectangle(new Rect(25.0, 45.0, 16.0, 107.0), 8.0f, 8.0f, SwitchHole);
		drawingSession.FillRoundedRectangle(new Rect(33.0, 47.0, 10.0, 104.0), 5.0f, 5.0f, Black);

		HandlerTransform handler = GetHandlerTransform(progress);
		float handlerBottom = 145.0f + handler.TranslateY;
		float handlerHeight = 20.0f * handler.ScaleY;
		float handlerTop = handlerBottom - handlerHeight;

		drawingSession.FillRoundedRectangle(new Rect(14.0, handlerTop, 39.0, handlerHeight), 4.0f, 4.0f, Handler);
		drawingSession.FillRectangle(new Rect(47.0, handlerTop, 6.0, handlerHeight), HandlerShadow);
	}

	private void DrawFace(CanvasDrawingSession drawingSession, float progress, Color bodyColor, bool showFineDetails)
	{
		const float faceX = 102.0f;
		const float faceY = 25.0f;

		// face-happy opacity is 1 outside 23%..51%, face-tense opacity is 1 inside it.
		bool tense = progress >= 0.23f && progress <= 0.515f;

		if (tense)
		{
			Vector2 jitter = GetTenseEyeJitter(progress);

			// Each tense eye is two black bar rotated about their own center.
			DrawTenseBrow(drawingSession, faceX + 71.5f + jitter.X, faceY + 51.0f + jitter.Y, 0.366519f);
			DrawTenseBrow(drawingSession, faceX + 71.5f + jitter.X, faceY + 66.0f + jitter.Y, -0.418879f);

			DrawTenseBrow(drawingSession, faceX + 166.5f + jitter.X, faceY + 51.0f + jitter.Y, -0.366519f);
			DrawTenseBrow(drawingSession, faceX + 166.5f + jitter.X, faceY + 66.0f + jitter.Y, 0.418879f);

			drawingSession.FillGeometry(_tenseMouthGeometry, Black);
			drawingSession.FillEllipse(new Vector2(faceX + 102.0f, faceY + 101.0f), 5.0f, 5.0f, Black);
			drawingSession.FillEllipse(new Vector2(faceX + 135.0f, faceY + 101.0f), 5.0f, 5.0f, Black);
		}
		else
		{
			float happyScaleY = GetHappyFaceScaleY(progress);
			Matrix3x2 oldTransform = drawingSession.Transform;
			Vector2 happyCenter = new(faceX + 110.5f, faceY + 68.5f);
			drawingSession.Transform = Matrix3x2.CreateScale(1.0f, happyScaleY, happyCenter) * oldTransform;

			DrawHappyEye(drawingSession, faceX + 49.0f, faceY + 9.0f, progress, showFineDetails);
			DrawHappyEye(drawingSession, faceX + 149.0f, faceY + 9.0f, progress, showFineDetails);

			if (showFineDetails)
			{
				drawingSession.FillGeometry(_mouthShadowGeometry, PopForgeLightShadow);
			}

			drawingSession.FillGeometry(_mouthGeometry, MouthUp);
			drawingSession.FillGeometry(_teethGeometry, White);

			if (showFineDetails)
			{
				drawingSession.FillGeometry(_teethInsetGeometry, WhiteShadow);
			}

			drawingSession.FillGeometry(_tongueGeometry, MouthTongue);
			drawingSession.FillGeometry(_palateGeometry, bodyColor);

			drawingSession.Transform = oldTransform;
		}

		ReadOnlySpan<float> blushTimes = [0.0f, 0.34f, 0.47f, 0.70f, 1.0f];
		ReadOnlySpan<float> blushValues = [0.0f, 0.0f, 1.0f, 0.0f, 0.0f];
		float blushOpacity = SampleKeyframes(progress, blushTimes, blushValues);

		if (blushOpacity > 0.0f)
		{
			byte alpha = (byte)Math.Clamp((int)MathF.Round(255.0f * blushOpacity), 0, 255);
			Color blushColor = Color.FromArgb(alpha, Blush.R, Blush.G, Blush.B);
			drawingSession.FillEllipse(new Vector2(faceX + 26.5f, faceY + 102.5f), 18.5f, 8.5f, blushColor);
			drawingSession.FillEllipse(new Vector2(faceX + 194.5f, faceY + 102.5f), 18.5f, 8.5f, blushColor);
		}
	}

	private static void DrawTenseBrow(CanvasDrawingSession drawingSession, float centerX, float centerY, float angle)
	{
		Matrix3x2 oldTransform = drawingSession.Transform;
		drawingSession.Transform = Matrix3x2.CreateRotation(angle, new Vector2(centerX, centerY)) * oldTransform;
		drawingSession.FillRoundedRectangle(new Rect(centerX - 23.5f, centerY - 6.0f, 47.0f, 12.0f), 6.0f, 6.0f, Black);
		drawingSession.Transform = oldTransform;
	}

	private readonly struct PupilTransform(float scaleX, float scaleY, float translateX, float translateY)
	{
		internal float ScaleX => scaleX;
		internal float ScaleY => scaleY;
		internal float TranslateX => translateX;
		internal float TranslateY => translateY;
	}

	private static void DrawHappyEye(CanvasDrawingSession drawingSession, float x, float y, float progress, bool showFineDetails)
	{
		ReadOnlySpan<float> eyeTimes = [0.0f, 0.2041f, 0.225f, 0.5125f, 1.0f];
		ReadOnlySpan<float> eyeScales = [1.0f, 1.0f, 0.8f, 1.0f, 1.0f];
		float eyeScaleY = SampleKeyframes(progress, eyeTimes, eyeScales);
		float eyeTop = y + 33.5f * (1.0f - eyeScaleY);
		float eyeHeight = 67.0f * eyeScaleY;

		if (showFineDetails)
		{
			drawingSession.FillRoundedRectangle(new Rect(x - 4.0f, eyeTop + 7.0f, 26.0f, MathF.Max(0.0f, eyeHeight - 6.0f)), 13.0f, 13.0f, PopForgeLightShadow);
		}

		drawingSession.FillRoundedRectangle(new Rect(x, eyeTop, 32.0f, eyeHeight), 16.0f, 16.0f, White);

		PupilTransform pupil = GetPupilTransform(progress);
		Vector2 pupilOrigin = new(x + 9.0f, y + 33.5f);
		Matrix3x2 oldTransform = drawingSession.Transform;
		drawingSession.Transform = Matrix3x2.CreateScale(pupil.ScaleX, pupil.ScaleY, pupilOrigin) *
								   Matrix3x2.CreateTranslation(pupil.TranslateX, pupil.TranslateY) * oldTransform;
		drawingSession.FillRoundedRectangle(new Rect(x + 9.0f, y + 11.0f, 17.0f, 45.0f), 9.0f, 9.0f, Black);
		drawingSession.Transform = oldTransform;
	}

	private static PupilTransform GetPupilTransform(float progress)
	{
		ReadOnlySpan<float> times = [0.0f, 0.016f, 0.025f, 0.041f, 0.0875f, 0.0925f, 0.1125f, 0.65f, 0.658f, 0.666f, 0.72f, 0.729f, 0.75f, 1.0f];
		ReadOnlySpan<float> scaleX = [1, 1, 1.4f, 1, 1, 1.4f, 1, 1, 1, 1, 1, 1, 1, 1];
		ReadOnlySpan<float> scaleY = [1, 1, 1, 1, 1, 1, 1, 1, 1.2f, 1, 1, 1.2f, 1, 1];
		ReadOnlySpan<float> translateX = [0, 0, 0, 7, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0];
		ReadOnlySpan<float> translateY = [0, 0, 0, 0, 0, 0, 0, 0, -6, -11, -11, -6, 0, 0];
		return new PupilTransform(SampleKeyframes(progress, times, scaleX), SampleKeyframes(progress, times, scaleY), SampleKeyframes(progress, times, translateX), SampleKeyframes(progress, times, translateY));
	}

	private void DrawBread(CanvasDrawingSession drawingSession, float x, float y, bool heart, bool showFineDetails)
	{
		Matrix3x2 oldTransform = drawingSession.Transform;
		drawingSession.Transform = Matrix3x2.CreateTranslation(x, y) * oldTransform;

		drawingSession.FillRoundedRectangle(new Rect(-10.0, 0.0, 107.0, 94.0), 20.0f, 20.0f, BreadShadow);
		drawingSession.FillRoundedRectangle(new Rect(0.0, 0.0, 97.0, 94.0), 20.0f, 20.0f, Bread);
		drawingSession.FillRoundedRectangle(new Rect(-14.0, -20.0, 125.0, 66.0), 42.0f, 42.0f, BreadShadow);
		drawingSession.FillRoundedRectangle(new Rect(-4.0, -20.0, 115.0, 66.0), 42.0f, 42.0f, Bread);
		drawingSession.FillRectangle(new Rect(0.0, 35.0, 97.0, 44.0), Bread);

		DrawBreadBubbles(drawingSession, heart, showFineDetails);

		// The pre-stroked icon (cached). The heart is one complete outline; the ball is the ring
		// plus its clipped seams already unioned into a single fill.
		drawingSession.FillGeometry(heart ? _heartGeometry : _ballGeometry, BreadPicture);

		drawingSession.Transform = oldTransform;
	}

	private static void DrawBreadBubbles(CanvasDrawingSession drawingSession, bool heart, bool showFineDetails)
	{
		if (heart)
		{
			DrawBubble(drawingSession, 11.0f, -3.0f, 9.0f, showFineDetails);
			DrawBubble(drawingSession, 53.0f, -10.0f, 5.0f, showFineDetails);
			DrawBubble(drawingSession, 17.0f, 71.0f, 4.0f, showFineDetails);
			DrawBubble(drawingSession, 85.0f, 68.0f, 6.0f, showFineDetails);
			DrawBubble(drawingSession, 46.0f, 40.0f, 7.0f, showFineDetails);
			DrawBubble(drawingSession, 68.0f, 28.0f, 4.0f, showFineDetails);
			DrawBubble(drawingSession, 85.5f, 68.0f, 6.25f, showFineDetails);
		}
		else
		{
			DrawBubble(drawingSession, 10.0f, 10.0f, 10.0f, showFineDetails);
			DrawBubble(drawingSession, 20.0f, -7.0f, 5.0f, showFineDetails);
			DrawBubble(drawingSession, 92.0f, 11.0f, 4.0f, showFineDetails);
		}
	}

	private static void DrawBubble(CanvasDrawingSession drawingSession, float centerX, float centerY, float radius, bool showFineDetails)
	{
		if (showFineDetails)
		{
			drawingSession.FillEllipse(new Vector2(centerX, centerY), radius, radius, BreadBubbleShadow);
			drawingSession.FillEllipse(new Vector2(centerX + radius * 0.22f, centerY - radius * 0.16f), radius, radius, BreadBubble);
			return;
		}

		drawingSession.FillEllipse(new Vector2(centerX, centerY), radius, radius, BreadBubble);
	}

	private static CanvasGeometry BuildHeart(ICanvasResourceCreator resourceCreator)
	{
		const float centerX = 46.0f;
		const float lobeRadius = 10.0f;
		const float lobeCenterY = 20.0f;
		const float bottomY = 44.0f;
		const float tangentOffsetX = 17.04f; // horizontal distance from centerX to each side's tangent point
		const float tangentY = 27.10f;       // shared y of both tangent points

		Vector2 leftLobe = new(centerX - lobeRadius, lobeCenterY);
		Vector2 rightLobe = new(centerX + lobeRadius, lobeCenterY);
		Vector2 bottomPoint = new(centerX, bottomY);
		Vector2 leftTangent = new(centerX - tangentOffsetX, tangentY);
		Vector2 rightTangent = new(centerX + tangentOffsetX, tangentY);

		const float leftStartAngle = 2.35202f;
		const float rightStartAngle = 3.14159f;
		const float lobeSweep = 3.93117f;

		using CanvasPathBuilder pathBuilder = new(resourceCreator);
		pathBuilder.BeginFigure(bottomPoint);
		pathBuilder.AddLine(leftTangent);
		pathBuilder.AddArc(leftLobe, lobeRadius, lobeRadius, leftStartAngle, lobeSweep);
		pathBuilder.AddArc(rightLobe, lobeRadius, lobeRadius, rightStartAngle, lobeSweep);
		pathBuilder.AddLine(rightTangent);
		pathBuilder.AddLine(bottomPoint);
		pathBuilder.EndFigure(CanvasFigureLoop.Closed);

		using CanvasGeometry path = CanvasGeometry.CreatePath(pathBuilder);
		return path.Stroke(6.0f);
	}

	private static CanvasGeometry BuildBall(ICanvasResourceCreator resourceCreator)
	{
		Matrix3x2 identity = Matrix3x2.Identity;

		using CanvasGeometry disc = CanvasGeometry.CreateEllipse(resourceCreator, 49.5f, 40.0f, 30.5f, 30.0f);

		// The ball's own border ring (not clipped).
		using CanvasGeometry outerRing = CanvasGeometry.CreateEllipse(resourceCreator, 49.5f, 40.0f, 33.5f, 33.0f);
		using CanvasGeometry outerStroke = outerRing.Stroke(6.0f);

		using CanvasGeometry innerRing = CanvasGeometry.CreateEllipse(resourceCreator, -38.5f, 79.5f, 104.5f, 104.5f);
		using CanvasGeometry innerStroke = innerRing.Stroke(6.0f);
		using CanvasGeometry innerClipped = innerStroke.CombineWith(disc, identity, CanvasGeometryCombine.Intersect);

		using CanvasGeometry afterRing = CanvasGeometry.CreateEllipse(resourceCreator, 68.5f, 84.0f, 44.5f, 41.0f);
		using CanvasGeometry afterStroke = afterRing.Stroke(6.0f);
		using CanvasGeometry afterClipped = afterStroke.CombineWith(disc, identity, CanvasGeometryCombine.Intersect);

		using CanvasGeometry beforeRing = CanvasGeometry.CreateEllipse(resourceCreator, 41.5f, -1.0f, 44.5f, 32.0f);
		using CanvasGeometry beforeRotated = beforeRing.Transform(Matrix3x2.CreateRotation(-0.488692f, new Vector2(41.5f, -1.0f)));
		using CanvasGeometry beforeStroke = beforeRotated.Stroke(6.0f);
		using CanvasGeometry beforeClipped = beforeStroke.CombineWith(disc, identity, CanvasGeometryCombine.Intersect);

		using CanvasGeometry union0 = outerStroke.CombineWith(innerClipped, identity, CanvasGeometryCombine.Union);
		using CanvasGeometry union1 = union0.CombineWith(afterClipped, identity, CanvasGeometryCombine.Union);
		return union1.CombineWith(beforeClipped, identity, CanvasGeometryCombine.Union);
	}

	private static float BreadBallOffset(float progress)
	{
		if (progress <= 0.52f) return 76.0f;
		if (progress <= 0.55f) return 76.0f + Lerp(0.0f, -161.0f, Ease((progress - 0.52f) / 0.03f));
		if (progress <= 0.566f) return 76.0f + Lerp(-161.0f, -235.0f, Ease((progress - 0.55f) / 0.016f));
		if (progress <= 0.575f) return 76.0f - 235.0f;
		if (progress <= 0.5875f) return 76.0f + Lerp(-235.0f, -230.0f, Ease((progress - 0.575f) / 0.0125f));
		if (progress <= 0.6541f) return 76.0f + Lerp(-230.0f, -79.0f, Ease((progress - 0.5875f) / 0.0666f));
		if (progress <= 0.81f) return 76.0f - 79.0f;
		if (progress <= 0.93f) return 76.0f + Lerp(-79.0f, -50.0f, Ease((progress - 0.81f) / 0.12f));
		return 76.0f + Lerp(-50.0f, 0.0f, Ease((progress - 0.93f) / 0.07f));
	}

	private static float BreadHeartOffset(float progress)
	{
		if (progress <= 0.54f) return 76.0f - 24.0f;
		if (progress <= 0.57f) return 76.0f + Lerp(-24.0f, -154.0f, Ease((progress - 0.54f) / 0.03f));
		if (progress <= 0.5916f) return 76.0f + Lerp(-154.0f, -262.0f, Ease((progress - 0.57f) / 0.0216f));
		if (progress <= 0.6041f) return 76.0f - 262.0f;
		if (progress <= 0.68f) return 76.0f + Lerp(-262.0f, -70.0f, Ease((progress - 0.6041f) / 0.0759f));
		if (progress <= 0.82f) return 76.0f - 70.0f;
		if (progress <= 0.93f) return 76.0f + Lerp(-70.0f, -30.0f, Ease((progress - 0.82f) / 0.11f));
		return 76.0f + Lerp(-30.0f, -24.0f, Ease((progress - 0.93f) / 0.07f));
	}

	private readonly struct PopForgeTransform(float x, float y, float rotationRadians)
	{
		internal float X => x;
		internal float Y => y;
		internal float RotationRadians => rotationRadians;
	}

	private static PopForgeTransform GetPopForgeTransform(float progress)
	{
		ReadOnlySpan<float> times =
		[
			0.0f, 0.35f, 0.354f, 0.366f, 0.37f, 0.375f, 0.39f, 0.396f, 0.40f,
			0.415f, 0.42f, 0.435f, 0.44f, 0.446f, 0.45f, 0.456f, 0.48f,
			0.485f, 0.49f, 0.50f, 0.506f, 0.51f, 0.54f, 0.55f, 0.5625f,
			0.5708f, 0.5768f, 0.583f, 0.60f, 0.6125f, 0.6208f, 0.6268f, 1.0f
		];

		ReadOnlySpan<float> xValues =
		[
			0, 0, -5, 0, 5, 0, 0, -5, 0, 5, 0, 0, -5, 0, 5, 0, 0, -5, 0, 5, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		];

		ReadOnlySpan<float> yValues =
		[
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, -62, -62, 0, -8, -8, -3, 0, -3, -1, 0, 0
		];

		ReadOnlySpan<float> rotationDegrees =
		[
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, -2, -3, 0, 2, 1, 0, 0
		];

		int upperIndex = 1;
		while (upperIndex < times.Length && progress > times[upperIndex])
		{
			upperIndex++;
		}

		if (upperIndex >= times.Length)
		{
			upperIndex = times.Length - 1;
		}

		int lowerIndex = upperIndex - 1;
		float duration = times[upperIndex] - times[lowerIndex];
		float localProgress = duration > 0.0f ? (progress - times[lowerIndex]) / duration : 0.0f;
		float easedProgress = Ease(localProgress);

		float x = Lerp(xValues[lowerIndex], xValues[upperIndex], easedProgress);
		float y = Lerp(yValues[lowerIndex], yValues[upperIndex], easedProgress);
		float rotationRadians = Lerp(rotationDegrees[lowerIndex], rotationDegrees[upperIndex], easedProgress) * MathF.PI / 180.0f;

		return new PopForgeTransform(x, y, rotationRadians);
	}

	private static float BodyScale(float progress)
	{
		ReadOnlySpan<float> times = [0.0f, 0.229f, 0.254f, 0.279f, 0.466f, 0.4875f, 0.4975f, 0.52f, 0.55f, 0.57f, 1.0f];
		ReadOnlySpan<float> values = [1.0f, 1.0f, 1.03f, 0.9f, 0.9f, 0.81f, 0.81f, 1.14f, 0.88f, 1.0f, 1.0f];
		return SampleKeyframes(progress, times, values);
	}

	private readonly struct HandlerTransform(float translateY, float scaleY)
	{
		internal float TranslateY => translateY;
		internal float ScaleY => scaleY;
	}

	private static HandlerTransform GetHandlerTransform(float progress)
	{
		ReadOnlySpan<float> times = [0.0f, 0.516f, 0.5208f, 0.529f, 0.533f, 0.829f, 0.958f, 1.0f];
		ReadOnlySpan<float> translateY = [0.0f, 0.0f, 0.0f, -23.0f, -64.0f, -64.0f, 0.0f, 0.0f];
		ReadOnlySpan<float> scaleY = [1.0f, 1.0f, 2.0f, 2.0f, 1.0f, 1.0f, 1.0f, 1.0f];
		return new HandlerTransform(SampleKeyframes(progress, times, translateY), SampleKeyframes(progress, times, scaleY));
	}

	private static float GetHappyFaceScaleY(float progress)
	{
		ReadOnlySpan<float> times = [0.0f, 0.5151f, 0.5208f, 0.5458f, 1.0f];
		ReadOnlySpan<float> values = [1.0f, 1.0f, 1.4f, 1.0f, 1.0f];
		return SampleKeyframes(progress, times, values);
	}

	private static float GetBodyDarkFactor(float progress)
	{
		ReadOnlySpan<float> times = [0.0f, 0.35f, 0.516f, 0.6125f, 1.0f];
		ReadOnlySpan<float> values = [0.0f, 0.0f, 1.0f, 0.0f, 0.0f];
		return SampleKeyframes(progress, times, values);
	}

	private static Vector2 GetTenseEyeJitter(float progress)
	{
		ReadOnlySpan<float> times =
		[
			0.0f, 0.266f, 0.2708f, 0.2756f, 0.28f, 0.286f, 0.29f, 0.305f, 0.31f, 0.315f,
			0.325f, 0.33f, 0.34f, 0.35f, 0.36f, 0.38f, 0.39f, 0.40f, 0.41f, 0.42f,
			0.43f, 0.44f, 0.45f, 0.46f, 0.47f, 0.48f, 0.49f, 0.50f
		];
		ReadOnlySpan<float> xValues =
		[
			0, 0, -5, 7, 7, -5, 0, -5, -5, -5,
			0, 2, 0, -5, -3, -5, 7, -5, 0, -5,
			7, -5, 0, 7, -5, 7, -3, -3
		];
		ReadOnlySpan<float> yValues =
		[
			0, 0, 12, 15, 15, 12, 13, 12, 15, 12,
			17, 13, 0, 12, 10, 12, 15, 12, 13, 12,
			15, 12, 13, 15, 12, 15, 20, 20
		];
		return new Vector2(SampleKeyframes(progress, times, xValues), SampleKeyframes(progress, times, yValues));
	}

	// Builds an open arc, strokes it to a fill geometry, and returns that (used once at cache time).
	private static CanvasGeometry BuildStrokedArc(
		ICanvasResourceCreator resourceCreator,
		Vector2 centerPoint,
		float radius,
		float startAngle,
		float sweepAngle,
		float strokeWidth)
	{
		Vector2 startPoint = new(
			centerPoint.X + radius * MathF.Cos(startAngle),
			centerPoint.Y + radius * MathF.Sin(startAngle));

		using CanvasPathBuilder pathBuilder = new(resourceCreator);
		pathBuilder.BeginFigure(startPoint);
		pathBuilder.AddArc(centerPoint, radius, radius, startAngle, sweepAngle);
		pathBuilder.EndFigure(CanvasFigureLoop.Open);

		using CanvasGeometry path = CanvasGeometry.CreatePath(pathBuilder);
		return path.Stroke(strokeWidth);
	}

	// Rounded rectangle with an independent radius per corner (traversed clockwise).
	private static CanvasGeometry CreateRoundedRectGeometry(
		ICanvasResourceCreator resourceCreator,
		float x,
		float y,
		float width,
		float height,
		float topLeft,
		float topRight,
		float bottomRight,
		float bottomLeft)
	{
		using CanvasPathBuilder pathBuilder = new(resourceCreator);

		pathBuilder.BeginFigure(x + topLeft, y);
		pathBuilder.AddLine(x + width - topRight, y);
		if (topRight > 0.0f)
		{
			pathBuilder.AddArc(new Vector2(x + width, y + topRight), topRight, topRight, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		}

		pathBuilder.AddLine(x + width, y + height - bottomRight);
		if (bottomRight > 0.0f)
		{
			pathBuilder.AddArc(new Vector2(x + width - bottomRight, y + height), bottomRight, bottomRight, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		}

		pathBuilder.AddLine(x + bottomLeft, y + height);
		if (bottomLeft > 0.0f)
		{
			pathBuilder.AddArc(new Vector2(x, y + height - bottomLeft), bottomLeft, bottomLeft, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		}

		pathBuilder.AddLine(x, y + topLeft);
		if (topLeft > 0.0f)
		{
			pathBuilder.AddArc(new Vector2(x + topLeft, y), topLeft, topLeft, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		}

		pathBuilder.EndFigure(CanvasFigureLoop.Closed);
		return CanvasGeometry.CreatePath(pathBuilder);
	}

	// PopForge body silhouette: rounded top corners and square bottom corners.
	private static CanvasGeometry CreateBodyGeometry(ICanvasResourceCreator resourceCreator, float top, float bottom, float cornerRadiusY)
	{
		const float rx = 61.0f;
		using CanvasPathBuilder pathBuilder = new(resourceCreator);

		pathBuilder.BeginFigure(rx, top);
		pathBuilder.AddLine(344.0f - rx, top);
		pathBuilder.AddArc(new Vector2(344.0f, top + cornerRadiusY), rx, cornerRadiusY, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.AddLine(344.0f, bottom);
		pathBuilder.AddLine(0.0f, bottom);
		pathBuilder.AddLine(0.0f, top + cornerRadiusY);
		pathBuilder.AddArc(new Vector2(rx, top), rx, cornerRadiusY, 0.0f, CanvasSweepDirection.Clockwise, CanvasArcSize.Small);
		pathBuilder.EndFigure(CanvasFigureLoop.Closed);

		return CanvasGeometry.CreatePath(pathBuilder);
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

	private static Color LerpColor(Color start, Color end, float amount)
	{
		float clamped = Math.Clamp(amount, 0.0f, 1.0f);
		return Color.FromArgb(
			(byte)(start.A + (end.A - start.A) * clamped),
			(byte)(start.R + (end.R - start.R) * clamped),
			(byte)(start.G + (end.G - start.G) * clamped),
			(byte)(start.B + (end.B - start.B) * clamped));
	}

	private static float Lerp(float start, float end, float amount) => start + (end - start) * amount;
}
