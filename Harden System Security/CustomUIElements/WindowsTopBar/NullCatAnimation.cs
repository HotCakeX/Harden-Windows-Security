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
using System.Globalization;
using System.Numerics;
using Microsoft.Graphics.Canvas;
using Microsoft.Graphics.Canvas.Svg;
using Microsoft.Graphics.Canvas.UI.Xaml;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Windows.UI;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

// A self-contained animation control. While loaded, the XAML composition callback invalidates
// its CanvasControl and its Stopwatch supplies animation time. Unloading stops callbacks and releases
// the canvas and SVG resources.
internal sealed partial class NullCatAnimation : UserControl
{
	private const float DesignWidth = 787.3f;
	private const float DesignHeight = 433.8f;
	private const float ArtworkLeft = 0.0f;
	private const float ArtworkTop = 0.0f;
	private const float ArtworkWidth = 670.0f;
	private const float ArtworkHeight = 353.0f;
	private const double PawCycleSeconds = 0.3;
	private const double CodeCycleSeconds = 1.2;

	private CanvasControl? _nullCatCanvas;
	private readonly Stopwatch _animationClock = new();

	// The owned SVG document (built once per device, mutated per frame, disposed on unload).
	private CanvasDevice? _nullCatResourceDevice;
	private CanvasSvgDocument? _svgDocument;

	// Cached element references so no per-frame lookups are needed.
	private CanvasSvgNamedElement? _pawRightUp;
	private CanvasSvgNamedElement? _pawRightDown;
	private CanvasSvgNamedElement? _pawLeftUp;
	private CanvasSvgNamedElement? _pawLeftDown;
	private readonly CanvasSvgNamedElement?[] _codeLineElements = new CanvasSvgNamedElement?[9];

	// Tracks the last paw phase applied, so the display attributes are only rewritten on change.
	private int _lastPawPhase = -1;

	private readonly struct CodeLine(string id, float startX, float y, float fullX, float startFraction, float endFraction)
	{
		internal string Id => id;
		internal float StartX => startX;
		internal float Y => y;
		internal float FullX => fullX;
		internal float StartFraction => startFraction;
		internal float EndFraction => endFraction;
	}

	private static readonly CodeLine[] CodeLines =
	[
		new CodeLine("f1-l1", 0.0f, 1.0f, 160.0f, 0.00f, 0.14f),
		new CodeLine("f1-l2", 8.0f, 13.0f, 124.0f, 0.14f, 0.24f),
		new CodeLine("f1-l3", 8.0f, 25.0f, 61.0f, 0.24f, 0.30f),
		new CodeLine("f2-l4", 0.0f, 1.0f, 136.0f, 0.30f, 0.44f),
		new CodeLine("f2-l5", 8.0f, 13.0f, 114.0f, 0.44f, 0.54f),
		new CodeLine("f2-l6", 8.0f, 25.0f, 69.0f, 0.54f, 0.60f),
		new CodeLine("f3-l7", 0.0f, 1.0f, 96.0f, 0.60f, 0.68f),
		new CodeLine("f3-l8", 8.0f, 13.0f, 146.0f, 0.68f, 0.82f),
		new CodeLine("f3-l9", 8.0f, 25.0f, 96.0f, 0.82f, 0.92f)
	];

	internal NullCatAnimation()
	{
		IsTabStop = false;
		Loaded += OnNullCatLoaded;
		Unloaded += OnNullCatUnloaded;
	}

	private void OnNullCatLoaded(object sender, RoutedEventArgs e)
	{
		if (!_animationClock.IsRunning)
		{
			_animationClock.Start();
			CompositionTarget.Rendering += OnAnimationRendering;
		}
		if (_nullCatCanvas is null)
		{
			_nullCatCanvas = CreateNullCatCanvas();
			Content = _nullCatCanvas;
		}
	}

	// Stop frame callbacks and release the CanvasControl and SVG resources when disconnected from XAML.
	private void OnNullCatUnloaded(object sender, RoutedEventArgs e)
	{
		CompositionTarget.Rendering -= OnAnimationRendering;
		_animationClock.Stop();
		DisposeSvgDocument();

		if (_nullCatCanvas is not null)
		{
			_nullCatCanvas.Draw -= OnNullCatCanvasDraw;
			_nullCatCanvas.RemoveFromVisualTree();
			_nullCatCanvas = null;
		}

		Content = null;
	}

	private void OnAnimationRendering(object? sender, object e) => _nullCatCanvas?.Invalidate();

	private CanvasControl CreateNullCatCanvas()
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

		canvas.Draw += OnNullCatCanvasDraw;
		return canvas;
	}

	private void OnNullCatCanvasDraw(CanvasControl sender, CanvasDrawEventArgs args)
	{
		float width = (float)sender.Size.Width;
		float height = (float)sender.Size.Height;

		if (width < 2.0f || height < 2.0f)
		{
			return;
		}

		EnsureNullCatResources(sender);

		if (_svgDocument is null)
		{
			return;
		}

		double totalSeconds = _animationClock.Elapsed.TotalSeconds;
		UpdatePaws(totalSeconds);
		UpdateCode(totalSeconds);

		// Fit and center the visible artwork bounds rather than the padded SVG viewBox.
		// The laptop base reaches Y 353 in the original SVG, so the complete artwork remains visible.
		float scale = MathF.Min(width / ArtworkWidth, height / ArtworkHeight);
		float destinationWidth = DesignWidth * scale;
		float destinationHeight = DesignHeight * scale;
		float offsetX = ((width - ArtworkWidth * scale) * 0.5f) - ArtworkLeft * scale;
		float offsetY = ((height - ArtworkHeight * scale) * 0.5f) - ArtworkTop * scale;

		CanvasDrawingSession drawingSession = args.DrawingSession;
		drawingSession.Transform = Matrix3x2.CreateTranslation(offsetX, offsetY);
		drawingSession.DrawSvg(_svgDocument, new Size(destinationWidth, destinationHeight));
	}

	private void UpdatePaws(double totalSeconds)
	{
		double phaseTime = totalSeconds % PawCycleSeconds;
		int phase = phaseTime < (PawCycleSeconds * 0.5) ? 0 : 1;

		if (phase == _lastPawPhase)
		{
			return;
		}

		_lastPawPhase = phase;

		bool showRightUpLeftDown = phase == 0;
		SetDisplay(_pawRightUp, showRightUpLeftDown);
		SetDisplay(_pawLeftDown, showRightUpLeftDown);
		SetDisplay(_pawRightDown, !showRightUpLeftDown);
		SetDisplay(_pawLeftUp, !showRightUpLeftDown);
	}

	private static void SetDisplay(CanvasSvgNamedElement? element, bool visible) =>
		element?.SetStringAttribute("display", visible ? "inline" : "none");

	private void UpdateCode(double totalSeconds)
	{
		float progress = (float)(totalSeconds % CodeCycleSeconds / CodeCycleSeconds);

		for (int index = 0; index < CodeLines.Length; index++)
		{
			CanvasSvgNamedElement? element = _codeLineElements[index];
			if (element is null)
			{
				continue;
			}

			CodeLine line = CodeLines[index];
			float currentX;
			if (progress <= line.StartFraction)
			{
				currentX = line.StartX;
			}
			else if (progress >= line.EndFraction)
			{
				currentX = line.FullX;
			}
			else
			{
				float t = (progress - line.StartFraction) / (line.EndFraction - line.StartFraction);
				currentX = line.StartX + (line.FullX - line.StartX) * t;
			}

			string pathData = string.Format(
				CultureInfo.InvariantCulture,
				"M{0},{1}L{2},{1}",
				line.StartX,
				line.Y,
				currentX);
			element.SetStringAttribute("d", pathData);
		}
	}

	// Lazily builds the SVG document for the current device and rebuilds it if the device is lost
	// and replaced. Element references are cached once here.
	private void EnsureNullCatResources(CanvasControl sender)
	{
		CanvasDevice device = sender.Device;

		if (_nullCatResourceDevice == device && _svgDocument != null)
		{
			return;
		}

		DisposeSvgDocument();
		_nullCatResourceDevice = device;
		_svgDocument = CanvasSvgDocument.LoadFromXml(sender, NullCatSvg);

		_pawRightUp = _svgDocument.FindElementById("paw-right--up");
		_pawRightDown = _svgDocument.FindElementById("paw-right--down");
		_pawLeftUp = _svgDocument.FindElementById("paw-left--up");
		_pawLeftDown = _svgDocument.FindElementById("paw-left--down");

		for (int index = 0; index < CodeLines.Length; index++)
		{
			_codeLineElements[index] = _svgDocument.FindElementById(CodeLines[index].Id);
		}

		// Force the paw display to be applied on the next frame.
		_lastPawPhase = -1;
	}

	private void DisposeSvgDocument()
	{
		// Release the cached element wrappers before releasing their owning document.
		_pawRightUp?.Dispose();
		_pawRightUp = null;
		_pawRightDown?.Dispose();
		_pawRightDown = null;
		_pawLeftUp?.Dispose();
		_pawLeftUp = null;
		_pawLeftDown?.Dispose();
		_pawLeftDown = null;

		for (int index = 0; index < _codeLineElements.Length; index++)
		{
			_codeLineElements[index]?.Dispose();
			_codeLineElements[index] = null;
		}

		_svgDocument?.Dispose();
		_svgDocument = null;
		_nullCatResourceDevice = null;
	}

	private const string NullCatSvg = @"<svg xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' viewBox='0 0 787.3 433.8'><defs>
<g id='eye'><circle cx='9.4' cy='9.1' r='8'/><path d='M16.3,5.1a1.3,1.3,0,0,1-1.4-.3,7.2,7.2,0,0,0-4.5-2.6A7.2,7.2,0,0,0,5.5,3.5,6.8,6.8,0,0,0,2.8,7.8a6.8,6.8,0,0,0,1,4.8,6.2,6.2,0,0,0,4,2.7,6.1,6.1,0,0,0,4.6-.7,6.7,6.7,0,0,0,2.9-3.7,6.4,6.4,0,0,0-.5-4.5c-.1-.2.8-1,1.5-1.3s2.2,0,2.3.5a9.4,9.4,0,0,1-.2,7.2,9.4,9.4,0,0,1-5.1,5.1,9,9,0,0,1-7,.2A9.6,9.6,0,0,1,1,13.5,9.2,9.2,0,0,1,.4,6.6,8.9,8.9,0,0,1,4.6,1.3,9,9,0,0,1,11.2.2,9.3,9.3,0,0,1,16.7,4C16.9,4.3,17,4.8,16.3,5.1Z'/></g>
<g id='paw-pads'><path d='M6.8,16a3.7,3.7,0,0,1,1.1,2.8,3.2,3.2,0,0,1-1.6,2.6L5,21.8H4.4a2.8,2.8,0,0,1-1.8.3A4.2,4.2,0,0,1,.2,19.1,7.7,7.7,0,0,1,0,17.6a2.8,2.8,0,0,1,.6-2,3.2,3.2,0,0,1,2.1-.8H4A5,5,0,0,1,6.8,16Zm7.3-4.8a1.8,1.8,0,0,0,.7-.5l.7-.4a3.5,3.5,0,0,0,1.1-1,3.2,3.2,0,0,0,.3-1.4,1.4,1.4,0,0,0-.2-.6,3.4,3.4,0,0,0-.3-2.4,3.2,3.2,0,0,0-2.1-1.5H13.1a4.7,4.7,0,0,0-1.6.4,2,2,0,0,0-.9.9l-.4.6v.4a6.1,6.1,0,0,0-.5,1.2,4.3,4.3,0,0,0,0,1.6,3.5,3.5,0,0,0,.5,2l.7.6a3.3,3.3,0,0,0,1.7.7A3,3,0,0,0,14.1,11.2ZM22.7,7l.6.2h.3A2.3,2.3,0,0,0,25,6.8l.4-.3.6-.3a7.5,7.5,0,0,0,1.5-.9,4.2,4.2,0,0,0,.8-1.2,1.9,1.9,0,0,0,.1-1.5A2.6,2.6,0,0,0,27.5,1,3.5,3.5,0,0,0,23.6.3a3.8,3.8,0,0,0-2,1.5,4.8,4.8,0,0,0-.7,2,3.6,3.6,0,0,0,.9,2.6ZM31,24.1a13.5,13.5,0,0,0-2.2-4.7,36.6,36.6,0,0,0-3.2-3.9,5.3,5.3,0,0,0-5-1.9,10.5,10.5,0,0,0-4.5,2.2A5.6,5.6,0,0,0,13.5,20a15.1,15.1,0,0,0,1.2,6.3c.8,2,1.7,4,2.6,5.9a1.6,1.6,0,0,0,1.5.8,1.7,1.7,0,0,0,1.9.9,17.1,17.1,0,0,0,8.7-4.8,8.2,8.2,0,0,0,1.7-2C31.6,26.3,31.3,25,31,24.1Z' fill='#ef97b0'/></g>
</defs><g id='head'>
<g id='head__outline'><path d='M303.2,186.3c4-7,14.8-20.2,20-26,17-19,34.6-34.9,43-41l12-8s16.6-32,21-33c9-2,33,22,33,22s20-9,79,7c41,11.1,47,14,57,22,7.5,6,18,16,18,16s33.7-19.5,41-15-2,66-2,66,5.9,12.9,11,22c9.1,16.2,13.6,20.2,19,31,3.6,7.2,8.4,28.5,10.5,43.5l-385-62Z' fill='#fff'/><path d='M302.9,186.9c-1.2,3-5.9,12.6-9,18.8l-12.5,25.5-.6-1.2c32.2,4.8,64.4,9.2,96.6,13.6s64.4,8.9,96.5,13.7,64.3,9.7,96.4,14.9,64.1,10.5,96.2,15.8l-5.6,5.5c-1.2-8.5-2.8-17.1-4.8-25.6-1-4.1-2.1-8.4-3.4-12.3l-.5-1.4-.5-1.4-.6-1.3-.7-1.3a59.5,59.5,0,0,0-3.1-5.5c-2.2-3.6-4.7-7.2-7.1-11s-4.8-7.6-7-11.5c-4.5-7.9-8.3-15.9-12.1-24a4,4,0,0,1-.3-2.6h0c1.4-9.1,2.7-18.2,3.7-27.4.5-4.5.9-9.1,1.2-13.7s.4-9.1.2-13.4a26.4,26.4,0,0,0-.8-6,8.1,8.1,0,0,0-.3-1.1c-.1-.3-.2-.4-.1-.3h.3c0,.1.1.1,0,.1h-.6a11.9,11.9,0,0,0-2.5.2,16.3,16.3,0,0,0-3,.7,56.7,56.7,0,0,0-6.2,2.1,212.6,212.6,0,0,0-24.5,11.9h-.1a3.9,3.9,0,0,1-4.7-.6c-4.9-4.7-10-9.4-15.1-13.8a86.6,86.6,0,0,0-7.9-6,46.1,46.1,0,0,0-8.5-4.6c-6-2.6-12.6-4.6-19.2-6.7l-19.8-5.7a324.9,324.9,0,0,0-40-8.9,196.8,196.8,0,0,0-20.2-1.8c-1.7,0-3.4-.1-5.1,0h-2.5l-2.5.2-2.5.2-2.4.4-2.4.5-1.1.3h-.5l-.4.2H433a2.5,2.5,0,0,1-2.6-.7c-4.6-4.6-9.5-9.1-14.5-13.2a82.7,82.7,0,0,0-7.9-5.7L403.9,81a10.8,10.8,0,0,0-4-.9c-.1,0-.3,0-.3.1h0l-.7.5-1.5,1.7c-1,1.2-2,2.6-2.9,3.9s-3.6,5.5-5.3,8.3c-3.5,5.7-6.8,11.4-9.9,17.3h0l-.4.4-10.2,6.6a53.6,53.6,0,0,0-4.9,3.4l-4.6,3.8c-6.2,5.1-12.1,10.6-17.9,16.2s-11.3,11.4-16.7,17.4c-2.7,3-5.3,6.1-7.8,9.2s-5,6.3-7.4,9.5c-4.2,5.6-7,10-5.7,7.1a34.1,34.1,0,0,1,2.1-3.8l3.8-5.6c2.9-4,6.3-8.3,8.5-10.9s4.4-5.2,6.7-7.7l6.9-7.4c4.7-4.9,9.4-9.7,14.3-14.3s9.8-9.3,15-13.7l4-3.2,4.2-2.9,8.3-5.7-.4.4c3-5.9,6.1-11.8,9.4-17.7,1.6-2.9,3.3-5.8,5.1-8.6l2.9-4.3,1.8-2a7.5,7.5,0,0,1,1.3-1.1c.1-.2.6-.4,1-.5l.9-.2h1.7l1.4.2,2.7.8c1.7.7,3.3,1.5,4.8,2.3a84,84,0,0,1,8.5,5.7A175.7,175.7,0,0,1,434,98.5l-2.9-.6.8-.3.7-.2L434,97l2.7-.7,2.7-.5a23,23,0,0,1,2.6-.3l2.7-.3,2.7-.2h5.3a182.1,182.1,0,0,1,21,1.3,332.5,332.5,0,0,1,41.1,8.4l20,5.5c6.7,2,13.4,4,20.1,6.7a65.3,65.3,0,0,1,9.8,5.1c3.1,2.1,5.9,4.3,8.6,6.5,5.4,4.5,10.6,9.2,15.7,14l-4.8-.6c4.1-2.4,8.2-4.6,12.4-6.7s8.6-4.2,13-6c2.3-.9,4.6-1.7,7-2.4a23.4,23.4,0,0,1,3.8-.9,20,20,0,0,1,4.4-.4h1.3l1.5.4a5.1,5.1,0,0,1,1.7.7l.9.7.8.7a8.3,8.3,0,0,1,1.6,2.6,12.7,12.7,0,0,1,.8,2.3,44.6,44.6,0,0,1,1.1,7.7c.2,5,.1,9.7-.1,14.4s-.7,9.5-1.2,14.1c-.9,9.4-2.1,18.6-3.6,27.9l-.3-2.6c3.7,7.9,7.5,15.8,11.8,23.3,2.1,3.7,4.4,7.4,6.8,11s4.9,7.2,7.3,11.1c1.3,2,2.4,4,3.5,6.1a10.9,10.9,0,0,0,.8,1.5l.8,1.8.7,1.7.6,1.7c1.5,4.4,2.6,8.7,3.7,13.1a262,262,0,0,1,5.2,26.4,4.9,4.9,0,0,1-4.1,5.6h-1.5c-32.1-5-64.2-9.9-96.3-15.1s-64.1-10.6-96.1-16.1-64-11.4-96-17.4-63.9-11.9-95.9-17.4h-.1a.8.8,0,0,1-.6-.9v-.2l16.6-32.1C299.8,192.2,304.1,183.9,302.9,186.9Z'/></g>
<g id='head__face'><g id='eyes'>
<use width='19.2' height='18.7' transform='translate(474.8 195.2)' xlink:href='#eye'/>
<use width='19.2' height='18.7' transform='matrix(-0.51 -0.85 0.82 -0.5 370.39 192.59)' xlink:href='#eye'/>
</g><g id='mouth'><path d='M399.2,186.3c.9,3.6,2.6,7.8,6,9,6.4,2.3,19-6,19-6s4.1,12.4,10,15,10.7-1.7,16-6' fill='#fff'/><path d='M450.2,198.3c.6,1.2.2,1.9-.2,2.2a36.7,36.7,0,0,1-7.6,4.9,14.9,14.9,0,0,1-4.8,1.4h-1.4l-1.3-.2-1.4-.4-1.3-.6a21.6,21.6,0,0,1-6.4-7.2,52.8,52.8,0,0,1-4-8.3l3.8,1.3a62.3,62.3,0,0,1-7.1,4.1,32.1,32.1,0,0,1-7.9,2.8,13.2,13.2,0,0,1-4.9.2l-1.4-.3a7.5,7.5,0,0,1-1.3-.6,7.9,7.9,0,0,1-2.3-1.6,16.8,16.8,0,0,1-2.9-4,24.1,24.1,0,0,1-1.6-4.2c-.1-.5,1.6-1.3,3-1.4s3.5.2,3.6.6a10.3,10.3,0,0,0,2.6,4.9l.7.5h2.4l1.5-.2a28.4,28.4,0,0,0,6.5-2c2.1-1,4.3-2.1,6.3-3.3h.1a2.5,2.5,0,0,1,3.4.9l.3.5a43.1,43.1,0,0,0,3.2,7.7,19.8,19.8,0,0,0,2.2,3.4,8.1,8.1,0,0,0,2.6,2.6,5,5,0,0,0,3,.7,10.8,10.8,0,0,0,3.7-1,33.4,33.4,0,0,0,7.2-4.3C448.8,197.4,449.5,197.2,450.2,198.3Z'/></g></g></g><g id='laptop'><g id='laptop__base'><polygon points='641.9 304.1 454.7 348.2 103.8 271.3 254.6 230.3 641.9 304.1' fill='#f2f2f2'/><path d='M641.9,304.1c1.5-.1-2.3,1.5-10.3,3.6-28.9,7.5-58.1,15.2-87.7,22.6s-59.1,14.5-88.4,21.3l-.8.2-.8-.2-349.5-78-1.1-.2-8.7-1.9,8.6-2.3,150.6-41.5.6-.2h.7c62.5,11.7,125.5,23.6,188.4,35.9s125.6,25.1,188,37.6c8,1.6,11.9,3,10.4,3a185.6,185.6,0,0,1-18.4-2.6c-61.9-11.2-123.6-22.2-185-33.5s-122.7-23.1-184.4-35h1.2L104.4,273.4h-.1v-4.3l351.2,75.7h-1.5c28.3-6.7,56.3-13.3,84.3-19.5s56.5-12,85.2-18.1C631.3,305.6,640.4,304.1,641.9,304.1Z' fill='#231f20'/></g><g id='laptop__keyboard'><polygon points='371.1 274.8 256.8 253.5 257 252.7 266.2 251.1 382.4 271.5 382.3 272.3 371.1 274.8' fill='#3e3e54'/><polygon points='237.4 265.6 221.3 262.4 221.4 261.7 230.2 260.2 246.8 262.6 246.6 263.4 237.4 265.6' fill='#3e3e54'/><polygon points='474.6 312.9 249.9 268.1 250.1 267.3 259.2 265.8 487.7 309.6 487.5 310.5 474.6 312.9' fill='#3e3e54'/><polygon points='411.8 309.4 204.2 266.7 204.4 266 212.9 264.5 423.9 306.3 423.7 307.2 411.8 309.4' fill='#3e3e54'/><polygon points='450 317.3 428.5 312.9 428.8 312 440.7 310.6 462.7 314.1 462.5 315 450 317.3' fill='#3e3e54'/><polygon points='201.6 273.9 187.5 270.9 187.7 270.2 196 268.7 210.4 271 210.3 271.7 201.6 273.9' fill='#3e3e54'/><polygon points='222.6 278.3 208.1 275.3 208.3 274.5 216.9 273.1 231.8 275.4 231.6 276.2 222.6 278.3' fill='#3e3e54'/><polygon points='362.9 308.1 231.5 280.2 231.7 279.5 240.7 278.1 374.2 305.1 374 305.9 362.9 308.1' fill='#3e3e54'/><polygon points='444.3 288.4 385.2 277.4 385.4 276.5 396.6 274.9 456.9 285.1 456.7 285.9 444.3 288.4' fill='#3e3e54'/><polygon points='526.1 303.6 460.1 291.3 460.3 290.4 472.8 288.9 540.1 300.2 539.9 301.1 526.1 303.6' fill='#3e3e54'/><polygon points='426.2 321.6 376.1 310.9 376.3 310.1 387.4 308.7 438.5 318.5 438.3 319.4 426.2 321.6' fill='#3e3e54'/><g><polygon points='410.6 286.5 399.1 288 398.9 288.8 499.9 308.3 513.3 305.9 513.5 305 410.6 286.5' fill='#3e3e54'/><polygon points='395.7 283.7 395.9 282.8 248.2 255.7 239.2 257.3 239 258 384.3 286 395.7 283.7' fill='#3e3e54'/></g><polygon points='371.3 273.9 256.9 252.7 266.4 250.3 382.4 271.5 371.3 273.9' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.2' fill='none'/><polygon points='237.6 264.9 221.4 261.7 230.4 259.4 246.8 262.6 237.6 264.9' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.2' fill='none'/><polygon points='474.8 312 250 267.3 259.4 265.1 487.7 309.6 474.8 312' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.2' fill='none'/><polygon points='412 308.5 204.4 266 213.1 263.8 423.9 306.3 412 308.5' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.2' fill='none'/><polygon points='450.2 316.4 428.8 312 440.9 309.7 462.8 314.1 450.2 316.4' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.2' fill='none'/><polygon points='201.7 273.1 187.7 270.2 196.2 268 210.4 271 201.7 273.1' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.2' fill='none'/><polygon points='222.8 277.6 208.3 274.5 217.1 272.4 231.8 275.4 222.8 277.6' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.2' fill='none'/><polygon points='363.1 307.3 231.7 279.5 240.9 277.3 374.2 305.1 363.1 307.3' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.2' fill='none'/><polygon points='444.6 287.5 385.4 276.5 396.8 274.1 456.9 285 444.6 287.5' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.2' fill='none'/><polygon points='526.3 302.7 460.3 290.4 473 288 540.1 300.2 526.3 302.7' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.2' fill='none'/><polygon points='426.4 320.7 376.3 310.1 387.6 307.9 438.5 318.5 426.4 320.7' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.2' fill='none'/><g><polygon points='410.7 285.6 399.1 288 500.1 307.4 513.5 305 410.7 285.6' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.2' fill='none'/><polygon points='395.9 282.8 248.4 255 239.2 257.3 384.5 285.2 395.9 282.8' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.2' fill='none'/></g></g><g id='paw-right'>
<g id='paw-right--down' display='none'><path d='M293.2,191.3l10-7s-18.4,11.1-24,20-13,20.4-9,31c4.7,12.4,20.5,15.7,22,16,20,3.8,47.8-24.3,47.8-24.3s1.9-3.3,2.2-3.7' fill='#fff'/><path d='M342.1,223.4c.9,1.2.2,2.8-.3,3.7l-.4.7-.3.3a118.1,118.1,0,0,1-14.2,12.3,83.2,83.2,0,0,1-16.2,9.8,43.9,43.9,0,0,1-9.3,3,26.3,26.3,0,0,1-10.1.2,44.5,44.5,0,0,1-9.3-3.2,34.2,34.2,0,0,1-8.3-5.5,23,23,0,0,1-5.8-8.5,21.3,21.3,0,0,1-1.3-10.3,34.9,34.9,0,0,1,2.7-9.7,76.1,76.1,0,0,1,4.5-8.5l2.4-4,.6-1,.8-1.1a15.6,15.6,0,0,1,1.6-2,49.9,49.9,0,0,1,7-6.8,136.1,136.1,0,0,1,15.3-11.2,3.1,3.1,0,0,1,4.4,1,3,3,0,0,1-.8,4.2H305l-8.6,6.2c-.9.6-2.7-.5-3.1-1.9s.5-4.4,1.5-5l6.6-4.5,3.5,5.3A131.9,131.9,0,0,0,290,197.4a52.7,52.7,0,0,0-6.4,6,6.5,6.5,0,0,0-1.3,1.6l-.6.8-.7,1-2.4,3.8c-1.6,2.6-3.1,5.2-4.4,7.8a27.7,27.7,0,0,0-2.4,8.1,15.6,15.6,0,0,0,.8,8,17.4,17.4,0,0,0,4.4,6.7,27.2,27.2,0,0,0,7.1,4.9,39.5,39.5,0,0,0,8.1,3,21.6,21.6,0,0,0,8.4,0,37.8,37.8,0,0,0,8.5-2.6,84.9,84.9,0,0,0,15.7-9,142.4,142.4,0,0,0,14.1-11.6l-.3.3,1.1-1.8C340.3,223.4,341.3,222.2,342.1,223.4Z'/></g>
<g id='paw-right--up' display='inline'><g><path d='M282.2,215.2c-1.6-1.6-12.8-17.9-14-34.3-.1-2.5,1.7-16,12.9-22.4s22.3-1.9,26.2.4c12.2,7.3,21.2,19.1,22.8,22.4' fill='#fff'/><path d='M330,181.2a2.4,2.4,0,0,1-2.6-1.3,71.4,71.4,0,0,0-9.8-10.8,64,64,0,0,0-11.7-8.6,26.3,26.3,0,0,0-6.5-2.3,26.9,26.9,0,0,0-6.9-.6,24.9,24.9,0,0,0-6.7,1.3,20.8,20.8,0,0,0-5.8,3.3,23.1,23.1,0,0,0-7.6,11,32.5,32.5,0,0,0-1.4,6.6,6.6,6.6,0,0,0,.1,1.4l.2,1.8c.1,1.2.4,2.3.6,3.5a65,65,0,0,0,4.8,13.4c1,2.2,2.2,4.3,3.4,6.4a43.1,43.1,0,0,0,3.9,5.9.6.6,0,0,1,0,.6c0,.2-.2.4-.4.7a5.7,5.7,0,0,1-1.5,1.6c-1.3.6-4.1.1-4.6-.6a89.5,89.5,0,0,1-7.2-13.7,63.7,63.7,0,0,1-4.3-14.9,25.7,25.7,0,0,1-.5-4c0-.3-.1-.6-.1-1v-1.2a12.5,12.5,0,0,1,.2-2.1,35.2,35.2,0,0,1,2.4-7.8,28.6,28.6,0,0,1,4.1-6.9,24.6,24.6,0,0,1,6.1-5.5,26.2,26.2,0,0,1,15.5-4.2,28.9,28.9,0,0,1,7.8,1.2l3.8,1.3,1.8.9,1.8,1a78.2,78.2,0,0,1,11.9,9.6,80.2,80.2,0,0,1,9.7,11.8C331.1,179.7,331.4,181,330,181.2Z'/></g>
<use width='31.4' height='33.93' transform='translate(273.2 166.1) rotate(-5.6)' xlink:href='#paw-pads'/></g></g><g id='laptop__terminal'><path d='M316.9,238.7,153.5,205.2a5.1,5.1,0,0,1-4-3.5L109.8,75.4c-1-3.3,1.9-6.6,5.6-6.3L277.9,84.5a5.2,5.2,0,0,1,4.6,3.7l40.7,144.4C324.2,236.2,320.8,239.5,316.9,238.7Z'/><path d='M317.3,238.7a7.9,7.9,0,0,0,2.2-.7,5,5,0,0,0,2.2-1.9,3.7,3.7,0,0,0,.6-2.9l-.3-.8-.2-.9a15.4,15.4,0,0,1-.5-1.7L300,154.6l-10.7-37.5L284,98.3l-2.6-9.4a7.9,7.9,0,0,0-.4-.9,4.3,4.3,0,0,0-.4-.7,3.3,3.3,0,0,0-1.5-1.1l-.9-.3h-1.1l-2.4-.2L119.2,71.2l-2.4-.3h-2.2a3.3,3.3,0,0,0-2.8,1.6,2.4,2.4,0,0,0-.5,1.4v.8c.1.1.1.2.1.4l.2.6,1.5,4.6L119,98.8l11.8,37.3,11.7,37.2,5.9,18.6,2.9,9.3a3.4,3.4,0,0,0,2.2,2h1l1.2.3,2.4.4,153,31.1c4.3.9,7.4,2.9,5.2,3.3s-11.7-.1-16-1l-75.8-15.7L186.6,214l-19-3.9-9.5-2-4.7-1h-.7l-.8-.3a6.1,6.1,0,0,1-1.4-.7,7.6,7.6,0,0,1-2.3-2.4l-.4-.8a1.9,1.9,0,0,1-.2-.7l-.4-1.2-.7-2.3-1.4-4.6-2.9-9.2-5.8-18.5-11.5-36.9-11.5-37-2.9-9.2L109,78.5l-.7-2.3v-.6c0-.3-.1-.6-.1-.8a4.8,4.8,0,0,1,0-1.7,6.8,6.8,0,0,1,3.8-5,10.1,10.1,0,0,1,3-.7h2.6l9.6,1L204.1,76l38.5,3.7,19.3,1.9,9.6.9,4.8.5h2.6a6.6,6.6,0,0,1,2.7,1.2,7.2,7.2,0,0,1,1.9,2.4,12.1,12.1,0,0,1,.5,1.4l.3,1.1,1.3,4.7,2.6,9.3,5.2,18.6,10.4,37.3,10.4,37.3,5.3,18.6,2.6,9.4,1.3,4.6.6,2.4a7,7,0,0,1,.4,2.7,5.7,5.7,0,0,1-1.8,3.7,5.9,5.9,0,0,1-3.4,1.6,3.5,3.5,0,0,1-2.1-.4C316.7,239,316.8,238.9,317.3,238.7Z'/></g><g id='laptop__terminal_code_scene'><g id='laptop__code' transform='matrix(0.6394 0.0864 0.2714 0.9043 27.5110 -5.1253)'><g stroke='#3DE0E8' stroke-width='6' transform='matrix(-1 0 0 1 278 103)'><g id='f3' transform='translate(0 76)'><path id='f3-l9' d='M8,25L8,25' stroke-dasharray='60,10'/><path id='f3-l8' d='M8,13L8,13' stroke-dasharray='50,10'/><path id='f3-l7' d='M0,1L0,1' stroke-dasharray='25,10'/></g><g id='f2' transform='translate(0 38)'><path id='f2-l6' d='M8,25L8,25' stroke-dasharray='40,10'/><path id='f2-l5' d='M8,13L8,13' stroke-dasharray='60,10'/><path id='f2-l4' d='M0,1L0,1' stroke-dasharray='30,10'/></g><g id='f1'><path id='f1-l3' d='M8,25L8,25' stroke-dasharray='60,10'/><path id='f1-l2' d='M8,13L8,13' stroke-dasharray='60,10'/><path id='f1-l1' d='M0,1L0,1' stroke-dasharray='60,10'/></g></g></g></g><g id='laptop__cover' opacity='0.55'><polygon points='440.7 347.2 90.3 275.6 4.7 3.8 353 36.7 440.7 347.2' fill='#f2f2f2'/><path d='M440.4,346.4c-2.5-5.3-6.5-18.8-9-27.4L390.7,178c-13.6-46.8-26.9-93.7-40.3-140.6l2.3,2L4.4,7.1,7.9,2.8,94,274.5l-2.9-2.6q83.7,16.8,166.8,34.2t166.8,35.4c8.8,1.9,17.5,5.1,14.7,5.5s-6.3-.2-12-.9-12.3-1.5-16.8-2.3Q330.5,328.1,250,312.1c-53.5-10.8-107.1-21.7-160.4-32.7l-2.3-.5-.6-2.1L1.5,4.8,0,0,5,.5,353.3,34l1.8.2.5,1.8q20.7,73.8,41.2,147.8l40.6,147.5C439.8,340.1,442.9,351.7,440.4,346.4Z'/></g></g><g id='paw-left'>
<g id='paw-left--up' display='none'><g><path d='M545.4,261.9c-7.1-13-12.9-31.1-13.3-37.6-.6-9,0-15.6,5.2-22.2s15-9.8,22.7-8.8a26.7,26.7,0,0,1,17.3,9.4c5.3,5.8,9.4,12.9,11.6,16.6' fill='#fff'/><path d='M588.9,219.2c-1.4.4-2.3-.7-2.8-1.4a93.9,93.9,0,0,0-8.9-12.5c-3.3-3.9-7.1-7-11.7-8.6a24.2,24.2,0,0,0-7.1-1.4,24.5,24.5,0,0,0-7.1.7,27,27,0,0,0-6.6,2.7,21,21,0,0,0-5.2,4.6,20.6,20.6,0,0,0-3.5,6.1,22.2,22.2,0,0,0-1.3,6.9,47.3,47.3,0,0,0,.1,7.5,52.2,52.2,0,0,0,1.4,7.1c1.4,4.8,3.1,9.7,5,14.4a147.7,147.7,0,0,0,6.5,13.9c.4.7-1,2.3-2.4,2.6s-4-.6-4.4-1.4c-2.3-4.8-4.3-9.7-6.1-14.6a128.8,128.8,0,0,1-4.6-15.3c-.3-1.3-.5-2.6-.7-4a16.4,16.4,0,0,1-.2-2.2v-2a57,57,0,0,1,.4-8.2,27.2,27.2,0,0,1,2.3-8.2c.7-1.3,1.4-2.5,2.2-3.7l1.3-1.7,1.4-1.6a28.8,28.8,0,0,1,7-5,27.6,27.6,0,0,1,8-2.5,25.6,25.6,0,0,1,8.3-.2,27.4,27.4,0,0,1,15.1,6.7,50.6,50.6,0,0,1,5.5,5.9,111.3,111.3,0,0,1,8.7,13.2C589.8,217.7,590.3,218.9,588.9,219.2Z'/></g>
<use width='31.4' height='33.93' transform='matrix(0.99 -0.03 0.04 1 539.85 203.52)' xlink:href='#paw-pads'/></g>
<g id='paw-left--down' display='inline'><path d='M538.2,239.3c-3.2,1.6-33,10.8-37,28-.4,1.8-2.1,18.9,7,26,5.5,4.3,12.7,2.8,25,0,10.3-2.3,19-5.8,40-16,9.1-4.4,16.6-8.2,22-11' fill='#fff'/><path d='M595.1,266.4c.1,1.4-1.4,2.4-2.4,2.9l-18.3,9.4c-6.2,3.1-12.3,6.1-18.6,9a120.8,120.8,0,0,1-19.6,7.2l-5.1,1.2-5.1,1.1a43.4,43.4,0,0,1-5.2.9,33.8,33.8,0,0,1-5.6.3,17.8,17.8,0,0,1-5.8-1.5,6.1,6.1,0,0,1-1.4-.7l-1.3-.9-2.2-2a23.6,23.6,0,0,1-5.2-10.2,44.5,44.5,0,0,1-1.3-10.9c0-.9.1-1.8.1-2.7a6.6,6.6,0,0,0,.1-1.4v-.7c.1-.3.1-.7.2-.9a21.6,21.6,0,0,1,2.1-5.5,33.4,33.4,0,0,1,7.1-8.7,67.1,67.1,0,0,1,8.7-6.4,121.7,121.7,0,0,1,19-9,1.5,1.5,0,0,1,1.7.6,3.4,3.4,0,0,1,.9,1.9c.1,1.5-1.6,4.2-2.6,4.6a91.1,91.1,0,0,0-17.8,8.5,40.1,40.1,0,0,0-7.6,5.8,22.8,22.8,0,0,0-5.2,7.3l-.4,1-.3,1a1.7,1.7,0,0,0-.2.5v.4c-.1.4-.1.8-.2,1.2s-.1,3.1-.1,4.7a35.4,35.4,0,0,0,1.4,9.3,15.6,15.6,0,0,0,4.5,7.3c2,1.9,4.7,2.6,7.8,2.5a55.9,55.9,0,0,0,9.7-1.2l4.9-1.1,4.9-1.1a121,121,0,0,0,18.8-6.8c12.4-5.3,24.6-11.5,36.8-17.4C593.4,265.4,595,264.9,595.1,266.4Z'/></g></g></svg>";
}
