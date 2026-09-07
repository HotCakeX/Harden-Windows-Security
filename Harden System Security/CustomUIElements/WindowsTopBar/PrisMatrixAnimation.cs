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
using System.Numerics;
using Microsoft.Graphics.Canvas;
using Microsoft.Graphics.Canvas.Geometry;
using Microsoft.Graphics.Canvas.UI.Xaml;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

// A self-contained rotating animation control. While loaded, the XAML composition callback
// invalidates its CanvasControl and its Stopwatch supplies animation time. Unloading stops callbacks
// and releases the canvas.
internal sealed partial class PrisMatrixAnimation : UserControl
{
	private const int Rows = 5;
	private const int Faces = 4;
	private const double RotationSeconds = 13.57;
	private const double SizeSeconds = 3.91;
	private const float FaceTiltDegrees = 35.2644f;
	private const float InradiusFactor = 0.20412f;
	private static readonly float TriangleHeightFactor = 0.5f * MathF.Sqrt(3.0f);
	private static readonly Color FrontColor = Color.FromArgb(255, 242, 242, 242);
	private static readonly Color BackColor = Color.FromArgb(255, 255, 30, 173);
	private static readonly Color EdgeColor = Color.FromArgb(70, 0, 0, 0);

	private CanvasControl? _canvas;
	private readonly Stopwatch _animationClock = new();

	// A single small triangle of a face, in face-local design units, with its
	// centroid, whether it points up, and its column index used for the animation wave.
	private readonly struct FaceTriangle(Vector2 a, Vector2 b, Vector2 c, Vector2 centroid, int columnIndex)
	{
		internal Vector2 A => a;
		internal Vector2 B => b;
		internal Vector2 C => c;
		internal Vector2 Centroid => centroid;
		internal int ColumnIndex => columnIndex;
	}

	// One face: its yaw, tilt, vertical flip sign, and index (for the wave delay).
	private readonly struct FaceParams(float yawDegrees, float tiltDegrees, float flipSign, int index)
	{
		internal float YawDegrees => yawDegrees;
		internal float TiltDegrees => tiltDegrees;
		internal float FlipSign => flipSign;
		internal int Index => index;
	}

	// A ready-to-draw triangle for one frame: three screen points, fill color, and the paint-order
	// sort key (true average depth, plus the back-tier bias when the triangle faces away from the
	// camera) used for painter's-order sorting (drawn far to near).
	private struct DrawTriangle
	{
		internal Vector2 P0;
		internal Vector2 P1;
		internal Vector2 P2;
		internal Color Fill;
		internal byte Opacity;
		internal float Depth;
		// A stable insertion order used as a tiebreaker so triangles at equal depth keep a fixed
		// relative draw order every frame. Array.Sort is not stable, so without this two overlapping
		// equal-depth triangles could swap order frame to frame and visibly flicker/pop.
		internal int Order;
	}

	private static readonly FaceTriangle[] Triangles = BuildFaceTriangles();
	private static readonly FaceParams[] FaceList =
	[
		new FaceParams(270.0f, FaceTiltDegrees, -1.0f, 3),
		new FaceParams(180.0f, -FaceTiltDegrees, 1.0f, 2),
		new FaceParams(90.0f, FaceTiltDegrees, -1.0f, 1),
		new FaceParams(0.0f, -FaceTiltDegrees, 1.0f, 0)
	];

	// Per-frame scratch buffer for all faces x triangles, reused to avoid allocation.
	private readonly DrawTriangle[] _drawBuffer = new DrawTriangle[Faces * Rows * Rows];

	internal PrisMatrixAnimation()
	{
		IsTabStop = false;
		Loaded += OnLoaded;
		Unloaded += OnUnloaded;
	}

	private void OnLoaded(object sender, RoutedEventArgs e)
	{
		if (!_animationClock.IsRunning)
		{
			_animationClock.Start();
			CompositionTarget.Rendering += OnAnimationRendering;
		}
		if (_canvas is null)
		{
			_canvas = CreateCanvas();
			Content = _canvas;
		}
	}

	private void OnUnloaded(object sender, RoutedEventArgs e)
	{
		CompositionTarget.Rendering -= OnAnimationRendering;
		_animationClock.Stop();
		if (_canvas is not null)
		{
			_canvas.Draw -= OnDraw;
			_canvas.RemoveFromVisualTree();
			_canvas = null;
		}

		Content = null;
	}

	private void OnAnimationRendering(object? sender, object e) => _canvas?.Invalidate();

	private CanvasControl CreateCanvas()
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

		canvas.Draw += OnDraw;
		return canvas;
	}

	private void OnDraw(CanvasControl sender, CanvasDrawEventArgs args)
	{
		float width = (float)sender.Size.Width;
		float height = (float)sender.Size.Height;

		if (width < 2.0f || height < 2.0f)
		{
			return;
		}

		CanvasDrawingSession drawingSession = args.DrawingSession;

		float minDimension = MathF.Min(width, height);
		float edge = minDimension * 0.18f;
		float perspective = 6.67f * edge;
		float translateZ = Rows * InradiusFactor * edge;
		float centerX = width * 0.5f;
		float centerY = height * 0.5f;

		double totalSeconds = _animationClock.Elapsed.TotalSeconds;
		float globalYaw = (float)(totalSeconds % RotationSeconds / RotationSeconds) * 360.0f;
		float sizePhase = (float)(totalSeconds % SizeSeconds / SizeSeconds);

		int count = 0;
		foreach (FaceParams face in FaceList)
		{
			float yawRadians = (globalYaw + face.YawDegrees) * MathF.PI / 180.0f;
			float tiltRadians = face.TiltDegrees * MathF.PI / 180.0f;
			float cosYaw = MathF.Cos(yawRadians);
			float sinYaw = MathF.Sin(yawRadians);
			float cosTilt = MathF.Cos(tiltRadians);
			float sinTilt = MathF.Sin(tiltRadians);
			// Compute one continuous facing value for the whole planar face from fixed geometry.
			// This avoids the per-triangle boolean front/back switch problem, which would change a whole
			// face's color and sort tier in one frame as the face crossed edge-on.
			float facing = GetFaceFacing(edge, face.FlipSign, translateZ, perspective, cosTilt, sinTilt, cosYaw, sinYaw);
			Color faceColor = LerpColor(BackColor, FrontColor, facing);

			foreach (FaceTriangle triangle in Triangles)
			{
				// Diagonal wave: each triangle grows based on its column and face index.
				// The scale pulses 0 -> 1 -> 0 so the loop is seamless.
				float delay = triangle.ColumnIndex / 11.0f / 2.0f + face.Index / (float)Faces;
				float local = sizePhase - delay;
				local -= MathF.Floor(local);
				float scale = PulseScale(local);
				// Keep the triangle in the stable draw list for the complete cycle and fade it
				// continuously near zero. A hard scale cutoff causes a one-frame disappearance.
				float opacity = Smootherstep(Math.Clamp(scale / 0.15f, 0.0f, 1.0f));

				scale *= 0.95f;

				Vector3 v0 = Project(triangle.A, triangle.Centroid, scale, edge, face.FlipSign, translateZ, cosTilt, sinTilt, cosYaw, sinYaw);
				Vector3 v1 = Project(triangle.B, triangle.Centroid, scale, edge, face.FlipSign, translateZ, cosTilt, sinTilt, cosYaw, sinYaw);
				Vector3 v2 = Project(triangle.C, triangle.Centroid, scale, edge, face.FlipSign, translateZ, cosTilt, sinTilt, cosYaw, sinYaw);


				float divisor0 = perspective - v0.Z;
				float divisor1 = perspective - v1.Z;
				float divisor2 = perspective - v2.Z;
				if (divisor0 <= 1.0f || divisor1 <= 1.0f || divisor2 <= 1.0f)
				{
					continue; // behind or too close to the camera plane
				}

				float f0 = perspective / divisor0;
				float f1 = perspective / divisor1;
				float f2 = perspective / divisor2;

				// True continuous depth only. There is no discontinuous front/back tier.
				float sortDepth = (v0.Z + v1.Z + v2.Z) / 3.0f;

				DrawTriangle draw = new()
				{
					P0 = new Vector2(centerX + v0.X * f0, centerY + v0.Y * f0),
					P1 = new Vector2(centerX + v1.X * f1, centerY + v1.Y * f1),
					P2 = new Vector2(centerX + v2.X * f2, centerY + v2.Y * f2),
					Fill = faceColor,
					Opacity = (byte)Math.Clamp((int)MathF.Round(255.0f * opacity), 0, 255),
					Depth = sortDepth,
					Order = count
				};
				_drawBuffer[count++] = draw;
			}
		}

		// Painter's order: draw the deepest (most negative Z) first.
		Array.Sort(_drawBuffer, 0, count, DepthComparer.Instance);

		for (int index = 0; index < count; index++)
		{
			DrawTriangle triangle = _drawBuffer[index];
			using CanvasPathBuilder pathBuilder = new(drawingSession);
			pathBuilder.BeginFigure(triangle.P0);
			pathBuilder.AddLine(triangle.P1);
			pathBuilder.AddLine(triangle.P2);
			pathBuilder.EndFigure(CanvasFigureLoop.Closed);
			using CanvasGeometry geometry = CanvasGeometry.CreatePath(pathBuilder);
			Color fill = Color.FromArgb(triangle.Opacity, triangle.Fill.R, triangle.Fill.G, triangle.Fill.B);
			byte edgeAlpha = (byte)((EdgeColor.A * triangle.Opacity + 127) / 255);
			Color edgeColor = Color.FromArgb(edgeAlpha, EdgeColor.R, EdgeColor.G, EdgeColor.B);
			drawingSession.FillGeometry(geometry, fill);
			drawingSession.DrawGeometry(geometry, edgeColor, 1.0f);
		}
	}

	// Returns a continuously eased back-to-front blend for one complete planar face. A fixed,
	// fully sized sample triangle is used, so the result cannot become numerically unstable when an
	// animated triangle is tiny. The transition band around edge-on deliberately blends pink and
	// white instead of switching them in one frame.
	private static float GetFaceFacing(
		float edge,
		float flipSign,
		float translateZ,
		float perspective,
		float cosTilt,
		float sinTilt,
		float cosYaw,
		float sinYaw)
	{
		FaceTriangle sample = Triangles[0];
		Vector3 v0 = Project(sample.A, sample.Centroid, 0.95f, edge, flipSign, translateZ, cosTilt, sinTilt, cosYaw, sinYaw);
		Vector3 v1 = Project(sample.B, sample.Centroid, 0.95f, edge, flipSign, translateZ, cosTilt, sinTilt, cosYaw, sinYaw);
		Vector3 v2 = Project(sample.C, sample.Centroid, 0.95f, edge, flipSign, translateZ, cosTilt, sinTilt, cosYaw, sinYaw);

		Vector2 p0 = PerspectiveProject(v0, perspective);
		Vector2 p1 = PerspectiveProject(v1, perspective);
		Vector2 p2 = PerspectiveProject(v2, perspective);
		Vector2 e0 = p1 - p0;
		Vector2 e1 = p2 - p0;
		float denominator = MathF.Sqrt(e0.LengthSquared() * e1.LengthSquared());
		if (denominator <= float.Epsilon)
		{
			return 0.5f;
		}

		float signedFacing = -((e0.X * e1.Y - e0.Y * e1.X) * flipSign) / denominator;
		const float transitionWidth = 0.18f;
		float normalized = (signedFacing + transitionWidth) / (2.0f * transitionWidth);
		return Smootherstep(Math.Clamp(normalized, 0.0f, 1.0f));
	}

	private static Vector2 PerspectiveProject(Vector3 point, float perspective)
	{
		float factor = perspective / (perspective - point.Z);
		return new Vector2(point.X * factor, point.Y * factor);
	}

	private static Color LerpColor(Color start, Color end, float amount)
	{
		float clamped = Math.Clamp(amount, 0.0f, 1.0f);
		return Color.FromArgb(
			255,
			(byte)MathF.Round(start.R + (end.R - start.R) * clamped),
			(byte)MathF.Round(start.G + (end.G - start.G) * clamped),
			(byte)MathF.Round(start.B + (end.B - start.B) * clamped));
	}

	private static Vector3 Project(
		Vector2 vertex,
		Vector2 centroid,
		float scale,
		float edge,
		float flipSign,
		float translateZ,
		float cosTilt,
		float sinTilt,
		float cosYaw,
		float sinYaw)
	{
		float x = (centroid.X + (vertex.X - centroid.X) * scale) * edge;
		float y = (centroid.Y + (vertex.Y - centroid.Y) * scale) * edge * flipSign;
		float z = translateZ;

		float y1 = y * cosTilt - z * sinTilt;
		float z1 = y * sinTilt + z * cosTilt;

		float x2 = x * cosYaw + z1 * sinYaw;
		float z2 = -x * sinYaw + z1 * cosYaw;

		return new Vector3(x2, y1, z2);
	}

	// Pulse 0 -> 1 -> 0 across the cycle so the infinite loop has no visible snap. Both the grow and the
	// shrink use smoothstep so their velocity is zero at every boundary: that removes the linear-ramp
	// corners that otherwise cause a "sudden move", making the motion continuously smooth (C1
	// continuous) across the whole loop, including the wrap back to the start.
	private static float PulseScale(float phase)
	{
		if (phase < 0.13f)
		{
			return 0.0f;
		}

		if (phase < 0.37f)
		{
			return Smoothstep((phase - 0.13f) / 0.24f);
		}

		if (phase < 0.76f)
		{
			return 1.0f;
		}

		if (phase < 1.0f)
		{
			return Smoothstep(1.0f - (phase - 0.76f) / 0.24f);
		}

		return 0.0f;
	}

	// Classic smoothstep: eases in and out with zero slope at t = 0 and t = 1.
	private static float Smoothstep(float t)
	{
		float clamped = Math.Clamp(t, 0.0f, 1.0f);
		return clamped * clamped * (3.0f - 2.0f * clamped);
	}

	// Quintic smootherstep has zero first and second derivatives at both ends.
	private static float Smootherstep(float t)
	{
		float clamped = Math.Clamp(t, 0.0f, 1.0f);
		return clamped * clamped * clamped * (clamped * (clamped * 6.0f - 15.0f) + 10.0f);
	}

	// Builds the 25 small triangles subdividing one big triangular face,
	// centered on the face centroid, apex pointing up. Each carries its column index for the
	// animation wave. Face-local units use edge length = 1.
	private static FaceTriangle[] BuildFaceTriangles()
	{
		FaceTriangle[] result = new FaceTriangle[Rows * Rows];
		int index = 0;

		float bigHeight = Rows * TriangleHeightFactor;
		float centroidY = 2.0f / 3.0f * bigHeight;

		for (int row = 0; row < Rows; row++)
		{
			float topY = row * TriangleHeightFactor - centroidY;
			float bottomY = (row + 1) * TriangleHeightFactor - centroidY;

			// Up-pointing triangles: apex on the top edge, base on the bottom edge.
			for (int i = 0; i <= row; i++)
			{
				float topX = (-row / 2.0f + i) * 1.0f;
				float baseX0 = (-(row + 1) / 2.0f + i) * 1.0f;
				float baseX1 = (-(row + 1) / 2.0f + i + 1) * 1.0f;
				result[index++] = MakeTriangle(new Vector2(topX, topY), new Vector2(baseX0, bottomY), new Vector2(baseX1, bottomY));
			}

			// Down-pointing triangles: base on the top edge, apex on the bottom edge.
			for (int i = 0; i < row; i++)
			{
				float topX0 = (-row / 2.0f + i) * 1.0f;
				float topX1 = (-row / 2.0f + i + 1) * 1.0f;
				float baseX = (-(row + 1) / 2.0f + i + 1) * 1.0f;
				result[index++] = MakeTriangle(new Vector2(topX0, topY), new Vector2(topX1, topY), new Vector2(baseX, bottomY));
			}
		}

		return result;
	}

	private static FaceTriangle MakeTriangle(Vector2 a, Vector2 b, Vector2 c)
	{
		Vector2 centroid = new((a.X + b.X + c.X) / 3.0f, (a.Y + b.Y + c.Y) / 3.0f);
		int columnIndex = (int)MathF.Round(5.0f + centroid.X / 0.5f);
		columnIndex = Math.Clamp(columnIndex, 1, 9);
		return new FaceTriangle(a, b, c, centroid, columnIndex);
	}

	private sealed class DepthComparer : IComparer<DrawTriangle>
	{
		internal static readonly DepthComparer Instance = new();

		public int Compare(DrawTriangle x, DrawTriangle y)
		{
			int byDepth = x.Depth.CompareTo(y.Depth);
			return byDepth != 0 ? byDepth : x.Order.CompareTo(y.Order);
		}
	}
}
