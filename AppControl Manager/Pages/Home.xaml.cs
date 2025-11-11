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
using Microsoft.Graphics.Canvas.UI.Xaml;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.Foundation;
using Windows.UI;

#pragma warning disable CA5394

namespace AppControlManager.Pages;

internal sealed partial class Home : Page, IDisposable, CommonCore.UI.IInvisibleCrumbar
{
#if HARDEN_SYSTEM_SECURITY
	private ViewModels.HomeVM ViewModel { get; } = HardenSystemSecurity.ViewModels.ViewModelProvider.HomeVM;
#else
	private ViewModels.HomeVM ViewModel { get; } = ViewModels.ViewModelProvider.HomeVM;
#endif


	// This is necessary so that the carousel content wouldn't be visible briefly after navigating to another page by clicking on one of the carousel tiles.
	protected override void OnNavigatingFrom(NavigatingCancelEventArgs e)
	{
		// Brute-force Teardown ensures the old page cannot render a single more frame during navigation.

		// Stop any CompositionTarget.Rendering callbacks immediately.
		try
		{
			DetachRenderHook();
		}
		catch
		{
			// No-op: teardown must never throw
		}

		// Remove Win2D CanvasControl from the tree so it cannot draw.
		try
		{
			if (BackgroundCanvas != null)
			{
				// Prefer removing from parent panel; this guarantees it's gone even if RemoveFromVisualTree is unavailable.
				if (BackgroundCanvas.Parent is Panel parentPanel)
				{
					_ = parentPanel.Children.Remove(BackgroundCanvas);
				}
				else
				{
					// Fallback for Win2D's helper in case available
					try
					{
						BackgroundCanvas.RemoveFromVisualTree();
					}
					catch
					{
						// Ignore
					}
				}
			}
		}
		catch
		{
			// Ignore
		}

		// Proactively drop any graph data so nothing keeps the page alive.
		_bgNodes = null;
		_bgEdges = null;
		_bgStarEdges?.Clear();
		_bgStarEdges = null;
		_bgNodeCount = 0;
		_bgEdgeCount = 0;

		// Clear both visual layers. This forces Unloaded to fire on all children (carousel, opacity mask view, lights, etc.),
		// So their own cleanup runs (timers stop, Composition resources disposed).
		try
		{
			BackgroundLayer?.Children.Clear();
			ContentLayer?.Children.Clear();
		}
		catch
		{
			// Ignore
		}

		// Nuke the page content so Frame has nothing to render from this page while it swaps to the next.
		// This guarantees no "ghost" visuals during DrillIn or even with no animation.
		try
		{
			this.Content = null;
		}
		catch
		{
			// Ignore
		}

		// Finally navigate to the requested page.
		base.OnNavigatingFrom(e);
	}


	private static readonly Random _random = new(0x5A17C3);

	// Global timings
	private static readonly Stopwatch _animationStopwatch = Stopwatch.StartNew();
	private double _animationTimeSeconds;
	private bool _renderHookAttached;

	// Idle gating flags (avoids continuous redraws)
	private bool _needsBackgroundRedrawOnce;

	// Web Background (clustered twinkles)

	private struct BgNode
	{
		internal float BaseX;
		internal float BaseY;
		internal float PhaseX;
		internal float PhaseY;
		internal float Seed;
		internal byte Layer;
	}

	private struct BgEdge
	{
		internal int A;
		internal int B;
		internal byte Layer;
	}

	private struct StarEdgePersist
	{
		internal int A;
		internal int B;
		internal byte Layer;
		internal double ExpireAt;
	}

	private BgNode[]? _bgNodes;
	private int _bgNodeCount;
	private BgEdge[]? _bgEdges;
	private int _bgEdgeCount;

	private List<StarEdgePersist>? _bgStarEdges;

	private float _bgLastW;
	private float _bgLastH;

	private double _bgLastEdgeRebuildTime;
	private double _bgLastStarCreateTime;

	// Background "twinkle" cadence (single frame)
	private double _bgNextTwinkleTime;

	internal Home()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	private void OnInitialLoaded(object sender, RoutedEventArgs e)
	{
		// One-time draws on load
		_needsBackgroundRedrawOnce = true;

		AttachRenderHook();

		// Initial invalidations
		if (BackgroundCanvas != null)
		{
			BackgroundCanvas.Invalidate();
			_needsBackgroundRedrawOnce = false;
		}

		// Schedule the first background twinkle refresh (slow cadence)
		_bgNextTwinkleTime = _animationStopwatch.Elapsed.TotalSeconds + 7.5 + _random.NextDouble() * 1.5;

		// Run the code that needs to run in ViewModel class when page is loaded.
		ViewModel.OnHomePageLoaded(sender);
	}

	private void AttachRenderHook()
	{
		if (_renderHookAttached)
			return;

		CompositionTarget.Rendering += OnRendering;
		_renderHookAttached = true;
	}

	private void DetachRenderHook()
	{
		if (!_renderHookAttached)
			return;

		CompositionTarget.Rendering -= OnRendering;
		_renderHookAttached = false;
	}

	private void OnRendering(object? sender, object e)
	{
		_animationTimeSeconds = _animationStopwatch.Elapsed.TotalSeconds;

		// Background: single-frame refresh when needed, slow twinkles otherwise
		if (_needsBackgroundRedrawOnce && BackgroundCanvas != null)
		{
			BackgroundCanvas.Invalidate();
			_needsBackgroundRedrawOnce = false;
		}
		else if (BackgroundCanvas != null && _animationTimeSeconds >= _bgNextTwinkleTime)
		{
			BackgroundCanvas.Invalidate();
			_bgNextTwinkleTime = _animationTimeSeconds + 7.5 + _random.NextDouble() * 1.5;
		}
	}

	private void OnUnloadedDisposeResources(object sender, RoutedEventArgs e)
	{
		DetachRenderHook();

		_bgNodes = null;
		_bgEdges = null;
		_bgNodeCount = 0;
		_bgEdgeCount = 0;
		_bgStarEdges?.Clear();
		_bgStarEdges = null;

		// Run the code that needs to run in ViewModel class when page is unloaded.
		ViewModel.OnHomePageUnLoaded();
	}

	#region Background Web (static idle, clustered one-frame twinkles)

	private void OnBackgroundCanvasDraw(CanvasControl sender, CanvasDrawEventArgs args)
	{
		float w = (float)sender.ActualWidth;
		float h = (float)sender.ActualHeight;
		if (w < 2.0f || h < 2.0f)
		{
			return;
		}

		// Initialize or rebuild graph on size change
		if (_bgNodes == null || _bgEdges == null || Math.Abs(w - _bgLastW) > 0.5f || Math.Abs(h - _bgLastH) > 0.5f)
		{
			InitializeBackgroundGraph(w, h);
			RebuildBackgroundEdges(w, h);
			_bgLastW = w;
			_bgLastH = h;
			_bgLastEdgeRebuildTime = _animationTimeSeconds;
			_bgNextTwinkleTime = _animationTimeSeconds + 7.5 + _random.NextDouble() * 1.5;
		}

		// Rebuild edges very infrequently (mostly static net) to keep GPU usage minimum.
		if (_animationTimeSeconds - _bgLastEdgeRebuildTime > 60.0)
		{
			RebuildBackgroundEdges(w, h);
			_bgLastEdgeRebuildTime = _animationTimeSeconds;
		}

		// Determine tint influence
		Color accent = Color.FromArgb(255, 220, 180, 110);
		double tintInfluence = 0.12;

		// Quantize time heavily to keep stillness
		double tQuant = Math.Floor(_animationTimeSeconds / 8.00) * 8.00;

		// Node positions
		Vector2[] positions = new Vector2[_bgNodeCount];
		const float layer0Speed = 0.50f;
		const float layer1Speed = 0.35f;
		float ampX0 = w * 0.006f;
		float ampY0 = h * 0.008f;
		float ampX1 = w * 0.004f;
		float ampY1 = h * 0.006f;

		for (int i = 0; i < _bgNodeCount; i++)
		{
			BgNode n = _bgNodes![i];
			float speed = n.Layer == 0 ? layer0Speed : layer1Speed;
			float ax = n.Layer == 0 ? ampX0 : ampX1;
			float ay = n.Layer == 0 ? ampY0 : ampY1;

			double t = tQuant * (0.05 + 0.03 * n.Seed) * speed;
			float dx = (float)(ax * Math.Sin(n.PhaseX + t));
			float dy = (float)(ay * Math.Cos(n.PhaseY + t * 0.85));

			float x = n.BaseX * w + dx;
			float y = n.BaseY * h + dy;

			positions[i] = new Vector2(x, y);
		}

		// Stars (persisting motifs)
		MaybeUpdateStarEdges(positions, w, h);

		// Colors
		Color baseEdge = Color.FromArgb(28, 70, 85, 110);
		Color edgeTint = MixColors(baseEdge, accent, tintInfluence);
		Color baseEdgeBack = Color.FromArgb(18, 60, 75, 100);
		Color edgeTintBack = MixColors(baseEdgeBack, accent, tintInfluence * 0.8);

		// Edges
		for (int i = 0; i < _bgEdgeCount; i++)
		{
			BgEdge e = _bgEdges![i];
			Vector2 a = positions[e.A];
			Vector2 b = positions[e.B];

			float dx = b.X - a.X;
			float dy = b.Y - a.Y;
			float dist = MathF.Sqrt(dx * dx + dy * dy);
			if (dist <= 0.5f)
			{
				continue;
			}

			float refDist = MathF.Min(w, h) * (e.Layer == 0 ? 0.18f : 0.22f);
			float lengthFactor = MathF.Max(0.0f, 1.0f - (dist / refDist));

			byte alpha = (byte)Math.Clamp((int)((e.Layer == 0 ? 38.0f : 26.0f) * lengthFactor), 8, 56);
			Color c = e.Layer == 0 ? Color.FromArgb(alpha, edgeTint.R, edgeTint.G, edgeTint.B)
								   : Color.FromArgb(alpha, edgeTintBack.R, edgeTintBack.G, edgeTintBack.B);

			args.DrawingSession.DrawLine(a, b, c, 1.0f);
		}

		// Persistent stars
		if (_bgStarEdges != null && _bgStarEdges.Count > 0)
		{
			for (int i = _bgStarEdges.Count - 1; i >= 0; i--)
			{
				StarEdgePersist se = _bgStarEdges[i];
				if (se.ExpireAt <= _animationTimeSeconds)
				{
					continue;
				}

				Vector2 a = positions[se.A];
				Vector2 b = positions[se.B];

				float dx = b.X - a.X;
				float dy = b.Y - a.Y;
				float dist = MathF.Sqrt(dx * dx + dy * dy);
				if (dist <= 0.5f)
				{
					continue;
				}

				Color baseC = Color.FromArgb(54, edgeTint.R, edgeTint.G, edgeTint.B);
				Color glowC = Color.FromArgb(18, edgeTint.R, edgeTint.G, edgeTint.B);

				args.DrawingSession.DrawLine(a, b, baseC, 1.2f);
				args.DrawingSession.DrawLine(a, b, glowC, 2.0f);
			}
		}

		// One-frame clustered twinkles (foreground layer)
		if (_bgEdgeCount > 0)
		{
			// Build adjacency for layer 0
			List<int>[] adj = new List<int>[_bgNodeCount];
			for (int i = 0; i < _bgNodeCount; i++) { adj[i] = new List<int>(6); }
			for (int i = 0; i < _bgEdgeCount; i++)
			{
				BgEdge e = _bgEdges![i];
				if (e.Layer != 0) { continue; }
				adj[e.A].Add(e.B);
				adj[e.B].Add(e.A);
			}

			int seedCount = Math.Clamp(_bgNodeCount / 80, 1, 2);
			List<int> seeds = new(seedCount);

			int attempts = 0;
			while (seeds.Count < seedCount && attempts < 40)
			{
				int idx = _random.Next(_bgNodeCount);
				attempts++;
				if (_bgNodes![idx].Layer != 0) { continue; }
				if (adj[idx].Count == 0) { continue; }
				bool already = false;
				for (int s = 0; s < seeds.Count; s++) { if (seeds[s] == idx) { already = true; break; } }
				if (!already) { seeds.Add(idx); }
			}
			if (seeds.Count == 0 && _bgNodeCount > 0) { seeds.Add(0); }

			for (int s = 0; s < seeds.Count; s++)
			{
				int seed = seeds[s];
				bool[] mask = new bool[_bgNodeCount];
				mask[seed] = true;
				List<int> neigh = adj[seed];
				for (int j = 0; j < neigh.Count; j++) { mask[neigh[j]] = true; }

				List<int> candidateEdges = new(32);
				for (int i = 0; i < _bgEdgeCount; i++)
				{
					BgEdge e = _bgEdges![i];
					if (e.Layer != 0) { continue; }
					if (mask[e.A] || mask[e.B]) { candidateEdges.Add(i); }
				}
				if (candidateEdges.Count == 0) { continue; }

				int perCluster = Math.Clamp(candidateEdges.Count / 6, 2, 6);

				Color baseC = edgeTint;
				for (int k = 0; k < perCluster; k++)
				{
					int ei = candidateEdges[_random.Next(candidateEdges.Count)];
					BgEdge e = _bgEdges![ei];

					Vector2 a = positions[e.A];
					Vector2 b = positions[e.B];
					float t = 0.35f + (float)_random.NextDouble() * 0.30f;
					Vector2 p = new(a.X + (b.X - a.X) * t, a.Y + (b.Y - a.Y) * t);

					byte twinkleAlpha = 140;
					byte haloAlpha = 40;

					Color twinkleColor = Color.FromArgb(twinkleAlpha, baseC.R, baseC.G, baseC.B);
					Color haloColor = Color.FromArgb(haloAlpha, baseC.R, baseC.G, baseC.B);

					float size = 2.4f;
					float halo = 5.0f;

					args.DrawingSession.FillEllipse(p, halo, halo, haloColor);
					Rect r = new(p.X - size * 0.5f, p.Y - size * 0.5f, size, size);
					args.DrawingSession.FillRectangle(r, twinkleColor);
				}
			}
		}
	}

	private void InitializeBackgroundGraph(float w, float h)
	{
		double density = Math.Sqrt(w * h) / 14.0;
		int totalNodes = Math.Clamp((int)Math.Round(density), 40, 100);

		_bgNodeCount = totalNodes;
		_bgNodes = new BgNode[_bgNodeCount];

		int layer0Count = (int)Math.Round(_bgNodeCount * 0.60);
		int layer1Count = _bgNodeCount - layer0Count;

		float margin = 0.04f;

		for (int i = 0; i < layer0Count; i++)
		{
			_bgNodes[i] = new BgNode
			{
				BaseX = margin + (float)_random.NextDouble() * (1.0f - 2.0f * margin),
				BaseY = margin + (float)_random.NextDouble() * (1.0f - 2.0f * margin),
				PhaseX = (float)(_random.NextDouble() * Math.PI * 2.0),
				PhaseY = (float)(_random.NextDouble() * Math.PI * 2.0),
				Seed = (float)_random.NextDouble(),
				Layer = 0
			};
		}

		for (int i = 0; i < layer1Count; i++)
		{
			int idx = layer0Count + i;
			_bgNodes[idx] = new BgNode
			{
				BaseX = margin + (float)_random.NextDouble() * (1.0f - 2.0f * margin),
				BaseY = margin + (float)_random.NextDouble() * (1.0f - 2.0f * margin),
				PhaseX = (float)(_random.NextDouble() * Math.PI * 2.0),
				PhaseY = (float)(_random.NextDouble() * Math.PI * 2.0),
				Seed = (float)_random.NextDouble(),
				Layer = 1
			};
		}

		if (_bgStarEdges == null)
		{
			_bgStarEdges = new List<StarEdgePersist>(16);
		}
		else
		{
			_bgStarEdges.Clear();
		}
	}

	private void RebuildBackgroundEdges(float w, float h)
	{
		if (_bgNodes == null || _bgNodeCount <= 1)
		{
			_bgEdges = [];
			_bgEdgeCount = 0;
			return;
		}

		Vector2[] pos = new Vector2[_bgNodeCount];

		double tQuant = Math.Floor(_animationTimeSeconds / 8.00) * 8.00;

		const float layer0Speed = 0.50f;
		const float layer1Speed = 0.35f;
		float ampX0 = w * 0.006f;
		float ampY0 = h * 0.008f;
		float ampX1 = w * 0.004f;
		float ampY1 = h * 0.006f;

		for (int i = 0; i < _bgNodeCount; i++)
		{
			BgNode n = _bgNodes[i];
			float speed = n.Layer == 0 ? layer0Speed : layer1Speed;
			float ax = n.Layer == 0 ? ampX0 : ampX1;
			float ay = n.Layer == 0 ? ampY0 : ampY1;

			double t = tQuant * (0.05 + 0.03 * n.Seed) * speed;
			float dx = (float)(ax * Math.Sin(n.PhaseX + t));
			float dy = (float)(ay * Math.Cos(n.PhaseY + t * 0.85));

			float x = n.BaseX * w + dx;
			float y = n.BaseY * h + dy;

			pos[i] = new Vector2(x, y);
		}

		List<BgEdge> edges = new(_bgNodeCount * 3);
		BuildEdgesForLayer(0, 3, pos, edges);
		BuildEdgesForLayer(1, 2, pos, edges);

		PruneAndAugmentEdges(pos, edges, w, h);

		_bgEdges = edges.ToArray();
		_bgEdgeCount = _bgEdges.Length;
	}

	private void BuildEdgesForLayer(byte layer, int k, Vector2[] pos, List<BgEdge> outEdges)
	{
		if (_bgNodes == null)
		{
			return;
		}

		for (int i = 0; i < _bgNodeCount; i++)
		{
			if (_bgNodes[i].Layer != layer)
			{
				continue;
			}

			int[] bestIdx = new int[k];
			float[] bestD2 = new float[k];
			for (int t = 0; t < k; t++)
			{
				bestIdx[t] = -1;
				bestD2[t] = float.MaxValue;
			}

			for (int j = 0; j < _bgNodeCount; j++)
			{
				if (j == i || _bgNodes[j].Layer != layer)
				{
					continue;
				}
				float dx = pos[j].X - pos[i].X;
				float dy = pos[j].Y - pos[i].Y;
				float d2 = dx * dx + dy * dy;

				for (int t = 0; t < k; t++)
				{
					if (d2 < bestD2[t])
					{
						for (int s = k - 1; s > t; s--)
						{
							bestD2[s] = bestD2[s - 1];
							bestIdx[s] = bestIdx[s - 1];
						}
						bestD2[t] = d2;
						bestIdx[t] = j;
						break;
					}
				}
			}

			for (int t = 0; t < k; t++)
			{
				int j = bestIdx[t];
				if (j >= 0 && i < j)
				{
					outEdges.Add(new BgEdge { A = i, B = j, Layer = layer });
				}
			}
		}
	}

	private void PruneAndAugmentEdges(Vector2[] pos, List<BgEdge> edges, float w, float h)
	{
		int count = edges.Count;
		if (count == 0)
		{
			return;
		}

		float[] lengths = new float[count];
		for (int i = 0; i < count; i++)
		{
			BgEdge e = edges[i];
			Vector2 a = pos[e.A];
			Vector2 b = pos[e.B];
			float dx = b.X - a.X;
			float dy = b.Y - a.Y;
			lengths[i] = MathF.Sqrt(dx * dx + dy * dy);
		}

		List<int> idxL0 = new(count);
		List<int> idxL1 = new(count);
		for (int i = 0; i < count; i++)
		{
			if (edges[i].Layer == 0) { idxL0.Add(i); } else { idxL1.Add(i); }
		}

		static float ComputeQuantile(List<int> idx, float[] values, double q)
		{
			if (idx.Count == 0) { return 0.0f; }
			int[] arr = idx.ToArray();
			Array.Sort(arr, (a, b) => values[a].CompareTo(values[b]));
			int qi = Math.Clamp((int)Math.Round((arr.Length - 1) * q), 0, arr.Length - 1);
			return values[arr[qi]];
		}

		float q20L0 = ComputeQuantile(idxL0, lengths, 0.20);
		float q20L1 = ComputeQuantile(idxL1, lengths, 0.20);

		List<BgEdge> kept = new(count);

		for (int i = 0; i < count; i++)
		{
			BgEdge e = edges[i];
			float len = lengths[i];

			float q = e.Layer == 0 ? q20L0 : q20L1;
			bool veryShort = len <= q * 1.02f;
			if (veryShort)
			{
				if (_random.NextDouble() < 0.50)
				{
					continue;
				}
			}

			kept.Add(e);
		}

		AugmentWithSpanEdges(0, (int)Math.Max(1, Math.Round(_bgNodeCount * 0.14)), pos, kept, w, h);
		AugmentWithSpanEdges(1, (int)Math.Max(1, Math.Round(_bgNodeCount * 0.08)), pos, kept, w, h);

		edges.Clear();
		edges.AddRange(kept);
	}

	private void AugmentWithSpanEdges(byte layer, int additions, Vector2[] pos, List<BgEdge> edges, float w, float h)
	{
		if (_bgNodes == null || additions <= 0)
		{
			return;
		}

		int attempts = additions * 2;
		int added = 0;

		for (int it = 0; it < attempts && added < additions; it++)
		{
			int i = _random.Next(_bgNodeCount);
			if (_bgNodes[i].Layer != layer)
			{
				continue;
			}

			int[] nnIdx = FindNearestInLayer(i, layer, pos, 6);
			if (nnIdx.Length < 5)
			{
				continue;
			}

			int kIdx = _random.NextDouble() < 0.5 ? 3 : 4;
			int j = nnIdx[kIdx];
			if (j < 0)
			{
				continue;
			}

			float dx = pos[j].X - pos[i].X;
			float dy = pos[j].Y - pos[i].Y;
			float len = MathF.Sqrt(dx * dx + dy * dy);
			float minL = MathF.Min(w, h) * 0.05f;
			float maxL = MathF.Min(w, h) * 0.35f;
			if (len < minL || len > maxL)
			{
				continue;
			}

			if (EdgeExists(edges, i, j))
			{
				continue;
			}

			int a = Math.Min(i, j);
			int b = Math.Max(i, j);
			edges.Add(new BgEdge { A = a, B = b, Layer = layer });
			added++;
		}
	}

	private int[] FindNearestInLayer(int index, byte layer, Vector2[] pos, int count)
	{
		if (_bgNodes == null)
		{
			return [];
		}

		int capacity = Math.Min(count, _bgNodeCount - 1);
		int[] bestIdx = new int[capacity];
		float[] bestD2 = new float[capacity];
		for (int t = 0; t < capacity; t++)
		{
			bestIdx[t] = -1;
			bestD2[t] = float.MaxValue;
		}

		Vector2 p = pos[index];
		for (int j = 0; j < _bgNodeCount; j++)
		{
			if (j == index || _bgNodes[j].Layer != layer)
			{
				continue;
			}
			float dx = pos[j].X - p.X;
			float dy = pos[j].Y - p.Y;
			float d2 = dx * dx + dy * dy;

			for (int t = 0; t < capacity; t++)
			{
				if (d2 < bestD2[t])
				{
					for (int s = capacity - 1; s > t; s--)
					{
						bestD2[s] = bestD2[s - 1];
						bestIdx[s] = bestIdx[s - 1];
					}
					bestD2[t] = d2;
					bestIdx[t] = j;
					break;
				}
			}
		}

		int valid = capacity;
		while (valid > 0 && bestIdx[valid - 1] == -1)
		{
			valid--;
		}
		if (valid == capacity)
		{
			return bestIdx;
		}
		int[] trimmed = new int[valid];
		for (int i = 0; i < valid; i++) { trimmed[i] = bestIdx[i]; }
		return trimmed;
	}

	private static bool EdgeExists(List<BgEdge> edges, int i, int j)
	{
		int a = Math.Min(i, j);
		int b = Math.Max(i, j);
		for (int t = 0; t < edges.Count; t++)
		{
			if (edges[t].A == a && edges[t].B == b)
			{
				return true;
			}
		}
		return false;
	}

	private void MaybeUpdateStarEdges(Vector2[] pos, float w, float h)
	{
		_bgStarEdges ??= new List<StarEdgePersist>(16);

		// Expire old motifs
		for (int i = _bgStarEdges.Count - 1; i >= 0; i--)
		{
			if (_bgStarEdges[i].ExpireAt <= _animationTimeSeconds)
			{
				_bgStarEdges.RemoveAt(i);
			}
		}

		// Limit to ~2 simultaneous motifs; throttle creation
		int approxMotifs = _bgStarEdges.Count / 6;
		if (_animationTimeSeconds - _bgLastStarCreateTime < 2.0 || approxMotifs >= 2)
		{
			return;
		}

		// Low probability attempt
		if (_random.NextDouble() < 0.35)
		{
			if (TryCreateStarUsingNodes(pos, w, h, out StarEdgePersist[] starEdges))
			{
				for (int k = 0; k < starEdges.Length; k++)
				{
					_bgStarEdges.Add(starEdges[k]);
				}
				_bgLastStarCreateTime = _animationTimeSeconds;
			}
		}
	}

	private bool TryCreateStarUsingNodes(Vector2[] pos, float w, float h, out StarEdgePersist[] edgesOut)
	{
		edgesOut = [];
		if (_bgNodes == null || _bgNodeCount < 12)
		{
			return false;
		}

		int centerIdx = -1;
		for (int attempts = 0; attempts < 8 && centerIdx < 0; attempts++)
		{
			int idx = _random.Next(_bgNodeCount);
			if (_bgNodes[idx].Layer == 0)
			{
				centerIdx = idx;
			}
		}
		if (centerIdx < 0)
		{
			return false;
		}

		Vector2 c = pos[centerIdx];
		float rBase = MathF.Min(w, h) * (0.10f + (float)_random.NextDouble() * 0.06f);
		float rMin = rBase * 0.65f;
		float rMax = rBase * 1.35f;

		List<int> candidates = new(24);
		for (int i = 0; i < _bgNodeCount; i++)
		{
			if (i == centerIdx || _bgNodes[i].Layer != 0)
			{
				continue;
			}
			float dx = pos[i].X - c.X;
			float dy = pos[i].Y - c.Y;
			float d = MathF.Sqrt(dx * dx + dy * dy);
			if (d >= rMin && d <= rMax)
			{
				candidates.Add(i);
			}
		}

		if (candidates.Count < 8)
		{
			return false;
		}

		double theta0 = _random.NextDouble() * Math.PI * 2.0;
		int sectorCount = 6;
		int[] chosen = new int[sectorCount];
		float[] bestDelta = new float[sectorCount];
		for (int s = 0; s < sectorCount; s++)
		{
			chosen[s] = -1;
			bestDelta[s] = float.MaxValue;
		}

		for (int idx = 0; idx < candidates.Count; idx++)
		{
			int i = candidates[idx];
			float dx = pos[i].X - c.X;
			float dy = pos[i].Y - c.Y;
			double ang = Math.Atan2(dy, dx);
			if (ang < 0) { ang += Math.PI * 2.0; }

			int bestSector = -1;
			float best = float.MaxValue;
			for (int s = 0; s < sectorCount; s++)
			{
				double center = theta0 + s * (Math.PI / 3.0);
				double dAng = Math.Abs(NormalizeAngle(ang - center));
				if (dAng < best)
				{
					best = (float)dAng;
					bestSector = s;
				}
			}

			if (bestSector >= 0 && best < bestDelta[bestSector])
			{
				bestDelta[bestSector] = best;
				chosen[bestSector] = i;
			}
		}

		int filled = 0;
		for (int s = 0; s < sectorCount; s++)
		{
			if (chosen[s] >= 0) { filled++; }
		}
		if (filled < 5)
		{
			return false;
		}

		List<int> verts = new(6);
		for (int s = 0; s < sectorCount; s++)
		{
			if (chosen[s] >= 0) { verts.Add(chosen[s]); }
		}
		if (verts.Count < 5)
		{
			return false;
		}
		if (verts.Count == 5)
		{
			verts.Add(verts[4]);
		}

		int[] starPairs =
		[
			verts[0], verts[2],
			verts[2], verts[4],
			verts[4], verts[0],
			verts[1], verts[3],
			verts[3], verts[5],
			verts[5], verts[1],
		];

		double ttl = 4.0 + _random.NextDouble() * 3.0;
		double expire = _animationTimeSeconds + ttl;

		StarEdgePersist[] result = new StarEdgePersist[starPairs.Length / 2];
		for (int k = 0; k < result.Length; k++)
		{
			int a = starPairs[k * 2 + 0];
			int b = starPairs[k * 2 + 1];

			int ia = Math.Min(a, b);
			int ib = Math.Max(a, b);

			result[k] = new StarEdgePersist
			{
				A = ia,
				B = ib,
				Layer = 0,
				ExpireAt = expire
			};
		}

		edgesOut = result;
		return true;
	}

	private static double NormalizeAngle(double x)
	{
		while (x < -Math.PI) { x += Math.PI * 2.0; }
		while (x > Math.PI) { x -= Math.PI * 2.0; }
		return Math.Abs(x);
	}

	private static Color MixColors(Color a, Color b, double mix)
	{
		double m = Math.Clamp(mix, 0.0, 1.0);
		byte r = (byte)Math.Clamp((int)Math.Round(a.R * (1.0 - m) + b.R * m), 0, 255);
		byte g = (byte)Math.Clamp((int)Math.Round(a.G * (1.0 - m) + b.G * m), 0, 255);
		byte bl = (byte)Math.Clamp((int)Math.Round(a.B * (1.0 - m) + b.B * m), 0, 255);
		return Color.FromArgb(a.A, r, g, bl);
	}

	#endregion

	// Disposal guard to ensure owned resources are released exactly once
	private bool _disposed;

	// Safe to call multiple times, and also safe to call in addition to Unloaded cleanup.
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}
		_disposed = true;

		// This detaches render hooks, stops timers, and disposes all CanvasRenderTargets, etc.
		OnUnloadedDisposeResources(this, new RoutedEventArgs());
	}
}
