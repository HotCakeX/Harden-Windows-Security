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
using System.Numerics;
using AppControlManager.ViewModels;
using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace AppControlManager.Pages;

internal sealed partial class FirewallSentinel : Page, CommonCore.UI.IPageHeaderProvider
{
	private FirewallSentinelVM ViewModel => ViewModelProvider.FirewallSentinelVM;

	internal FirewallSentinel()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => GlobalVars.GetStr("FirewallSentinelPageTitle");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/Firewall-Sentinel");

	#region Neon Border Animation Logic

	// The intended design is to have a border around each profile area so that on hover, the border starts from the bottom left corner and finished at top right corner.
	// It has neon like style.
	// Only 1 neon animated border must be visible at a time.

	// Map the parent Grid (which receives pointer events) to the visuals wrapper
	private readonly Dictionary<Grid, NeonBorderVisuals> _neonVisualsMap = [];

	// Track the currently active card to handle touch interactions where PointerExited might not fire before the next PointerEntered
	private Grid? _currentActiveCard;

	/// <summary>
	/// List of colors to cycle through.
	/// </summary>
	private static readonly List<Color> _pastelColors =
	[
		Color.FromArgb(255, 255, 179, 186), // Pastel Yellow
        Color.FromArgb(255, 255, 223, 186), // Pastel Orange
        Color.FromArgb(255, 255, 255, 186), // Pastel Light Yellow
        Color.FromArgb(255, 186, 255, 201), // Pastel Green
        Color.FromArgb(255, 186, 225, 255), // Pastel Blue
        Color.FromArgb(255, 218, 186, 255), // Pastel Purple
        Color.FromArgb(255, 255, 186, 240), // Pastel Pink
        Color.FromArgb(255, 255, 105, 180), // Hot Pink
        Color.FromArgb(255, 135, 206, 250), // Light Sky Blue
        Color.FromArgb(255, 147, 112, 219)  // Medium Purple
    ];

	private int _colorIndex;

	/// <summary>
	/// Cleanup resources when the page is unloaded to prevent memory leaks.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FirewallSentinel_Unloaded(object sender, RoutedEventArgs e)
	{
		foreach (NeonBorderVisuals visual in _neonVisualsMap.Values)
		{
			visual.Dispose();
		}
		_neonVisualsMap.Clear();
		_neonVisualsMap.TrimExcess();
		_currentActiveCard = null;
	}

	/// <summary>
	/// Called when the Inner overlay grid is loaded
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void Card_Loaded(object sender, RoutedEventArgs e)
	{
		if (sender is Grid overlayGrid)
		{
			// Find the parent grid (the main card)
			if (overlayGrid.Parent is Grid parentCard)
			{
				if (!_neonVisualsMap.ContainsKey(parentCard))
				{
					// Create visuals attached to the overlay grid
					NeonBorderVisuals visuals = new(overlayGrid);
					_neonVisualsMap[parentCard] = visuals;

					// Update layout immediately
					if (overlayGrid.ActualWidth > 0 && overlayGrid.ActualHeight > 0)
					{
						visuals.UpdateLayout(new Vector2((float)overlayGrid.ActualWidth, (float)overlayGrid.ActualHeight));
					}
				}
			}
		}
	}

	private void Card_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (sender is Grid parentCard && _neonVisualsMap.TryGetValue(parentCard, out NeonBorderVisuals? visuals))
		{
			// Check if there is another card that is currently active (e.g., from a touch interaction that didn't clear)
			if (_currentActiveCard != null && _currentActiveCard != parentCard)
			{
				// Force close the previous card
				if (_neonVisualsMap.TryGetValue(_currentActiveCard, out NeonBorderVisuals? prevVisuals))
				{
					prevVisuals.PlayClose();
				}
			}

			// Update the current active card
			_currentActiveCard = parentCard;

			// Get the next color in the cycle
			Color nextColor = _pastelColors[_colorIndex];
			_colorIndex = (_colorIndex + 1) % _pastelColors.Count;

			visuals.PlayOpen(nextColor);
		}
	}

	private void Card_PointerExited(object sender, PointerRoutedEventArgs e)
	{
		if (sender is Grid parentCard && _neonVisualsMap.TryGetValue(parentCard, out NeonBorderVisuals? visuals))
		{
			visuals.PlayClose();

			// If the exiting card was the tracked active card, clear the reference
			if (_currentActiveCard == parentCard)
			{
				_currentActiveCard = null;
			}
		}
	}

	/// <summary>
	/// Prevents the pointer event from bubbling up to the Expander when clicking strictly within the card area.
	/// This prevents the Expander from collapsing/expanding when selecting a profile.
	/// </summary>
	private void Card_PointerPressed(object sender, PointerRoutedEventArgs e)
	{
		if (e.OriginalSource is DependencyObject current)
		{
			// Traverse up to the card root (sender)
			while (current != null && current != (DependencyObject)sender)
			{
				// If we found a Button, do not handle the event. Let the button work.
				if (current is ButtonBase)
				{
					return;
				}
				current = VisualTreeHelper.GetParent(current);
			}
		}

		// It wasn't a button, so it's just the card background/text. Block the Expander toggle.
		e.Handled = true;
	}

	private sealed partial class NeonBorderVisuals : IDisposable
	{
		internal Compositor Compositor { get; }
		internal ContainerVisual RootContainer { get; }

		internal SpriteVisual LeftLine { get; }
		internal SpriteVisual BottomLine { get; }
		internal SpriteVisual TopLine { get; }
		internal SpriteVisual RightLine { get; }

		private readonly Grid _hostGrid;
		private const float _strokeThickness = 2.0f; // Thickness of the neon line

		internal NeonBorderVisuals(Grid hostGrid)
		{
			_hostGrid = hostGrid;
			Visual visual = ElementCompositionPreview.GetElementVisual(hostGrid);
			Compositor = visual.Compositor;

			RootContainer = Compositor.CreateContainerVisual();
			RootContainer.RelativeSizeAdjustment = Vector2.One;
			ElementCompositionPreview.SetElementChildVisual(hostGrid, RootContainer);

			// Create initial brushes (transparent until PlayOpen is called)
			CompositionColorBrush brush = Compositor.CreateColorBrush(Colors.Transparent);

			// --- LEFT LINE ---
			LeftLine = Compositor.CreateSpriteVisual();
			LeftLine.Brush = brush;

			// --- BOTTOM LINE ---
			BottomLine = Compositor.CreateSpriteVisual();
			BottomLine.Brush = brush;

			// --- TOP LINE ---
			TopLine = Compositor.CreateSpriteVisual();
			TopLine.Brush = brush;

			// --- RIGHT LINE ---
			RightLine = Compositor.CreateSpriteVisual();
			RightLine.Brush = brush;

			// Add to container
			RootContainer.Children.InsertAtTop(LeftLine);
			RootContainer.Children.InsertAtTop(BottomLine);
			RootContainer.Children.InsertAtTop(TopLine);
			RootContainer.Children.InsertAtTop(RightLine);

			// Set initial state (Scale 0)
			Reset();

			// Subscribe to SizeChanged event to update layout
			_hostGrid.SizeChanged += HostGrid_SizeChanged;
		}

		private void HostGrid_SizeChanged(object sender, SizeChangedEventArgs e) =>
			UpdateLayout(new Vector2((float)e.NewSize.Width, (float)e.NewSize.Height));

		private DropShadow CreateNeonShadow(Color color)
		{
			DropShadow shadow = Compositor.CreateDropShadow();
			shadow.Color = color;
			shadow.BlurRadius = 12f; // Glow amount
			shadow.Opacity = 1.0f;
			shadow.Offset = Vector3.Zero;
			shadow.SourcePolicy = CompositionDropShadowSourcePolicy.Default;
			return shadow;
		}

		internal void UpdateLayout(Vector2 newSize)
		{
			float w = newSize.X;
			float h = newSize.Y;
			if (w <= 0 || h <= 0) return;

			// SpriteVisuals are rectangles.

			// LEFT: x=0, y=0, w=Thick, h=Full. Anchor: Bottom-Left (0, 1).
			LeftLine.Size = new Vector2(_strokeThickness, h);
			LeftLine.Offset = new Vector3(0, h, 0); // Bottom Left corner
			LeftLine.AnchorPoint = new Vector2(0, 1.0f); // Pivot for scaling

			// BOTTOM: x=0, y=h-Thick, w=Full, h=Thick. Anchor: Bottom-Left.
			BottomLine.Size = new Vector2(w, _strokeThickness);
			BottomLine.Offset = new Vector3(0, h, 0); // Bottom Left corner
			BottomLine.AnchorPoint = new Vector2(0, 1.0f); // Pivot for scaling

			// TOP: x=0, y=0, w=Full, h=Thick. Anchor: Top-Left.
			TopLine.Size = new Vector2(w, _strokeThickness);
			TopLine.Offset = new Vector3(0, 0, 0); // Top Left corner
			TopLine.AnchorPoint = new Vector2(0, 0); // Pivot for scaling (Top Left)

			// RIGHT: x=w-Thick, y=0, w=Thick, h=Full. Anchor: Bottom-Right.
			RightLine.Size = new Vector2(_strokeThickness, h);
			RightLine.Offset = new Vector3(w, h, 0); // Bottom Right corner
			RightLine.AnchorPoint = new Vector2(1.0f, 1.0f); // Pivot for scaling (Bottom Right)
		}

		internal void PlayOpen(Color neonColor)
		{
			// Ensure previous animations are stopped so delayed animations don't trigger later
			StopAnimations();

			// Update color
			CompositionColorBrush newBrush = Compositor.CreateColorBrush(neonColor);
			DropShadow newShadow = CreateNeonShadow(neonColor);

			LeftLine.Brush = newBrush;
			LeftLine.Shadow = newShadow;

			BottomLine.Brush = newBrush;
			BottomLine.Shadow = newShadow;

			TopLine.Brush = newBrush;
			TopLine.Shadow = newShadow;

			RightLine.Brush = newBrush;
			RightLine.Shadow = newShadow;

			// Animation
			TimeSpan duration = TimeSpan.FromMilliseconds(400);
			CubicBezierEasingFunction ease = Compositor.CreateCubicBezierEasingFunction(new Vector2(0.2f, 0.8f), new Vector2(0.2f, 1f));

			// 1. Left (Up) - Scale Y 0->1
			Vector3KeyFrameAnimation scaleUpY = Compositor.CreateVector3KeyFrameAnimation();
			scaleUpY.Target = "Scale";
			scaleUpY.InsertKeyFrame(1f, Vector3.One, ease);
			scaleUpY.Duration = duration;

			// 2. Bottom (Right) - Scale X 0->1
			Vector3KeyFrameAnimation scaleUpX = Compositor.CreateVector3KeyFrameAnimation();
			scaleUpX.Target = "Scale";
			scaleUpX.InsertKeyFrame(1f, Vector3.One, ease);
			scaleUpX.Duration = duration;

			// 3. Top (Right) - Delayed - Scale X 0->1
			Vector3KeyFrameAnimation topAnim = Compositor.CreateVector3KeyFrameAnimation();
			topAnim.Target = "Scale";
			topAnim.InsertKeyFrame(0f, new Vector3(0, 1, 1)); // Start X=0
			topAnim.InsertKeyFrame(1f, Vector3.One, ease);
			topAnim.DelayTime = duration;
			topAnim.Duration = duration;

			// 4. Right (Up) - Delayed - Scale Y 0->1
			Vector3KeyFrameAnimation rightAnim = Compositor.CreateVector3KeyFrameAnimation();
			rightAnim.Target = "Scale";
			rightAnim.InsertKeyFrame(0f, new Vector3(1, 0, 1)); // Start Y=0
			rightAnim.InsertKeyFrame(1f, Vector3.One, ease);
			rightAnim.DelayTime = duration;
			rightAnim.Duration = duration;

			LeftLine.StartAnimation("Scale", scaleUpY);
			BottomLine.StartAnimation("Scale", scaleUpX);
			TopLine.StartAnimation("Scale", topAnim);
			RightLine.StartAnimation("Scale", rightAnim);
		}

		internal void PlayClose()
		{
			// Stop any pending/running open animations to prevent conflict
			StopAnimations();

			TimeSpan duration = TimeSpan.FromMilliseconds(200);
			CubicBezierEasingFunction ease = Compositor.CreateCubicBezierEasingFunction(new Vector2(0.2f, 0.8f), new Vector2(0.2f, 1f));

			// 1. Top and Right lines shrink first immediately (reversing the end of the open animation)
			Vector3KeyFrameAnimation topShrink = Compositor.CreateVector3KeyFrameAnimation();
			topShrink.Target = "Scale";
			topShrink.InsertKeyFrame(1f, new Vector3(0f, 1f, 1f), ease);
			topShrink.Duration = duration;

			Vector3KeyFrameAnimation rightShrink = Compositor.CreateVector3KeyFrameAnimation();
			rightShrink.Target = "Scale";
			rightShrink.InsertKeyFrame(1f, new Vector3(1f, 0f, 1f), ease);
			rightShrink.Duration = duration;

			// 2. Left and Bottom lines shrink delayed (reversing the start of the open animation)
			Vector3KeyFrameAnimation leftShrink = Compositor.CreateVector3KeyFrameAnimation();
			leftShrink.Target = "Scale";
			leftShrink.InsertKeyFrame(0f, Vector3.One); // Hold at full scale during the delay
			leftShrink.InsertKeyFrame(1f, new Vector3(1f, 0f, 1f), ease);
			leftShrink.DelayTime = duration;
			leftShrink.Duration = duration;

			Vector3KeyFrameAnimation bottomShrink = Compositor.CreateVector3KeyFrameAnimation();
			bottomShrink.Target = "Scale";
			bottomShrink.InsertKeyFrame(0f, Vector3.One); // Hold at full scale during the delay
			bottomShrink.InsertKeyFrame(1f, new Vector3(0f, 1f, 1f), ease);
			bottomShrink.DelayTime = duration;
			bottomShrink.Duration = duration;

			TopLine.StartAnimation("Scale", topShrink);
			RightLine.StartAnimation("Scale", rightShrink);
			LeftLine.StartAnimation("Scale", leftShrink);
			BottomLine.StartAnimation("Scale", bottomShrink);
		}

		// Stops animations on all lines to ensure no delayed animations trigger after PlayClose is called
		private void StopAnimations()
		{
			LeftLine.StopAnimation("Scale");
			BottomLine.StopAnimation("Scale");
			TopLine.StopAnimation("Scale");
			RightLine.StopAnimation("Scale");
		}

		private void Reset()
		{
			// Initial state: Hidden
			LeftLine.Scale = new Vector3(1, 0, 1);
			BottomLine.Scale = new Vector3(0, 1, 1);
			TopLine.Scale = new Vector3(0, 1, 1);
			RightLine.Scale = new Vector3(1, 0, 1);
		}

		public void Dispose()
		{
			// Unsubscribe from event
			if (_hostGrid != null)
			{
				_hostGrid.SizeChanged -= HostGrid_SizeChanged;
				ElementCompositionPreview.SetElementChildVisual(_hostGrid, null);
			}

			// Dispose Composition objects
			LeftLine?.Dispose();
			BottomLine?.Dispose();
			TopLine?.Dispose();
			RightLine?.Dispose();
			RootContainer?.Dispose();
		}
	}

	#endregion
}
