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

// The following code is based on the Microsoft AI Dev Gallery, MIT licensed code.
// It has modifications made by Violet Hansen.
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// Repository: https://github.com/microsoft/ai-dev-gallery
// License file: https://github.com/microsoft/ai-dev-gallery/blob/main/LICENSE
//    MIT License
//
//    Copyright (c) Microsoft Corporation.
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE
//

using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Foundation;

namespace AppControlManager.CustomUIElements.HomePageCarousel;

internal sealed partial class HeaderCarousel : UserControl
{
	private readonly DispatcherTimer selectionTimer = new() { Interval = TimeSpan.FromMilliseconds(4000) };
	private readonly DispatcherTimer deselectionTimer = new() { Interval = TimeSpan.FromMilliseconds(3000) };
	private readonly List<int> numbers = [];
	private HeaderTile? selectedTile;
	private int currentIndex;

	// Periodic single-run glitch trigger for the header title
	private readonly DispatcherTimer glitchTimer = new() { Interval = TimeSpan.FromSeconds(4) };

	internal HeaderCarousel()
	{
		InitializeComponent();
	}

	private void UserControl_Loaded(object sender, RoutedEventArgs e)
	{
		ResetAndShuffle();
		SelectNextTile();
		SubscribeToEvents();

		// Start the glitch effect timer for the title
		glitchTimer.Tick += OnGlitchTimerTick;
		glitchTimer.Start();
	}

	private void SubscribeToEvents()
	{
		selectionTimer.Tick += SelectionTimer_Tick;
		deselectionTimer.Tick += DeselectionTimer_Tick;
		selectionTimer.Start();
		foreach (HeaderTile tile in TilePanel.Children.Cast<HeaderTile>())
		{
			tile.PointerEntered += Tile_PointerEntered;
			tile.PointerExited += Tile_PointerExited;
			tile.GotFocus += Tile_GotFocus;
			tile.LostFocus += Tile_LostFocus;
			tile.Click += Tile_Click;
		}
	}

	private void UserControl_Unloaded(object sender, RoutedEventArgs e)
	{
		selectionTimer.Tick -= SelectionTimer_Tick;
		deselectionTimer.Tick -= DeselectionTimer_Tick;
		selectionTimer.Stop();
		deselectionTimer.Stop();

		glitchTimer.Tick -= OnGlitchTimerTick;
		glitchTimer.Stop();

		foreach (HeaderTile tile in TilePanel.Children.Cast<HeaderTile>())
		{
			tile.PointerEntered -= Tile_PointerEntered;
			tile.PointerExited -= Tile_PointerExited;
			tile.GotFocus -= Tile_GotFocus;
			tile.LostFocus -= Tile_LostFocus;
			tile.Click -= Tile_Click;
		}
	}

	private void Tile_Click(object sender, RoutedEventArgs e)
	{
		if (sender is HeaderTile tile)
		{
			tile.PointerExited -= Tile_PointerExited;

			Type? targetPage = tile.SampleID switch
			{
				"Supplemental" => typeof(Pages.CreateSupplementalPolicy),
				"AllowNewApps" => typeof(Pages.AllowNewApps),
				"DenyPolicy" => typeof(Pages.CreateDenyPolicy),
				"AdvancedHunting" => typeof(Pages.MDEAHPolicyCreation),
				"Simulation" => typeof(Pages.Simulation),
				"PolicyEditor" => typeof(Pages.PolicyEditor),
				_ => null
			};

			if (targetPage is not null)
				ViewModelProvider.NavigationService.Navigate(targetPage);
		}
	}

	private void SelectionTimer_Tick(object? sender, object e) => SelectNextTile();

	private async void SelectNextTile()
	{
		if (TilePanel.Children[GetNextUniqueRandom()] is HeaderTile tile)
		{
			selectedTile = tile;
			GeneralTransform transform = selectedTile.TransformToVisual(TilePanel);
			Point point = transform.TransformPoint(new Point(0, 0));
			_ = scrollViewer.ChangeView(point.X - (scrollViewer.ActualWidth / 2) + (selectedTile.ActualSize.X / 2), null, null);
			await Task.Delay(500);
			SetTileVisuals();
			deselectionTimer.Start();
		}
	}

	private void DeselectionTimer_Tick(object? sender, object e)
	{
		_ = (selectedTile?.IsSelected = false);
		selectedTile = null;

		deselectionTimer.Stop();
	}

	private void ResetAndShuffle()
	{
		numbers.Clear();
		for (int i = 0; i <= TilePanel.Children.Count - 1; i++)
		{
			numbers.Add(i);
		}

		// Shuffle the list
		for (int i = numbers.Count - 1; i > 0; i--)
		{
			int j = System.Security.Cryptography.RandomNumberGenerator.GetInt32(i + 1);
			(numbers[j], numbers[i]) = (numbers[i], numbers[j]);
		}

		currentIndex = 0;
	}

	private int GetNextUniqueRandom()
	{
		if (currentIndex >= numbers.Count)
		{
			ResetAndShuffle();
		}

		return numbers[currentIndex++];
	}

	private void SetTileVisuals()
	{
		if (selectedTile != null)
		{
			selectedTile.IsSelected = true;

			if (selectedTile.ImageUrl is BitmapImage bitmapImage && bitmapImage.UriSource is Uri uri)
			{
				BackDropImage.ImageUrl = uri;
			}

			if (selectedTile.Foreground is LinearGradientBrush brush)
			{
				AnimateTitleGradient(brush);
			}
		}
	}

	private void AnimateTitleGradient(LinearGradientBrush brush)
	{
		// Create a storyboard to hold the animations
		Storyboard storyboard = new();

		int i = 0;
		foreach (GradientStop stop in brush.GradientStops)
		{
			ColorAnimation colorAnimation1 = new()
			{
				To = stop.Color,
				Duration = new Duration(TimeSpan.FromMilliseconds(500)),
				EnableDependentAnimation = true
			};
			Storyboard.SetTarget(colorAnimation1, AnimatedGradientBrush.GradientStops[i]);
			Storyboard.SetTargetProperty(colorAnimation1, "Color");
			storyboard.Children.Add(colorAnimation1);
			i++;
		}

		storyboard.Begin();
	}

	private void Tile_PointerExited(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
	{
		((HeaderTile)sender).IsSelected = false;
		selectionTimer.Start();
	}

	private void Tile_PointerEntered(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
	{
		selectedTile = (HeaderTile)sender;
		SelectTile();
	}

	private async void SelectTile()
	{
		await Task.Delay(100);
		selectionTimer.Stop();
		deselectionTimer.Stop();

		foreach (HeaderTile t in TilePanel.Children.Cast<HeaderTile>())
		{
			t.IsSelected = false;
		}

		// Wait for the animation of a potential other tile to finish
		await Task.Delay(360);
		SetTileVisuals();
	}

	private void Tile_GotFocus(object sender, RoutedEventArgs e)
	{
		selectedTile = (HeaderTile)sender;
		SelectTile();
	}

	private void Tile_LostFocus(object sender, RoutedEventArgs e)
	{
		((HeaderTile)sender).IsSelected = false;
		selectionTimer.Start();
	}

	// Trigger the single-run glitch storyboard if present
	private void OnGlitchTimerTick(object? sender, object e)
	{
		Storyboard storyboard = (Storyboard)Resources["CarouselGlitchStoryboard"];
		storyboard.Stop();
		storyboard.Begin();
	}
}
