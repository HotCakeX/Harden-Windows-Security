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

using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Hash card item for display in the grid
/// </summary>
internal sealed partial class HashCardItem : ViewModelBase
{
	internal string DisplayName { get; set => SP(ref field, value); } = string.Empty;
	internal string AlgorithmName { get; set => SP(ref field, value); } = string.Empty;
	internal string HashTypeName { get; set => SP(ref field, value); } = string.Empty;
	internal string HashType { get; set => SP(ref field, value); } = string.Empty;
	internal string HashKey { get; set => SP(ref field, value); } = string.Empty;
	internal string HashValue { get; set => SP(ref field, value); } = string.Empty;
	internal string KeySize { get; set => SP(ref field, value); } = string.Empty;
	internal Visibility ProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
}

/// <summary>
/// Handles the file selection and computes various cryptographic hashes for the selected file. Displays the results in
/// the UI.
/// </summary>
internal sealed partial class GetCIHashes : Page
{
	private GetCIHashesVM ViewModel { get; } = ViewModelProvider.GetCIHashesVM;

	/// <summary>
	/// Initializes the component and sets the navigation cache mode to required for the GetCIHashes class.
	/// </summary>
	internal GetCIHashes()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	private void HashGridView_ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		if (args.ItemContainer is GridViewItem container)
		{
			// Set up mouse events for tilt animation
			container.PointerEntered += CardContainer_PointerEntered;
			container.PointerMoved += CardContainer_PointerMoved;
			container.PointerExited += CardContainer_PointerExited;
		}
	}

	private void CardContainer_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (sender is GridViewItem container)
		{
			// Get the actual card element (the Grid inside the DataTemplate)
			FrameworkElement? cardElement = container.ContentTemplateRoot as FrameworkElement;
			if (cardElement != null)
			{
				// Apply transforms to the container instead of the content
				// PlaneProjection for 3D transformations
				if (container.Projection is not PlaneProjection)
				{
					container.Projection = new PlaneProjection();
				}

				// Adding a CompositeTransform for scaling
				if (container.RenderTransform is not CompositeTransform)
				{
					container.RenderTransform = new CompositeTransform();
				}
			}
		}
	}

	private void CardContainer_PointerMoved(object sender, PointerRoutedEventArgs e)
	{
		if (sender is GridViewItem container)
		{
			FrameworkElement? cardElement = container.ContentTemplateRoot as FrameworkElement;
			if (cardElement != null &&
				container.Projection is PlaneProjection projection &&
				container.RenderTransform is CompositeTransform transform)
			{
				// Get pointer position relative to the container
				Microsoft.UI.Input.PointerPoint position = e.GetCurrentPoint(container);
				double containerWidth = container.ActualWidth;
				double containerHeight = container.ActualHeight;

				if (containerWidth > 0 && containerHeight > 0)
				{
					// Calculate normalized position (-1 to 1)
					double normalizedX = (position.Position.X / containerWidth - 0.5) * 2;
					double normalizedY = (position.Position.Y / containerHeight - 0.5) * 2;

					// Calculate tilt angles (max 15 degrees)
					const double maxTilt = 15.0;
					double rotationY = -normalizedX * maxTilt; // Negative for correct left/right tilt direction
					double rotationX = normalizedY * maxTilt; // Tilt up/down based on Y position

					DoubleAnimation rotationXAnimation = new()
					{
						To = rotationX,
						Duration = TimeSpan.FromMilliseconds(100),
						EasingFunction = new QuadraticEase() { EasingMode = EasingMode.EaseOut }
					};

					DoubleAnimation rotationYAnimation = new()
					{
						To = rotationY,
						Duration = TimeSpan.FromMilliseconds(100),
						EasingFunction = new QuadraticEase() { EasingMode = EasingMode.EaseOut }
					};

					DoubleAnimation scaleXAnimation = new()
					{
						To = 1.05,
						Duration = TimeSpan.FromMilliseconds(100),
						EasingFunction = new QuadraticEase() { EasingMode = EasingMode.EaseOut }
					};

					DoubleAnimation scaleYAnimation = new()
					{
						To = 1.05,
						Duration = TimeSpan.FromMilliseconds(100),
						EasingFunction = new QuadraticEase() { EasingMode = EasingMode.EaseOut }
					};

					// Create storyboard
					Storyboard storyboard = new();

					// Set targets for PlaneProjection rotations
					Storyboard.SetTarget(rotationXAnimation, projection);
					Storyboard.SetTargetProperty(rotationXAnimation, "RotationX");

					Storyboard.SetTarget(rotationYAnimation, projection);
					Storyboard.SetTargetProperty(rotationYAnimation, "RotationY");

					// Set targets for CompositeTransform scaling
					Storyboard.SetTarget(scaleXAnimation, transform);
					Storyboard.SetTargetProperty(scaleXAnimation, "ScaleX");

					Storyboard.SetTarget(scaleYAnimation, transform);
					Storyboard.SetTargetProperty(scaleYAnimation, "ScaleY");

					storyboard.Children.Add(rotationXAnimation);
					storyboard.Children.Add(rotationYAnimation);
					storyboard.Children.Add(scaleXAnimation);
					storyboard.Children.Add(scaleYAnimation);

					storyboard.Begin();
				}
			}
		}
	}

	private void CardContainer_PointerExited(object sender, PointerRoutedEventArgs e)
	{
		if (sender is GridViewItem container)
		{
			if (container.Projection is PlaneProjection projection &&
				container.RenderTransform is CompositeTransform transform)
			{
				// Reset to original state with smooth animation
				Storyboard resetStoryboard = new();

				DoubleAnimation resetRotationX = new()
				{
					To = 0,
					Duration = TimeSpan.FromMilliseconds(200),
					EasingFunction = new QuadraticEase() { EasingMode = EasingMode.EaseOut }
				};

				DoubleAnimation resetRotationY = new()
				{
					To = 0,
					Duration = TimeSpan.FromMilliseconds(200),
					EasingFunction = new QuadraticEase() { EasingMode = EasingMode.EaseOut }
				};

				DoubleAnimation resetScaleX = new()
				{
					To = 1.0,
					Duration = TimeSpan.FromMilliseconds(200),
					EasingFunction = new QuadraticEase() { EasingMode = EasingMode.EaseOut }
				};

				DoubleAnimation resetScaleY = new()
				{
					To = 1.0,
					Duration = TimeSpan.FromMilliseconds(200),
					EasingFunction = new QuadraticEase() { EasingMode = EasingMode.EaseOut }
				};

				Storyboard.SetTarget(resetRotationX, projection);
				Storyboard.SetTargetProperty(resetRotationX, "RotationX");

				Storyboard.SetTarget(resetRotationY, projection);
				Storyboard.SetTargetProperty(resetRotationY, "RotationY");

				Storyboard.SetTarget(resetScaleX, transform);
				Storyboard.SetTargetProperty(resetScaleX, "ScaleX");

				Storyboard.SetTarget(resetScaleY, transform);
				Storyboard.SetTargetProperty(resetScaleY, "ScaleY");

				resetStoryboard.Children.Add(resetRotationX);
				resetStoryboard.Children.Add(resetRotationY);
				resetStoryboard.Children.Add(resetScaleX);
				resetStoryboard.Children.Add(resetScaleY);

				resetStoryboard.Begin();
			}
		}
	}

	private void HashGrid_ItemClick(object sender, ItemClickEventArgs e)
	{
		if (e.ClickedItem is not HashCardItem clickedItem)
			return;

		ConnectedAnimation? animation = null;

		// Get the collection item corresponding to the clicked item
		if (hashGridView.ContainerFromItem(e.ClickedItem) is GridViewItem)
		{
			// Store the clicked item in ViewModel for modal display
			ViewModel.SelectedHashItem = clickedItem;

			// Prepare the connected animation
			animation = hashGridView.PrepareConnectedAnimation("forwardAnimation", clickedItem, "connectedElement");
		}

		SmokeGrid.Visibility = Visibility.Visible;

		_ = (animation?.TryStart(destinationElement));
	}

	private async void BackButton_Click(object sender, RoutedEventArgs e)
	{
		if (ViewModel.SelectedHashItem == null)
			return;

		// Hide the smoke grid immediately to prevent flashing
		SmokeGrid.Visibility = Visibility.Collapsed;

		ConnectedAnimation animation = ConnectedAnimationService.GetForCurrentView().PrepareToAnimate("backwardsAnimation", destinationElement);

		// If the connected item appears outside the viewport, scroll it into view
		hashGridView.ScrollIntoView(ViewModel.SelectedHashItem, ScrollIntoViewAlignment.Default);
		hashGridView.UpdateLayout();

		// Use the Direct configuration to go back (if the API is available)
		if (Windows.Foundation.Metadata.ApiInformation.IsApiContractPresent("Windows.Foundation.UniversalApiContract", 7))
		{
			animation.Configuration = new DirectConnectedAnimationConfiguration();
		}

		// Play the second connected animation
		_ = await hashGridView.TryStartConnectedAnimationAsync(animation, ViewModel.SelectedHashItem, "connectedElement");
	}

	private void SmokeGrid_Tapped(object sender, TappedRoutedEventArgs e)
	{
		// Close modal when clicking on the background
		BackButton_Click(sender, e);
	}

	private void DestinationElement_Tapped(object sender, TappedRoutedEventArgs e)
	{
		// Prevent the tap from bubbling up to the smoke grid
		e.Handled = true;
	}
}
