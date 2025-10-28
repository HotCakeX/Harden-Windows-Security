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

using System.Threading.Tasks;
using CommunityToolkit.WinUI;
using CommunityToolkit.WinUI.Media;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Windows.UI;

#if HARDEN_SYSTEM_SECURITY
#pragma warning disable CA1852
using HardenSystemSecurity;
#endif

namespace AppControlManager.CustomUIElements;

/// <summary>
/// The base design of all of the Content Dialogs in the app.
/// Every Content Dialog must inherit from this.
/// </summary>
internal partial class ContentDialogV2 : ContentDialog, IDisposable
{
	private Border? _shadowContainer;
	private Border? _dialogContainer;
	private Grid? _mainGrid;
	private bool _shadowApplied;
	private bool _disposed;

	// Shadow configuration constants
	private const string ShadowOffset = "0";
	private const double ShadowOpacity = 0.5;
	private const double ShadowBlurRadius = 25.0;
	private const double ShadowCornerRadius = 14.0;
	private const double DialogCornerRadius = 14.0;
	private const double ShadowMargin = 25;
	// Use Windows accent color for shadow color to match the border color, if not found then use Hot Pink as fallback
	private static readonly Color ShadowColor = Application.Current.Resources["SystemAccentColor"] is Color accentColor ? accentColor : Colors.HotPink;

	// Static pre-allocated objects for performance
	private static readonly SolidColorBrush TransparentBrush = new(Colors.Transparent);
	private static readonly Thickness ZeroThickness = new(0);
	private static readonly System.Numerics.Vector3 ZeroVector = new(0, 0, 0);
	private static readonly CornerRadius DialogCorner = new(DialogCornerRadius);
	private static readonly CornerRadius ShadowCorner = new(ShadowCornerRadius);
	private static readonly Thickness ShadowThickness = new(ShadowMargin, ShadowMargin, ShadowMargin, ShadowMargin);
	private static readonly Thickness BorderThick = new(0.7);

	private Border? _originalBackgroundBorder; // Keeps reference to the original background element
	private bool _backgroundBorderSizeHooked;  // Ensures we hook only once

	// Static cached shadow instance for performance
	private static readonly AttachedCardShadow CachedShadow = new()
	{
		Offset = ShadowOffset,
		Color = ShadowColor,
		BlurRadius = ShadowBlurRadius,
		Opacity = ShadowOpacity,
		CornerRadius = ShadowCornerRadius
	};

	// Event handlers stored as fields to enable proper cleanup
	private readonly RoutedEventHandler? _loadedHandler;
	private readonly TypedEventHandler<ContentDialog, ContentDialogOpenedEventArgs>? _openedHandler;
	private readonly TypedEventHandler<ContentDialog, ContentDialogClosingEventArgs>? _closingHandler;

	internal ContentDialogV2()
	{
		try
		{
			// Initialize event handlers
			_loadedHandler = ContentDialogV2_Loaded;
			_openedHandler = ContentDialogV2_Opened;
			_closingHandler = ContentDialogV2_Closing;

			BorderBrush = Application.Current.Resources["AccentFillColorDefaultBrush"] as Brush ?? TransparentBrush;
			BorderThickness = BorderThick;
			XamlRoot = App.MainWindow?.Content.XamlRoot;
			RequestedTheme = GetRequestedTheme();
			CornerRadius = DialogCorner;
			Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"];

			// Immediately disable the default ContentDialog shadow by setting the Translation property
			this.Translation = ZeroVector;

			// Immediately remove any shadow from the dialog itself
			if (this.Shadow is not null)
			{
				this.Shadow = null;
			}

			// Subscribe to events using the stored handlers
			this.Loaded += _loadedHandler;
			this.Opened += _openedHandler;
			this.Closing += _closingHandler;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Ensure basic initialization even if something fails
			try
			{
				_loadedHandler = ContentDialogV2_Loaded;
				_openedHandler = ContentDialogV2_Opened;
				_closingHandler = ContentDialogV2_Closing;
			}
			catch (Exception innerEx)
			{
				Logger.Write(innerEx);
				// Constructor must never throw - continue with default state
			}
		}
	}

	// Method for theme determination - called once per instance using advanced pattern matching
	private static ElementTheme GetRequestedTheme()
	{
		try
		{
			return App.Settings.AppTheme switch
			{
				string theme when string.Equals(theme, "Light", StringComparison.OrdinalIgnoreCase) => ElementTheme.Light,
				string theme when string.Equals(theme, "Dark", StringComparison.OrdinalIgnoreCase) => ElementTheme.Dark,
				_ => ElementTheme.Default
			};
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return ElementTheme.Default;
		}
	}

	protected override void OnApplyTemplate()
	{
		try
		{
			// Immediately disable shadows when template is applied - this is the earliest point we can access the visual tree
			DisableDefaultShadowImmediately();
			base.OnApplyTemplate();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			try
			{
				base.OnApplyTemplate();
			}
			catch (Exception innerEx)
			{
				Logger.Write(innerEx);
				// OnApplyTemplate must never throw - continue with default state
			}
		}
	}

	private void DisableDefaultShadowImmediately()
	{
		try
		{
			// Set Translation to zero to remove elevation shadow
			this.Translation = ZeroVector;

			// Try to remove shadow from the dialog itself
			if (this.Shadow is not null)
			{
				this.Shadow = null;
			}

			// Find and disable any default shadow elements immediately
			if (FindChildByName(this, "Shadow") is { } shadowElement)
			{
				shadowElement.Visibility = Visibility.Collapsed;
			}

			// Look for ThemeShadow or DropShadow elements
			if (FindChildOfType<Border>(this) is { Shadow: not null } themeShadowElement)
			{
				themeShadowElement.Shadow = null;
			}

			// Try to find and disable shadow on the main container
			if (FindChildByName(this, "Container") is Border { Shadow: not null } containerBorder)
			{
				containerBorder.Shadow = null;
			}

			// Try to find and disable shadow on background element
			if (FindChildByName(this, "BackgroundElement") is Border { Shadow: not null } backgroundBorder)
			{
				backgroundBorder.Shadow = null;
			}

			// Try to find and disable shadow on layout root
			if (FindChildByName(this, "LayoutRoot") is Border { Shadow: not null } layoutBorder)
			{
				layoutBorder.Shadow = null;
			}

			// Find all Border elements in the visual tree and remove their shadows
			DisableAllBorderShadows(this);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Shadow disabling failure should not prevent dialog from working
		}
	}

	// Method for recursive shadow removal
	private static void DisableAllBorderShadows(DependencyObject? parent)
	{
		if (parent is null)
		{
			return;
		}

		try
		{
			// If this element is a Border, remove its shadow using pattern matching
			if (parent is Border { Shadow: not null } border)
			{
				border.Shadow = null;
			}

			// If this element is a FrameworkElement, remove its shadow using pattern matching
			if (parent is FrameworkElement { Shadow: not null } frameworkElement)
			{
				frameworkElement.Shadow = null;
			}

			// Recursively check all children
			int childCount = VisualTreeHelper.GetChildrenCount(parent);
			for (int i = 0; i < childCount; i++)
			{
				try
				{
					DependencyObject child = VisualTreeHelper.GetChild(parent, i);
					DisableAllBorderShadows(child);
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
					// Continue with next child - one child failing should not stop others
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Recursive shadow removal failure should not prevent dialog from working
		}
	}

	private async void ContentDialogV2_Loaded(object sender, RoutedEventArgs e)
	{
		try
		{
			if (_disposed)
			{
				return;
			}

			// Immediately disable shadows again when loaded
			DisableDefaultShadowImmediately();

			if (!_shadowApplied)
			{
				// Apply custom shadow immediately without delay to prevent any flickering
				ApplyShadowToDialog();

				// Also apply after a small delay to ensure it sticks
				try
				{
					await Task.Delay(10);
					if (!_shadowApplied && !_disposed)
					{
						ApplyShadowToDialog();
					}
				}
				catch (Exception asyncEx)
				{
					Logger.Write(asyncEx);
					// Async operation failure should not prevent dialog from working
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Event handler must never throw - dialog should still be usable
		}
	}

	private async void ContentDialogV2_Opened(object sender, ContentDialogOpenedEventArgs e)
	{
		try
		{
			if (_disposed)
			{
				return;
			}

			// Immediately disable shadows again when opened
			DisableDefaultShadowImmediately();

			if (!_shadowApplied)
			{
				// Apply custom shadow immediately
				ApplyShadowToDialog();

				try
				{
					// Comprehensive shadow removal after a minimal delay
					await Task.Delay(5);
					if (!_disposed)
					{
						DisableDefaultShadow();
					}

					// Final check and reapplication
					await Task.Delay(20);
					if (!_shadowApplied && !_disposed)
					{
						ApplyShadowToDialog();
					}

					// Final comprehensive shadow removal
					if (!_disposed)
					{
						DisableDefaultShadow();
					}
				}
				catch (Exception asyncEx)
				{
					Logger.Write(asyncEx);
					// Async operation failure should not prevent dialog from working
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Event handler must never throw - dialog should still be usable
		}
	}

	private void ContentDialogV2_Closing(object sender, ContentDialogClosingEventArgs e)
	{
		try
		{
			// Reset shadow applied flag for potential reuse
			_shadowApplied = false;

			// Clear static reference to allow this dialog to be garbage collected
			if (ReferenceEquals(App.CurrentlyOpenContentDialog, this))
			{
				App.CurrentlyOpenContentDialog = null;
			}

			// Clean up event handlers to prevent memory leaks
			CleanupEventHandlers();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Event handler must never throw - dialog should still close properly
		}
	}

	private void CleanupEventHandlers()
	{
		try
		{
			// Unsubscribe from events using the stored handlers
			this.Loaded -= _loadedHandler;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Continue with other cleanups even if one fails
		}

		try
		{
			this.Opened -= _openedHandler;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Continue with other cleanups even if one fails
		}

		try
		{
			this.Closing -= _closingHandler;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Individual cleanup failure should not prevent other cleanups
		}

		try
		{
			if (_originalBackgroundBorder is not null && _backgroundBorderSizeHooked)
			{
				_originalBackgroundBorder.SizeChanged -= BackgroundBorder_SizeChanged;
				_backgroundBorderSizeHooked = false;
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	private void DisableDefaultShadow()
	{
		try
		{
			if (_disposed)
			{
				return;
			}

			// Find and disable any default shadow elements
			if (FindChildByName(this, "Shadow") is { } shadowElement)
			{
				shadowElement.Visibility = Visibility.Collapsed;
			}

			// Look for ThemeShadow or DropShadow elements
			if (FindChildOfType<Border>(this) is { Shadow: not null } themeShadowElement)
			{
				themeShadowElement.Shadow = null;
			}

			// Try to find and disable shadow on the main container
			if (FindChildByName(this, "Container") is Border { Shadow: not null } containerBorder)
			{
				containerBorder.Shadow = null;
			}

			// Try to find and disable shadow on background element
			if (FindChildByName(this, "BackgroundElement") is Border { Shadow: not null } backgroundBorder)
			{
				backgroundBorder.Shadow = null;
			}

			// Try to find and disable shadow on layout root
			if (FindChildByName(this, "LayoutRoot") is Border { Shadow: not null } layoutBorder)
			{
				layoutBorder.Shadow = null;
			}

			// Set Translation to zero to remove elevation shadow
			this.Translation = ZeroVector;

			// Try to remove shadow from the dialog itself
			if (this.Shadow is not null)
			{
				this.Shadow = null;
			}

			// Comprehensive removal of all shadows in the visual tree
			DisableAllBorderShadows(this);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Shadow disabling failure should not prevent dialog from working
		}
	}

	// Method returning cached shadow instance for performance
	private static AttachedCardShadow CreateShadow()
	{
		try
		{
			return CachedShadow;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Return a new instance as fallback
			try
			{
				return new AttachedCardShadow
				{
					Offset = ShadowOffset,
					Color = ShadowColor,
					BlurRadius = ShadowBlurRadius,
					Opacity = ShadowOpacity,
					CornerRadius = ShadowCornerRadius
				};
			}
			catch (Exception innerEx)
			{
				Logger.Write(innerEx);
				// Return basic shadow as final fallback - must never throw
				try
				{
					return new AttachedCardShadow();
				}
				catch (Exception finalEx)
				{
					Logger.Write(finalEx);
					// If we can't create any shadow, return null - handled by caller
					return null!;
				}
			}
		}
	}

	// Method for creating shadow container
	private static Border CreateShadowContainer()
	{
		try
		{
			return new Border
			{
				Background = TransparentBrush,
				CornerRadius = ShadowCorner,
				Margin = ShadowThickness,
				HorizontalAlignment = HorizontalAlignment.Stretch,
				VerticalAlignment = VerticalAlignment.Stretch
			};
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Return minimal border as fallback
			try
			{
				return new Border
				{
					Background = TransparentBrush,
					HorizontalAlignment = HorizontalAlignment.Stretch,
					VerticalAlignment = VerticalAlignment.Stretch
				};
			}
			catch (Exception innerEx)
			{
				Logger.Write(innerEx);
				// Return basic border as final fallback - must never throw
				try
				{
					return new Border();
				}
				catch (Exception finalEx)
				{
					Logger.Write(finalEx);
					// If we can't create any border, return null - handled by caller
					return null!;
				}
			}
		}
	}

	// Method for creating dialog container with specific properties
	private static Border CreateDialogContainer(Brush? background, Brush? borderBrush, Thickness borderThickness, CornerRadius cornerRadius)
	{
		try
		{
			return new Border
			{
				Background = background,
				BorderBrush = borderBrush,
				BorderThickness = borderThickness,
				CornerRadius = cornerRadius,
				Margin = ShadowThickness,
				HorizontalAlignment = HorizontalAlignment.Stretch,
				VerticalAlignment = VerticalAlignment.Stretch
			};
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Return minimal border as fallback
			try
			{
				return new Border
				{
					Background = background,
					BorderBrush = borderBrush,
					BorderThickness = borderThickness,
					CornerRadius = cornerRadius,
					HorizontalAlignment = HorizontalAlignment.Stretch,
					VerticalAlignment = VerticalAlignment.Stretch
				};
			}
			catch (Exception innerEx)
			{
				Logger.Write(innerEx);
				// Return basic border with just background as final fallback
				try
				{
					return new Border
					{
						Background = background,
						HorizontalAlignment = HorizontalAlignment.Stretch,
						VerticalAlignment = VerticalAlignment.Stretch
					};
				}
				catch (Exception finalEx)
				{
					Logger.Write(finalEx);
					// Return basic border as absolute final fallback - must never throw
					try
					{
						return new Border();
					}
					catch (Exception absoluteFinalEx)
					{
						Logger.Write(absoluteFinalEx);
						// If we can't create any border, return null - handled by caller
						return null!;
					}
				}
			}
		}
	}

	// Method for creating dialog container with default dialog corner radius
	private static Border CreateDialogContainerWithDialogCorner(Brush? background, Brush? borderBrush, Thickness borderThickness)
	{
		try
		{
			return CreateDialogContainer(background, borderBrush, borderThickness, DialogCorner);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Return basic border as fallback - must never throw
			try
			{
				return new Border
				{
					Background = background,
					BorderBrush = borderBrush,
					BorderThickness = borderThickness,
					HorizontalAlignment = HorizontalAlignment.Stretch,
					VerticalAlignment = VerticalAlignment.Stretch
				};
			}
			catch (Exception innerEx)
			{
				Logger.Write(innerEx);
				// Return minimal border as final fallback
				try
				{
					return new Border();
				}
				catch (Exception finalEx)
				{
					Logger.Write(finalEx);
					// If we can't create any border, return null - handled by caller
					return null!;
				}
			}
		}
	}

	// Method for clearing border properties using pattern matching
	private static void ClearBorderProperties(Border border)
	{
		try
		{
			border.Background = TransparentBrush;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Continue with other properties even if one fails
		}

		try
		{
			border.BorderBrush = TransparentBrush;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Continue with other properties even if one fails
		}

		try
		{
			border.BorderThickness = ZeroThickness;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Continue with other properties even if one fails
		}

		try
		{
			// Remove any existing shadow from the border using pattern matching
			if (border is { Shadow: not null })
			{
				border.Shadow = null;
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Shadow clearing failure should not prevent other property clearing
		}
	}

	// Method for handling panel parent scenario
	private static bool HandlePanelParentStatic(Border backgroundBorder, Border dialogContainer, Grid mainGrid)
	{
		try
		{
			// Store the original content
			UIElement? originalContent = backgroundBorder.Child;

			// Remove the original background
			backgroundBorder.Child = null;

			// Clear the background from the original element to avoid double borders
			ClearBorderProperties(backgroundBorder);

			// Put the original content into our dialog container
			dialogContainer.Child = originalContent;

			// Add our main grid to the background element
			backgroundBorder.Child = mainGrid;

			return true;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return false;
		}
	}

	// Method for handling content presenter parent scenario
	private static bool HandleContentPresenterParentStatic(Border backgroundBorder, ContentPresenter contentPresenter, Border dialogContainer, Grid mainGrid)
	{
		try
		{
			// Handle ContentPresenter scenario
			object? originalContent = contentPresenter.Content;

			// Clear the background from the original element to avoid double borders
			try
			{
				dialogContainer.Background = backgroundBorder.Background;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with other properties even if one fails
			}

			try
			{
				dialogContainer.BorderBrush = backgroundBorder.BorderBrush;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with other properties even if one fails
			}

			try
			{
				dialogContainer.BorderThickness = backgroundBorder.BorderThickness;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with other properties even if one fails
			}

			ClearBorderProperties(backgroundBorder);

			// Put the original content into our dialog container using pattern matching
			try
			{
				if (originalContent is FrameworkElement originalElement)
				{
					contentPresenter.Content = null;
					dialogContainer.Child = originalElement;
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Content transfer failure should not prevent grid setup
			}

			// Add our main grid to the content presenter
			try
			{
				contentPresenter.Content = mainGrid;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return false;
			}

			return true;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return false;
		}
	}

	// Method for handling border parent scenario
	private static bool HandleBorderParentStatic(Border backgroundBorder, Border parentBorder, Border dialogContainer, Grid mainGrid)
	{
		try
		{
			// Handle Border parent scenario
			UIElement? originalContent = backgroundBorder.Child;

			// Store the parent border's properties
			Brush? parentBackground = null;
			Brush? parentBorderBrush = null;
			Thickness parentBorderThickness = default;
			CornerRadius parentCornerRadius = default;

			try
			{
				parentBackground = parentBorder.Background;
				parentBorderBrush = parentBorder.BorderBrush;
				parentBorderThickness = parentBorder.BorderThickness;
				parentCornerRadius = parentBorder.CornerRadius;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with default values if property access fails
			}

			// Use parent properties for our dialog container
			try
			{
				dialogContainer.Background = parentBackground ?? backgroundBorder.Background;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with other properties even if one fails
			}

			try
			{
				dialogContainer.BorderBrush = parentBorderBrush ?? backgroundBorder.BorderBrush;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with other properties even if one fails
			}

			try
			{
				dialogContainer.BorderThickness = parentBorderThickness;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with other properties even if one fails
			}

			try
			{
				dialogContainer.CornerRadius = parentCornerRadius;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with other operations even if one fails
			}

			// Remove the original background
			try
			{
				backgroundBorder.Child = null;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with other operations even if one fails
			}

			// Clear the background from the original element to avoid double borders
			ClearBorderProperties(backgroundBorder);

			// Clear parent border properties to avoid double styling
			ClearBorderProperties(parentBorder);

			// Put the original content into our dialog container
			try
			{
				dialogContainer.Child = originalContent;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);

			}

			// Add our main grid to the background element
			try
			{
				backgroundBorder.Child = mainGrid;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return false;
			}

			return true;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return false;
		}
	}

	// Method for handling grid parent scenario
	private static bool HandleGridParentStatic(Border backgroundBorder, Border dialogContainer, Grid mainGrid)
	{
		try
		{
			// Handle Grid parent scenario
			UIElement? originalContent = backgroundBorder.Child;

			// Remove the original background
			try
			{
				backgroundBorder.Child = null;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with other operations even if one fails
			}

			// Clear the background from the original element to avoid double borders
			ClearBorderProperties(backgroundBorder);

			// Put the original content into our dialog container
			try
			{
				dialogContainer.Child = originalContent;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);

			}

			// Add our main grid to the background element
			try
			{
				backgroundBorder.Child = mainGrid;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return false;
			}

			return true;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return false;
		}
	}

	// Method for handling stack panel parent scenario
	private static bool HandleStackPanelParentStatic(Border backgroundBorder, Border dialogContainer, Grid mainGrid)
	{
		try
		{
			// Handle StackPanel parent scenario
			UIElement? originalContent = backgroundBorder.Child;

			// Remove the original background
			try
			{
				backgroundBorder.Child = null;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with other operations even if one fails
			}

			// Clear the background from the original element to avoid double borders
			ClearBorderProperties(backgroundBorder);

			// Put the original content into our dialog container
			try
			{
				dialogContainer.Child = originalContent;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);

			}

			// Add our main grid to the background element
			try
			{
				backgroundBorder.Child = mainGrid;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return false;
			}

			return true;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return false;
		}
	}

	// Method for handling canvas parent scenario
	private static bool HandleCanvasParentStatic(Border backgroundBorder, Border dialogContainer, Grid mainGrid)
	{
		try
		{
			// Handle Canvas parent scenario
			UIElement? originalContent = backgroundBorder.Child;

			// Remove the original background
			try
			{
				backgroundBorder.Child = null;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with other operations even if one fails
			}

			// Clear the background from the original element to avoid double borders
			ClearBorderProperties(backgroundBorder);

			// Put the original content into our dialog container
			try
			{
				dialogContainer.Child = originalContent;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);

			}

			// Add our main grid to the background element
			try
			{
				backgroundBorder.Child = mainGrid;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return false;
			}

			return true;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return false;
		}
	}

	// Method for handling generic parent scenario
	private static bool HandleGenericParentStatic(Border backgroundBorder, Border dialogContainer, Grid mainGrid)
	{
		try
		{
			// Generic parent handling
			UIElement? originalContent = backgroundBorder.Child;

			// Remove the original background
			try
			{
				backgroundBorder.Child = null;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with other operations even if one fails
			}

			// Clear the background from the original element to avoid double borders
			ClearBorderProperties(backgroundBorder);

			// Put the original content into our dialog container
			try
			{
				dialogContainer.Child = originalContent;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);

			}

			// Add our main grid to the background element
			try
			{
				backgroundBorder.Child = mainGrid;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return false;
			}

			return true;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return false;
		}
	}

	// Method for handling grid background scenario
	private static bool HandleGridBackgroundStatic(Grid backgroundGrid, Border dialogContainer, Grid mainGrid)
	{
		try
		{
			// Store all original children
			int childCount = 0;
			UIElement[] originalChildren = [];

			try
			{
				childCount = backgroundGrid.Children.Count;
				originalChildren = new UIElement[childCount];
				for (int i = 0; i < childCount; i++)
				{
					originalChildren[i] = backgroundGrid.Children[i];
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with empty array if children access fails
			}

			// Clear original children
			try
			{
				backgroundGrid.Children.Clear();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue even if clearing fails
			}

			// Add original children to dialog container
			Grid contentGrid = new();
			for (int i = 0; i < originalChildren.Length; i++)
			{
				try
				{
					contentGrid.Children.Add(originalChildren[i]);
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
					// Continue with next child even if one fails
				}
			}

			// Put the content grid into our dialog container
			try
			{
				dialogContainer.Child = contentGrid;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with background clearing even if content setting fails
			}

			// Clear the background from the original element to avoid double styling
			try
			{
				backgroundGrid.Background = TransparentBrush;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with grid addition even if background clearing fails
			}

			// Add our main grid to the background grid
			try
			{
				backgroundGrid.Children.Add(mainGrid);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return false;
			}

			return true;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return false;
		}
	}

	// Method for handling panel background scenario
	private static bool HandlePanelBackgroundStatic(Panel backgroundPanel, Border dialogContainer, Grid mainGrid)
	{
		try
		{
			// Store all original children
			int childCount = 0;
			UIElement[] originalChildren = [];

			try
			{
				childCount = backgroundPanel.Children.Count;
				originalChildren = new UIElement[childCount];
				for (int i = 0; i < childCount; i++)
				{
					originalChildren[i] = backgroundPanel.Children[i];
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with empty array if children access fails
			}

			// Clear original children
			try
			{
				backgroundPanel.Children.Clear();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue even if clearing fails
			}

			// Add original children to dialog container
			Grid contentGrid = new();
			for (int i = 0; i < originalChildren.Length; i++)
			{
				try
				{
					contentGrid.Children.Add(originalChildren[i]);
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
					// Continue with next child even if one fails
				}
			}

			// Put the content grid into our dialog container
			try
			{
				dialogContainer.Child = contentGrid;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with background clearing even if content setting fails
			}

			// Clear the background from the original element to avoid double styling
			try
			{
				backgroundPanel.Background = TransparentBrush;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with panel addition even if background clearing fails
			}

			// Add our main grid to the background panel
			try
			{
				backgroundPanel.Children.Add(mainGrid);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return false;
			}

			return true;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return false;
		}
	}

	private void ApplyShadowToDialog()
	{
		try
		{
			if (_shadowApplied || _disposed)
			{
				return;
			}

			// Find the dialog's background element
			FrameworkElement? backgroundElement = null;
			try
			{
				backgroundElement = ((FindChildByName(this, "BackgroundElement") ?? FindChildByName(this, "Container")) ?? FindChildByName(this, "LayoutRoot")) ?? FindChildOfType<Border>(this);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				// Continue with null background element - will be handled below
			}

			switch (backgroundElement)
			{
				case Border backgroundBorder:
					{
						try
						{
							// Keep original background border reference (only once)
							if (!_backgroundBorderSizeHooked)
							{
								_originalBackgroundBorder = backgroundBorder;
								try
								{
									_originalBackgroundBorder.SizeChanged += BackgroundBorder_SizeChanged;
									_backgroundBorderSizeHooked = true;
								}
								catch (Exception hookEx)
								{
									Logger.Write(hookEx);
								}
							}

							// Create a new Grid to wrap the existing content
							_mainGrid = new Grid();

							// Create shadow container using static method
							_shadowContainer = CreateShadowContainer();
							if (_shadowContainer is null)
							{
								// Skip shadow application if container creation failed
								break;
							}

							// Create dialog container using static method
							_dialogContainer = CreateDialogContainerWithDialogCorner(backgroundBorder.Background, backgroundBorder.BorderBrush, backgroundBorder.BorderThickness);
							if (_dialogContainer is null)
							{
								// Skip shadow application if dialog container creation failed
								break;
							}

							// Apply shadow to the shadow container
							try
							{
								AttachedCardShadow dialogShadow = CreateShadow();
								if (dialogShadow is not null)
								{
									Effects.SetShadow(_shadowContainer, dialogShadow);
								}
							}
							catch (Exception shadowEx)
							{
								Logger.Write(shadowEx);
								// Continue without shadow effect if shadow application fails
							}

							// Set up the layering
							try
							{
								_mainGrid.Children.Add(_shadowContainer);
								_mainGrid.Children.Add(_dialogContainer);
							}
							catch (Exception layeringEx)
							{
								Logger.Write(layeringEx);
								// Skip parent handling if layering fails
								break;
							}

							// Handle parent using pattern matching switch expression - ordered by specificity (most specific first)
							bool handlingSuccessful = false;
							try
							{
								handlingSuccessful = backgroundBorder.Parent switch
								{
									ContentPresenter contentPresenter => HandleContentPresenterParentStatic(backgroundBorder, contentPresenter, _dialogContainer, _mainGrid),
									Border parentBorder => HandleBorderParentStatic(backgroundBorder, parentBorder, _dialogContainer, _mainGrid),
									Grid => HandleGridParentStatic(backgroundBorder, _dialogContainer, _mainGrid),
									StackPanel => HandleStackPanelParentStatic(backgroundBorder, _dialogContainer, _mainGrid),
									Canvas => HandleCanvasParentStatic(backgroundBorder, _dialogContainer, _mainGrid),
									Panel => HandlePanelParentStatic(backgroundBorder, _dialogContainer, _mainGrid),
									_ => HandleGenericParentStatic(backgroundBorder, _dialogContainer, _mainGrid)
								};
							}
							catch (Exception parentEx)
							{
								Logger.Write(parentEx);
								// Try generic handling as fallback
								try
								{
									handlingSuccessful = HandleGenericParentStatic(backgroundBorder, _dialogContainer, _mainGrid);
								}
								catch (Exception genericEx)
								{
									Logger.Write(genericEx);
									handlingSuccessful = false;
								}
							}

							if (handlingSuccessful)
							{
								_shadowApplied = true;
							}
						}
						catch (Exception ex)
						{
							Logger.Write(ex);
							// Border case handling failed - continue to other cases or fallback
						}
						break;
					}

				case Grid backgroundGrid:
					{
						try
						{
							// Handle case where background element is a Grid
							_mainGrid = new Grid();

							// Create shadow container using static method
							_shadowContainer = CreateShadowContainer();
							if (_shadowContainer is null)
							{
								// Skip shadow application if container creation failed
								break;
							}

							// Create dialog container using static method
							_dialogContainer = CreateDialogContainerWithDialogCorner(backgroundGrid.Background, this.BorderBrush, this.BorderThickness);
							if (_dialogContainer is null)
							{
								// Skip shadow application if dialog container creation failed
								break;
							}

							// Apply shadow to the shadow container
							try
							{
								AttachedCardShadow dialogShadow = CreateShadow();
								if (dialogShadow is not null)
								{
									Effects.SetShadow(_shadowContainer, dialogShadow);
								}
							}
							catch (Exception shadowEx)
							{
								Logger.Write(shadowEx);
								// Continue without shadow effect if shadow application fails
							}

							// Set up the layering
							try
							{
								_mainGrid.Children.Add(_shadowContainer);
								_mainGrid.Children.Add(_dialogContainer);
							}
							catch (Exception layeringEx)
							{
								Logger.Write(layeringEx);
								// Skip grid handling if layering fails
								break;
							}

							// Handle grid background using static method
							bool handlingSuccessful = HandleGridBackgroundStatic(backgroundGrid, _dialogContainer, _mainGrid);

							if (handlingSuccessful)
							{
								_shadowApplied = true;
							}
						}
						catch (Exception ex)
						{
							Logger.Write(ex);
							// Grid case handling failed - continue to other cases or fallback
						}
						break;
					}

				case Panel backgroundPanel:
					{
						try
						{
							// Handle case where background element is another type of Panel
							_mainGrid = new Grid();

							// Create shadow container using static method
							_shadowContainer = CreateShadowContainer();
							if (_shadowContainer is null)
							{
								// Skip shadow application if container creation failed
								break;
							}

							// Create dialog container using static method
							_dialogContainer = CreateDialogContainerWithDialogCorner(backgroundPanel.Background, this.BorderBrush, this.BorderThickness);
							if (_dialogContainer is null)
							{
								// Skip shadow application if dialog container creation failed
								break;
							}

							// Apply shadow to the shadow container
							try
							{
								AttachedCardShadow dialogShadow = CreateShadow();
								if (dialogShadow is not null)
								{
									Effects.SetShadow(_shadowContainer, dialogShadow);
								}
							}
							catch (Exception shadowEx)
							{
								Logger.Write(shadowEx);
								// Continue without shadow effect if shadow application fails
							}

							// Set up the layering
							try
							{
								_mainGrid.Children.Add(_shadowContainer);
								_mainGrid.Children.Add(_dialogContainer);
							}
							catch (Exception layeringEx)
							{
								Logger.Write(layeringEx);
								// Skip panel handling if layering fails
								break;
							}

							// Handle panel background using static method
							bool handlingSuccessful = HandlePanelBackgroundStatic(backgroundPanel, _dialogContainer, _mainGrid);

							if (handlingSuccessful)
							{
								_shadowApplied = true;
							}
						}
						catch (Exception ex)
						{
							Logger.Write(ex);
							// Panel case handling failed - continue to fallback
						}
						break;
					}

				default:
					// No valid background element found - dialog will work without custom shadow
					break;
			}

			// After applying custom shadow, immediately remove any remaining default shadows
			DisableDefaultShadowImmediately();
		}
		catch (Exception ex)
		{
			// Shadow application completely failed - dialog should still work without custom shadow
			Logger.Write(ex);
			// Try simple fallback shadow application
			try
			{
				AttachedCardShadow simpleShadow = CreateShadow();
				if (simpleShadow is not null)
				{
					Effects.SetShadow(this, simpleShadow);
					_shadowApplied = true;
				}
			}
			catch (Exception fallbackEx)
			{
				Logger.Write(fallbackEx);
				// Even fallback failed - dialog works without shadow
			}
		}
	}

	// Method for finding child of type
	private static T? FindChildOfType<T>(DependencyObject? parent) where T : DependencyObject
	{
		try
		{
			if (parent is null)
			{
				return null;
			}

			int childCount = VisualTreeHelper.GetChildrenCount(parent);
			for (int i = 0; i < childCount; i++)
			{
				try
				{
					DependencyObject child = VisualTreeHelper.GetChild(parent, i);

					if (child is T result)
					{
						return result;
					}

					if (FindChildOfType<T>(child) is T childResult)
					{
						return childResult;
					}
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
					// Continue with next child even if one fails
				}
			}

			return null;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return null;
		}
	}

	// Method for finding child by name
	private static FrameworkElement? FindChildByName(DependencyObject? parent, string name)
	{
		try
		{
			if (parent is null)
			{
				return null;
			}

			int childCount = VisualTreeHelper.GetChildrenCount(parent);
			for (int i = 0; i < childCount; i++)
			{
				try
				{
					DependencyObject child = VisualTreeHelper.GetChild(parent, i);

					if (child is FrameworkElement { Name: var elementName } frameworkElement && elementName == name)
					{
						return frameworkElement;
					}

					if (FindChildByName(child, name) is { } childResult)
					{
						return childResult;
					}
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
					// Continue with next child even if one fails
				}
			}

			return null;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return null;
		}
	}

	/// <summary>
	/// This method can throw during stress testing content dialog by opening and closing it in quick succession.
	/// The problem is that WinUI ContentDialog has a built-in restriction: "Only a single ContentDialog can be open at any time."
	/// by rapidly opening and closing dialogs, the previous dialog might not be fully closed yet when we try to open a new one,
	/// causing this COM exception.
	/// The error occurs at base.ShowAsync() which calls the underlying WinUI ContentDialog.ShowAsync() method.
	/// This method throws a COMException when another ContentDialog is already open.
	///	The issue is that the current code tries to call base.ShowAsync() again in the fallback, which will just cause the same error again.
	///	The code is resilient however, so the app doesn't crash, only an error is logged which is an acceptable outcome.
	///	The goal is resiliency during stress tests, however, we can improve this with proper dialog queue management.
	/// </summary>
	/// <returns></returns>
	internal new IAsyncOperation<ContentDialogResult> ShowAsync()
	{
		try
		{
			App.CurrentlyOpenContentDialog = this;
			return base.ShowAsync();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			// Return a completed task with a default result to prevent crashes - dialog must always show
			try
			{
				return Task.FromResult(ContentDialogResult.None).AsAsyncOperation();
			}
			catch (Exception innerEx)
			{
				Logger.Write(innerEx);
				// Try alternative approach for creating async result
				try
				{
					TaskCompletionSource<ContentDialogResult> taskCompletionSource = new();
					taskCompletionSource.SetResult(ContentDialogResult.None);
					return taskCompletionSource.Task.AsAsyncOperation();
				}
				catch (Exception finalEx)
				{
					Logger.Write(finalEx);
					// Last resort - try base implementation one more time without setting CurrentlyOpenContentDialog
					try
					{
						return base.ShowAsync();
					}
					catch (Exception absoluteFinalEx)
					{
						Logger.Write(absoluteFinalEx);
						// Create a minimal async operation that completes immediately
						TaskCompletionSource<ContentDialogResult> finalTaskSource = new();
						finalTaskSource.SetResult(ContentDialogResult.None);
						return finalTaskSource.Task.AsAsyncOperation();
					}
				}
			}
		}
	}

	/// <summary>
	/// Without this event handler, when the ContentDialog resizes either by us or due to content size inside of it changes,
	/// It would get an ugly opaque shadow thingy around it.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BackgroundBorder_SizeChanged(object sender, SizeChangedEventArgs e)
	{
		try
		{
			if (_disposed)
			{
				return;
			}

			// Re-suppress any reintroduced default shadow or background after internal content resize
			DisableDefaultShadowImmediately();

			// Reassert corner radius of custom container if WinUI re-templated anything
			try
			{
				_ = (_dialogContainer?.CornerRadius = new CornerRadius(DialogCornerRadius));
			}
			catch (Exception exCorner)
			{
				Logger.Write(exCorner);
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	public void Dispose()
	{
		try
		{
			Dispose(true);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}

		try
		{
			GC.SuppressFinalize(this);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	protected virtual void Dispose(bool disposing)
	{
		try
		{
			if (!_disposed && disposing)
			{
				try
				{
					// Clean up event handlers
					CleanupEventHandlers();
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
				}

				// Clear static reference if still pointing to this instance
				if (ReferenceEquals(App.CurrentlyOpenContentDialog, this))
				{
					App.CurrentlyOpenContentDialog = null;
				}

				try
				{
					// Clear visual tree references
					_shadowContainer = null;
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
				}

				try
				{
					_dialogContainer = null;
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
				}

				try
				{
					_mainGrid = null;
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
				}

				try
				{
					_originalBackgroundBorder = null;
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
				}

				_disposed = true;
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			try
			{
				_disposed = true;
			}
			catch (Exception innerEx)
			{
				Logger.Write(innerEx);
			}
		}
	}

	~ContentDialogV2()
	{
		try
		{
			Dispose(false);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}
}
