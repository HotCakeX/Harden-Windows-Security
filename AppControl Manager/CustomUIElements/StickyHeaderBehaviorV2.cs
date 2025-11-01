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


/*

The code in this file is MODIFIED version of the MIT licensed code in the following repository: https://github.com/CommunityToolkit/Windows
Taken from this URL: https://github.com/CommunityToolkit/Windows/tree/321f5ddc8f3bf07865c8f51d992febb25fd7859a/components/Behaviors/src/Headers

It's removed the "ScrollViewer_GotFocus" from the base class to prevent scroll positions from changing when clicking on the header which is an unwanted behavior.

It is also self-contained and does not require any additional dependencies such as "CommunityToolkit.WinUI.Behaviors" and "Microsoft.Xaml.Behaviors.WinUI.Managed".

License file: https://github.com/CommunityToolkit/Windows/blob/main/License.md

Windows Community Toolkit
Copyright © .NET Foundation and Contributors

All rights reserved.

MIT License (MIT)
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 */

using System.Numerics;
using CommunityToolkit.WinUI;
using CommunityToolkit.WinUI.Animations.Expressions;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;

namespace AppControlManager.CustomUIElements;

#pragma warning disable CA1515

/// <summary>
/// Sticky Header for List Views.
/// </summary>
public static class StickyHeaderBehaviorV2
{
	/// <summary>
	/// From Doc: https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.canvas.zindex
	/// </summary>
	private const int CanvasZIndexMax = 1_000_000;

	/// <summary>
	/// Attached property to enable/disable the behavior
	/// </summary>
	public static readonly DependencyProperty IsEnabledProperty =
		DependencyProperty.RegisterAttached(
			"IsEnabled",
			typeof(bool),
			typeof(StickyHeaderBehaviorV2),
			new PropertyMetadata(false, OnIsEnabledChanged));

	public static void SetIsEnabled(DependencyObject element, bool value)
	{
		ArgumentNullException.ThrowIfNull(element);
		element.SetValue(IsEnabledProperty, value);
	}

	public static bool GetIsEnabled(DependencyObject element)
	{
		ArgumentNullException.ThrowIfNull(element);
		// Default metadata for IsEnabledProperty is false, so this cast is safe
		return (bool)element.GetValue(IsEnabledProperty);
	}

	/// <summary>
	/// Private attached property to hold per-element state
	/// </summary>
	private static readonly DependencyProperty StateProperty =
		DependencyProperty.RegisterAttached(
			"State",
			typeof(StickyHeaderState),
			typeof(StickyHeaderBehaviorV2),
			new PropertyMetadata(null));

	private static void SetState(DependencyObject element, StickyHeaderState? value) => element.SetValue(StateProperty, value);

	private static StickyHeaderState? GetState(DependencyObject element) => (StickyHeaderState?)element.GetValue(StateProperty);

	private static void OnIsEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is not FrameworkElement element)
		{
			return;
		}

		bool enabled = e.NewValue is bool b && b;

		StickyHeaderState? existing = GetState(element);
		if (enabled)
		{
			if (existing is null)
			{
				StickyHeaderState state = new();
				SetState(element, state);
				state.Attach(element);
			}
		}
		else
		{
			if (existing is not null)
			{
				existing.Detach();
				SetState(element, null);
			}
		}
	}

	// Encapsulates all composition state and event hookups for a single attached element
	private sealed class StickyHeaderState
	{
		private FrameworkElement? _headerElement;

		/// <summary>
		/// The ScrollViewer associated with the ListViewBase control.
		/// </summary>
		private ScrollViewer? _scrollViewer;

		/// <summary>
		/// The CompositionPropertySet associated with the ScrollViewer.
		/// </summary>
		private CompositionPropertySet? _scrollProperties;


		private CompositionPropertySet? _animationProperties;

		/// <summary>
		/// The Visual associated with the header element.
		/// </summary>
		private Visual? _headerVisual;


		private bool _isAttached;

		internal void Attach(FrameworkElement element)
		{
			if (_isAttached)
			{
				return;
			}

			_headerElement = element;

			// Hook load/unload to manage lifecycle robustly
			_headerElement.Loaded -= OnLoaded;
			_headerElement.Unloaded -= OnUnloaded;
			_headerElement.Loaded += OnLoaded;
			_headerElement.Unloaded += OnUnloaded;

			// If already loaded, initialize immediately
			if (_headerElement.IsLoaded)
			{
				InitializeAndStart();
			}

			_isAttached = true;
		}

		internal void Detach()
		{
			if (!_isAttached)
			{
				return;
			}

			if (_headerElement is not null)
			{
				_headerElement.SizeChanged -= OnSizeChanged;
				_headerElement.Loaded -= OnLoaded;
				_headerElement.Unloaded -= OnUnloaded;
			}

			StopAnimation();

			_scrollViewer = null;
			_scrollProperties = null;
			_animationProperties = null;
			_headerVisual = null;
			_headerElement = null;

			_isAttached = false;
		}

		private void OnLoaded(object sender, RoutedEventArgs e) => InitializeAndStart();

		// Ensure everything is released when element leaves the tree
		private void OnUnloaded(object sender, RoutedEventArgs e) => StopAnimation();

		private void OnSizeChanged(object sender, SizeChangedEventArgs e) => InitializeAndStart();

		private void InitializeAndStart()
		{
			if (_headerElement is null)
			{
				return;
			}

			StopAnimation();

			// Must have a meaningful size to set up the expression properly
			if (_headerElement.RenderSize.Height == 0)
			{
				_headerElement.SizeChanged -= OnSizeChanged;
				_headerElement.SizeChanged += OnSizeChanged;
				return;
			}

			if (_scrollViewer is null)
			{
				// Find the ancestor ScrollViewer within the ListView/Grid/List control
				_scrollViewer = _headerElement.FindAscendant<ScrollViewer>();
				if (_scrollViewer is null)
				{
					return;
				}
			}

			// Ensure the header is above list content (or list content behind header)
			ItemsControl? itemsControl = _headerElement.FindAscendant<ItemsControl>();
			if (itemsControl is not null && itemsControl.ItemsPanelRoot is not null)
			{
				Canvas.SetZIndex(itemsControl.ItemsPanelRoot, -1);
			}
			else
			{
				Canvas.SetZIndex(_headerElement, CanvasZIndexMax);
			}

			if (_scrollProperties is null)
			{
				_scrollProperties = ElementCompositionPreview.GetScrollViewerManipulationPropertySet(_scrollViewer);
				if (_scrollProperties is null)
				{
					return;
				}
			}

			if (_headerVisual is null)
			{
				_headerVisual = ElementCompositionPreview.GetElementVisual(_headerElement);
				if (_headerVisual is null)
				{
					return;
				}
			}

			_headerElement.SizeChanged -= OnSizeChanged;
			_headerElement.SizeChanged += OnSizeChanged;

			Compositor compositor = _scrollProperties.Compositor;

			if (_animationProperties is null)
			{
				_animationProperties = compositor.CreatePropertySet();
			}

			_animationProperties.InsertScalar("OffsetY", 0.0f);

			// Build expression: max(OffsetY - Scroll.Translation.Y, 0)
			ScalarNode propSetOffset = _animationProperties.GetReference().GetScalarProperty("OffsetY");
			ManipulationPropertySetReferenceNode scrollPropSet = _scrollProperties.GetSpecializedReference<ManipulationPropertySetReferenceNode>();
			ScalarNode expressionAnimation = ExpressionFunctions.Max(propSetOffset - scrollPropSet.Translation.Y, 0);

			_headerVisual.StartAnimation("Offset.Y", expressionAnimation);
		}

		/// <summary>
		/// Stop the animation of the UIElement.
		/// </summary>
		private void StopAnimation()
		{
			_animationProperties?.InsertScalar("OffsetY", 0.0f);

			if (_headerVisual is not null)
			{
				_headerVisual.StopAnimation("Offset.Y");

				Vector3 offset = _headerVisual.Offset;
				offset.Y = 0.0f;
				_headerVisual.Offset = offset;
			}
		}
	}
}
