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

using AppControlManager.Others;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// This custom ListView is suitable for use in a page that already has a ScrollView around it.
/// It will offer proper scrolling functionality for both touch and mouse.
/// </summary>
internal sealed partial class ListViewV3 : ListView
{
	/// <summary>
	/// When set in XAML, this key will be used to register/unregister the ScrollViewer inside of the ListView and the ListView itself.
	/// </summary>
	public ListViewHelper.ListViewsRegistry RegistryKey
	{
		get => (ListViewHelper.ListViewsRegistry)GetValue(RegistryKeyProperty);
		set => SetValue(RegistryKeyProperty, value);
	}

	/// <summary>
	/// A DP added to the ListView which is a type Enum, used to register it in the caches.
	/// This property is exposed and is available in the XAML just like other native properties of the ListView.
	/// </summary>
	internal static readonly DependencyProperty RegistryKeyProperty =
		DependencyProperty.Register(
			name: nameof(RegistryKey),
			propertyType: typeof(ListViewHelper.ListViewsRegistry),
			ownerType: typeof(ListViewV3),
			typeMetadata: new PropertyMetadata(null));

	// Reference to the parent ScrollView (external to this ListView)
	private ScrollView? _parentScrollView;

	// Reference to the inner ScrollViewer that WinUI creates around the ListView
	private ScrollViewer? _innerScrollViewer;

	internal ListViewV3()
	{
		// Apply default ScrollViewer settings for the dependency properties
		ScrollViewer.SetVerticalScrollBarVisibility(this, ScrollBarVisibility.Visible);

		// Set a default style of the ListView
		this.ShowsScrollingPlaceholders = true;

		// Subscribe to lifecycle events of the ListView
		Loaded += OnLoaded;
		Unloaded += OnUnloaded;

		// Wire up pointer events to intercept mouse wheel and pointer behaviors
		PointerEntered += OnPointerEntered;
		PointerExited += OnPointerExited;
		PointerPressed += OnPointerPressed;
	}

	private void OnLoaded(object? sender, RoutedEventArgs e)
	{
		// Delay execution until the visual tree is ready
		_ = this.DispatcherQueue.TryEnqueue(() =>
		{
			// Grab the inner ScrollViewer
			_innerScrollViewer = this.FindScrollViewer();

			if (_innerScrollViewer != null)
			{
				// Register the control + inner ScrollViewer in the helper
				ListViewHelper.Register(RegistryKey, this, _innerScrollViewer);
			}
		});
	}

	private void OnUnloaded(object? sender, RoutedEventArgs e)
	{
		// Ensure the outer ScrollView is re-enabled even if the pointer is inside during unload (mouse hover path).
		// Without this, the parent could remain stuck in Disabled mode after navigation.
		_ = (_parentScrollView?.VerticalScrollMode = ScrollingScrollMode.Enabled);

		ListViewHelper.Unregister(RegistryKey, this);
	}

	// Since we have a ScrollView around the page, it captures the mouse Scroll Wheel events.
	// We have to disable its scrolling ability while pointer is inside of the ListView.
	// Scrolling via touch or dragging the ListView's scrollbar via mouse doesn't require this and they work either way.
	private void OnPointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (e.Pointer.PointerDeviceType == PointerDeviceType.Mouse)
		{
			// Find the outer ScrollView if not already captured
			if (_parentScrollView == null)
			{
				_parentScrollView = FindParentScrollView();
			}

			// Disable vertical scrolling for the outer ScrollView only for mouse input
			_ = (_parentScrollView?.VerticalScrollMode = ScrollingScrollMode.Disabled);
		}
	}

	private void OnPointerExited(object sender, PointerRoutedEventArgs e)
	{
		// Re-enable vertical scrolling for the outer ScrollView
		_ = (_parentScrollView?.VerticalScrollMode = ScrollingScrollMode.Enabled);
	}

	private void OnPointerPressed(object sender, PointerRoutedEventArgs e)
	{
		// Always enable vertical scrolling for non-mouse input
		if (e.Pointer.PointerDeviceType != PointerDeviceType.Mouse && _parentScrollView != null)
		{
			_parentScrollView.VerticalScrollMode = ScrollingScrollMode.Enabled;
		}
	}

	/// <summary>
	/// Walks up the visual tree to find the first ScrollView ancestor *after* the ListView's own inner ScrollViewer
	/// </summary>
	private ScrollView? FindParentScrollView()
	{
		// Start from the inner ScrollViewer if we have it, otherwise from 'this'
		DependencyObject? parent = (_innerScrollViewer as DependencyObject) ?? this;

		// Move up until we find a ScrollView that's *not* the inner one
		while (parent != null)
		{
			parent = VisualTreeHelper.GetParent(parent);
			if (parent is ScrollView sv && sv != _innerScrollViewer)
			{
				return sv;
			}
		}
		return null;
	}
}
