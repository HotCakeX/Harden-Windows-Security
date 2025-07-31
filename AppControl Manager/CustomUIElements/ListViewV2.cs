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

using System;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.CustomUIElements;

internal sealed partial class ListViewV2 : ListView
{
	// A counter to prevent SelectionChanged event from firing twice when right-clicking on an unselected row (when on internal programmatic selects)
	private int _skipSelectionChangedCount;

	/// <summary>
	/// When set in XAML, this key will be used for to register/unregister the ScrollViewer inside of the ListView and the ListView itself.
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
			ownerType: typeof(ListViewV2),
			typeMetadata: new PropertyMetadata(null));

	/// <summary>
	/// The SelectionChanged and ContainerContentChanging events can still be subscribed to from the code behind of any page that utilizes this ListView.
	/// </summary>
	internal ListViewV2()
	{
		// Wire our handlers
		SelectionChanged += OnListViewV2SelectionChanged;
		ContainerContentChanging += OnListViewV2ContainerContentChanging;

		// Apply default ScrollViewer settings for the dependency properties
		ScrollViewer.SetHorizontalScrollMode(this, ScrollMode.Enabled);
		ScrollViewer.SetIsHorizontalRailEnabled(this, true);
		ScrollViewer.SetHorizontalScrollBarVisibility(this, ScrollBarVisibility.Visible);
		ScrollViewer.SetVerticalScrollBarVisibility(this, ScrollBarVisibility.Visible);

		// Set a default style of the ListView
		this.ShowsScrollingPlaceholders = true;

		// Subscribe to life cycle events of the ListView
		Loaded += OnLoaded;
		Unloaded += OnUnloaded;
	}

	private async void OnListViewV2SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		try
		{
			// Skip if this was triggered by our RightTapped selection
			if (_skipSelectionChangedCount > 0)
			{
				_skipSelectionChangedCount--;
				return;
			}

			ListView lv = (ListView)sender;

			await ListViewHelper.SmoothScrollIntoViewWithIndexCenterVerticallyOnlyAsync(
					listViewBase: lv,
					listView: lv,
					index: lv.SelectedIndex,
					disableAnimation: false,
					scrollIfVisible: true,
					additionalHorizontalOffset: 0,
					additionalVerticalOffset: 0
				);
		}
		catch (Exception ex)
		{
			Logger.Write(ErrorWriter.FormatException(ex));
		}
	}

	// When right-clicking on an unselected row, first it becomes selected and then the context menu will be shown for the selected row
	// This is a much more expected behavior. Without this, the right-click would be meaningless on the ListView unless user left-clicks on the row first
	private void OnListViewV2ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		var container = args.ItemContainer;

		// When the container is being recycled, detach the handler.
		if (args.InRecycleQueue)
		{
			container.RightTapped -= OnListViewV2ItemRightTapped;
		}
		else
		{
			// Detach first to avoid multiple subscriptions, then attach the handler.
			container.RightTapped -= OnListViewV2ItemRightTapped;
			container.RightTapped += OnListViewV2ItemRightTapped;
		}
	}

	private void OnListViewV2ItemRightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		// If the item is not already selected, clear previous selections and select this one.
		if (sender is ListViewItem item && !item.IsSelected)
		{
			// Set the counter so that the SelectionChanged event handler will ignore the next 2 events.
			_skipSelectionChangedCount = 2;
			item.IsSelected = true;
		}
	}

	/// <summary>
	/// Loaded event of the ListView. Every time the ListView becomes visible, such as by navigating to the page containing it, this event will be fired.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OnLoaded(object? sender, RoutedEventArgs e)
	{
		// Delay execution until the visual tree is ready
		_ = this.DispatcherQueue.TryEnqueue(() =>
		{
			ScrollViewer? sv = this.FindScrollViewer();
			if (sv != null)
				ListViewHelper.Register(RegistryKey, this, sv);
		});
	}

	/// <summary>
	/// Whenever we navigate away from a page that contains the ListView, this even will be fired.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OnUnloaded(object? sender, RoutedEventArgs e)
	{
		ListViewHelper.Unregister(RegistryKey);
	}

}
