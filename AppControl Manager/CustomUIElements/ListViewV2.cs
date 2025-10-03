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

			// Early exit when there is no selection or the list is empty.
			// This prevents container lookups and ScrollIntoView calls.
			if (lv.Items.Count == 0 || lv.SelectedIndex < 0)
			{
				return;
			}

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
			Logger.Write(ex);
		}
	}

	// When right-clicking on an unselected row, first it becomes selected and then the context menu will be shown for the selected row
	// This is a much more expected behavior. Without this, the right-click would be meaningless on the ListView unless user left-clicks on the row first
	private void OnListViewV2ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		// When the container is being recycled, detach the handler.
		if (args.InRecycleQueue)
		{
			args.ItemContainer.RightTapped -= OnListViewV2ItemRightTapped;
		}
		else
		{
			// Detach first to avoid multiple subscriptions, then attach the handler.
			args.ItemContainer.RightTapped -= OnListViewV2ItemRightTapped;
			args.ItemContainer.RightTapped += OnListViewV2ItemRightTapped;
		}
	}

	// When right-clicking on a row:
	// - If we right-click on an item that is already selected, or if we right-click on one of the items among multiple items that are selected,
	// keep the current selection and just show the context menu for that selection.
	// - If we right-click on an unselected item, clear the previous selection and select only that item.
	// P.S: We skip the next two SelectionChanged events to avoid unintended smooth scrolling due to programmatic changes.
	private void OnListViewV2ItemRightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		// Don't proceed further if the sender is not a ListViewItem or if the ListView is in None or Single selection mode because then SelectedItems property is readonly and we get COM error if we attempt to clear it.
		if (sender is not ListViewItem item || this.SelectionMode is ListViewSelectionMode.None or ListViewSelectionMode.Single)
			return;

		// If the item is already selected, do nothing so multi-selection is preserved.
		// This allows right-click actions (copy/delete) to apply to the full current selection.
		if (item.IsSelected)
			return;

		// Otherwise, switch to single-selection on this item.
		// SelectionChanged will fire for Clear and for the new selection; suppress both.
		_skipSelectionChangedCount = 2;
		this.SelectedItems.Clear();
		item.IsSelected = true;
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
		ListViewHelper.Unregister(RegistryKey, this);
	}

	/// <summary>
	/// Suppresses the SelectionChanged handler from performing smooth centering
	/// for the next 'count' SelectionChanged events (used to avoid unintended
	/// scroll jumps during programmatic operations like sorting).
	/// </summary>
	/// <param name="count">How many upcoming SelectionChanged events to skip; minimum is 1.</param>
	internal void SuppressSelectionChanged(int count = 1)
	{
		if (count < 1)
		{
			count = 1;
		}

		// Reusing the existing counter leveraged by right-click selection logic.
		_skipSelectionChangedCount = count;
	}

}
