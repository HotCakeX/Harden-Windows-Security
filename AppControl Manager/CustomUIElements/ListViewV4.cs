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
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.CustomUIElements;

// Use by Incremental Collections. Doesn't use "RegistryKey" Dependency Property but that RegistryKey enum value is used for other things.
internal sealed partial class ListViewV4 : ListView
{
	// A counter to prevent SelectionChanged event from firing twice when right-clicking on an unselected row (when on internal programmatic selects)
	private int _skipSelectionChangedCount;

	/// <summary>
	/// The SelectionChanged and ContainerContentChanging events can still be subscribed to from the code behind of any page that utilizes this ListView.
	/// </summary>
	internal ListViewV4()
	{
		// Wire our handlers
		SelectionChanged += OnListViewV2SelectionChanged;
		ContainerContentChanging += OnListViewContainerContentChanging;

		// Apply default ScrollViewer settings for the dependency properties
		ScrollViewer.SetHorizontalScrollMode(this, ScrollMode.Enabled);
		ScrollViewer.SetIsHorizontalRailEnabled(this, true);
		ScrollViewer.SetHorizontalScrollBarVisibility(this, ScrollBarVisibility.Visible);
		ScrollViewer.SetVerticalScrollBarVisibility(this, ScrollBarVisibility.Visible);

		// Set a default style of the ListView
		this.ShowsScrollingPlaceholders = true;
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
	private void OnListViewContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
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
		if (sender is not ListViewItem item)
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
