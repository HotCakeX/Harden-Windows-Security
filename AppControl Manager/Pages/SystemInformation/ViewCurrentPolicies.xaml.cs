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
using AppControlManager.CustomUIElements;
using AppControlManager.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Represents a page for viewing current policies with data binding and navigation state management. It includes event
/// handlers for menu and list interactions.
/// </summary>
public sealed partial class ViewCurrentPolicies : Page
{

#pragma warning disable CA1822
	internal ViewCurrentPoliciesVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<ViewCurrentPoliciesVM>();
#pragma warning restore CA1822

	internal ListView DeployedPoliciesListView { get; }

	// Singleton instance of the class
	private static ViewCurrentPolicies? _instance;

	/// <summary>
	/// Initializes the component and sets the DataContext for data binding in XAML. Ensures navigation maintains the
	/// page's state.
	/// </summary>
	public ViewCurrentPolicies()
	{
		this.InitializeComponent();

		DataContext = ViewModel; // Set the DataContext for x:Bind references in the header in XAML

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;

		_instance = this;

		DeployedPoliciesListView = DeployedPolicies;
	}

	internal static ViewCurrentPolicies Instance => _instance ?? throw new InvalidOperationException("ViewCurrentPolicies is not initialized.");


#pragma warning disable CA1822

	/// <summary>
	/// Event handler to prevent the MenuFlyout to automatically close immediately after selecting a checkbox or any button in it
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void MenuFlyout_Closing(FlyoutBase sender, FlyoutBaseClosingEventArgs args)
	{
		if (sender is MenuFlyoutV2 { IsPointerOver: true })
		{
			args.Cancel = true;
		}
	}

#pragma warning restore CA1822

	#region Ensuring right-click on rows behaves better and normally on ListView

	// When right-clicking on an unselected row, first it becomes selected and then the context menu will be shown for the selected row
	// This is a much more expected behavior. Without this, the right-click would be meaningless on the ListView unless user left-clicks on the row first

	private void ListView_ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		// When the container is being recycled, detach the handler.
		if (args.InRecycleQueue)
		{
			args.ItemContainer.RightTapped -= ListViewItem_RightTapped;
		}
		else
		{
			// Detach first to avoid multiple subscriptions, then attach the handler.
			args.ItemContainer.RightTapped -= ListViewItem_RightTapped;
			args.ItemContainer.RightTapped += ListViewItem_RightTapped;
		}
	}


	private void ListViewItem_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		// Cast the sender to a ListViewItem.
		if (sender is ListViewItem item)
		{
			// If the item isn't already selected, clear existing selections
			// and mark this item as selected.
			if (!item.IsSelected)
			{
				// Set the counter so that the SelectionChanged event handler will ignore the next 2 events.
				ViewModel._skipSelectionChangedCount = 2;

				item.IsSelected = true;
			}
		}
	}

	#endregion

}
