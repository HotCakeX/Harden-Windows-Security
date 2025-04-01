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
using AppControlManager.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

internal sealed partial class ViewOnlinePolicies : Page
{

#pragma warning disable CA1822
	private ViewOnlinePoliciesVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<ViewOnlinePoliciesVM>();
	private MicrosoftGraph.ViewModel ViewModelMSGraph { get; } = App.AppHost.Services.GetRequiredService<MicrosoftGraph.ViewModel>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
#pragma warning restore CA1822

	internal ListView ListViewElement { get; }

	// Singleton instance of the class
	private static ViewOnlinePolicies? _instance;

	internal ViewOnlinePolicies()
	{
		this.InitializeComponent();

		this.DataContext = this;

		this.NavigationCacheMode = NavigationCacheMode.Required;

		_instance = this;

		ListViewElement = DeployedPolicies;
	}


	internal static ViewOnlinePolicies Instance => _instance ?? throw new InvalidOperationException("ViewOnlinePolicies is not initialized.");


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
