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

using AppControlManager.CustomUIElements;
using AppControlManager.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Represents a page for viewing current policies with data binding and navigation state management. It includes event
/// handlers for menu and list interactions.
/// </summary>
internal sealed partial class ViewCurrentPolicies : Page
{

#pragma warning disable CA1822
	private ViewCurrentPoliciesVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<ViewCurrentPoliciesVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
#pragma warning restore CA1822

	/// <summary>
	/// Initializes the component and sets the DataContext for data binding in XAML. Ensures navigation maintains the
	/// page's state.
	/// </summary>
	internal ViewCurrentPolicies()
	{
		this.InitializeComponent();

		DataContext = ViewModel; // Set the DataContext for x:Bind references in the header in XAML

		this.NavigationCacheMode = NavigationCacheMode.Disabled;
	}

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

}
