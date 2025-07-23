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

using HardenWindowsSecurity.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace HardenWindowsSecurity.Pages;

internal sealed partial class Protect : Page
{
	private ProtectVM ViewModel { get; } = ViewModelProvider.ProtectVM;

	internal Protect()
	{
		InitializeComponent();
		this.DataContext = ViewModel;
		NavigationCacheMode = NavigationCacheMode.Disabled;
		ViewModel.UIListView = ProtectionCategoriesListView; // Save a reference to the ListView in the ViewModel for direct access.
	}

	private async void OnBorderPointerEntered(object sender, PointerRoutedEventArgs e)
	{
		await ShadowEnterAnimation.StartAsync((UIElement)sender);
	}
	private async void OnBorderPointerExited(object sender, PointerRoutedEventArgs e)
	{
		await ShadowExitAnimation.StartAsync((UIElement)sender);
	}
}
