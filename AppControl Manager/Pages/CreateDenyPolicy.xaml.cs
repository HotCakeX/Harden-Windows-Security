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

using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// CreateDenyPolicy is a page for creating deny policies for files and folders.
/// </summary>
internal sealed partial class CreateDenyPolicy : Page
{
	private CreateDenyPolicyVM ViewModel { get; } = ViewModelProvider.CreateDenyPolicyVM;

	internal CreateDenyPolicy()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}

	// Since using behaviors in XAML is not Native AOT compatible, we use event handlers.
	private async void OnBorderPointerEntered(object sender, PointerRoutedEventArgs e)
	{
		await ShadowEnterAnimation.StartAsync((UIElement)sender);
	}
	private async void OnBorderPointerExited(object sender, PointerRoutedEventArgs e)
	{
		await ShadowExitAnimation.StartAsync((UIElement)sender);
	}
}
