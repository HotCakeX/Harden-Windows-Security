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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// CreateDenyPolicy is a page for creating deny policies for files and folders.
/// </summary>
internal sealed partial class CreateDenyPolicy : Page
{
	private CreateDenyPolicyVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<CreateDenyPolicyVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();

	internal CreateDenyPolicy()
	{
		this.InitializeComponent();
		this.NavigationCacheMode = NavigationCacheMode.Disabled;
		this.DataContext = ViewModel;
	}
}
