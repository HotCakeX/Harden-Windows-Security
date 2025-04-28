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
/// Initializes the CreatePolicy component, disabling log size inputs and maintaining navigation state.
/// of various policies.
/// </summary>
internal sealed partial class CreatePolicy : Page
{

#pragma warning disable CA1822
	private CreatePolicyVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<CreatePolicyVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
#pragma warning restore CA1822

	internal CreatePolicy()
	{
		this.InitializeComponent();
		this.DataContext = ViewModel;
		this.NavigationCacheMode = NavigationCacheMode.Disabled;
	}
}
