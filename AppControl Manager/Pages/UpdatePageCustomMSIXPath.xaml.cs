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

using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Handles the selection and confirmation of a custom package file path for updates. Updates UI elements based on user
/// interactions.
/// </summary>
internal sealed partial class UpdatePageCustomMSIXPath : Page
{
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
	private ViewModels.UpdateVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<ViewModels.UpdateVM>();

	internal UpdatePageCustomMSIXPath()
	{
		this.InitializeComponent();
		this.NavigationCacheMode = NavigationCacheMode.Disabled;
		this.DataContext = this;
	}
}
