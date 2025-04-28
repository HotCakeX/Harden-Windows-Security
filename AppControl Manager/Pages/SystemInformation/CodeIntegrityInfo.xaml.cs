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
/// Initializes the CodeIntegrityInfo class and sets the navigation cache mode. Retrieves and displays code integrity
/// information.
/// </summary>
internal sealed partial class CodeIntegrityInfo : Page
{
#pragma warning disable CA1822
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
	private ViewModels.CodeIntegrityInfoVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<ViewModels.CodeIntegrityInfoVM>();
#pragma warning restore CA1822

	/// <summary>
	/// Initializes a new instance of the CodeIntegrityInfo class.
	/// </summary>
	internal CodeIntegrityInfo()
	{
		this.InitializeComponent();
		this.NavigationCacheMode = NavigationCacheMode.Disabled;
		this.DataContext = ViewModel;
	}
}
