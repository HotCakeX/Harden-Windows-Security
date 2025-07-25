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

using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

#if APP_CONTROL_MANAGER
using AppControlManager.ViewModels;
namespace AppControlManager.Pages;
#endif
#if HARDEN_WINDOWS_SECURITY
using HardenWindowsSecurity.ViewModels;
namespace HardenWindowsSecurity.Pages;
#endif

internal sealed partial class Settings : Page
{

	private SettingsVM ViewModel { get; } = ViewModelProvider.SettingsVM;
	private MainWindowVM ViewModelMainWindow { get; } = ViewModelProvider.MainWindowVM;

	internal Settings()
	{
		this.InitializeComponent();
		this.DataContext = this;
		this.NavigationCacheMode = NavigationCacheMode.Disabled;
	}
}
