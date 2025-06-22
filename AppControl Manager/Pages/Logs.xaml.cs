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
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// The Logs class manages log files, allowing users to view and filter log content. It initializes with navigation
/// cache disabled.
/// </summary>
internal sealed partial class Logs : Page
{
	private LogsVM ViewModel { get; } = ViewModelProvider.LogsVM;

	internal Logs()
	{
		this.InitializeComponent();
		this.NavigationCacheMode = NavigationCacheMode.Disabled;
		this.DataContext = ViewModel;
	}

	/// <summary>
	/// Called when the page is navigated to.
	/// </summary>
	/// <param name="e">The navigation event data.</param>
	protected override void OnNavigatedTo(NavigationEventArgs e)
	{
		base.OnNavigatedTo(e);

		// Trigger log files loading and auto-selection when navigating to the page
		ViewModel.LoadLogFiles();
	}

	/// <summary>
	/// Called when the page is navigated from.
	/// </summary>
	/// <param name="e">The navigation event data.</param>
	protected async override void OnNavigatedFrom(NavigationEventArgs e)
	{
		base.OnNavigatedFrom(e);

		// Clean up current session but keep ViewModel alive for DI container
		await ViewModel.CleanupCurrentSession();
	}
}

/// <summary>
/// Represents one log line.
/// </summary>
internal sealed class LogLine(string text)
{
	internal string Text => text;
}
