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
using AppControlManager.Others;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Represents a page for Microsoft documentation with navigation controls. It manages WebView2 state and handles back,
/// forward, reload, and home actions.
/// </summary>
internal sealed partial class MicrosoftDocumentation : Page
{

	private AppSettings.Main AppSettings { get; } = ViewModels.ViewModelProvider.AppSettings;

	/// <summary>
	/// Initializes the MicrosoftDocumentation component, sets the background color of WebView2 to transparent, and handles
	/// navigation events.
	/// </summary>
	internal MicrosoftDocumentation()
	{
		this.InitializeComponent();
		// Set background color of WebView2 while content is loading
		MicrosoftDocumentationWebView2.DefaultBackgroundColor = Colors.Transparent;

		// Handle navigation events to manage button state
		MicrosoftDocumentationWebView2.NavigationCompleted += WebView2_NavigationCompleted;

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Enabled;
	}

	// Event handler for Back button
	private void BackButton_Click(object sender, RoutedEventArgs e)
	{
		if (MicrosoftDocumentationWebView2.CanGoBack)
		{
			MicrosoftDocumentationWebView2.GoBack();
		}
	}

	// Event handler for Forward button
	private void ForwardButton_Click(object sender, RoutedEventArgs e)
	{
		if (MicrosoftDocumentationWebView2.CanGoForward)
		{
			MicrosoftDocumentationWebView2.GoForward();
		}
	}

	// Event handler for Reload button
	private void ReloadButton_Click(object sender, RoutedEventArgs e)
	{
		MicrosoftDocumentationWebView2.Reload();
	}

	// Event handler for Home button
	private void HomeButton_Click(object sender, RoutedEventArgs e)
	{
		MicrosoftDocumentationWebView2.Source = new Uri("https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/appcontrol");
	}

	// Update the state of navigation buttons when navigation is completed so that the Back/Forward buttons will be enabled only when they can be used
	private void WebView2_NavigationCompleted(object sender, Microsoft.Web.WebView2.Core.CoreWebView2NavigationCompletedEventArgs e)
	{
		// The following checks are required to prevent any errors when intentionally spam navigating between pages and elements extremely fast
		try
		{
			// Check if the WebView2 control or its CoreWebView2 instance is disposed
			if (MicrosoftDocumentationWebView2 is { CoreWebView2: not null })
			{
				BackButton.IsEnabled = MicrosoftDocumentationWebView2.CanGoBack;
				ForwardButton.IsEnabled = MicrosoftDocumentationWebView2.CanGoForward;
			}
		}

		catch (ObjectDisposedException ex)
		{
			// Log the exception, but avoid crashing the app
			Logger.Write("WebView2 in Microsoft Documentation page has been disposed: " + ex.Message);
		}
	}
}
