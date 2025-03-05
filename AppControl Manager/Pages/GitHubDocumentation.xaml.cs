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

public sealed partial class GitHubDocumentation : Page
{
	public GitHubDocumentation()
	{
		this.InitializeComponent();

		// Background color of the WebView2 while content is loading
		GitHubDocumentationWebView2.DefaultBackgroundColor = Colors.Black;

		// Handle navigation events to manage button state
		GitHubDocumentationWebView2.NavigationCompleted += WebView2_NavigationCompleted;

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Enabled;
	}

	// Event handler for Back button
	private void BackButton_Click(object sender, RoutedEventArgs e)
	{
		if (GitHubDocumentationWebView2.CanGoBack)
		{
			GitHubDocumentationWebView2.GoBack();
		}
	}

	// Event handler for Forward button
	private void ForwardButton_Click(object sender, RoutedEventArgs e)
	{
		if (GitHubDocumentationWebView2.CanGoForward)
		{
			GitHubDocumentationWebView2.GoForward();
		}
	}

	// Event handler for Reload button
	private void ReloadButton_Click(object sender, RoutedEventArgs e)
	{
		GitHubDocumentationWebView2.Reload();
	}

	// Event handler for Home button
	private void HomeButton_Click(object sender, RoutedEventArgs e)
	{
		GitHubDocumentationWebView2.Source = new Uri("https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction");
	}

	// Update the state of navigation buttons when navigation is completed so that the Back/Forward buttons will be enabled only when they can be used
	private void WebView2_NavigationCompleted(object sender, Microsoft.Web.WebView2.Core.CoreWebView2NavigationCompletedEventArgs e)
	{

		// The following checks are required to prevent any errors when intentionally spam navigating between pages and elements extremely fast
		try
		{

			// Check if the WebView2 control or its CoreWebView2 instance is disposed
			if (GitHubDocumentationWebView2 is { CoreWebView2: not null })
			{
				BackButton.IsEnabled = GitHubDocumentationWebView2.CanGoBack;
				ForwardButton.IsEnabled = GitHubDocumentationWebView2.CanGoForward;
			}
		}
		catch (ObjectDisposedException ex)
		{
			// Log the exception, but avoid crashing the app
			Logger.Write("WebView2 in GitHub Documentation Page has been disposed: " + ex.Message);
		}
	}
}
