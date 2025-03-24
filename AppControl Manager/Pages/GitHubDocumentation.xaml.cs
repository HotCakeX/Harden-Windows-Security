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
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Initializes the GitHubDocumentation component, sets the WebView2 background color, and manages navigation events.
/// Maintains page state.
/// </summary>
public sealed partial class GitHubDocumentation : Page
{
	/// <summary>
	/// Initializes the GitHubDocumentation component, sets the background color of the WebView2, and manages navigation
	/// events. Maintains page state during navigation.
	/// </summary>
	public GitHubDocumentation()
	{
		this.InitializeComponent();

		// Background color of the WebView2 while content is loading
		GitHubDocumentationWebView2.DefaultBackgroundColor = Colors.Transparent;

		// Handle navigation events to manage button state
		GitHubDocumentationWebView2.NavigationCompleted += WebView2_NavigationCompleted;

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Enabled;
	}

	/// <summary>
	/// Event handler for Back button
	/// </summary>
	private void BackButton_Click()
	{
		if (GitHubDocumentationWebView2.CanGoBack)
		{
			GitHubDocumentationWebView2.GoBack();
		}
	}

	/// <summary>
	/// Event handler for Forward button
	/// </summary>
	private void ForwardButton_Click()
	{
		if (GitHubDocumentationWebView2.CanGoForward)
		{
			GitHubDocumentationWebView2.GoForward();
		}
	}

	/// <summary>
	/// Event handler for Reload button
	/// </summary>
	private void ReloadButton_Click()
	{
		GitHubDocumentationWebView2.Reload();
	}

	/// <summary>
	/// Event handler for Home button
	/// </summary>
	private void HomeButton_Click()
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
