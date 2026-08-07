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
namespace AppControlManager.Pages;
#endif
#if HARDEN_SYSTEM_SECURITY
namespace HardenSystemSecurity.Pages;
#endif

internal sealed partial class GitHubDocumentation : Page
{
	internal GitHubDocumentation()
	{
		InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		NavigationCacheMode = NavigationCacheMode.Enabled;

		_ = WebView2Config.ConfigureWebView2(GitHubDocumentationWebView2, URLToUse);
	}

	/// <summary>
	/// Event handler for Back button
	/// </summary>
	private void BackButton_Click()
	{
		if (GitHubDocumentationWebView2.CanGoBack)
			GitHubDocumentationWebView2.GoBack();
	}

	/// <summary>
	/// Event handler for Forward button
	/// </summary>
	private void ForwardButton_Click()
	{
		if (GitHubDocumentationWebView2.CanGoForward)
			GitHubDocumentationWebView2.GoForward();
	}

	/// <summary>
	/// Event handler for Reload button
	/// </summary>
	private void ReloadButton_Click() => GitHubDocumentationWebView2.Reload();

#if APP_CONTROL_MANAGER
	private static readonly Uri URLToUse = new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction");
#endif
#if HARDEN_SYSTEM_SECURITY
	private static readonly Uri URLToUse = new("https://github.com/HotCakeX/Harden-Windows-Security");
#endif

	/// <summary>
	/// Event handler for Home button
	/// </summary>
	private void HomeButton_Click() => GitHubDocumentationWebView2.Source = URLToUse;
}
