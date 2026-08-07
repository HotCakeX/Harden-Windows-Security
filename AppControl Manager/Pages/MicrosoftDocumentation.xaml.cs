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

namespace AppControlManager.Pages;

internal sealed partial class MicrosoftDocumentation : Page
{
	internal MicrosoftDocumentation()
	{
		InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		NavigationCacheMode = NavigationCacheMode.Enabled;

		_ = WebView2Config.ConfigureWebView2(MicrosoftDocumentationWebView2, URLToUse);
	}

	// Event handler for Back button
	private void BackButton_Click()
	{
		if (MicrosoftDocumentationWebView2.CanGoBack)
			MicrosoftDocumentationWebView2.GoBack();
	}

	// Event handler for Forward button
	private void ForwardButton_Click()
	{
		if (MicrosoftDocumentationWebView2.CanGoForward)
			MicrosoftDocumentationWebView2.GoForward();
	}

	private static readonly Uri URLToUse = new("https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/appcontrol");

	// Event handler for Reload button
	private void ReloadButton_Click() => MicrosoftDocumentationWebView2.Reload();

	// Event handler for Home button
	private void HomeButton_Click() => MicrosoftDocumentationWebView2.Source = URLToUse;
}
