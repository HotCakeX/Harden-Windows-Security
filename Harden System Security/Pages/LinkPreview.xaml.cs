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

using System.Threading.Tasks;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.System;

namespace AppControlManager.Pages;

internal sealed partial class LinkPreview : Page
{
	private CommonCore.AppSettings.Main AppSettings => GlobalVars.Settings;

	internal string PreviewUrl
	{
		get; set
		{
			if (!string.Equals(field, value, StringComparison.OrdinalIgnoreCase))
			{
				field = value;
				_ = GlobalVars.AppDispatcher.TryEnqueue(() => { LinkPreviewWebView2.Source = new(value); });
			}
		}
	} = "https://bing.com";

	internal LinkPreview()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;

		// Initialize WebView2 and then re-apply the current PreviewUrl so it always wins over the initializer's source
		_ = InitializeWebView2Async();
	}

	private async Task InitializeWebView2Async()
	{
		await WebView2Config.ConfigureWebView2(LinkPreviewWebView2, new(PreviewUrl));

		// Re-apply the current PreviewUrl after initialization to ensure it is the final navigation target
		LinkPreviewWebView2.Source = new(PreviewUrl);
	}

	// Event handler for Back button
	private void BackButton_Click()
	{
		if (LinkPreviewWebView2.CanGoBack)
			LinkPreviewWebView2.GoBack();
	}

	// Event handler for Forward button
	private void ForwardButton_Click()
	{
		if (LinkPreviewWebView2.CanGoForward)
			LinkPreviewWebView2.GoForward();
	}

	// Event handler for Reload button
	private void ReloadButton_Click() => LinkPreviewWebView2.Reload();

	// Event handler for Home button
	private void HomeButton_Click() => LinkPreviewWebView2.Source = new(PreviewUrl);

	private async void OpenURL_Click()
	{
		try
		{
			_ = await Launcher.LaunchUriAsync(LinkPreviewWebView2.Source);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}
}
