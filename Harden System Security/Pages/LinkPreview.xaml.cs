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

using System.ComponentModel;
using HardenSystemSecurity;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.System;

namespace AppControlManager.Pages;

internal sealed partial class LinkPreview : Page, INotifyPropertyChanged
{
	private HardenSystemSecurity.AppSettings.Main AppSettings => App.Settings;

	internal string PreviewUrl
	{
		get;
		set
		{
			if (field != value)
			{
				field = value;
				PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(PreviewUrl)));
			}
		}
	} = "https://bing.com";

	public event PropertyChangedEventHandler? PropertyChanged;

	internal LinkPreview()
	{
		this.InitializeComponent();
		this.NavigationCacheMode = NavigationCacheMode.Disabled;
	}

	// Event handler for Back button
	private void BackButton_Click()
	{
		if (LinkPreviewWebView2.CanGoBack)
		{
			LinkPreviewWebView2.GoBack();
		}
	}

	// Event handler for Forward button
	private void ForwardButton_Click()
	{
		if (LinkPreviewWebView2.CanGoForward)
		{
			LinkPreviewWebView2.GoForward();
		}
	}

	// Event handler for Reload button
	private void ReloadButton_Click()
	{
		LinkPreviewWebView2.Reload();
	}

	// Event handler for Home button
	private void HomeButton_Click()
	{
		LinkPreviewWebView2.Source = new Uri(PreviewUrl);
	}

	// Update the state of navigation buttons when navigation is completed so that the Back/Forward buttons will be enabled only when they can be used
	private void WebView2_NavigationCompleted(object sender, Microsoft.Web.WebView2.Core.CoreWebView2NavigationCompletedEventArgs e)
	{
		// The following checks are required to prevent any errors when intentionally spam navigating between pages and elements extremely fast
		try
		{
			// Check if the WebView2 control or its CoreWebView2 instance is disposed
			if (LinkPreviewWebView2 is { CoreWebView2: not null })
			{
				BackButton.IsEnabled = LinkPreviewWebView2.CanGoBack;
				ForwardButton.IsEnabled = LinkPreviewWebView2.CanGoForward;
			}
		}
		catch (ObjectDisposedException ex)
		{
			Logger.Write("WebView2 in Link Preview Page has been disposed: " + ex.Message);
		}
	}

	private async void OpenURL_Click()
	{
		try
		{
			_ = await Launcher.LaunchUriAsync(new Uri(PreviewUrl));
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}
}
