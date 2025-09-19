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
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.Web.WebView2.Core;

namespace AppControlManager.CustomUIElements.HomePageStageContents;

internal sealed partial class Item3 : UserControl
{
	// Whether we have expanded the video to inline "fullscreen" inside the page client area.
	private bool _isInlineFullscreen;

	// Original parent of the WebView2 to restore after exiting fullscreen.
	private Panel? _originalParentPanel;

	// Reference to the page-level overlay host (Home.xaml: Grid x:Name="ContentHost").
	private Grid? _overlayHost;

	// A transient overlay container we add into ContentHost when going fullscreen.
	private Grid? _overlayContainer;

	// Remember ContentHost's original margin so we can remove it during fullscreen and restore afterward.
	private Thickness _overlayOriginalMargin;

	// Save and restore ContentHost's z-order so the video renders above stage lights/projectors while fullscreen.
	private int _overlayHostOriginalZIndex;
	private bool _overlayHostZIndexSaved;

	// Injected reference to the page's ContentHost.
	internal Grid? OverlayHostGrid { get; set; }

	internal Item3()
	{
		InitializeComponent();
	}

	// Initialize CoreWebView2 once the control is loaded.
	private async void OnLoadedInitCore(object? sender, RoutedEventArgs e)
	{
		try
		{
			await PlayerView.EnsureCoreWebView2Async();
		}
		catch { }
	}

	// YouTube embed with fullscreen enabled (fs=1) and minimal UI.
	private static readonly Uri uri = new("https://www.youtube-nocookie.com/embed/SzMs13n7elE?rel=0&modestbranding=1&playsinline=1&autoplay=0&controls=1&fs=1");

	// After Core is ready, track HTML fullscreen state from the web content.
	private void OnCoreWebView2Initialized(WebView2 sender, CoreWebView2InitializedEventArgs args)
	{
		PlayerView.Source = uri;

		sender.CoreWebView2.ContainsFullScreenElementChanged += OnContainsFullScreenElementChanged;
	}

	// Toggle inline fullscreen when the web content enters/exits HTML fullscreen.
	private void OnContainsFullScreenElementChanged(CoreWebView2 sender, object args)
	{
		if (sender.ContainsFullScreenElement)
		{
			EnterInlineFullscreen();
		}
		else
		{
			ExitInlineFullscreen();
		}
	}

	/// <summary>
	/// Make the video fill the app's client area (inside the page), without switching the OS window to fullscreen.
	/// Requires OverlayHostGrid to be set by the parent page.
	/// </summary>
	private void EnterInlineFullscreen()
	{
		if (_isInlineFullscreen)
		{
			return;
		}

		// Use the injected host only.
		_overlayHost ??= OverlayHostGrid;
		if (_overlayHost is null)
		{
			// Parent page must set OverlayHostGrid before fullscreen can work.
			return;
		}

		// Lazily create a dedicated overlay container we can add/remove cleanly.
		if (_overlayContainer is null)
		{
			Grid container = new()
			{
				HorizontalAlignment = HorizontalAlignment.Stretch,
				VerticalAlignment = VerticalAlignment.Stretch,
				Background = new SolidColorBrush(Colors.Black)
			};
			_overlayContainer = container;
		}

		// Remove ContentHost's margin temporarily so the video fills the client area fully.
		_overlayOriginalMargin = _overlayHost.Margin;
		_overlayHost.Margin = new Thickness(0);

		// Save current z-order of ContentHost and then boost it so it renders above stage/projectors.
		if (!_overlayHostZIndexSaved)
		{
			_overlayHostOriginalZIndex = Canvas.GetZIndex(_overlayHost);
			_overlayHostZIndexSaved = true;
		}
		Canvas.SetZIndex(_overlayHost, 10000); // higher than StageCarouselViewport and HUDs

		// Add overlay container if not already present.
		if (!_overlayHost.Children.Contains(_overlayContainer))
		{
			_overlayHost.Children.Add(_overlayContainer);
		}

		// Capture original parent and move the player into the overlay container.
		_originalParentPanel ??= PlayerView.Parent as Panel;
		if (PlayerView.Parent is Panel parent && !ReferenceEquals(parent, _overlayContainer))
		{
			_ = parent.Children.Remove(PlayerView);
		}
		if (!_overlayContainer.Children.Contains(PlayerView))
		{
			_overlayContainer.Children.Add(PlayerView);
		}

		// Ensure the WebView2 stretches fully.
		PlayerView.HorizontalAlignment = HorizontalAlignment.Stretch;
		PlayerView.VerticalAlignment = VerticalAlignment.Stretch;

		_isInlineFullscreen = true;
	}

	/// <summary>
	/// Restore the player back to its original location and remove the overlay container.
	/// </summary>
	private void ExitInlineFullscreen()
	{
		if (!_isInlineFullscreen)
		{
			return;
		}

		// Move player back to original parent.
		if (_originalParentPanel is not null)
		{
			if (PlayerView.Parent is Panel parent && !ReferenceEquals(parent, _originalParentPanel))
			{
				_ = parent.Children.Remove(PlayerView);
			}
			if (!_originalParentPanel.Children.Contains(PlayerView))
			{
				_originalParentPanel.Children.Add(PlayerView);
			}
		}

		// Remove overlay container and restore ContentHost's margin and z-order.
		if (_overlayHost is not null)
		{
			if (_overlayContainer is not null && _overlayHost.Children.Contains(_overlayContainer))
			{
				_ = _overlayHost.Children.Remove(_overlayContainer);
			}

			// Restore original z-index if we had saved it.
			if (_overlayHostZIndexSaved)
			{
				Canvas.SetZIndex(_overlayHost, _overlayHostOriginalZIndex);
				_overlayHostZIndexSaved = false;
			}

			_overlayHost.Margin = _overlayOriginalMargin;
			_overlayHost.Background = null;
		}

		_isInlineFullscreen = false;
	}

	/// <summary>
	/// API for parent page to stop and destroy playback.
	/// </summary>
	internal void StopAndTearDown()
	{
		// Unhook fullscreen monitoring.
		try
		{
			if (PlayerView.CoreWebView2 is not null)
			{
				PlayerView.CoreWebView2.ContainsFullScreenElementChanged -= OnContainsFullScreenElementChanged;
			}
		}
		catch
		{ }

		// If currently in inline fullscreen, restore first.
		try
		{
			if (_isInlineFullscreen)
			{
				ExitInlineFullscreen();
			}
		}
		catch { }

		// mute, stop, and navigate away to tear down the media pipeline.
		try
		{
			if (PlayerView.CoreWebView2 is not null)
			{
				PlayerView.CoreWebView2.IsMuted = true;
				PlayerView.CoreWebView2.Stop();
				PlayerView.CoreWebView2.Navigate("about:blank");
			}
		}
		catch { }

		PlayerView.Source = null;
	}

	/// <summary>
	/// Ensure teardown on unload.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OnUserControlUnloaded(object? sender, RoutedEventArgs e) => StopAndTearDown();

}
