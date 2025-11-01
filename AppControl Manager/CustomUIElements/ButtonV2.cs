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

using CommunityToolkit.WinUI;
using CommunityToolkit.WinUI.Media;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.UI;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// This button displays its inner Flyout when it's RightTapped (e.g., Right-clicked) or Holding on it with touch.
/// When the bound ObservedData indicates "has content", it shows a green glow and changes its text to "Selected" (localized).
/// </summary>
internal sealed partial class ButtonV2 : Button
{
	// Keep original content so we can restore it when there is no selection
	private object? _originalContent;

	// Shadow used to indicate selection.
	private readonly AttachedCardShadow _selectedShadow = new()
	{
		Color = Color.FromArgb(255, 56, 239, 125),
		Offset = "0",
		BlurRadius = 20.0,
		Opacity = 0.95,
		CornerRadius = 4.0
	};

	// DP to observe either a string or a numeric count
	internal static readonly DependencyProperty ObservedDataProperty =
		DependencyProperty.Register(
			nameof(ObservedData),
			typeof(object),
			typeof(ButtonV2),
			new PropertyMetadata(null, OnObservedDataChanged));

	/// <summary>
	/// Bound to either a string (non-empty => selected) or a numeric count (int/long > 0 => selected).
	/// </summary>
	public object? ObservedData
	{
		get { return GetValue(ObservedDataProperty); }
		set { SetValue(ObservedDataProperty, value); }
	}

	private static void OnObservedDataChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) => ((ButtonV2)d).UpdateAppearance();

	internal ButtonV2()
	{
		RightTapped += OnRightTapped_ShowFlyout;
		Holding += OnHolding_ShowFlyout;
		// Ensure we (re)apply the correct visuals when the element is realized since pages don't have navigation cache.
		Loaded += OnLoaded_ApplyState;
		Unloaded += OnUnloaded_Cleanup;
	}

	private void OnLoaded_ApplyState(object sender, RoutedEventArgs e)
	{
		// Capture original content once so we can restore it later
		_originalContent ??= Content;
		UpdateAppearance();
	}

	private void OnRightTapped_ShowFlyout(object sender, RightTappedRoutedEventArgs e) => e.Handled = TryShowFlyout();

	private void OnHolding_ShowFlyout(object sender, HoldingRoutedEventArgs e)
	{
		// Only show at the start of the hold
		if (e.HoldingState == HoldingState.Started)
			e.Handled = TryShowFlyout();
	}

	/// <summary>
	/// If a Flyout is attached to this Button and it isn't open, shows it.
	/// Returns true if there was a Flyout to show, false otherwise.
	/// </summary>
	internal bool TryShowFlyout()
	{
		if (Flyout is Flyout flyout && !flyout.IsOpen)
		{
			flyout.ShowAt(this);
			return true;
		}
		return false;
	}

	// Removes the shadow entirely and frees composition resources
	// This is the correct way to clean up shadows instead of using: Effects.SetShadow(this, null);
	private void OnUnloaded_Cleanup(object sender, RoutedEventArgs e) => ClearValue(Effects.ShadowProperty);

	// Apply glow and text when ObservedData indicates "has content"
	private void UpdateAppearance()
	{
		_originalContent ??= Content;

		bool hasContent = ObservedData switch
		{
			string s => !string.IsNullOrEmpty(s),
			int i => i > 0,
			long l => l > 0,
			_ => false
		};

		if (hasContent)
		{
			Content = GlobalVars.GetStr("SelectedText"); // Change text to "Selected" (localized) when active; otherwise restore original content

			// Without this dispatcher, due to pages not having navigation page, sometimes the shadow will not be re-applied when we navigate away to another page and then navigate back
			_ = DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () =>
				{
					Effects.SetShadow(this, _selectedShadow);
				});
		}
		else if (_originalContent is not null)
		{
			Content = _originalContent;
			ClearValue(Effects.ShadowProperty);
		}
	}
}
