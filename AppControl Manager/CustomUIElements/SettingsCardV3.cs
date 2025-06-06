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

using System.Linq;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// A SettingsCard that:
///  - On RightTapped or Holding (on the card), shows its inner Button.Flyout at the card.
///  - On RightTapped (on the Button), shows its Flyout at the button.
///  It has special use case, for when the setting card hosts a button used for browsing for files/folders.
/// </summary>
internal sealed partial class SettingsCardV3 : SettingsCardV2
{
	private Button? _innerButton;

	internal SettingsCardV3()
	{
		// Wait until Content is applied
		Loaded += OnLoaded;
	}

	private void OnLoaded(object? sender, RoutedEventArgs e)
	{
		// Since OnLoaded event fires every time we navigate to the page where this element is located or during theme change etc.
		// We need to immediately unsubscribe from it so we only hook the event handlers once.
		Loaded -= OnLoaded;

		// 1) Direct Content is a Button?
		if (Content is Button btn)
		{
			_innerButton = btn;
		}
		// 2) Or Content is a Panel containing a Button?
		else if (Content is Panel panel)
		{
			_innerButton = panel
				.Children
				.OfType<Button>()
				.FirstOrDefault();
		}

		if (_innerButton is null)
			return;   // no button → nothing to do

		// Hook card-level events
		RightTapped += Card_RightTapped;
		Holding += Card_Holding;

		// Hook button-level right-tap
		_innerButton.RightTapped += Button_RightTapped;
	}

	private void Button_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (_innerButton is null || !_innerButton.IsEnabled)
			return;

		FlyoutBase flyout = _innerButton.Flyout;
		if (flyout is not null && !flyout.IsOpen)
			flyout.ShowAt(_innerButton);

		e.Handled = true;
	}

	private void Card_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (_innerButton is null || !_innerButton.IsEnabled)
			return;

		FlyoutBase flyout = _innerButton.Flyout;
		if (flyout is not null && !flyout.IsOpen)
			flyout.ShowAt(this);

		e.Handled = true;
	}

	private void Card_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState != HoldingState.Started || _innerButton is null || !_innerButton.IsEnabled)
			return;

		FlyoutBase flyout = _innerButton.Flyout;
		if (flyout is not null && !flyout.IsOpen)
			flyout.ShowAt(this);

		e.Handled = true;
	}
}
