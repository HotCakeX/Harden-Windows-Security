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

using Microsoft.UI.Input;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// This button displays its inner Flyout when it's RightTapped (e.g., Right-clicked) or Holding on it with touch.
/// </summary>
internal sealed partial class ButtonV2 : Button
{
	internal ButtonV2()
	{
		RightTapped += OnRightTapped_ShowFlyout;
		Holding += OnHolding_ShowFlyout;
	}

	private void OnRightTapped_ShowFlyout(object sender, RightTappedRoutedEventArgs e)
	{
		e.Handled = TryShowFlyout();
	}

	private void OnHolding_ShowFlyout(object sender, HoldingRoutedEventArgs e)
	{
		// Only show at the start of the hold
		if (e.HoldingState == HoldingState.Started)
		{
			e.Handled = TryShowFlyout();
		}
	}

	/// <summary>
	/// If a Flyout is attached to this Button and it isn't open, shows it.
	/// Returns true if there was a Flyout to show, false otherwise.
	/// </summary>
	private bool TryShowFlyout()
	{
		if (this.Flyout is Flyout flyout && !flyout.IsOpen)
		{
			flyout.ShowAt(this);
			return true;
		}

		return false;
	}
}
