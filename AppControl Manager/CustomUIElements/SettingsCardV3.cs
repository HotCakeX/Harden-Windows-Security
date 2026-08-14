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
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using WinRT;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// A SettingsCard that delegates click, right-tap, and holding interactions to a hosted ButtonV2 or SplitButtonV3.
/// </summary>
internal sealed partial class SettingsCardV3 : SettingsCardV2
{
	private Control? _innerControl;

	internal SettingsCardV3() =>
		// Wait until Content is applied
		Loaded += OnLoaded;

	[DynamicWindowsRuntimeCast(typeof(Button))]
	[DynamicWindowsRuntimeCast(typeof(Control))]
	[DynamicWindowsRuntimeCast(typeof(Panel))]
	private void OnLoaded(object? sender, RoutedEventArgs e)
	{
		// Since the OnLoaded event fires every time we navigate to the page where this element is located or during theme change etc.
		// We need to immediately unsubscribe from it so we only hook the event handlers once.
		Loaded -= OnLoaded;

		// 1) Direct Content is a supported button?
		if (Content is Control { } control && control is Button or SplitButtonV3)
		{
			_innerControl = control;
		}
		// 2) Or Content is a Panel containing a supported button?
		else if (Content is Panel panel)
		{
			_innerControl = panel
				.Children
				.OfType<Control>()
				.FirstOrDefault(item => item is Button or SplitButtonV3);
		}

		if (_innerControl is null)
			return;   // no supported button -> nothing to do

		// Hook card-level events
		if (_innerControl is SplitButtonV3)
			Click += Card_Click;
		RightTapped += Card_RightTapped;
		Holding += Card_Holding;
	}

	private void Card_Click(object sender, RoutedEventArgs e)
	{
		if (_innerControl is SplitButtonV3 { IsEnabled: true } splitButtonV3)
			new SplitButtonAutomationPeer(splitButtonV3).Invoke();
	}

	private void Card_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (_innerControl is null || !_innerControl.IsEnabled)
			return;

		// Delegate to the hosted button's own logic.
		if (_innerControl is ButtonV2 buttonV2)
		{
			e.Handled = buttonV2.TryShowFlyout();
			return;
		}
		if (_innerControl is SplitButtonV3 splitButtonV3)
		{
			e.Handled = splitButtonV3.TryShowDetailsFlyout();
			return;
		}

		e.Handled = true;
	}

	private void Card_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState != HoldingState.Started || _innerControl is null || !_innerControl.IsEnabled)
			return;

		// Delegate to the hosted button's own logic.
		if (_innerControl is ButtonV2 buttonV2)
		{
			e.Handled = buttonV2.TryShowFlyout();
			return;
		}
		if (_innerControl is SplitButtonV3 splitButtonV3)
		{
			e.Handled = splitButtonV3.TryShowDetailsFlyout();
			return;
		}

		e.Handled = true;
	}
}
