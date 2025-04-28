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
using CommunityToolkit.WinUI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// Extends SettingsCard to automatically invoke its single child element
/// (ToggleSwitch, ComboBox or Button) when the card itself is clicked.
/// No click happens on the internal element when the element is disabled.
/// </summary>
internal partial class SettingsCardV2 : SettingsCard
{
	internal SettingsCardV2()
	{
		// Hook the card click
		Click += OnSettingsCardClick;

		// Setting default properties
		IsClickEnabled = true;
		IsActionIconVisible = false;
	}

	private void OnSettingsCardClick(object sender, RoutedEventArgs e)
	{

		switch (Content)
		{
			case ToggleSwitch obj:
				if (!obj.IsEnabled) return;
				obj.IsOn = !obj.IsOn;
				break;

			case ComboBox obj:
				if (!obj.IsEnabled) return;
				obj.IsDropDownOpen = !obj.IsDropDownOpen;
				break;

			case Button obj:
				InvokeButton(obj);
				break;

			// If it's a Panel such as StackPanel or WrapPanel, etc. Then get the first applicable element.
			// The Panel class in WinUI is an abstract base class that all layout containers inherit from.
			// The is keyword will check the type or whether the object inherits from the type.
			case Panel panel:
				{
					// ToggleSwitch
					ToggleSwitch? childToggle = panel.Children.OfType<ToggleSwitch>().FirstOrDefault();
					if (childToggle != null && childToggle.IsEnabled)
					{
						childToggle.IsOn = !childToggle.IsOn;
						return;
					}

					// ComboBox
					ComboBox? childCombo = panel.Children.OfType<ComboBox>().FirstOrDefault();
					if (childCombo != null && childCombo.IsEnabled)
					{
						childCombo.IsDropDownOpen = !childCombo.IsDropDownOpen;
						return;
					}

					// Button
					Button? childButton = panel.Children.OfType<Button>().FirstOrDefault();
					if (childButton != null)
					{
						InvokeButton(childButton);
						return;
					}

					break;
				}

			default:
				break;
		}
	}

	private static void InvokeButton(Button button)
	{
		if (!button.IsEnabled) return;

		// Use the UI automation peer to raise its Click
		ButtonAutomationPeer peer = new(button);
		if (peer.GetPattern(PatternInterface.Invoke) is IInvokeProvider invoker)
			invoker.Invoke();
	}
}
