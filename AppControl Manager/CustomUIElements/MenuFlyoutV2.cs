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

using System.Collections.Generic;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// A custom implementation of MenuFlyout that prevents the flyout from automatically closing
/// when a menu item is selected. This is achieved by tracking pointer interactions on the flyout items.
/// </summary>
internal sealed partial class MenuFlyoutV2 : MenuFlyout
{
	/// <summary>
	/// Initializes a new instance of the <see cref="MenuFlyoutV2"/> class.
	/// Subscribes to the Opened event to attach pointer event handlers to the menu items.
	/// </summary>
	internal MenuFlyoutV2()
	{
		// Attach the handler for the Opened event to initialize event listeners for pointer interactions on menu items
		Opened += MenuFlyoutV2_Opened;
		Closing += MenuFlyout_Closing;
	}

	/// <summary>
	/// Event handler to prevent the MenuFlyout to automatically close immediately after selecting a checkbox or any button in it
	/// </summary>
	internal void MenuFlyout_Closing(FlyoutBase sender, FlyoutBaseClosingEventArgs args)
	{
		if (sender is MenuFlyoutV2 { IsPointerOver: true })
		{
			args.Cancel = true;
		}
	}

	/// <summary>
	/// Property to track whether the user's pointer is currently over any menu item in the flyout.
	/// </summary>
	internal bool IsPointerOver { get; set; }

	/// <summary>
	/// Event handler for when the flyout is opened.
	/// Attaches PointerEntered and PointerExited event handlers to each item in the flyout.
	/// </summary>
	/// <param name="sender">The source of the event (the flyout itself).</param>
	/// <param name="e">The event data.</param>
	private void MenuFlyoutV2_Opened(object? sender, object e)
	{
		// Only run the initialization once so pointer tracking becomes inherent behavior
		// instead of being re-applied every time the flyout opens.
		Opened -= MenuFlyoutV2_Opened;

		AssignEventHandlers(Items);
	}

	private void AssignEventHandlers(IList<MenuFlyoutItemBase> items)
	{
		foreach (MenuFlyoutItemBase menuItem in items)
		{
			menuItem.PointerEntered += MenuItem_PointerEntered;
			menuItem.PointerExited += MenuItem_PointerExited;

			if (menuItem is MenuFlyoutSubItem menuFlyoutSubItem)
			{
				AssignEventHandlers(menuFlyoutSubItem.Items);
			}
		}
	}

	/// <summary>
	/// Event handler for when the pointer enters a menu item in the flyout.
	/// This sets the IsPointerOver property to true, indicating that the pointer is interacting with the menu and is inside the flyout.
	/// </summary>
	private void MenuItem_PointerEntered(object sender, PointerRoutedEventArgs e) => IsPointerOver = true;

	/// <summary>
	/// Event handler for when the pointer exits a menu item in the flyout.
	/// This sets the IsPointerOver property to false, indicating that the pointer is no longer interacting with the menu and has left the flyout.
	/// </summary>
	private void MenuItem_PointerExited(object sender, PointerRoutedEventArgs e) => IsPointerOver = false;
}
