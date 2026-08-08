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

using System.Collections;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinRT;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// A UserControl wrapping a ListBox that adds a delete button to the right of each string item.
/// </summary>
internal sealed partial class ListBoxV2 : UserControl
{
	private static readonly DependencyProperty ItemsSourceProperty =
		DependencyProperty.Register(
			nameof(ItemsSource),
			typeof(IEnumerable),
			typeof(ListBoxV2),
			new PropertyMetadata(null));

	private static readonly DependencyProperty SelectionModeProperty =
		DependencyProperty.Register(
			nameof(SelectionMode),
			typeof(SelectionMode),
			typeof(ListBoxV2),
			new PropertyMetadata(SelectionMode.Single));

	public IEnumerable? ItemsSource
	{
		get => (IEnumerable?)GetValue(ItemsSourceProperty); set => SetValue(ItemsSourceProperty, value);
	}

	public SelectionMode SelectionMode
	{
		[DynamicWindowsRuntimeCast(typeof(SelectionMode))]
		get => (SelectionMode)GetValue(SelectionModeProperty); set => SetValue(SelectionModeProperty, value);
	}

	internal ListBoxV2() => InitializeComponent();

	/// <summary>
	/// Click handler for the delete button. Removes the item from the bound collection. Handles all collection types currently used by the app.
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(Button))]
	internal void DeleteItem_Click(object sender, RoutedEventArgs e)
	{
		// Handle UniqueStringObservableCollection
		if (((Button)sender).Tag is string stringToRemove && ItemsSource is UniqueStringObservableCollection uniqueCollection)
		{
			_ = uniqueCollection.Remove(stringToRemove);
		}
	}
}
