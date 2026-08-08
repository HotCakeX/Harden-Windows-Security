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
using AppControlManager.SiPolicy;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinRT;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// A UserControl wrapping a ListBox that adds a delete button to the right side of each item.
/// Uses a DataTemplateSelector to handle both Strings and <see cref="PolicyFileRepresent"/> object types.
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
		// Get the tag content from the button
		object? tagContent = ((Button)sender).Tag;

		// Handle PolicyFileRepresent removal
		if (tagContent is PolicyFileRepresent itemToRemove && ItemsSource is UniquePolicyFileRepresentObservableCollection collectionToRemoveFrom)
		{
			_ = collectionToRemoveFrom.Remove(itemToRemove);
		}

		// Handle string removal
		else if (tagContent is string stringToRemove && ItemsSource is UniqueStringObservableCollection uniqueCollection)
		{
			_ = uniqueCollection.Remove(stringToRemove);
		}
	}
}

/// <summary>
/// Selects the appropriate DataTemplate based on the item type.
/// </summary>
internal sealed partial class ListBoxItemTemplateSelector : DataTemplateSelector
{
	public DataTemplate? StringTemplate { get; set; }
	public DataTemplate? PolicyTemplate { get; set; }

	protected override DataTemplate? SelectTemplateCore(object item, DependencyObject container)
	{
		if (item is string)
		{
			return StringTemplate;
		}

		if (item is PolicyFileRepresent)
		{
			return PolicyTemplate;
		}

		return base.SelectTemplateCore(item, container);
	}
}
