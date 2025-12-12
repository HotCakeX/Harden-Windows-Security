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
using System.Collections.ObjectModel;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// A UserControl wrapping a ListBox that adds a delete button to the right of each string item.
/// Works with UniqueStringObservableCollection, ObservableCollection<string>, or any IList containing strings.
/// </summary>
internal sealed partial class ListBoxV2 : UserControl
{
	public static readonly DependencyProperty ItemsSourceProperty =
		DependencyProperty.Register(
			nameof(ItemsSource),
			typeof(IEnumerable),
			typeof(ListBoxV2),
			new PropertyMetadata(null));

	public static readonly DependencyProperty SelectionModeProperty =
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
		get => (SelectionMode)GetValue(SelectionModeProperty); set => SetValue(SelectionModeProperty, value);
	}

	internal ListBoxV2() => InitializeComponent();

	/// <summary>
	/// Click handler for the delete button. Removes the item from the bound collection.
	/// </summary>
	internal void DeleteItem_Click(object sender, RoutedEventArgs e)
	{
		string? path = ((Button)sender).Tag as string;
		if (string.IsNullOrEmpty(path))
			return;

		// Fast path for UniqueStringObservableCollection
		UniqueStringObservableCollection? uniqueCollection = ItemsSource as UniqueStringObservableCollection;
		if (uniqueCollection is not null)
		{
			_ = uniqueCollection.Remove(path);
			return;
		}

		// ObservableCollection<string>
		ObservableCollection<string>? observableStrings = ItemsSource as ObservableCollection<string>;
		if (observableStrings is not null)
		{
			RemoveFromObservable(observableStrings, path);
			return;
		}

		// IList (generic fallback)
		if (ItemsSource is not IList list)
			return;

		RemoveFromIList(list, path);
	}

	/// <summary>
	/// Removes a string from an ObservableCollection<string>.
	/// </summary>
	private static void RemoveFromObservable(ObservableCollection<string> collection, string target)
	{
		for (int i = 0; i < collection.Count; i++)
		{
			string current = collection[i];
			if (string.Equals(current, target, StringComparison.OrdinalIgnoreCase))
			{
				collection.RemoveAt(i);
				break;
			}
		}
	}

	/// <summary>
	/// Removes a matching string from an IList.
	/// </summary>
	private static void RemoveFromIList(IList list, string target)
	{
		for (int i = 0; i < list.Count; i++)
		{
			object? entry = list[i];
			string? value = entry as string;
			if (value is not null && string.Equals(value, target, StringComparison.OrdinalIgnoreCase))
			{
				list.Remove(entry);
				break;
			}
		}
	}
}
