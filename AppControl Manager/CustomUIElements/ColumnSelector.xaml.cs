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

using System.Collections.ObjectModel;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

internal sealed partial class ColumnSelector : UserControl
{
	internal ColumnSelector() => InitializeComponent();

	/// <summary>
	/// Dependency Property to bind the ViewModel's ColumnSelectionItems to this control.
	/// </summary>
	public static readonly DependencyProperty ItemsSourceProperty =
		DependencyProperty.Register(
			nameof(ItemsSource),
			typeof(ObservableCollection<ColumnSelectionItem>),
			typeof(ColumnSelector),
			new PropertyMetadata(null));

	public ObservableCollection<ColumnSelectionItem> ItemsSource
	{
		get => (ObservableCollection<ColumnSelectionItem>)GetValue(ItemsSourceProperty);
		set => SetValue(ItemsSourceProperty, value);
	}

	private void SelectAll_Click(object sender, RoutedEventArgs e)
	{
		if (ItemsSource is null) return;

		foreach (var item in ItemsSource)
		{
			item.IsChecked = true;
		}
	}

	private void DeselectAll_Click(object sender, RoutedEventArgs e)
	{
		if (ItemsSource is null) return;

		foreach (var item in ItemsSource)
		{
			item.IsChecked = false;
		}
	}
}
