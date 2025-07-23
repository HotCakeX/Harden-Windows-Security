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
using HardenWindowsSecurity.Helpers;
using HardenWindowsSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

internal sealed partial class MUnitListViewControl : UserControl
{
	internal MUnitListViewControl()
	{
		this.InitializeComponent();
	}

	// Dependency Properties
	internal static readonly DependencyProperty ListViewItemsSourceProperty =
		DependencyProperty.Register(
			nameof(ListViewItemsSource),
			typeof(ObservableCollection<GroupInfoListForMUnit>),
			typeof(MUnitListViewControl),
			new PropertyMetadata(new ObservableCollection<GroupInfoListForMUnit>()));

	internal static readonly DependencyProperty ProgressBarVisibilityProperty =
		DependencyProperty.Register(
			nameof(ProgressBarVisibility),
			typeof(Visibility),
			typeof(MUnitListViewControl),
			new PropertyMetadata(Visibility.Collapsed));

	internal static readonly DependencyProperty ElementsAreEnabledProperty =
		DependencyProperty.Register(
			nameof(ElementsAreEnabled),
			typeof(bool),
			typeof(MUnitListViewControl),
			new PropertyMetadata(true));

	internal static readonly DependencyProperty ViewModelProperty =
		DependencyProperty.Register(
			nameof(ViewModel),
			typeof(IMUnitListViewModel),
			typeof(MUnitListViewControl),
			new PropertyMetadata(null, OnViewModelChanged));

	// Properties
	public ObservableCollection<GroupInfoListForMUnit> ListViewItemsSource
	{
		get => (ObservableCollection<GroupInfoListForMUnit>)GetValue(ListViewItemsSourceProperty);
		set => SetValue(ListViewItemsSourceProperty, value);
	}

	public Visibility ProgressBarVisibility
	{
		get => (Visibility)GetValue(ProgressBarVisibilityProperty);
		set => SetValue(ProgressBarVisibilityProperty, value);
	}

	public bool ElementsAreEnabled
	{
		get => (bool)GetValue(ElementsAreEnabledProperty);
		set => SetValue(ElementsAreEnabledProperty, value);
	}

	public IMUnitListViewModel? ViewModel
	{
		get => (IMUnitListViewModel?)GetValue(ViewModelProperty);
		set => SetValue(ViewModelProperty, value);
	}

	private static void OnViewModelChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is MUnitListViewControl control && e.NewValue is IMUnitListViewModel viewModel)
		{
			// Set the ListView reference in the ViewModel
			viewModel.UIListView = control.MainListView;
		}
	}

	// Event Handlers
	private void ApplyAllButton_Click(object sender, RoutedEventArgs e)
	{
		ViewModel?.ApplyAllMUnits();
	}

	private void RemoveAllButton_Click(object sender, RoutedEventArgs e)
	{
		ViewModel?.RemoveAllMUnits();
	}

	private void VerifyAllButton_Click(object sender, RoutedEventArgs e)
	{
		ViewModel?.VerifyAllMUnits();
	}

	private void SelectAllMenuFlyoutItem_Click(object sender, RoutedEventArgs e)
	{
		ViewModel?.ListView_SelectAll(sender, e);
	}

	private void RemoveSelectionsMenuFlyoutItem_Click(object sender, RoutedEventArgs e)
	{
		ViewModel?.ListView_RemoveSelections(sender, e);
	}

	private void ApplySelectedMenuFlyoutItem_Click(object sender, RoutedEventArgs e)
	{
		ViewModel?.ApplySelectedMUnits();
	}

	private void VerifySelectedMenuFlyoutItem_Click(object sender, RoutedEventArgs e)
	{
		ViewModel?.VerifySelectedMUnits();
	}

	private void RemoveSelectedMenuFlyoutItem_Click(object sender, RoutedEventArgs e)
	{
		ViewModel?.RemoveSelectedMUnits();
	}

	private void MainListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		ViewModel?.ListView_SelectionChanged(sender, e);
	}
}
