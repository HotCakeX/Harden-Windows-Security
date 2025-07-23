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
using HardenWindowsSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenWindowsSecurity.Helpers;

/// <summary>
/// ViewModels that implement ListView that shows <see cref="MUnit"/> must use this interface.
/// </summary>
internal interface IMUnitListViewModel
{
	ObservableCollection<GroupInfoListForMUnit> ListViewItemsSource { get; }
	Visibility ProgressBarVisibility { get; }
	bool ElementsAreEnabled { get; }
	ListViewBase? UIListView { get; set; }

	void ApplyAllMUnits();
	void RemoveAllMUnits();
	void VerifyAllMUnits();
	void ApplySelectedMUnits();
	void RemoveSelectedMUnits();
	void VerifySelectedMUnits();
	void ListView_SelectAll(object sender, RoutedEventArgs e);
	void ListView_RemoveSelections(object sender, RoutedEventArgs e);
	void ListView_SelectionChanged(object sender, SelectionChangedEventArgs e);
}
