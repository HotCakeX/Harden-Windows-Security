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

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using HardenWindowsSecurity.Helpers;
using HardenWindowsSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenWindowsSecurity.ViewModels;

internal sealed partial class UACVM : ViewModelBase, IMUnitListViewModel
{

	internal UACVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			null, null);
	}

	/// <summary>
	/// The main InfoBar for the Settings VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	public Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	public bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;


	internal static readonly string JSONConfigPath = Path.Combine(AppContext.BaseDirectory, "Resources", "WindowsUpdate.json");

	/// <summary>
	/// Items Source of the ListView.
	/// </summary>
	public ObservableCollection<GroupInfoListForMUnit> ListViewItemsSource { get; set => SP(ref field, value); } = [];

	/// <summary>
	/// Selected Items list in the ListView.
	/// </summary>
	internal List<MUnit> ItemsSourceSelectedItems = [];

	/// <summary>
	/// ListView reference of the UI.
	/// </summary>
	public ListViewBase? UIListView { get; set; }

	public void ApplyAllMUnits()
	{

	}

	public void RemoveAllMUnits()
	{

	}

	public void VerifyAllMUnits()
	{

	}

	public void ApplySelectedMUnits()
	{

	}

	public void RemoveSelectedMUnits()
	{

	}

	public void VerifySelectedMUnits()
	{

	}

	public void ListView_SelectAll(object sender, RoutedEventArgs e)
	{

	}

	public void ListView_RemoveSelections(object sender, RoutedEventArgs e)
	{

	}

	public void ListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{

	}
}
