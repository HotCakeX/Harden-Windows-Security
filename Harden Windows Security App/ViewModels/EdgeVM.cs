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
using System.Collections.ObjectModel;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using HardenWindowsSecurity.Helpers;
using HardenWindowsSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenWindowsSecurity.ViewModels;

internal sealed partial class EdgeVM : ViewModelBase, IMUnitListViewModel
{

	internal EdgeVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			null, null);

		// Initializing the cancellable buttons
		ApplyAllCancellableButton = new(GlobalVars.GetStr("ApplyAllButtonText/Text"));
		RemoveAllCancellableButton = new(GlobalVars.GetStr("RemoveAllButtonText/Text"));
		VerifyAllCancellableButton = new(GlobalVars.GetStr("VerifyAllButtonText"));

		IMUnitListViewModel.CreateUIValuesCategories(this);
	}

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	public InfoBarSettings MainInfoBar { get; }

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

	/// <summary>
	/// Items Source of the ListView.
	/// </summary>
	public ObservableCollection<GroupInfoListForMUnit> ListViewItemsSource { get; set => SP(ref field, value); } = [];

	public List<GroupInfoListForMUnit> ListViewItemsSourceBackingField { get; set; } = [];

	/// <summary>
	/// Selected Items list in the ListView.
	/// </summary>
	public List<MUnit> ItemsSourceSelectedItems { get; set; } = [];

	/// <summary>
	/// Search keyword for ListView.
	/// </summary>
	public string? SearchKeyword { get; set; }

	/// <summary>
	/// Initialization details for the Apply All button
	/// </summary>
	public AnimatedCancellableButtonInitializer ApplyAllCancellableButton { get; }

	/// <summary>
	/// Initialization details for the Remove All button
	/// </summary>
	public AnimatedCancellableButtonInitializer RemoveAllCancellableButton { get; }

	/// <summary>
	/// Initialization details for the Verify All button
	/// </summary>
	public AnimatedCancellableButtonInitializer VerifyAllCancellableButton { get; }

	/// <summary>
	/// Total number of items loaded (all MUnits)
	/// </summary>
	public int TotalItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items currently displayed after filtering
	/// </summary>
	public int FilteredItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of currently selected items
	/// </summary>
	public int SelectedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items with Undetermined status (N/A state)
	/// </summary>
	public int UndeterminedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items with Applied status
	/// </summary>
	public int AppliedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items with NotApplied status
	/// </summary>
	public int NotAppliedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Creates all MUnits for this ViewModel.
	/// </summary>
	/// <returns>List of all MUnits for this ViewModel</returns>
	public List<MUnit> CreateAllMUnits()
	{
		return MUnit.CreateMUnitsFromPolicies(Categories.EdgeBrowserConfigurations);
	}

}
