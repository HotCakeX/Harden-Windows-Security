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
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.Others;
using HardenWindowsSecurity.Protect;
using Microsoft.UI.Xaml;

namespace HardenWindowsSecurity.Helpers;

internal enum MUnitOperation
{
	Apply,
	Remove,
	Verify
}

/// <summary>
/// ViewModels that implement ListView that shows <see cref="MUnit"/> must use this interface.
/// </summary>
internal interface IMUnitListViewModel
{
	/// <summary>
	/// Main collection bound to the ListView.
	/// </summary>
	ObservableCollection<GroupInfoListForMUnit> ListViewItemsSource { get; set; }

	/// <summary>
	/// Backing field used for search.
	/// </summary>
	List<GroupInfoListForMUnit> ListViewItemsSourceBackingField { get; set; }

	/// <summary>
	/// Selected Items list in the User Control ListView.
	/// </summary>
	List<MUnit> ItemsSourceSelectedItems { get; }

	/// <summary>
	/// Visibility of the ProgressBar in the user control.
	/// </summary>
	Visibility ProgressBarVisibility { get; }

	/// <summary>
	/// Whether the elements in the User Control are enabled or disabled.
	/// </summary>
	bool ElementsAreEnabled { get; set; }

	/// <summary>
	/// Gets the settings for the main information bar.
	/// </summary>
	InfoBarSettings MainInfoBar { get; }

	/// <summary>
	/// The search keyword that persists across navigation.
	/// </summary>
	string? SearchKeyword { get; set; }

	/// <summary>
	/// Initialization details for the Apply All button
	/// </summary>
	AnimatedCancellableButtonInitializer ApplyAllCancellableButton { get; }

	/// <summary>
	/// Initialization details for the Remove All button
	/// </summary>
	AnimatedCancellableButtonInitializer RemoveAllCancellableButton { get; }

	/// <summary>
	/// Initialization details for the Verify All button
	/// </summary>
	AnimatedCancellableButtonInitializer VerifyAllCancellableButton { get; }

	/// <summary>
	/// Total number of items loaded (all MUnits)
	/// </summary>
	int TotalItemsCount { get; set; }

	/// <summary>
	/// Number of items currently displayed after filtering
	/// </summary>
	int FilteredItemsCount { get; set; }

	/// <summary>
	/// Number of currently selected items
	/// </summary>
	int SelectedItemsCount { get; set; }

	/// <summary>
	/// Number of items with Undetermined status (N/A state)
	/// </summary>
	int UndeterminedItemsCount { get; set; }

	/// <summary>
	/// Number of items with Applied status
	/// </summary>
	int AppliedItemsCount { get; set; }

	/// <summary>
	/// Number of items with NotApplied status
	/// </summary>
	int NotAppliedItemsCount { get; set; }

	/// <summary>
	/// Creates all MUnits for this specific ViewModel.
	/// Each ViewModel implements this to provide its specific MUnit creation logic.
	/// </summary>
	/// <returns>List of all MUnits for this ViewModel</returns>
	List<MUnit> CreateAllMUnits();

	/// <summary>
	/// Static helper method to create UI values categories for ViewModels that implement IMUnitListViewModel.
	/// Used to create a collection of grouped items, create a query that groups an existing list, or returns a grouped collection from a database.
	/// The output will be used as the ItemsSource for our CollectionViewSource that is defined in XAML.
	/// </summary>
	/// <param name="viewModel">The ViewModel instance</param>
	static void CreateUIValuesCategories(IMUnitListViewModel viewModel)
	{
		_ = Task.Run(() =>
		{
			List<MUnit> allResults = [];
			IEnumerable<GroupInfoListForMUnit> query = [];

			try
			{
				_ = App.AppDispatcher.TryEnqueue(() =>
				{
					viewModel.ElementsAreEnabled = false;
				});

				// Call the ViewModel-specific method to create MUnits
				allResults = viewModel.CreateAllMUnits();

				// Grab Protection Categories objects
				query = from item in allResults
							// Group the items returned from the query, sort and select the ones you want to keep
						group item by item.Name![..1].ToUpper() into g
						orderby g.Key
						// GroupInfoListForMUnit is a simple custom class that has an IEnumerable type attribute, and
						// a key attribute. The IGrouping-typed variable g now holds the App objects,
						// and these objects will be used to create a new GroupInfoListForMUnit object.
						select new GroupInfoListForMUnit(
							items: g,
							key: g.Key);

				_ = App.AppDispatcher.TryEnqueue(() =>
				{
					viewModel.ListViewItemsSource = new(query);
					viewModel.ListViewItemsSourceBackingField = new(query);

					// Update total items count
					int totalCount = 0;
					foreach (GroupInfoListForMUnit group in viewModel.ListViewItemsSourceBackingField)
					{
						totalCount += group.Count;
					}
					viewModel.TotalItemsCount = totalCount;
					viewModel.FilteredItemsCount = totalCount;
					viewModel.SelectedItemsCount = 0;

					// Initialize status counts to 0 - they will be updated when status changes occur
					viewModel.UndeterminedItemsCount = 0;
					viewModel.AppliedItemsCount = 0;
					viewModel.NotAppliedItemsCount = 0;
				});
			}
			catch (Exception ex)
			{
				_ = App.AppDispatcher.TryEnqueue(() =>
				{
					viewModel.MainInfoBar.WriteError(ex);
				});
			}
			finally
			{
				_ = App.AppDispatcher.TryEnqueue(() =>
				{
					viewModel.ElementsAreEnabled = true;
				});
			}
		});
	}
}
