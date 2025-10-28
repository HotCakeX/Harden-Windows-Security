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
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.Others;
using HardenSystemSecurity.Protect;
using Microsoft.UI.Xaml;

namespace HardenSystemSecurity.Helpers;

internal enum MUnitOperation : uint
{
	Apply = 0,
	Remove = 1,
	Verify = 2
}

/// <summary>
/// ViewModels that implement ListView that shows <see cref="MUnit"/> must use this interface.
/// If this doesn't inherit from <see cref="INotifyPropertyChanged"/>, then the MUnitListViewControl won't update bindings.
/// </summary>
internal interface IMUnitListViewModel : INotifyPropertyChanged
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
	/// Gets the current catalog of all MUnits for this ViewModel.
	/// Contract: the implementation should return the value of a single, shared Lazy<List<MUnit>>.
	/// The returned list instance should be treated as read-only by convention.
	/// </summary>
	List<MUnit> AllMUnits { get; }

	/// <summary>
	/// Static helper method to create UI values categories for ViewModels that implement IMUnitListViewModel. It is only run once in ViewModel's ctor.
	/// Used to create a collection of grouped items, create a query that groups an existing list, or returns a grouped collection from a database.
	/// The output will be used as the ItemsSource for our CollectionViewSource that is defined in XAML.
	/// </summary>
	/// <param name="viewModel">The ViewModel instance</param>
	static void CreateUIValuesCategories(IMUnitListViewModel viewModel)
	{
		_ = Task.Run(() =>
		{
			IEnumerable<GroupInfoListForMUnit> query = [];

			try
			{
				viewModel.ElementsAreEnabled = false;

				// Grab Protection Categories objects
				query = from item in viewModel.AllMUnits
							// Group the items returned from the query, sort and select the ones you want to keep
						group item by item.Name![..1].ToUpperInvariant() into g
						orderby g.Key
						// GroupInfoListForMUnit is a simple custom class that has an IEnumerable type attribute, and
						// a key attribute. The IGrouping-typed variable g now holds the App objects,
						// and these objects will be used to create a new GroupInfoListForMUnit object.
						select new GroupInfoListForMUnit(
							items: g,
							key: g.Key);

				_ = App.AppDispatcher.TryEnqueue(() =>
				{
					// Set backing field first so the control sees populated data when ItemsSource changes
					viewModel.ListViewItemsSourceBackingField = new(query);
					viewModel.ListViewItemsSource = new(query);

					// Update total items count
					int totalCount = 0;
					foreach (GroupInfoListForMUnit group in viewModel.ListViewItemsSourceBackingField)
					{
						totalCount += group.Count;
					}
					viewModel.TotalItemsCount = totalCount;
					viewModel.FilteredItemsCount = totalCount;
					viewModel.SelectedItemsCount = 0;

					// Compute initial status counts from AllMUnits.
					int undetermined = 0;
					int applied = 0;
					int notApplied = 0;

					foreach (MUnit m in viewModel.AllMUnits)
					{
						StatusState status = m.StatusState;
						switch (status)
						{
							case StatusState.Undetermined:
								undetermined++;
								break;
							case StatusState.Applied:
								applied++;
								break;
							case StatusState.NotApplied:
								notApplied++;
								break;
							default:
								break;
						}
					}

					viewModel.UndeterminedItemsCount = undetermined;
					viewModel.AppliedItemsCount = applied;
					viewModel.NotAppliedItemsCount = notApplied;
				});
			}
			catch (Exception ex)
			{
				viewModel.MainInfoBar.WriteError(ex);
			}
			finally
			{
				viewModel.ElementsAreEnabled = true;
			}
		});
	}

	/// <summary>
	/// Status Overview toggles status for filtering.
	/// </summary>
	bool ShowApplied { get; set; }
	bool ShowNotApplied { get; set; }
	bool ShowUndetermined { get; set; }
}
