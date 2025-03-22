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
using System.Linq;
using AppControlManager.IntelGathering;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Represents a page for creating supplemental policy files and folders scan results, managing data display and user
/// interactions.
/// </summary>
public sealed partial class CreateSupplementalPolicyFilesAndFoldersScanResults : Page
{

#pragma warning disable CA1822
	internal CreateSupplementalPolicyVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<CreateSupplementalPolicyVM>();
#pragma warning restore CA1822

	/// <summary>
	/// Constructor for the CreateSupplementalPolicyFilesAndFoldersScanResults class. Initializes components, maintains
	/// navigation state, and sets the DataContext.
	/// </summary>
	public CreateSupplementalPolicyFilesAndFoldersScanResults()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Enabled;

		this.DataContext = ViewModel;
	}



	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	/// <param name="sender">The event sender.</param>
	/// <param name="e">The event arguments.</param>
	private void ListViewFlyoutMenuCopy_Click(object sender, RoutedEventArgs e)
	{
		// Check if there are selected items in the ListView
		if (FileIdentitiesListView.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText(FileIdentitiesListView.SelectedItems);
		}
	}

	/// <summary>
	/// Click event handler for copy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void CopyToClipboard_Click(object sender, RoutedEventArgs e)
	{
		// Attempt to retrieve the property mapping using the Tag as the key.
		if (ListViewHelper.PropertyMappings.TryGetValue((string)((MenuFlyoutItem)sender).Tag, out (string Label, Func<FileIdentity, object?> Getter) mapping))
		{
			// Use the mapping's Getter, converting the result to a string.
			ListViewHelper.CopyToClipboard(item => mapping.Getter(item)?.ToString(), FileIdentitiesListView);
		}
	}

	// Event handler for all sort buttons
	private void ColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		_ = ListViewHelper.PropertyMappings.TryGetValue((string)((MenuFlyoutItem)sender).Tag, out (string Label, Func<FileIdentity, object?> Getter) mapping);

		Func<FileIdentity, object?> selector = mapping.Getter;
		ListViewHelper.SortColumn(selector, SearchBox, SortingDirectionToggle, ViewModel.filesAndFoldersScanResultsList, ViewModel.FilesAndFoldersScanResults);
	}


	/// <summary>
	/// Event handler for the SearchBox text change
	/// </summary>
	private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		ApplyFilters();
	}

	/// <summary>
	/// Applies the date and search filters to the data grid
	/// </summary>
	private void ApplyFilters()
	{
		ListViewHelper.ApplyFilters(
			allFileIdentities: ViewModel.filesAndFoldersScanResultsList.AsEnumerable(),
			filteredCollection: ViewModel.FilesAndFoldersScanResults,
			searchTextBox: SearchBox,
			datePicker: null
		);
		ViewModel.UpdateTotalFilesFilesAndFolders();
	}

	/// <summary>
	/// Event handler for the Clear Data button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void ClearDataButton_Click(object sender, RoutedEventArgs e)
	{
		ViewModel.FilesAndFoldersScanResults.Clear();
		ViewModel.filesAndFoldersScanResultsList.Clear();

		ViewModel.UpdateTotalFilesFilesAndFolders(true);
	}

	/// <summary>
	/// Selects all of the displayed rows on the ListView
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SelectAll_Click(object sender, RoutedEventArgs e)
	{
		ListViewHelper.SelectAll(FileIdentitiesListView, ViewModel.FilesAndFoldersScanResults);
	}

	/// <summary>
	/// De-selects all of the displayed rows on the ListView
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void DeSelectAll_Click(object sender, RoutedEventArgs e)
	{
		FileIdentitiesListView.SelectedItems.Clear(); // Deselect all rows by clearing SelectedItems
	}



	#region Ensuring right-click on rows behaves better and normally on ListView

	// When right-clicking on an unselected row, first it becomes selected and then the context menu will be shown for the selected row
	// This is a much more expected behavior. Without this, the right-click would be meaningless on the ListView unless user left-clicks on the row first

	private void ListView_ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		// When the container is being recycled, detach the handler.
		if (args.InRecycleQueue)
		{
			args.ItemContainer.RightTapped -= ListViewItem_RightTapped;
		}
		else
		{
			// Detach first to avoid multiple subscriptions, then attach the handler.
			args.ItemContainer.RightTapped -= ListViewItem_RightTapped;
			args.ItemContainer.RightTapped += ListViewItem_RightTapped;
		}
	}

	private void ListViewItem_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (sender is ListViewItem item)
		{
			// If the item is not already selected
			if (!item.IsSelected)
			{
				// Set the counter so that the SelectionChanged event handler will ignore the next 2 events.
				_skipSelectionChangedCount = 2;

				//clear for exclusive selection
				FileIdentitiesListView.SelectedItems.Clear();
				item.IsSelected = true;
			}
		}
	}

	#endregion


	/// <summary>
	/// CTRL + C shortcuts event handler
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void CtrlC_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		ListViewFlyoutMenuCopy_Click(sender, new RoutedEventArgs());
		args.Handled = true;
	}

	// A counter to prevent SelectionChanged event from firing twice when right-clicking on an unselected row
	private int _skipSelectionChangedCount;

	private async void FileIdentitiesListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Check if we need to skip this event.
		if (_skipSelectionChangedCount > 0)
		{
			_skipSelectionChangedCount--;
			return;
		}

		await ListViewHelper.SmoothScrollIntoViewWithIndexCenterVerticallyOnlyAsync(listViewBase: (ListView)sender, listView: (ListView)sender, index: ((ListView)sender).SelectedIndex, disableAnimation: false, scrollIfVisible: true, additionalHorizontalOffset: 0, additionalVerticalOffset: 0);
	}
}
