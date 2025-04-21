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
/// Represents a page for creating deny policy scan results, managing navigation state and data context. Handles user
/// interactions like copying, filtering, and selecting items.
/// </summary>
internal sealed partial class CreateDenyPolicyFilesAndFoldersScanResults : Page
{

#pragma warning disable CA1822
	private CreateDenyPolicyVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<CreateDenyPolicyVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
#pragma warning restore CA1822

	/// <summary>
	/// Constructor for the CreateDenyPolicyFilesAndFoldersScanResults class. Initializes components, maintains navigation
	/// state, and sets the DataContext.
	/// </summary>
	internal CreateDenyPolicyFilesAndFoldersScanResults()
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


	private void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			if (ListViewHelper.PropertyMappings.TryGetValue(key, out (string Label, Func<FileIdentity, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					SearchBox,
					ViewModel.filesAndFoldersScanResultsList,
					ViewModel.FilesAndFoldersScanResults,
					ViewModel.SortStateFilesAndFolders,
					key,
					regKey: ListViewHelper.ListViewsRegistry.DenyPolicy_FilesAndFolders_ScanResults);
			}
		}
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
			datePicker: null,
			regKey: ListViewHelper.ListViewsRegistry.DenyPolicy_FilesAndFolders_ScanResults
		);
		ViewModel.UpdateTotalFiles();
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

		ViewModel.UpdateTotalFiles(true);
	}

	/// <summary>
	/// Selects all of the displayed rows on the ListView
	/// </summary>
	private void SelectAll_Click()
	{
		ListViewHelper.SelectAll(FileIdentitiesListView, ViewModel.FilesAndFoldersScanResults);
	}

	/// <summary>
	/// De-selects all of the displayed rows on the ListView
	/// </summary>
	private void DeSelectAll_Click()
	{
		FileIdentitiesListView.SelectedItems.Clear();
	}

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
}
