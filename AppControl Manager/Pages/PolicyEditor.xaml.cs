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
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class PolicyEditor : Page
{
	internal PolicyEditorVM ViewModel { get; } = new PolicyEditorVM();

	public PolicyEditor()
	{
		this.InitializeComponent();
		this.NavigationCacheMode = NavigationCacheMode.Enabled;
		DataContext = ViewModel;
	}

	private void BrowseForPolicyButton_RightTappedOrHolding()
	{
		if (!BrowseForPolicyButton_Flyout.IsOpen)
			BrowseForPolicyButton_Flyout.ShowAt(BrowseForPolicyButton);
	}

	/// <summary>
	/// Event handler for deleting selected items from the FileBasedRulesListView's Items Source
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FileBasedRulesListView_DeleteItems(object sender, RoutedEventArgs e)
	{
		// Collect the selected items to delete - without ToList() or [.. ], only half of the selected items are removed from the collection
		IEnumerable<AppControlManager.PolicyEditor.FileBasedRulesForListView> itemsToDelete = [.. FileBasedRulesListView.SelectedItems.Cast<AppControlManager.PolicyEditor.FileBasedRulesForListView>()];

		// Iterate over the copy to remove each item
		foreach (AppControlManager.PolicyEditor.FileBasedRulesForListView item in itemsToDelete)
		{
			PolicyEditorVM.Instance.RemoveFileRuleFromCollection(item);
		}
	}


	/// <summary>
	/// Event handler for deleting selected items from the SignatureBasedRulesListView's Items Source
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SignatureBasedRulesListView_DeleteItems(object sender, RoutedEventArgs e)
	{
		// Collect the selected items to delete - without ToList() or [.. ], only half of the selected items are removed from the collection
		IEnumerable<AppControlManager.PolicyEditor.SignatureBasedRulesForListView> itemsToDelete = [.. SignatureBasedRulesListView.SelectedItems.Cast<AppControlManager.PolicyEditor.SignatureBasedRulesForListView>()];

		// Iterate over the copy to remove each item
		foreach (AppControlManager.PolicyEditor.SignatureBasedRulesForListView item in itemsToDelete)
		{
			PolicyEditorVM.Instance.RemoveSignatureRuleFromCollection(item);
		}
	}


	#region FileBasedRulesListView enhancements


	#region Ensuring right-click on rows behaves better and normally on FileBasedRulesListView

	// When right-clicking on an unselected row, first it becomes selected and then the context menu will be shown for the selected row
	// This is a much more expected behavior. Without this, the right-click would be meaningless on the ListView unless user left-clicks on the row first

	private void FileBasedRulesListView_ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		// When the container is being recycled, detach the handler.
		if (args.InRecycleQueue)
		{
			args.ItemContainer.RightTapped -= FileBasedRulesListViewItem_RightTapped;
		}
		else
		{
			// Detach first to avoid multiple subscriptions, then attach the handler.
			args.ItemContainer.RightTapped -= FileBasedRulesListViewItem_RightTapped;
			args.ItemContainer.RightTapped += FileBasedRulesListViewItem_RightTapped;
		}
	}

	private void FileBasedRulesListViewItem_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (sender is ListViewItem item)
		{
			// If the item is not already selected, clear previous selections and select this one.
			if (!item.IsSelected)
			{

				// Set the counter so that the SelectionChanged event handler will ignore the next 2 events.
				_skipSelectionChangedCountForFileBasedRulesListView = 2;

				//clear for exclusive selection
				FileBasedRulesListView.SelectedItems.Clear();
				item.IsSelected = true;
			}
		}
	}

	#endregion


	// A counter to prevent SelectionChanged event from firing twice when right-clicking on an unselected row
	private int _skipSelectionChangedCountForFileBasedRulesListView;

	private async void FileBasedRulesListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Check if we need to skip this event.
		if (_skipSelectionChangedCountForFileBasedRulesListView > 0)
		{
			_skipSelectionChangedCountForFileBasedRulesListView--;
			return;
		}

		await ListViewHelper.SmoothScrollIntoViewWithIndexCenterVerticallyOnlyAsync(listViewBase: (ListView)sender, listView: (ListView)sender, index: ((ListView)sender).SelectedIndex, disableAnimation: false, scrollIfVisible: true, additionalHorizontalOffset: 0, additionalVerticalOffset: 0);
	}

	#endregion


	#region SignatureBasedRulesListView enhancements

	#region Ensuring right-click on rows behaves better and normally on ListView

	// When right-clicking on an unselected row, first it becomes selected and then the context menu will be shown for the selected row
	// This is a much more expected behavior. Without this, the right-click would be meaningless on the ListView unless user left-clicks on the row first

	private void SignatureBasedRulesListView_ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		// When the container is being recycled, detach the handler.
		if (args.InRecycleQueue)
		{
			args.ItemContainer.RightTapped -= SignatureBasedRulesListViewItem_RightTapped;
		}
		else
		{
			// Detach first to avoid multiple subscriptions, then attach the handler.
			args.ItemContainer.RightTapped -= SignatureBasedRulesListViewItem_RightTapped;
			args.ItemContainer.RightTapped += SignatureBasedRulesListViewItem_RightTapped;
		}
	}

	private void SignatureBasedRulesListViewItem_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (sender is ListViewItem item)
		{
			// If the item is not already selected, clear previous selections and select this one.
			if (!item.IsSelected)
			{

				// Set the counter so that the SelectionChanged event handler will ignore the next 2 events.
				_skipSelectionChangedCountForSignatureBasedRulesListView = 2;

				//clear for exclusive selection
				SignatureBasedRulesListView.SelectedItems.Clear();
				item.IsSelected = true;
			}
		}
	}

	#endregion


	// A counter to prevent SelectionChanged event from firing twice when right-clicking on an unselected row
	private int _skipSelectionChangedCountForSignatureBasedRulesListView;

	private async void SignatureBasedRulesListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Check if we need to skip this event.
		if (_skipSelectionChangedCountForSignatureBasedRulesListView > 0)
		{
			_skipSelectionChangedCountForSignatureBasedRulesListView--;
			return;
		}

		await ListViewHelper.SmoothScrollIntoViewWithIndexCenterVerticallyOnlyAsync(listViewBase: (ListView)sender, listView: (ListView)sender, index: ((ListView)sender).SelectedIndex, disableAnimation: false, scrollIfVisible: true, additionalHorizontalOffset: 0, additionalVerticalOffset: 0);
	}


	#endregion


	/// <summary>
	/// Performs search in both collections of the ListView.
	/// Implementing it in the ViewModel via x:Bind would not work properly.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
	{

		string searchTerm = SearchBoxTextBox.Text;
		searchTerm = searchTerm.Trim();

		List<AppControlManager.PolicyEditor.FileBasedRulesForListView> filteredResults = [];

		await Task.Run(() =>
		{
			// Perform a case-insensitive search in all relevant fields
			filteredResults = [.. PolicyEditorVM.Instance.FileRulesCollectionList.Where(p =>
			(p.Id?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.FriendlyName?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.FileDescription?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.FileName?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.FilePath?.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.InternalName?.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.PackageFamilyName?.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.ProductName?.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.Hash?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)
			)];
		});

		PolicyEditorVM.Instance.FileRulesCollection.Clear();

		foreach (AppControlManager.PolicyEditor.FileBasedRulesForListView item in filteredResults)
		{
			PolicyEditorVM.Instance.FileRulesCollection.Add(item);
		}

		PolicyEditorVM.Instance.UpdateFileBasedCollectionsCount();


		List<AppControlManager.PolicyEditor.SignatureBasedRulesForListView> filteredResults2 = [];

		await Task.Run(() =>
		{
			// Perform a case-insensitive search in all relevant fields
			filteredResults2 = [.. PolicyEditorVM.Instance.SignatureRulesCollectionList.Where(p =>
			(p.Id?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.CertIssuer?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.CertificateEKU?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.CertOemID?.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.CertPublisher?.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.CertRoot?.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.Name?.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)
			)];
		});

		PolicyEditorVM.Instance.SignatureRulesCollection.Clear();

		foreach (AppControlManager.PolicyEditor.SignatureBasedRulesForListView item in filteredResults2)
		{
			PolicyEditorVM.Instance.SignatureRulesCollection.Add(item);
		}

		PolicyEditorVM.Instance.UpdateSignatureBasedCollectionsCount();

	}

	/// <summary>
	/// Event handler to open the Policy type ComboBox's dropdown menu when its parent settings card is clicked on
	/// </summary>
	private void PolicyTypeSettingsCard_Click()
	{
		PolicyTypeComboBox.IsDropDownOpen = true;
	}


	/// <summary>
	/// Event handler to open the Policy HVCI Option/Level ComboBox's dropdown menu when its parent settings card is clicked on
	/// </summary>
	private void PolicyHVCIOptionsComboBox_Click()
	{
		PolicyHVCIOptionsComboBox.IsDropDownOpen = true;
	}
}
