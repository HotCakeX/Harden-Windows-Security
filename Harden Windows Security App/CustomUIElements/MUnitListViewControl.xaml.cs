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
using AppControlManager.Others;
using AppControlManager.ViewModels;
using HardenWindowsSecurity.Helpers;
using HardenWindowsSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

internal sealed partial class MUnitListViewControl : UserControl, IDisposable
{
	internal MUnitListViewControl()
	{
		this.InitializeComponent();
		this.Unloaded += MUnitListViewControl_Unloaded;
	}

	private bool _isDisposed;

	internal static readonly DependencyProperty ListViewItemsSourceProperty =
		DependencyProperty.Register(
			nameof(ListViewItemsSource),
			typeof(ObservableCollection<GroupInfoListForMUnit>),
			typeof(MUnitListViewControl),
			new PropertyMetadata(new ObservableCollection<GroupInfoListForMUnit>(), OnListViewItemsSourceChanged));

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

	internal static readonly DependencyProperty SearchKeywordProperty =
		DependencyProperty.Register(
			nameof(SearchKeyword),
			typeof(string),
			typeof(MUnitListViewControl),
			new PropertyMetadata(null, OnSearchKeywordChanged));

	internal static readonly DependencyProperty TotalItemsCountProperty =
		DependencyProperty.Register(
			nameof(TotalItemsCount),
			typeof(int),
			typeof(MUnitListViewControl),
			new PropertyMetadata(0));

	internal static readonly DependencyProperty FilteredItemsCountProperty =
		DependencyProperty.Register(
			nameof(FilteredItemsCount),
			typeof(int),
			typeof(MUnitListViewControl),
			new PropertyMetadata(0));

	internal static readonly DependencyProperty SelectedItemsCountProperty =
		DependencyProperty.Register(
			nameof(SelectedItemsCount),
			typeof(int),
			typeof(MUnitListViewControl),
			new PropertyMetadata(0));

	internal static readonly DependencyProperty UndeterminedItemsCountProperty =
		DependencyProperty.Register(
			nameof(UndeterminedItemsCount),
			typeof(int),
			typeof(MUnitListViewControl),
			new PropertyMetadata(0));

	internal static readonly DependencyProperty AppliedItemsCountProperty =
		DependencyProperty.Register(
			nameof(AppliedItemsCount),
			typeof(int),
			typeof(MUnitListViewControl),
			new PropertyMetadata(0));

	internal static readonly DependencyProperty NotAppliedItemsCountProperty =
		DependencyProperty.Register(
			nameof(NotAppliedItemsCount),
			typeof(int),
			typeof(MUnitListViewControl),
			new PropertyMetadata(0));

	/// <summary>
	/// Flag to prevent recursive selection change events during selection restoration
	/// </summary>
	private volatile bool _isRestoringSelection;

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

	public string SearchKeyword
	{
		get => (string)GetValue(SearchKeywordProperty);
		set => SetValue(SearchKeywordProperty, value);
	}

	public int TotalItemsCount
	{
		get => (int)GetValue(TotalItemsCountProperty);
		set => SetValue(TotalItemsCountProperty, value);
	}

	public int FilteredItemsCount
	{
		get => (int)GetValue(FilteredItemsCountProperty);
		set => SetValue(FilteredItemsCountProperty, value);
	}

	public int SelectedItemsCount
	{
		get => (int)GetValue(SelectedItemsCountProperty);
		set => SetValue(SelectedItemsCountProperty, value);
	}

	public int UndeterminedItemsCount
	{
		get => (int)GetValue(UndeterminedItemsCountProperty);
		set => SetValue(UndeterminedItemsCountProperty, value);
	}

	public int AppliedItemsCount
	{
		get => (int)GetValue(AppliedItemsCountProperty);
		set => SetValue(AppliedItemsCountProperty, value);
	}

	public int NotAppliedItemsCount
	{
		get => (int)GetValue(NotAppliedItemsCountProperty);
		set => SetValue(NotAppliedItemsCountProperty, value);
	}

	private static void OnViewModelChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is MUnitListViewControl control && !control._isDisposed)
		{
			// Set user control reference in all MUnits
			control.SetUserControlReferenceInMUnits();
			// Restore selection if needed
			control.RestoreSelectionFromViewModel();
			// Update counts when ViewModel changes
			control.UpdateCounts();
		}
	}

	private static void OnListViewItemsSourceChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is MUnitListViewControl control && !control._isDisposed)
		{
			// Unsubscribe from old items first
			control.UnsubscribeFromAllMUnits();

			// Set user control reference in all MUnits when the items source changes
			control.SetUserControlReferenceInMUnits();
			// Update counts when items source changes
			control.UpdateCounts();
			// Restore selection when items source changes (e.g., after data loading)
			control.RestoreSelectionFromViewModel();
			// Subscribe to status changes for all MUnits to track status counts
			control.SubscribeToStatusChanges();
		}
	}

	/// <summary>
	/// Sets the user control reference in all MUnits so they can call back to this control
	/// </summary>
	private void SetUserControlReferenceInMUnits()
	{
		if (_isDisposed) return;

		foreach (GroupInfoListForMUnit group in ListViewItemsSource)
		{
			foreach (MUnit munit in group)
			{
				munit.UserControlReference = this;
			}
		}
	}

	/// <summary>
	/// Subscribes to PropertyChanged events of all MUnits to track status changes
	/// </summary>
	private void SubscribeToStatusChanges()
	{
		if (_isDisposed) return;

		foreach (GroupInfoListForMUnit group in ListViewItemsSource)
		{
			foreach (MUnit munit in group)
			{
				// Subscribe to property changes to update status counts when IsApplied changes
				munit.PropertyChanged += MUnit_PropertyChanged;
			}
		}

		// Initial status count calculation
		UpdateStatusCounts();
	}

	/// <summary>
	/// Unsubscribes from all MUnit PropertyChanged events
	/// </summary>
	private void UnsubscribeFromAllMUnits()
	{
		foreach (GroupInfoListForMUnit MUnitGroup in ListViewItemsSource)
		{
			foreach (MUnit munit in MUnitGroup)
			{
				munit.PropertyChanged -= MUnit_PropertyChanged;

				// Clear the reference to this User Control from each MUnit instance when this element is being destroyed during page navigation.
				munit.UserControlReference = null;
			}
		}
	}

	/// <summary>
	/// Handles property changes from MUnits to update status counts
	/// </summary>
	private void MUnit_PropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
	{
		if (_isDisposed) return;

		if (e.PropertyName == nameof(MUnit.IsApplied))
		{
			// Update status counts when any MUnit's IsApplied property changes
			_ = DispatcherQueue.TryEnqueue(UpdateStatusCounts);
		}
	}

	/// <summary>
	/// Updates the count properties based on current data
	/// </summary>
	private void UpdateCounts()
	{
		if (ViewModel == null || _isDisposed) return;

		// Update basic counts from ViewModel
		TotalItemsCount = ViewModel.TotalItemsCount;
		FilteredItemsCount = ViewModel.FilteredItemsCount;
		SelectedItemsCount = ViewModel.SelectedItemsCount;

		// Update status counts from ViewModel
		UndeterminedItemsCount = ViewModel.UndeterminedItemsCount;
		AppliedItemsCount = ViewModel.AppliedItemsCount;
		NotAppliedItemsCount = ViewModel.NotAppliedItemsCount;
	}

	/// <summary>
	/// Updates the status counts by examining all MUnits in the backing field
	/// </summary>
	private void UpdateStatusCounts()
	{
		if (ViewModel?.ListViewItemsSourceBackingField == null || _isDisposed) return;

		int undeterminedCount = 0;
		int appliedCount = 0;
		int notAppliedCount = 0;

		// Count status from all MUnits in the backing field (not just filtered ones)
		foreach (GroupInfoListForMUnit group in ViewModel.ListViewItemsSourceBackingField)
		{
			foreach (MUnit munit in group)
			{
				StatusState status = munit.StatusState;
				switch (status)
				{
					case StatusState.Undetermined:
						undeterminedCount++;
						break;
					case StatusState.Applied:
						appliedCount++;
						break;
					case StatusState.NotApplied:
						notAppliedCount++;
						break;
					default:
						break;
				}
			}
		}

		// Update ViewModel with new counts
		ViewModel.UndeterminedItemsCount = undeterminedCount;
		ViewModel.AppliedItemsCount = appliedCount;
		ViewModel.NotAppliedItemsCount = notAppliedCount;

		// Update local properties for UI binding
		UndeterminedItemsCount = undeterminedCount;
		AppliedItemsCount = appliedCount;
		NotAppliedItemsCount = notAppliedCount;
	}

	/// <summary>
	/// Restores ListView selection from ViewModel's persisted selection state. Runs for the Loaded event handler of the ListView too in order to restore selection when ListView is loaded (important for navigation scenarios).
	/// This is crucial for maintaining selection across navigation when NavigationCacheMode is disabled.
	/// So that when we navigate away and then back to the page, the items that were selected will remain selected.
	/// </summary>
	private void RestoreSelectionFromViewModel()
	{
		if (ViewModel?.ItemsSourceSelectedItems == null || ListViewItemsSource.Count == 0 || _isRestoringSelection || _isDisposed)
			return;

		// Only restore if there are items to restore and ListView has items
		if (ViewModel.ItemsSourceSelectedItems.Count == 0)
			return;

		_isRestoringSelection = true;

		try
		{
			// Clearing the current ListView selection without triggering selection changed events
			MainListView.SelectedItems.Clear();

			// A flat list of all currently visible MUnits for faster lookup
			HashSet<MUnit> visibleMUnits = [];
			foreach (GroupInfoListForMUnit group in ListViewItemsSource)
			{
				foreach (MUnit munit in group)
				{
					_ = visibleMUnits.Add(munit);
				}
			}

			// Restore selection for items that are in the ViewModel's selection list and currently visible
			foreach (MUnit selectedMUnit in ViewModel.ItemsSourceSelectedItems)
			{
				if (visibleMUnits.Contains(selectedMUnit))
				{
					MainListView.SelectedItems.Add(selectedMUnit);
				}
			}
		}
		finally
		{
			_isRestoringSelection = false;
		}
	}

	private static void OnSearchKeywordChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is MUnitListViewControl control && !control._isDisposed)
		{
			if (control.ViewModel == null)
				return;

			control.ViewModel.SearchKeyword = e.NewValue as string;
			control.PerformSearch(control.ViewModel.SearchKeyword);
		}
	}

	private void PerformSearch(string? searchTerm)
	{
		if (ViewModel?.ListViewItemsSourceBackingField == null || _isDisposed)
			return;

		UnsubscribeFromAllMUnits();

		if (string.IsNullOrWhiteSpace(searchTerm))
		{
			// Show all items when search is empty
			ListViewItemsSource.Clear();
			foreach (GroupInfoListForMUnit group in ViewModel.ListViewItemsSourceBackingField)
			{
				ListViewItemsSource.Add(group);
			}
			// Set user control reference after restoring items
			SetUserControlReferenceInMUnits();

			// Update filtered count to total count
			ViewModel.FilteredItemsCount = ViewModel.TotalItemsCount;
			UpdateCounts();

			// Restore selection after clearing search
			RestoreSelectionFromViewModel();
			// Re-subscribe to status changes after clearing search
			SubscribeToStatusChanges();
			return;
		}

		// Perform case-insensitive search
		List<GroupInfoListForMUnit> filteredGroups = ViewModel.ListViewItemsSourceBackingField
			.Select(group => new GroupInfoListForMUnit(
				items: group.Where(munit =>
					(munit.Name?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
					(munit.SubCategoryName?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
					(munit.URL?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)),
				key: group.Key))
			.Where(group => group.Any()) // Only include groups that have matching items
			.ToList();

		ListViewItemsSource.Clear();
		foreach (GroupInfoListForMUnit group in filteredGroups)
		{
			ListViewItemsSource.Add(group);
		}

		// Update filtered count
		int filteredCount = 0;
		foreach (GroupInfoListForMUnit group in filteredGroups)
		{
			filteredCount += group.Count;
		}
		ViewModel.FilteredItemsCount = filteredCount;

		// Set user control reference after filtering
		SetUserControlReferenceInMUnits();
		UpdateCounts();

		// Restore selection after filtering (only items that match search will be selected)
		RestoreSelectionFromViewModel();
		// Re-subscribe to status changes after filtering
		SubscribeToStatusChanges();
	}

	/// <summary>
	/// For selecting all items on the UI. Will automatically trigger <see cref="MainListView_SelectionChanged"/> method as well,
	/// Adding the items to <see cref="ItemsSourceSelectedItems"/>.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SelectAllMenuFlyoutItem_Click(object sender, RoutedEventArgs e)
	{
		if (_isDisposed) return;

		foreach (GroupInfoListForMUnit group in ListViewItemsSource)
		{
			foreach (MUnit item in group)
			{
				MainListView.SelectedItems.Add(item);
			}
		}
	}

	/// <summary>
	/// For De-selecting all items on the UI. Will automatically trigger <see cref="MainListView_SelectionChanged"/> method as well,
	/// Removing the items from <see cref="ItemsSourceSelectedItems"/>.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void RemoveSelectionsMenuFlyoutItem_Click(object sender, RoutedEventArgs e)
	{
		if (_isDisposed) return;

		MainListView.SelectedItems.Clear();
	}

	/// <summary>
	/// Event handler for the SelectionChanged event of the ListView.
	/// Triggered by <see cref="SelectAllMenuFlyoutItem_Click(object, RoutedEventArgs)"/> and <see cref="RemoveSelectionsMenuFlyoutItem_Click(object, RoutedEventArgs)"/> to keep things consistent.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void MainListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Skip processing if we're currently restoring selection to prevent recursion
		if (_isRestoringSelection || _isDisposed)
			return;

		foreach (MUnit item in e.AddedItems.Cast<MUnit>())
		{
			ViewModel?.ItemsSourceSelectedItems.Add(item);
		}

		foreach (MUnit item in e.RemovedItems.Cast<MUnit>())
		{
			_ = ViewModel?.ItemsSourceSelectedItems.Remove(item);
		}

		// Update selected count
		if (ViewModel != null)
		{
			ViewModel.SelectedItemsCount = ViewModel.ItemsSourceSelectedItems.Count;
			UpdateCounts();
		}
	}

	#region Single MUnit Operations

	/// <summary>
	/// Apply a single MUnit
	/// </summary>
	/// <param name="mUnit">The MUnit to apply</param>
	internal async void ApplyMUnit(MUnit mUnit)
	{
		if (_isDisposed) return;

		try
		{
			await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, [mUnit], MUnitOperation.Apply);
		}
		catch (Exception ex)
		{
			ViewModel?.MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Remove a single MUnit
	/// </summary>
	/// <param name="mUnit">The MUnit to remove</param>
	internal async void RemoveMUnit(MUnit mUnit)
	{
		if (_isDisposed) return;

		try
		{
			if (mUnit.RemoveStrategy == null)
				return;

			await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, [mUnit], MUnitOperation.Remove);
		}
		catch (Exception ex)
		{
			ViewModel?.MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Verify a single MUnit
	/// </summary>
	/// <param name="mUnit">The MUnit to verify</param>
	internal async void VerifyMUnit(MUnit mUnit)
	{
		if (_isDisposed) return;

		try
		{
			if (mUnit.VerifyStrategy == null)
				return;

			await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, [mUnit], MUnitOperation.Verify);
		}
		catch (Exception ex)
		{
			ViewModel?.MainInfoBar.WriteError(ex);
		}
	}

	#endregion

	#region Bulk Operations

	/// <summary>
	/// Apply all MUnits.
	/// </summary>
	internal async void ApplyAllMUnits()
	{
		if (ViewModel is null || _isDisposed) return;

		bool errorsOccurred = false;

		ViewModel.ApplyAllCancellableButton.Begin();

		try
		{
			ViewModel.ElementsAreEnabled = false;
			ViewModel.MainInfoBar.WriteInfo("Applying all configurations...");

			List<MUnit> allMUnits = [];
			foreach (GroupInfoListForMUnit group in ListViewItemsSource)
			{
				allMUnits.AddRange(group);
			}
			await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, allMUnits, MUnitOperation.Apply, ViewModel.ApplyAllCancellableButton.Cts?.Token);
		}
		catch (Exception ex)
		{
			ViewModelBase.HandleExceptions(ex, ref errorsOccurred, ref ViewModel.ApplyAllCancellableButton.wasCancelled, ViewModel.MainInfoBar);
		}
		finally
		{
			if (ViewModel.ApplyAllCancellableButton.wasCancelled)
			{
				ViewModel.MainInfoBar.WriteWarning("Apply All operation was cancelled by user");
			}
			else if (!errorsOccurred)
			{
				ViewModel.MainInfoBar.WriteSuccess("Successfully applied all configurations");
			}

			ViewModel.ApplyAllCancellableButton.End();
			ViewModel.ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Apply only the selected MUnits.
	/// </summary>
	private async void ApplySelectedMUnits()
	{
		if (_isDisposed) return;

		try
		{

			if (ViewModel?.ItemsSourceSelectedItems.Count > 0)
			{
				await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, ViewModel.ItemsSourceSelectedItems, MUnitOperation.Apply);
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ErrorWriter.FormatException(ex));
		}
	}

	/// <summary>
	/// Remove all MUnits - modified to use cancellable button pattern like CreateSupplementalPolicyVM
	/// </summary>
	internal async void RemoveAllMUnits()
	{
		if (ViewModel is null || _isDisposed) return;

		bool errorsOccurred = false;

		ViewModel.RemoveAllCancellableButton.Begin();

		try
		{
			ViewModel.ElementsAreEnabled = false;
			ViewModel.MainInfoBar.WriteInfo("Removing all configurations...");

			List<MUnit> allMUnits = [];
			foreach (GroupInfoListForMUnit group in ListViewItemsSource)
			{
				foreach (MUnit mUnit in group)
				{
					if (mUnit.RemoveStrategy is not null)
					{
						allMUnits.Add(mUnit);
					}
				}
			}
			await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, allMUnits, MUnitOperation.Remove, ViewModel.RemoveAllCancellableButton.Cts?.Token);
		}
		catch (Exception ex)
		{
			ViewModelBase.HandleExceptions(ex, ref errorsOccurred, ref ViewModel.RemoveAllCancellableButton.wasCancelled, ViewModel.MainInfoBar);
		}
		finally
		{
			if (ViewModel.RemoveAllCancellableButton.wasCancelled)
			{
				ViewModel.MainInfoBar.WriteWarning("Remove All operation was cancelled by user");
			}
			else if (!errorsOccurred)
			{
				ViewModel.MainInfoBar.WriteSuccess("Successfully removed all configurations");
			}

			ViewModel.RemoveAllCancellableButton.End();
			ViewModel.ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Remove only the selected MUnits.
	/// </summary>
	private async void RemoveSelectedMUnits()
	{
		if (_isDisposed) return;

		try
		{
			if (ViewModel?.ItemsSourceSelectedItems != null)
			{
				List<MUnit> allMUnits = [];
				foreach (MUnit mUnit in ViewModel.ItemsSourceSelectedItems)
				{
					if (mUnit.RemoveStrategy is not null)
					{
						allMUnits.Add(mUnit);
					}
				}

				if (allMUnits.Count > 0)
				{
					await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, allMUnits, MUnitOperation.Remove);
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ErrorWriter.FormatException(ex));
		}
	}

	/// <summary>
	/// Verify all MUnits - modified to use cancellable button pattern like CreateSupplementalPolicyVM
	/// </summary>
	internal async void VerifyAllMUnits()
	{
		if (ViewModel is null || _isDisposed) return;

		bool errorsOccurred = false;

		ViewModel.VerifyAllCancellableButton.Begin();

		try
		{
			ViewModel.ElementsAreEnabled = false;
			ViewModel.MainInfoBar.WriteInfo("Verifying all configurations...");

			List<MUnit> allMUnits = [];
			foreach (GroupInfoListForMUnit group in ListViewItemsSource)
			{
				foreach (MUnit mUnit in group)
				{
					if (mUnit.VerifyStrategy is not null)
					{
						allMUnits.Add(mUnit);
					}
				}
			}
			await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, allMUnits, MUnitOperation.Verify, ViewModel.VerifyAllCancellableButton.Cts?.Token);
		}
		catch (Exception ex)
		{
			ViewModelBase.HandleExceptions(ex, ref errorsOccurred, ref ViewModel.VerifyAllCancellableButton.wasCancelled, ViewModel.MainInfoBar);
		}
		finally
		{
			if (ViewModel.VerifyAllCancellableButton.wasCancelled)
			{
				ViewModel.MainInfoBar.WriteWarning("Verify All operation was cancelled by user");
			}
			else if (!errorsOccurred)
			{
				ViewModel.MainInfoBar.WriteSuccess("Successfully verified all configurations");
			}

			ViewModel.VerifyAllCancellableButton.End();
			ViewModel.ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Verify only the selected MUnits.
	/// </summary>
	private async void VerifySelectedMUnits()
	{
		if (_isDisposed) return;

		try
		{
			if (ViewModel?.ItemsSourceSelectedItems != null)
			{
				List<MUnit> allMUnits = [];

				foreach (MUnit mUnit in ViewModel.ItemsSourceSelectedItems)
				{
					if (mUnit.VerifyStrategy is not null)
					{
						allMUnits.Add(mUnit);
					}
				}

				if (allMUnits.Count > 0)
				{
					await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, allMUnits, MUnitOperation.Verify);
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ErrorWriter.FormatException(ex));
		}
	}

	#endregion

	/// <summary>
	/// Handle Unloaded event to clean up resources
	/// </summary>
	private void MUnitListViewControl_Unloaded(object sender, RoutedEventArgs e)
	{
		Dispose();
	}

	public void Dispose()
	{
		if (_isDisposed) return;
		_isDisposed = true;

		// Unsubscribe from all MUnit events
		UnsubscribeFromAllMUnits();

		// Unregister from Unloaded event
		this.Unloaded -= MUnitListViewControl_Unloaded;
	}
}
