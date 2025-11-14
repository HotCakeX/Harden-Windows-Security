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
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.ViewModels;
using HardenSystemSecurity;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// UserControl that hosts the grouped ListView of MUnits plus command bar.
/// </summary>
internal sealed partial class MUnitListViewControl : UserControl, IDisposable
{
	private HardenSystemSecurity.AppSettings.Main AppSettings => App.Settings;

	internal MUnitListViewControl()
	{
		this.InitializeComponent();
	}

	private bool _isDisposed;

	#region Explicit Disposal Control

	/// <summary>
	/// DependencyProperty to control whether this control disposes itself automatically on Unloaded.
	/// When set to true, disposal is skipped on Unloaded and must be invoked explicitly by the host
	/// (e.g. in Page.OnNavigatedFrom). Default is false.
	/// </summary>
	internal static readonly DependencyProperty DisposeOnlyOnExplicitCallProperty =
		DependencyProperty.Register(
			nameof(DisposeOnlyOnExplicitCall),
			typeof(bool),
			typeof(MUnitListViewControl),
			new PropertyMetadata(false));

	/// <summary>
	/// Wrapper so XAML can set the property.
	/// </summary>
	public bool DisposeOnlyOnExplicitCall
	{
		get => (bool)GetValue(DisposeOnlyOnExplicitCallProperty);
		set => SetValue(DisposeOnlyOnExplicitCallProperty, value);
	}

	/// <summary>
	/// DependencyProperty that, when true, attempts to mark all child controls that implement <see cref="IExplicitDisposalOptIn"/>
	/// with their own DisposeOnlyOnExplicitCall flag so they also survive transient unloads under a TabView.
	/// </summary>
	internal static readonly DependencyProperty ChildButtonsDisposeOnlyOnExplicitCallProperty =
		DependencyProperty.Register(
			nameof(ChildButtonsDisposeOnlyOnExplicitCall),
			typeof(bool),
			typeof(MUnitListViewControl),
			new PropertyMetadata(false, OnChildButtonsDisposeOnlyOnExplicitCallChanged));

	public bool ChildButtonsDisposeOnlyOnExplicitCall
	{
		get => (bool)GetValue(ChildButtonsDisposeOnlyOnExplicitCallProperty);
		set => SetValue(ChildButtonsDisposeOnlyOnExplicitCallProperty, value);
	}

	private static void OnChildButtonsDisposeOnlyOnExplicitCallChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is MUnitListViewControl control && (bool)e.NewValue)
		{
			control.TrySetChildExplicitDisposalOptIn();
		}
	}

	private void MainListView_ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		if (!_isDisposed && ChildButtonsDisposeOnlyOnExplicitCall && args.ItemContainer is not null)
		{
			// Traverse the container's subtree to set the flag on any new controls
			TrySetChildExplicitDisposalOptIn(args.ItemContainer);
		}
	}

	/// <summary>
	/// Traverses visual tree breadth-first to set DisposeOnlyOnExplicitCall = true
	/// on any descendant implementing <see cref="IExplicitDisposalOptIn"/>.
	/// </summary>
	private void TrySetChildExplicitDisposalOptIn(DependencyObject? rootOverride = null)
	{
		if (_isDisposed) return;
		if (!ChildButtonsDisposeOnlyOnExplicitCall) return;

		try
		{
			DependencyObject start = rootOverride ?? this;
			Queue<DependencyObject> queue = new();
			queue.Enqueue(start);

			while (queue.Count > 0)
			{
				DependencyObject current = queue.Dequeue();
				int count = VisualTreeHelper.GetChildrenCount(current);
				for (int i = 0; i < count; i++)
				{
					DependencyObject child = VisualTreeHelper.GetChild(current, i);

					if (child is IExplicitDisposalOptIn explicitControl && !explicitControl.DisposeOnlyOnExplicitCall)
					{
						explicitControl.DisposeOnlyOnExplicitCall = true;
					}

					queue.Enqueue(child);
				}
			}
		}
		catch { }
	}

	#endregion

	/// <summary>
	/// Handles the Loaded event to configure the ItemsStackPanel with current settings
	/// </summary>
	private void MUnitListViewControl_Loaded(object sender, RoutedEventArgs e)
	{
		// Set the initial value and configure the panel
		ConfigureItemsStackPanel();

		ApplyCombinedFilters();

		// Ensure status counts are available immediately for the flyout numbers
		UpdateStatusCounts();

		// Subscribe to AppSettings property changes when control is loaded
		if (AppSettings is INotifyPropertyChanged notifyPropertyChanged)
		{
			notifyPropertyChanged.PropertyChanged -= AppSettings_PropertyChanged; // Ensure no duplicate subscription
			notifyPropertyChanged.PropertyChanged += AppSettings_PropertyChanged;
		}

		// If caller requested propagation to child controls, attempt it now (some may already be realized).
		if (ChildButtonsDisposeOnlyOnExplicitCall)
		{
			TrySetChildExplicitDisposalOptIn();
		}
	}

	/// <summary>
	/// Event handler for AppSettings property changes to ensure immediate updates
	/// </summary>
	private void AppSettings_PropertyChanged(object? sender, PropertyChangedEventArgs e)
	{
		if (e.PropertyName == nameof(AppSettings.StickyHeadersForListViews))
		{
			// Update the ItemsStackPanel when the setting changes
			ConfigureItemsStackPanel();
		}
	}

	/// <summary>
	/// Configures the ItemsStackPanel with the current AppSettings value
	/// </summary>
	private void ConfigureItemsStackPanel()
	{
		if (MainListView.ItemsPanelRoot is ItemsStackPanel itemsStackPanel)
		{
			itemsStackPanel.AreStickyGroupHeadersEnabled = AppSettings.StickyHeadersForListViews;
		}
	}

	internal static readonly DependencyProperty ListViewItemsSourceProperty =
		DependencyProperty.Register(
			nameof(ListViewItemsSource),
			typeof(ObservableCollection<GroupInfoListForMUnit>),
			typeof(MUnitListViewControl),
			new PropertyMetadata(new ObservableCollection<GroupInfoListForMUnit>(), OnListViewItemsSourceChanged));

	internal static readonly DependencyProperty ViewModelProperty =
		DependencyProperty.Register(
			nameof(ViewModel),
			typeof(IMUnitListViewModel),
			typeof(MUnitListViewControl),
			new PropertyMetadata(null, OnViewModelChanged));

	/// <summary>
	/// Flag to prevent recursive selection change events during selection restoration
	/// </summary>
	private volatile bool _isRestoringSelection;

	public ObservableCollection<GroupInfoListForMUnit> ListViewItemsSource
	{
		get => (ObservableCollection<GroupInfoListForMUnit>)GetValue(ListViewItemsSourceProperty);
		set => SetValue(ListViewItemsSourceProperty, value);
	}

	/// <summary>
	/// Needs to stay nullable due to x:Bind.
	/// </summary>
	public IMUnitListViewModel? ViewModel
	{
		get => (IMUnitListViewModel?)GetValue(ViewModelProperty);
		set => SetValue(ViewModelProperty, value);
	}

	private static void OnViewModelChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is MUnitListViewControl control && !control._isDisposed)
		{
			// Set user control reference in all MUnits
			control.SetUserControlReferenceInMUnits();
			// Restore selection if needed
			control.RestoreSelectionFromViewModel();
			// Ensure status counts are computed right away
			control.UpdateStatusCounts();
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
			// Restore selection when items source changes (e.g., after data loading)
			control.RestoreSelectionFromViewModel();
			// Subscribe to status changes for all MUnits to track status counts
			control.SubscribeToStatusChanges();

			// Configure the ItemsStackPanel when items source changes
			control.ConfigureItemsStackPanel();

			// If requested, propagate explicit-disposal configuration to child controls (they may appear now)
			if (control.ChildButtonsDisposeOnlyOnExplicitCall)
			{
				control.TrySetChildExplicitDisposalOptIn();
			}
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
	private void MUnit_PropertyChanged(object? sender, PropertyChangedEventArgs e)
	{
		if (_isDisposed) return;

		if (e.PropertyName == nameof(MUnit.IsApplied))
		{
			// Update status counts when any MUnit's IsApplied property changes
			_ = DispatcherQueue.TryEnqueue(UpdateStatusCounts);
		}
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

	/// <summary>
	/// For selecting all items on the UI. Will automatically trigger <see cref="MainListView_SelectionChanged(object, SelectionChangedEventArgs)"/> method as well,
	/// Adding the items to <see cref="IMUnitListViewModel.ItemsSourceSelectedItems"/>.
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
	/// For De-selecting all items on the UI. Will automatically trigger <see cref="MainListView_SelectionChanged(object, SelectionChangedEventArgs)"/> method as well,
	/// Removing the items from <see cref="IMUnitListViewModel.ItemsSourceSelectedItems"/>.
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
		_ = (ViewModel?.SelectedItemsCount = ViewModel.ItemsSourceSelectedItems.Count);
	}

	#region Single MUnit Operations

	/// <summary>
	/// Apply a single MUnit
	/// </summary>
	/// <param name="mUnit">The MUnit to apply</param>
	internal async void ApplyMUnit(MUnit mUnit)
	{
		// If the UI is loading the ViewModel will be null initially due to x:Bind usage, so this check ensures ProcessMUnitsWithBulkOperations method always receives a valid ViewModel reference.
		if (ViewModel is null || _isDisposed) return;

		try
		{
			// Mark a per-item operation as running so the "All" animated buttons disable themselves.
			BeginItemOperation();

			await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, [mUnit], MUnitOperation.Apply);
		}
		catch (Exception ex)
		{
			ViewModel?.MainInfoBar.WriteError(ex);
		}
		finally
		{
			// Clear the per-item operation running flag.
			EndItemOperation();
		}
	}

	/// <summary>
	/// Remove a single MUnit
	/// </summary>
	/// <param name="mUnit">The MUnit to remove</param>
	internal async void RemoveMUnit(MUnit mUnit)
	{
		// If the UI is loading the ViewModel will be null initially due to x:Bind usage, so this check ensures ProcessMUnitsWithBulkOperations method always receives a valid ViewModel reference.
		if (ViewModel is null || _isDisposed) return;

		try
		{
			if (mUnit.RemoveStrategy == null)
				return;

			// Mark a per-item operation as running so the "All" animated buttons disable themselves.
			BeginItemOperation();

			await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, [mUnit], MUnitOperation.Remove);
		}
		catch (Exception ex)
		{
			ViewModel?.MainInfoBar.WriteError(ex);
		}
		finally
		{
			// Clear the per-item operation running flag.
			EndItemOperation();
		}
	}

	/// <summary>
	/// Verify a single MUnit
	/// </summary>
	/// <param name="mUnit">The MUnit to verify</param>
	internal async void VerifyMUnit(MUnit mUnit)
	{
		// If the UI is loading the ViewModel will be null initially due to x:Bind usage, so this check ensures ProcessMUnitsWithBulkOperations method always receives a valid ViewModel reference.
		if (ViewModel is null || _isDisposed) return;

		try
		{
			if (mUnit.VerifyStrategy == null)
				return;

			// Mark a per-item operation as running so the "All" animated buttons disable themselves.
			BeginItemOperation();

			await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, [mUnit], MUnitOperation.Verify);
		}
		catch (Exception ex)
		{
			ViewModel?.MainInfoBar.WriteError(ex);
		}
		finally
		{
			// Clear the per-item operation running flag.
			EndItemOperation();
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
			ViewModel.MainInfoBar.WriteInfo(GlobalVars.GetStr("ApplyingAllSecurityMeasures"));

			List<MUnit> allMUnits = [];
			foreach (GroupInfoListForMUnit group in ListViewItemsSource)
			{
				// Only include MUnits whose sub-category is null for Apply All
				// Because user might not be expecting to apply the more extreme sub-categories when using the "Apply All" button.
				foreach (MUnit mUnit in group)
				{
					if (mUnit.SubCategory is null)
					{
						allMUnits.Add(mUnit);
					}
				}
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
				ViewModel.MainInfoBar.WriteWarning(GlobalVars.GetStr("ApplyOperationCancelledByUser"));
			}
			else if (!errorsOccurred)
			{
				ViewModel.MainInfoBar.WriteSuccess(GlobalVars.GetStr("ApplyingAllSecurityMeasuresSuccessful"));
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
			Logger.Write(ex);
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
			ViewModel.MainInfoBar.WriteInfo(GlobalVars.GetStr("RemovingAllSecurityMeasures"));

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
				ViewModel.MainInfoBar.WriteWarning(GlobalVars.GetStr("RemoveOperationCancelledByUser"));
			}
			else if (!errorsOccurred)
			{
				ViewModel.MainInfoBar.WriteSuccess(GlobalVars.GetStr("RemovingAllSecurityMeasuresSuccessful"));
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
			Logger.Write(ex);
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
			ViewModel.MainInfoBar.WriteInfo(GlobalVars.GetStr("VerifyingAllSecurityMeasures"));

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
				ViewModel.MainInfoBar.WriteWarning(GlobalVars.GetStr("VerifyOperationCancelledByUser"));
			}
			else if (!errorsOccurred)
			{
				ViewModel.MainInfoBar.WriteSuccess(GlobalVars.GetStr("VerifyingAllSecurityMeasuresSuccessful"));
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
			Logger.Write(ex);
		}
	}

	#endregion

	/// <summary>
	/// Handle Unloaded event to clean up resources
	/// </summary>
	private void MUnitListViewControl_Unloaded(object sender, RoutedEventArgs e)
	{
		// If the host requested explicit disposal, skip automatic disposal here.
		if (DisposeOnlyOnExplicitCall)
		{
			return;
		}
		Dispose();
	}

	public void Dispose()
	{
		if (_isDisposed) return;
		_isDisposed = true;

		// Unsubscribe from AppSettings property changes
		if (AppSettings is INotifyPropertyChanged notifyPropertyChanged)
		{
			notifyPropertyChanged.PropertyChanged -= AppSettings_PropertyChanged;
		}

		// Unsubscribe from all MUnit events
		UnsubscribeFromAllMUnits();
	}

	#region Logic for Animated Button Enablement

	// ============================================================================================================
	// - If one of the three animated "All" buttons (Apply/Verify/Remove) is running, the other two must be disabled.
	// - If any per-item operation is running, all three animated "All" buttons must be disabled until it completes.
	// Implemented by:
	//   1) A DP flag AnyItemOperationInProgress, toggled around per-item operations.
	//   2) Three compute helpers used by XAML x:Bind to control IsEnabled for the top animated buttons.
	// ============================================================================================================

	/// <summary>
	/// Tracks whether any item-level operation (single-row Apply/Verify/Remove) is currently in progress.
	/// XAML binds this to decide if the three "All" animated buttons should be disabled.
	/// </summary>
	internal static readonly DependencyProperty AnyItemOperationInProgressProperty =
		DependencyProperty.Register(
			nameof(AnyItemOperationInProgress),
			typeof(bool),
			typeof(MUnitListViewControl),
			new PropertyMetadata(false));

	/// <summary>
	/// True when at least one per-item operation is running.
	/// </summary>
	public bool AnyItemOperationInProgress
	{
		get => (bool)GetValue(AnyItemOperationInProgressProperty);
		set => SetValue(AnyItemOperationInProgressProperty, value);
	}

	/// <summary>
	/// Internal counter to handle overlapping per-item operations without flicker.
	/// </summary>
	private int _itemOpsInFlight;

	/// <summary>
	/// Call when a per-item operation begins. Keeps top animated buttons disabled while any item op runs.
	/// </summary>
	private void BeginItemOperation()
	{
		_itemOpsInFlight++;
		AnyItemOperationInProgress = _itemOpsInFlight > 0;
	}

	/// <summary>
	/// Call when a per-item operation finishes.
	/// </summary>
	private void EndItemOperation()
	{
		if (_itemOpsInFlight > 0)
		{
			_itemOpsInFlight--;
		}
		AnyItemOperationInProgress = _itemOpsInFlight > 0;
	}

	/// <summary>
	/// Enables Apply-All if it's currently running (so Cancel remains clickable),
	/// otherwise disables it when Verify-All or Remove-All or any item op is running.
	/// </summary>
	internal bool ComputeApplyAllEnabled(bool isApplyAllBusy, bool isVerifyAllBusy, bool isRemoveAllBusy, bool anyItemBusy)
	{
		bool enabled = isApplyAllBusy || !(isVerifyAllBusy || isRemoveAllBusy || anyItemBusy);
		return enabled;
	}

	/// <summary>
	/// Enables Verify-All if it's currently running (so Cancel remains clickable),
	/// otherwise disables it when Apply-All or Remove-All or any item op is running.
	/// </summary>
	internal bool ComputeVerifyAllEnabled(bool isVerifyAllBusy, bool isApplyAllBusy, bool isRemoveAllBusy, bool anyItemBusy)
	{
		bool enabled = isVerifyAllBusy || !(isApplyAllBusy || isRemoveAllBusy || anyItemBusy);
		return enabled;
	}

	/// <summary>
	/// Enables Remove-All if it's currently running (so Cancel remains clickable),
	/// otherwise disables it when Apply-All or Verify-All or any item op is running.
	/// </summary>
	internal bool ComputeRemoveAllEnabled(bool isRemoveAllBusy, bool isApplyAllBusy, bool isVerifyAllBusy, bool anyItemBusy)
	{
		bool enabled = isRemoveAllBusy || !(isApplyAllBusy || isVerifyAllBusy || anyItemBusy);
		return enabled;
	}

	#endregion


	#region Unified Search and Filteration

	// Function binding for SearchKeyword used by the SearchBox Text binding.
	// Getter returns current VM keyword.
	private string? GetSearchKeyword()
	{
		if (ViewModel is null) return string.Empty;
		return ViewModel.SearchKeyword;
	}

	// BindBack handler for SearchKeyword. Updates VM and runs filter.
	private void SetSearchKeyword(string? value)
	{
		if (_isDisposed || ViewModel is null) return;
		ViewModel.SearchKeyword = value;
		ApplyCombinedFilters();
	}

	/// <summary>
	/// Applies both search and status filters to rebuild the ListViewItemsSource
	/// without duplicating backing data (always uses ViewModel.ListViewItemsSourceBackingField).
	/// </summary>
	private void ApplyCombinedFilters()
	{
		if (ViewModel?.ListViewItemsSourceBackingField == null || _isDisposed)
			return;

		// Rebuild filtered view from the single backing field.
		UnsubscribeFromAllMUnits();

		// Pre-dedicate the max capacity to the list.
		List<GroupInfoListForMUnit> filteredGroups = new(ViewModel.ListViewItemsSourceBackingField.Count);

		foreach (GroupInfoListForMUnit group in ViewModel.ListViewItemsSourceBackingField)
		{
			// Filter items by status toggles and optional search.
			IEnumerable<MUnit> filteredItemsEnum = group.Where(munit =>
				// Status filter
				((munit.StatusState == StatusState.Applied && ViewModel.ShowApplied) ||
				 (munit.StatusState == StatusState.NotApplied && ViewModel.ShowNotApplied) ||
				 (munit.StatusState == StatusState.Undetermined && ViewModel.ShowUndetermined))
				// Search filter
				&& (string.IsNullOrWhiteSpace(ViewModel.SearchKeyword) ||
					(munit.Name?.Contains(ViewModel.SearchKeyword, StringComparison.OrdinalIgnoreCase) ?? false) ||
					(munit.SubCategoryName?.Contains(ViewModel.SearchKeyword, StringComparison.OrdinalIgnoreCase) ?? false) ||
					(munit.URL?.Contains(ViewModel.SearchKeyword, StringComparison.OrdinalIgnoreCase) ?? false)));

			List<MUnit> filteredItems = filteredItemsEnum.ToList();

			if (filteredItems.Count > 0)
			{
				// Create lightweight group wrappers referencing the same MUnit instances.
				filteredGroups.Add(new GroupInfoListForMUnit(filteredItems, group.Key));
			}
		}

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

		// Maintain the rest of the plumbing
		SetUserControlReferenceInMUnits();

		// Restore selection after filtering (only items that match search will be selected)
		RestoreSelectionFromViewModel();

		// Re-subscribe to status changes after filtering
		SubscribeToStatusChanges();

		if (ChildButtonsDisposeOnlyOnExplicitCall)
		{
			TrySetChildExplicitDisposalOptIn();
		}
	}


	// Function binding getters used by x:Bind for the Status Overview checkboxes.
	// Return bool? because CheckBox.IsChecked is nullable.
	// Default to showing all items when VM not ready
	private bool? GetShowApplied() => ViewModel is null || ViewModel.ShowApplied;
	private bool? GetShowNotApplied() => ViewModel is null || ViewModel.ShowNotApplied;
	private bool? GetShowUndetermined() => ViewModel is null || ViewModel.ShowUndetermined;

	// Function binding BindBack handlers. They set the VM property and trigger re-filter only when changed.
	private void SetShowApplied(bool? value)
	{
		if (_isDisposed || ViewModel is null) return;

		bool effective = value == true;
		if (ViewModel.ShowApplied == effective)
		{
			// No change; skip re-filtering work
			return;
		}

		ViewModel.ShowApplied = effective;
		ApplyCombinedFilters();
	}

	private void SetShowNotApplied(bool? value)
	{
		if (_isDisposed || ViewModel is null) return;

		bool effective = value == true;
		if (ViewModel.ShowNotApplied == effective)
		{
			return;
		}

		ViewModel.ShowNotApplied = effective;
		ApplyCombinedFilters();
	}

	private void SetShowUndetermined(bool? value)
	{
		if (_isDisposed || ViewModel is null) return;

		bool effective = value == true;
		if (ViewModel.ShowUndetermined == effective)
		{
			return;
		}

		ViewModel.ShowUndetermined = effective;
		ApplyCombinedFilters();
	}

	#endregion

	#region Export to JSON

	/// <summary>
	/// Exports all of the security measures that belong to the current category to a JSON file.
	/// </summary>
	internal async void ExportToJson_Click(object sender, RoutedEventArgs e)
	{
		if (_isDisposed || ViewModel is null)
		{
			return;
		}

		try
		{
			if (ViewModel.ListViewItemsSourceBackingField.Count == 0)
			{
				ViewModel.MainInfoBar.WriteWarning(GlobalVars.GetStr("NoVerificationResultsToExport"));
				return;
			}

			ViewModel.ElementsAreEnabled = false;
			ViewModel.MainInfoBar.IsClosable = false;

			// Flatten the groups into a single list
			List<MUnit> itemsToExport = [];
			foreach (GroupInfoListForMUnit group in ViewModel.ListViewItemsSourceBackingField)
			{
				foreach (MUnit m in group)
				{
					itemsToExport.Add(m);
				}
			}

			if (itemsToExport.Count == 0)
			{
				ViewModel.MainInfoBar.WriteWarning(GlobalVars.GetStr("NoVerificationResultsToExport"));
				return;
			}

			DateTime now = DateTime.Now;
			string defaultFileName = $"Security Measures {now:yyyy-MM-dd_HH-mm-ss}.json";

			string? savePath = FileDialogHelper.ShowSaveFileDialog(GlobalVars.JSONPickerFilter, defaultFileName);
			if (string.IsNullOrWhiteSpace(savePath))
			{
				return;
			}

			await Task.Run(() =>
			{
				string json = MUnitJsonContext.SerializeList(itemsToExport);
				File.WriteAllText(savePath, json, Encoding.UTF8);
			});

			ViewModel.MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyExportedVerificationResults"), itemsToExport.Count, savePath));
		}
		catch (Exception ex)
		{
			ViewModel.MainInfoBar.WriteError(ex);
		}
		finally
		{
			ViewModel.ElementsAreEnabled = true;
			ViewModel.MainInfoBar.IsClosable = true;
		}
	}

	#endregion

}
