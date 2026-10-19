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
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using AppControlManager.Others;
using CommonCore.GroupPolicy;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using HardenSystemSecurity.Traverse;
using HardenSystemSecurity.WindowComponents;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.UI;
using WinRT;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// UserControl that hosts the grouped ListView of MUnits plus command bar.
/// </summary>
internal sealed partial class MUnitListViewControl : UserControl, IDisposable
{
	private CommonCore.AppSettings.Main AppSettings => Atlas.Settings;

	internal MUnitListViewControl() => InitializeComponent();

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
	private void MUnitListViewControl_Loaded()
	{
		// Set the initial value and configure the panel
		ConfigureItemsStackPanel();

		ApplyCombinedFilters();

		// Ensure status counts are available immediately for the flyout numbers
		UpdateStatusCounts();

		// Check global pending navigation target
		CheckForPendingNavigationHighlight();

		// Subscribe to AppSettings property changes when control is loaded
		AppSettings.PropertyChanged -= AppSettings_PropertyChanged; // Ensure no duplicate subscription
		AppSettings.PropertyChanged += AppSettings_PropertyChanged;

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
		if (string.Equals(e.PropertyName, nameof(AppSettings.StickyHeadersForListViews), StringComparison.Ordinal))
		{
			// Update the ItemsStackPanel when the setting changes
			ConfigureItemsStackPanel();
		}
	}

	/// <summary>
	/// Configures the ItemsStackPanel with the current AppSettings value
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(ItemsStackPanel))]
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
			// Check global pending navigation target when ViewModel is set
			control.CheckForPendingNavigationHighlight();
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

			// Check global pending navigation target when Data changes
			control.CheckForPendingNavigationHighlight();

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
		IMUnitListViewModel.ComputeStatusCounts(ViewModel);
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
	private void SelectAllMenuFlyoutItem_Click()
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
	private void RemoveSelectionsMenuFlyoutItem_Click()
	{
		if (_isDisposed) return;
		MainListView.SelectedItems.Clear();
	}

	/// <summary>
	/// Event handler for the SelectionChanged event of the ListView.
	/// Triggered by <see cref="SelectAllMenuFlyoutItem_Click(object, RoutedEventArgs)"/> and <see cref="RemoveSelectionsMenuFlyoutItem_Click(object, RoutedEventArgs)"/> to keep things consistent.
	/// </summary>
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
	internal async void ApplyMUnit(MUnit mUnit) => await ProcessSingleMUnit(mUnit, MUnitOperation.Apply);

	/// <summary>
	/// Remove a single MUnit
	/// </summary>
	/// <param name="mUnit">The MUnit to remove</param>
	internal async void RemoveMUnit(MUnit mUnit) => await ProcessSingleMUnit(mUnit, MUnitOperation.Remove);

	/// <summary>
	/// Verify a single MUnit
	/// </summary>
	/// <param name="mUnit">The MUnit to verify</param>
	internal async void VerifyMUnit(MUnit mUnit) => await ProcessSingleMUnit(mUnit, MUnitOperation.Verify);

	/// <summary>
	/// Shared implementation of <see cref="ApplyMUnit"/>, <see cref="RemoveMUnit"/> and <see cref="VerifyMUnit"/>.
	/// </summary>
	/// <param name="mUnit">The MUnit to process</param>
	/// <param name="operation">The operation to perform on the MUnit</param>
	private async Task ProcessSingleMUnit(MUnit mUnit, MUnitOperation operation)
	{
		// If the UI is loading the ViewModel will be null initially due to x:Bind usage, so this check ensures ProcessMUnitsWithBulkOperations method always receives a valid ViewModel reference.
		if (ViewModel is null || _isDisposed) return;

		try
		{
			// Remove and Verify are skipped for MUnits that don't have the corresponding strategy.
			if (!HasStrategyFor(mUnit, operation))
				return;

			// Mark a per-item operation as running so the "All" animated buttons disable themselves.
			BeginItemOperation();

			await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, [mUnit], operation);
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
	/// Whether the MUnit has the strategy required by the operation.
	/// Remove and Verify require their own strategies, Apply is always allowed.
	/// </summary>
	/// <param name="mUnit">The MUnit to check</param>
	/// <param name="operation">The operation to check for</param>
	private static bool HasStrategyFor(MUnit mUnit, MUnitOperation operation) => operation switch
	{
		MUnitOperation.Remove => mUnit.RemoveStrategy is not null,
		MUnitOperation.Verify => mUnit.VerifyStrategy is not null,
		_ => true
	};

	#endregion

	#region Bulk Operations

	/// <summary>
	/// Handles the F5 keyboard accelerator to verify all MUnits or cancel an ongoing verification.
	/// </summary>
	private void VerifyAllAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		args.Handled = true;

		if (_isDisposed || ViewModel is null) return;

		// If the verification is currently running, pressing F5 should cancel it
		if (ViewModel.VerifyAllCancellableButton.IsOperationInProgress)
		{
			_ = ViewModel.VerifyAllCancellableButton.Cancel();
			return;
		}

		// Check if we are allowed to verify by checking the states of all overlapping button rules
		bool isEnabled = ComputeVerifyAllEnabled(
			ViewModel.VerifyAllCancellableButton.IsOperationInProgress,
			ViewModel.ApplyAllCancellableButton.IsOperationInProgress,
			ViewModel.RemoveAllCancellableButton.IsOperationInProgress,
			AnyItemOperationInProgress);

		// Proceed only if no other blocking operation is actively running
		if (isEnabled && ViewModel.ElementsAreEnabled)
		{
			VerifyAllMUnits();
		}
	}

	/// <summary>
	/// Apply all MUnits.
	/// </summary>
	internal async void ApplyAllMUnits() => await ProcessAllMUnits(
		MUnitOperation.Apply,
		"ApplyingAllSecurityMeasures",
		"ApplyOperationCancelledByUser",
		"ApplyingAllSecurityMeasuresSuccessful");

	/// <summary>
	/// Remove all MUnits.
	/// </summary>
	internal async void RemoveAllMUnits() => await ProcessAllMUnits(
		MUnitOperation.Remove,
		"RemovingAllSecurityMeasures",
		"RemoveOperationCancelledByUser",
		"RemovingAllSecurityMeasuresSuccessful");

	/// <summary>
	/// Verify all MUnits.
	/// </summary>
	internal async void VerifyAllMUnits() => await ProcessAllMUnits(
		MUnitOperation.Verify,
		"VerifyingAllSecurityMeasures",
		"VerifyOperationCancelledByUser",
		"VerifyingAllSecurityMeasuresSuccessful");

	/// <summary>
	/// Shared implementation of <see cref="ApplyAllMUnits"/>, <see cref="RemoveAllMUnits"/> and <see cref="VerifyAllMUnits"/>.
	/// </summary>
	/// <param name="operation">The operation to perform on the MUnits</param>
	/// <param name="startedMsgKey">Resource key of the message displayed when the operation starts</param>
	/// <param name="cancelledMsgKey">Resource key of the message displayed when the operation is cancelled</param>
	/// <param name="successMsgKey">Resource key of the message displayed when the operation succeeds</param>
	private async Task ProcessAllMUnits(MUnitOperation operation, string startedMsgKey, string cancelledMsgKey, string successMsgKey)
	{
		if (ViewModel is null || _isDisposed) return;

		AnimatedCancellableButtonInitializer button = operation switch
		{
			MUnitOperation.Apply => ViewModel.ApplyAllCancellableButton,
			MUnitOperation.Remove => ViewModel.RemoveAllCancellableButton,
			_ => ViewModel.VerifyAllCancellableButton
		};

		bool errorsOccurred = false;

		button.Begin();

		using IDisposable taskTracker = TaskTracking.RegisterOperation();

		try
		{
			ViewModel.ElementsAreEnabled = false;
			ViewModel.MainInfoBar.WriteInfo(Atlas.GetStr(startedMsgKey));

			List<MUnit> allMUnits = [];
			foreach (GroupInfoListForMUnit group in ListViewItemsSource)
			{
				foreach (MUnit mUnit in group)
				{
					// Only include MUnits whose sub-category is null for Apply All
					// Because user might not be expecting to apply the more extreme sub-categories when using the "Apply All" button.
					// For Remove All and Verify All, only include MUnits that have the corresponding strategy.
					bool include = operation is MUnitOperation.Apply ? mUnit.SubCategory is null : HasStrategyFor(mUnit, operation);

					if (include)
					{
						allMUnits.Add(mUnit);
					}
				}
			}
			await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, allMUnits, operation, button.Cts?.Token);
		}
		catch (Exception ex)
		{
			ViewModelBase.HandleExceptions(ex, ref errorsOccurred, ref button.wasCancelled, ViewModel.MainInfoBar);
		}
		finally
		{
			if (button.wasCancelled)
			{
				ViewModel.MainInfoBar.WriteWarning(Atlas.GetStr(cancelledMsgKey));
			}
			else if (!errorsOccurred)
			{
				ViewModel.MainInfoBar.WriteSuccess(Atlas.GetStr(successMsgKey));
			}

			button.End();
			ViewModel.ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Apply only the selected MUnits.
	/// </summary>
	private async void ApplySelectedMUnits() => await ProcessSelectedMUnits(MUnitOperation.Apply);

	/// <summary>
	/// Remove only the selected MUnits.
	/// </summary>
	private async void RemoveSelectedMUnits() => await ProcessSelectedMUnits(MUnitOperation.Remove);

	/// <summary>
	/// Verify only the selected MUnits.
	/// </summary>
	private async void VerifySelectedMUnits() => await ProcessSelectedMUnits(MUnitOperation.Verify);

	/// <summary>
	/// Shared implementation of <see cref="ApplySelectedMUnits"/>, <see cref="RemoveSelectedMUnits"/> and <see cref="VerifySelectedMUnits"/>.
	/// </summary>
	/// <param name="operation">The operation to perform on the selected MUnits</param>
	private async Task ProcessSelectedMUnits(MUnitOperation operation)
	{
		if (_isDisposed) return;

		try
		{
			if (ViewModel?.ItemsSourceSelectedItems != null)
			{
				// Apply uses the selected MUnits as they are.
				// Remove and Verify only include the selected MUnits that have the corresponding strategy.
				List<MUnit> selectedMUnits = ViewModel.ItemsSourceSelectedItems;
				if (operation is not MUnitOperation.Apply)
				{
					selectedMUnits = [];
					foreach (MUnit mUnit in ViewModel.ItemsSourceSelectedItems)
					{
						if (HasStrategyFor(mUnit, operation))
						{
							selectedMUnits.Add(mUnit);
						}
					}
				}

				if (selectedMUnits.Count > 0)
				{
					await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, selectedMUnits, operation);
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
	private void MUnitListViewControl_Unloaded()
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

		// Stop any active highlight animation to clean up timer
		StopHighlightAnimation();

		// Unsubscribe from AppSettings property changes
		AppSettings.PropertyChanged -= AppSettings_PropertyChanged;

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
	internal static bool ComputeApplyAllEnabled(bool isApplyAllBusy, bool isVerifyAllBusy, bool isRemoveAllBusy, bool anyItemBusy)
	{
		bool enabled = isApplyAllBusy || !(isVerifyAllBusy || isRemoveAllBusy || anyItemBusy);
		return enabled;
	}

	/// <summary>
	/// Enables Verify-All if it's currently running (so Cancel remains clickable),
	/// otherwise disables it when Apply-All or Remove-All or any item op is running.
	/// </summary>
	internal static bool ComputeVerifyAllEnabled(bool isVerifyAllBusy, bool isApplyAllBusy, bool isRemoveAllBusy, bool anyItemBusy)
	{
		bool enabled = isVerifyAllBusy || !(isApplyAllBusy || isRemoveAllBusy || anyItemBusy);
		return enabled;
	}

	/// <summary>
	/// Enables Remove-All if it's currently running (so Cancel remains clickable),
	/// otherwise disables it when Apply-All or Verify-All or any item op is running.
	/// </summary>
	internal static bool ComputeRemoveAllEnabled(bool isRemoveAllBusy, bool isApplyAllBusy, bool isVerifyAllBusy, bool anyItemBusy)
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

		foreach (GroupInfoListForMUnit group in CollectionsMarshal.AsSpan(ViewModel.ListViewItemsSourceBackingField))
		{
			// Filter items by status toggles and optional search.
			List<MUnit> filteredItems = group.Where(munit =>
				// Status filter
				((munit.StatusState == StatusState.Applied && ViewModel.ShowApplied) ||
				 (munit.StatusState == StatusState.NotApplied && ViewModel.ShowNotApplied) ||
				 (munit.StatusState == StatusState.Undetermined && ViewModel.ShowUndetermined))
				// Search filter
				&& (string.IsNullOrWhiteSpace(ViewModel.SearchKeyword) ||
					(munit.Name?.Contains(ViewModel.SearchKeyword, StringComparison.OrdinalIgnoreCase) ?? false) ||
					(munit.SubCategoryName?.Contains(ViewModel.SearchKeyword, StringComparison.OrdinalIgnoreCase) ?? false) ||
					(munit.URL?.Contains(ViewModel.SearchKeyword, StringComparison.OrdinalIgnoreCase) ?? false))).ToList();

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
	internal async void ExportToJson_Click()
	{
		if (_isDisposed || ViewModel is null)
		{
			return;
		}

		try
		{
			ViewModel.ElementsAreEnabled = false;
			ViewModel.MainInfoBar.IsClosable = false;

			string? savePath = FileDialogHelper.ShowSaveFileDialog(Atlas.JSONPickerFilter, Generator.GetFileName());
			if (string.IsNullOrEmpty(savePath))
				return;

			// Get the up to date data for the current category
			(int Score, List<MUnit> Items) =
				await Generator.VerifyAndSnapshotMUnitCategoryAsync(ViewModel, System.Threading.CancellationToken.None);

			await Task.Run(() =>
			{
				// Build a traverse container with only this category populated and write directly to file
				MContainer container = BuildSingleCategoryContainer(Score, Items);

				MContainerJsonContext.SerializeSingle(container, savePath);
			});

			ViewModel.MainInfoBar.WriteSuccess(string.Format(Atlas.GetStr("SuccessfullyExportedVerificationResults"), Items.Count, savePath));
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

	/// <summary>
	/// Builds an MContainer with only the current category populated, others are null.
	/// </summary>
	private static MContainer BuildSingleCategoryContainer(int score, List<MUnit> items)
	{
		int total = items.Count;
		int compliant = score;
		int nonCompliant = total - score;

		// Detect category
		Categories category = items[0].Category;

		// Initialize all category objects as null initially.
		MicrosoftDefender? microsoftDefender = null;
		BitLockerSettings? bitLockerSettings = null;
		TLSSecurity? tlsSecurity = null;
		LockScreen? lockScreen = null;
		UserAccountControl? userAccountControl = null;
		DeviceGuard? deviceGuard = null;
		WindowsFirewall? windowsFirewall = null;
		WindowsNetworking? windowsNetworking = null;
		MiscellaneousConfigurations? miscellaneousConfigurations = null;
		WindowsUpdateConfigurations? windowsUpdateConfigurations = null;
		EdgeBrowserConfigurations? edgeBrowserConfigurations = null;
		NonAdminCommands? nonAdminCommands = null;
		MSFTSecBaselines_OptionalOverrides? overrides = null;

		switch (category)
		{
			case Categories.MicrosoftDefender:
				microsoftDefender = new(items) { Score = score };
				break;
			case Categories.BitLockerSettings:
				bitLockerSettings = new(items) { Score = score };
				break;
			case Categories.TLSSecurity:
				tlsSecurity = new(items) { Score = score };
				break;
			case Categories.LockScreen:
				lockScreen = new(items) { Score = score };
				break;
			case Categories.UserAccountControl:
				userAccountControl = new(items) { Score = score };
				break;
			case Categories.DeviceGuard:
				deviceGuard = new(items) { Score = score };
				break;
			case Categories.WindowsFirewall:
				windowsFirewall = new(items) { Score = score };
				break;
			case Categories.WindowsNetworking:
				windowsNetworking = new(items) { Score = score };
				break;
			case Categories.MiscellaneousConfigurations:
				miscellaneousConfigurations = new(items) { Score = score };
				break;
			case Categories.WindowsUpdateConfigurations:
				windowsUpdateConfigurations = new(items) { Score = score };
				break;
			case Categories.EdgeBrowserConfigurations:
				edgeBrowserConfigurations = new(items) { Score = score };
				break;
			case Categories.NonAdminCommands:
				nonAdminCommands = new(items) { Score = score };
				break;
			case Categories.MSFTSecBaselines_OptionalOverrides:
				overrides = new(items) { Score = score };
				break;
			case Categories.MicrosoftSecurityBaseline:
			case Categories.Microsoft365AppsSecurityBaseline:
			case Categories.AttackSurfaceReductionRules:
			case Categories.OptionalWindowsFeatures:
			case Categories.CertificateChecking:
			case Categories.CountryIPBlocking:
			default:
				break;
		}

		return new(
			total: total,
			compliant: compliant,
			nonCompliant: nonCompliant,
			microsoftDefender: microsoftDefender,
			bitLockerSettings: bitLockerSettings,
			tlsSecurity: tlsSecurity,
			lockScreen: lockScreen,
			userAccountControl: userAccountControl,
			deviceGuard: deviceGuard,
			windowsFirewall: windowsFirewall,
			windowsNetworking: windowsNetworking,
			miscellaneousConfigurations: miscellaneousConfigurations,
			windowsUpdateConfigurations: windowsUpdateConfigurations,
			edgeBrowserConfigurations: edgeBrowserConfigurations,
			nonAdminCommands: nonAdminCommands,
			msftSecBaselines_OptionalOverrides: overrides
		);
	}

	#endregion

	#region Scrolling and Highlighting Logic

	/// <summary>
	/// Checks for a pending navigation target in the global NavigationService state.
	/// If one exists and belongs to the current data set, scrolls to and highlights it.
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(ListViewItem))]
	private void CheckForPendingNavigationHighlight()
	{
		if (_isDisposed) return;
		if (NavigationService.PendingNavigationTargetId == null) return;

		if (ViewModel == null) return;
		if (ListViewItemsSource == null || ListViewItemsSource.Count == 0) return;
		if (!IsLoaded) return;

		MUnit? targetMUnit = null;
		foreach (GroupInfoListForMUnit group in ListViewItemsSource)
		{
			targetMUnit = group.FirstOrDefault(static m => m.ID == NavigationService.PendingNavigationTargetId.Value);
			if (targetMUnit != null)
				break;
		}

		if (targetMUnit == null) return;

		// Null it after we found the target
		NavigationService.PendingNavigationTargetId = null;

		try
		{
			// Scroll to the item
			MainListView.ScrollIntoView(targetMUnit, ScrollIntoViewAlignment.Leading);

			MainListView.UpdateLayout(); // Force synchronous layout pass

			ListViewItem? container = MainListView.ContainerFromItem(targetMUnit) as ListViewItem;
			if (container == null) return;

			Border? targetBorder = FindVisualChild<Border>(container, "ItemRootBorder");
			if (targetBorder != null)
			{
				StartHighlightAnimation(targetBorder);
			}
		}
		catch { }
	}

	/// <summary>
	/// Helper to find a child element by name in the visual tree.
	/// </summary>
	private static T? FindVisualChild<T>(DependencyObject parent, string childName) where T : FrameworkElement
	{
		int childCount = VisualTreeHelper.GetChildrenCount(parent);
		for (int i = 0; i < childCount; i++)
		{
			DependencyObject child = VisualTreeHelper.GetChild(parent, i);
			if (child is T element && element.Name == childName)
			{
				return element;
			}

			T? result = FindVisualChild<T>(child, childName);
			if (result != null)
				return result;
		}
		return null;
	}

	// Animation State
	private Storyboard? _highlightStoryboard;
	private Border? _currentHighlightedElement;
	private Brush? _originalBackgroundBrush;

	// Using HighlightColor for the "Pulse"
	private static readonly Color HighlightColor = Color.FromArgb(255, 138, 43, 226); // Violet

	[DynamicWindowsRuntimeCast(typeof(SolidColorBrush))]
	private void StartHighlightAnimation(Border target)
	{
		StopHighlightAnimation();

		_currentHighlightedElement = target;
		_originalBackgroundBrush = target.Background; // Capture original brush

		// Extract the color from the current brush
		Color targetColor = ((SolidColorBrush)_originalBackgroundBrush).Color;

		// Prepare the border for animation by setting a new SolidColorBrush with the Start color.
		target.Background = new SolidColorBrush(HighlightColor);

		// Animate from Violet -> Original Color.
		Microsoft.UI.Xaml.Media.Animation.ColorAnimation colorAnimation = new()
		{
			From = HighlightColor,
			To = targetColor,
			Duration = new Duration(TimeSpan.FromSeconds(2)),
			EnableDependentAnimation = true
		};

		Storyboard.SetTarget(colorAnimation, target.Background);
		Storyboard.SetTargetProperty(colorAnimation, "Color");

		_highlightStoryboard = new();
		_highlightStoryboard.Children.Add(colorAnimation);

		// When done, restore the original brush object (which might be a ThemeResource).
		_highlightStoryboard.Completed += (s, e) =>
		{
			if (_currentHighlightedElement != null && _originalBackgroundBrush != null)
			{
				_currentHighlightedElement.Background = _originalBackgroundBrush;
			}
			StopHighlightAnimation();
		};

		_highlightStoryboard.Begin();
	}

	private void StopHighlightAnimation()
	{
		_highlightStoryboard?.Stop();
		_highlightStoryboard = null;
		// If we are stopping prematurely, we should also restore the brush if possible
		if (_currentHighlightedElement != null && _originalBackgroundBrush != null)
		{
			_currentHighlightedElement.Background = _originalBackgroundBrush;
		}

		_currentHighlightedElement = null;
		_originalBackgroundBrush = null;
	}

	#endregion

}
