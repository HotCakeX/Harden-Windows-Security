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
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using AppControlManager.Others;
using CommonCore.GroupPolicy;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media.Imaging;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class ProtectVM : ViewModelBase
{
	internal ProtectVM()
	{
		_ = IsVM(); // Do not wait

		// Initialize cancellable buttons for Presets section
		ApplySelectedCancellableButton = new(Atlas.GetStr("ApplySelectedMenuFlyoutItem/Text"));
		RemoveSelectedCancellableButton = new(Atlas.GetStr("RemoveSelectedMenuFlyoutItem/Text"));
		VerifySelectedCancellableButton = new(Atlas.GetStr("VerifySelectedMenuFlyoutItem/Text"));

		// Initialize cancellable buttons for Device Usage Intents section
		ApplyIntentsCancellableButton = new(Atlas.GetStr("ApplyText/Text"));

		// Initial protections category population
		ProtectionCategoriesListItemsSource = new(GenerateCategories(ProtectionPresetsSelectedIndex));
		SelectAllItemsInListView();
	}

	/// <summary>
	/// Used to track if running in a VM so we can check/uncheck the <see cref="SubCategories.OptionalWindowsFeatures_IncludeEnablements"/>
	/// Whenever the <see cref="GenerateCategories"/> method recreates the categories/subcategories.
	/// </summary>
	private volatile bool IsSystemVM;

	/// <summary>
	/// Determines if running in a VM and if so, unchecks the enablements for the <see cref="SubCategories.OptionalWindowsFeatures_IncludeEnablements"/> since they enable virtualization-based features.
	/// </summary>
	private async Task IsVM()
	{
		await Task.Run(() =>
		{
			try
			{
				string result = QuantumRelayHSS.Client.RunCommand(Atlas.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpComputerStatus IsVirtualMachine");
				if (bool.TryParse(result, out bool actualResult))
				{
					// Apply the changes to the checkbox immediately without waiting for user to use ComboBox to switch between presets.
					_ = Atlas.AppDispatcher.TryEnqueue(() =>
					{
						foreach (ProtectionCategoryListViewItem item in ProtectionCategoriesListItemsSource)
						{
							if (item.Category == Categories.OptionalWindowsFeatures)
							{
								foreach (SubCategoryDefinition sub in item.SubCategories)
								{
									if (sub.SubCategory == SubCategories.OptionalWindowsFeatures_IncludeEnablements)
									{
										sub.IsChecked = !actualResult;
									}
								}
							}
						}
					});

					IsSystemVM = actualResult;
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		});
	}

	/// <summary>
	/// The protection presets source for the ComboBox with ratings.
	/// </summary>
	internal readonly List<ProtectionPresetComboBoxType> ProtectionPresetsSource =
	[
		new ProtectionPresetComboBoxType(Atlas.GetStr("BasicProtectionPresetComboBoxItemText"), 1),
		new ProtectionPresetComboBoxType(Atlas.GetStr("RecommendedProtectionPresetComboBoxItemText"), 3),
		new ProtectionPresetComboBoxType(Atlas.GetStr("CompleteProtectionPresetComboBoxItemText"), 5)
	];

	/// <summary>
	/// The order of these must match the order of the Categories Enum.
	/// </summary>
	private readonly BitmapImage[] CategoryImages = [
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/Microsoft-Security-Baseline.png")),
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/Microsoft-365-Apps-Security-Baselines.png")),
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/WindowsDefender.png")),
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/ASRrules.png")),
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/Bitlocker.png")), // 4
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/TLS.png")), // 5
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/LockScreen.png")),
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/UAC.png")), // 7
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/DeviceGuard.png")), // 8
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/Firewall.png")), // 9
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/OptionalFeatures.png")), // 10
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/Networking.png")), // 11
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/MiscellaneousCommands.png")), // 12
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/WindowsUpdate.png")), // 13
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/EdgeBrowser.png")), // 14
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/Certificate.png")), // 15
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/CountryIPBlocking.png")), // 16
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/NonAdmin.png")), // 17
		new(new("ms-appx:///Assets/ProtectionCategoriesIcons/MicrosoftBaseLinesOverrides.png")) // 18
	];

	/// <summary>
	/// The MUnits that match currently selected device intent and used as ItemsSource of the ListView that displays them.
	/// Items in this collection are just for displaying purposes and the <see cref="MUnit"/>s displayed there are not actually used anywhere except for getting their distinct list of categories.
	/// The <see cref="MUnitCategoryProcessor"/> and <see cref="CategoryProcessorFactory"/> are responsible for identifying, filtering and applying the applicable MUnits/Non-MUnit security measures.
	/// </summary>
	internal readonly ObservableCollection<MUnit> DeviceIntentMUnitsPreview = [];

	/// <summary>
	/// Backing list field for <see cref="DeviceIntentMUnitsPreview"/>.
	/// </summary>
	private readonly List<MUnit> AllDeviceIntentMUnitsPreview = [];

	/// <summary>
	/// Search keyword for <see cref="DeviceIntentMUnitsPreview"/> items.
	/// </summary>
	internal string? SearchKeyword
	{
		get; set
		{
			if (SPT(ref field, value))
				SearchBox_TextChanged();
		}
	}

	/// <summary>
	/// Selected Device Intent on the GridView.
	/// </summary>
	internal IntentItem? SelectedDeviceIntent
	{
		get; set
		{
			if (SP(ref field, value))
				RecomputeDeviceIntentsPreview();
		}
	}

	/// <summary>
	/// Cache of all MUnits across categories (built once on first use)
	/// </summary>
	private List<MUnit>? _allMUnitsAcrossCategoriesCache;

	internal AnimatedCancellableButtonInitializer ApplyIntentsCancellableButton { get; }

	/// <summary>
	/// Event handler for when text changes for searching among the <see cref="DeviceIntentMUnitsPreview"/> items.
	/// </summary>
	internal void SearchBox_TextChanged()
	{
		string? searchTerm = SearchKeyword?.Trim();

		if (searchTerm is null)
			return;

		// Perform a case-insensitive search across relevant MUnit fields
		List<MUnit> filteredResults = AllDeviceIntentMUnitsPreview.Where(m =>
			(m.Name is not null && m.Name.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(m.SubCategoryName is not null && m.SubCategoryName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			((m.Category.ToString()?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ?? false) ||
			(m.URL is not null && m.URL.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
		).ToList();

		DeviceIntentMUnitsPreview.Clear();

		for (int i = 0; i < filteredResults.Count; i++)
		{
			DeviceIntentMUnitsPreview.Add(filteredResults[i]);
		}
	}

	/// <summary>
	/// This is invoked from the ListView item's context menu (Tag carries the bound MUnit).
	/// Deletes a single MUnit from both the preview ObservableCollection and its backing list.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void DeleteDeviceIntentPreviewItem_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		MUnit mUnit = (MUnit)menuItem.Tag;

		// Remove from UI-bound collection
		_ = DeviceIntentMUnitsPreview.Remove(mUnit);

		// Remove from backing list so the item won't reappear due to filter changes
		_ = AllDeviceIntentMUnitsPreview.Remove(mUnit);
	}

	/// <summary>
	/// Swipe Control's delete action event handler to delete an item from the ListView.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	internal void DeleteDeviceIntentPreviewItem_SwipeInvoked(SwipeItem sender, SwipeItemInvokedEventArgs args)
	{
		// Resolve the bound item (MUnit) from the SwipeControl that raised the event
		FrameworkElement contentElement = (FrameworkElement)args.SwipeControl.Content;
		MUnit mUnit = (MUnit)contentElement.DataContext;

		_ = DeviceIntentMUnitsPreview.Remove(mUnit);
		_ = AllDeviceIntentMUnitsPreview.Remove(mUnit);
	}

	/// <summary>
	/// Event handler for the UI button.
	/// </summary>
	internal async void ApplySelectedDeviceIntents() => await ApplySelectedDeviceIntents_Internal();

	/// <summary>
	/// Apply all previewed MUnits grouped by category, using category processors and passing selected intent.
	/// No cancellation implemented yet.
	/// i.e.,: this method collects distinct categories from the previews, then calls <see cref="CategoryProcessorFactory.GetProcessor"/> for each category and passes selectedIntent.
	/// </summary>
	private async Task ApplySelectedDeviceIntents_Internal()
	{
		// Nothing to apply if the preview is empty
		if (DeviceIntentMUnitsPreview.Count == 0)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("NoDeviceIntentSelectedOrNoMatchingItemsToApply"));
			return;
		}

		// If no intent selected, warn and bail
		if (SelectedDeviceIntent is null)
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("NoDeviceIntentSelectedOrNoMatchingItemsToApply"));
			return;
		}

		// Begin animated button lifecycle
		ApplyIntentsCancellableButton.Begin();

		try
		{
			// Disable non-cancellable UI while the operation runs
			ElementsAreEnabled = false;

			// Gate other animated buttons and enable only this one
			CurrentRunningOperation = RunningOperation.ApplyIntents;

			// Get distinct categories present in the unfiltered backing preview and enforce execution order
			List<Categories> categories = AllDeviceIntentMUnitsPreview
				.Select(m => m.Category)
				.Distinct()
				.OrderBy(CategoryProcessorFactory.GetExecutionPriority)
				.ToList();

			int totalCategoriesProcessed = 0;

			MainInfoBar.WriteInfo($"Applying {AllDeviceIntentMUnitsPreview.Count} security measures for selected device intent...");

			// Process each category with cancellation support
			for (int i = 0; i < categories.Count; i++)
			{
				ApplyIntentsCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				Categories cat = categories[i];
				ICategoryProcessor processor = CategoryProcessorFactory.GetProcessor(cat);

				MainInfoBar.WriteInfo($"Applying category {i + 1}/{categories.Count}: {processor.CategoryDisplayName}");

				// Using the category processor like Presets, but we pass the selected intents.
				await processor.ApplyAllAsync(
					selectedSubCategories: null,
					selectedIntent: SelectedDeviceIntent.Intent,
					cancellationToken: ApplyIntentsCancellableButton.Cts?.Token);

				totalCategoriesProcessed++;
			}

			MainInfoBar.WriteSuccess($"Successfully applied security measures for {totalCategoriesProcessed} categories.");
		}
		catch (OperationCanceledException)
		{
			// Mark cancellation and inform the user
			ApplyIntentsCancellableButton.wasCancelled = true;
			MainInfoBar.WriteWarning(Atlas.GetStr("ApplyOperationCancelledByUser"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			// End animated button lifecycle and re-enable UI
			ApplyIntentsCancellableButton.End();

			// Clear gating state and re-enable other buttons
			CurrentRunningOperation = RunningOperation.None;

			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Recompute the preview list from the <see cref="SelectedDeviceIntent"/>.
	/// - Includes items with <see cref="HardenSystemSecurity.DeviceIntents.Intent.All"/> whenever an intent is selected.
	/// - Includes any MUnit intersecting the selected intents.
	/// </summary>
	private void RecomputeDeviceIntentsPreview()
	{
		// Ensure cache is built
		_allMUnitsAcrossCategoriesCache ??= BuildAllMUnitsAcrossCategories();

		// If nothing selected, clear both the backing list and the UI-bound collection, then return
		if (SelectedDeviceIntent is null)
		{
			AllDeviceIntentMUnitsPreview.Clear();
			DeviceIntentMUnitsPreview.Clear();
			return;
		}

		// Build a new preview from the cache
		List<MUnit> newPreview = new(_allMUnitsAcrossCategoriesCache.Count);

		for (int i = 0; i < _allMUnitsAcrossCategoriesCache.Count; i++)
		{
			MUnit m = _allMUnitsAcrossCategoriesCache[i];

			// Include Intent.All
			bool include = m.DeviceIntents.Contains(Intent.All);

			// Or include if intersects with any selected intent
			if (!include)
			{
				for (int j = 0; j < m.DeviceIntents.Count; j++)
				{
					if (SelectedDeviceIntent.Intent == m.DeviceIntents[j])
					{
						include = true;
						break;
					}
				}
			}

			if (include)
			{
				newPreview.Add(m);
			}
		}

		// Populate backing list first
		AllDeviceIntentMUnitsPreview.Clear();
		for (int i = 0; i < newPreview.Count; i++)
		{
			AllDeviceIntentMUnitsPreview.Add(newPreview[i]);
		}

		// If there's no active search, show all items; otherwise, apply the filter
		if (string.IsNullOrEmpty(SearchKeyword))
		{
			DeviceIntentMUnitsPreview.Clear();
			for (int i = 0; i < AllDeviceIntentMUnitsPreview.Count; i++)
			{
				DeviceIntentMUnitsPreview.Add(AllDeviceIntentMUnitsPreview[i]);
			}
		}
		else
		{
			SearchBox_TextChanged();
		}
	}

	// Builds a one-time cache of all MUnits across categories for device-intents preview.
	// - Uses proxies for non-MUnit-based categories/VMs so they appear in the preview.
	private List<MUnit> BuildAllMUnitsAcrossCategories()
	{
		List<MUnit> result = new(capacity: 512);

		// The preview matches what processors apply
		result.AddRange(ViewModelProvider.MicrosoftBaseLinesOverridesVM.AllMUnits);
		result.AddRange(ViewModelProvider.MicrosoftDefenderVM.AllMUnits);
		result.AddRange(ViewModelProvider.BitLockerVM.AllMUnits);
		result.AddRange(ViewModelProvider.TLSVM.AllMUnits);
		result.AddRange(ViewModelProvider.LockScreenVM.AllMUnits);
		result.AddRange(ViewModelProvider.UACVM.AllMUnits);
		result.AddRange(ViewModelProvider.DeviceGuardVM.AllMUnits);
		result.AddRange(ViewModelProvider.WindowsFirewallVM.AllMUnits);
		result.AddRange(ViewModelProvider.WindowsNetworkingVM.AllMUnits);
		result.AddRange(ViewModelProvider.MiscellaneousConfigsVM.AllMUnits);
		result.AddRange(ViewModelProvider.WindowsUpdateVM.AllMUnits);
		result.AddRange(ViewModelProvider.EdgeVM.AllMUnits);
		result.AddRange(ViewModelProvider.NonAdminVM.AllMUnits);

		List<Intent> intentsForBaselinesAndOptional = [
			Intent.Business,
			Intent.SpecializedAccessWorkstation,
			Intent.PrivilegedAccessWorkstation
		];

		// Microsoft Security Baseline proxy
		// - Appears in preview when any of the three intents defined above is selected.
		// - Real application is performed via CategoryProcessorFactory (by category),
		//   so the strategy here is intentionally a no-op.
		MUnit msSecurityBaselineProxy = new(
			category: Categories.MicrosoftSecurityBaseline,
			name: Atlas.GetStr("ProtectCategory_MSFTSecBaseline"),
			deviceIntents: intentsForBaselinesAndOptional,
			applyStrategy: new DefaultApply(() => { /* no-op: applied via category processor in intents flow */ }),
			verifyStrategy: null,
			removeStrategy: null,
			subCategory: null,
			url: "https://www.microsoft.com/en-us/download/details.aspx?id=55319",
			id: Guid.CreateVersion7());

		result.Add(msSecurityBaselineProxy);

		// Microsoft 365 Apps Security Baseline proxy (applied via its processor)
		MUnit m365AppsBaselineProxy = new(
			category: Categories.Microsoft365AppsSecurityBaseline,
			name: Atlas.GetStr("ProtectCategory_MSFT365AppsSecBaseline"),
			deviceIntents: intentsForBaselinesAndOptional,
			applyStrategy: new DefaultApply(() => { /* no-op: applied via category processor in intents flow */ }),
			verifyStrategy: null,
			removeStrategy: null,
			subCategory: null,
			url: "https://www.microsoft.com/en-us/download/details.aspx?id=55319",
			id: Guid.CreateVersion7());

		result.Add(m365AppsBaselineProxy);

		// Optional Windows Features proxy (applied via its processor)
		MUnit optionalWindowsFeaturesProxy = new(
			category: Categories.OptionalWindowsFeatures,
			name: Atlas.GetStr("ProtectCategory_OptionalWinFeatures"),
			deviceIntents: intentsForBaselinesAndOptional,
			applyStrategy: new DefaultApply(() => { /* no-op: applied via category processor in intents flow */ }),
			verifyStrategy: null,
			removeStrategy: null,
			subCategory: null,
			url: "https://github.com/HotCakeX/Harden-Windows-Security/wiki/Optional-Windows-Features",
			id: Guid.CreateVersion7());

		result.Add(optionalWindowsFeaturesProxy);

		// Attack Surface Reduction (ASR) proxy (applied via its processor)
		MUnit asrProxy = new(
			category: Categories.AttackSurfaceReductionRules,
			name: Atlas.GetStr("ProtectCategory_ASRRules"),
			deviceIntents: intentsForBaselinesAndOptional,
			applyStrategy: new DefaultApply(() => { /* no-op: applied via category processor in intents flow */ }),
			verifyStrategy: null,
			removeStrategy: null,
			subCategory: null,
			url: "https://github.com/HotCakeX/Harden-Windows-Security/wiki/Attack-Surface-Reduction",
			id: Guid.CreateVersion7());

		result.Add(asrProxy);

		// Country IP Blocking proxy (applied via its processor)
		MUnit countryIPBlockingProxy = new(
			category: Categories.CountryIPBlocking,
			name: Atlas.GetStr("ProtectCategory_CountryIPBlock"),
			deviceIntents: [Intent.All],
			applyStrategy: new DefaultApply(() => { /* no-op: applied via category processor in intents flow */ }),
			verifyStrategy: null,
			removeStrategy: null,
			subCategory: null,
			url: "https://github.com/HotCakeX/Harden-Windows-Security/wiki/Country-IP-Blocking",
			id: Guid.CreateVersion7());

		result.Add(countryIPBlockingProxy);

		return result;
	}

	/// <summary>
	/// The main InfoBar for the Protect VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar = new();

	/// <summary>
	/// Cancellable button for Apply Selected operation
	/// </summary>
	internal AnimatedCancellableButtonInitializer ApplySelectedCancellableButton { get; }

	/// <summary>
	/// Cancellable button for Remove Selected operation
	/// </summary>
	internal AnimatedCancellableButtonInitializer RemoveSelectedCancellableButton { get; }

	/// <summary>
	/// Cancellable button for Verify Selected operation
	/// </summary>
	internal AnimatedCancellableButtonInitializer VerifySelectedCancellableButton { get; }

	/// <summary>
	/// Whether elements are enabled (used to disable non-cancellable buttons during operations)
	/// </summary>
	internal bool ElementsAreEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Enum to track which cancellable operation is currently running
	/// </summary>
	private enum RunningOperation
	{
		None,
		Apply,
		Remove,
		Verify,
		ApplyIntents
	}

	/// <summary>
	/// Tracks which cancellable operation is currently running so that only one of the cancellable buttons will ever be enabled during the operation.
	/// </summary>
	private RunningOperation CurrentRunningOperation
	{
		get; set
		{
			if (SP(ref field, value))
			{
				// Update button enabled states when the running operation changes
				IsApplyButtonEnabled = value == RunningOperation.None || value == RunningOperation.Apply;
				IsRemoveButtonEnabled = value == RunningOperation.None || value == RunningOperation.Remove;
				IsVerifyButtonEnabled = value == RunningOperation.None || value == RunningOperation.Verify;

				// Gate the Device Intents animated Apply button the same way as other animated buttons in the Protect page.
				IsApplyIntentsButtonEnabled = value == RunningOperation.None || value == RunningOperation.ApplyIntents;
			}
		}
	} = RunningOperation.None;

	/// <summary>
	/// Disables/Enables all animated buttons in this page.
	/// </summary>
	/// <param name="enable"></param>
	private void EnableDisableAnimatedButtons(bool enable)
	{
		IsApplyButtonEnabled = enable;
		IsRemoveButtonEnabled = enable;
		IsVerifyButtonEnabled = enable;
		IsApplyIntentsButtonEnabled = enable;
	}

	/// <summary>
	/// Whether the Apply button should be enabled
	/// </summary>
	internal bool IsApplyButtonEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the Remove button should be enabled
	/// </summary>
	internal bool IsRemoveButtonEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the Verify button should be enabled
	/// </summary>
	internal bool IsVerifyButtonEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the Apply button for the Device Intents section should be enabled
	/// </summary>
	internal bool IsApplyIntentsButtonEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Selected index for the preset comboBox.
	/// </summary>
	internal int ProtectionPresetsSelectedIndex
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProtectionCategoriesListItemsSource = new(GenerateCategories(ProtectionPresetsSelectedIndex));
				SelectAllItemsInListView();
			}
		}
	} = 1;

	#region SelectorBar Navigation
	internal Visibility IsPresetsSectionVisible { get; set => SP(ref field, value); } = Visibility.Visible;
	internal Visibility IsDeviceIntentSectionVisible { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal void SelectorBar_SelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
	{
		SelectorBarItem selectedItem = sender.SelectedItem;

		string selectedTag = (string)selectedItem.Tag;
		bool isPresets = string.Equals(selectedTag, "Presets", StringComparison.OrdinalIgnoreCase);

		IsPresetsSectionVisible = isPresets ? Visibility.Visible : Visibility.Collapsed;
		IsDeviceIntentSectionVisible = isPresets ? Visibility.Collapsed : Visibility.Visible;
	}
	#endregion

	/// <summary>
	/// All of the Device intents with their details for the UI GridView.
	/// </summary>
	internal readonly List<IntentItem> DeviceIntents = [
			new(
				intent: Intent.Development,
				title: Atlas.GetStr("DeviceUsageIntent-Development-Title"),
				description: Atlas.GetStr("DeviceUsageIntent-Development-Description"),
				image: new("ms-appx:///Assets/DeviceIntents/Development.png")
			),
			new (
				intent: Intent.Gaming,
				title: Atlas.GetStr("DeviceUsageIntent-Gaming-Title"),
				description: Atlas.GetStr("DeviceUsageIntent-Gaming-Description"),
				image: new("ms-appx:///Assets/DeviceIntents/Gaming.png")
			),
			new (
				intent: Intent.School,
				title: Atlas.GetStr("DeviceUsageIntent-School-Title"),
				description: Atlas.GetStr("DeviceUsageIntent-School-Description"),
				image: new("ms-appx:///Assets/DeviceIntents/School.png")
			),
			new (
				intent: Intent.Business,
				title: Atlas.GetStr("DeviceUsageIntent-Business-Title"),
				description: Atlas.GetStr("DeviceUsageIntent-Business-Description"),
				image: new("ms-appx:///Assets/DeviceIntents/Business.png")
			),
			new (
				intent: Intent.SpecializedAccessWorkstation,
				title: Atlas.GetStr("DeviceUsageIntent-SpecializedAccessWorkstation-Title"),
				description: Atlas.GetStr("DeviceUsageIntent-SpecializedAccessWorkstation-Description"),
				image: new("ms-appx:///Assets/DeviceIntents/Specialized.png")
			),
			new (
				intent: Intent.PrivilegedAccessWorkstation,
				title: Atlas.GetStr("DeviceUsageIntent-PrivilegedAccessWorkstation-Title"),
				description: Atlas.GetStr("DeviceUsageIntent-PrivilegedAccessWorkstation-Description"),
				image: new("ms-appx:///Assets/DeviceIntents/Privileged.png")
			),
		];

	/// <summary>
	/// Items Source of the ListView that displays the list of Protection Categories.
	/// </summary>
	internal ObservableCollection<ProtectionCategoryListViewItem> ProtectionCategoriesListItemsSource { get; set => SP(ref field, value); } = [];

	/// <summary>
	/// Selected Items list in the ListView.
	/// </summary>
	internal List<ProtectionCategoryListViewItem> ProtectionCategoriesListItemsSourceSelectedItems = [];

	/// <summary>
	/// A flag to make sure only one method is adding/removing items between ListView and the ProtectionCategoriesListItemsSourceSelectedItems.
	/// </summary>
	private volatile bool IsAdding;

	/// <summary>
	/// ListView reference of the UI.
	/// </summary>
	internal volatile ListViewBase? UIListView;

	/// <summary>
	/// Popup reference of the UI.
	/// </summary>
	internal volatile Popup? VerificationResultsPopUp;

	/// <summary>
	/// To select all of the items in the ListView.
	/// </summary>
	private void SelectAllItemsInListView()
	{
		if (IsAdding) return;

		try
		{
			IsAdding = true;

			foreach (ProtectionCategoryListViewItem item in CollectionsMarshal.AsSpan(ProtectionCategoriesListItemsSourceSelectedItems))
			{
				UIListView?.SelectedItems.Add(item);
			}
		}
		finally
		{
			IsAdding = false;
		}
	}

	/// <summary>
	/// Event handler for the SelectionChanged event of the ListView.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void ListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		if (IsAdding) return;

		try
		{
			IsAdding = true;

			foreach (ProtectionCategoryListViewItem item in e.AddedItems.Cast<ProtectionCategoryListViewItem>())
			{
				ProtectionCategoriesListItemsSourceSelectedItems.Add(item);
			}

			foreach (ProtectionCategoryListViewItem item in e.RemovedItems.Cast<ProtectionCategoryListViewItem>())
			{
				_ = ProtectionCategoriesListItemsSourceSelectedItems.Remove(item);
			}
		}
		finally
		{
			IsAdding = false;
		}
	}

	/// <summary>
	/// When the ListView is loaded or page is navigated to/from, this runs to check all of the items that were previously checked.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void ProtectionCategoriesListView_Loaded(object sender, RoutedEventArgs e)
	{
		if (IsAdding) return;

		try
		{
			IsAdding = true;

			ListView lv = (ListView)sender;

			foreach (ProtectionCategoryListViewItem item in ProtectionCategoriesListItemsSourceSelectedItems)
			{
				lv.SelectedItems.Add(item);
			}
		}
		finally
		{
			IsAdding = false;
		}
	}

	/// <summary>
	/// Generates Protection categories based on the selected preset.
	/// </summary>
	/// <param name="Preset"></param>
	/// <returns></returns>
	/// <exception cref="ArgumentOutOfRangeException"></exception>
	private List<ProtectionCategoryListViewItem> GenerateCategories(int Preset)
	{
		List<ProtectionCategoryListViewItem> output = [];

		switch (Preset)
		{
			case 0:
				{
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MicrosoftSecurityBaseline,
						title: Atlas.GetStr("ProtectCategory_MSFTSecBaseline"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MSFTSecBaseline"),
						logo: CategoryImages[(int)Categories.MicrosoftSecurityBaseline],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MSFTSecBaselines_OptionalOverrides,
						title: Atlas.GetStr("ProtectCategory_MSFTSecBaselineOverrides"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MSFTSecBaselineOverrides"),
						logo: CategoryImages[(int)Categories.MSFTSecBaselines_OptionalOverrides],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.Microsoft365AppsSecurityBaseline,
						title: Atlas.GetStr("ProtectCategory_MSFT365AppsSecBaseline"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MSFT365AppsSecBaseline"),
						logo: CategoryImages[(int)Categories.Microsoft365AppsSecurityBaseline],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MicrosoftDefender,
						title: Atlas.GetStr("ProtectCategory_MSFTDefender"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MSFTDefender"),
						logo: CategoryImages[(int)Categories.MicrosoftDefender],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.DeviceGuard,
						title: Atlas.GetStr("ProtectCategory_DeviceGuard"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_DeviceGuard"),
						logo: CategoryImages[(int)Categories.DeviceGuard],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.OptionalWindowsFeatures,
						title: Atlas.GetStr("ProtectCategory_OptionalWinFeatures"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_OptionalWinFeatures"),
						logo: CategoryImages[(int)Categories.OptionalWindowsFeatures],
						subCategories: [
										new SubCategoryDefinition(
										subCategory:SubCategories.OptionalWindowsFeatures_IncludeEnablements,
										description: Atlas.GetStr("ProtectSubCategory_IncludeEnablements"),
										tip: Atlas.GetStr("OptionalWindowsFeatures_IncludeEnablements"))
										{ IsChecked = !IsSystemVM }
										]
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.NonAdminCommands,
						title: Atlas.GetStr("ProtectCategory_NonAdmin"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_NonAdmin"),
						logo: CategoryImages[(int)Categories.NonAdminCommands],
						subCategories: []
						));

					break;
				}
			case 1:
				{

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MicrosoftSecurityBaseline,
						title: Atlas.GetStr("ProtectCategory_MSFTSecBaseline"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MSFTSecBaseline"),
						logo: CategoryImages[(int)Categories.MicrosoftSecurityBaseline],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MSFTSecBaselines_OptionalOverrides,
						title: Atlas.GetStr("ProtectCategory_MSFTSecBaselineOverrides"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MSFTSecBaselineOverrides"),
						logo: CategoryImages[(int)Categories.MSFTSecBaselines_OptionalOverrides],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.Microsoft365AppsSecurityBaseline,
						title: Atlas.GetStr("ProtectCategory_MSFT365AppsSecBaseline"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MSFT365AppsSecBaseline"),
						logo: CategoryImages[(int)Categories.Microsoft365AppsSecurityBaseline],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MicrosoftDefender,
						title: Atlas.GetStr("ProtectCategory_MSFTDefender"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MSFTDefender"),
						logo: CategoryImages[(int)Categories.MicrosoftDefender],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.AttackSurfaceReductionRules,
						title: Atlas.GetStr("ProtectCategory_ASRRules"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_ASRRules"),
						logo: CategoryImages[(int)Categories.AttackSurfaceReductionRules],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.BitLockerSettings,
						title: Atlas.GetStr("ProtectCategory_BitLocker"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_BitLocker"),
						logo: CategoryImages[(int)Categories.BitLockerSettings],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.TLSSecurity,
						title: Atlas.GetStr("ProtectCategory_TLS"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_TLS"),
						logo: CategoryImages[(int)Categories.TLSSecurity],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.TLS_ForBattleNet,
							description: Atlas.GetStr("ProtectSubCategory_TLS_ForBattleNet"),
							tip: Atlas.GetStr("TLSSecurity_TLS_ForBattleNet"))
							]
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.LockScreen,
						title: Atlas.GetStr("ProtectCategory_LockScreen"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_LockScreen"),
						logo: CategoryImages[(int)Categories.LockScreen],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.UserAccountControl,
						title: Atlas.GetStr("ProtectCategory_UAC"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_UAC"),
						logo: CategoryImages[(int)Categories.UserAccountControl],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.DeviceGuard,
						title: Atlas.GetStr("ProtectCategory_DeviceGuard"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_DeviceGuard"),
						logo: CategoryImages[(int)Categories.DeviceGuard],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.WindowsFirewall,
						title: Atlas.GetStr("ProtectCategory_WindowsFirewall"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_WindowsFirewall"),
						logo: CategoryImages[(int)Categories.WindowsFirewall],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.OptionalWindowsFeatures,
						title: Atlas.GetStr("ProtectCategory_OptionalWinFeatures"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_OptionalWinFeatures"),
						logo: CategoryImages[(int)Categories.OptionalWindowsFeatures],
						subCategories: [
										new SubCategoryDefinition(
										subCategory:SubCategories.OptionalWindowsFeatures_IncludeEnablements,
										description: Atlas.GetStr("ProtectSubCategory_IncludeEnablements"),
										tip: Atlas.GetStr("OptionalWindowsFeatures_IncludeEnablements"))
										{ IsChecked = !IsSystemVM }
										]
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.WindowsNetworking,
						title: Atlas.GetStr("ProtectCategory_WindowsNetworking"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_WindowsNetworking"),
						logo: CategoryImages[(int)Categories.WindowsNetworking],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.WindowsNetworking_BlockNTLM,
							description: Atlas.GetStr("ProtectSubCategory_BlockNTLM"),
							tip: Atlas.GetStr("WindowsNetworking_BlockNTLMTIP"))
							]
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MiscellaneousConfigurations,
						title: Atlas.GetStr("ProtectCategory_MiscellaneousConfig"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MiscellaneousConfig"),
						logo: CategoryImages[(int)Categories.MiscellaneousConfigurations],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.MiscellaneousConfigurations_EnableLongPathSupport,
							description: Atlas.GetStr("ProtectSubCategory_EnableLongPathSupport")),

							new SubCategoryDefinition(
							subCategory:SubCategories.MiscellaneousConfigurations_ReducedTelemetry,
							description: Atlas.GetStr("ProtectSubCategory_MiscellaneousConfigurations_ReducedTelemetry"),
							tip: Atlas.GetStr("MiscellaneousConfigurations_MiscellaneousConfigurations_ReducedTelemetry")),

							new SubCategoryDefinition(
							subCategory:SubCategories.MiscellaneousConfigurations_DriverLoadPolicyGoodOnly,
							description: Atlas.GetStr("ProtectSubCategory_MiscellaneousConfigurations_DriverLoadPolicyGoodOnly"),
							tip: Atlas.GetStr("MiscellaneousConfigurations_MiscellaneousConfigurations_DriverLoadPolicyGoodOnly"))
							]
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.WindowsUpdateConfigurations,
						title: Atlas.GetStr("ProtectCategory_WindowsUpdate"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_WindowsUpdate"),
						logo: CategoryImages[(int)Categories.WindowsUpdateConfigurations],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.EdgeBrowserConfigurations,
						title: Atlas.GetStr("ProtectCategory_Edge"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_Edge"),
						logo: CategoryImages[(int)Categories.EdgeBrowserConfigurations],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.CountryIPBlocking,
						title: Atlas.GetStr("ProtectCategory_CountryIPBlock"),
						subTitle: Atlas.GetStr("CountryIPBlockingNavItem/ToolTipService/ToolTip"),
						logo: CategoryImages[(int)Categories.CountryIPBlocking],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.NonAdminCommands,
						title: Atlas.GetStr("ProtectCategory_NonAdmin"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_NonAdmin"),
						logo: CategoryImages[(int)Categories.NonAdminCommands],
						subCategories: []
						));

					break;
				}
			case 2:
				{

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MicrosoftSecurityBaseline,
						title: Atlas.GetStr("ProtectCategory_MSFTSecBaseline"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MSFTSecBaseline"),
						logo: CategoryImages[(int)Categories.MicrosoftSecurityBaseline],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MSFTSecBaselines_OptionalOverrides,
						title: Atlas.GetStr("ProtectCategory_MSFTSecBaselineOverrides"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MSFTSecBaselineOverrides"),
						logo: CategoryImages[(int)Categories.MSFTSecBaselines_OptionalOverrides],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.Microsoft365AppsSecurityBaseline,
						title: Atlas.GetStr("ProtectCategory_MSFT365AppsSecBaseline"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MSFT365AppsSecBaseline"),
						logo: CategoryImages[(int)Categories.Microsoft365AppsSecurityBaseline],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MicrosoftDefender,
						title: Atlas.GetStr("ProtectCategory_MSFTDefender"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MSFTDefender"),
						logo: CategoryImages[(int)Categories.MicrosoftDefender],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.MSDefender_SmartAppControl,
							description: Atlas.GetStr("ProtectSubCategory_SmartAppControl")),

							new SubCategoryDefinition(
							subCategory:SubCategories.MSDefender_BetaUpdateChannelsForDefender,
							description: Atlas.GetStr("ProtectSubCategory_BetaUpdateChannels"))
							]
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.AttackSurfaceReductionRules,
						title: Atlas.GetStr("ProtectCategory_ASRRules"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_ASRRules"),
						logo: CategoryImages[(int)Categories.AttackSurfaceReductionRules],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.BitLockerSettings,
						title: Atlas.GetStr("ProtectCategory_BitLocker"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_BitLocker"),
						logo: CategoryImages[(int)Categories.BitLockerSettings],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.TLSSecurity,
						title: Atlas.GetStr("ProtectCategory_TLS"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_TLS"),
						logo: CategoryImages[(int)Categories.TLSSecurity],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.TLS_ForBattleNet,
							description: Atlas.GetStr("ProtectSubCategory_TLS_ForBattleNet"),
							tip: Atlas.GetStr("TLSSecurity_TLS_ForBattleNet"))
							]
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.LockScreen,
						title: Atlas.GetStr("ProtectCategory_LockScreen"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_LockScreen"),
						logo: CategoryImages[(int)Categories.LockScreen],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.LockScreen_NoLastSignedIn,
							description: Atlas.GetStr("ProtectSubCategory_NoLastSignedIn"),
							tip: Atlas.GetStr("UAC_NoFastUserSwitchingTIP")),

							new SubCategoryDefinition(
							subCategory:SubCategories.LockScreen_RequireCTRLAltDel,
							description: Atlas.GetStr("ProtectSubCategory_RequireCTRLAltDel"))
							]
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.UserAccountControl,
						title: Atlas.GetStr("ProtectCategory_UAC"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_UAC"),
						logo: CategoryImages[(int)Categories.UserAccountControl],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.UAC_NoFastUserSwitching,
							description: Atlas.GetStr("ProtectSubCategory_NoFastUserSwitching"),
							tip: Atlas.GetStr("UAC_NoFastUserSwitchingTIP")),

							new SubCategoryDefinition(
							subCategory:SubCategories.UAC_OnlyElevateSigned,
							description: Atlas.GetStr("ProtectSubCategory_OnlyElevateSigned"))
							]
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.DeviceGuard,
						title: Atlas.GetStr("ProtectCategory_DeviceGuard"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_DeviceGuard"),
						logo: CategoryImages[(int)Categories.DeviceGuard],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.DeviceGuard_MandatoryModeForVBS,
							description: Atlas.GetStr("ProtectSubCategory_MandatoryModeForVBS"))
							]
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.WindowsFirewall,
						title: Atlas.GetStr("ProtectCategory_WindowsFirewall"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_WindowsFirewall"),
						logo: CategoryImages[(int)Categories.WindowsFirewall],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.OptionalWindowsFeatures,
						title: Atlas.GetStr("ProtectCategory_OptionalWinFeatures"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_OptionalWinFeatures"),
						logo: CategoryImages[(int)Categories.OptionalWindowsFeatures],
						subCategories: [
										new SubCategoryDefinition(
										subCategory:SubCategories.OptionalWindowsFeatures_IncludeEnablements,
										description: Atlas.GetStr("ProtectSubCategory_IncludeEnablements"),
										tip: Atlas.GetStr("OptionalWindowsFeatures_IncludeEnablements"))
										{ IsChecked = !IsSystemVM }
										]
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.WindowsNetworking,
						title: Atlas.GetStr("ProtectCategory_WindowsNetworking"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_WindowsNetworking"),
						logo: CategoryImages[(int)Categories.WindowsNetworking],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.WindowsNetworking_BlockNTLM,
							description: Atlas.GetStr("ProtectSubCategory_BlockNTLM"))
							]
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MiscellaneousConfigurations,
						title: Atlas.GetStr("ProtectCategory_MiscellaneousConfig"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_MiscellaneousConfig"),
						logo: CategoryImages[(int)Categories.MiscellaneousConfigurations],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.MiscellaneousConfigurations_ForceStrongKeyProtection,
							description: Atlas.GetStr("ProtectSubCategory_ForceStrongKeyProtection")),

							new SubCategoryDefinition(
							subCategory:SubCategories.MiscellaneousConfigurations_EnableWindowsProtectedPrint,
							description: Atlas.GetStr("ProtectSubCategory_EnableWindowsProtectedPrint")),

							new SubCategoryDefinition(
							subCategory:SubCategories.MiscellaneousConfigurations_EnableLongPathSupport,
							description: Atlas.GetStr("ProtectSubCategory_EnableLongPathSupport")),

							new SubCategoryDefinition(
							subCategory:SubCategories.MiscellaneousConfigurations_ReducedTelemetry,
							description: Atlas.GetStr("ProtectSubCategory_MiscellaneousConfigurations_ReducedTelemetry"),
							tip: Atlas.GetStr("MiscellaneousConfigurations_MiscellaneousConfigurations_ReducedTelemetry")),

							new SubCategoryDefinition(
							subCategory:SubCategories.MiscellaneousConfigurations_DriverLoadPolicyGoodOnly,
							description: Atlas.GetStr("ProtectSubCategory_MiscellaneousConfigurations_DriverLoadPolicyGoodOnly"),
							tip: Atlas.GetStr("MiscellaneousConfigurations_MiscellaneousConfigurations_DriverLoadPolicyGoodOnly"))
							]
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.WindowsUpdateConfigurations,
						title: Atlas.GetStr("ProtectCategory_WindowsUpdate"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_WindowsUpdate"),
						logo: CategoryImages[(int)Categories.WindowsUpdateConfigurations],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.EdgeBrowserConfigurations,
						title: Atlas.GetStr("ProtectCategory_Edge"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_Edge"),
						logo: CategoryImages[(int)Categories.EdgeBrowserConfigurations],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.CountryIPBlocking,
						title: Atlas.GetStr("ProtectCategory_CountryIPBlock"),
						subTitle: Atlas.GetStr("CountryIPBlockingNavItem/ToolTipService/ToolTip"),
						logo: CategoryImages[(int)Categories.CountryIPBlocking],
						subCategories: []
						));

					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.NonAdminCommands,
						title: Atlas.GetStr("ProtectCategory_NonAdmin"),
						subTitle: Atlas.GetStr("ProtectCategory_Description_NonAdmin"),
						logo: CategoryImages[(int)Categories.NonAdminCommands],
						subCategories: []
						));

					break;
				}
			default:
				throw new ArgumentOutOfRangeException(nameof(Preset), "Invalid preset selected.");
		}

		// Add the same items to the List so we can mark them as selected in the ListView.
		ProtectionCategoriesListItemsSourceSelectedItems = output;

		return output;
	}

	/// <summary>
	/// Apply security measures for selected categories
	/// </summary>
	internal async void ApplySelectedCategories() =>
		await ExecuteSelectedCategoriesOperation(MUnitOperation.Apply, ApplySelectedCancellableButton);

	/// <summary>
	/// Remove security measures for selected categories
	/// </summary>
	internal async void RemoveSelectedCategories() =>
			await ExecuteSelectedCategoriesOperation(MUnitOperation.Remove, RemoveSelectedCancellableButton);

	/// <summary>
	/// Verify security measures for selected categories
	/// </summary>
	internal async void VerifySelectedCategories() =>
			await ExecuteSelectedCategoriesOperation(MUnitOperation.Verify, VerifySelectedCancellableButton);

	/// <summary>
	/// Execute the specified operation on selected categories
	/// </summary>
	/// <param name="operation">The operation to perform</param>
	/// <param name="button">The cancellable button handling this operation</param>
	private async Task ExecuteSelectedCategoriesOperation(MUnitOperation operation, AnimatedCancellableButtonInitializer button)
	{
		if (ProtectionCategoriesListItemsSourceSelectedItems.Count == 0)
		{
			MainInfoBar.WriteWarning("No categories selected. Please select at least one category to process.");
			return;
		}

		bool errorsOccurred = false;

		try
		{
			button.Begin();

			// Set flags to disable other operations and UI elements
			ElementsAreEnabled = false;

			using IDisposable taskTracker = TaskTracking.RegisterOperation();

			// Close the verification results PopUp if it's open
			_ = (VerificationResultsPopUp?.IsOpen = false);

			// Set the current running operation to enable/disable appropriate buttons
			CurrentRunningOperation = operation switch
			{
				MUnitOperation.Apply => RunningOperation.Apply,
				MUnitOperation.Remove => RunningOperation.Remove,
				MUnitOperation.Verify => RunningOperation.Verify,
				_ => RunningOperation.None
			};

			string operationText = operation switch
			{
				MUnitOperation.Apply => Atlas.GetStr("Applying"),
				MUnitOperation.Remove => Atlas.GetStr("Removing"),
				MUnitOperation.Verify => Atlas.GetStr("Verifying"),
				_ => Atlas.GetStr("Processing")
			};

			MainInfoBar.WriteInfo($"{operationText} {ProtectionCategoriesListItemsSourceSelectedItems.Count} selected categories...");

			// Ensure categories are processed in the correct order based on their execution priority.
			List<ProtectionCategoryListViewItem> orderedSelection = ProtectionCategoriesListItemsSourceSelectedItems
					.OrderBy(item => CategoryProcessorFactory.GetExecutionPriority(item.Category)).ToList();

			int processedCategories = 0;
			int totalCategories = orderedSelection.Count;

			foreach (ProtectionCategoryListViewItem selectedCategory in orderedSelection)
			{
				button.Cts?.Token.ThrowIfCancellationRequested();

				try
				{
					// Update progress
					processedCategories++;
					MainInfoBar.WriteInfo($"{operationText} category {processedCategories}/{totalCategories}: {selectedCategory.Title}");

					// Get selected sub-categories for this category (only checked ones)
					List<SubCategories> selectedSubCategories = GetSelectedSubCategoriesFromData(selectedCategory);

					// Get processor for this category
					ICategoryProcessor processor = CategoryProcessorFactory.GetProcessor(selectedCategory.Category);

					// Execute the operation
					switch (operation)
					{
						case MUnitOperation.Apply:
							await processor.ApplyAllAsync(
								selectedSubCategories: selectedSubCategories.Count > 0 ? selectedSubCategories : null,
								selectedIntent: null,
								cancellationToken: button.Cts?.Token);
							break;
						case MUnitOperation.Remove:
							await processor.RemoveAllAsync(
								selectedSubCategories: selectedSubCategories.Count > 0 ? selectedSubCategories : null,
								selectedIntent: null,
								cancellationToken: button.Cts?.Token);
							break;
						case MUnitOperation.Verify:
							await processor.VerifyAllAsync(
								selectedSubCategories: selectedSubCategories.Count > 0 ? selectedSubCategories : null,
								selectedIntent: null,
								cancellationToken: button.Cts?.Token);
							break;
						default:
							break;
					}

					button.Cts?.Token.ThrowIfCancellationRequested();
				}
				catch (Exception ex)
				{
					if (IsCancellationException(ex)) throw;

					// If any category fails, stop all operations
					MainInfoBar.WriteWarning($"Failed to process category '{selectedCategory.Title}'. Please view the logs for the full error details.");

					// It's important to print the full exception details here for both CLI and GUI modes.
					Logger.Write(ex);

					errorsOccurred = true;
					break;
				}
			}

			if (!errorsOccurred)
			{
				string operationPastTense = operation switch
				{
					MUnitOperation.Apply => "applied",
					MUnitOperation.Remove => "removed",
					MUnitOperation.Verify => "verified",
					_ => "processed"
				};
				MainInfoBar.WriteSuccess($"Successfully {operationPastTense} {processedCategories} categories");

				// Prepare verification results PopUp
				if (operation == MUnitOperation.Verify)
				{
					int total = 0;
					int compliant = 0;

					foreach (ProtectionCategoryListViewItem selectedCategory in orderedSelection)
					{
						(int Total, int Compliant) = await GetCategoryStatsAsync(selectedCategory.Category);
						total += Total;
						compliant += Compliant;
					}

					VerificationTotal = total;
					VerificationCompliant = compliant;
					VerificationNonCompliant = total - compliant;
					VerificationPercentage = total > 0 ? (double)compliant / total * 100.0 : 0.0;

					// Trigger update for the string property
					OnPropertyChanged(nameof(VerificationPercentageString));

					DisplayVerificationPopup();

					Logger.Write($"Verified {VerificationTotal} Security Measures in total. {VerificationCompliant} were compliant while {VerificationNonCompliant} were non-compliant. The system's security score is: {VerificationPercentage:F1}% UwU");
				}
			}
		}
		catch (OperationCanceledException)
		{
			button.wasCancelled = true;
		}
		catch (Exception ex)
		{
			errorsOccurred = true;
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			if (button.wasCancelled)
			{
				string operationText = operation switch
				{
					MUnitOperation.Apply => Atlas.GetStr("ApplyText/Text"),
					MUnitOperation.Remove => Atlas.GetStr("RemoveText/Text"),
					MUnitOperation.Verify => Atlas.GetStr("VerifyText/Text"),
					_ => Atlas.GetStr("AddExclusionsForProcessMenuFlyoutItem/Text")
				};
				MainInfoBar.WriteWarning($"{operationText} operation was cancelled by user.");
			}

			button.End();
			// Re-enable UI elements and clear current running operation
			ElementsAreEnabled = true;
			CurrentRunningOperation = RunningOperation.None;
		}
	}

	private static List<SubCategories> GetSelectedSubCategoriesFromData(ProtectionCategoryListViewItem categoryItem)
	{
		List<SubCategories> output = [];

		foreach (SubCategoryDefinition sc in categoryItem.SubCategories)
		{
			if (sc.IsChecked)
			{
				output.Add(sc.SubCategory);
			}
		}

		return output;
	}

	/// <summary>
	/// Programmatically runs the same pipeline as the UI for a given preset index and operation.
	/// </summary>
	internal async Task RunPresetFromCliAsync(int presetIndex, HardenSystemSecurity.Helpers.MUnitOperation operation)
	{
		// This setter triggers GenerateCategories and the same selection logic the UI uses.
		ProtectionPresetsSelectedIndex = presetIndex;

		// Run the exact same pipeline as the UI buttons.
		// Passing ApplySelectedCancellableButton just to satisfy the method signature, it has no effect on CLI operation.
		await ExecuteSelectedCategoriesOperation(operation, ApplySelectedCancellableButton);
	}

	/// <summary>
	/// Programmatically applies security measures for a given device usage intent using the same
	/// category processor pipeline as the UI.
	/// </summary>
	/// <param name="selectedIntent">Device usage intent to apply.</param>
	internal async Task RunIntentFromCliAsync(Intent selectedIntent)
	{
		// Set the selected intent; this triggers RecomputeDeviceIntentsPreview() via the property setter.
		SelectedDeviceIntent = DeviceIntents.First(i => i.Intent == selectedIntent);

		await ApplySelectedDeviceIntents_Internal();
	}

	/// <summary>
	/// Event handler for the UI.
	/// </summary>
	internal async void GenerateSystemReport()
	{
		try
		{
			ElementsAreEnabled = false;
			EnableDisableAnimatedButtons(false);

			using IDisposable taskTracker = TaskTracking.RegisterOperation();

			string? savePath = FileDialogHelper.ShowSaveFileDialog(Atlas.JSONPickerFilter, Traverse.Generator.GetFileName());

			if (savePath is null)
				return;

			MainInfoBar.WriteInfo(Atlas.GetStr("SystemStateReportGenerationBeginsMsg"));

			await Traverse.Generator.GenerateTraverseData(savePath);

			MainInfoBar.WriteSuccess(string.Format(Atlas.GetStr("SystemStateReportGenerationFinishedMsg"), savePath));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			EnableDisableAnimatedButtons(true);
		}
	}

	/// <summary>
	/// Event handler for the UI.
	/// </summary>
	internal async void RestoreSystemState()
	{
		try
		{
			ElementsAreEnabled = false;
			EnableDisableAnimatedButtons(false);

			using IDisposable taskTracker = TaskTracking.RegisterOperation();

			string? loadPath = FileDialogHelper.ShowFilePickerDialog(Atlas.JSONPickerFilter);

			if (loadPath is null)
				return;

			MainInfoBar.WriteInfo(Atlas.GetStr("SystemStateRestorationBeginsMsg"));

			await Traverse.Importer.ImportAndApplyAsync(
				filePath: loadPath,
				synchronizeExact: RestorationModeFull
				);

			MainInfoBar.WriteSuccess(Atlas.GetStr("SystemStateRestorationFinishedMsg"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			EnableDisableAnimatedButtons(true);
		}
	}

	internal bool RestorationModePartial { get; set => SP(ref field, value); }
	internal bool RestorationModeFull { get; set => SP(ref field, value); } = true;

	#region Verification Popup Properties & Methods

	private bool VerificationPopupIsPending;
	internal int VerificationTotal { get; set => SP(ref field, value); }
	internal int VerificationCompliant { get; set => SP(ref field, value); }
	internal int VerificationNonCompliant { get; set => SP(ref field, value); }
	internal double VerificationPercentage { get; set => SP(ref field, value); }
	internal string VerificationPercentageString => $"{VerificationPercentage:F1}%";

	internal void CloseVerificationPopup() => VerificationResultsPopUp?.IsOpen = false;

	private void DisplayVerificationPopup()
	{
		// Differ showing the popup to when the page is loaded to make sure user will see it.
		if (VerificationResultsPopUp is null)
		{
			VerificationPopupIsPending = true;
		}
		else
		{
			VerificationResultsPopUp.IsOpen = true;
			VerificationPopupIsPending = false;
		}
	}

	/// <summary>
	/// Gathers the total and compliant counts for a specific category using the correct ViewModel.
	/// </summary>
	private static async Task<(int Total, int Compliant)> GetCategoryStatsAsync(Categories category)
	{
		switch (category)
		{
			case Categories.MicrosoftSecurityBaseline:
				HardenSystemSecurity.Traverse.MicrosoftSecurityBaseline msb = await ViewModelProvider.MicrosoftSecurityBaselineVM.GetTraverseData();
				return (msb.Items.Count, msb.Score);
			case Categories.Microsoft365AppsSecurityBaseline:
				HardenSystemSecurity.Traverse.Microsoft365AppsSecurityBaseline m365 = await ViewModelProvider.Microsoft365AppsSecurityBaselineVM.GetTraverseData();
				return (m365.Items.Count, m365.Score);
			case Categories.AttackSurfaceReductionRules:
				HardenSystemSecurity.Traverse.AttackSurfaceReductionRules asr = await ViewModelProvider.ASRVM.GetTraverseData();
				return (asr.Items.Count, asr.Score);
			case Categories.OptionalWindowsFeatures:
				return (0, 0); // Not tracked in the standard compliant/non-compliant way in traverse data yet
			case Categories.MicrosoftDefender: return GetMUnitStats(ViewModelProvider.MicrosoftDefenderVM);
			case Categories.BitLockerSettings: return GetMUnitStats(ViewModelProvider.BitLockerVM);
			case Categories.TLSSecurity: return GetMUnitStats(ViewModelProvider.TLSVM);
			case Categories.LockScreen: return GetMUnitStats(ViewModelProvider.LockScreenVM);
			case Categories.UserAccountControl: return GetMUnitStats(ViewModelProvider.UACVM);
			case Categories.DeviceGuard: return GetMUnitStats(ViewModelProvider.DeviceGuardVM);
			case Categories.WindowsFirewall: return GetMUnitStats(ViewModelProvider.WindowsFirewallVM);
			case Categories.WindowsNetworking: return GetMUnitStats(ViewModelProvider.WindowsNetworkingVM);
			case Categories.MiscellaneousConfigurations: return GetMUnitStats(ViewModelProvider.MiscellaneousConfigsVM);
			case Categories.WindowsUpdateConfigurations: return GetMUnitStats(ViewModelProvider.WindowsUpdateVM);
			case Categories.EdgeBrowserConfigurations: return GetMUnitStats(ViewModelProvider.EdgeVM);
			case Categories.NonAdminCommands: return GetMUnitStats(ViewModelProvider.NonAdminVM);
			case Categories.MSFTSecBaselines_OptionalOverrides: return GetMUnitStats(ViewModelProvider.MicrosoftBaseLinesOverridesVM);
			case Categories.CertificateChecking:
				return (0, 0); // N/A
			case Categories.CountryIPBlocking:
				return (0, 0); // N/A
			default: return (0, 0);
		}
	}

	private static (int Total, int Compliant) GetMUnitStats(IMUnitListViewModel vm)
	{
		int total = vm.AllMUnits.Count;
		int compliant = vm.AllMUnits.Count(m => m.IsApplied == true);
		return (total, compliant);
	}

	#endregion

	internal void Page_Unloaded(object sender, RoutedEventArgs e)
	{
		// Null the UI references when the page is unloaded.
		UIListView = null;
		VerificationResultsPopUp = null;
	}

	internal void Page_Loaded(object sender, RoutedEventArgs e)
	{
		if (VerificationPopupIsPending)
			DisplayVerificationPopup();
	}

}
