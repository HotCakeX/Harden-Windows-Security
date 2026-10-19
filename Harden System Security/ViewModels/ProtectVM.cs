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
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Others;
using CommonCore.GroupPolicy;
using HardenSystemSecurity.CustomUIElements;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media.Imaging;
using Microsoft.Windows.AppNotifications.Builder;
using WinRT;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class ProtectVM : ViewModelBase, IDisposable
{
	/// <summary>
	/// Aggregate compliance statistics produced by a completed preset verification.
	/// </summary>
	internal readonly record struct PresetVerificationResult(int Categories, int Total, int Compliant, int NonCompliant, double Percentage);

	/// <summary>
	/// Outcome of a preset operation, including verification statistics when applicable.
	/// </summary>
	internal readonly record struct PresetOperationResult(bool Succeeded, PresetVerificationResult? Verification);

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
			m.Category.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
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
	[DynamicWindowsRuntimeCast(typeof(MenuFlyoutItem))]
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
	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
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
				.Select(static m => m.Category)
				.Distinct()
				.OrderBy(CategoryProcessorFactory.GetExecutionPriority)
				.ToList();

			MainInfoBar.WriteInfo($"Applying {AllDeviceIntentMUnitsPreview.Count} security measures for selected device intent...");

			// Process each category with cancellation support
			for (int i = 0; i < categories.Count; i++)
			{
				ApplyIntentsCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				Categories cat = categories[i];
				ICategoryProcessor processor = CategoryProcessorFactory.GetProcessor(cat);

				MainInfoBar.WriteInfo($"Applying category {i + 1}/{categories.Count}: {processor.CategoryDisplayName}");
				HighlightCategory(cat);

				// Using the category processor like Presets, but we pass the selected intents.
				await processor.ApplyAllAsync(
					selectedSubCategories: null,
					selectedIntent: SelectedDeviceIntent.Intent,
					cancellationToken: ApplyIntentsCancellableButton.Cts?.Token);
			}

			MainInfoBar.WriteSuccess($"Successfully applied security measures for {categories.Count} categories.");
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
			HighlightCategory(null);

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
		result.Add(CreateProxyMUnit(
			Categories.MicrosoftSecurityBaseline,
			"ProtectCategory_MSFTSecBaseline",
			intentsForBaselinesAndOptional,
			"https://www.microsoft.com/en-us/download/details.aspx?id=55319"));

		// Microsoft 365 Apps Security Baseline proxy (applied via its processor)
		result.Add(CreateProxyMUnit(
			Categories.Microsoft365AppsSecurityBaseline,
			"ProtectCategory_MSFT365AppsSecBaseline",
			intentsForBaselinesAndOptional,
			"https://www.microsoft.com/en-us/download/details.aspx?id=55319"));

		// Optional Windows Features proxy (applied via its processor)
		result.Add(CreateProxyMUnit(
			Categories.OptionalWindowsFeatures,
			"ProtectCategory_OptionalWinFeatures",
			intentsForBaselinesAndOptional,
			"https://github.com/HotCakeX/Harden-Windows-Security/wiki/Optional-Windows-Features"));

		// Attack Surface Reduction (ASR) proxy (applied via its processor)
		result.Add(CreateProxyMUnit(
			Categories.AttackSurfaceReductionRules,
			"ProtectCategory_ASRRules",
			intentsForBaselinesAndOptional,
			"https://github.com/HotCakeX/Harden-Windows-Security/wiki/Attack-Surface-Reduction"));

		// Country IP Blocking proxy (applied via its processor)
		result.Add(CreateProxyMUnit(
			Categories.CountryIPBlocking,
			"ProtectCategory_CountryIPBlock",
			[Intent.All],
			"https://github.com/HotCakeX/Harden-Windows-Security/wiki/Country-IP-Blocking"));

		return result;
	}

	/// <summary>
	/// Creates a proxy MUnit for a non-MUnit-based category so that it appears in the device-intents preview.
	/// The apply strategy is intentionally a no-op because the real application is performed via its category processor.
	/// </summary>
	/// <param name="category">The non-MUnit-based category the proxy represents.</param>
	/// <param name="nameKey">Resource key of the proxy's name.</param>
	/// <param name="deviceIntents">The device intents that make the proxy appear in the preview.</param>
	/// <param name="url">The URL of the proxy.</param>
	private static MUnit CreateProxyMUnit(Categories category, string nameKey, List<Intent> deviceIntents, string url) => new(
		category: category,
		name: Atlas.GetStr(nameKey),
		deviceIntents: deviceIntents,
		applyStrategy: new DefaultApply(static () => { /* no-op: applied via category processor in intents flow */ }),
		verifyStrategy: null,
		removeStrategy: null,
		subCategory: null,
		url: url,
		id: Guid.CreateVersion7());

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
				IsApplyButtonEnabled = value is RunningOperation.None or RunningOperation.Apply;
				IsRemoveButtonEnabled = value is RunningOperation.None or RunningOperation.Remove;
				IsVerifyButtonEnabled = value is RunningOperation.None or RunningOperation.Verify;

				// Gate the Device Intents animated Apply button the same way as other animated buttons in the Protect page.
				IsApplyIntentsButtonEnabled = value is RunningOperation.None or RunningOperation.ApplyIntents;
			}
		}
	} = RunningOperation.None;

	/// <summary>
	/// Disables/Enables all animated buttons in this page.
	/// </summary>
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
	[DynamicWindowsRuntimeCast(typeof(ListView))]
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
	/// <exception cref="ArgumentOutOfRangeException"></exception>
	private List<ProtectionCategoryListViewItem> GenerateCategories(int Preset)
	{
		List<ProtectionCategoryListViewItem> output;

		switch (Preset)
		{
			case 0:
				{
					output = [
						CreateCategory(Categories.MicrosoftSecurityBaseline),
						CreateCategory(Categories.MSFTSecBaselines_OptionalOverrides),
						CreateCategory(Categories.Microsoft365AppsSecurityBaseline),
						CreateCategory(Categories.MicrosoftDefender),
						CreateCategory(Categories.DeviceGuard),
						CreateCategory(Categories.OptionalWindowsFeatures, [
							new SubCategoryDefinition(
							subCategory: SubCategories.OptionalWindowsFeatures_IncludeEnablements,
							description: Atlas.GetStr("ProtectSubCategory_IncludeEnablements"),
							tip: Atlas.GetStr("OptionalWindowsFeatures_IncludeEnablements"))
							{ IsChecked = !IsSystemVM }]),
						CreateCategory(Categories.NonAdminCommands)
						];

					break;
				}
			case 1:
				{
					output = [
						CreateCategory(Categories.MicrosoftSecurityBaseline),
						CreateCategory(Categories.MSFTSecBaselines_OptionalOverrides),
						CreateCategory(Categories.Microsoft365AppsSecurityBaseline),
						CreateCategory(Categories.MicrosoftDefender),
						CreateCategory(Categories.AttackSurfaceReductionRules),
						CreateCategory(Categories.BitLockerSettings),
						CreateCategory(Categories.TLSSecurity, [
							new SubCategoryDefinition(
							subCategory:SubCategories.TLS_ForBattleNet,
							description: Atlas.GetStr("ProtectSubCategory_TLS_ForBattleNet"),
							tip: Atlas.GetStr("TLSSecurity_TLS_ForBattleNet"))
							]),
						CreateCategory(Categories.LockScreen),
						CreateCategory(Categories.UserAccountControl),
						CreateCategory(Categories.DeviceGuard),
						CreateCategory(Categories.WindowsFirewall),
						CreateCategory(Categories.OptionalWindowsFeatures, [
							new SubCategoryDefinition(
							subCategory: SubCategories.OptionalWindowsFeatures_IncludeEnablements,
							description: Atlas.GetStr("ProtectSubCategory_IncludeEnablements"),
							tip: Atlas.GetStr("OptionalWindowsFeatures_IncludeEnablements"))
							{ IsChecked = !IsSystemVM }]),
						CreateCategory(Categories.WindowsNetworking, [
							new SubCategoryDefinition(
							subCategory:SubCategories.WindowsNetworking_BlockNTLM,
							description: Atlas.GetStr("ProtectSubCategory_BlockNTLM"),
							tip: Atlas.GetStr("WindowsNetworking_BlockNTLMTIP"))
							]),
						CreateCategory(Categories.MiscellaneousConfigurations, [
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
							]),
						CreateCategory(Categories.WindowsUpdateConfigurations),
						CreateCategory(Categories.EdgeBrowserConfigurations, [
							new SubCategoryDefinition(
							subCategory:SubCategories.Edge_DynamicCodeSettings,
							description: Atlas.GetSecurityStr("DynamicCodeSettings-Edge"),
							tip: Atlas.GetStr("DynamicCodeSettings-Edge-TIP"))
							]),
						CreateCategory(Categories.CountryIPBlocking),
						CreateCategory(Categories.NonAdminCommands)
						];

					break;
				}
			case 2:
				{
					output = [
						CreateCategory(Categories.MicrosoftSecurityBaseline),
						CreateCategory(Categories.MSFTSecBaselines_OptionalOverrides),
						CreateCategory(Categories.Microsoft365AppsSecurityBaseline),
						CreateCategory(Categories.MicrosoftDefender, [
							new SubCategoryDefinition(
							subCategory:SubCategories.MSDefender_SmartAppControl,
							description: Atlas.GetStr("ProtectSubCategory_SmartAppControl")),

							new SubCategoryDefinition(
							subCategory:SubCategories.MSDefender_BetaUpdateChannelsForDefender,
							description: Atlas.GetStr("ProtectSubCategory_BetaUpdateChannels"))
							]),
						CreateCategory(Categories.AttackSurfaceReductionRules),
						CreateCategory(Categories.BitLockerSettings),
						CreateCategory(Categories.TLSSecurity, [
							new SubCategoryDefinition(
							subCategory:SubCategories.TLS_ForBattleNet,
							description: Atlas.GetStr("ProtectSubCategory_TLS_ForBattleNet"),
							tip: Atlas.GetStr("TLSSecurity_TLS_ForBattleNet"))
							]),
						CreateCategory(Categories.LockScreen, [
							new SubCategoryDefinition(
							subCategory:SubCategories.LockScreen_NoLastSignedIn,
							description: Atlas.GetStr("ProtectSubCategory_NoLastSignedIn"),
							tip: Atlas.GetStr("UAC_NoFastUserSwitchingTIP")),

							new SubCategoryDefinition(
							subCategory:SubCategories.LockScreen_RequireCTRLAltDel,
							description: Atlas.GetStr("ProtectSubCategory_RequireCTRLAltDel"))
							]),
						CreateCategory(Categories.UserAccountControl, [
							new SubCategoryDefinition(
							subCategory:SubCategories.UAC_NoFastUserSwitching,
							description: Atlas.GetStr("ProtectSubCategory_NoFastUserSwitching"),
							tip: Atlas.GetStr("UAC_NoFastUserSwitchingTIP")),

							new SubCategoryDefinition(
							subCategory:SubCategories.UAC_OnlyElevateSigned,
							description: Atlas.GetStr("ProtectSubCategory_OnlyElevateSigned"))
							]),
						CreateCategory(Categories.DeviceGuard, [
							new SubCategoryDefinition(
							subCategory:SubCategories.DeviceGuard_MandatoryModeForVBS,
							description: Atlas.GetStr("ProtectSubCategory_MandatoryModeForVBS"))
							]),
						CreateCategory(Categories.WindowsFirewall),
						CreateCategory(Categories.OptionalWindowsFeatures, [
							new SubCategoryDefinition(
							subCategory: SubCategories.OptionalWindowsFeatures_IncludeEnablements,
							description: Atlas.GetStr("ProtectSubCategory_IncludeEnablements"),
							tip: Atlas.GetStr("OptionalWindowsFeatures_IncludeEnablements"))
							{ IsChecked = !IsSystemVM }]),
						CreateCategory(Categories.WindowsNetworking, [
							new SubCategoryDefinition(
							subCategory:SubCategories.WindowsNetworking_BlockNTLM,
							description: Atlas.GetStr("ProtectSubCategory_BlockNTLM"))
							]),
						CreateCategory(Categories.MiscellaneousConfigurations, [
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
							]),
						CreateCategory(Categories.WindowsUpdateConfigurations),
						CreateCategory(Categories.EdgeBrowserConfigurations, [
							new SubCategoryDefinition(
							subCategory:SubCategories.Edge_DynamicCodeSettings,
							description: Atlas.GetSecurityStr("DynamicCodeSettings-Edge"),
							tip: Atlas.GetStr("DynamicCodeSettings-Edge-TIP"))
							]),
						CreateCategory(Categories.CountryIPBlocking),
						CreateCategory(Categories.NonAdminCommands)
						];

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
	/// Creates a Protection category item for the <see cref="GenerateCategories"/> method and the <see cref="SystemStateRestoreDialog"/>.
	/// </summary>
	/// <param name="category">The category to create the item for.</param>
	/// <param name="subCategories">Sub-categories of the item. They must be new instances for every item because their IsChecked state is per instance.</param>
	/// <exception cref="ArgumentOutOfRangeException"></exception>
	internal ProtectionCategoryListViewItem CreateCategory(Categories category, List<SubCategoryDefinition>? subCategories = null)
	{
		// Resource keys of the title and subtitle of each category.
		(string titleKey, string subTitleKey) = category switch
		{
			Categories.MicrosoftSecurityBaseline => ("ProtectCategory_MSFTSecBaseline", "ProtectCategory_Description_MSFTSecBaseline"),
			Categories.MSFTSecBaselines_OptionalOverrides => ("ProtectCategory_MSFTSecBaselineOverrides", "ProtectCategory_Description_MSFTSecBaselineOverrides"),
			Categories.Microsoft365AppsSecurityBaseline => ("ProtectCategory_MSFT365AppsSecBaseline", "ProtectCategory_Description_MSFT365AppsSecBaseline"),
			Categories.MicrosoftDefender => ("ProtectCategory_MSFTDefender", "ProtectCategory_Description_MSFTDefender"),
			Categories.AttackSurfaceReductionRules => ("ProtectCategory_ASRRules", "ProtectCategory_Description_ASRRules"),
			Categories.BitLockerSettings => ("ProtectCategory_BitLocker", "ProtectCategory_Description_BitLocker"),
			Categories.TLSSecurity => ("ProtectCategory_TLS", "ProtectCategory_Description_TLS"),
			Categories.LockScreen => ("ProtectCategory_LockScreen", "ProtectCategory_Description_LockScreen"),
			Categories.UserAccountControl => ("ProtectCategory_UAC", "ProtectCategory_Description_UAC"),
			Categories.DeviceGuard => ("ProtectCategory_DeviceGuard", "ProtectCategory_Description_DeviceGuard"),
			Categories.WindowsFirewall => ("ProtectCategory_WindowsFirewall", "ProtectCategory_Description_WindowsFirewall"),
			Categories.OptionalWindowsFeatures => ("ProtectCategory_OptionalWinFeatures", "ProtectCategory_Description_OptionalWinFeatures"),
			Categories.WindowsNetworking => ("ProtectCategory_WindowsNetworking", "ProtectCategory_Description_WindowsNetworking"),
			Categories.MiscellaneousConfigurations => ("ProtectCategory_MiscellaneousConfig", "ProtectCategory_Description_MiscellaneousConfig"),
			Categories.WindowsUpdateConfigurations => ("ProtectCategory_WindowsUpdate", "ProtectCategory_Description_WindowsUpdate"),
			Categories.EdgeBrowserConfigurations => ("ProtectCategory_Edge", "ProtectCategory_Description_Edge"),
			Categories.CountryIPBlocking => ("ProtectCategory_CountryIPBlock", "CountryIPBlockingNavItem/ToolTipService/ToolTip"),
			Categories.NonAdminCommands => ("ProtectCategory_NonAdmin", "ProtectCategory_Description_NonAdmin"),
			_ => throw new ArgumentOutOfRangeException(nameof(category), category, "Category is not available in the Protect page.")
		};

		return new ProtectionCategoryListViewItem(
			category: category,
			title: Atlas.GetStr(titleKey),
			subTitle: Atlas.GetStr(subTitleKey),
			logo: CategoryImages[(int)category],
			subCategories: subCategories ?? []
			);
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
	private async Task<PresetOperationResult> ExecuteSelectedCategoriesOperation(
		MUnitOperation operation,
		AnimatedCancellableButtonInitializer button,
		Func<int, int, string, Task>? progress = null)
	{
		if (ProtectionCategoriesListItemsSourceSelectedItems.Count == 0)
		{
			MainInfoBar.WriteWarning("No categories selected. Please select at least one category to process.");
			return default;
		}

		bool errorsOccurred = false;
		PresetVerificationResult? verificationResult = null;
		PresetOperationResult operationResult = default;

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
					.OrderBy(static item => CategoryProcessorFactory.GetExecutionPriority(item.Category)).ToList();

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
					HighlightCategory(selectedCategory.Category);
					if (progress is not null)
					{
						try
						{
							await progress(processedCategories, totalCategories, selectedCategory.Title);
						}
						catch (Exception ex)
						{
							// Progress delivery is optional and must not stop or partially apply a protection operation.
							Logger.Write(ex);
							progress = null;
						}
					}

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

				string toastTitle = "Protection operation completed.";
				string toastBody = $"Successfully {operationPastTense} {processedCategories} categories.";
				string toastAttribution = "Review the results on the Protect page.";

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
					verificationResult = new(totalCategories, VerificationTotal, VerificationCompliant, VerificationNonCompliant, VerificationPercentage);

					// Trigger update for the string property
					OnPropertyChanged(nameof(VerificationPercentageString));

					DisplayVerificationPopup();

					Logger.Write($"Verified {VerificationTotal} Security Measures in total. {VerificationCompliant} were compliant while {VerificationNonCompliant} were non-compliant. The system's security score is: {VerificationPercentage:F1}% UwU");

					toastTitle = "Security verification completed.";
					toastBody = $"{VerificationCompliant} of {VerificationTotal} security measures are compliant.";
					toastAttribution = $"System security score: {VerificationPercentage:F1}%";
				}

				UnelevatedOperations.ToastNotifications.ShowToastNotification(
					title: toastTitle,
					body: toastBody,
					attributionText: toastAttribution,
					group: "Protection Operations",
					soundEvent: AppNotificationSoundEvent.SMS);

				operationResult = new(true, verificationResult);
			}
		}
		catch (OperationCanceledException)
		{
			button.wasCancelled = true;
		}
		catch (Exception ex)
		{
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
			HighlightCategory(null);
			// Re-enable UI elements and clear current running operation
			ElementsAreEnabled = true;
			CurrentRunningOperation = RunningOperation.None;
		}
		return operationResult;
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
	internal async Task<PresetOperationResult> RunPresetFromCliAsync(int presetIndex, MUnitOperation operation, Func<int, int, string, Task>? progress = null)
	{
		// This setter triggers GenerateCategories and the same selection logic the UI uses.
		ProtectionPresetsSelectedIndex = presetIndex;

		// Run the exact same pipeline as the UI buttons.
		// Passing ApplySelectedCancellableButton just to satisfy the method signature, it has no effect on CLI operation.
		return await ExecuteSelectedCategoriesOperation(operation, ApplySelectedCancellableButton, progress);
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

			using CancellationTokenSource cts = BeginSystemStateOperation();

			await Traverse.Generator.GenerateTraverseData(filePath: savePath, categoryStarted: HighlightCategory, cancellationToken: cts.Token);

			MainInfoBar.WriteSuccess(string.Format(Atlas.GetStr("SystemStateReportGenerationFinishedMsg"), savePath));
		}
		catch (Exception ex) when (IsCancellationException(ex))
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("OperationCancelledMsg"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			EndSystemStateOperation();
			ElementsAreEnabled = true;
			EnableDisableAnimatedButtons(true);
		}
	}

	/// <summary>
	/// Event handler for the UI.
	/// </summary>
	internal async void RestoreSystemState() => await ReviewSystemStateAsync(apply: true);

	/// <summary>
	/// Event handler for the UI. Opens a backup file for modification only, without applying it.
	/// </summary>
	internal async void FineTuneSystemState() => await ReviewSystemStateAsync(apply: false);

	/// <summary>
	/// Loads a backup file and displays it in the <see cref="SystemStateRestoreDialog"/> for review and modification.
	/// </summary>
	/// <param name="apply">Whether the dialog offers applying the backup to the system.</param>
	private async Task ReviewSystemStateAsync(bool apply)
	{
		try
		{
			ElementsAreEnabled = false;
			EnableDisableAnimatedButtons(false);

			using IDisposable taskTracker = TaskTracking.RegisterOperation();

			string? loadPath = FileDialogHelper.ShowFilePickerDialog(Atlas.JSONPickerFilter);

			if (loadPath is null)
				return;

			// Load the file and let the user review and modify its contents before applying them.
			(JsonObject root, Traverse.MContainer container) = await Task.Run(() => Traverse.MContainerJsonContext.LoadEditable(loadPath));

			using SystemStateRestoreDialog dialog = new(loadPath, root, container, apply ? RestorationModeFull : null);

			if (await dialog.ShowAsync() is not ContentDialogResult.Primary)
				return;

			MainInfoBar.WriteInfo(Atlas.GetStr("SystemStateRestorationBeginsMsg"));

			using CancellationTokenSource cts = BeginSystemStateOperation();

			await Traverse.Importer.ApplyAsync(
				container: container,
				filePath: loadPath,
				synchronizeExact: RestorationModeFull,
				categoryStarted: HighlightCategory,
				cancellationToken: cts.Token
				);

			MainInfoBar.WriteSuccess(Atlas.GetStr("SystemStateRestorationFinishedMsg"));
		}
		catch (Exception ex) when (IsCancellationException(ex))
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("OperationCancelledMsg"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			EndSystemStateOperation();
			ElementsAreEnabled = true;
			EnableDisableAnimatedButtons(true);
		}
	}

	/// <summary>
	/// Cancellation source of the running system state backup or restore operation.
	/// </summary>
	private CancellationTokenSource? SystemStateCts;

	/// <summary>
	/// Whether a system state backup or restore operation is running. Displays the Cancel button for it.
	/// </summary>
	internal bool IsSystemStateOperationRunning { get; private set => SP(ref field, value); }

	/// <summary>
	/// Starts tracking a cancellable system state operation. The caller owns and disposes the returned source.
	/// </summary>
	private CancellationTokenSource BeginSystemStateOperation()
	{
		SystemStateCts = new();
		IsSystemStateOperationRunning = true;
		return SystemStateCts;
	}

	/// <summary>
	/// Stops tracking the system state operation and clears the category highlight.
	/// </summary>
	private void EndSystemStateOperation()
	{
		SystemStateCts = null;
		IsSystemStateOperationRunning = false;
		HighlightCategory(null);
	}

	/// <summary>
	/// Event handler for the UI Cancel button of the system state operations.
	/// </summary>
	internal void CancelSystemStateOperation()
	{
		SystemStateCts?.Cancel();
		MainInfoBar.WriteInfo(Atlas.GetStr("Cancelling"));
	}

	/// <summary>
	/// Highlights the category that is currently being processed in the Protect page's ListView and scrolls it into view.
	/// Pass null to remove the highlight.
	/// </summary>
	private void HighlightCategory(Categories? category)
	{
		ProtectionCategoryListViewItem? activeItem = null;

		foreach (ProtectionCategoryListViewItem item in ProtectionCategoriesListItemsSource)
		{
			item.IsProcessing = item.Category == category;

			if (item.IsProcessing)
				activeItem = item;
		}

		// The ListView is disabled during operations so the user cannot scroll to the active item manually.
		if (activeItem is not null)
			_ = Atlas.AppDispatcher.TryEnqueue(() => UIListView?.ScrollIntoView(activeItem, ScrollIntoViewAlignment.Leading));
	}

	internal bool RestorationModePartial
	{
		get; set
		{
			// Prevent unchecking if the other one isn't checked
			if (!value && !RestorationModeFull) return;

			if (SP(ref field, value) && value)
			{
				RestorationModeFull = false;
			}
		}
	}

	internal bool RestorationModeFull
	{
		get; set
		{
			// Prevent unchecking if the other one isn't checked
			if (!RestorationModePartial && !value) return;

			if (SP(ref field, value) && value)
			{
				RestorationModePartial = false;
			}
		}
	} = true;

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
		// Defer showing the popup until the page is loaded to make sure the user sees it.
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
#pragma warning disable IDE0010
		switch (category)
		{
			case Categories.MicrosoftSecurityBaseline:
				Traverse.MicrosoftSecurityBaseline msb = await ViewModelProvider.MicrosoftSecurityBaselineVM.GetTraverseData();
				return (msb.Items.Count, msb.Score);
			case Categories.Microsoft365AppsSecurityBaseline:
				Traverse.Microsoft365AppsSecurityBaseline m365 = await ViewModelProvider.Microsoft365AppsSecurityBaselineVM.GetTraverseData();
				return (m365.Items.Count, m365.Score);
			case Categories.AttackSurfaceReductionRules:
				Traverse.AttackSurfaceReductionRules asr = await ViewModelProvider.ASRVM.GetTraverseData();
				return (asr.Items.Count, asr.Score);
			default:
				// MUnit-based categories get their stats from the ViewModel that owns their MUnits.
				IMUnitListViewModel? vm = CategoryProcessorFactory.GetMUnitViewModel(category);
				return vm is null ? (0, 0) : GetMUnitStats(vm);
		}
#pragma warning restore IDE0010
	}

	private static (int Total, int Compliant) GetMUnitStats(IMUnitListViewModel vm)
	{
		int total = vm.AllMUnits.Count;
		int compliant = vm.AllMUnits.Count(static m => m.IsApplied == true);
		return (total, compliant);
	}

	#endregion

	internal void Page_Unloaded()
	{
		// Null the UI references when the page is unloaded.
		UIListView = null;
		VerificationResultsPopUp = null;
	}

	internal void Page_Loaded()
	{
		if (VerificationPopupIsPending)
			DisplayVerificationPopup();
	}

	public void Dispose() => SystemStateCts?.Dispose();
}
