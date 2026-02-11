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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using CommonCore.GroupPolicy;
using CommonCore.IncrementalCollection;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using CommonCore.SecurityPolicy;
using HardenSystemSecurity.Traverse;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class MicrosoftSecurityBaselineVM : ViewModelBase
{
	internal MicrosoftSecurityBaselineVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// Initialize cancellable buttons
		ApplyAllCancellableButton = new(GlobalVars.GetStr("ApplyAllButtonText/Text"));
		RemoveAllCancellableButton = new(GlobalVars.GetStr("RemoveAllButtonText/Text"));
		VerifyAllCancellableButton = new(GlobalVars.GetStr("VerifyAllButtonText"));

		// To adjust the initial width of the columns, giving them nice paddings.
		_ = Dispatcher.TryEnqueue(CalculateColumnWidths);

		// Enrich the data to improve detection rate by ensuring specialized strategies are registered.
		SpecializedStrategiesRegistry.RegisterWmiSpecializedVerificationsOnceFromFile();
	}

	/// <summary>
	/// Only one cancellable operation can be active at a time for this page.
	/// </summary>
	internal enum RunningOperation
	{
		None,
		Apply,
		Remove,
		Verify
	}

	/// <summary>
	/// Tracks the currently running operation and toggles each button's enabled state.
	/// </summary>
	internal RunningOperation CurrentRunningOperation
	{
		get; set
		{
			if (SP(ref field, value))
			{
				IsApplyButtonEnabled = field == RunningOperation.None || field == RunningOperation.Apply;
				IsRemoveButtonEnabled = field == RunningOperation.None || field == RunningOperation.Remove;
				IsVerifyButtonEnabled = field == RunningOperation.None || field == RunningOperation.Verify;
			}
		}
	} = RunningOperation.None;

	/// <summary>
	/// Whether the Apply All button should be enabled.
	/// </summary>
	internal bool IsApplyButtonEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the Remove All button should be enabled.
	/// </summary>
	internal bool IsRemoveButtonEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the Verify All button should be enabled.
	/// </summary>
	internal bool IsVerifyButtonEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	/// <summary>
	/// Initialization details for the Apply All button
	/// </summary>
	internal AnimatedCancellableButtonInitializer ApplyAllCancellableButton { get; }

	/// <summary>
	/// Initialization details for the Remove All button
	/// </summary>
	internal AnimatedCancellableButtonInitializer RemoveAllCancellableButton { get; }

	/// <summary>
	/// Initialization details for the Verify All button
	/// </summary>
	internal AnimatedCancellableButtonInitializer VerifyAllCancellableButton { get; }

	#region ListView

	internal GridLength ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth5 { get; set => SP(ref field, value); }

	internal void CalculateColumnWidths()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("FriendlyNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("SourceHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("StatusHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("CurrentValueHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("ExpectedValueHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (VerificationResult item in VerificationResults)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.FriendlyName, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.SourceDisplay, maxWidth2);
			maxWidth4 = ListViewHelper.MeasureText(item.CurrentValue, maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.ExpectedValue, maxWidth5);
		}

		// Set the column width properties.
		ColumnWidth1 = new(maxWidth1);
		ColumnWidth2 = new(maxWidth2);
		ColumnWidth3 = new(ListViewHelper.MeasureText(GlobalVars.GetStr("NotAppliedText"), maxWidth3) + 60); // Using the same string as the one StatusIndicatorV2 uses, the longer one.
		ColumnWidth4 = new(maxWidth4);
		ColumnWidth5 = new(maxWidth5);
	}

	#endregion

	/// <summary>
	/// UI Search box value.
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
	/// Collection of all verification results bound to the ListView.
	/// </summary>
	internal readonly RangedObservableCollection<VerificationResult> VerificationResults = [];

	/// <summary>
	/// Backing field of all verification results.
	/// </summary>
	internal readonly List<VerificationResult> AllVerificationResults = [];

	/// <summary>
	/// Whether the optional overrides must be applied after the Microsoft Security Baseline has been applied or not.
	/// </summary>
	internal bool ApplyBaselineOverridesToggle { get; set => SP(ref field, value); } = true;

	#region Search

	/// <summary>
	/// Event handler for the SearchBox text change
	/// </summary>
	private void SearchBox_TextChanged()
	{
		string? searchTerm = SearchKeyword?.Trim();

		if (searchTerm is null)
			return;

		// Get the ListView ScrollViewer info
		ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.MicrosoftSecurityBaseline);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		// Perform a case-insensitive search in all relevant fields
		IEnumerable<VerificationResult> filteredResults = AllVerificationResults.Where(result =>
			(result.FriendlyName is not null && result.FriendlyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(result.SourceDisplay is not null && result.SourceDisplay.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(result.CurrentValue is not null && result.CurrentValue.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(result.ExpectedValue is not null && result.ExpectedValue.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
		);

		VerificationResults.Clear();
		VerificationResults.AddRange(filteredResults);

		if (Sv != null && savedHorizontal.HasValue)
		{
			// restore horizontal scroll position
			_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
		}
	}

	#endregion

	#region Sort

	/// <summary>
	/// Stores the sort state for the ListView.
	/// </summary>
	private ListViewHelper.SortState SortState { get; set; } = new();

	/// <summary>
	/// Sorts the ListView based on the clicked header column tag.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			Func<VerificationResult, object?> keySelector = key switch
			{
				"FriendlyName" => result => result.FriendlyName,
				"Source" => result => result.SourceDisplay,
				"IsCompliant" => result => result.IsCompliant,
				"CurrentValue" => result => result.CurrentValue,
				"ExpectedValue" => result => result.ExpectedValue,
				_ => result => result.FriendlyName
			};

			ListViewHelper.SortColumn(
				keySelector,
				SearchKeyword,
				AllVerificationResults,
				VerificationResults,
				SortState,
				key,
				regKey: ListViewHelper.ListViewsRegistry.MicrosoftSecurityBaseline);
		}
	}

	#endregion

	/// <summary>
	/// Exports the verification results to a JSON file.
	/// </summary>
	internal async void ExportToJson()
	{
		try
		{
			string? savePath = FileDialogHelper.ShowSaveFileDialog(GlobalVars.JSONPickerFilter, Generator.GetFileName());

			if (savePath is null)
				return;

			Traverse.MicrosoftSecurityBaseline results = await GetTraverseData();

			await Task.Run(() =>
			{
				MContainer container = new(
				total: results.Count,
				compliant: results.Score,
				nonCompliant: results.Count - results.Score,
				microsoftSecurityBaseline: results
				);

				MContainerJsonContext.SerializeSingle(container, savePath);

				MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyExportedVerificationResults"), results.Count, savePath));
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Apply Microsoft Security Baseline.
	/// </summary>
	internal async void ApplySecurityBaseline() => await ApplyInternal();

	internal async Task ApplyInternal()
	{
		bool errorsOccurred = false;
		// Mark "Apply" as the only enabled cancellable button
		CurrentRunningOperation = RunningOperation.Apply;
		ApplyAllCancellableButton.Begin();

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;
			MainInfoBar.WriteInfo(GlobalVars.GetStr("ApplyingMicrosoftSecurityBaseline"));

			// Use custom ZIP file if provided, otherwise use the URL selected in the ComboBox
			Uri sourceUri = !string.IsNullOrEmpty(CustomBaselineFilePath)
				? new Uri(CustomBaselineFilePath)
				: new Uri(DownloadURLs[SecurityBaselinesComboBoxSelectedItem]);

			List<VerificationResult>? results = await MSBaseline.DownloadAndProcessSecurityBaseline(
				sourceUri,
				MSBaseline.Action.Apply,
				cancellationToken: ApplyAllCancellableButton.Cts?.Token);

			// Check if the Optional Overrides toggle is enabled
			if (ApplyBaselineOverridesToggle)
			{
				ICategoryProcessor overridesProcessor = CategoryProcessorFactory.GetProcessor(Categories.MSFTSecBaselines_OptionalOverrides);

				// Apply the optional overrides (apply all MUnits in that category)
				await overridesProcessor.ApplyAllAsync(
					selectedSubCategories: null,
					selectedIntent: null, // No specific intent filter, apply all available overrides
					cancellationToken: ApplyAllCancellableButton.Cts?.Token);
			}

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("MicrosoftSecurityBaselineAppliedSuccessfully"));

			await VerifyInternal();
		}
		catch (Exception ex)
		{
			HandleExceptions(ex, ref errorsOccurred, ref ApplyAllCancellableButton.wasCancelled, MainInfoBar);
		}
		finally
		{
			if (ApplyAllCancellableButton.wasCancelled)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("ApplyOperationCancelledByUser"));
			}

			ApplyAllCancellableButton.End();
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
			// Re-enable all three buttons
			CurrentRunningOperation = RunningOperation.None;
		}
	}

	/// <summary>
	/// Applies security measures imported from a JSON file.
	/// </summary>
	/// <param name="importedItems">List of imported verification results</param>
	/// <param name="synchronizeExact">If true, removes non-compliant settings (Group Policy only)</param>
	/// <param name="cancellationToken">Cancellation token</param>
	internal async Task ApplyImportedStates(List<VerificationResult> importedItems, bool synchronizeExact, CancellationToken cancellationToken)
	{
		// Use the IDs from the verification results to selectively apply settings from the baseline ZIP
		HashSet<string> applyIds = importedItems.Where(x => x.IsCompliant).Select(x => x.ID).ToHashSet(StringComparer.OrdinalIgnoreCase);

		// Use custom ZIP file if provided, otherwise use the URL selected in the ComboBox
		Uri sourceUri = !string.IsNullOrEmpty(CustomBaselineFilePath)
			? new Uri(CustomBaselineFilePath)
			: new Uri(DownloadURLs[SecurityBaselinesComboBoxSelectedItem]);

		if (applyIds.Count > 0)
		{
			Logger.Write($"Applying {applyIds.Count} imported baseline settings...");
			_ = await MSBaseline.DownloadAndProcessSecurityBaseline(
				sourceUri,
				MSBaseline.Action.Apply,
				cancellationToken,
				applyIds);
		}

		// If synchronizeExact is requested, try to remove the policies that are marked as not compliant in the import.
		// P.S MSBaseline currently supports removal only for Group Policy settings (POL files).
		if (synchronizeExact)
		{
			HashSet<string> removeIds = importedItems.Where(x => !x.IsCompliant).Select(x => x.ID).ToHashSet(StringComparer.OrdinalIgnoreCase);
			if (removeIds.Count > 0)
			{
				Logger.Write($"Removing {removeIds.Count} non-compliant imported baseline settings (Group Policy only)...");
				_ = await MSBaseline.DownloadAndProcessSecurityBaseline(
					sourceUri,
					MSBaseline.Action.Remove,
					cancellationToken,
					removeIds);
			}
		}
	}

	/// <summary>
	/// Remove Microsoft Security Baseline.
	/// </summary>
	internal async void RemoveSecurityBaseline() => await RemoveInternal();

	internal async Task RemoveInternal()
	{
		bool errorsOccurred = false;
		// Mark "Remove" as the only enabled cancellable button
		CurrentRunningOperation = RunningOperation.Remove;
		RemoveAllCancellableButton.Begin();

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;
			MainInfoBar.WriteInfo(GlobalVars.GetStr("RemovingMicrosoftSecurityBaseline"));

			// Use custom ZIP file if provided, otherwise use the URL selected in the ComboBox
			Uri sourceUri = !string.IsNullOrEmpty(CustomBaselineFilePath)
				? new Uri(CustomBaselineFilePath)
				: new Uri(DownloadURLs[SecurityBaselinesComboBoxSelectedItem]);

			List<VerificationResult>? results = await MSBaseline.DownloadAndProcessSecurityBaseline(
				sourceUri,
				MSBaseline.Action.Remove,
				cancellationToken: RemoveAllCancellableButton.Cts?.Token);

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("MicrosoftSecurityBaselineRemovedSuccessfully"));

			await VerifyInternal();
		}
		catch (Exception ex)
		{
			HandleExceptions(ex, ref errorsOccurred, ref RemoveAllCancellableButton.wasCancelled, MainInfoBar);
		}
		finally
		{
			if (RemoveAllCancellableButton.wasCancelled)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("RemoveOperationCancelledByUser"));
			}

			RemoveAllCancellableButton.End();
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
			// Re-enable all three buttons
			CurrentRunningOperation = RunningOperation.None;
		}
	}

	/// <summary>
	/// Verify Microsoft Security Baseline.
	/// </summary>
	internal async void VerifySecurityBaseline() => await VerifyInternal();

	internal async Task VerifyInternal()
	{
		bool errorsOccurred = false;
		// Mark "Verify" as the only enabled cancellable button
		CurrentRunningOperation = RunningOperation.Verify;
		VerifyAllCancellableButton.Begin();

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;
			MainInfoBar.WriteInfo(GlobalVars.GetStr("VerifyingMicrosoftSecurityBaseline"));

			// Use custom ZIP file if provided, otherwise use the URL selected in the ComboBox
			Uri sourceUri = !string.IsNullOrEmpty(CustomBaselineFilePath)
				? new Uri(CustomBaselineFilePath)
				: new Uri(DownloadURLs[SecurityBaselinesComboBoxSelectedItem]);

			List<VerificationResult>? results = await MSBaseline.DownloadAndProcessSecurityBaseline(
				sourceUri,
				MSBaseline.Action.Verify,
				cancellationToken: VerifyAllCancellableButton.Cts?.Token) ?? throw new InvalidOperationException(GlobalVars.GetStr("NoResultsReturnedFromVerificationProcess"));

			// Clear existing results
			AllVerificationResults.Clear();
			VerificationResults.Clear();

			// Add new results
			AllVerificationResults.AddRange(results);
			VerificationResults.AddRange(results);

			CalculateColumnWidths();

			int compliantCount = results.Count(r => r.IsCompliant);
			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("VerificationCompletedCompliantPolicies"), compliantCount, results.Count));

		}
		catch (Exception ex)
		{
			HandleExceptions(ex, ref errorsOccurred, ref VerifyAllCancellableButton.wasCancelled, MainInfoBar);
		}
		finally
		{
			if (VerifyAllCancellableButton.wasCancelled)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("VerifyOperationCancelledByUser"));
			}

			VerifyAllCancellableButton.End();
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
			// Re-enable all three buttons
			CurrentRunningOperation = RunningOperation.None;
		}
	}

	/// <summary>
	/// Clears all of the data from the UI.
	/// </summary>
	internal void ClearData()
	{
		VerificationResults.Clear();
		AllVerificationResults.Clear();
		CalculateColumnWidths();
	}

	/// <summary>
	/// Mapping of security baseline names to their download URLs.
	/// </summary>
	private static readonly FrozenDictionary<string, string> DownloadURLs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
	{
		{"Windows 11 version 22H2", @"https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20version%2022H2%20Security%20Baseline.zip"},
		{"Windows 11 version 23H2", @"https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v23H2%20Security%20Baseline.zip"},
		{"Windows 11 version 24H2", @"https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v24H2%20Security%20Baseline.zip"},
		{"Windows 11 version 25H2", @"https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip"},
		{"Windows Server 2025 - 2506", @"https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202025%20Security%20Baseline.zip"}
	}.ToFrozenDictionary();

	internal List<string> SecurityBaselinesComboBoxItemsSource => DownloadURLs.Keys.ToList();

	internal string SecurityBaselinesComboBoxSelectedItem { get; set => SP(ref field, value); } = "Windows 11 version 25H2";

	/// <summary>
	/// The path to the custom baseline file, if any.
	/// </summary>
	internal string? CustomBaselineFilePath
	{
		get; set
		{
			if (SP(ref field, value))
			{
				IsMultiBaselineComboBoxEnabled = string.IsNullOrEmpty(value);
			}
		}
	}

	/// <summary>
	/// Clears the CustomBaselineFilePath
	/// </summary>
	internal void ClearCustomBaselineFilePath() => CustomBaselineFilePath = null;

	/// <summary>
	/// Event handler for the browse button.
	/// </summary>
	internal void CustomBaselineFilePathButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.ZIPFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected file path
			CustomBaselineFilePath = selectedFile;
		}
	}

	/// <summary>
	/// If user selects a custom baseline file, disable the multi-baseline ComboBox.
	/// </summary>
	internal bool IsMultiBaselineComboBoxEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Used for <see cref="Traverse.MContainer"/> data retrieval.
	/// </summary>
	/// <returns></returns>
	internal async Task<Traverse.MicrosoftSecurityBaseline> GetTraverseData()
	{
		// Always get fresh data, otherwise the data may be stale if user just applied the security measures and other categories override the data in the Security Baseline categories.
		await VerifyInternal();

		return new(items: AllVerificationResults) { Score = AllVerificationResults.Count(x => x.IsCompliant) };
	}

	#region Copy

	/// <summary>
	/// Property mappings for VerificationResult used for clipboard operations.
	/// </summary>
	internal static readonly FrozenDictionary<string, (string Label, Func<VerificationResult, object?> Getter)> VerificationResultPropertyMappings
		= new Dictionary<string, (string Label, Func<VerificationResult, object?> Getter)>(StringComparer.OrdinalIgnoreCase)
		{
			{ "FriendlyName",   (GlobalVars.GetStr("FriendlyNameHeader/Text") + ": ", vr => vr.FriendlyName) },
			{ "Source",         (GlobalVars.GetStr("SourceHeader/Text") + ": ",       vr => vr.SourceDisplay) },
			{ "IsCompliant",    (GlobalVars.GetStr("StatusHeader/Text") + ": ",       vr => vr.IsCompliant) },
			{ "CurrentValue",   (GlobalVars.GetStr("CurrentValueHeader/Text") + ": ",  vr => vr.CurrentValue) },
			{ "ExpectedValue",  (GlobalVars.GetStr("ExpectedValueHeader/Text") + ": ", vr => vr.ExpectedValue) }
		}.ToFrozenDictionary();

	/// <summary>
	/// Converts the selected verification results into a labeled text block and copies it to the clipboard.
	/// </summary>
	internal void CopySelectedVerificationResults_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.MicrosoftSecurityBaseline);
		if (lv is null) return;
		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText<VerificationResult>(lv.SelectedItems, VerificationResultPropertyMappings);
		}
	}

	/// <summary>
	/// Copies a single property of the currently selected verification result to the clipboard.
	/// </summary>
	/// <param name="sender">MenuFlyoutItem whose Tag corresponds to the property key.</param>
	/// <param name="e"></param>
	internal void CopyVerificationResultProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.MicrosoftSecurityBaseline);
		if (lv is null) return;

		if (VerificationResultPropertyMappings.TryGetValue(key, out (string Label, Func<VerificationResult, object?> Getter) map))
		{
			ListViewHelper.CopyToClipboard<VerificationResult>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

	#endregion

	#region Delete

	/// <summary>
	/// Deletes/Removes the selected policies from the system.
	/// Supports:
	/// - Group Policy (Registry.pol removal)
	/// - Audit Policy (Setting to No Auditing)
	/// </summary>
	internal async void DeleteSelectedPolicies_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.MicrosoftSecurityBaseline);

		if (lv is null || lv.SelectedItems.Count == 0)
		{
			MainInfoBar.WriteWarning("No policies selected for deletion.");
			return;
		}

		// Collect IDs of the selected items
		HashSet<string> idsToRemove = new(StringComparer.OrdinalIgnoreCase);
		foreach (object item in lv.SelectedItems)
		{
			if (item is VerificationResult res)
			{
				_ = idsToRemove.Add(res.ID);
			}
		}

		if (idsToRemove.Count == 0)
		{
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;
			MainInfoBar.WriteInfo($"Removing {idsToRemove.Count} selected policies...");

			// Use custom ZIP file if provided, otherwise use the URL selected in the ComboBox
			Uri sourceUri = !string.IsNullOrEmpty(CustomBaselineFilePath)
				? new Uri(CustomBaselineFilePath)
				: new Uri(DownloadURLs[SecurityBaselinesComboBoxSelectedItem]);

			// Perform removal with IDs filtering
			_ = await MSBaseline.DownloadAndProcessSecurityBaseline(
				sourceUri,
				MSBaseline.Action.Remove,
				cancellationToken: CancellationToken.None,
				filterIds: idsToRemove);

			MainInfoBar.WriteSuccess("Selected policies removed successfully.");

			// Verify again to show the updated state
			await VerifyInternal();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	#endregion

	/// <summary>
	/// Event handler for the UI button to export System Access policies.
	/// </summary>
	internal async void ExportSystemAccessData()
	{
		try
		{
			string? filePath = FileDialogHelper.ShowSaveFileDialog(GlobalVars.JSONPickerFilter, "DefaultValues.json");

			if (string.IsNullOrEmpty(filePath))
				return;

			await Task.Run(() => SystemAccessDefaults.BackupSystemAccessPolicies(filePath));

			MainInfoBar.WriteSuccess($"System Access policies backed up to: {filePath}");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

}
