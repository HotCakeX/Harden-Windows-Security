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
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using CommunityToolkit.WinUI;
using HardenSystemSecurity.GroupPolicy;
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
			null, null);

		// Initialize cancellable buttons
		ApplyAllCancellableButton = new(GlobalVars.GetStr("ApplyAllButtonText/Text"));
		RemoveAllCancellableButton = new(GlobalVars.GetStr("RemoveAllButtonText/Text"));
		VerifyAllCancellableButton = new(GlobalVars.GetStr("VerifyAllButtonText"));

		// To adjust the initial width of the columns, giving them nice paddings.
		CalculateColumnWidths();
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
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("CurrentValueHeaderText"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("ExpectedValueHeaderText"));

		// Iterate over all items to determine the widest string for each column.
		foreach (VerificationResult item in VerificationResults)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.FriendlyName, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.SourceDisplay, maxWidth2);
			maxWidth4 = ListViewHelper.MeasureText(item.CurrentValue, maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.ExpectedValue, maxWidth5);
		}

		// Set the column width properties.
		ColumnWidth1 = new GridLength(maxWidth1);
		ColumnWidth2 = new GridLength(maxWidth2);
		ColumnWidth3 = new GridLength(ListViewHelper.MeasureText(GlobalVars.GetStr("NotAppliedText"), maxWidth3) + 60); // Using the same string as the one StatusIndicatorV2 uses, the longer one.
		ColumnWidth4 = new GridLength(maxWidth4);
		ColumnWidth5 = new GridLength(maxWidth5);
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
	/// Total number of verification results loaded.
	/// </summary>
	internal string TotalResults { get; set => SP(ref field, value); } = "0";

	/// <summary>
	/// Collection of all verification results bound to the ListView.
	/// </summary>
	internal ObservableCollection<VerificationResult> VerificationResults = [];

	/// <summary>
	/// Backing field of all verification results.
	/// </summary>
	internal readonly List<VerificationResult> AllVerificationResults = [];

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
		List<VerificationResult> filteredResults = AllVerificationResults.Where(result =>
			(result.FriendlyName is not null && result.FriendlyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(result.SourceDisplay is not null && result.SourceDisplay.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(result.CurrentValue is not null && result.CurrentValue.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(result.ExpectedValue is not null && result.ExpectedValue.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
		).ToList();

		VerificationResults.Clear();

		foreach (VerificationResult item in filteredResults)
		{
			VerificationResults.Add(item);
		}

		TotalResults = VerificationResults.Count.ToString();

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
			if (VerificationResults.Count == 0)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("NoVerificationResultsToExport"));
				return;
			}

			DateTime now = DateTime.Now;
			string formattedDateTime = now.ToString("yyyy-MM-dd_HH-mm-ss");
			string fileName = string.Format(GlobalVars.GetStr("ExportFileNameFormat"), formattedDateTime);

			string? savePath = FileDialogHelper.ShowSaveFileDialog(GlobalVars.JSONPickerFilter, fileName);

			if (savePath is null)
				return;

			await Task.Run(async () =>
			{
				List<VerificationResult> resultsToExport = VerificationResults.ToList();

				VerificationResult.Save(savePath, resultsToExport);

				await Dispatcher.EnqueueAsync(() =>
				{
					MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyExportedVerificationResults"), resultsToExport.Count, savePath));
				});
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
			MainInfoBar.IsClosable = false;
			MainInfoBar.WriteInfo(GlobalVars.GetStr("ApplyingMicrosoftSecurityBaseline"));

			List<VerificationResult>? results = await MSBaseline.DownloadAndProcessSecurityBaseline(
				new Uri(DownloadURL),
				MSBaseline.Action.Apply,
				microsoftSecurityBaselineVMRef: this,
				cancellationToken: ApplyAllCancellableButton.Cts?.Token);

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
			MainInfoBar.IsClosable = true;
			// Re-enable all three buttons
			CurrentRunningOperation = RunningOperation.None;
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
			MainInfoBar.IsClosable = false;
			MainInfoBar.WriteInfo(GlobalVars.GetStr("RemovingMicrosoftSecurityBaseline"));

			List<VerificationResult>? results = await MSBaseline.DownloadAndProcessSecurityBaseline(
				new Uri(DownloadURL),
				MSBaseline.Action.Remove,
				microsoftSecurityBaselineVMRef: this,
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
			MainInfoBar.IsClosable = true;
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
			MainInfoBar.IsClosable = false;
			MainInfoBar.WriteInfo(GlobalVars.GetStr("VerifyingMicrosoftSecurityBaseline"));

			List<VerificationResult>? results = await MSBaseline.DownloadAndProcessSecurityBaseline(
				new Uri(DownloadURL),
				MSBaseline.Action.Verify,
				microsoftSecurityBaselineVMRef: this,
				cancellationToken: VerifyAllCancellableButton.Cts?.Token) ?? throw new InvalidOperationException(GlobalVars.GetStr("NoResultsReturnedFromVerificationProcess"));

			// Clear existing results
			AllVerificationResults.Clear();
			VerificationResults.Clear();

			// Add new results
			foreach (VerificationResult result in results)
			{
				AllVerificationResults.Add(result);
				VerificationResults.Add(result);
			}

			CalculateColumnWidths();
			TotalResults = VerificationResults.Count.ToString();

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
			MainInfoBar.IsClosable = true;
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

		TotalResults = "0";

		CalculateColumnWidths();
	}

	/// <summary>
	/// Custom URL input for the baseline download
	/// </summary>
	internal string DownloadURL { get; set => SP(ref field, value); } = DefaultDownloadUrl;

	/// <summary>
	/// Default URL.
	/// </summary>
	internal const string DefaultDownloadUrl = @"https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Windows%2011%20v24H2%20Security%20Baseline.zip";

	/// <summary>
	/// Resets to the default URL
	/// </summary>
	internal void ResetToDefaultUrl() => DownloadURL = DefaultDownloadUrl;
}
