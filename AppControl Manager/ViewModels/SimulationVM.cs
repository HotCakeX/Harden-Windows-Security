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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.ViewModels;

internal sealed partial class SimulationVM : ViewModelBase
{

	internal SimulationVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			null, null);

		ProgressRingValueProgress = new Progress<double>(p => ProgressRingValue = p);
	}

	internal readonly InfoBarSettings MainInfoBar;

	internal readonly ObservableCollection<SimulationOutput> SimulationOutputs = [];

	/// <summary>
	/// Store all outputs for searching
	/// </summary>
	internal readonly List<SimulationOutput> AllSimulationOutputs = [];

	/// <summary>
	/// For selected file paths
	/// </summary>
	internal UniqueStringObservableCollection FilePaths = [];

	/// <summary>
	/// For selected folder paths
	/// </summary>
	internal readonly UniqueStringObservableCollection FolderPaths = [];

	/// <summary>
	/// For selected XML file path
	/// </summary>
	internal string? XmlFilePath { get; set => SP(ref field, value); }

	/// <summary>
	/// For selected Cat Root paths
	/// </summary>
	internal List<string> CatRootPaths = [];

	/// <summary>
	/// The total count of the Simulation results.
	/// </summary>
	internal string TotalCountOfTheFilesTextBox { get; set => SP(ref field, value); } = "0";

	/// <summary>
	/// The text entered in the Text box for search.
	/// </summary>
	internal string? SearchBoxTextBox { get; set => SP(ref field, value); }

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	/// <summary>
	/// Determines whether the UI elements are enabled or disabled.
	/// </summary>
	internal bool AreElementsEnabled { get; set => SP(ref field, value); } = true;

	// a Progress<double> so Report() callbacks run on the UI thread
	internal IProgress<double> ProgressRingValueProgress;

	/// <summary>
	/// Value of the UI Progress Ring.
	/// </summary>
	internal double ProgressRingValue { get; set => SP(ref field, value); }

	/// <summary>
	/// The value of the Radial Gauge for scalability.
	/// </summary>
	internal double ScalabilityRadialGaugeValue
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ScalabilityButtonContent = GlobalVars.GetStr("Scalability") + field;
			}
		}
	} = 2;

	/// <summary>
	/// The content of the button that has the RadialGauge inside it.
	/// </summary>
	internal string ScalabilityButtonContent { get; set => SP(ref field, value); } = GlobalVars.GetStr("Scalability") + "2";

	/// <summary>
	/// Whether the Simulation should scan and take into account the security catalogs.
	/// </summary>
	internal bool NoCatRootScanning { get; set => SP(ref field, value); } = true;

	#region LISTVIEW IMPLEMENTATIONS

	// Properties to hold each columns' width.
	internal GridLength ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth6 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth7 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth8 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth9 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth10 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth11 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth12 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth13 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth14 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth15 { get; set => SP(ref field, value); }

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidths()
	{

		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("PathHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("SourceHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("IsAuthorizedHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("MatchCriteriaHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("SpecificFileNameLevelMatchCriteriaHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.GetStr("SignerIDHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.GetStr("SignerNameHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.GetStr("SignerCertRootHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureText(GlobalVars.GetStr("SignerCertPublisherHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureText(GlobalVars.GetStr("SignerScopeHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureText(GlobalVars.GetStr("CertSubjectCNHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureText(GlobalVars.GetStr("CertIssuerCNHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureText(GlobalVars.GetStr("CertNotAfterHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureText(GlobalVars.GetStr("CertTBSValueHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureText(GlobalVars.GetStr("FilePathHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (SimulationOutput item in SimulationOutputs)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.Path, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.Source, maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.IsAuthorized.ToString(), maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.MatchCriteria?.ToString(), maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.SpecificFileNameLevelMatchCriteria, maxWidth5);
			maxWidth6 = ListViewHelper.MeasureText(item.SignerID, maxWidth6);
			maxWidth7 = ListViewHelper.MeasureText(item.SignerName, maxWidth7);
			maxWidth8 = ListViewHelper.MeasureText(item.SignerCertRoot, maxWidth8);
			maxWidth9 = ListViewHelper.MeasureText(item.SignerCertPublisher, maxWidth9);
			maxWidth10 = ListViewHelper.MeasureText(item.SignerScope, maxWidth10);
			maxWidth11 = ListViewHelper.MeasureText(item.CertSubjectCN, maxWidth11);
			maxWidth12 = ListViewHelper.MeasureText(item.CertIssuerCN, maxWidth12);
			maxWidth13 = ListViewHelper.MeasureText(item.CertNotAfter, maxWidth13);
			maxWidth14 = ListViewHelper.MeasureText(item.CertTBSValue, maxWidth14);
			maxWidth15 = ListViewHelper.MeasureText(item.FilePath, maxWidth15);
		}

		// Set the column width properties.
		ColumnWidth1 = new GridLength(maxWidth1);
		ColumnWidth2 = new GridLength(maxWidth2);
		ColumnWidth3 = new GridLength(maxWidth3);
		ColumnWidth4 = new GridLength(maxWidth4);
		ColumnWidth5 = new GridLength(maxWidth5);
		ColumnWidth6 = new GridLength(maxWidth6);
		ColumnWidth7 = new GridLength(maxWidth7);
		ColumnWidth8 = new GridLength(maxWidth8);
		ColumnWidth9 = new GridLength(maxWidth9);
		ColumnWidth10 = new GridLength(maxWidth10);
		ColumnWidth11 = new GridLength(maxWidth11);
		ColumnWidth12 = new GridLength(maxWidth12);
		ColumnWidth13 = new GridLength(maxWidth13);
		ColumnWidth14 = new GridLength(maxWidth14);
		ColumnWidth15 = new GridLength(maxWidth15);
	}

	#endregion


	/// <summary>
	/// Event handler for the SearchBox text change
	/// </summary>
	internal void SearchBox_TextChanged()
	{
		string? searchTerm = SearchBoxTextBox?.Trim();

		if (searchTerm is null)
			return;

		// Get the ListView ScrollViewer info
		ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.Locally_Deployed_Policies);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		// Perform a case-insensitive search in all relevant fields
		List<SimulationOutput> filteredResults = AllSimulationOutputs.Where(output =>
			(output.Path is not null && output.Path.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(output.Source is not null && output.Source.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(output.MatchCriteria is not null && output.MatchCriteria.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(output.SpecificFileNameLevelMatchCriteria is not null && output.SpecificFileNameLevelMatchCriteria.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(output.CertSubjectCN is not null && output.CertSubjectCN.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(output.SignerName is not null && output.SignerName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(output.FilePath is not null && output.FilePath.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
		).ToList();

		SimulationOutputs.Clear();

		foreach (SimulationOutput item in filteredResults)
		{
			SimulationOutputs.Add(item);
		}

		if (Sv != null && savedHorizontal.HasValue)
		{
			// restore horizontal scroll position
			_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
		}
	}


	#region Sort

	/// <summary>
	/// Enum listing all available sort columns.
	/// </summary>
	private enum SimulationSortColumn
	{
		Path,
		Source,
		IsAuthorized,
		MatchCriteria,
		SpecificFileNameLevelMatchCriteria,
		SignerID,
		SignerName,
		SignerCertRoot,
		SignerCertPublisher,
		SignerScope,
		CertSubjectCN,
		CertIssuerCN,
		CertNotAfter,
		CertTBSValue,
		FilePath
	}


	// Sorting state: current sort column and sort direction.
	private SimulationSortColumn? _currentSortColumn;
	private bool _isDescending = true; // Defaults to descending when a new column is selected.

	/// <summary>
	/// Common sort method that toggles sort order on consecutive clicks and resets order on column change.
	/// </summary>
	/// <param name="newSortColumn">The column to sort by.</param>
	private async void Sort(SimulationSortColumn newSortColumn)
	{

		// Get the ListView ScrollViewer info
		ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.Locally_Deployed_Policies);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		// Toggle sort order if the same column is clicked; otherwise, default to descending.
		if (_currentSortColumn.HasValue && _currentSortColumn.Value == newSortColumn)
		{
			_isDescending = !_isDescending;
		}
		else
		{
			_currentSortColumn = newSortColumn;
			_isDescending = true;
		}

		// Use all outputs if no search text; otherwise, sort the currently displayed collection.
		bool isSearchEmpty = string.IsNullOrWhiteSpace(SearchBoxTextBox);

		List<SimulationOutput> sourceData = isSearchEmpty ? AllSimulationOutputs : SimulationOutputs.ToList();

		List<SimulationOutput> sortedData = [];

		switch (newSortColumn)
		{
			case SimulationSortColumn.Path:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.Path).ToList() : sourceData.OrderBy(s => s.Path).ToList();
				break;
			case SimulationSortColumn.Source:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.Source).ToList() : sourceData.OrderBy(s => s.Source).ToList();
				break;
			case SimulationSortColumn.IsAuthorized:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.IsAuthorized).ToList() : sourceData.OrderBy(s => s.IsAuthorized).ToList();
				break;
			case SimulationSortColumn.MatchCriteria:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.MatchCriteria).ToList() : sourceData.OrderBy(s => s.MatchCriteria).ToList();
				break;
			case SimulationSortColumn.SpecificFileNameLevelMatchCriteria:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.SpecificFileNameLevelMatchCriteria).ToList() : sourceData.OrderBy(s => s.SpecificFileNameLevelMatchCriteria).ToList();
				break;
			case SimulationSortColumn.SignerID:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.SignerID).ToList() : sourceData.OrderBy(s => s.SignerID).ToList();
				break;
			case SimulationSortColumn.SignerName:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.SignerName).ToList() : sourceData.OrderBy(s => s.SignerName).ToList();
				break;
			case SimulationSortColumn.SignerCertRoot:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.SignerCertRoot).ToList() : sourceData.OrderBy(s => s.SignerCertRoot).ToList();
				break;
			case SimulationSortColumn.SignerCertPublisher:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.SignerCertPublisher).ToList() : sourceData.OrderBy(s => s.SignerCertPublisher).ToList();
				break;
			case SimulationSortColumn.SignerScope:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.SignerScope).ToList() : sourceData.OrderBy(s => s.SignerScope).ToList();
				break;
			case SimulationSortColumn.CertSubjectCN:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.CertSubjectCN).ToList() : sourceData.OrderBy(s => s.CertSubjectCN).ToList();
				break;
			case SimulationSortColumn.CertIssuerCN:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.CertIssuerCN).ToList() : sourceData.OrderBy(s => s.CertIssuerCN).ToList();
				break;
			case SimulationSortColumn.CertNotAfter:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.CertNotAfter).ToList() : sourceData.OrderBy(s => s.CertNotAfter).ToList();
				break;
			case SimulationSortColumn.CertTBSValue:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.CertTBSValue).ToList() : sourceData.OrderBy(s => s.CertTBSValue).ToList();
				break;
			case SimulationSortColumn.FilePath:
				sortedData = _isDescending ? sourceData.OrderByDescending(s => s.FilePath).ToList() : sourceData.OrderBy(s => s.FilePath).ToList();
				break;
			default:
				break;
		}

		// Update the observable collection on the UI thread.
		await Dispatcher.EnqueueAsync(() =>
		{
			SimulationOutputs.Clear();
			foreach (SimulationOutput item in sortedData)
			{
				SimulationOutputs.Add(item);
			}

			if (Sv != null && savedHorizontal.HasValue)
			{
				// restore horizontal scroll position
				_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
			}
		});
	}

	// Methods bound to each header button’s Click events.
	internal void SortByPath() { Sort(SimulationSortColumn.Path); }
	internal void SortBySource() { Sort(SimulationSortColumn.Source); }
	internal void SortByIsAuthorized() { Sort(SimulationSortColumn.IsAuthorized); }
	internal void SortByMatchCriteria() { Sort(SimulationSortColumn.MatchCriteria); }
	internal void SortBySpecificFileNameLevelMatchCriteria() { Sort(SimulationSortColumn.SpecificFileNameLevelMatchCriteria); }
	internal void SortBySignerID() { Sort(SimulationSortColumn.SignerID); }
	internal void SortBySignerName() { Sort(SimulationSortColumn.SignerName); }
	internal void SortBySignerCertRoot() { Sort(SimulationSortColumn.SignerCertRoot); }
	internal void SortBySignerCertPublisher() { Sort(SimulationSortColumn.SignerCertPublisher); }
	internal void SortBySignerScope() { Sort(SimulationSortColumn.SignerScope); }
	internal void SortByCertSubjectCN() { Sort(SimulationSortColumn.CertSubjectCN); }
	internal void SortByCertIssuerCN() { Sort(SimulationSortColumn.CertIssuerCN); }
	internal void SortByCertNotAfter() { Sort(SimulationSortColumn.CertNotAfter); }
	internal void SortByCertTBSValue() { Sort(SimulationSortColumn.CertTBSValue); }
	internal void SortByFilePath() { Sort(SimulationSortColumn.FilePath); }

	#endregion


	/// <summary>
	/// Exports the list of SimulationOutput objects to a CSV file.
	/// </summary>
	internal async void ExportToCsv()
	{

		if (AllSimulationOutputs.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoSimulationOutputToExport"));
			return;
		}

		await Task.Run(() =>
		{

			string outputFilePath = Path.Combine(GlobalVars.UserConfigDir, @$"AppControl Simulation output {DateTime.Now:yyyy-MM-dd HH-mm-ss}.csv");

			// Use a StringBuilder to gather CSV content.
			StringBuilder csvBuilder = new();

			_ = csvBuilder.AppendLine("\"Path\",\"Source\",\"IsAuthorized\",\"SignerID\",\"SignerName\",\"SignerCertRoot\","
				+ "\"SignerCertPublisher\",\"SignerScope\",\"SignerFileAttributeIDs\",\"MatchCriteria\","
				+ "\"SpecificFileNameLevelMatchCriteria\",\"CertSubjectCN\",\"CertIssuerCN\",\"CertNotAfter\","
				+ "\"CertTBSValue\",\"FilePath\"");

			foreach (SimulationOutput record in AllSimulationOutputs)
			{
				// Retrieve all properties. If a property is null, use an empty string.
				// Use a helper method to properly wrap and escape the values.
				List<string> values =
				[
					WrapValue(record.Path),
					WrapValue(record.Source),
					WrapValue(record.IsAuthorized.ToString()),
					WrapValue(record.SignerID),
					WrapValue(record.SignerName),
					WrapValue(record.SignerCertRoot),
					WrapValue(record.SignerCertPublisher),
					WrapValue(record.SignerScope),
                    // For the list, join the items using a comma separator.
                    WrapValue(record.SignerFileAttributeIDs is not null
						? string.Join(",", record.SignerFileAttributeIDs)
						: string.Empty),
					WrapValue(record.MatchCriteria),
					WrapValue(record.SpecificFileNameLevelMatchCriteria),
					WrapValue(record.CertSubjectCN),
					WrapValue(record.CertIssuerCN),
					WrapValue(record.CertNotAfter),
					WrapValue(record.CertTBSValue),
					WrapValue(record.FilePath)
				];

				// Join the values with comma and add the row to our CSV builder.
				_ = csvBuilder.AppendLine(string.Join(",", values));
			}

			// Write the CSV content to file
			File.WriteAllText(outputFilePath, csvBuilder.ToString());

		});
	}

	/// <summary>
	/// Wraps a value in double quotes, replacing nulls with empty strings and escaping inner quotes.
	/// </summary>
	/// <param name="value">The value to wrap.</param>
	/// <returns>A string with the value wrapped in double quotes.</returns>
	private static string WrapValue(string? value)
	{
		// If the value is null, use empty string.
		string safeValue = value ?? string.Empty;

		// Escape any double quotes within the value by doubling them.
		safeValue = safeValue.Replace("\"", "\"\"");

		// Wrap the value in double quotes.
		return $"\"{safeValue}\"";
	}

	/// <summary>
	/// Converts the properties of a SimulationOutput row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	/// <param name="row">The selected SimulationOutput row from the ListView.</param>
	/// <returns>A formatted string of the row's properties with labels.</returns>
	private static string ConvertRowToText(SimulationOutput row)
	{
		// Use StringBuilder to format each property with its label for easy reading
		return new StringBuilder()
			.AppendLine($"Path: {row.Path}")
			.AppendLine($"Source: {row.Source}")
			.AppendLine($"Is Authorized: {row.IsAuthorized}")
			.AppendLine($"Match Criteria: {row.MatchCriteria}")
			.AppendLine($"Specific File Name Criteria: {row.SpecificFileNameLevelMatchCriteria}")
			.AppendLine($"Signer ID: {row.SignerID}")
			.AppendLine($"Signer Name: {row.SignerName}")
			.AppendLine($"Signer Cert Root: {row.SignerCertRoot}")
			.AppendLine($"Signer Cert Publisher: {row.SignerCertPublisher}")
			.AppendLine($"Signer Scope: {row.SignerScope}")
			.AppendLine($"Cert Subject CN: {row.CertSubjectCN}")
			.AppendLine($"Cert Issuer CN: {row.CertIssuerCN}")
			.AppendLine($"Cert Not After: {row.CertNotAfter}")
			.AppendLine($"Cert TBS Value: {row.CertTBSValue}")
			.AppendLine($"File Path: {row.FilePath}")
			.ToString();
	}

	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	internal void ListViewFlyoutMenuCopy_Click()
	{

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Simulation);
		if (lv is null) return;

		// Check if there are selected items in the ListView
		if (lv.SelectedItems.Count > 0)
		{
			// Initialize StringBuilder to store all selected rows' data with labels
			StringBuilder dataBuilder = new();

			// Loop through each selected item in the ListView
			foreach (var selectedItem in lv.SelectedItems)
			{
				if (selectedItem is SimulationOutput obj)

					// Append each row's formatted data to the StringBuilder
					_ = dataBuilder.AppendLine(ConvertRowToText(obj));

				// Add a separator between rows for readability in multi-row copies
				_ = dataBuilder.AppendLine(ListViewHelper.DefaultDelimiter);
			}

			ClipboardManagement.CopyText(dataBuilder.ToString());
		}
	}

	// Click event handlers for each property
	internal void CopyPath_Click() => CopyToClipboard((item) => item.Path);
	internal void CopySource_Click() => CopyToClipboard((item) => item.Source);
	internal void CopyIsAuthorized_Click() => CopyToClipboard((item) => item.IsAuthorized.ToString());
	internal void CopyMatchCriteria_Click() => CopyToClipboard((item) => item.MatchCriteria);
	internal void CopySpecificFileNameLevelMatch_Click() => CopyToClipboard((item) => item.SpecificFileNameLevelMatchCriteria);
	internal void CopySignerID_Click() => CopyToClipboard((item) => item.SignerID);
	internal void CopySignerName_Click() => CopyToClipboard((item) => item.SignerName);
	internal void CopySignerCertRoot_Click() => CopyToClipboard((item) => item.SignerCertRoot);
	internal void CopySignerCertPublisher_Click() => CopyToClipboard((item) => item.SignerCertPublisher);
	internal void CopySignerScope_Click() => CopyToClipboard((item) => item.SignerScope);
	internal void CopyCertSubjectCN_Click() => CopyToClipboard((item) => item.CertSubjectCN);
	internal void CopyCertIssuerCN_Click() => CopyToClipboard((item) => item.CertIssuerCN);
	internal void CopyCertNotAfter_Click() => CopyToClipboard((item) => item.CertNotAfter);
	internal void CopyCertTBSValue_Click() => CopyToClipboard((item) => item.CertTBSValue);
	internal void CopyFilePath_Click() => CopyToClipboard((item) => item.FilePath);

	/// <summary>
	/// Helper method to copy a specified property to clipboard without reflection
	/// </summary>
	/// <param name="getProperty">Function that retrieves the desired property value as a string</param>
	private static void CopyToClipboard(Func<SimulationOutput, string?> getProperty)
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Simulation);
		if (lv is null) return;

		if (lv.SelectedItem is SimulationOutput selectedItem)
		{
			string? propertyValue = getProperty(selectedItem);
			if (propertyValue is not null)
			{
				ClipboardManagement.CopyText(propertyValue);
			}
		}
	}

	/// <summary>
	/// Event handler for the Begin Simulation button
	/// </summary>
	internal async void BeginSimulationButton_Click()
	{
		if (XmlFilePath is null || !File.Exists(XmlFilePath))
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectExistingXmlPolicyFileMessage"));
			return;
		}

		bool error = false;

		try
		{
			AreElementsEnabled = false;

			MainInfoBarIsClosable = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("PerformingSimulationMessage"));

			// Run the simulation
			ConcurrentDictionary<string, SimulationOutput> result = await Task.Run(() =>
			{
				return AppControlSimulation.Invoke(
					FilePaths.UniqueItems,
					FolderPaths.UniqueItems,
					XmlFilePath,
					NoCatRootScanning,
					CatRootPaths,
					(ushort)ScalabilityRadialGaugeValue,
					ProgressRingValueProgress
				);
			});

			// Clear the current ObservableCollection and backup the full data set
			SimulationOutputs.Clear();
			AllSimulationOutputs.Clear();

			// Update the TextBox with the total count of files
			TotalCountOfTheFilesTextBox = result.Count.ToString(CultureInfo.InvariantCulture);

			AllSimulationOutputs.AddRange(result.Values);

			// Add to the ObservableCollection bound to the UI
			foreach (KeyValuePair<string, SimulationOutput> entry in result)
			{
				// Add a reference to the ViewModel class so we can use it for navigation in the XAML
				entry.Value.ParentViewModelSimulationVM = this;
				SimulationOutputs.Add(entry.Value);
			}

			CalculateColumnWidths();
		}
		catch (NoValidFilesSelectedException ex)
		{
			error = true;
			MainInfoBar.WriteWarning(ex.Message);

			return;
		}
		catch (Exception ex)
		{
			error = true;
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorDuringSimulationMessage"));
		}
		finally
		{
			if (!error)
			{
				MainInfoBar.WriteSuccess(GlobalVars.GetStr("SimulationCompletedSuccessfullyMessage"));
			}

			AreElementsEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for the Select XML File button
	/// </summary>
	internal void SelectXmlFileButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			XmlFilePath = selectedFile;
		}
	}

	/// <summary>
	/// Event handler for the Select Files button
	/// </summary>
	internal void SelectFilesButton_Click()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.AnyFilePickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string item in selectedFiles)
			{
				FilePaths.Add(item);
			}
		}
	}

	/// <summary>
	/// Event handler for the Select Folders button
	/// </summary>
	internal void SelectFoldersButton_Click()
	{
		List<string> selectedFolders = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		if (selectedFolders.Count > 0)
		{
			foreach (string folder in selectedFolders)
			{
				FolderPaths.Add(folder);
			}
		}
	}

	/// <summary>
	/// Event handler for the Cat Root Paths button
	/// </summary>
	internal void CatRootPathsButton_Click()
	{
		List<string> selectedCatRoots = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		if (selectedCatRoots.Count > 0)
		{
			CatRootPaths = selectedCatRoots;
		}
	}

	// Event handler for the Clear Data button
	internal void ClearDataButton_Click()
	{
		// Clear the ObservableCollection
		SimulationOutputs.Clear();
		// Clear the full data
		AllSimulationOutputs.Clear();

		// set the total count to 0 after clearing all the data
		TotalCountOfTheFilesTextBox = "0";
	}

	internal void SelectXmlFileButton_Flyout_Clear_Click()
	{
		XmlFilePath = null;
	}

	internal void SelectFilesButton_Flyout_Clear_Click()
	{
		FilePaths.Clear();
	}

	internal void SelectFoldersButton_Flyout_Clear_Click()
	{
		FolderPaths.Clear();
	}

	/// <summary>
	/// CTRL + C shortcuts event handler
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	internal void CtrlC_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		ListViewFlyoutMenuCopy_Click();
		args.Handled = true;
	}
}
