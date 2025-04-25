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
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.Others;
using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class SimulationVM : ViewModelBase
{
	internal readonly ObservableCollection<SimulationOutput> SimulationOutputs = [];

	// Store all outputs for searching
	internal readonly List<SimulationOutput> AllSimulationOutputs = [];


	#region UI-Bound Properties

	internal string? SearchBoxTextBox
	{
		get; set => SetProperty(ref field, value);
	}

	internal Visibility MainInfoBarVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	internal bool MainInfoBarIsOpen
	{
		get; set => SetProperty(ref field, value);
	}

	internal string? MainInfoBarMessage
	{
		get; set => SetProperty(ref field, value);
	}

	internal InfoBarSeverity MainInfoBarSeverity
	{
		get; set => SetProperty(ref field, value);
	} = InfoBarSeverity.Informational;

	internal bool MainInfoBarIsClosable
	{
		get; set => SetProperty(ref field, value);
	}

	#endregion


	#region LISTVIEW IMPLEMENTATIONS

	// Properties to hold each columns' width.
	internal GridLength ColumnWidth1
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth2
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth3
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth4
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth5
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth6
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth7
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth8
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth9
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth10
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth11
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth12
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth13
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth14
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth15
	{
		get; set => SetProperty(ref field, value);
	}

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidths()
	{

		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PathHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SourceHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsAuthorizedHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("MatchCriteriaHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SpecificFileNameLevelMatchCriteriaHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignerIDHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignerNameHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignerCertRootHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignerCertPublisherHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignerScopeHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("CertSubjectCNHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("CertIssuerCNHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("CertNotAfterHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("CertTBSValueHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FilePathHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (SimulationOutput item in SimulationOutputs)
		{
			double w1 = ListViewHelper.MeasureTextWidth(item.Path);
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewHelper.MeasureTextWidth(item.Source);
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewHelper.MeasureTextWidth(item.IsAuthorized.ToString());
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewHelper.MeasureTextWidth(item.MatchCriteria?.ToString());
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewHelper.MeasureTextWidth(item.SpecificFileNameLevelMatchCriteria);
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewHelper.MeasureTextWidth(item.SignerID);
			if (w6 > maxWidth6) maxWidth6 = w6;

			double w7 = ListViewHelper.MeasureTextWidth(item.SignerName);
			if (w7 > maxWidth7) maxWidth7 = w7;

			double w8 = ListViewHelper.MeasureTextWidth(item.SignerCertRoot);
			if (w8 > maxWidth8) maxWidth8 = w8;

			double w9 = ListViewHelper.MeasureTextWidth(item.SignerCertPublisher);
			if (w9 > maxWidth9) maxWidth9 = w9;

			double w10 = ListViewHelper.MeasureTextWidth(item.SignerScope);
			if (w10 > maxWidth10) maxWidth10 = w10;

			double w11 = ListViewHelper.MeasureTextWidth(item.CertSubjectCN);
			if (w11 > maxWidth11) maxWidth11 = w11;

			double w12 = ListViewHelper.MeasureTextWidth(item.CertIssuerCN);
			if (w12 > maxWidth12) maxWidth12 = w12;

			double w13 = ListViewHelper.MeasureTextWidth(item.CertNotAfter);
			if (w13 > maxWidth13) maxWidth13 = w13;

			double w14 = ListViewHelper.MeasureTextWidth(item.CertTBSValue);
			if (w14 > maxWidth14) maxWidth14 = w14;

			double w15 = ListViewHelper.MeasureTextWidth(item.FilePath);
			if (w15 > maxWidth15) maxWidth15 = w15;
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
		List<SimulationOutput> filteredResults = [.. AllSimulationOutputs.Where(output =>
			(output.Path is not null && output.Path.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(output.Source is not null && output.Source.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(output.MatchCriteria is not null && output.MatchCriteria.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(output.SpecificFileNameLevelMatchCriteria is not null && output.SpecificFileNameLevelMatchCriteria.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(output.CertSubjectCN is not null && output.CertSubjectCN.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(output.SignerName is not null && output.SignerName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(output.FilePath is not null && output.FilePath.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
		)];

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
			Logger.Write("There are no simulation output to export");
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
				List<string> values = new()
				{
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
				};

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

}
