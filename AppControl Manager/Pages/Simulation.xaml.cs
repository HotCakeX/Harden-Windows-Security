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
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using CommunityToolkit.WinUI;
using CommunityToolkit.WinUI.Controls;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;
using WinRT;

namespace AppControlManager.Pages;

// Since the columns for data in the ItemTemplate use "Binding" instead of "x:Bind", we need to use [GeneratedBindableCustomProperty] for them to work properly
[GeneratedBindableCustomProperty]
public sealed partial class Simulation : Page, INotifyPropertyChanged
{

	#region LISTVIEW IMPLEMENTATIONS

	public event PropertyChangedEventHandler? PropertyChanged;
	private void OnPropertyChanged(string propertyName) =>
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

	// Properties to hold each columns' width.
	private GridLength _columnWidth1;
	public GridLength ColumnWidth1
	{
		get => _columnWidth1;
		set { _columnWidth1 = value; OnPropertyChanged(nameof(ColumnWidth1)); }
	}

	private GridLength _columnWidth2;
	public GridLength ColumnWidth2
	{
		get => _columnWidth2;
		set { _columnWidth2 = value; OnPropertyChanged(nameof(ColumnWidth2)); }
	}

	private GridLength _columnWidth3;
	public GridLength ColumnWidth3
	{
		get => _columnWidth3;
		set { _columnWidth3 = value; OnPropertyChanged(nameof(ColumnWidth3)); }
	}

	private GridLength _columnWidth4;
	public GridLength ColumnWidth4
	{
		get => _columnWidth4;
		set { _columnWidth4 = value; OnPropertyChanged(nameof(ColumnWidth4)); }
	}

	private GridLength _columnWidth5;
	public GridLength ColumnWidth5
	{
		get => _columnWidth5;
		set { _columnWidth5 = value; OnPropertyChanged(nameof(ColumnWidth5)); }
	}

	private GridLength _columnWidth6;
	public GridLength ColumnWidth6
	{
		get => _columnWidth6;
		set { _columnWidth6 = value; OnPropertyChanged(nameof(ColumnWidth6)); }
	}

	private GridLength _columnWidth7;
	public GridLength ColumnWidth7
	{
		get => _columnWidth7;
		set { _columnWidth7 = value; OnPropertyChanged(nameof(ColumnWidth7)); }
	}

	private GridLength _columnWidth8;
	public GridLength ColumnWidth8
	{
		get => _columnWidth8;
		set { _columnWidth8 = value; OnPropertyChanged(nameof(ColumnWidth8)); }
	}

	private GridLength _columnWidth9;
	public GridLength ColumnWidth9
	{
		get => _columnWidth9;
		set { _columnWidth9 = value; OnPropertyChanged(nameof(ColumnWidth9)); }
	}

	private GridLength _columnWidth10;
	public GridLength ColumnWidth10
	{
		get => _columnWidth10;
		set { _columnWidth10 = value; OnPropertyChanged(nameof(ColumnWidth10)); }
	}

	private GridLength _columnWidth11;
	public GridLength ColumnWidth11
	{
		get => _columnWidth11;
		set { _columnWidth11 = value; OnPropertyChanged(nameof(ColumnWidth11)); }
	}

	private GridLength _columnWidth12;
	public GridLength ColumnWidth12
	{
		get => _columnWidth12;
		set { _columnWidth12 = value; OnPropertyChanged(nameof(ColumnWidth12)); }
	}

	private GridLength _columnWidth13;
	public GridLength ColumnWidth13
	{
		get => _columnWidth13;
		set { _columnWidth13 = value; OnPropertyChanged(nameof(ColumnWidth13)); }
	}

	private GridLength _columnWidth14;
	public GridLength ColumnWidth14
	{
		get => _columnWidth14;
		set { _columnWidth14 = value; OnPropertyChanged(nameof(ColumnWidth14)); }
	}

	private GridLength _columnWidth15;
	public GridLength ColumnWidth15
	{
		get => _columnWidth15;
		set { _columnWidth15 = value; OnPropertyChanged(nameof(ColumnWidth15)); }
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
	/// <param name="sender">The event sender.</param>
	/// <param name="e">The event arguments.</param>
	private void ListViewFlyoutMenuCopy_Click(object sender, RoutedEventArgs e)
	{
		// Check if there are selected items in the ListView
		if (SimOutputListView.SelectedItems.Count > 0)
		{
			// Initialize StringBuilder to store all selected rows' data with labels
			StringBuilder dataBuilder = new();

			// Loop through each selected item in the ListView
			foreach (var selectedItem in SimOutputListView.SelectedItems)
			{
				if (selectedItem is SimulationOutput obj)

					// Append each row's formatted data to the StringBuilder
					_ = dataBuilder.AppendLine(ConvertRowToText(obj));

				// Add a separator between rows for readability in multi-row copies
				_ = dataBuilder.AppendLine(ListViewHelper.DefaultDelimiter);
			}

			// Create a DataPackage to hold the text data
			DataPackage dataPackage = new();

			// Set the formatted text as the content of the DataPackage
			dataPackage.SetText(dataBuilder.ToString());

			// Copy the DataPackage content to the clipboard
			Clipboard.SetContent(dataPackage);
		}
	}

	// Click event handlers for each property
	private void CopyPath_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.Path);
	private void CopySource_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.Source);
	private void CopyIsAuthorized_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsAuthorized.ToString());
	private void CopyMatchCriteria_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.MatchCriteria);
	private void CopySpecificFileNameLevelMatch_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SpecificFileNameLevelMatchCriteria);
	private void CopySignerID_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SignerID);
	private void CopySignerName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SignerName);
	private void CopySignerCertRoot_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SignerCertRoot);
	private void CopySignerCertPublisher_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SignerCertPublisher);
	private void CopySignerScope_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SignerScope);
	private void CopyCertSubjectCN_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.CertSubjectCN);
	private void CopyCertIssuerCN_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.CertIssuerCN);
	private void CopyCertNotAfter_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.CertNotAfter);
	private void CopyCertTBSValue_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.CertTBSValue);
	private void CopyFilePath_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FilePath);

	/// <summary>
	/// Helper method to copy a specified property to clipboard without reflection
	/// </summary>
	/// <param name="getProperty">Function that retrieves the desired property value as a string</param>
	private void CopyToClipboard(Func<SimulationOutput, string?> getProperty)
	{
		if (SimOutputListView.SelectedItem is SimulationOutput selectedItem)
		{
			string? propertyValue = getProperty(selectedItem);
			if (propertyValue is not null)
			{
				DataPackage dataPackage = new();
				dataPackage.SetText(propertyValue);
				Clipboard.SetContent(dataPackage);
			}
		}
	}

	// Event handlers for each sort button
	private void ColumnSortingButton_Path_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.Path);
	}
	private void ColumnSortingButton_Source_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.Source);
	}
	private void ColumnSortingButton_IsAuthorized_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.IsAuthorized);
	}
	private void ColumnSortingButton_MatchCriteria_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.MatchCriteria);
	}
	private void ColumnSortingButton_SpecificFileNameLevelMatchCriteria_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.SpecificFileNameLevelMatchCriteria);
	}
	private void ColumnSortingButton_SignerID_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.SignerID);
	}
	private void ColumnSortingButton_SignerName_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.SignerName);
	}
	private void ColumnSortingButton_SignerCertRoot_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.SignerCertRoot);
	}
	private void ColumnSortingButton_SignerCertPublisher_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.SignerCertPublisher);
	}
	private void ColumnSortingButton_SignerScope_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.SignerScope);
	}
	private void ColumnSortingButton_CertSubjectCN_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.CertSubjectCN);
	}
	private void ColumnSortingButton_CertIssuerCN_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.CertIssuerCN);
	}
	private void ColumnSortingButton_CertNotAfter_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.CertNotAfter);
	}
	private void ColumnSortingButton_CertTBSValue_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.CertTBSValue);
	}
	private void ColumnSortingButton_FilePath_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(SimOutput => SimOutput.FilePath);
	}

	/// <summary>
	/// Performs data sorting
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="keySelector"></param>
	private void SortColumn<T>(Func<SimulationOutput, T> keySelector)
	{
		// Determine if a search filter is active.
		bool isSearchEmpty = string.IsNullOrWhiteSpace(SearchBox.Text);
		// Use either the full list (AllSimulationOutputs) or the current display list.
		List<SimulationOutput> collectionToSort = isSearchEmpty ? AllSimulationOutputs : [.. SimulationOutputs];

		if (SortingDirectionToggle.IsChecked)
		{
			// Sort in descending order.
			SimulationOutputs = [.. collectionToSort.OrderByDescending(keySelector)];
		}
		else
		{
			// Sort in ascending order.
			SimulationOutputs = [.. collectionToSort.OrderBy(keySelector)];
		}

		// Refresh the ItemsSource so the UI updates.
		SimOutputListView.ItemsSource = SimulationOutputs;
	}

	#endregion

	internal ObservableCollection<SimulationOutput> SimulationOutputs { get; set; }
	private readonly List<SimulationOutput> AllSimulationOutputs; // Store all outputs for searching
	private List<string> filePaths; // For selected file paths
	private readonly List<string> folderPaths; // For selected folder paths
	private string? xmlFilePath; // For selected XML file path
	private List<string> catRootPaths; // For selected Cat Root paths

	public Simulation()
	{
		this.InitializeComponent();
		this.NavigationCacheMode = NavigationCacheMode.Required;

		SimulationOutputs = [];
		AllSimulationOutputs = [];
		filePaths = [];
		folderPaths = [];
		catRootPaths = [];
	}

	// Event handler for the Begin Simulation button
	private async void BeginSimulationButton_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			// Collect values from UI elements
			bool noCatRootScanning = (NoCatRootScanningToggle.IsChecked);
			double radialGaugeValue = ScalabilityRadialGauge.Value; // Value from radial gauge
			bool CSVOutput = (CSVOutputToggle.IsChecked);

			BeginSimulationButton.IsEnabled = false;
			ScalabilityRadialGauge.IsEnabled = false;

			// Reset the progress bar value back to 0 if it was set from previous runs
			SimulationProgressBar.Value = 0;

			// Run the simulation
			ConcurrentDictionary<string, SimulationOutput> result = await Task.Run(() =>
			{
				return AppControlSimulation.Invoke(
					filePaths,
					folderPaths,
					xmlFilePath,
					noCatRootScanning,
					CSVOutput,
					catRootPaths,
					(ushort)radialGaugeValue,
					SimulationProgressBar
				);
			});

			// Clear the current ObservableCollection and backup the full data set
			SimulationOutputs.Clear();
			AllSimulationOutputs.Clear();

			// Update the TextBox with the total count of files
			TotalCountOfTheFilesTextBox.Text = result.Count.ToString(CultureInfo.InvariantCulture);

			// Add to the ObservableCollection bound to the UI
			await DispatcherQueue.EnqueueAsync(() =>
			{
				// Update the ObservableCollection on the UI thread
				foreach (KeyValuePair<string, SimulationOutput> entry in result)
				{
					// Add to the full list and observable collection
					SimulationOutputs.Add(entry.Value);

					AllSimulationOutputs.Add(entry.Value);
				}

				CalculateColumnWidths();
				SimOutputListView.ItemsSource = SimulationOutputs;
			});
		}
		finally
		{
			BeginSimulationButton.IsEnabled = true;
			ScalabilityRadialGauge.IsEnabled = true;
		}
	}

	// Event handler for the Select XML File button
	private void SelectXmlFileButton_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			xmlFilePath = selectedFile;

			// Update the TextBox with the selected XML file path
			SelectXmlFileButton_SelectedFilesTextBox.Text = selectedFile;
		}
	}

	// Event handler for the Select Files button
	private void SelectFilesButton_Click(object sender, RoutedEventArgs e)
	{
		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.AnyFilePickerFilter);

		if (selectedFiles is { Count: > 0 })
		{
			filePaths = [.. selectedFiles];

			foreach (string file in selectedFiles)
			{
				SelectFilesButton_SelectedFilesTextBox.Text += file + Environment.NewLine;
			}
		}
	}

	// Event handler for the Select Folders button
	private void SelectFoldersButton_Click(object sender, RoutedEventArgs e)
	{
		List<string>? selectedFolders = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		if (selectedFolders is { Count: > 0 })
		{
			foreach (string folder in selectedFolders)
			{
				folderPaths.Add(folder);

				SelectFoldersButton_SelectedFilesTextBox.Text += folder + Environment.NewLine;
			}
		}
	}


	// Event handler for the Cat Root Paths button
	private void CatRootPathsButton_Click(object sender, RoutedEventArgs e)
	{
		List<string>? selectedCatRoots = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		if (selectedCatRoots is { Count: > 0 })
		{
			catRootPaths = selectedCatRoots;
		}
	}


	// Event handler for RadialGauge ValueChanged
	private void ScalabilityRadialGauge_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
	{
		// Update the button content with the current value of the gauge
		ScalabilityButton.Content = $"Scalability: {((RadialGauge)sender).Value:N0}";
	}

	// Event handler for the Clear Data button
	private void ClearDataButton_Click(object sender, RoutedEventArgs e)
	{
		// Clear the ObservableCollection
		SimulationOutputs.Clear();
		// Clear the full data
		AllSimulationOutputs.Clear();

		// set the total count to 0 after clearing all the data
		TotalCountOfTheFilesTextBox.Text = "0";
	}

	// Event handler for the SearchBox text change
	private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		string searchTerm = SearchBox.Text.Trim();

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


		// Update the ObservableCollection with the filtered results
		SimulationOutputs = [.. filteredResults];

		// Explicitly set the ListView's ItemsSource to ensure the data refreshes
		SimOutputListView.ItemsSource = SimulationOutputs;
	}


	private void SelectXmlFileButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!SelectXmlFileButton_Flyout.IsOpen)
				SelectXmlFileButton_Flyout.ShowAt(SelectXmlFileButton);
	}

	private void SelectXmlFileButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!SelectXmlFileButton_Flyout.IsOpen)
			SelectXmlFileButton_Flyout.ShowAt(SelectXmlFileButton);
	}

	private void SelectXmlFileButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		SelectXmlFileButton_SelectedFilesTextBox.Text = null;
		xmlFilePath = null;
	}

	private void SelectFilesButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!SelectFilesButton_Flyout.IsOpen)
			SelectFilesButton_Flyout.ShowAt(SelectFilesButton);
	}

	private void SelectFilesButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!SelectFilesButton_Flyout.IsOpen)
				SelectFilesButton_Flyout.ShowAt(SelectFilesButton);
	}

	private void SelectFilesButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		SelectFilesButton_SelectedFilesTextBox.Text = null;
		filePaths.Clear();
	}

	private void SelectFoldersButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		SelectFoldersButton_SelectedFilesTextBox.Text = null;
		folderPaths.Clear();
	}

	private void SelectFoldersButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!SelectFoldersButton_Flyout.IsOpen)
				SelectFoldersButton_Flyout.ShowAt(SelectFoldersButton);
	}

	private void SelectFoldersButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!SelectFoldersButton_Flyout.IsOpen)
			SelectFoldersButton_Flyout.ShowAt(SelectFoldersButton);
	}


	#region Ensuring right-click on rows behaves better and normally on ListView

	// When right-clicking on an unselected row, first it becomes selected and then the context menu will be shown for the selected row
	// This is a much more expected behavior. Without this, the right-click would be meaningless on the ListView unless user left-clicks on the row first

	private void ListView_ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		// When the container is being recycled, detach the handler.
		if (args.InRecycleQueue)
		{
			args.ItemContainer.RightTapped -= ListViewItem_RightTapped;
		}
		else
		{
			// Detach first to avoid multiple subscriptions, then attach the handler.
			args.ItemContainer.RightTapped -= ListViewItem_RightTapped;
			args.ItemContainer.RightTapped += ListViewItem_RightTapped;
		}
	}

	private void ListViewItem_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (sender is ListViewItem item)
		{
			// If the item is not already selected, clear previous selections and select this one.
			if (!item.IsSelected)
			{
				// Set the counter so that the SelectionChanged event handler will ignore the next 2 events.
				_skipSelectionChangedCount = 2;

				//clear for exclusive selection
				SimOutputListView.SelectedItems.Clear();
				item.IsSelected = true;
			}
		}
	}

	#endregion


	/// <summary>
	/// CTRL + C shortcuts event handler
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void CtrlC_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		ListViewFlyoutMenuCopy_Click(sender, new RoutedEventArgs());
		args.Handled = true;
	}

	// A counter to prevent SelectionChanged event from firing twice when right-clicking on an unselected row
	private int _skipSelectionChangedCount;

	private async void SimOutputListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Check if we need to skip this event.
		if (_skipSelectionChangedCount > 0)
		{
			_skipSelectionChangedCount--;
			return;
		}

		await ListViewHelper.SmoothScrollIntoViewWithIndexCenterVerticallyOnlyAsync(listViewBase: (ListView)sender, listView: (ListView)sender, index: ((ListView)sender).SelectedIndex, disableAnimation: false, scrollIfVisible: true, additionalHorizontalOffset: 0, additionalVerticalOffset: 0);
	}
}
