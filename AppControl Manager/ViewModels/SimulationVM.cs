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

using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

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
			Dispatcher, null, null);

		ProgressRingValueProgress = new Progress<double>(p => ProgressRingValue = p);

		// To adjust the initial width of the columns, giving them nice paddings.
		CalculateColumnWidths();
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
	/// The text entered in the Text box for search.
	/// </summary>
	internal string? SearchBoxTextBox { get; set => SPT(ref field, value); }

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
	internal bool ScanSecurityCatalogs { get; set => SP(ref field, value); } = true;

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
			maxWidth2 = ListViewHelper.MeasureText(item.Source.ToString(), maxWidth2);
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
		ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.Simulation);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		// Perform a case-insensitive search in all relevant fields
		List<SimulationOutput> filteredResults = AllSimulationOutputs.Where(output =>
			(output.Path is not null && output.Path.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			output.Source.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
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

	private ListViewHelper.SortState SortState { get; set; } = new();

	// Pre‑computed property getters for high performance.
	// Used for column sorting and column copying (single cell and entire row), for all ListViews that display SimulationOutput data type
	private static readonly FrozenDictionary<string, (string Label, Func<SimulationOutput, object?> Getter)> SimulationOutputPropertyMappings
		= new Dictionary<string, (string Label, Func<SimulationOutput, object?> Getter)>
		{
			{ "Path",                                  (GlobalVars.GetStr("PathHeader/Text") + ": ",                                so => so.Path) },
			{ "Source",                                (GlobalVars.GetStr("SourceHeader/Text") + ": ",                              so => so.Source) },
			{ "IsAuthorized",                          (GlobalVars.GetStr("IsAuthorizedHeader/Text") + ": ",                        so => so.IsAuthorized) },
			{ "SignerID",                              (GlobalVars.GetStr("SignerIDHeader/Text") + ": ",                            so => so.SignerID) },
			{ "SignerName",                            (GlobalVars.GetStr("SignerNameHeader/Text") + ": ",                          so => so.SignerName) },
			{ "SignerCertRoot",                        (GlobalVars.GetStr("SignerCertRootHeader/Text") + ": ",                      so => so.SignerCertRoot) },
			{ "SignerCertPublisher",                   (GlobalVars.GetStr("SignerCertPublisherHeader/Text") + ": ",                 so => so.SignerCertPublisher) },
			{ "SignerScope",                           (GlobalVars.GetStr("SignerScopeHeader/Text") + ": ",                         so => so.SignerScope) },
			{ "MatchCriteria",                         (GlobalVars.GetStr("MatchCriteriaHeader/Text") + ": ",                       so => so.MatchCriteria) },
			{ "SpecificFileNameLevelMatchCriteria",    (GlobalVars.GetStr("SpecificFileNameLevelMatchCriteriaHeader/Text") + ": ",  so => so.SpecificFileNameLevelMatchCriteria) },
			{ "CertSubjectCN",                         (GlobalVars.GetStr("CertSubjectCNHeader/Text") + ": ",                       so => so.CertSubjectCN) },
			{ "CertIssuerCN",                          (GlobalVars.GetStr("CertIssuerCNHeader/Text") + ": ",                        so => so.CertIssuerCN) },
			{ "CertNotAfter",                          (GlobalVars.GetStr("CertNotAfterHeader/Text") + ": ",                        so => so.CertNotAfter) },
			{ "CertTBSValue",                          (GlobalVars.GetStr("CertTBSValueHeader/Text") + ": ",                        so => so.CertTBSValue) },
			{ "FilePath",                              (GlobalVars.GetStr("FilePathHeader/Text") + ": ",                            so => so.FilePath) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			// Look up the mapping in the reusable property mappings dictionary.
			if (SimulationOutputPropertyMappings.TryGetValue(key, out (string Label, Func<SimulationOutput, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					keySelector: mapping.Getter,
					searchBoxText: SearchBoxTextBox,
					originalList: AllSimulationOutputs,
					observableCollection: SimulationOutputs,
					sortState: SortState,
					newKey: key,
					regKey: ListViewHelper.ListViewsRegistry.Simulation);
			}
		}
	}

	#endregion

	#region Copy
	/// <summary>
	/// Converts the properties of a SimulationOutput row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	internal void CopySelectedPolicies_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Simulation);

		if (lv is null) return;

		if (lv.SelectedItems.Count > 0)
		{
			// SelectedItems is an IList, and contains SimulationOutput
			ListViewHelper.ConvertRowToText(lv.SelectedItems, SimulationOutputPropertyMappings);
		}
	}

	/// <summary>
	/// Copy a single property of the current selection
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void CopyPolicyProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Simulation);

		if (lv is null) return;

		if (SimulationOutputPropertyMappings.TryGetValue(key, out var map))
		{
			// TElement = SimulationOutput, copy just that one property
			ListViewHelper.CopyToClipboard<SimulationOutput>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}
	#endregion

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
					ScanSecurityCatalogs,
					CatRootPaths,
					(ushort)ScalabilityRadialGaugeValue,
					ProgressRingValueProgress
				);
			});

			// Clear the current ObservableCollection and backup the full data set
			SimulationOutputs.Clear();
			AllSimulationOutputs.Clear();

			AllSimulationOutputs.AddRange(result.Values);

			// Add to the ObservableCollection bound to the UI
			foreach (KeyValuePair<string, SimulationOutput> entry in result)
			{
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

		CalculateColumnWidths();
	}

	internal void SelectXmlFileButton_Flyout_Clear_Click() => XmlFilePath = null;

	internal void SelectFilesButton_Flyout_Clear_Click() => FilePaths.Clear();

	internal void SelectFoldersButton_Flyout_Clear_Click() => FolderPaths.Clear();

	#region Export

	/// <summary>
	/// Exports all of the Simulation results to JSON.
	/// </summary>
	internal async void ExportToJsonButton_Click()
	{
		if (AllSimulationOutputs.Count is 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("NoSimulationOutputToExport"));
			return;
		}

		try
		{
			DateTime now = DateTime.Now;
			string formattedDateTime = now.ToString("yyyy-MM-dd_HH-mm-ss");
			string fileName = $"AppControlManager_Simulation_Export_{formattedDateTime}.json";

			string? savePath = FileDialogHelper.ShowSaveFileDialog(GlobalVars.JSONPickerFilter, fileName);

			if (savePath is null)
				return;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("ExportingToJSONMsg"));

			List<SimulationOutput> dataToExport = [];

			await Task.Run(() =>
			{
				dataToExport = AllSimulationOutputs.ToList();

				string jsonString = JsonSerializer.Serialize(
					dataToExport,
					SimulationOutputJsonContext.Default.ListSimulationOutput);

				File.WriteAllText(savePath, jsonString);
			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyExportedDataToJSON"), dataToExport.Count, savePath));

		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	#endregion

}
