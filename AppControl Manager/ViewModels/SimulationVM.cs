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
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
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

		// Initialize the column manager with specific definitions for this page
		// We map the Key (for sorting/selection) to the Header Resource Key (for localization) and the Data Getter (for width measurement)
		ColumnManager = new ListViewColumnManager<SimulationOutput>(
		[
			new("Path", "PathHeader/Text", x => x.Path),
			new("Source", "SourceHeader/Text", x => x.Source.ToString()),
			new("IsAuthorized", "IsAuthorizedHeader/Text", x => x.IsAuthorized.ToString()),
			new("MatchCriteria", "MatchCriteriaHeader/Text", x => x.MatchCriteria?.ToString()),
			new("SpecificFileNameLevelMatchCriteria", "SpecificFileNameLevelMatchCriteriaHeader/Text", x => x.SpecificFileNameLevelMatchCriteria),
			new("SignerID", "SignerIDHeader/Text", x => x.SignerID),
			new("SignerName", "SignerNameHeader/Text", x => x.SignerName),
			new("SignerCertRoot", "SignerCertRootHeader/Text", x => x.SignerCertRoot),
			new("SignerCertPublisher", "SignerCertPublisherHeader/Text", x => x.SignerCertPublisher),
			new("SignerScope", "SignerScopeHeader/Text", x => x.SignerScope),
			new("CertSubjectCN", "CertSubjectCNHeader/Text", x => x.CertSubjectCN),
			new("CertIssuerCN", "CertIssuerCNHeader/Text", x => x.CertIssuerCN),
			new("CertNotAfter", "CertNotAfterHeader/Text", x => x.CertNotAfter),
			new("CertTBSValue", "CertTBSValueHeader/Text", x => x.CertTBSValue),
			new("FilePath", "FilePathHeader/Text", x => x.FilePath)
		]);

		// To adjust the initial width of the columns, giving them nice paddings.
		ColumnManager.CalculateColumnWidths(SimulationOutputs);
	}

	internal readonly InfoBarSettings MainInfoBar;

	internal Visibility SelectedPolicyLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal readonly CommonCore.IncrementalCollection.RangedObservableCollection<SimulationOutput> SimulationOutputs = [];

	/// <summary>
	/// Store all outputs for searching
	/// </summary>
	internal readonly List<SimulationOutput> AllSimulationOutputs = [];

	/// <summary>
	/// The Column Manager Composition
	/// </summary>
	internal ListViewColumnManager<SimulationOutput> ColumnManager { get; }

	/// <summary>
	/// For selected file paths
	/// </summary>
	internal UniqueStringObservableCollection FilePaths = [];

	/// <summary>
	/// For selected folder paths
	/// </summary>
	internal readonly UniqueStringObservableCollection FolderPaths = [];

	/// <summary>
	/// For the selected App Control policy.
	/// </summary>
	internal PolicyFileRepresent? SelectedPolicy { get; set => SP(ref field, value); }

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

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidths() => ColumnManager.CalculateColumnWidths(SimulationOutputs);

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

		foreach (SimulationOutput item in CollectionsMarshal.AsSpan(filteredResults))
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
		if (SelectedPolicy is null)
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
					SelectedPolicy.PolicyObj,
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

			await Task.Run(CalculateColumnWidths);
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
	/// Event handler for the Select policy button
	/// </summary>
	internal async void SelectXmlFileButton_Click()
	{
		try
		{
			string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

			if (!string.IsNullOrEmpty(selectedFile))
			{
				SiPolicy.SiPolicy policyObj = await Task.Run(() => Management.Initialize(selectedFile, null));

				SelectedPolicy = new(policyObj);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Event handler for the Select Files button
	/// </summary>
	internal void SelectFilesButton_Click()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.AnyFilePickerFilter);

		foreach (string item in CollectionsMarshal.AsSpan(selectedFiles))
		{
			FilePaths.Add(item);
		}
	}

	/// <summary>
	/// Event handler for the Select Folders button
	/// </summary>
	internal void SelectFoldersButton_Click()
	{
		List<string> selectedFolders = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		foreach (string folder in CollectionsMarshal.AsSpan(selectedFolders))
		{
			FolderPaths.Add(folder);
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

	internal void SelectXmlFileButton_Flyout_Clear_Click() => SelectedPolicy = null;

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

			// Ensure the file path ends with .json
			if (!savePath.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
			{
				savePath += ".json";
			}

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
