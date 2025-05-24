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
using AppControlManager.IntelGathering;
using AppControlManager.Others;
using AppControlManager.Pages;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class MDEAHPolicyCreationVM : ViewModelBase
{
	internal MDEAHPolicyCreationVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			null, null);
	}

	internal readonly InfoBarSettings MainInfoBar;

	// To store the FileIdentities displayed on the ListView
	// Binding happens on the XAML but methods related to search update the ItemSource of the ListView from code behind otherwise there will not be an expected result
	internal readonly ObservableCollection<FileIdentity> FileIdentities = [];

	// Store all outputs for searching, used as a temporary storage for filtering
	// If ObservableCollection were used directly, any filtering or modification could remove items permanently
	// from the collection, making it difficult to reset or apply different filters without re-fetching data.
	internal readonly List<FileIdentity> AllFileIdentities = [];

	/// <summary>
	/// To store the MDE Advanced Hunting CSV log file path.
	/// </summary>
	internal string? MDEAdvancedHuntingLogs { get; set => SP(ref field, value); }

	internal ListViewHelper.SortState SortState { get; set; } = new();

	#region UI-Bound Properties

	internal Visibility OpenInPolicyEditorInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	/// <summary>
	/// Determines whether the UI elements are enabled or disabled.
	/// </summary>
	internal bool AreElementsEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// For Selector Bar's navigation
	/// </summary>
	internal SelectorBarItem? SelectedItem
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(IsLocalSelected));
				OnPropertyChanged(nameof(IsCloudSelected));
				OnPropertyChanged(nameof(IsCreateSelected));
				OnPropertyChanged(nameof(LocalVisibility));
				OnPropertyChanged(nameof(CloudVisibility));
				OnPropertyChanged(nameof(CreateVisibility));
			}
		}
	}
	internal bool IsLocalSelected => string.Equals(SelectedItem?.Text, "Local", StringComparison.OrdinalIgnoreCase);
	internal bool IsCloudSelected => string.Equals(SelectedItem?.Text, "Cloud", StringComparison.OrdinalIgnoreCase);
	internal bool IsCreateSelected => string.Equals(SelectedItem?.Text, "Create", StringComparison.OrdinalIgnoreCase);
	internal Visibility LocalVisibility => IsLocalSelected ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility CloudVisibility => IsCloudSelected ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility CreateVisibility => IsCreateSelected ? Visibility.Visible : Visibility.Collapsed;


	#endregion


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
	internal GridLength ColumnWidth16 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth17 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth18 { get; set => SP(ref field, value); }

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidths()
	{

		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("TimeCreatedHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SignatureStatusHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("ActionHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("OriginalFileNameHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("InternalNameHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileDescriptionHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileVersionHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA256HashHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA1HashHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA256FlatHashHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA1FlatHashHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SigningScenarioHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FilePathHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("ComputerNameHeader/Text"));
		double maxWidth16 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("PolicyGUIDHeader/Text"));
		double maxWidth17 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("PolicyNameHeader/Text"));
		double maxWidth18 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FilePublishersHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileIdentity item in FileIdentities)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.FileName, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.TimeCreated.ToString(), maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.SignatureStatus.ToString(), maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.Action.ToString(), maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.OriginalFileName, maxWidth5);
			maxWidth6 = ListViewHelper.MeasureText(item.InternalName, maxWidth6);
			maxWidth7 = ListViewHelper.MeasureText(item.FileDescription, maxWidth7);
			maxWidth8 = ListViewHelper.MeasureText(item.FileVersion?.ToString(), maxWidth8);
			maxWidth9 = ListViewHelper.MeasureText(item.SHA256Hash, maxWidth9);
			maxWidth10 = ListViewHelper.MeasureText(item.SHA1Hash, maxWidth10);
			maxWidth11 = ListViewHelper.MeasureText(item.SHA256FlatHash, maxWidth11);
			maxWidth12 = ListViewHelper.MeasureText(item.SHA1FlatHash, maxWidth12);
			maxWidth13 = ListViewHelper.MeasureText(item.SISigningScenario.ToString(), maxWidth13);
			maxWidth14 = ListViewHelper.MeasureText(item.FilePath, maxWidth14);
			maxWidth15 = ListViewHelper.MeasureText(item.ComputerName, maxWidth15);
			maxWidth16 = ListViewHelper.MeasureText(item.PolicyGUID.ToString(), maxWidth16);
			maxWidth17 = ListViewHelper.MeasureText(item.PolicyName, maxWidth17);
			maxWidth18 = ListViewHelper.MeasureText(item.FilePublishersToDisplay, maxWidth18);
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
		ColumnWidth16 = new GridLength(maxWidth16);
		ColumnWidth17 = new GridLength(maxWidth17);
		ColumnWidth18 = new GridLength(maxWidth18);
	}

	#endregion


	// The list of queries property for x:Bind
	internal readonly List<MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage> AdvancedHuntingQueries = [

		new MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage
		{
			QueryTitle = "Default Query",
			Query = """
DeviceEvents
| where ActionType startswith "AppControlCodeIntegrity"
   or ActionType startswith "AppControlCIScriptBlocked"
   or ActionType startswith "AppControlCIScriptAudited"
"""
		},
		new MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage
		{
			QueryTitle = "Default Query with Device name filter",
			Query = """
DeviceEvents
| where (ActionType startswith "AppControlCodeIntegrity"
    or ActionType startswith "AppControlCIScriptBlocked"
    or ActionType startswith "AppControlCIScriptAudited")
    and DeviceName == "deviceName"
"""
		},
		new MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage
		{
			QueryTitle = "Default Query with Device name and Time filter",
			Query = """
DeviceEvents
| where Timestamp >= ago(1h)

| where (ActionType startswith "AppControlCodeIntegrity"
    or ActionType startswith "AppControlCIScriptBlocked"
    or ActionType startswith "AppControlCIScriptAudited")
    and DeviceName == "deviceName"
"""
		},

		new MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage
		{
			QueryTitle = "Default Query with Device name and Policy name filter",
			Query = """
DeviceEvents
| where (ActionType startswith "AppControlCodeIntegrity"
    or ActionType startswith "AppControlCIScriptBlocked"
    or ActionType startswith "AppControlCIScriptAudited")
    and DeviceName == "deviceName" | where parse_json(AdditionalFields)["PolicyName"] == 'NameOfThePolicy'
"""
		}

		];


	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	internal void ListViewFlyoutMenuCopy_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.MDE_AdvancedHunting);
		if (lv is null) return;

		// Check if there are selected items in the ListView
		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText(lv.SelectedItems);
		}
	}

	internal void BrowseForLogs_Flyout_Clear_Click()
	{
		MDEAdvancedHuntingLogs = null;
	}


	/// <summary>
	/// Event handler for the select Code Integrity EVTX file path button
	/// </summary>
	internal void BrowseForLogs_Click()
	{
		const string filter = "CSV file|*.csv";

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(filter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected csv file path
			MDEAdvancedHuntingLogs = selectedFile;

			Logger.Write($"Selected {selectedFile} for MDE Advanced Hunting scan");
		}
	}
}
