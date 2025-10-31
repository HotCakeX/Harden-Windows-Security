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
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using CommunityToolkit.WinUI;
using HardenSystemSecurity.GroupPolicy;
using HardenSystemSecurity.SecurityPolicy;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class GroupPolicyEditorVM : ViewModelBase
{

	internal GroupPolicyEditorVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// To adjust the initial width of the columns, giving them nice paddings.
		CalculateColumnWidths();
	}

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

	#region ListView

	internal GridLength ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth6 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth7 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth8 { get; set => SP(ref field, value); }

	internal void CalculateColumnWidths()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("KeynameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("ValueNameHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("ValueHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("CategoryHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("SubCategoryHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.GetStr("PolicyActionHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.GetStr("FriendlyNameHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.GetStr("SizeHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (RegistryPolicyEntry item in Policies)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.KeyName, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.ValueName.ToString(), maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.ParsedValue?.ToString(), maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.Category.ToString(), maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.SubCategory.ToString(), maxWidth5);
			maxWidth6 = ListViewHelper.MeasureText(item.policyAction.ToString(), maxWidth6);
			maxWidth7 = ListViewHelper.MeasureText(item.FriendlyName, maxWidth7);
			maxWidth8 = ListViewHelper.MeasureText(item.Size.ToString(), maxWidth8);
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
	/// Collection of all policies bound to the ListView.
	/// </summary>
	internal ObservableCollection<RegistryPolicyEntry> Policies = [];

	/// <summary>
	/// Backing field of all policies.
	/// </summary>
	internal readonly List<RegistryPolicyEntry> AllPolicies = [];

	/// <summary>
	/// Whether the sidebar's pane is open or closed.
	/// </summary>
	internal bool MergeSidebarIsOpen { get; set => SP(ref field, value); }
	internal void OpenSideBar() => MergeSidebarIsOpen = true;
	internal void CloseSideBar() => MergeSidebarIsOpen = false;

	#region Search

	/// <summary>
	/// Event handler for the SearchBox text change
	/// </summary>
	internal void SearchBox_TextChanged()
	{
		string? searchTerm = SearchKeyword?.Trim();

		if (searchTerm is null)
			return;

		// Get the ListView ScrollViewer info
		ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.GroupPolicyEditor);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		// Perform a case-insensitive search in all relevant fields
		List<RegistryPolicyEntry> filteredResults = AllPolicies.Where(policy =>
			(policy.KeyName is not null && policy.KeyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(policy.ValueName is not null && policy.ValueName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(policy.ParsedValue is not null && policy.ParsedValue.ToString()!.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(policy.Category is not null && (policy.Category?.ToString()?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)) ||
			(policy.SubCategory is not null && (policy.SubCategory?.ToString()?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)) ||
			(policy.FriendlyName is not null && policy.FriendlyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			policy.policyAction.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)
		).ToList();

		Policies.Clear();

		foreach (RegistryPolicyEntry item in filteredResults)
		{
			Policies.Add(item);
		}

		if (Sv != null && savedHorizontal.HasValue)
		{
			// restore horizontal scroll position
			_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
		}
	}

	#endregion

	#region Sort

	private ListViewHelper.SortState SortState { get; set; } = new();

	// Used for column sorting and column copying (single cell and entire row), for all ListViews that display RegistryPolicyEntry data type
	private static readonly FrozenDictionary<string, (string Label, Func<RegistryPolicyEntry, object?> Getter)> RegistryPolicyEntryPropertyMappings
		= new Dictionary<string, (string Label, Func<RegistryPolicyEntry, object?> Getter)>
		{
			{ "KeyName",        (GlobalVars.GetStr("KeynameHeader/Text") + ": ",        rpe => rpe.KeyName) },
			{ "ValueName",      (GlobalVars.GetStr("ValueNameHeader/Text") + ": ",      rpe => rpe.ValueName) },
			{ "Value",          (GlobalVars.GetStr("ValueHeader/Text") + ": ",          rpe => rpe.ParsedValue) },
			{ "Category",       (GlobalVars.GetStr("CategoryHeader/Text") + ": ",       rpe => rpe.Category) },
			{ "SubCategory",    (GlobalVars.GetStr("SubCategoryHeader/Text") + ": ",    rpe => rpe.SubCategory) },
			{ "PolicyAction",   (GlobalVars.GetStr("PolicyActionHeader/Text") + ": ",   rpe => rpe.policyAction) },
			{ "FriendlyName",   (GlobalVars.GetStr("FriendlyNameHeader/Text") + ": ",   rpe => rpe.FriendlyName) },
			{ "Size",           (GlobalVars.GetStr("SizeHeader/Text") + ": ",           rpe => rpe.Size) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			// Look up the mapping in the reusable property mappings dictionary.
			if (RegistryPolicyEntryPropertyMappings.TryGetValue(key, out (string Label, Func<RegistryPolicyEntry, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					SearchKeyword,
					AllPolicies,
					Policies,
					SortState,
					key,
					regKey: ListViewHelper.ListViewsRegistry.GroupPolicyEditor);
			}
		}
	}

	#endregion

	#region Copy

	/// <summary>
	/// Converts the properties of a RegistryPolicyEntry row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	internal void CopySelectedPolicies_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.GroupPolicyEditor);

		if (lv is null) return;

		if (lv.SelectedItems.Count > 0)
		{
			// SelectedItems is an IList, and contains RegistryPolicyEntry
			ListViewHelper.ConvertRowToText(lv.SelectedItems, RegistryPolicyEntryPropertyMappings);
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

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.GroupPolicyEditor);

		if (lv is null) return;

		if (RegistryPolicyEntryPropertyMappings.TryGetValue(key, out var map))
		{
			// TElement = RegistryPolicyEntry, copy just that one property
			ListViewHelper.CopyToClipboard<RegistryPolicyEntry>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}
	#endregion

	#region Delete

	/// <summary>
	/// Deletes the selected policies from the currently loaded POL file and refreshes the UI.
	/// </summary>
	internal async void DeleteSelectedPolicies_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.GroupPolicyEditor);

		if (lv is null || lv.SelectedItems.Count == 0)
		{
			MainInfoBar.WriteWarning("No policies selected for deletion.");
			return;
		}

		// Check if we have a valid POL file loaded
		if (string.IsNullOrEmpty(SelectedFile) || !IsValidPOLFile(SelectedFile))
		{
			MainInfoBar.WriteWarning("No valid POL file is currently loaded. Please load a POL file first.");
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			// Get the selected policies
			List<RegistryPolicyEntry> policiesToDelete = [];
			foreach (object item in lv.SelectedItems)
			{
				if (item is RegistryPolicyEntry policy)
				{
					policiesToDelete.Add(policy);
				}
			}

			if (policiesToDelete.Count == 0)
			{
				MainInfoBar.WriteWarning("No policies selected for deletion.");
				return;
			}

			await Task.Run(() =>
			{
				// Remove policies directly from the loaded POL file
				RegistryPolicyParser.RemovePoliciesFromPOLFile(SelectedFile, policiesToDelete);
			});

			// Remove policies from UI collections
			foreach (RegistryPolicyEntry policy in policiesToDelete)
			{
				_ = Policies.Remove(policy);
				_ = AllPolicies.Remove(policy);
			}

			// Update UI
			CalculateColumnWidths();

			MainInfoBar.WriteSuccess($"Successfully deleted {policiesToDelete.Count} policies from the POL file.");
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

	/// <summary>
	/// Checks if the specified file is a valid POL file that exists on disk.
	/// </summary>
	/// <param name="filePath">The file path to check</param>
	/// <returns>True if it's a valid POL file that exists, false otherwise</returns>
	private static bool IsValidPOLFile(string filePath)
	{
		if (string.IsNullOrEmpty(filePath))
			return false;

		// Check if it's a POL file and exists
		return string.Equals(Path.GetExtension(filePath), ".pol", StringComparison.OrdinalIgnoreCase) &&
			   File.Exists(filePath);
	}

	#endregion

	/// <summary>
	/// The main policy file whose data will be displayed in the ListView.
	/// </summary>
	internal string? SelectedFile { get; set => SPT(ref field, value); }

	internal void ClearSelectedFile_Click() => SelectedFile = null;

	/// <summary>
	/// Opens a file picker dialog to select a policy file (JSON or POL).
	/// </summary>
	internal void BrowseForPolicy_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.JSONAndPOLPickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			SelectedFile = selectedFile;
		}
	}

	/// <summary>
	/// Event handler for the UI process button,
	/// </summary>
	internal async void ProcessSelectedFile()
	{
		try
		{
			await ProcessSelectedFilePrivate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Parses the selected policy file and displays it data in the ListView.
	/// </summary>
	private async Task ProcessSelectedFilePrivate()
	{
		if (SelectedFile is null)
			return;

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			AllPolicies.Clear();
			Policies.Clear();

			await Task.Run(async () =>
			{
				string fileExtension = Path.GetExtension(SelectedFile);

				if (string.Equals(fileExtension, ".json", StringComparison.OrdinalIgnoreCase))
				{
					List<RegistryPolicyEntry> policy = RegistryPolicyEntry.Load(SelectedFile);

					// Ensures the JSON file that is loaded has correct "RegValue".
					foreach (RegistryPolicyEntry item in policy)
					{
						if (item.Source == Source.GroupPolicy)
						{
							item.RegValue = RegistryManager.Manager.BuildRegValueFromParsedValue(item);
						}
					}

					// Persist the updated RegValue(s) back to disk
					RegistryPolicyEntry.Save(SelectedFile, policy);

					// Load again
					policy = RegistryPolicyEntry.Load(SelectedFile);

					// Retrieve friendly names
					AdmxAdmlParser.PopulateFriendlyNames(policy);

					await Dispatcher.EnqueueAsync(() =>
					{
						foreach (RegistryPolicyEntry item in policy)
						{
							Policies.Add(item);
							AllPolicies.Add(item);
						}
					});
				}
				else if (string.Equals(fileExtension, ".pol", StringComparison.OrdinalIgnoreCase))
				{
					RegistryPolicyFile policy = RegistryPolicyParser.ParseFile(SelectedFile);

					// Retrieve friendly names
					AdmxAdmlParser.PopulateFriendlyNames(policy.Entries);

					await Dispatcher.EnqueueAsync(() =>
					{
						foreach (RegistryPolicyEntry item in policy.Entries)
						{
							Policies.Add(item);
							AllPolicies.Add(item);
						}
					});
				}
				else
				{
					throw new NotSupportedException(string.Format(GlobalVars.GetStr("UnsupportedFileTypeError"), fileExtension));
				}

			});

			CalculateColumnWidths();
			MainInfoBar.WriteSuccess(GlobalVars.GetStr("GroupPolicyDataLoadedSuccess"));
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

	/// <summary>
	/// Retrieves and loads the effective Group Policies on the system.
	/// </summary>
	internal async void GetEffectivePolicies_Click()
	{
		try
		{
			SelectedFile = RegistryPolicyParser.LocalPolicyMachineFilePath;

			await ProcessSelectedFilePrivate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Retrieves and loads the effective Group Policies for the User.
	/// </summary>
	internal async void GetEffectiveUserPolicies_Click()
	{
		try
		{
			SelectedFile = RegistryPolicyParser.LocalPolicyUserFilePath;

			await ProcessSelectedFilePrivate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Clears all of the data from the UI.
	/// </summary>
	internal void ClearData()
	{
		Policies.Clear();
		AllPolicies.Clear();
		CalculateColumnWidths();
	}

	#region Merge POL files

	internal string? SelectedMainPOLFileForMerge { get; set => SPT(ref field, value); }
	internal void ClearSelectedMainPOLFileForMerge_Click() => SelectedMainPOLFileForMerge = null;

	internal UniqueStringObservableCollection SelectedOtherPOLFilesForMerge = [];
	internal void ClearSelectedOtherPOLFilesForMerge() => SelectedOtherPOLFilesForMerge.Clear();

	internal void BrowseForMainPolFile()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.POLPickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			SelectedMainPOLFileForMerge = selectedFile;
		}
	}

	internal void PickPOLFiles()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.POLPickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string item in selectedFiles)
			{
				SelectedOtherPOLFilesForMerge.Add(item);
			}
		}
	}

	internal async void StartPOLFilesMergeOperation()
	{
		if (SelectedMainPOLFileForMerge is null || SelectedOtherPOLFilesForMerge.Count == 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectMainAndOtherPOLFilesWarning"));
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			await Task.Run(() =>
			{
				MergeResult result = RegistryPolicyParser.MergePolicyFilesWithReport(SelectedMainPOLFileForMerge, SelectedOtherPOLFilesForMerge.UniqueItems.ToArray());

				// Log each operation
				foreach (MergeOperation operation in result.Operations)
				{
					Logger.Write(operation.ToString());
				}

				// Log summary statistics
				Logger.Write(GlobalVars.GetStr("MergeSummaryHeader"));
				Logger.Write(string.Format(GlobalVars.GetStr("TotalOperationsLog"), result.Operations.Count));
				Logger.Write(string.Format(GlobalVars.GetStr("AddedEntriesLog"), result.Operations.Count(op => op.OperationType == OperationType.Added)));
				Logger.Write(string.Format(GlobalVars.GetStr("ReplacedEntries"), result.Operations.Count(op => op.OperationType == OperationType.Replaced)));
				Logger.Write(string.Format(GlobalVars.GetStr("TotalEntriesInMergedFileLog"), result.MergedFile.Entries.Count));

				RegistryPolicyFile newPolFile = new(
					signature: RegistryPolicyFile.REGISTRY_FILE_SIGNATURE,
					version: RegistryPolicyFile.REGISTRY_FILE_VERSION,
					entries: result.MergedFile.Entries);

				RegistryPolicyParser.WriteFile(SelectedMainPOLFileForMerge, newPolFile);
			});

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("POLFilesMergedSuccess"));
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

	#region Convert POL to JSON

	internal UniqueStringObservableCollection SelectedPOLFilesForConversionToJSON = [];
	internal void ClearSelectedPOLFilesForConversionToJSON() => SelectedPOLFilesForConversionToJSON.Clear();

	internal string? OutputDirForJsonFilesAfterConversion { get; set => SP(ref field, value); }
	internal void ClearOutputDirForJsonFilesAfterConversion_Click() => OutputDirForJsonFilesAfterConversion = null;

	internal void PickPOLFilesForJSONConversion()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.POLPickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string item in selectedFiles)
			{
				SelectedPOLFilesForConversionToJSON.Add(item);
			}
		}
	}

	internal void PickADirectory()
	{
		string? dir = FileDialogHelper.ShowDirectoryPickerDialog();

		if (!string.IsNullOrEmpty(dir))
		{
			OutputDirForJsonFilesAfterConversion = dir;
		}
	}

	internal async void ConvertPOLToJSON()
	{
		if (SelectedPOLFilesForConversionToJSON.Count == 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectAtLeastOnePOLFileWarning"));
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			await Task.Run(async () =>
			{
				foreach (string item in SelectedPOLFilesForConversionToJSON)
				{
					RegistryPolicyFile policy = RegistryPolicyParser.ParseFile(item);

					// Retrieve friendly names
					AdmxAdmlParser.PopulateFriendlyNames(policy.Entries);

					string? saveLoc = null;

					if (OutputDirForJsonFilesAfterConversion is null)
					{
						saveLoc = Path.Combine(
							Path.GetDirectoryName(item) ?? GlobalVars.SystemDrive,
							Path.GetFileNameWithoutExtension(item) + ".json");
					}
					else
					{
						saveLoc = Path.Combine(
							OutputDirForJsonFilesAfterConversion,
							Path.GetFileNameWithoutExtension(item) + ".json");
					}

					// Populate RegValue for Group Policy entries at save time so the generated JSON includes it.
					foreach (RegistryPolicyEntry entry in policy.Entries)
					{
						if (entry.Source == Source.GroupPolicy)
						{
							entry.RegValue = RegistryManager.Manager.BuildRegValueFromParsedValue(entry);
						}
					}

					RegistryPolicyEntry.Save(saveLoc, policy.Entries);

					MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("POLFilesConvertedToJSONSuccess"), saveLoc));
				}
			});
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

	#region Convert JSON to POL

	internal string? OutputDirForPOLFilesAfterConversion { get; set => SP(ref field, value); }
	internal void ClearOutputDirForPOLFilesAfterConversion_Click() => OutputDirForPOLFilesAfterConversion = null;

	internal UniqueStringObservableCollection SelectedJSONFilesForConversionToPol = [];
	internal void ClearSelectedJSONFilesForConversionToPol() => SelectedJSONFilesForConversionToPol.Clear();

	internal void PickADirectoryForJSONToPOLConversion()
	{
		string? dir = FileDialogHelper.ShowDirectoryPickerDialog();

		if (!string.IsNullOrEmpty(dir))
		{
			OutputDirForPOLFilesAfterConversion = dir;
		}
	}

	internal void PickJSONFilesForPOLConversion()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.JSONPickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string item in selectedFiles)
			{
				SelectedJSONFilesForConversionToPol.Add(item);
			}
		}
	}

	internal async void ConvertJSONToPol()
	{
		if (SelectedJSONFilesForConversionToPol.Count == 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectAtLeastOneJSONFileWarning"));
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			await Task.Run(async () =>
			{
				foreach (string item in SelectedJSONFilesForConversionToPol)
				{
					List<RegistryPolicyEntry> policies = RegistryPolicyEntry.Load(item);

					RegistryPolicyFile newPolicyFile = new(
							signature: RegistryPolicyFile.REGISTRY_FILE_SIGNATURE,
							version: RegistryPolicyFile.REGISTRY_FILE_VERSION,
							entries: policies);

					string? saveLoc = null;

					if (OutputDirForPOLFilesAfterConversion is null)
					{
						saveLoc = Path.Combine(
							Path.GetDirectoryName(item) ?? GlobalVars.SystemDrive,
							Path.GetFileNameWithoutExtension(item) + ".pol");
					}
					else
					{
						saveLoc = Path.Combine(
							OutputDirForPOLFilesAfterConversion,
							Path.GetFileNameWithoutExtension(item) + ".pol");
					}

					RegistryPolicyParser.WriteFile(saveLoc, newPolicyFile);

					MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("JSONFileConvertedToPOLSuccess"), saveLoc));
				}
			});
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

	#region Convert Security INF to JSON

	internal UniqueStringObservableCollection SelectedSecurityINFFilesForConversionToJSON = [];
	internal void ClearSelectedSecurityINFFilesForConversionToJSON() => SelectedSecurityINFFilesForConversionToJSON.Clear();

	internal string? OutputDirForSecurityINFToJSONConversion { get; set => SP(ref field, value); }
	internal void ClearOutputDirForSecurityINFToJSONConversion_Click() => OutputDirForSecurityINFToJSONConversion = null;

	internal void PickSecurityINFFilesForJSONConversion()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.SecurityINFPickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string item in selectedFiles)
			{
				SelectedSecurityINFFilesForConversionToJSON.Add(item);
			}
		}
	}

	internal void PickADirectoryForSecurityINFToJSON()
	{
		string? dir = FileDialogHelper.ShowDirectoryPickerDialog();

		if (!string.IsNullOrEmpty(dir))
		{
			OutputDirForSecurityINFToJSONConversion = dir;
		}
	}

	internal async void ConvertSecurityINFToJSON()
	{
		if (SelectedSecurityINFFilesForConversionToJSON.Count == 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectAtLeastOneSecurityINFFileWarning"));
			return;
		}

		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			await Task.Run(async () =>
			{
				foreach (string item in SelectedSecurityINFFilesForConversionToJSON)
				{
					List<RegistryPolicyEntry> policies = SecurityINFParser.ParseSecurityINFFile(item);

					string? saveLoc = null;

					if (OutputDirForSecurityINFToJSONConversion is null)
					{
						saveLoc = Path.Combine(
							Path.GetDirectoryName(item) ?? GlobalVars.SystemDrive,
							Path.GetFileNameWithoutExtension(item) + ".json");
					}
					else
					{
						saveLoc = Path.Combine(
							OutputDirForSecurityINFToJSONConversion,
							Path.GetFileNameWithoutExtension(item) + ".json");
					}

					RegistryPolicyEntry.Save(saveLoc, policies);

					MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SecurityINFFileConvertedToJSONSuccess"), saveLoc));
				}
			});
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

	#region Retrive System Security Policy

	internal async void RetrieveSystemSecurityPolicy()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			string? saveLocation = FileDialogHelper.ShowSaveFileDialog(
					"Security Reports|*.txt",
					"SecurityPolicy_Report.txt");

			if (saveLocation is null)
				return;

			await DataDump.DumpSystemSecurityPoliciesData(saveLocation);

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SecurityPolicyReportSavedSuccess"), saveLocation));
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
	/// Method used to open the Group Policy Editor with the selected policy file.
	/// </summary>
	/// <param name="filePath"></param>
	/// <returns></returns>
	internal async Task OpenInGroupPolicyEditor(string? filePath)
	{
		if (filePath is null)
			return;
		try
		{
			SelectedFile = filePath;

			ViewModelProvider.NavigationService.Navigate(typeof(Pages.GroupPolicyEditor));

			await ProcessSelectedFilePrivate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}
}
