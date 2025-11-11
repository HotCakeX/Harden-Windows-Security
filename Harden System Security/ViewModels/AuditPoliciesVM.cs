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
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using CommunityToolkit.WinUI;
using HardenSystemSecurity.SecurityPolicy;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class AuditPoliciesVM : ViewModelBase
{
	internal AuditPoliciesVM()
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

	internal void CalculateColumnWidths()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("CategoryHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("SubcategoryHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("AuditSettingHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("CategoryGUIDHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("SubcategoryGUIDHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (AuditPolicyInfo item in AuditPolicies)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.CategoryName, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.SubcategoryName, maxWidth2);
			// Column 3 is ComboBox + Apply button, so we add extra space
			maxWidth4 = ListViewHelper.MeasureText(item.CategoryGuid.ToString(), maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.SubcategoryGuid.ToString(), maxWidth5);
		}

		// Extra padding for ComboBox + Apply button (ComboBox width + Apply button + spacing)
		maxWidth3 = Math.Max(maxWidth3 + 50, 210); // ComboBox (160) + Apply button (32) + spacing (8) + padding

		// Set the column width properties.
		ColumnWidth1 = new GridLength(maxWidth1);
		ColumnWidth2 = new GridLength(maxWidth2);
		ColumnWidth3 = new GridLength(maxWidth3);
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
	/// Collection of all audit policies bound to the ListView.
	/// </summary>
	internal ObservableCollection<AuditPolicyInfo> AuditPolicies = [];

	/// <summary>
	/// Backing field of all audit policies.
	/// </summary>
	private readonly List<AuditPolicyInfo> AllAuditPolicies = [];

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
		ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.AuditPolicies);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		// Perform a case-insensitive search in all relevant fields
		List<AuditPolicyInfo> filteredResults = AllAuditPolicies.Where(policy =>
			policy.CategoryName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			policy.SubcategoryName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			policy.CategoryGuid.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			policy.SubcategoryGuid.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			policy.AuditSettingDescription.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)
		).ToList();

		AuditPolicies.Clear();

		foreach (AuditPolicyInfo item in filteredResults)
		{
			AuditPolicies.Add(item);
		}

		if (Sv != null && savedHorizontal.HasValue)
		{
			// restore horizontal scroll position
			_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
		}
	}

	#endregion

	#region Sort

	/// <summary>
	/// To store the Sort state of the columns.
	/// </summary>
	private ListViewHelper.SortState SortState { get; set; } = new();

	/// <summary>
	/// Used for column sorting and column copying (single cell and entire row), for all ListViews that display <see cref="AuditPolicyInfo"/> data type
	/// </summary>
	private static readonly FrozenDictionary<string, (string Label, Func<AuditPolicyInfo, object?> Getter)> AuditPolicyInfoPropertyMappings
		= new Dictionary<string, (string Label, Func<AuditPolicyInfo, object?> Getter)>
		{
			{ "CategoryName",            (GlobalVars.GetStr("CategoryHeader/Text"),           ape => ape.CategoryName) },
			{ "SubcategoryName",         (GlobalVars.GetStr("SubcategoryHeader/Text"),        ape => ape.SubcategoryName) },
			{ "AuditSettingDescription", (GlobalVars.GetStr("AuditSettingHeader/Text"),       ape => ape.AuditSettingDescription) },
			{ "CategoryGuid",            (GlobalVars.GetStr("CategoryGUIDHeader/Text"),       ape => ape.CategoryGuid) },
			{ "SubcategoryGuid",         (GlobalVars.GetStr("SubcategoryGUIDHeader/Text"),    ape => ape.SubcategoryGuid) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			// Look up the mapping in the property mappings dictionary.
			if (AuditPolicyInfoPropertyMappings.TryGetValue(key, out (string Label, Func<AuditPolicyInfo, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					SearchKeyword,
					AllAuditPolicies,
					AuditPolicies,
					SortState,
					key,
					regKey: ListViewHelper.ListViewsRegistry.AuditPolicies);
			}
		}
	}

	#endregion

	#region Copy

	/// <summary>
	/// Converts the properties of an <see cref="AuditPolicyInfo"/> row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	internal void CopySelectedPolicies_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.AuditPolicies);

		if (lv is null) return;

		if (lv.SelectedItems.Count > 0)
		{
			/// SelectedItems is an IList, and contains <see cref="AuditPolicyInfo"/>
			ListViewHelper.ConvertRowToText(lv.SelectedItems, AuditPolicyInfoPropertyMappings);
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

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.AuditPolicies);

		if (lv is null) return;

		if (AuditPolicyInfoPropertyMappings.TryGetValue(key, out (string Label, Func<AuditPolicyInfo, object?> Getter) map))
		{
			/// TElement = <see cref="AuditPolicyInfo"/>, copy just that one property
			ListViewHelper.CopyToClipboard<AuditPolicyInfo>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}
	#endregion

	#region Export

	/// <summary>
	/// Exports the current audit policies to a JSON file
	/// </summary>
	internal async void ExportToJson_Click()
	{
		try
		{
			if (AuditPolicies.Count == 0)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("NoAuditPoliciesAvailable"));
				return;
			}

			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			string? saveLocation = FileDialogHelper.ShowSaveFileDialog(
					"Audit Policies|*.JSON",
					"Audit Policies.JSON");

			if (saveLocation is null)
				return;

			List<AuditPolicyInfo> policiesToExport = AuditPolicies.ToList();

			await Task.Run(() =>
			{
				string jsonString = JsonSerializer.Serialize(policiesToExport, AuditPolicyJsonContext.Default.ListAuditPolicyInfo);

				File.WriteAllText(saveLocation, jsonString, Encoding.UTF8);
			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyExportedAuditPolicies"), policiesToExport.Count, saveLocation));
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
	/// Imports audit policies from a JSON file and applies them to the system
	/// </summary>
	internal async void ImportFromJson_Click()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			string? selectedFilePath = FileDialogHelper.ShowFilePickerDialog(GlobalVars.JSONPickerFilter);

			if (selectedFilePath is null)
				return;

			List<AuditPolicyInfo>? importedPolicies = await Task.Run(() =>
			{
				byte[] jsonContent = File.ReadAllBytes(selectedFilePath);
				return JsonSerializer.Deserialize(jsonContent, AuditPolicyJsonContext.Default.ListAuditPolicyInfo);
			});

			if (importedPolicies is null || importedPolicies.Count == 0)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("NoAuditPoliciesAvailableToImport"));
				return;
			}

			// Convert imported policies to AUDIT_POLICY_INFORMATION array for application
			List<AUDIT_POLICY_INFORMATION> policiesToApply = [];

			foreach (AuditPolicyInfo importedPolicy in importedPolicies)
			{
				// Validate that the subcategory GUID exists on this system
				try
				{
					Guid categoryGuid = AuditPolicyManager.GetCategoryGuidForSubcategory(importedPolicy.SubcategoryGuid);

					policiesToApply.Add(new AUDIT_POLICY_INFORMATION
					{
						AuditSubCategoryGuid = importedPolicy.SubcategoryGuid,
						AuditingInformation = importedPolicy.AuditingInformation,
						AuditCategoryGuid = categoryGuid
					});
				}
				catch (InvalidOperationException)
				{
					Logger.Write($"Skipping unknown subcategory: {importedPolicy.SubcategoryName} ({importedPolicy.SubcategoryGuid})");
				}
			}

			if (policiesToApply.Count == 0)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("NoAuditPoliciesApplicableInJSON"));
				return;
			}

			// Apply the policies to the system
			await Task.Run(() =>
			{
				AuditPolicyManager.SetAuditPolicies(policiesToApply.ToArray());
			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyImportedAuditPolicies"), policiesToApply.Count, selectedFilePath));

			// Refresh the list view to show the updated policies
			await RetrieveAuditPoliciesPrivate();
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

	#region Audit Policy Application

	/// <summary>
	/// Applies an individual audit policy change.
	/// </summary>
	internal async void ApplyIndividualChange_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is AuditPolicyInfo auditPolicy)
		{
			if (!auditPolicy.HasPendingChanges)
			{
				return;
			}

			try
			{
				ElementsAreEnabled = false;
				MainInfoBarIsClosable = false;

				await Task.Run(async () =>
				{
					AUDIT_POLICY_INFORMATION auditPolicyStruct = new()
					{
						AuditSubCategoryGuid = auditPolicy.SubcategoryGuid,
						AuditingInformation = auditPolicy.AuditingInformation,
						AuditCategoryGuid = auditPolicy.CategoryGuid
					};

					AuditPolicyManager.SetAuditPolicies([auditPolicyStruct]);

					// Commit the changes
					await Dispatcher.EnqueueAsync(auditPolicy.CommitChanges);
				});

				MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("AuditPolicyAppliedSuccess"), auditPolicy.SubcategoryName, auditPolicy.AuditSettingDescription));
			}
			catch (Exception ex)
			{
				MainInfoBar.WriteError(ex);

				// Revert the change on error
				auditPolicy.RevertChanges();
			}
			finally
			{
				ElementsAreEnabled = true;
				MainInfoBarIsClosable = true;
			}
		}
	}

	#endregion

	/// <summary>
	/// Retrieves and loads all audit policies on the system.
	/// </summary>
	internal async void RetrieveAuditPolicies_Click()
	{
		try
		{
			await RetrieveAuditPoliciesPrivate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Retrieves all audit policies and displays their data in the ListView.
	/// </summary>
	private async Task RetrieveAuditPoliciesPrivate()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			AllAuditPolicies.Clear();
			AuditPolicies.Clear();

			List<AuditPolicyInfo> allAuditPolicies = await Task.Run(AuditPolicyManager.GetAllAuditPolicies);

			await Dispatcher.EnqueueAsync(() =>
			{
				foreach (AuditPolicyInfo item in allAuditPolicies)
				{
					AuditPolicies.Add(item);
				}
			});

			AllAuditPolicies.AddRange(allAuditPolicies);

			CalculateColumnWidths();
			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("AuditPoliciesLoadedSuccess"), AuditPolicies.Count));
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
	/// Clears all of the data from the UI.
	/// </summary>
	internal void ClearData()
	{
		AuditPolicies.Clear();
		AllAuditPolicies.Clear();
		CalculateColumnWidths();
	}
}
