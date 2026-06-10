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

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using CommonCore.GroupPolicy;
using CommonCore.ToolKits;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using Microsoft.UI.Xaml;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class WindowsUpdateVM : MUnitListViewModelBase
{
	[SetsRequiredMembers]
	internal WindowsUpdateVM()
	{
		MainInfoBar = new();

		// Initializing the cancellable buttons
		ApplyAllCancellableButton = new(Atlas.GetStr("ApplyAllButtonText/Text"));
		RemoveAllCancellableButton = new(Atlas.GetStr("RemoveAllButtonText/Text"));
		VerifyAllCancellableButton = new(Atlas.GetStr("VerifyAllButtonText"));

		IMUnitListViewModel.CreateUIValuesCategories(this);
	}

	/// <summary>
	/// Creates all MUnits for this ViewModel.
	/// </summary>
	private static readonly Lazy<List<MUnit>> LazyCatalog =
		new(() =>
		{
			return MUnit.CreateMUnitsFromPolicies(Categories.WindowsUpdateConfigurations);
		}, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// Gets the current catalog of all MUnits for this ViewModel.
	/// </summary>
	public override List<MUnit> AllMUnits => LazyCatalog.Value;

	#region Management

	/// <summary>
	/// Collection of available Windows updates bound to the management ListView.
	/// </summary>
	internal readonly ObservableCollection<WindowsUpdateItem> AvailableUpdates = [];

	/// <summary>
	/// Backing collection for available Windows updates.
	/// </summary>
	internal readonly List<WindowsUpdateItem> AllAvailableUpdates = [];

	internal Visibility ManagementProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool ManagementProgressRingIsActive { get; set => SP(ref field, value); }

	internal Visibility EmptyStatePlaceholderVisibility { get; set => SP(ref field, value); } = Visibility.Visible;

	internal string DateSortButtonText { get; set => SP(ref field, value); } = "Date: unsorted";
	internal string DateSortGlyph { get; set => SP(ref field, value); } = "\uE8CB";

	/// <summary>
	/// True means the next date sort operation will put the newest Windows updates first.
	/// False means the next date sort operation will put the oldest Windows updates first.
	/// </summary>
	private bool DateSortDescending { get; set => SP(ref field, value); } = true;

	internal bool ManagementElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ManagementProgressRingVisibility = field ? Visibility.Collapsed : Visibility.Visible;
				ManagementProgressRingIsActive = !field;
			}
		}
	} = true;

	/// <summary>
	/// Sorts the available Windows updates by LastDeploymentChangeTime.
	/// The button text describes the current visible sort order after the sort completes.
	/// </summary>
	internal void SortAvailableUpdatesByDate_Click()
	{
		if (AllAvailableUpdates.Count == 0)
		{
			MainInfoBar.WriteWarning("There are no Windows updates to sort.");
			return;
		}

		List<WindowsUpdateItem> sortedUpdates = DateSortDescending
			? AllAvailableUpdates
				.OrderByDescending(update => update.LastDeploymentChangeTimeSortKey)
				.ThenBy(update => update.Title, StringComparer.OrdinalIgnoreCase)
				.ToList()
			: AllAvailableUpdates
				.OrderBy(update => update.LastDeploymentChangeTimeSortKey)
				.ThenBy(update => update.Title, StringComparer.OrdinalIgnoreCase)
				.ToList();

		ReplaceAvailableUpdates(sortedUpdates);

		if (DateSortDescending)
		{
			DateSortButtonText = "Date: newest first";
			DateSortGlyph = "\uE74A";
		}
		else
		{
			DateSortButtonText = "Date: oldest first";
			DateSortGlyph = "\uE74B";
		}

		DateSortDescending = !DateSortDescending;
	}

	/// <summary>
	/// Clears the available Windows updates from the management ListView.
	/// </summary>
	internal void ClearAvailableUpdates_Click()
	{
		AvailableUpdates.Clear();
		AllAvailableUpdates.Clear();
		EmptyStatePlaceholderVisibility = Visibility.Visible;
	}

	/// <summary>
	/// Sets hidden or unhidden state for selected updates and refreshes the list afterwards.
	/// </summary>
	/// <param name="selectedItems">Selected ListView items.</param>
	/// <param name="isHidden">Desired hidden state.</param>
	/// <returns></returns>
	internal async Task SetSelectedUpdatesHiddenState(IList<object> selectedItems, bool isHidden)
	{
		List<WindowsUpdateItem> selectedUpdates = GetSelectedUpdateItems(selectedItems);

		if (selectedUpdates.Count == 0)
		{
			MainInfoBar.WriteWarning("Select one or more updates first.");
			return;
		}

		try
		{
			ManagementElementsAreEnabled = false;
			MainInfoBar.IsClosable = false;

			MainInfoBar.WriteInfo(isHidden ? "Hiding selected updates..." : "Unhiding selected updates...");

			using IDisposable taskTracker = TaskTracking.RegisterOperation();

			List<HiddenStateChangeResult> results = await Task.Run(() => WindowsUpdateManager.SetHiddenStates(selectedUpdates, isHidden));

			int successCount = results.Count(result => result.Succeeded);
			int failedCount = results.Count - successCount;

			List<WindowsUpdateItem> refreshedUpdates = await Task.Run(WindowsUpdateManager.SearchAvailableUpdates);

			await Atlas.AppDispatcher.EnqueueAsync(() =>
			{
				ReplaceAvailableUpdates(refreshedUpdates);

				string completedOperationText = isHidden ? "hidden" : "unhidden";

				if (failedCount == 0)
				{
					MainInfoBar.WriteSuccess(string.Format(
						CultureInfo.InvariantCulture,
						"Successfully {0} {1} update(s).",
						completedOperationText,
						successCount));
				}
				else
				{
					MainInfoBar.WriteWarning(string.Format(
						CultureInfo.InvariantCulture,
						"{0} update(s) succeeded and {1} update(s) failed.",
						successCount,
						failedCount));
				}
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManagementElementsAreEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Exports selected updates to JSON. If no updates are selected, exports all loaded updates.
	/// </summary>
	/// <param name="selectedItems">Selected ListView items.</param>
	/// <returns></returns>
	internal async Task ExportUpdatesToJson(IList<object> selectedItems)
	{
		List<WindowsUpdateItem> selectedUpdates = GetSelectedUpdateItems(selectedItems);

		List<WindowsUpdateItem> updatesToExport = selectedUpdates.Count > 0
			? selectedUpdates
			: new List<WindowsUpdateItem>(AllAvailableUpdates);

		if (updatesToExport.Count == 0)
		{
			MainInfoBar.WriteWarning("There are no Windows updates to export.");
			return;
		}

		string? selectedFile = FileDialogHelper.ShowSaveFileDialog(
			Atlas.JSONPickerFilter,
			"Harden System Security Windows Updates.json");

		if (string.IsNullOrWhiteSpace(selectedFile))
		{
			MainInfoBar.WriteWarning("You need to select a location to export the data to.");
			return;
		}

		try
		{
			ManagementElementsAreEnabled = false;
			MainInfoBar.IsClosable = false;

			WindowsUpdateExportFile exportFile = new(DateTimeOffset.UtcNow, updatesToExport.Count, updatesToExport);

			await Task.Run(() =>
			{
				using FileStream stream = File.Create(selectedFile);
				JsonSerializer.Serialize(stream, exportFile, WindowsUpdateJsonContext.Default.WindowsUpdateExportFile);
			});

			MainInfoBar.WriteSuccess(string.Format(CultureInfo.InvariantCulture, "Successfully exported {0} update(s) to JSON.", updatesToExport.Count));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManagementElementsAreEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Retrieves available Windows updates and loads their full info into the management ListView.
	/// </summary>
	internal async void RetrieveAvailableUpdates()
	{
		try
		{
			ManagementElementsAreEnabled = false;
			MainInfoBar.IsClosable = false;
			MainInfoBar.WriteInfo("Retrieving available Windows updates...");

			using IDisposable taskTracker = TaskTracking.RegisterOperation();

			List<WindowsUpdateItem> updates = await Task.Run(WindowsUpdateManager.SearchAvailableUpdates);

			await Atlas.AppDispatcher.EnqueueAsync(() =>
			{
				ReplaceAvailableUpdates(updates);
			});

			MainInfoBar.WriteSuccess(string.Format(
				CultureInfo.InvariantCulture,
				"Successfully retrieved {0} available update(s).",
				updates.Count));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManagementElementsAreEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	private void ReplaceAvailableUpdates(List<WindowsUpdateItem> updates)
	{
		AvailableUpdates.Clear();
		AllAvailableUpdates.Clear();

		for (int index = 0; index < updates.Count; index++)
		{
			WindowsUpdateItem update = updates[index];

			AvailableUpdates.Add(update);
			AllAvailableUpdates.Add(update);
		}

		EmptyStatePlaceholderVisibility = updates.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
	}

	private static List<WindowsUpdateItem> GetSelectedUpdateItems(IList<object> selectedItems)
	{
		List<WindowsUpdateItem> selectedUpdates = [];

		foreach (object? selectedItem in selectedItems)
		{
			if (selectedItem is WindowsUpdateItem update)
			{
				selectedUpdates.Add(update);
			}
		}

		return selectedUpdates;
	}

	#endregion
}

internal sealed class WindowsUpdateExportFile(DateTimeOffset exportedAtUtc, int count, List<WindowsUpdateItem> updates)
{
	public DateTimeOffset ExportedAtUtc => exportedAtUtc;
	public int Count => count;
	public List<WindowsUpdateItem> Updates => updates;
}

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(WindowsUpdateExportFile))]
[JsonSerializable(typeof(List<WindowsUpdateItem>))]
[JsonSerializable(typeof(WindowsUpdateCollection<WindowsUpdateCategory>))]
[JsonSerializable(typeof(WindowsUpdateCollection<WindowsUpdateDownloadContent>))]
[JsonSerializable(typeof(WindowsUpdateCategory))]
[JsonSerializable(typeof(WindowsUpdateDownloadContent))]
[JsonSerializable(typeof(WindowsUpdateBehaviorDetails))]
[JsonSerializable(typeof(WindowsUpdateDriverDetails))]
internal sealed partial class WindowsUpdateJsonContext : JsonSerializerContext;
