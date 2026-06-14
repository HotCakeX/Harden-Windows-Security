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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using AppControlManager.Others;
using CommonCore.IncrementalCollection;
using CommonCore.IntelGathering;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class ViewExportedFunctionsVM : ViewModelBase
{
	private ListViewHelper.SortState SortState { get; set; } = new();

	private static readonly FrozenDictionary<string, Func<ExportedFunctionDisplayEntry, object?>> ExportEntryMappings = new Dictionary<string, Func<ExportedFunctionDisplayEntry, object?>>
	{
		{ nameof(ExportedFunctionDisplayEntry.DllName), static entry => entry.DllName },
		{ nameof(ExportedFunctionDisplayEntry.ExportName), static entry => entry.ExportName },
		{ nameof(ExportedFunctionDisplayEntry.Ordinal), static entry => entry.Ordinal },
		{ nameof(ExportedFunctionDisplayEntry.ForwarderText), static entry => entry.ForwarderText }
	}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal ViewExportedFunctionsVM()
	{
		ColumnManager = new ListViewColumnManager<ExportedFunctionDisplayEntry>(
		[
			new(nameof(ExportedFunctionDisplayEntry.DllName), "DLL", static x => x.DllName, useRawHeader: true),
			new(nameof(ExportedFunctionDisplayEntry.ExportName), "Export", static x => x.ExportName, useRawHeader: true),
			new(nameof(ExportedFunctionDisplayEntry.Ordinal), "Ordinal", static x => x.OrdinalText, useRawHeader: true),
			new(nameof(ExportedFunctionDisplayEntry.ForwarderText), "Forwarder", static x => x.ForwarderText, useRawHeader: true)
		]);

		ColumnManager.CalculateColumnWidths(ExportedFunctions);
	}

	internal readonly InfoBarSettings MainInfoBar = new();

	// User-selected files.
	internal readonly UniqueStringObservableCollection SelectedFiles = [];

	// User-selected directories.
	internal readonly UniqueStringObservableCollection SelectedDirectories = [];

	// Main collection bound to the ListView to display the exported functions.
	internal readonly RangedObservableCollection<ExportedFunctionDisplayEntry> ExportedFunctions = [];

	// The backing list of the main collection.
	private readonly List<ExportedFunctionDisplayEntry> _allExportedFunctions = [];

	internal readonly ListViewColumnManager<ExportedFunctionDisplayEntry> ColumnManager;

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility ResultsVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility EmptyStateVisibility { get; set => SP(ref field, value); } = Visibility.Visible;

	// Controls whether the UI elements are enabled or not.
	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = value ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	internal string? ExportSearchText { get; set => SPT(ref field, value); }

	internal void BrowseForFiles_Click()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog("Dynamic-link library files|*.dll");
		foreach (string file in CollectionsMarshal.AsSpan(selectedFiles))
		{
			SelectedFiles.Add(file);
		}
	}

	internal void BrowseForDirectories_Click()
	{
		List<string> selectedDirectories = FileDialogHelper.ShowMultipleDirectoryPickerDialog();
		foreach (string directory in CollectionsMarshal.AsSpan(selectedDirectories))
		{
			SelectedDirectories.Add(directory);
		}
	}

	internal void ClearSelectedDirectories() => SelectedDirectories.Clear();
	internal void ClearSelectedFiles() => SelectedFiles.Clear();

	internal void ClearAll_Click()
	{
		SelectedFiles.Clear();
		SelectedDirectories.Clear();

		ExportedFunctions.Clear();
		_allExportedFunctions.Clear();

		SortState.IsDescending = false;
		MainInfoBar.IsOpen = false;
		ExportSearchText = null;
		ColumnManager.CalculateColumnWidths(ExportedFunctions);
	}

	internal async void ExportToJson_Click()
	{
		try
		{
			List<ExportedFunctionDisplayEntry> entriesToExport = [.. _allExportedFunctions];
			if (entriesToExport.Count is 0)
			{
				MainInfoBar.WriteWarning("No exported functions are available to export.");
				return;
			}

			string? jsonPath = FileDialogHelper.ShowSaveFileDialog(Atlas.JSONPickerFilter, "ExportedFunctions.json");
			if (string.IsNullOrWhiteSpace(jsonPath))
			{
				return;
			}

			if (!jsonPath.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
			{
				jsonPath += ".json";
			}

			MainInfoBar.WriteInfo("Exporting data to JSON...");

			await Task.Run(() =>
			{
				ExportedFunctionsExportDocument exportDocument = new(
				format: "Harden System Security Exported Functions",
				source: "Exported functions",
				exportedAt: DateTimeOffset.Now,
				results:
				[
					.. entriesToExport
						.GroupBy(static entry => entry.DllPath, StringComparer.OrdinalIgnoreCase)
						.Select(static dllGroup => new ExportedFunctionDllExportEntry(
							dllPath: dllGroup.Key,
							exports:
							[
								.. dllGroup.Select(static entry => new ExportedFunctionExportEntry(
									exportName: entry.ExportName,
									ordinal: entry.Ordinal,
									forwarder: entry.ForwarderText))
							]))
				]);

				string json = JsonSerializer.Serialize(exportDocument, ExportedFunctionsJsonContext.Default.ExportedFunctionsExportDocument);
				File.WriteAllText(jsonPath, json, Encoding.UTF8);
			});

			MainInfoBar.WriteSuccess($"Successfully exported {entriesToExport.Count} entries to {jsonPath}");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button &&
			button.Tag is string key &&
			ExportEntryMappings.TryGetValue(key, out Func<ExportedFunctionDisplayEntry, object?>? getter))
		{
			ListViewHelper.SortColumn(
				getter,
				ExportSearchText,
				_allExportedFunctions,
				ExportedFunctions,
				SortState,
				key,
				regKey: ListViewHelper.ListViewsRegistry.ViewExportedFunctions);

			ResultsVisibility = ExportedFunctions.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
			EmptyStateVisibility = ExportedFunctions.Count > 0 ? Visibility.Collapsed : Visibility.Visible;
		}
	}

	// The main method that initiates the scan.
	internal async void StartScan()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBar.IsClosable = false;

			using IDisposable taskTracker = TaskTracking.RegisterOperation();

			MainInfoBar.WriteInfo("Searching for DLL files among the selected files and directories.");

			(List<ExportedFunctionDisplayEntry> Entries, List<string> Failures, int totalDlls) = await Task.Run(() =>
			{
				List<ExportedFunctionDisplayEntry> entries = [];
				List<string> failures = [];

				(IEnumerable<string>, int) fileScanResults = FileUtility.GetFilesFast(SelectedDirectories, SelectedFiles, [".dll"], null);

				if (fileScanResults.Item2 == 0)
				{
					MainInfoBar.WriteWarning("No DLL file was found in any of the selected files or directories.");
					return (entries, failures, 0);
				}

				MainInfoBar.WriteInfo($"Processing {fileScanResults.Item2} DLL files...please wait");

				foreach (string dllFilePath in fileScanResults.Item1)
				{
					try
					{
						IReadOnlyList<PortableExecutableExport> exportedFunctions = KernelModeDrivers.GetExportedFunctions(dllFilePath);
						string dllName = Path.GetFileName(dllFilePath);

						foreach (PortableExecutableExport exportedFunction in exportedFunctions.OrderBy(static entry => entry.Ordinal))
						{
							entries.Add(new ExportedFunctionDisplayEntry(
								dllPath: dllFilePath,
								dllName: dllName,
								exportName: exportedFunction.Name,
								ordinal: exportedFunction.Ordinal,
								forwarderText: exportedFunction.ForwarderName ?? "Direct export"));
						}
					}
					catch (Exception ex)
					{
						failures.Add($"{Path.GetFileName(dllFilePath)}: {ex.Message}");
					}
				}

				return (entries, failures, fileScanResults.Item2);
			});

			// Add results to the backing collection
			_allExportedFunctions.Clear();
			_allExportedFunctions.AddRange(Entries);

			// Add results to the main UI-bound collection
			ExportedFunctions.Clear();
			ExportedFunctions.AddRange(Entries);

			ResultsVisibility = ExportedFunctions.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
			EmptyStateVisibility = ExportedFunctions.Count > 0 ? Visibility.Collapsed : Visibility.Visible;

			await Task.Run(() => ColumnManager.CalculateColumnWidths(_allExportedFunctions));

			string successMessage = $"Found {_allExportedFunctions.Count} exported functions in {totalDlls} DLL files.";
			if (Failures.Count > 0)
			{
				MainInfoBar.WriteWarning($"{successMessage}{Environment.NewLine}{Failures.Count} DLL files could not be scanned. Please see the logs for more info.");
				Logger.Write($"DLL Scan failed results:{Environment.NewLine}{string.Join(Environment.NewLine, Failures)}");
			}
			else
			{
				MainInfoBar.WriteSuccess(successMessage);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	internal async void SearchBox_TextChanged()
	{
		try
		{
			IEnumerable<ExportedFunctionDisplayEntry> results = _allExportedFunctions;
			string? normalizedSearch = ExportSearchText?.Trim();

			ScrollViewer? scrollViewer = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.ViewExportedFunctions);
			double? savedHorizontal = null;

			if (scrollViewer is not null)
			{
				savedHorizontal = scrollViewer.HorizontalOffset;
			}

			if (!string.IsNullOrWhiteSpace(normalizedSearch))
			{
				results = results.Where(entry => entry.Contains(normalizedSearch));
			}

			ExportedFunctions.Clear();
			ExportedFunctions.AddRange(results);
			ResultsVisibility = ExportedFunctions.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
			EmptyStateVisibility = ExportedFunctions.Count > 0 ? Visibility.Collapsed : Visibility.Visible;

			_ = scrollViewer?.ChangeView(savedHorizontal, null, null, disableAnimation: false);

			await Task.Run(() => ColumnManager.CalculateColumnWidths(ExportedFunctions));
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}
}

internal sealed class ExportedFunctionDisplayEntry(string dllPath, string dllName, string exportName, uint ordinal, string forwarderText)
{
	internal string DllPath => dllPath;
	internal string DllName => dllName;
	internal string ExportName => exportName;
	internal uint Ordinal => ordinal;
	internal string OrdinalText => ordinal.ToString(CultureInfo.InvariantCulture);
	internal string ForwarderText => forwarderText;

	internal bool Contains(string searchText) =>
		DllPath.Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
		ExportName.Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
		OrdinalText.Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
		ForwarderText.Contains(searchText, StringComparison.OrdinalIgnoreCase);
}

internal sealed class ExportedFunctionsExportDocument(string format, string source, DateTimeOffset exportedAt, List<ExportedFunctionDllExportEntry> results)
{
	[JsonInclude]
	[JsonPropertyOrder(0)]
	internal string Format => format;

	[JsonInclude]
	[JsonPropertyOrder(1)]
	internal string Source => source;

	[JsonInclude]
	[JsonPropertyOrder(2)]
	internal DateTimeOffset ExportedAt => exportedAt;

	[JsonInclude]
	[JsonPropertyOrder(3)]
	internal List<ExportedFunctionDllExportEntry> Results => results;
}

internal sealed class ExportedFunctionDllExportEntry(string dllPath, List<ExportedFunctionExportEntry> exports)
{
	[JsonInclude]
	[JsonPropertyOrder(0)]
	internal string DllPath => dllPath;

	[JsonInclude]
	[JsonPropertyOrder(1)]
	internal List<ExportedFunctionExportEntry> Exports => exports;
}

internal sealed class ExportedFunctionExportEntry(string exportName, uint ordinal, string forwarder)
{
	[JsonInclude]
	[JsonPropertyOrder(0)]
	internal string ExportName => exportName;

	[JsonInclude]
	[JsonPropertyOrder(1)]
	internal uint Ordinal => ordinal;

	[JsonInclude]
	[JsonPropertyOrder(2)]
	internal string Forwarder => forwarder;
}

[JsonSerializable(typeof(ExportedFunctionsExportDocument))]
[JsonSerializable(typeof(ExportedFunctionDllExportEntry))]
[JsonSerializable(typeof(ExportedFunctionExportEntry))]
[JsonSerializable(typeof(List<ExportedFunctionDllExportEntry>))]
[JsonSerializable(typeof(List<ExportedFunctionExportEntry>))]
[JsonSourceGenerationOptions(
	WriteIndented = true,
	PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified,
	PropertyNameCaseInsensitive = true,
	DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class ExportedFunctionsJsonContext : JsonSerializerContext
{
}
