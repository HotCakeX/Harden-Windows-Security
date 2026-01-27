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
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;

namespace AppControlManager.Others;

/// <summary>
/// Manages column visibility, width calculations, and grid splitters for ListViews.
/// Must be called from a background thread for maximum performance.
/// All UI operations already explicitly run on the UI thread.
/// </summary>
/// <typeparam name="T">The type of the data items in the ListView.</typeparam>
internal sealed partial class ListViewColumnManager<T> : INotifyPropertyChanged
{
	internal ListViewColumnManager(ColumnDefinition[] definitions)
	{
		_definitions = definitions;
		int count = _definitions.Length;
		_calculatedMaxWidths = new double[count];

		// Initialize collections
		for (int i = 0; i < count; i++)
		{
			// Default columns to their defined visibility
			ColumnVisibilities.Add(_definitions[i].DefaultVisibility);
			// Default width to 0 until calculated, or minimal
			ColumnWidths.Add(new BindableColumnWidth(new GridLength(0)));
		}

		// Initialize splitters (indices count to 2*count - 1)
		for (int i = 0; i < count; i++)
		{
			ColumnVisibilities.Add(Visibility.Visible);
		}

		// Initialize Selection Items
		// We use the Header Resource Key (or raw text) to get the display name for the checkbox
		foreach (ColumnDefinition def in _definitions)
		{
			string displayName = def.UseRawHeader ? def.HeaderResourceKeyOrText : GlobalVars.GetStr(def.HeaderResourceKeyOrText);
			bool isVisible = def.DefaultVisibility == Visibility.Visible;
			ColumnSelectionItems.Add(new(def.Key, displayName, isVisible, OnColumnSelectionChanged));
		}

		// Initial Visual State Update
		UpdateVisualState();
	}

	/// <summary>
	/// Data structure to define a column
	/// </summary>
	/// <param name="key"></param>
	/// <param name="headerResourceKeyOrText">Resource key for GlobalVars.GetStr OR the raw text itself if useRawHeader is true</param>
	/// <param name="dataGetter">Function to get the text for measurement</param>
	/// <param name="defaultVisibility">The default visibility of the column. Defaults to Visible.</param>
	/// <param name="useRawHeader">If true, headerResourceKeyOrText is treated as the final string. If false, it is used as a key for GlobalVars.GetStr.</param>
	internal readonly struct ColumnDefinition(string key, string headerResourceKeyOrText, Func<T, string?> dataGetter, Visibility defaultVisibility = Visibility.Visible, bool useRawHeader = false)
	{
		internal string Key => key;
		internal string HeaderResourceKeyOrText => headerResourceKeyOrText;
		internal Func<T, string?> DataGetter => dataGetter;
		internal Visibility DefaultVisibility => defaultVisibility;
		internal bool UseRawHeader => useRawHeader;
	}

	private readonly ColumnDefinition[] _definitions;
	private readonly double[] _calculatedMaxWidths;

	// Collection bound to the UI Checkboxes for showing/hiding columns
	internal readonly ObservableCollection<ColumnSelectionItem> ColumnSelectionItems = [];

	// Single collection to manage visibility for Columns and Splitters
	// Indices 0 to N-1: Column Visibility
	// Indices N to 2N-1: Splitter Visibility
	internal readonly ObservableCollection<Visibility> ColumnVisibilities = [];

	// Collection to hold the active GridLength for each column.
	// We use a collection of Bindable objects so we can update properties without triggering CollectionChanged events, avoiding re-entrancy issues with TwoWay bindings.
	internal readonly ObservableCollection<BindableColumnWidth> ColumnWidths = [];

	/// <summary>
	/// Recalculates column widths based on the provided data items.
	/// </summary>
	/// <param name="items">The collection of items to measure.</param>
	internal void CalculateColumnWidths(IEnumerable<T> items)
	{
		// Reset widths
		Array.Clear(_calculatedMaxWidths, 0, _calculatedMaxWidths.Length);

		// 1. Measure Headers using the Resource Keys or raw text provided in definitions
		for (int i = 0; i < _definitions.Length; i++)
		{
			ColumnDefinition def = _definitions[i];
			string headerText = def.UseRawHeader ? def.HeaderResourceKeyOrText : GlobalVars.GetStr(def.HeaderResourceKeyOrText);

			int capturedIndex = i;
			_ = App.AppDispatcher.TryEnqueue(() =>
			{
				_calculatedMaxWidths[capturedIndex] = ListViewHelper.MeasureText(headerText);
			});
		}

		// Access the underlying memory directly using Span to bypass indexer bounds checking and enumerator overhead.
		List<T> dataList = items is List<T> list ? list : new(items);

		Span<T> itemsSpan = CollectionsMarshal.AsSpan(dataList);

		if (itemsSpan.Length == 0)
		{
			_ = App.AppDispatcher.TryEnqueue(UpdateVisualState);
			return;
		}

		// 2. Measure Content
		// We take the 10 longest strings per column to measure, as they are most likely to define the max width for each column.
		const int MaxCandidates = 10;

		unsafe
		{
			// Allocating stack memory once for the entire method call to prevent stack growth during the loop.
			int* bestIndices = stackalloc int[MaxCandidates];
			int* bestLengths = stackalloc int[MaxCandidates];

			// Iterate through every column definition
			for (int i = 0; i < _definitions.Length; i++)
			{
				Func<T, string?> getter = _definitions[i].DataGetter;

				// Reset counters for this column (overwrite the stack memory)
				int candidatesCount = 0;
				int minLen = -1;

				for (int j = 0; j < itemsSpan.Length; j++)
				{
					string? text = getter(itemsSpan[j]);

					if (string.IsNullOrEmpty(text)) continue;

					int len = text.Length;

					if (candidatesCount < MaxCandidates)
					{
						// Insert into sorted position (Ascending order of Length)
						// We keep the array sorted so bestLengths[0] is always the smallest length we have found so far.
						int k = candidatesCount - 1;

						// Shift elements that are larger than 'len' to the right
						while (k >= 0 && bestLengths[k] > len)
						{
							bestLengths[k + 1] = bestLengths[k];
							bestIndices[k + 1] = bestIndices[k];
							k--;
						}
						bestLengths[k + 1] = len;
						bestIndices[k + 1] = j; // Store index of the item
						candidatesCount++;

						// Update minLen to the first item (smallest in top set)
						minLen = bestLengths[0];
					}
					else if (len > minLen)
					{
						// New item is longer than the shortest in our top 10.
						// Remove the 0th item (shortest) and insert the new one in correct spot.

						int k = 0;
						// Shift elements smaller than 'len' to the left
						while (k < MaxCandidates - 1 && bestLengths[k + 1] < len)
						{
							bestLengths[k] = bestLengths[k + 1];
							bestIndices[k] = bestIndices[k + 1];
							k++;
						}
						bestLengths[k] = len;
						bestIndices[k] = j;

						// New minimum is at index 0
						minLen = bestLengths[0];
					}
				}

				// Now measure the winners
				for (int k = 0; k < candidatesCount; k++)
				{
					string? textToMeasure = getter(itemsSpan[bestIndices[k]]);

					int capturedIndex = i;
					_ = App.AppDispatcher.TryEnqueue(() =>
					{
						_calculatedMaxWidths[capturedIndex] = ListViewHelper.MeasureText(textToMeasure, _calculatedMaxWidths[capturedIndex]);
					});
				}
			}
		}

		// 3. Apply calculated widths (respecting visibility)
		_ = App.AppDispatcher.TryEnqueue(UpdateVisualState);
	}

	private void OnColumnSelectionChanged(string key, bool isChecked)
	{
		// Find the index of the column with this key
		int index = -1;
		for (int i = 0; i < _definitions.Length; i++)
		{
			if (string.Equals(_definitions[i].Key, key, StringComparison.OrdinalIgnoreCase))
			{
				index = i;
				break;
			}
		}

		if (index != -1)
		{
			// Set Column Visibility
			ColumnVisibilities[index] = isChecked ? Visibility.Visible : Visibility.Collapsed;

			// Update all visual states (Splitters and Widths)
			UpdateVisualState();
		}
	}

	private void UpdateVisualState()
	{
		bool firstVisibleColumnFound = false;
		int count = _definitions.Length;

		for (int i = 0; i < count; i++)
		{
			bool isColumnVisible = ColumnVisibilities[i] == Visibility.Visible;

			// Update Widths
			// If visible, use calculated width. If not, 0.
			GridLength newWidth = isColumnVisible ? new(_calculatedMaxWidths[i]) : new(0);

			// Only update if changed to avoid unnecessary UI work
			if (ColumnWidths[i].Width.Value != newWidth.Value || ColumnWidths[i].Width.GridUnitType != newWidth.GridUnitType)
			{
				ColumnWidths[i].Width = newWidth;
			}

			// Update Splitters
			// Splitter index in the collection is i + count
			// Logic: Splitter is visible IF (Column is Visible AND a visible column has already been seen to the left)
			Visibility newSplitterVisibility;

			if (isColumnVisible)
			{
				if (!firstVisibleColumnFound)
				{
					// This is the first visible column. Hide its splitter (left side).
					newSplitterVisibility = Visibility.Collapsed;
					firstVisibleColumnFound = true;
				}
				else
				{
					// Not the first one. Show its splitter.
					newSplitterVisibility = Visibility.Visible;
				}
			}
			else
			{
				// Column itself is hidden, hide splitter
				newSplitterVisibility = Visibility.Collapsed;
			}

			if (ColumnVisibilities[i + count] != newSplitterVisibility)
			{
				ColumnVisibilities[i + count] = newSplitterVisibility;
			}
		}
	}

	public event PropertyChangedEventHandler? PropertyChanged;
	private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}
}

// Helper class for column selection UI
#pragma warning disable CA1515
public sealed partial class ColumnSelectionItem(string key, string name, bool isChecked, Action<string, bool> onChanged) : INotifyPropertyChanged
{
	private Action<string, bool> _onChanged => onChanged;

	internal string Key => key;
	internal string Name => name;

	internal bool IsChecked
	{
		get; set
		{
			if (field != value)
			{
				field = value;
				OnPropertyChanged();
				_onChanged(Key, value);
			}
		}
	} = isChecked;

	public event PropertyChangedEventHandler? PropertyChanged;
	private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}
}
#pragma warning restore CA1515

/// <summary>
/// A wrapper around GridLength that implements INotifyPropertyChanged.
/// This allows TwoWay binding to the Width property without triggering CollectionChanged events
/// on the parent ObservableCollection, preventing re-entrancy crashes.
/// </summary>
internal sealed partial class BindableColumnWidth(GridLength initialWidth) : INotifyPropertyChanged
{
	internal GridLength Width
	{
		get; set
		{
			if (field.Value != value.Value || field.GridUnitType != value.GridUnitType)
			{
				field = value;
				OnPropertyChanged();
			}
		}
	} = initialWidth;

	public event PropertyChangedEventHandler? PropertyChanged;
	private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}
}
