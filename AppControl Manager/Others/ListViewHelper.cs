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
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using CommunityToolkit.WinUI;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.Foundation;

namespace AppControlManager.Others;

/// <summary>
/// This class includes methods that are helpers for the custom ListView implementations in this application.
/// </summary>
internal static class ListViewHelper
{
	/// <summary>
	/// An offscreen TextBlock for measurement
	/// </summary>
	private static readonly TextBlock tb = new()
	{
		// It's important to make sure this matches the header text style so column texts will be aligned properly
		FontWeight = FontWeights.Bold,
		Margin = new Thickness(10, 0, 2, 0),
		TextWrapping = TextWrapping.NoWrap,
		Padding = new Thickness(5),
	};

	/// <summary>
	/// Measures the width (in pixels) required to display the given text.
	/// </summary>
	internal static double MeasureTextWidth(string? text)
	{
		tb.Text = text;

		tb.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));

		return tb.DesiredSize.Width;
	}

	internal const string DefaultDelimiter = "--------------------------------------------------";

	// Pre-computed property getters for high performance.
	// Used for column sorting and column copying (single cell and entire row), for all of the ListViews that display FileIdentity data type
	internal static readonly Dictionary<string, (string Label, Func<FileIdentity, object?> Getter)> PropertyMappings = new()
	{
		{ "Origin", ("Origin", fi => fi.Origin) },
		{ "SignatureStatus", ("Signature Status", fi => fi.SignatureStatus) },
		{ "Action", ("Action", fi => fi.Action) },
		{ "EventID", ("Event ID", fi => fi.EventID) },
		{ "TimeCreated", ("Time Created", fi => fi.TimeCreated) },
		{ "ComputerName", ("Computer Name", fi => fi.ComputerName) },
		{ "PolicyGUID", ("Policy GUID", fi => fi.PolicyGUID) },
		{ "UserWriteable", ("User Writeable", fi => fi.UserWriteable) },
		{ "ProcessName", ("Process Name", fi => fi.ProcessName) },
		{ "RequestedSigningLevel", ("Requested Signing Level", fi => fi.RequestedSigningLevel) },
		{ "ValidatedSigningLevel", ("Validated Signing Level", fi => fi.ValidatedSigningLevel) },
		{ "Status", ("Status", fi => fi.Status) },
		{ "USN", ("USN", fi => fi.USN) },
		{ "PolicyName", ("Policy Name", fi => fi.PolicyName) },
		{ "PolicyID", ("Policy ID", fi => fi.PolicyID) },
		{ "PolicyHash", ("Policy Hash", fi => fi.PolicyHash) },
		{ "UserID", ("User ID", fi => fi.UserID) },
		{ "FilePath", ("File Path", fi => fi.FilePath) },
		{ "FileName", ("File Name", fi => fi.FileName) },
		{ "SHA1Hash", ("SHA1 Hash", fi => fi.SHA1Hash) },
		{ "SHA256Hash", ("SHA256 Hash", fi => fi.SHA256Hash) },
		{ "SHA1PageHash", ("SHA1 Page Hash", fi => fi.SHA1PageHash) },
		{ "SHA256PageHash", ("SHA256 Page Hash", fi => fi.SHA256PageHash) },
		{ "SHA1FlatHash", ("SHA1 Flat Hash", fi => fi.SHA1FlatHash) },
		{ "SHA256FlatHash", ("SHA256 Flat Hash", fi => fi.SHA256FlatHash) },
		{ "SISigningScenario", ("Signing Scenario", fi => fi.SISigningScenario) },
		{ "OriginalFileName", ("Original File Name", fi => fi.OriginalFileName) },
		{ "InternalName", ("Internal Name", fi => fi.InternalName) },
		{ "FileDescription", ("File Description", fi => fi.FileDescription) },
		{ "ProductName", ("Product Name", fi => fi.ProductName) },
		{ "FileVersion", ("File Version", fi => fi.FileVersion) },
		{ "PackageFamilyName", ("Package Family Name", fi => fi.PackageFamilyName) },
		{ "FilePublishersToDisplay", ("File Publishers", fi => fi.FilePublishersToDisplay) },
		{ "HasWHQLSigner", ("Has WHQL Signer", fi => fi.HasWHQLSigner) },
		{ "IsECCSigned", ("Is ECC Signed", fi => fi.IsECCSigned) },
		{ "Opus", ("Opus Data", fi => fi.Opus) }
	};


	/// <summary>
	/// Formats one or more FileIdentity instances into a string.
	/// Only non-null and, in the case of strings, non-empty properties are included.
	/// Each instance's output is separated by a delimiter line.
	/// </summary>
	/// <param name="fileIdentities">An array of FileIdentity instances to format.</param>
	/// <returns></returns>
	internal static void ConvertRowToText(IList<object> fileIdentities)
	{
		if (fileIdentities is null || fileIdentities.Count == 0)
			return;

		StringBuilder sb = new();

		foreach (object fileIdentity in fileIdentities)
		{
			if (fileIdentity is FileIdentity fileIden)
			{
				foreach ((string label, Func<FileIdentity, object?> getter) in PropertyMappings.Values)
				{
					var value = getter(fileIden);
					if (value is null || (value is string s && string.IsNullOrWhiteSpace(s)))
						continue;

					_ = sb.AppendLine($"{label}: {value}");
				}
			}

			// Append a delimiter line between instances.
			_ = sb.AppendLine(DefaultDelimiter);
		}

		// Create a DataPackage to hold the text data
		DataPackage dataPackage = new();

		// Set the formatted text as the content of the DataPackage
		dataPackage.SetText(sb.ToString());

		// Copy the DataPackage content to the clipboard
		Clipboard.SetContent(dataPackage);
	}


	/// <summary>
	/// Copies a specified property of a selected file identity to the clipboard if it exists.
	/// </summary>
	/// <param name="getProperty">A function that retrieves a specific property value from a file identity.</param>
	/// <param name="lw">A list view component that displays file identities and allows selection.</param>
	internal static void CopyToClipboard(Func<FileIdentity, string?> getProperty, ListView lw)
	{
		if (lw.SelectedItem is FileIdentity selectedItem)
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

	/// <summary>
	/// Select all of the items in the ListView's ItemsSource
	/// </summary>
	/// <param name="lw"></param>
	/// <param name="source"></param>
	internal static void SelectAll(ListView lw, IList source)
	{
		// Clear existing selections from the List View
		lw.SelectedItems.Clear();

		foreach (var item in source)
		{
			// Select each item
			lw.SelectedItems.Add(item);
		}
	}


	/// <summary>
	/// Sorts a collection
	/// Used for the ObservableCollection of ListViews
	/// </summary>
	/// <typeparam name="T">The type returned by the key selector.</typeparam>
	/// <param name="keySelector">The key selector used for sorting.</param>
	/// <param name="searchBox">Reference to the search TextBox.</param>
	/// <param name="sortingToggle">Reference to the ToggleMenuFlyoutItem that indicates sort direction.</param>
	/// <param name="originalList">The full list to sort if no filter is active.</param>
	/// <param name="observableCollection">The ObservableCollection to update with sorted data.</param>
	internal static void SortColumn<T>(
	Func<FileIdentity, T> keySelector,
	TextBox searchBox,
	ToggleMenuFlyoutItem sortingToggle,
	List<FileIdentity> originalList,
	ObservableCollection<FileIdentity> observableCollection)
	{
		// Determine if a search filter is active.
		bool isSearchEmpty = string.IsNullOrWhiteSpace(searchBox.Text);

		// Choose the data source based on whether a search is active.
		List<FileIdentity> sourceData = isSearchEmpty
			? originalList
			: observableCollection.ToList();

		// Prepare the sorted data in a temporary list.
		List<FileIdentity> sortedData = sortingToggle.IsChecked
			? sourceData.OrderByDescending(keySelector).ToList()
			: sourceData.OrderBy(keySelector).ToList();

		// Clear the ObservableCollection and add the sorted items.
		observableCollection.Clear();
		foreach (FileIdentity item in sortedData)
		{
			observableCollection.Add(item);
		}
	}


	/// <summary>
	/// Applies the search (and optional date) filters to the provided data.
	/// </summary>
	/// <param name="allFileIdentities">
	/// The complete list of FileIdentity objects (unfiltered).
	/// </param>
	/// <param name="filteredCollection">
	/// The ObservableCollection that will be populated with the filtered results.
	/// </param>
	/// <param name="searchTextBox">
	/// The TextBox containing the search term.
	/// </param>
	/// <param name="datePicker">
	/// An optional CalendarDatePicker for date filtering. If null, no date filtering is applied.
	/// </param>
	internal static void ApplyFilters(
		IEnumerable<FileIdentity> allFileIdentities,
		ObservableCollection<FileIdentity> filteredCollection,
		TextBox searchTextBox,
		CalendarDatePicker? datePicker
		)
	{
		// Get the search term from the SearchBox, converting it to lowercase for case-insensitive searching
		string searchTerm = searchTextBox.Text.Trim();

		// Start with the full list.
		// This list is used as the base set for filtering to preserve original data
		IEnumerable<FileIdentity> filteredResults = allFileIdentities;

		// If a CalendarDatePicker is provided and a date is selected, filter by date.
		// Filter results to include only items where 'TimeCreated' is greater than or equal to the selected date
		if (datePicker is not null && datePicker.Date.HasValue)
		{
			DateTimeOffset selectedDate = datePicker.Date.Value;
			filteredResults = filteredResults.Where(item =>
				item.TimeCreated.HasValue && item.TimeCreated.Value >= selectedDate);
		}

		// Filter results further to match the search term across multiple properties, case-insensitively
		if (!string.IsNullOrWhiteSpace(searchTerm))
		{
			filteredResults = filteredResults.Where(output =>
				(output.FileName is not null && output.FileName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				output.SignatureStatus.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				output.Action.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				(output.OriginalFileName is not null && output.OriginalFileName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.InternalName is not null && output.InternalName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FileDescription is not null && output.FileDescription.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.ProductName is not null && output.ProductName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FileVersion is not null && output.FileVersion.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.PackageFamilyName is not null && output.PackageFamilyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FilePath is not null && output.FilePath.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.SHA256FlatHash is not null && output.SHA256FlatHash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.SHA256Hash is not null && output.SHA256Hash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FilePublishersToDisplay is not null && output.FilePublishersToDisplay.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.Opus is not null && output.Opus.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.PolicyName is not null && output.PolicyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.ComputerName is not null && output.ComputerName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
			);
		}

		// Clear the ObservableCollection
		filteredCollection.Clear();

		// Add the new filtered results to the ObservableCollection
		foreach (FileIdentity item in filteredResults)
		{
			filteredCollection.Add(item);
		}
	}


	/*

	Windows Community Toolkit

	Copyright © .NET Foundation and Contributors

	All rights reserved.

	MIT License (MIT)

	Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

	*/

	// This is a modification of the methods in Windows Community Toolkit, ListViewExtensions, Smooth Scroll Into View feature that only has the center vertically code plus some additional logic
	// https://github.com/CommunityToolkit/Windows/pull/648


	private static readonly Dictionary<ListView, int> ObjRemovalTracking = [];


	/// <summary>
	/// Smooth scrolling the list to bring the specified index into view, centering vertically
	/// </summary>
	/// <param name="listViewBase">Represents the base list view that contains the items to be scrolled into view.</param>
	/// <param name="listView">Specifies the ListView that displays the items and is affected by the scrolling action.</param>
	/// <param name="index">Indicates the position of the item to be centered vertically in the ListView.</param>
	/// <param name="disableAnimation">Controls whether the scrolling action should be animated or occur instantly.</param>
	/// <param name="scrollIfVisible">Determines if the scrolling should occur even if the item is already visible.</param>
	/// <param name="additionalHorizontalOffset">Allows for an extra horizontal adjustment when positioning the item in view.</param>
	/// <param name="additionalVerticalOffset">Enables an additional vertical adjustment when centering the item in the view.</param>
	/// <returns>Returns a Task representing the asynchronous operation of scrolling the item into view.</returns>
	internal static async Task SmoothScrollIntoViewWithIndexCenterVerticallyOnlyAsync(this ListViewBase listViewBase, ListView listView, int index, bool disableAnimation = false, bool scrollIfVisible = true, int additionalHorizontalOffset = 0, int additionalVerticalOffset = 0)
	{

		// Only perform the scroll if the setting is enabled
		if (!App.Settings.ListViewsVerticalCentering)
		{
			return;
		}

		// Don't center if an item was deleted
		// Without this step, after row deletion in ListView, the data jumps up/down in a weird way
		if (!ObjRemovalTracking.TryGetValue(listView, out int value))
		{
			ObjRemovalTracking.Add(listView, ((IList)listView.ItemsSource).Count);
		}

		if (value != ((IList)listView.ItemsSource).Count)
		{
			ObjRemovalTracking[listView] = ((IList)listView.ItemsSource).Count;

			return;
		}

		if (index > (listViewBase.Items.Count - 1))
		{
			index = listViewBase.Items.Count - 1;
		}

		if (index < -listViewBase.Items.Count)
		{
			index = -listViewBase.Items.Count;
		}

		index = (index < 0) ? (index + listViewBase.Items.Count) : index;

		bool isVirtualizing = default;
		double previousXOffset = default, previousYOffset = default;

		ScrollViewer? scrollViewer = listViewBase.FindDescendant<ScrollViewer>();
		SelectorItem? selectorItem = listViewBase.ContainerFromIndex(index) as SelectorItem;

		if (scrollViewer is null)
		{
			return;
		}

		// If selectorItem is null then the panel is virtualized.
		// So in order to get the container of the item we need to scroll to that item first and then use ContainerFromIndex
		if (selectorItem is null)
		{
			isVirtualizing = true;

			previousXOffset = scrollViewer.HorizontalOffset;
			previousYOffset = scrollViewer.VerticalOffset;

			TaskCompletionSource<object?> tcs = new();

			void ViewChanged(object? _, ScrollViewerViewChangedEventArgs __) => tcs.TrySetResult(result: default);

			try
			{
				scrollViewer.ViewChanged += ViewChanged;
				listViewBase.ScrollIntoView(listViewBase.Items[index], ScrollIntoViewAlignment.Leading);
				_ = await tcs.Task;
			}
			finally
			{
				scrollViewer.ViewChanged -= ViewChanged;
			}

			selectorItem = (SelectorItem)listViewBase.ContainerFromIndex(index);
		}

		GeneralTransform transform = selectorItem.TransformToVisual((UIElement)scrollViewer.Content);
		Point position = transform.TransformPoint(new Point(0, 0));

		// Scrolling back to previous position
		if (isVirtualizing)
		{
			await scrollViewer.ChangeViewAsync(previousXOffset, previousYOffset, zoomFactor: null, disableAnimation: true);
		}

		double listViewBaseWidth = listViewBase.ActualWidth;
		double selectorItemWidth = selectorItem.ActualWidth;
		double listViewBaseHeight = listViewBase.ActualHeight;
		double selectorItemHeight = selectorItem.ActualHeight;

		previousXOffset = scrollViewer.HorizontalOffset;
		previousYOffset = scrollViewer.VerticalOffset;

		double minXPosition = position.X - listViewBaseWidth + selectorItemWidth;
		double minYPosition = position.Y - listViewBaseHeight + selectorItemHeight;

		double maxXPosition = position.X;
		double maxYPosition = position.Y;

		double finalXPosition, finalYPosition;

		// If the Item is in view and scrollIfVisible is false then we don't need to scroll
		if (!scrollIfVisible && (previousXOffset <= maxXPosition && previousXOffset >= minXPosition) && (previousYOffset <= maxYPosition && previousYOffset >= minYPosition))
		{
			finalXPosition = previousXOffset;
			finalYPosition = previousYOffset;
		}
		// Center it vertically
		else
		{
			finalXPosition = previousXOffset + additionalHorizontalOffset;
			finalYPosition = maxYPosition - ((listViewBaseHeight - selectorItemHeight) / 2.0) + additionalVerticalOffset;
		}

		await scrollViewer.ChangeViewAsync(finalXPosition, finalYPosition, zoomFactor: null, disableAnimation);
	}

	/// <summary>
	/// Changes the view of <see cref="ScrollViewer"/> asynchronous.
	/// </summary>
	/// <param name="scrollViewer">The scroll viewer.</param>
	/// <param name="horizontalOffset">The horizontal offset.</param>
	/// <param name="verticalOffset">The vertical offset.</param>
	/// <param name="zoomFactor">The zoom factor.</param>
	/// <param name="disableAnimation">if set to <c>true</c> disable animation.</param>
	private static async Task ChangeViewAsync(this ScrollViewer scrollViewer, double? horizontalOffset, double? verticalOffset, float? zoomFactor, bool disableAnimation)
	{
		if (horizontalOffset > scrollViewer.ScrollableWidth)
		{
			horizontalOffset = scrollViewer.ScrollableWidth;
		}
		else if (horizontalOffset < 0)
		{
			horizontalOffset = 0;
		}

		if (verticalOffset > scrollViewer.ScrollableHeight)
		{
			verticalOffset = scrollViewer.ScrollableHeight;
		}
		else if (verticalOffset < 0)
		{
			verticalOffset = 0;
		}

		// MUST check this and return immediately, otherwise this async task will never complete because ViewChanged event won't get triggered
		if (horizontalOffset == scrollViewer.HorizontalOffset && verticalOffset == scrollViewer.VerticalOffset)
		{
			return;
		}

		TaskCompletionSource<object?> tcs = new();

		void ViewChanged(object? _, ScrollViewerViewChangedEventArgs e)
		{
			if (e.IsIntermediate)
			{
				return;
			}

			_ = tcs.TrySetResult(result: default);
		}

		try
		{
			scrollViewer.ViewChanged += ViewChanged;
			_ = scrollViewer.ChangeView(horizontalOffset, verticalOffset, zoomFactor, disableAnimation);
			_ = await tcs.Task;
		}
		finally
		{
			scrollViewer.ViewChanged -= ViewChanged;
		}
	}

}
