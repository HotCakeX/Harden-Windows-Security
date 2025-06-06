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
using System.Collections.Frozen;
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
using Windows.Foundation;

namespace AppControlManager.Others;

/// <summary>
/// This class includes methods that are helpers for the custom ListView implementations in this application.
/// </summary>
internal static class ListViewHelper
{
	/// <summary>
	/// A list of all of the ListViews in this application
	/// </summary>
	internal enum ListViewsRegistry
	{
		Locally_Deployed_Policies = 0,
		Online_Deployed_Policies = 1,
		Allow_New_Apps_EventLogs_ScanResults = 2,
		Allow_New_Apps_LocalFiles_ScanResults = 3,
		View_File_Certificates = 4,
		MDE_AdvancedHunting = 5,
		Event_Logs = 6,
		SupplementalPolicy_FilesAndFolders_ScanResults = 7,
		SupplementalPolicy_StrictKernelMode_ScanResults = 8,
		DenyPolicy_FilesAndFolders_ScanResults = 9,
		Simulation = 10,
		PolicyEditor_FileBasedRules = 11,
		PolicyEditor_SignatureBasedRules = 12,
		SupplementalPolicy_PFNBasedRules = 13,
		DenyPolicy_PFNBasedRules = 14,
		Deployment_IntuneGroupsListView = 15
	}

	/// <summary>
	/// Stores a reference to all of the ListViews currently available in the visual tree
	/// </summary>
	private static readonly Dictionary<ListViewsRegistry, ListView> ListViewsCache = [];

	/// <summary>
	/// Stores a reference to the ScrollViewers inside all of the ListViews currently available in the visual tree
	/// </summary>
	private static readonly Dictionary<ListViewsRegistry, ScrollViewer> ListViewsScrollViewerCache = [];

	/// <summary>
	/// Registers a ListView and its ScrollViewer in the caches.
	/// </summary>
	/// <param name="key"></param>
	/// <param name="listView"></param>
	/// <param name="viewer"></param>
	internal static void Register(ListViewsRegistry key, ListView listView, ScrollViewer viewer)
	{
		// Logger.Write("Registering ListView in the cache");
		ListViewsCache[key] = listView;
		ListViewsScrollViewerCache[key] = viewer;
	}

	/// <summary>
	/// Removes the references to a ListView and its ScrollViewer in the caches.
	/// </summary>
	/// <param name="key"></param>
	internal static void Unregister(ListViewsRegistry key)
	{
		// Logger.Write("Unregistering ListView from the cache");

		if (ListViewsCache.TryGetValue(key, out ListView? lv))
		{
			if (ObjRemovalTracking.Remove(lv))
			{
				// Logger.Write("Removed a ListView reference from ObjRemovalTracking");
			}
		}

		_ = ListViewsCache.Remove(key);
		_ = ListViewsScrollViewerCache.Remove(key);
	}

	/// <summary>
	/// Used to retrieve the ListView from the cache.
	/// </summary>
	/// <param name="key">the key used for retrieval.</param>
	/// <returns></returns>
	internal static ListView? GetListViewFromCache(ListViewsRegistry key)
	{
		_ = ListViewsCache.TryGetValue(key, out ListView? listView);
		return listView;
	}

	/// <summary>
	/// Used to retrieve a ScrollViewer from the cache.
	/// </summary>
	/// <param name="key">the key used for retrieval.</param>
	/// <returns></returns>
	internal static ScrollViewer? GetScrollViewerFromCache(ListViewsRegistry key)
	{
		_ = ListViewsScrollViewerCache.TryGetValue(key, out ScrollViewer? scrollViewer);
		return scrollViewer;
	}

	/// <summary>
	/// Walks the VisualTree under 'element' and returns the first ScrollViewer it finds.
	/// </summary>
	internal static ScrollViewer? FindScrollViewer(this DependencyObject element)
	{
		if (element is ScrollViewer sv)
			return sv;

		int count = VisualTreeHelper.GetChildrenCount(element);
		for (int i = 0; i < count; i++)
		{
			DependencyObject child = VisualTreeHelper.GetChild(element, i);
			ScrollViewer? result = FindScrollViewer(child);
			if (result != null)
				return result;
		}
		return null;
	}

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
	/// Measures the text width (in pixels) required to display the given text.
	/// </summary>
	internal static double MeasureText(string? text)
	{
		tb.Text = text;
		tb.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
		return tb.DesiredSize.Width;
	}

	internal static double MeasureText(string? text, double maxWidth)
	{
		tb.Text = text;
		tb.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
		return tb.DesiredSize.Width > maxWidth ? tb.DesiredSize.Width : maxWidth;
	}

	internal const string DefaultDelimiter = "--------------------------------------------------";

	// Pre-computed property getters for high performance.
	// Used for column sorting and column copying (single cell and entire row), for all of the ListViews that display FileIdentity data type
	internal static readonly FrozenDictionary<string, (string Label, Func<FileIdentity, object?> Getter)> PropertyMappings = new Dictionary<string, (string Label, Func<FileIdentity, object?> Getter)>
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
	}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);


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

		ClipboardManagement.CopyText(sb.ToString());
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
				ClipboardManagement.CopyText(propertyValue);
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
	/// Used to store sorting states of columns in ListViews
	/// </summary>
	internal sealed class SortState
	{
		internal string? CurrentSortKey { get; set; }
		internal bool IsDescending { get; set; } = true;
	}


	/// <summary>
	/// Sorts the ObservableCollection using the given key selector.
	/// The SortState parameter toggles sort order when the same column is pressed.
	/// </summary>
	/// <typeparam name="T">The type returned by the key selector.</typeparam>
	/// <param name="keySelector">Function to obtain the sort key from the FileIdentity.</param>
	/// <param name="searchBoxText">The Text used for filtering.</param>
	/// <param name="originalList">The full list (if no filter is active).</param>
	/// <param name="observableCollection">The observable collection to update.</param>
	/// <param name="sortState">An object that holds the current sort state.</param>
	/// <param name="newKey">The key for the column being sorted (from the button’s Tag).</param>
	/// <param name="regKey">used to find the ListView in the cache.</param>
	internal static void SortColumn<T>(
		Func<FileIdentity, T> keySelector,
		string? searchBoxText,
		List<FileIdentity> originalList,
		ObservableCollection<FileIdentity> observableCollection,
		SortState sortState,
		string newKey,
		ListViewsRegistry regKey)
	{

		// Get the ListView ScrollViewer info
		ScrollViewer? Sv = GetScrollViewerFromCache(regKey);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		// Toggle sort order if the same column; otherwise, reset to descending.
		if (sortState.CurrentSortKey == newKey)
		{
			sortState.IsDescending = !sortState.IsDescending;
		}
		else
		{
			sortState.CurrentSortKey = newKey;
			sortState.IsDescending = true;
		}

		bool isSearchEmpty = string.IsNullOrWhiteSpace(searchBoxText);
		List<FileIdentity> sourceData = isSearchEmpty ? originalList : observableCollection.ToList();

		List<FileIdentity> sortedData = sortState.IsDescending
			? sourceData.OrderByDescending(keySelector).ToList()
			: sourceData.OrderBy(keySelector).ToList();

		observableCollection.Clear();
		foreach (FileIdentity item in sortedData)
		{
			observableCollection.Add(item);
		}

		if (Sv != null && savedHorizontal.HasValue)
		{
			// restore horizontal scroll position
			_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
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
	/// <param name="searchText">
	/// The search term.
	/// </param>
	/// <param name="selectedDate">
	/// An optional DateTimeOffset for date filtering. If null, no date filtering is applied.
	/// </param>
	/// <param name="regKey">used to find the ListView in the cache.</param>
	internal static void ApplyFilters(
		IEnumerable<FileIdentity> allFileIdentities,
		ObservableCollection<FileIdentity> filteredCollection,
		string? searchText,
		DateTimeOffset? selectedDate,
		ListViewsRegistry regKey
		)
	{

		// Get the ListView ScrollViewer info
		ScrollViewer? Sv = GetScrollViewerFromCache(regKey);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		// Get the search term from the SearchBox, converting it to lowercase for case-insensitive searching
		string? searchTerm = searchText?.Trim();

		// Start with the full list.
		// This list is used as the base set for filtering to preserve original data
		IEnumerable<FileIdentity> filteredResults = allFileIdentities;

		// If a selectedDate is provided, filter by date.
		// Filter results to include only items where 'TimeCreated' is greater than or equal to the selected date.
		if (selectedDate is not null)
		{
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


		if (Sv != null && savedHorizontal.HasValue)
		{
			// restore horizontal scroll position
			_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
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
