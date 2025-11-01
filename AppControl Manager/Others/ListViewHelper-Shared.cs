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

using System.Collections;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.WinUI;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;

#if HARDEN_SYSTEM_SECURITY
using HardenSystemSecurity;
#endif

namespace AppControlManager.Others;

/// <summary>
/// This class includes methods that are helpers for the custom ListView implementations in this application.
/// </summary>
internal static partial class ListViewHelper
{

	/// <summary>
	/// A list of all of the ListViews in this or adjacent applications.
	/// </summary>
	internal enum ListViewsRegistry : uint
	{
		// For AppControl Manager
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
		Deployment_IntuneGroupsListView = 15,

		// For Harden System Security App
		GroupPolicyEditor = 10000,
		MicrosoftDefender = 10001,
		MicrosoftSecurityBaseline = 10002,
		Microsoft365AppsSecurityBaseline = 10003,
		CertificateChecking_NonStlCerts = 10004,
		AuditPolicies = 10005,
		BitLockerVolumes = 10006,
		CBOM_CryptoAlgorithms = 10007,
		CBOM_CNGCurves = 10008,
		CBOM_SSLProviderCurves = 10009,
		CBOM_TlsCipherSuites = 10010,
		CBOM_RegisteredProviders = 10011,
		MD_Exclusions = 10012
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

		// Update caches to point to the new instance
		ListViewsCache[key] = listView;
		ListViewsScrollViewerCache[key] = viewer;
	}

	/// <summary>
	/// Removes the references to a ListView and its ScrollViewer in the caches.
	/// </summary>
	/// <param name="key"></param>
	internal static void Unregister(ListViewsRegistry key, ListView instance)
	{
		// Always remove the exact instance from the tracking map.
		_ = ObjRemovalTracking.Remove(instance);

		// Only clear caches if they still point to this specific instance.
		if (ListViewsCache.TryGetValue(key, out ListView? current) && ReferenceEquals(current, instance))
		{
			// Remove caches for this registry since they still reference the instance being unloaded.
			_ = ListViewsCache.Remove(key);
			_ = ListViewsScrollViewerCache.Remove(key);
		}
		// If the cached instance does not match the one being unregistered, there is an active newer instance.
		// Do Not remove anything in that case; they belong to the active instance.
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
		FontFamily = new("Segoe UI") // Set as the same value as the one in the App Setting's default property value.
	};

	/// <summary>
	/// Called when the user changes the font for ListViews in the Settings page.
	/// </summary>
	/// <param name="fontFamily"></param>
	internal static void UpdateFontFamily(string fontFamily)
	{
		// Ensure the width is calculated correctly based on the selected font for List Views so the size of the text is accurate.
		tb.FontFamily = new FontFamily(fontFamily);
	}

	private static readonly Size SizeForMeasurement = new(double.PositiveInfinity, double.PositiveInfinity);

	/// <summary>
	/// Measures the text width (in pixels) required to display the given text.
	/// Adds an extra width as padding; This helps make it look better on the UI when ListView is empty.
	/// </summary>
	internal static double MeasureText(string? text)
	{
		tb.Text = text;
		tb.Measure(SizeForMeasurement);
		return tb.DesiredSize.Width + InitValueAdded;
	}

	/// <summary>
	/// Used by Incremental Collections to measure column cell widths without adding the InitValueAdded padding.
	/// </summary>
	/// <param name="text"></param>
	/// <returns></returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static double MeasureTextEx(string? text)
	{
		tb.Text = text;
		tb.Measure(SizeForMeasurement);
		return tb.DesiredSize.Width;
	}

	/// <summary>
	/// This overload is used for measuring column widths and returning the biggest value between the current text's width and current column's width.
	/// </summary>
	/// <param name="text"></param>
	/// <param name="maxWidth"></param>
	/// <returns></returns>
	internal static double MeasureText(string? text, double maxWidth)
	{
		tb.Text = text;
		tb.Measure(SizeForMeasurement);
		return tb.DesiredSize.Width > maxWidth ? tb.DesiredSize.Width : maxWidth;
	}

	internal const string DefaultDelimiter = "--------------------------------------------------";

	/// <summary>
	/// The value that is added to the width of each ListView column when it is empty.
	/// </summary>
	private const double InitValueAdded = 20;

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
	/// <typeparam name="TElement">The element type in the collections.</typeparam>
	/// <param name="keySelector">
	/// Function to obtain the sort key (object?) from each element.
	/// </param>
	/// <param name="searchBoxText">
	/// The Text used for filtering (only to decide whether to reset to originalList).
	/// </param>
	/// <param name="originalList">
	/// The full list (if no filter is active).
	/// </param>
	/// <param name="observableCollection">
	/// The observable collection to update.
	/// </param>
	/// <param name="sortState">
	/// An object that holds the current sort key and direction.
	/// </param>
	/// <param name="newKey">
	/// The key for the column being sorted (from the button's Tag).
	/// </param>
	/// <param name="regKey">
	/// Used to find the ListView's ScrollViewer in the cache.
	/// </param>
	internal static void SortColumn<TElement>(
		Func<TElement, object?> keySelector,
		string? searchBoxText,
		List<TElement> originalList,
		ObservableCollection<TElement> observableCollection,
		SortState sortState,
		string newKey,
		ListViewsRegistry regKey,
		string? propertyFilterValue = null)
	{
		// Get the ListView ScrollViewer info
		ScrollViewer? Sv = GetScrollViewerFromCache(regKey);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		// Toggle sort order if the same column; otherwise, reset to descending.
		if (string.Equals(sortState.CurrentSortKey, newKey, StringComparison.OrdinalIgnoreCase))
		{
			sortState.IsDescending = !sortState.IsDescending;
		}
		else
		{
			sortState.CurrentSortKey = newKey;
			sortState.IsDescending = true;
		}

		// Choose the source (filtered vs. original)
		// If either the property search has text or the regular search box has text then use the Obvs Collection because that means the user is currently seeing a filtered data.
		bool isSearchEmpty = string.IsNullOrEmpty(searchBoxText) && string.IsNullOrEmpty(propertyFilterValue);
		List<TElement> sourceData = isSearchEmpty
			? originalList
			: observableCollection.ToList();

		List<TElement> sortedData = sortState.IsDescending
			? sourceData.OrderByDescending(keySelector).ToList()
			: sourceData.OrderBy(keySelector).ToList();

		// Re-populate the ObservableCollection
		observableCollection.Clear();
		foreach (TElement item in sortedData)
		{
			observableCollection.Add(item);
		}

		// Restore horizontal scroll position
		if (Sv != null && savedHorizontal.HasValue)
		{
			_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: true);
		}
	}

	/// <summary>
	/// Formats one or more items of type TElement into a string using the supplied property mappings.
	/// Only non-null and, in the case of strings, non-empty properties are included.
	/// Each instance's output is separated by a delimiter line.
	/// </summary>
	/// <typeparam name="TElement">The element type (e.g. FileIdentity, SimulationOutput, etc.).</typeparam>
	/// <param name="items">An IList of objects; each will be cast to TElement.</param>
	/// <param name="propertyMappings">
	/// A FrozenDictionary whose Values are (Label, Getter) pairs for TElement.
	/// The Getter returns object? for each named property.
	/// </param>
	internal static void ConvertRowToText<TElement>(
		IList<object> items,
		FrozenDictionary<string, (string Label, Func<TElement, object?> Getter)> propertyMappings)
	{
		if (items is null || items.Count is 0)
			return;

		StringBuilder sb = new();

		foreach (object obj in items)
		{
			if (obj is TElement element)
			{
				foreach ((string label, Func<TElement, object?> getter) in propertyMappings.Values)
				{
					object? value = getter(element);
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
	/// Copies a specified property of the selected item in a ListView to the clipboard.
	/// </summary>
	/// <typeparam name="TElement">The element type stored in the ListView (e.g. FileIdentity).</typeparam>
	/// <param name="getProperty">
	/// A function that retrieves a string? from TElement (for example, mapping.Getter(item)?.ToString()).
	/// </param>
	/// <param name="lw">The ListView whose SelectedItem will be used.</param>
	internal static void CopyToClipboard<TElement>(
		Func<TElement, string?> getProperty,
		ListView lw)
	{
		if (lw.SelectedItem is TElement selected)
		{
			string? propertyValue = getProperty(selected);
			if (propertyValue is not null)
			{
				ClipboardManagement.CopyText(propertyValue);
			}
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
		double previousXOffset = default;
		double previousYOffset = default;

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

		double finalXPosition;
		double finalYPosition;

		// If the Item is in view and scrollIfVisible is false then we don't need to scroll
		if (!scrollIfVisible && previousXOffset <= maxXPosition && previousXOffset >= minXPosition && previousYOffset <= maxYPosition && previousYOffset >= minYPosition)
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

	/// <summary>
	/// Property mappings for PackagedAppView used for clipboard operations
	/// </summary>
	internal static readonly FrozenDictionary<string, (string Label, Func<PackagedAppView, object?> Getter)> PackagedAppPropertyMappings =
		new Dictionary<string, (string Label, Func<PackagedAppView, object?> Getter)>
		{
			["DisplayName"] = (GlobalVars.GetStr("PFNDisplayNameLabelText"), app => app.DisplayName),
			["Version"] = (GlobalVars.GetStr("PFNVersionLabel/Text"), app => app.Version),
			["Architecture"] = (GlobalVars.GetStr("PFNArchitectureLabel/Text"), app => app.Architecture),
			["Publisher"] = (GlobalVars.GetStr("PFNPublisherLabel/Text"), app => app.Publisher),
			["InstalledDate"] = (GlobalVars.GetStr("PFNInstalledDateLabel/Text"), app => app.InstalledDate),
			["PackageFamilyName"] = (GlobalVars.GetStr("PFNLabel/Text"), app => app.PackageFamilyName),
			["PublisherID"] = (GlobalVars.GetStr("PFNPublisherID/Text"), app => app.PublisherID),
			["Description"] = (GlobalVars.GetStr("PFNDescription/Text"), app => app.Description),
			["InstallLocation"] = (GlobalVars.GetStr("PFNInstallLocation/Text"), app => app.InstallLocation),
			["FullName"] = (GlobalVars.GetStr("PFNFullNameLabel/Text"), app => app.FullName)
		}.ToFrozenDictionary();


	#region Header Resource And Property Keys For Incremental Collections Controllers

	// FilesAndFolders sections of the Supplemental And Deny policy creations use the same exact columns/properties.
	internal static readonly string[] SupplementalAndDenyPolicyCreationHeaderResourceKeys =
	[
		"FileNameHeader/Text",
		"SignatureStatusHeader/Text",
		"OriginalFileNameHeader/Text",
		"InternalNameHeader/Text",
		"FileDescriptionHeader/Text",
		"ProductNameHeader/Text",
		"FileVersionHeader/Text",
		"PackageFamilyNameHeader/Text",
		"SHA256HashHeader/Text",
		"SHA1HashHeader/Text",
		"SigningScenarioHeader/Text",
		"FilePathHeader/Text",
		"SHA1PageHashHeader/Text",
		"SHA256PageHashHeader/Text",
		"HasWHQLSignerHeader/Text",
		"FilePublishersHeader/Text",
		"IsECCSignedHeader/Text",
		"OpusDataHeader/Text"
	];

	internal static readonly string[] SupplementalAndDenyPolicyCreationPropertyKeys =
	[
		"FileName",
		"SignatureStatus",
		"OriginalFileName",
		"InternalName",
		"FileDescription",
		"ProductName",
		"FileVersion",
		"PackageFamilyName",
		"SHA256Hash",
		"SHA1Hash",
		"SISigningScenario",
		"FilePath",
		"SHA1PageHash",
		"SHA256PageHash",
		"HasWHQLSigner",
		"FilePublishersToDisplay",
		"IsECCSigned",
		"Opus"
	];

	#endregion

}
