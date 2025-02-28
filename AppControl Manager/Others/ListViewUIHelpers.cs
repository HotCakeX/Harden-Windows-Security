using System.Collections;
using System.Collections.Generic;
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
using static AppControlManager.AppSettings.AppSettingsCls;

namespace AppControlManager.Others;

/// <summary>
/// This class includes methods that are helpers for the custom ListView implementations in this application.
/// </summary>
internal static class ListViewUIHelpers
{
	// An offscreen TextBlock for measurement
	private static readonly TextBlock tb = new()
	{
		// It's important to make sure this matches the header text style so column texts will be aligned properly
		FontWeight = FontWeights.Bold,
		Margin = new Thickness(10, 0, 2, 0),
		TextWrapping = TextWrapping.NoWrap,
		Padding = new Thickness(5),
	};

	// Padding to add to each column (in pixels)
	private const double padding = 15;

	/// <summary>
	/// Measures the width (in pixels) required to display the given text.
	/// If text is empty or null, the padding will be the only width returned.
	/// </summary>
	internal static double MeasureTextWidth(string? text)
	{
		tb.Text = text;

		tb.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));

		return tb.DesiredSize.Width + padding;
	}

	/// <summary>
	/// Converts the properties of a FileIdentity row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	/// <param name="row">The selected FileIdentity row from the ListView.</param>
	/// <returns>A formatted string of the row's properties with labels.</returns>
	internal static string ConvertRowToText(FileIdentity row)
	{
		// Use StringBuilder to format each property with its label for easy reading
		return new StringBuilder()
			.AppendLine($"File Name: {row.FileName}")
			.AppendLine($"Signature Status: {row.SignatureStatus}")
			.AppendLine($"Original File Name: {row.OriginalFileName}")
			.AppendLine($"Internal Name: {row.InternalName}")
			.AppendLine($"File Description: {row.FileDescription}")
			.AppendLine($"Product Name: {row.ProductName}")
			.AppendLine($"File Version: {row.FileVersion}")
			.AppendLine($"Package Family Name: {row.PackageFamilyName}")
			.AppendLine($"SHA256 Hash: {row.SHA256Hash}")
			.AppendLine($"SHA1 Hash: {row.SHA1Hash}")
			.AppendLine($"Signing Scenario: {row.SISigningScenario}")
			.AppendLine($"File Path: {row.FilePath}")
			.AppendLine($"SHA1 Page Hash: {row.SHA1PageHash}")
			.AppendLine($"SHA256 Page Hash: {row.SHA256PageHash}")
			.AppendLine($"Has WHQL Signer: {row.HasWHQLSigner}")
			.AppendLine($"File Publishers: {row.FilePublishersToDisplay}")
			.AppendLine($"Is ECC Signed: {row.IsECCSigned}")
			.AppendLine($"Opus Data: {row.Opus}")
			.ToString();
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
	/// <param name="listViewBase">List to scroll</param>
	/// <param name="index">The index to bring into view. Index can be negative.</param>
	/// <param name="disableAnimation">Set true to disable animation</param>
	/// <param name="scrollIfVisible">Set false to disable scrolling when the corresponding item is in view</param>
	/// <param name="additionalHorizontalOffset">Adds additional horizontal offset</param>
	/// <param name="additionalVerticalOffset">Adds additional vertical offset</param>
	/// <returns>Returns <see cref="Task"/> that completes after scrolling</returns>
	internal static async Task SmoothScrollIntoViewWithIndexCenterVerticallyOnlyAsync(this ListViewBase listViewBase, ListView listView, int index, bool disableAnimation = false, bool scrollIfVisible = true, int additionalHorizontalOffset = 0, int additionalVerticalOffset = 0)
	{

		// Only perform the scroll if the setting is enabled
		if (!GetSetting<bool>(SettingKeys.ListViewsVerticalCentering))
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
