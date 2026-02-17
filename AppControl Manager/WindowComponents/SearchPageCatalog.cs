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
using AppControlManager.ViewModels;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.WindowComponents;

/// <summary>
/// A catalog that searches through the AppControl Manager pages.
/// </summary>
internal static class SearchPageCatalog
{
	/// <summary>
	/// Preallocated empty list returned for empty/whitespace queries.
	/// </summary>
	private static readonly List<UnifiedSearchBarResult> _emptyPagesList = new(0);

	/// <summary>
	/// Preallocated list returned when the query yields results.
	/// </summary>
	private static readonly List<UnifiedSearchBarResult> _pagesListFromSearch = new(8);

	/// <summary>
	/// Retrieves up to 8 page types whose Titles contain the specified query string.
	/// </summary>
	/// <param name="query">The query string used to identify matching page types.</param>
	/// <returns>A list of up to 8 matching UnifiedSearchBarResult instances.</returns>
	internal static List<UnifiedSearchBarResult> GetPageFromQuery(string? query)
	{
		if (string.IsNullOrWhiteSpace(query))
			return _emptyPagesList;

		_pagesListFromSearch.Clear();

		// Normalize the query
		ReadOnlySpan<char> needle = query.Trim().AsSpan();

		// Iterate over the search map defined in MainWindowVM
		foreach (KeyValuePair<string, Type> entry in ViewModelProvider.MainWindowVM.NavigationPageToItemContentMapForSearch)
		{
			// Perform case-insensitive search on the Title
			if (entry.Key.Contains(needle, StringComparison.OrdinalIgnoreCase))
			{
				// Retrieve the NavigationViewItem to get the Icon and ToolTip (Description)
				IconElement? clonedIcon = null;
				string subtitle = string.Empty;

				if (MainWindowVM.PageTypeToNavItem is not null &&
					MainWindowVM.PageTypeToNavItem.TryGetValue(entry.Value, out NavigationViewItem? navItem))
				{
					// Clone the Icon
					// Icons in WinUI cannot be attached to two parents at once, so we must clone it for the search result.
					if (navItem.Icon is IconElement originalIcon)
					{
						clonedIcon = originalIcon switch
						{
							BitmapIcon b => new BitmapIcon { UriSource = b.UriSource, ShowAsMonochrome = b.ShowAsMonochrome },
							FontIcon f => new FontIcon { Glyph = f.Glyph, FontFamily = f.FontFamily, FontSize = f.FontSize, Foreground = f.Foreground },
							SymbolIcon s => new SymbolIcon { Symbol = s.Symbol },
							PathIcon p => new PathIcon { Data = p.Data, Foreground = p.Foreground },
							AnimatedIcon a => new AnimatedIcon { Source = a.Source },
							_ => null
						};
					}

					// Get the Subtitle from the ToolTip
					// In ACM, the ToolTips provide the description of the page.
					object toolTipObj = ToolTipService.GetToolTip(navItem);
					if (toolTipObj is string toolTipString)
					{
						subtitle = toolTipString;
					}
				}

				UnifiedSearchBarResult candidate = new(
					pageType: entry.Value,
					icon: clonedIcon,
					title: entry.Key,
					subtitle: subtitle, // Using ToolTip as the subtitle
					mUnitId: null       // ACM doesn't use MUnit IDs, so this remains null
				);

				_pagesListFromSearch.Add(candidate);

				// Limit results to 8
				if (_pagesListFromSearch.Count >= 8)
					break;
			}
		}

		// Return a new list instance for binding updates
		return new(_pagesListFromSearch);
	}
}
