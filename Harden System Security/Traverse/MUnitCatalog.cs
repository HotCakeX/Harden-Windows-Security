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
using System.Runtime.InteropServices;
using System.Threading;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using HardenSystemSecurity.ViewModels;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.Traverse;

/// <summary>
/// A catalog that aggregates all MUnit instances into multiple collections, created lazily in a single pass.
/// </summary>
internal static class MUnitCatalog
{
	/// <summary>
	/// Lazily-built state
	/// </summary>
	private static readonly Lazy<CatalogState> _state = new(BuildState, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// Dictionary of all MUnits keyed by their ID.
	/// </summary>
	internal static FrozenDictionary<Guid, MUnit> All => _state.Value.All;

	/// <summary>
	/// Dictionary mapping MUnit IDs to their corresponding Page types.
	/// </summary>
	private static FrozenDictionary<Guid, Type> PageByMUnitId => _state.Value.PageByMUnitId;

	/// <summary>
	/// Lower-cased MUnit names (pre-normalized at build time) aligned with <see cref="NameIds"/>.
	/// Index i in <see cref="LowerNames"/> corresponds to Guid at index i in <see cref="NameIds"/>.
	/// </summary>
	private static List<string> LowerNames => _state.Value.LowerNames;

	/// <summary>
	/// Guid IDs aligned with <see cref="LowerNames"/>.
	/// </summary>
	private static List<Guid> NameIds => _state.Value.NameIds;

	/// <summary>
	/// Preallocated empty list returned for empty/whitespace queries by <see cref="GetPageFromQuery"/>.
	/// </summary>
	private static readonly List<UnifiedSearchBarResult> _emptyPagesList = new(0);

	/// <summary>
	/// Preallocated list returned by <see cref="GetPageFromQuery"/> when the query yields results.
	/// </summary>
	private static readonly List<UnifiedSearchBarResult> _pagesListFromSearch = new(5);

	/// <summary>
	/// Extra non-MUnit search entries, to be registered once at startup before first query.
	/// </summary>
	/// <param name="pageType"></param>
	/// <param name="localizedTitle"></param>
	internal readonly struct ExtraSearchEntry(Type pageType, string localizedTitle)
	{
		internal Type PageType => pageType;
		internal string LocalizedTitle => localizedTitle;
	}

	/// <summary>
	/// Collected at startup; consumed once during BuildState.
	/// </summary>
	private static readonly List<ExtraSearchEntry> _extraEntries = new(capacity: 40);

	/// <summary>
	/// Must be called before the first call to <see cref="GetPageFromQuery"/> (i.e., before the catalog is built).
	/// Must NOT be called more than once. Currently called only once from the Main Window VM's ctor.
	/// MainWindowVM is constructor in ViewModelProvider: NavigationService's lazy factory calls new NavigationService(MainWindowVM).
	/// That access to MainWindowVM forces its creation if it hasn't been initialized.
	/// </summary>
	internal static void RegisterExtraPage(Type pageType, string localizedTitle) =>
		_extraEntries.Add(new(pageType, localizedTitle));

	/// <summary>
	/// Retrieves up to 8 page types whose MUnit names contain the specified query string.
	/// Performs a case-insensitive substring match over pre-normalized lower-cased names and returns the first 8 matches.
	/// </summary>
	/// <param name="query">The query string used to identify matching page types.</param>
	/// <returns>A list of up to 8 matching page <see cref="Type"/> instances; empty if no matches are found.</returns>
	internal static List<UnifiedSearchBarResult> GetPageFromQuery(string? query)
	{
		if (string.IsNullOrEmpty(query))
			return _emptyPagesList;

		_pagesListFromSearch.Clear();

		// Normalize the query once
		ReadOnlySpan<char> needle = query.Trim().ToLowerInvariant();

		for (int i = 0; i < LowerNames.Count; i++)
		{
			if (LowerNames[i].IndexOf(needle) >= 0)
			{
				Type candidatePageType = PageByMUnitId[NameIds[i]];

				IconElement? clonedIcon = null;
				if (MainWindowVM.PageTypeToNavItem is not null &&
					MainWindowVM.PageTypeToNavItem.TryGetValue(candidatePageType, out NavigationViewItem? navItem) &&
					navItem.Icon is IconElement originalIcon)
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

				UnifiedSearchBarResult candidate = new(
					pageType: candidatePageType,
					icon: clonedIcon,
					title: MainWindowVM.NavigationPageToItemContentMapForSearch[candidatePageType],
					subtitle: LowerNames[i]
					);

				_pagesListFromSearch.Add(candidate);

				if (_pagesListFromSearch.Count == 8)
					break;
			}
		}

		// Have to send a new list instance for binding to see updated changes
		return new(_pagesListFromSearch);
	}

	/// <summary>
	/// Mapping of MUnit-based ViewModels to their corresponding Page types.
	/// </summary>
	private static readonly Dictionary<IMUnitListViewModel, Type> VMToPageMapping = new(13)
	{
		{ ViewModelProvider.MicrosoftDefenderVM, typeof(HardenSystemSecurity.Pages.Protects.MicrosoftDefender) },
		{ ViewModelProvider.BitLockerVM, typeof(HardenSystemSecurity.Pages.Protects.BitLocker) },
		{ ViewModelProvider.TLSVM, typeof(HardenSystemSecurity.Pages.Protects.TLS) },
		{ ViewModelProvider.LockScreenVM, typeof(HardenSystemSecurity.Pages.Protects.LockScreen) },
		{ ViewModelProvider.UACVM, typeof(HardenSystemSecurity.Pages.Protects.UAC) },
		{ ViewModelProvider.DeviceGuardVM, typeof(HardenSystemSecurity.Pages.Protects.DeviceGuard) },
		{ ViewModelProvider.WindowsFirewallVM, typeof(HardenSystemSecurity.Pages.Protects.WindowsFirewall) },
		{ ViewModelProvider.WindowsNetworkingVM, typeof(HardenSystemSecurity.Pages.Protects.WindowsNetworking) },
		{ ViewModelProvider.MiscellaneousConfigsVM, typeof(HardenSystemSecurity.Pages.Protects.MiscellaneousConfigs) },
		{ ViewModelProvider.WindowsUpdateVM, typeof(HardenSystemSecurity.Pages.Protects.WindowsUpdate) },
		{ ViewModelProvider.EdgeVM, typeof(HardenSystemSecurity.Pages.Protects.Edge) },
		{ ViewModelProvider.NonAdminVM, typeof(HardenSystemSecurity.Pages.Protects.NonAdmin) },
		{ ViewModelProvider.MicrosoftBaseLinesOverridesVM, typeof(HardenSystemSecurity.Pages.Protects.MicrosoftBaseLinesOverrides) }
	};

	/// <summary>
	/// Builds frozen dictionaries in a single pass.
	/// Also builds two aligned arrays (LowerNames and NameIds) for substring search.
	/// </summary>
	private static CatalogState BuildState()
	{
		Dictionary<Guid, MUnit> units = new(capacity: 1000);
		Dictionary<Guid, Type> pages = new(capacity: 1000);

		// Parallel arrays for fast search
		List<string> lowerNames = new(capacity: 1000);
		List<Guid> nameIds = new(capacity: 1000);

		foreach (KeyValuePair<IMUnitListViewModel, Type> pair in VMToPageMapping)
		{
			foreach (MUnit item in CollectionsMarshal.AsSpan(pair.Key.AllMUnits))
			{
				units[item.ID] = item;
				pages[item.ID] = pair.Value;

				if (item.Name != null)
				{
					lowerNames.Add(item.Name.ToLowerInvariant());
					nameIds.Add(item.ID);
				}
			}
		}

		for (int i = 0; i < _extraEntries.Count; i++)
		{
			ExtraSearchEntry entry = _extraEntries[i];

			// synthetic ID for search mapping only
			Guid id = Guid.CreateVersion7();

			pages[id] = entry.PageType;
			lowerNames.Add(entry.LocalizedTitle.ToLowerInvariant());
			nameIds.Add(id);
		}

		// Clear the collections used only during state building.
		_extraEntries.Clear();
		_extraEntries.Capacity = 0;
		VMToPageMapping.Clear();

		return new(
			units.ToFrozenDictionary(),
			pages.ToFrozenDictionary(),
			lowerNames,
			nameIds
		);
	}

	private sealed class CatalogState(
		FrozenDictionary<Guid, MUnit> all,
		FrozenDictionary<Guid, Type> pageByMUnitId,
		List<string> lowerNames,
		List<Guid> nameIds
		)
	{
		internal FrozenDictionary<Guid, MUnit> All => all;
		internal FrozenDictionary<Guid, Type> PageByMUnitId => pageByMUnitId;
		internal List<string> LowerNames => lowerNames;
		internal List<Guid> NameIds => nameIds;
	}
}
