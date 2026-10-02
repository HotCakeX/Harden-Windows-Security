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
using System.Threading.Tasks;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using HardenSystemSecurity.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.Search.AppContentIndex;
using Windows.ApplicationModel;
using WinRT;

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
	private static readonly List<UnifiedSearchBarResult> _pagesListFromSearch = new(8);

	/// <summary>
	/// Extra non-MUnit search entries, to be registered once at startup before first query.
	/// </summary>
	private readonly struct ExtraSearchEntry(Type pageType, string localizedTitle)
	{
		internal Type PageType => pageType;
		internal string LocalizedTitle => localizedTitle;
	}

	/// <summary>
	/// Collected at startup; consumed once during BuildState.
	/// </summary>
	private static readonly List<ExtraSearchEntry> _extraEntries = new(capacity: 40);

	private static readonly SemaphoreSlim _indexGate = new(1, 1);
	private static volatile bool _indexReady;
	private const string IndexName = "HardenSystemSecuritySearchV1";

	/// <summary>
	/// Must be called before the first call to <see cref="GetPageFromQuery"/> (i.e., before the catalog is built).
	/// Must NOT be called more than once. Currently called only once from the Main Window VM's ctor.
	/// MainWindowVM is constructed in ViewModelProvider: NavigationService's lazy factory calls new NavigationService(MainWindowVM).
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
	private static List<UnifiedSearchBarResult> GetPageFromQuery(string? query)
	{
		if (string.IsNullOrEmpty(query))
			return _emptyPagesList;

		_pagesListFromSearch.Clear();

		// Normalize the query once
		ReadOnlySpan<char> needle = query.AsSpan().Trim();

		// Benchmarks show converting these Lists to Span first and then using For loop on them is faster than using For loop directly on Lists.
		ReadOnlySpan<string> lowerNamesSpan = CollectionsMarshal.AsSpan(LowerNames);
		ReadOnlySpan<Guid> nameIdsSpan = CollectionsMarshal.AsSpan(NameIds);

		for (int i = 0; i < lowerNamesSpan.Length; i++)
		{
			if (lowerNamesSpan[i].IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
			{
				_pagesListFromSearch.Add(CreateSearchResult(nameIdsSpan[i], lowerNamesSpan[i]));

				if (_pagesListFromSearch.Count == 8)
					break;
			}
		}

		// Have to send a new list instance for binding to see updated changes
		return new(_pagesListFromSearch);
	}

	/// <summary>
	/// Builds keyword and indexed search results.
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(BitmapIcon))]
	[DynamicWindowsRuntimeCast(typeof(FontIcon))]
	[DynamicWindowsRuntimeCast(typeof(SymbolIcon))]
	[DynamicWindowsRuntimeCast(typeof(PathIcon))]
	[DynamicWindowsRuntimeCast(typeof(AnimatedIcon))]
	private static UnifiedSearchBarResult CreateSearchResult(Guid id, string subtitle)
	{
		Type candidatePageType = PageByMUnitId[id];

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

		return new(
			pageType: candidatePageType,
			icon: clonedIcon,
			title: MainWindowVM.NavigationPageToItemContentMapForSearch[candidatePageType],
			subtitle: subtitle,
			mUnitId: id
			);
	}

	/// <summary>
	/// Marks localized index content for rebuilding on the next search.
	/// </summary>
	internal static void MarkContentSearchStale() => _indexReady = false;

	/// <summary>
	/// Indexes navigable security measures and pages without blocking the UI thread.
	/// https://learn.microsoft.com/windows/ai/apis/app-content-search-tutorial
	/// </summary>
	private static async Task InitializeContentSearchAsync()
	{
		await _indexGate.WaitAsync();
		try
		{
			if (_indexReady)
			{
				return;
			}
			LimitedAccessFeatureRequestResult access = LimitedAccessFeatures.TryUnlockFeature(
					"com.microsoft.windows.ai.appcontentindexer",
					"kfJOgPnUMeafIF01ANK6dg==",
					"ea7andspwdn10 has registered their use of com.microsoft.windows.ai.appcontentindexer with Microsoft and agrees to the terms of use.");
#if DEBUG
			Logger.Write($"App Content Search: limited-access status = {access.Status}.");
#endif
			// Only proceed when the limited-access feature was successfully unlocked.
			if (access.Status is not (LimitedAccessFeatureStatus.Available or LimitedAccessFeatureStatus.AvailableWithoutToken))
			{
				return;
			}
			List<KeyValuePair<Guid, string>> content = new(PageByMUnitId.Count);
			foreach (KeyValuePair<Guid, Type> entry in PageByMUnitId)
			{
				string title = MainWindowVM.NavigationPageToItemContentMapForSearch[entry.Value];
				string text = All.TryGetValue(entry.Key, out MUnit? unit)
					? $"{title}: {unit.Name} - {unit.Category}."
					: title;
				content.Add(new(entry.Key, text));
			}
			await Task.Run(() =>
			{
				GetOrCreateIndexResult result = AppContentIndexer.GetOrCreateIndex(IndexName);

				if (!result.Succeeded)
				{
					throw new InvalidOperationException($"App Content Search index: {result.Status}, {result.ExtendedError}");
				}

				using AppContentIndexer indexer = result.Indexer;
#if DEBUG
				LogSearchCapability(indexer);
#endif

				// This index belongs exclusively to this catalog; clear removed and language-stale entries.
				indexer.RemoveAllContentItems();
				foreach (KeyValuePair<Guid, string> entry in content)
				{
					indexer.AddOrUpdate(AppManagedIndexableAppContent.CreateFromString(entry.Key.ToString("D"), entry.Value));
				}
			});
			_indexReady = true;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
		finally
		{
			_ = _indexGate.Release();
		}
	}

	/// <summary>
	/// Returns ranked matches, or the existing keyword results if indexing is unavailable.
	/// </summary>
	internal static async Task<List<UnifiedSearchBarResult>> SearchAsync(string query)
	{
		await InitializeContentSearchAsync();
		if (!_indexReady)
		{
#if DEBUG
			Logger.Write($"App Content Search: index unavailable for query '{query}'; using keyword fallback.");
#endif
			return GetPageFromQuery(query);
		}
		try
		{
			List<Guid> ids = await Task.Run(() =>
			{
				GetOrCreateIndexResult result = AppContentIndexer.GetOrCreateIndex(IndexName);
				if (!result.Succeeded)
				{
					throw new InvalidOperationException($"App Content Search query: {result.Status}, {result.ExtendedError}");
				}

				using AppContentIndexer indexer = result.Indexer;
#if DEBUG
				LogSearchCapability(indexer);
				Logger.Write($"App Content Search: querying '{query}' (requesting up to 16 matches, displaying up to 8).");
#endif
				AppIndexTextQuery cursor = indexer.CreateTextQuery(query);
				List<Guid> matches = new(8);

				foreach (TextQueryMatch match in cursor.GetNextMatches(16))
				{
					if (Guid.TryParse(match.ContentId, out Guid id) && PageByMUnitId.ContainsKey(id) && !matches.Contains(id))
					{
						matches.Add(id);
					}
					if (matches.Count == 8)
					{
						break;
					}
				}
				return matches;
			});

			List<UnifiedSearchBarResult> suggestions = new(8);
			foreach (Guid id in ids)
			{
				int nameIndex = NameIds.IndexOf(id);
				string subtitle = nameIndex >= 0 ? LowerNames[nameIndex] : MainWindowVM.NavigationPageToItemContentMapForSearch[PageByMUnitId[id]].ToLowerInvariant();
				suggestions.Add(CreateSearchResult(id, subtitle));
			}
#if DEBUG
			if (suggestions.Count == 0)
			{
				Logger.Write($"App Content Search: no indexed matches for '{query}'; using keyword fallback.");
			}
#endif
			return suggestions.Count > 0 ? suggestions : GetPageFromQuery(query);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			_indexReady = false;
			return GetPageFromQuery(query);
		}
	}

#if DEBUG
	/// <summary>
	/// Reports whether the index supports semantic/lexical text matching.
	/// https://learn.microsoft.com/en-us/windows/ai/apis/#supported-hardware
	/// https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/release-notes/windows-app-sdk-2-0?pivots=stable#version-251
	/// "These APIs let apps provide text and image content for indexing and query that content using lexical matching and, on supported NPU-enabled devices, semantic matching."
	/// </summary>
	private static void LogSearchCapability(AppContentIndexer indexer)
	{
		// Semantic
		try
		{
			IndexCapabilityOfCurrentSystemStatus systemStatus = AppContentIndexer.GetIndexCapabilitiesOfCurrentSystem().GetIndexCapabilityStatus(IndexCapability.TextSemantic);
			Logger.Write($"App Content Search: current-system TextSemantic status = {systemStatus}.");
		}
		catch (Exception ex)
		{
			Logger.Write($"App Content Search: unable to inspect current-system TextSemantic capability: {ex}");
		}
		try
		{
			IndexCapabilityState state = indexer.GetIndexCapabilities().GetCapabilityState(IndexCapability.TextSemantic);
			Logger.Write($"App Content Search: TextSemantic status = {state.InitializationStatus}, error = {state.ErrorMessage}, extended error = {state.ExtendedError}.");
		}
		catch (Exception ex)
		{
			Logger.Write($"App Content Search: unable to inspect TextSemantic capability: {ex}");
		}

		// Lexical
		try
		{
			IndexCapabilityOfCurrentSystemStatus systemStatus = AppContentIndexer.GetIndexCapabilitiesOfCurrentSystem().GetIndexCapabilityStatus(IndexCapability.TextLexical);
			Logger.Write($"App Content Search: current-system TextLexical status = {systemStatus}.");
		}
		catch (Exception ex)
		{
			Logger.Write($"App Content Search: unable to inspect current-system TextLexical capability: {ex}");
		}
		try
		{
			IndexCapabilityState state = indexer.GetIndexCapabilities().GetCapabilityState(IndexCapability.TextLexical);
			Logger.Write($"App Content Search: TextLexical status = {state.InitializationStatus}, error = {state.ErrorMessage}, extended error = {state.ExtendedError}.");
		}
		catch (Exception ex)
		{
			Logger.Write($"App Content Search: unable to inspect TextLexical capability: {ex}");
		}
	}
#endif

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

		foreach (ExtraSearchEntry entry in CollectionsMarshal.AsSpan(_extraEntries))
		{
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
