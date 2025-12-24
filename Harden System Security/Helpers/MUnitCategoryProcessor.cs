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
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using HardenSystemSecurity.DeviceIntents;
using HardenSystemSecurity.Protect;

namespace HardenSystemSecurity.Helpers;

/// <summary>
/// Base implementation for MUnit-based category processors.
/// </summary>
internal abstract class MUnitCategoryProcessor : ICategoryProcessor
{
	public abstract Categories Category { get; }
	public abstract string CategoryDisplayName { get; }

	/// <summary>
	/// Gets all MUnits for this category.
	/// </summary>
	/// <returns>List of all MUnits</returns>
	protected abstract List<MUnit> AllMUnits { get; }

	protected abstract IMUnitListViewModel ViewModel { get; }

	/// <summary>
	/// Filter MUnits based on selected sub-categories
	/// Include all items without sub-categories + items with selected sub-categories
	/// </summary>
	/// <param name="allMUnits">All MUnits for the category</param>
	/// <param name="selectedSubCategories">Selected sub-categories (null means only include MUnits without sub-categories)</param>
	/// <returns>Filtered list of MUnits</returns>
	protected virtual List<MUnit> FilterMUnitsBySubCategories(List<MUnit> allMUnits, List<SubCategories>? selectedSubCategories)
	{
		if (selectedSubCategories == null || selectedSubCategories.Count == 0)
		{
			// If no sub-categories are selected, only include MUnits without sub-categories
			return allMUnits.Where(x => x.SubCategory is null).ToList();
		}

		// Include:
		// 1. All MUnits without sub-categories (SubCategory == null)
		// 2. MUnits with sub-categories that are in the selected list
		return allMUnits.Where(munit =>
			munit.SubCategory == null ||
			selectedSubCategories.Contains(munit.SubCategory.Value)).ToList();
	}

	/// <summary>
	/// Filter MUnits by selected device intent.
	/// Rules:
	/// - If selectedIntent is null => do not filter by intent.
	/// - Include MUnits containing Intent.All when an intent is selected.
	/// - Otherwise include if any MUnit.DeviceIntents equals the selectedIntent.
	/// </summary>
	protected virtual List<MUnit> FilterMUnitsByIntents(List<MUnit> mUnits, Intent? selectedIntent)
	{
		// If no intent selected, do not filter and return the collection immediately.
		if (selectedIntent is null)
		{
			return mUnits;
		}

		List<MUnit> filtered = new(mUnits.Count);
		foreach (MUnit m in CollectionsMarshal.AsSpan(mUnits))
		{
			// Include Intent.All when any selection exists
			if (m.DeviceIntents.Any(di => di == Intent.All))
			{
				filtered.Add(m);
				continue;
			}

			// Include if intersects
			if (m.DeviceIntents.Any(s => s == selectedIntent))
			{
				filtered.Add(m);
			}
		}

		return filtered;
	}

	/// <summary>
	/// Resolves conflicts where multiple <see cref="MUnit"/>s target the same Registry Key/Value (same <see cref="MUnit.JsonPolicyId"/>).
	/// Priority rule: MUnits with a specific <see cref="SubCategories"/> win over MUnits with no <see cref="SubCategories"/> (null).
	/// </summary>
	/// <param name="mUnits">The list of MUnits to process.</param>
	/// <returns>A new list of MUnits with conflicts resolved.</returns>
	protected virtual List<MUnit> ResolvePolicyConflicts(List<MUnit> mUnits)
	{
		if (mUnits is null || mUnits.Count <= 1)
			return mUnits ?? [];

		List<MUnit> result = [];

		// Keep MUnits with no JsonPolicyId (non-Registry/GP based, those from security baselines) as they don't have this conflict type.
		IEnumerable<MUnit> nonJsonMUnits = mUnits.Where(m => m.JsonPolicyId is null);
		result.AddRange(nonJsonMUnits);

		// Process Registry/GP based MUnits
		IEnumerable<IGrouping<string, MUnit>> jsonGroups = mUnits
			.Where(m => m.JsonPolicyId is not null)
			.GroupBy(m => m.JsonPolicyId!, StringComparer.OrdinalIgnoreCase);

		foreach (IGrouping<string, MUnit> group in jsonGroups)
		{
			// If no conflict (only 1 item targeting this Key|Value), keep it.
			if (group.Count() == 1)
			{
				result.Add(group.First());
				continue;
			}

			// Conflict detected.
			// Prefer items with a SubCategory (Specific) over those without (Generic).
			List<MUnit> specificItems = group.Where(m => m.SubCategory is not null).ToList();

			if (specificItems.Count > 0)
			{
				// Specific items exist, so they supersede the Generic ones (SubCategory == null).
				// We keep all specific items (in case multiple specific sub-categories were selected).
				result.AddRange(specificItems);
			}
			else
			{
				// Only generic items exist (e.g. duplicates in JSON file with no subcategory).
				result.AddRange(group);
			}
		}

		return result;
	}

	public virtual async Task ApplyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
	{
		// When applying based on intent (selectedIntent provided), do not use sub-category filtering.
		// Otherwise (no intent filter), apply sub-category filter.
		bool hasIntentFilter = selectedIntent != null;

		List<MUnit> baseList = hasIntentFilter
			? AllMUnits
			: FilterMUnitsBySubCategories(AllMUnits, selectedSubCategories);

		// Apply any possible Intent-based filtration.
		List<MUnit> filteredMUnits = FilterMUnitsByIntents(baseList, selectedIntent);

		// Resolve any conflicts (e.g. Same Key/Value but one is Specific and one is Generic)
		filteredMUnits = ResolvePolicyConflicts(filteredMUnits);

		// Calling the core method as if we called it from each VM's UI.
		await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, filteredMUnits, MUnitOperation.Apply, cancellationToken);
	}

	public virtual async Task RemoveAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
	{
		// When removing based on intent (selectedIntent provided), do not use sub-category filtering.
		// Otherwise (no intent filter), apply sub-category filter.
		bool hasIntentFilter = selectedIntent != null;

		List<MUnit> baseList = hasIntentFilter
			? AllMUnits
			: FilterMUnitsBySubCategories(AllMUnits, selectedSubCategories);

		// Apply any possible Intent-based filtration.
		List<MUnit> filteredMUnits = FilterMUnitsByIntents(baseList, selectedIntent);

		// Resolve any conflicts (e.g. Same Key/Value but one is Specific and one is Generic)
		filteredMUnits = ResolvePolicyConflicts(filteredMUnits);

		// Include all MUnits regardless of whether they have a remove strategy
		// The MUnit processing logic will handle cases where remove strategy is null
		await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, filteredMUnits, MUnitOperation.Remove, cancellationToken);
	}

	public virtual async Task VerifyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
	{
		// When verifying based on intent (selectedIntent provided), do not use sub-category filtering.
		// Otherwise (no intent filter), apply sub-category filter.
		bool hasIntentFilter = selectedIntent != null;

		List<MUnit> baseList = hasIntentFilter
			? AllMUnits
			: FilterMUnitsBySubCategories(AllMUnits, selectedSubCategories);

		// Apply any possible Intent-based filtration.
		List<MUnit> filteredMUnits = FilterMUnitsByIntents(baseList, selectedIntent);

		// Resolve any conflicts (e.g. Same Key/Value but one is Specific and one is Generic)
		filteredMUnits = ResolvePolicyConflicts(filteredMUnits);

		// Include all MUnits regardless of whether they have a verify strategy
		// The MUnit processing logic will handle cases where verify strategy is null
		await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, filteredMUnits, MUnitOperation.Verify, cancellationToken);
	}
}
