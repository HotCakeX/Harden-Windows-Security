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
using CommonCore.GroupPolicy;
using HardenSystemSecurity.Protect;

namespace HardenSystemSecurity.Helpers;

/// <summary>
/// Processor used by all of the MUnit-based categories.
/// </summary>
/// <param name="category">The MUnit-based category this processor handles.</param>
/// <param name="displayNameKey">Resource key of the category's display name.</param>
internal sealed class MUnitCategoryProcessor(Categories category, string displayNameKey) : ICategoryProcessor
{
	public Categories Category => category;
	public string CategoryDisplayName => Atlas.GetStr(displayNameKey);

	/// <summary>
	/// The ViewModel that owns this category's MUnits.
	/// Resolved on access so the ViewModel is only instantiated when it is actually needed.
	/// </summary>
	private IMUnitListViewModel ViewModel => CategoryProcessorFactory.GetMUnitViewModel(category)!;

	/// <summary>
	/// Gets all MUnits for this category.
	/// Using the ViewModel so Protect flows include everything the VM defines (JSON + programmatic MUnits),
	/// and also benefit from any specialized registrations/dependencies the VM wires.
	/// </summary>
	private List<MUnit> AllMUnits => ViewModel.AllMUnits;

	/// <summary>
	/// Filter MUnits based on selected sub-categories
	/// Include all items without sub-categories + items with selected sub-categories
	/// </summary>
	/// <param name="allMUnits">All MUnits for the category</param>
	/// <param name="selectedSubCategories">Selected sub-categories (null means only include MUnits without sub-categories)</param>
	/// <returns>Filtered list of MUnits</returns>
	private static List<MUnit> FilterMUnitsBySubCategories(List<MUnit> allMUnits, List<SubCategories>? selectedSubCategories)
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
	private static List<MUnit> FilterMUnitsByIntents(List<MUnit> mUnits, Intent? selectedIntent)
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
	private static List<MUnit> ResolvePolicyConflicts(List<MUnit> mUnits)
	{
		if (mUnits.Count <= 1)
			return mUnits;

		List<MUnit> result = [];

		// Keep MUnits with no JsonPolicyId (non-Registry/GP based, those from security baselines) as they don't have this conflict type.
		IEnumerable<MUnit> nonJsonMUnits = mUnits.Where(static m => m.JsonPolicyId is null);
		result.AddRange(nonJsonMUnits);

		// Process Registry/GP based MUnits
		IEnumerable<IGrouping<string, MUnit>> jsonGroups = mUnits
			.Where(static m => m.JsonPolicyId is not null)
			.GroupBy(static m => m.JsonPolicyId!, StringComparer.OrdinalIgnoreCase);

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
			List<MUnit> specificItems = group.Where(static m => m.SubCategory is not null).ToList();

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

	public Task ApplyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null) =>
		ProcessAllAsync(MUnitOperation.Apply, selectedSubCategories, selectedIntent, cancellationToken);

	public Task RemoveAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null) =>
		ProcessAllAsync(MUnitOperation.Remove, selectedSubCategories, selectedIntent, cancellationToken);

	public Task VerifyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null) =>
		ProcessAllAsync(MUnitOperation.Verify, selectedSubCategories, selectedIntent, cancellationToken);

	/// <summary>
	/// Shared implementation of <see cref="ApplyAllAsync"/>, <see cref="RemoveAllAsync"/> and <see cref="VerifyAllAsync"/>.
	/// </summary>
	/// <param name="operation">The operation to perform on the filtered MUnits.</param>
	/// <param name="selectedSubCategories">Selected sub-categories to include.</param>
	/// <param name="selectedIntent">Selected device intent to include (null means ignore intents).</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	private async Task ProcessAllAsync(MUnitOperation operation, List<SubCategories>? selectedSubCategories, Intent? selectedIntent, CancellationToken? cancellationToken)
	{
		// When processing based on intent (selectedIntent provided), do not use sub-category filtering.
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
		// For Remove and Verify, include all MUnits regardless of whether they have a remove/verify strategy.
		// The MUnit processing logic will handle cases where remove/verify strategy is null.
		await MUnit.ProcessMUnitsWithBulkOperations(ViewModel, filteredMUnits, operation, cancellationToken);
	}
}
