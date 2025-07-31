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
using System.Threading;
using System.Threading.Tasks;
using HardenWindowsSecurity.Protect;

namespace HardenWindowsSecurity.Helpers;

/// <summary>
/// Base implementation for MUnit-based category processors.
/// </summary>
internal abstract class MUnitCategoryProcessor : ICategoryProcessor
{
	public abstract Categories Category { get; }
	public abstract string CategoryDisplayName { get; }

	/// <summary>
	/// Create all MUnits for this category
	/// </summary>
	/// <returns>List of all MUnits</returns>
	protected abstract List<MUnit> CreateAllMUnits();

	/// <summary>
	/// Filter MUnits based on selected sub-categories
	/// Include all items without sub-categories + items with selected sub-categories
	/// </summary>
	/// <param name="allMUnits">All MUnits for the category</param>
	/// <param name="selectedSubCategories">Selected sub-categories (null means include no sub-category)</param>
	/// <returns>Filtered list of MUnits</returns>
	protected virtual List<MUnit> FilterMUnitsBySubCategories(List<MUnit> allMUnits, List<SubCategories>? selectedSubCategories)
	{
		if (selectedSubCategories == null || selectedSubCategories.Count == 0)
		{
			// Don't include any sub-category if null or 0
			return allMUnits.Where(x => x.SubCategory is null).ToList();
		}

		// Include:
		// 1. All MUnits without sub-categories (SubCategory == null)
		// 2. MUnits with sub-categories that are in the selected list
		return allMUnits.Where(munit =>
			munit.SubCategory == null ||
			selectedSubCategories.Contains(munit.SubCategory.Value)).ToList();
	}

	public virtual async Task ApplyAllAsync(List<SubCategories>? selectedSubCategories = null, CancellationToken? cancellationToken = null)
	{
		List<MUnit> allMUnits = CreateAllMUnits();
		List<MUnit> filteredMUnits = FilterMUnitsBySubCategories(allMUnits, selectedSubCategories);

		// Calling the core method as if we called it from each VM's UI.
		await MUnit.ProcessMUnitsWithBulkOperations(null, filteredMUnits, MUnitOperation.Apply, cancellationToken);
	}

	public virtual async Task RemoveAllAsync(List<SubCategories>? selectedSubCategories = null, CancellationToken? cancellationToken = null)
	{
		List<MUnit> allMUnits = CreateAllMUnits();
		List<MUnit> filteredMUnits = FilterMUnitsBySubCategories(allMUnits, selectedSubCategories);

		// Include all MUnits regardless of whether they have a remove strategy
		// The MUnit processing logic will handle cases where remove strategy is null
		await MUnit.ProcessMUnitsWithBulkOperations(null, filteredMUnits, MUnitOperation.Remove, cancellationToken);
	}

	public virtual async Task VerifyAllAsync(List<SubCategories>? selectedSubCategories = null, CancellationToken? cancellationToken = null)
	{
		List<MUnit> allMUnits = CreateAllMUnits();
		List<MUnit> filteredMUnits = FilterMUnitsBySubCategories(allMUnits, selectedSubCategories);

		// Include all MUnits regardless of whether they have a verify strategy
		// The MUnit processing logic will handle cases where verify strategy is null
		await MUnit.ProcessMUnitsWithBulkOperations(null, filteredMUnits, MUnitOperation.Verify, cancellationToken);
	}
}
