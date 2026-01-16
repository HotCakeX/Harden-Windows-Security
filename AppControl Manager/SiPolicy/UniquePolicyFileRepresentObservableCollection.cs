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
using System.Collections.ObjectModel;

namespace AppControlManager.SiPolicy;

/// <summary>
/// An ObservableCollection of <see cref="PolicyFileRepresent"/> that only allows unique items based on <see cref="PolicyFileRepresent.UniqueObjID"/>.
/// If a duplicate item is added, it replaces the existing item.
/// </summary>
internal sealed partial class UniquePolicyFileRepresentObservableCollection : ObservableCollection<PolicyFileRepresent>
{
	private readonly HashSet<Guid> InternalHashSet = [];

	/// <summary>
	/// Inserts an item into the collection.
	/// If the item's UniqueObjID already exists, the existing item is replaced with the new one.
	/// </summary>
	protected override void InsertItem(int index, PolicyFileRepresent item)
	{
		// Check if the identifier already exists
		if (InternalHashSet.Contains(item.UniqueObjID))
		{
			// Find the existing item index with the same identifier
			for (int i = 0; i < Count; i++)
			{
				if (Guid.Equals(this[i].UniqueObjID, item.UniqueObjID))
				{
					// Replace the existing item with the new one.
					// We use base.SetItem to bypass our own SetItem check logic and avoid recursion/conflicts.
					base.SetItem(i, item);
					return;
				}
			}
		}

		// If not a duplicate, add to HashSet and insert as a new item
		if (InternalHashSet.Add(item.UniqueObjID))
		{
			base.InsertItem(index, item);
		}
	}

	/// <summary>
	/// Removes the item at the specified index and updates the internal lookup.
	/// </summary>
	protected override void RemoveItem(int index)
	{
		// Capture the ID before removing the item from the underlying collection
		Guid idToRemove = this[index].UniqueObjID;

		base.RemoveItem(index);

		// Remove from the HashSet
		_ = InternalHashSet.Remove(idToRemove);
	}

	/// <summary>
	/// Replaces the element at the specified index.
	/// </summary>
	protected override void SetItem(int index, PolicyFileRepresent item)
	{
		Guid oldId = this[index].UniqueObjID;
		Guid newId = item.UniqueObjID;

		// If the new ID exists and is different from the old ID, we have a conflict with another item.
		// To follow the HashSet behavior, duplicates are not allowed. Ignore the operation to maintain uniqueness.
		if (InternalHashSet.Contains(newId) && !Guid.Equals(oldId, newId))
		{
			return;
		}

		base.SetItem(index, item);

		// Update HashSet
		_ = InternalHashSet.Remove(oldId);
		_ = InternalHashSet.Add(newId);
	}

	/// <summary>
	/// Removes all items from the collection and clears the internal lookup.
	/// </summary>
	protected override void ClearItems()
	{
		base.ClearItems();
		InternalHashSet.Clear();
	}
}
