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

namespace AppControlManager.Others;

/// <summary>
/// An ObservableCollection of strings that only allows unique items (case-insensitive, ordinal comparison).
/// Duplicate strings will be ignored when added or set.
/// </summary>
internal sealed partial class UniqueStringObservableCollection : ObservableCollection<string>
{
	private readonly HashSet<string> _hashSet = new(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// A read-only view of the internal set of unique items.
	/// </summary>
	internal IReadOnlyCollection<string> UniqueItems => _hashSet;

	/// <summary>
	/// Inserts an item into the collection at the specified index if it's not already present (case-insensitive).
	/// </summary>
	protected override void InsertItem(int index, string item)
	{
		if (_hashSet.Add(item))
		{
			base.InsertItem(index, item);
		}
		// else: duplicate, ignore
	}

	/// <summary>
	/// Removes the item at the specified index and updates the internal lookup.
	/// </summary>
	protected override void RemoveItem(int index)
	{
		string removed = this[index];
		base.RemoveItem(index);
		_ = _hashSet.Remove(removed);
	}

	/// <summary>
	/// Replaces the element at the specified index if the new value is not a duplicate.
	/// </summary>
	protected override void SetItem(int index, string item)
	{
		string old = this[index];
		if (_hashSet.Contains(item))
		{
			// Duplicate, ignore the set operation
			return;
		}

		base.SetItem(index, item);
		_ = _hashSet.Remove(old);
		_ = _hashSet.Add(item);
	}

	/// <summary>
	/// Removes all items from the collection and clears the internal lookup.
	/// </summary>
	protected override void ClearItems()
	{
		base.ClearItems();
		_hashSet.Clear();
	}
}
