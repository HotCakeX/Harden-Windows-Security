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

namespace AppControlManager.IntelGathering;

/// <summary>
/// A custom collection that manages a set of FileIdentity objects,
/// prioritizing newer FileIdentity items over older ones when adding items
/// with identical properties, based on the custom equality comparer.
/// Used by event logs scanning.
///
/// If an equivalent item (based on the FileIdentityComparer which takes priority) already exists,
/// the method checks the TimeCreated property of both the existing item and the new item:
/// If the existing item is older and the new item is newer: The older item is removed,
/// and the newer item is added to the set.
/// If the existing item is newer or has the same timestamp, the new item will not be added
/// because they are considered equal or the existing one is preferred.
/// </summary>
internal sealed class FileIdentityTimeBasedHashSet
{
	/// <summary>
	/// A HashSet to store FileIdentity objects with a custom comparer.
	/// This comparer defines equality based on selected properties in that comparer, ignoring TimeCreated for now.
	/// </summary>
	private readonly HashSet<FileIdentity> _set;

	/// <summary>
	/// Initializes a new instance of the FileIdentityTimeBasedHashSet class.
	/// </summary>
	internal FileIdentityTimeBasedHashSet()
	{
		_set = new HashSet<FileIdentity>(new FileIdentityComparer());
	}

	/// <summary>
	/// Expose the internal HashSet so we can access it directly.
	/// </summary>
	internal HashSet<FileIdentity> FileIdentitiesInternal => _set;

	/// <summary>
	/// Adds a FileIdentity item to the set, replacing an older equivalent item if it exists.
	/// </summary>
	/// <param name="item">The FileIdentity item to add.</param>
	/// <returns>True if a new item is added or an older item is replaced; false otherwise.</returns>
	public bool Add(FileIdentity item)
	{
		// Check if an equivalent item (based on FileIdentityComparer) already exists in the set
		if (_set.TryGetValue(item, out FileIdentity? existingItem))
		{
			// Prefer items that have TimeCreated over those that don't.
			// If both have TimeCreated, prefer the newer one. If equal or older, keep existing.
			DateTime? existingTime = existingItem.TimeCreated;
			DateTime? newTime = item.TimeCreated;

			// Both have timestamps: replace only if the new item is newer
			if (existingTime.HasValue && newTime.HasValue)
			{
				if (existingTime < newTime)
				{
					_ = _set.Remove(existingItem);
					_ = _set.Add(item);
					return true; // Replaced older with newer
				}
				return false; // Existing is newer or equal; keep it
			}

			// Existing has no timestamp but new has one: prefer the one with a timestamp
			if (!existingTime.HasValue && newTime.HasValue)
			{
				_ = _set.Remove(existingItem);
				_ = _set.Add(item);
				return true; // Replaced non-timestamped with timestamped
			}

			// Existing has a timestamp and new does not, or both lack timestamps: keep existing
			return false;
		}

		// If no equivalent item exists, add the new item to the set
		_ = _set.Add(item);
		return true;
	}

	/// <summary>
	/// Checks if the set contains an item equivalent to the specified FileIdentity item.
	/// </summary>
	/// <param name="item">The FileIdentity item to check for.</param>
	/// <returns>True if an equivalent item exists in the set; false otherwise.</returns>
	public bool Contains(FileIdentity item) => _set.Contains(item);

	/// <summary>
	/// Removes an equivalent FileIdentity item from the set, if it exists.
	/// </summary>
	/// <param name="item">The FileIdentity item to remove.</param>
	/// <returns>True if the item was removed; false if it did not exist in the set.</returns>
	public bool Remove(FileIdentity item) => _set.Remove(item);

	/// <summary>
	/// Gets the count of items in the set.
	/// </summary>
	public int Count => _set.Count;
}
