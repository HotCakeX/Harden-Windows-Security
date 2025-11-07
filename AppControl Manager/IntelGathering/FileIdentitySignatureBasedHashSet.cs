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
/// prioritizing signed FileIdentity items over unsigned ones when adding items
/// with identical properties, based on the custom equality comparer.
/// Mostly used for MDE Advanced Hunting logs.
///
/// If an equivalent item (based on the FileIdentityComparer which takes priority) already exists, the method checks the SignatureStatus of both the existing item and the new item:
/// If the existing item is unsigned and the new item is signed: The unsigned item is removed, and the signed item is added to the set.
/// If the existing item is already signed: The new item, signed or unsigned, will simply not be added because they are considered equal according to the FileIdentityComparer.
/// </summary>
internal sealed class FileIdentitySignatureBasedHashSet
{
	// A HashSet to store FileIdentity objects with a custom comparer.
	// This comparer defines equality based on selected properties in that comparer, ignoring SignatureStatus for now.
	private readonly HashSet<FileIdentity> _set;

	/// <summary>
	/// Initializes a new instance of the FileIdentitySignatureBasedHashSet class.
	/// </summary>
	internal FileIdentitySignatureBasedHashSet()
	{
		_set = new HashSet<FileIdentity>(new FileIdentityComparer());
	}

	/// <summary>
	/// Expose the internal HashSet so we can access it directly.
	/// </summary>
	internal HashSet<FileIdentity> FileIdentitiesInternal => _set;

	/// <summary>
	/// Adds a FileIdentity item to the set.
	/// </summary>
	/// <param name="item">The FileIdentity item to add.</param>
	/// <returns>True if a new item is added or an unsigned item is replaced; false otherwise.</returns>
	public bool Add(FileIdentity item)
	{
		// Check if an equivalent item (based on FileIdentityComparer) already exists in the set
		if (_set.TryGetValue(item, out FileIdentity? existingItem))
		{
			// If an equivalent unsigned item exists, replace it with the signed item
			if (existingItem.SignatureStatus == SignatureStatus.IsUnsigned && item.SignatureStatus == SignatureStatus.IsSigned)
			{
				Logger.Write(string.Format(
					GlobalVars.GetStr("ReplacingUnsignedItemMessage"),
					existingItem.FileName,
					existingItem.SHA256Hash));

				// Remove the existing unsigned item and add the signed one
				_ = _set.Remove(existingItem);
				_ = _set.Add(item);
				return true; // Indicate that an item was replaced
			}

			// If an equivalent signed item already exists, do not add the unsigned item
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
