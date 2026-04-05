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

namespace CommonCore.IntelGathering;

/// <summary>
/// A custom equality comparer for the FileIdentity class.
/// This comparer is used to determine the uniqueness of FileIdentity instances
/// based on specific properties.
/// </summary>
internal sealed class FileIdentityComparer : IEqualityComparer<FileIdentity>
{
	/// <summary>
	/// Determines whether two FileIdentity instances are equal.
	/// The instances are considered equal if all six specified properties are the same.
	///
	///
	/// Both FileIdentity Instances Are Null:
	/// Result: Equal(true).
	///
	///
	/// One Instance Is Null:
	/// Result: Not equal(false).
	///
	///
	/// Both Instances Are Not Null, with Some Properties Null:
	/// If a property is null in both instances, that property is considered equal.
	/// If a property is null in one instance but has a value in the other, that property is considered not equal.
	/// If all specified properties are equal (including handling of nulls), the instances are equal; otherwise, they are not.
	///
	/// </summary>
	/// <param name="x">The first FileIdentity instance to compare.</param>
	/// <param name="y">The second FileIdentity instance to compare.</param>
	/// <returns>true if the instances are equal; otherwise, false.</returns>
	public bool Equals(FileIdentity? x, FileIdentity? y)
	{
		// If both are null, they are considered equal
		if (x is null && y is null)
			return true;

		// If one is null and the other is not, they are not equal
		if (x is null || y is null)
			return false;

		// Compare the specified properties for equality using string comparison
		return string.Equals(x.SHA256Hash, y.SHA256Hash, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(x.SHA256FlatHash, y.SHA256FlatHash, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(x.ProductName, y.ProductName, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(x.InternalName, y.InternalName, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(x.OriginalFileName, y.OriginalFileName, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(x.FileDescription, y.FileDescription, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Returns a hash code for the given FileIdentity instance.
	/// The hash code is computed based on the six specified properties.
	/// </summary>
	/// <param name="obj">The FileIdentity instance for which to get the hash code.</param>
	/// <returns>A hash code for the given FileIdentity instance.</returns>
	public int GetHashCode(FileIdentity? obj)
	{
		if (obj is null) return 0;

		HashCode hash = new();

		hash.Add(obj.SHA256Hash, StringComparer.OrdinalIgnoreCase);
		hash.Add(obj.SHA256FlatHash, StringComparer.OrdinalIgnoreCase);
		hash.Add(obj.ProductName, StringComparer.OrdinalIgnoreCase);
		hash.Add(obj.InternalName, StringComparer.OrdinalIgnoreCase);
		hash.Add(obj.OriginalFileName, StringComparer.OrdinalIgnoreCase);
		hash.Add(obj.FileDescription, StringComparer.OrdinalIgnoreCase);

		return hash.ToHashCode();
	}
}
