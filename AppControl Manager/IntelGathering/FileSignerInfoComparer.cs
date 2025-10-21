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
/// A custom equality comparer for the FileSignerInfo class.
/// This comparer is used to determine the uniqueness of FileSignerInfo instances
/// based on PublisherTBSHash and IssuerTBSHash properties.
/// </summary>
internal sealed class FileSignerInfoComparer : IEqualityComparer<FileSignerInfo>
{
	/// <summary>
	/// Determines whether two FileSignerInfo instances are equal.
	/// The instances are considered equal if both the PublisherTBSHash
	/// and IssuerTBSHash properties are equal.
	/// </summary>
	/// <param name="x">The first FileSignerInfo instance to compare.</param>
	/// <param name="y">The second FileSignerInfo instance to compare.</param>
	/// <returns>true if the instances are equal; otherwise, false.</returns>
	public bool Equals(FileSignerInfo? x, FileSignerInfo? y)
	{
		// If both are null, they are considered equal
		if (x is null && y is null)
			return true;

		// If either instance is null, they are not considered equal
		if (x is null || y is null)
			return false;

		// Compare the PublisherTBSHash and IssuerTBSHash properties for equality
		return string.Equals(x.PublisherTBSHash, y.PublisherTBSHash, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(x.IssuerTBSHash, y.IssuerTBSHash, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Returns a hash code for the given FileSignerInfo instance.
	/// The hash code is computed based on the PublisherTBSHash and IssuerTBSHash properties.
	/// </summary>
	/// <param name="obj">The FileSignerInfo instance for which to get the hash code.</param>
	/// <returns>A hash code for the given FileSignerInfo instance.</returns>
	public int GetHashCode(FileSignerInfo obj)
	{

		int hashPublisher;
		int hashIssuer;

		// Get hash codes for both properties, using case-insensitive comparison for strings
		// Using unchecked to avoid exceptions from overflow
		unchecked
		{
			hashPublisher = obj.PublisherTBSHash?.GetHashCode(StringComparison.OrdinalIgnoreCase) ?? 0;
			hashIssuer = obj.IssuerTBSHash?.GetHashCode(StringComparison.OrdinalIgnoreCase) ?? 0;
		}

		// Combine the hash codes using XOR to produce a single hash code for the instance
		// Reducing collisions by using 397 prime number
		return unchecked((hashPublisher * 397) ^ hashIssuer);
	}
}
