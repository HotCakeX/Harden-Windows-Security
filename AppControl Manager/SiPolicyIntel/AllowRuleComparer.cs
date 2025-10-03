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
using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

/// <summary>
/// Provides custom equality comparison for <see cref="AllowRule"/> objects.
/// Two AllowRule objects are considered equal if they have the same SigningScenario and at least one
/// of the following property-based matching rules holds true:
///
/// Rule 1: Both Allow elements have non-empty PackageFamilyName values that are equal (case-insensitive).
/// Rule 2: Both Allow elements have non-null Hash values that are equal (using <see cref="BytesArrayComparer.AreByteArraysEqual"/>).
/// Rule 3: Both Allow elements have non-empty FilePath values that are equal (case-insensitive).
/// Special Rule: Both Allow elements have a FileName value equal to "*" (wildcard, case-insensitive).
/// Rule 4: If both Allow elements specify MinimumFileVersion or both specify MaximumFileVersion,
///         then at least one of the name-related properties (InternalName, FileDescription, ProductName, or FileName)
///         must match (case-insensitive).
///
/// In addition, if one element has a MinimumFileVersion and the other has a MaximumFileVersion, they are not considered equal.
/// </summary>

internal sealed class AllowRuleComparer : IEqualityComparer<AllowRule>
{
	public bool Equals(AllowRule? x, AllowRule? y)
	{
		if (x is null || y is null)
		{
			return false;
		}

		Allow allowX = x.AllowElement;
		Allow allowY = y.AllowElement;

		return Merger.CompareCommonRuleProperties(
			x.SigningScenario, y.SigningScenario,
			null, null,
			allowX.PackageFamilyName, allowY.PackageFamilyName,
			allowX.Hash, allowY.Hash,
			allowX.FilePath, allowY.FilePath,
			allowX.FileName, allowY.FileName,
			allowX.MinimumFileVersion, allowY.MinimumFileVersion,
			allowX.MaximumFileVersion, allowY.MaximumFileVersion,
			allowX.InternalName, allowY.InternalName,
			allowX.FileDescription, allowY.FileDescription,
			allowX.ProductName, allowY.ProductName);
	}

	public int GetHashCode(AllowRule obj)
	{
		Allow allow = obj.AllowElement;
		long hash = 17;  // Start with an initial value

		// Rule 1: Use PackageFamilyName for hash calculation
		if (!string.IsNullOrWhiteSpace(allow.PackageFamilyName))
		{
			hash = (hash * 31 + allow.PackageFamilyName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		// Rule 2: Use Hash for hash calculation
		if (allow.Hash is not null)
		{
			hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(allow.Hash)) % Merger.modulus;
		}

		// Rule 3: Use FilePath for hash calculation
		if (!string.IsNullOrWhiteSpace(allow.FilePath))
		{
			hash = (hash * 31 + allow.FilePath.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		// Rule 4: Use MinimumFileVersion, MaximumFileVersion, and name-related properties for hash
		if (!string.IsNullOrWhiteSpace(allow.MinimumFileVersion))
		{
			hash = (hash * 31 + allow.MinimumFileVersion.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		if (!string.IsNullOrWhiteSpace(allow.MaximumFileVersion))
		{
			hash = (hash * 31 + allow.MaximumFileVersion.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		if (!string.IsNullOrWhiteSpace(allow.InternalName))
		{
			hash = (hash * 31 + allow.InternalName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		if (!string.IsNullOrWhiteSpace(allow.FileDescription))
		{
			hash = (hash * 31 + allow.FileDescription.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		if (!string.IsNullOrWhiteSpace(allow.ProductName))
		{
			hash = (hash * 31 + allow.ProductName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		if (!string.IsNullOrWhiteSpace(allow.FileName))
		{
			hash = (hash * 31 + allow.FileName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		// Final adjustment to ensure the result is a non-negative int
		return (int)(hash & 0x7FFFFFFF); // Use only positive values
	}
}
