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
/// Compares two DenyRule objects for equality based on various properties. Generates a hash code for a DenyRule using
/// multiple attributes.
/// </summary>
internal sealed class DenyRuleComparer : IEqualityComparer<DenyRule>
{
	public bool Equals(DenyRule? x, DenyRule? y)
	{
		if (x is null || y is null)
		{
			return false;
		}

		Deny denyX = x.DenyElement;
		Deny denyY = y.DenyElement;

		return Merger.CompareCommonRuleProperties(
			x.SigningScenario, y.SigningScenario,
			null, null,
			denyX.PackageFamilyName, denyY.PackageFamilyName,
			denyX.Hash, denyY.Hash,
			denyX.FilePath, denyY.FilePath,
			denyX.FileName, denyY.FileName,
			denyX.MinimumFileVersion, denyY.MinimumFileVersion,
			denyX.MaximumFileVersion, denyY.MaximumFileVersion,
			denyX.InternalName, denyY.InternalName,
			denyX.FileDescription, denyY.FileDescription,
			denyX.ProductName, denyY.ProductName);
	}

	public int GetHashCode(DenyRule obj)
	{
		Deny deny = obj.DenyElement;
		long hash = 17;  // Start with an initial value

		// Rule 1: Use PackageFamilyName for hash calculation
		if (!string.IsNullOrWhiteSpace(deny.PackageFamilyName))
		{
			hash = (hash * 31 + deny.PackageFamilyName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		// Rule 2: Use Hash for hash calculation
		if (deny.Hash is not null)
		{
			hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(deny.Hash)) % Merger.modulus;
		}

		// Rule 3: Use FilePath for hash calculation
		if (!string.IsNullOrWhiteSpace(deny.FilePath))
		{
			hash = (hash * 31 + deny.FilePath.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		// Rule 4: Use MinimumFileVersion, MaximumFileVersion, and name-related properties for hash
		if (!string.IsNullOrWhiteSpace(deny.MinimumFileVersion))
		{
			hash = (hash * 31 + deny.MinimumFileVersion.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		if (!string.IsNullOrWhiteSpace(deny.MaximumFileVersion))
		{
			hash = (hash * 31 + deny.MaximumFileVersion.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		if (!string.IsNullOrWhiteSpace(deny.InternalName))
		{
			hash = (hash * 31 + deny.InternalName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		if (!string.IsNullOrWhiteSpace(deny.FileDescription))
		{
			hash = (hash * 31 + deny.FileDescription.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		if (!string.IsNullOrWhiteSpace(deny.ProductName))
		{
			hash = (hash * 31 + deny.ProductName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		if (!string.IsNullOrWhiteSpace(deny.FileName))
		{
			hash = (hash * 31 + deny.FileName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		// Final adjustment to ensure the result is a non-negative int
		return (int)(hash & 0x7FFFFFFF); // Use only positive values
	}
}
