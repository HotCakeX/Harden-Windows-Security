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

using System;
using System.Collections.Generic;
using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

internal sealed class AllowRuleComparer : IEqualityComparer<AllowRule>
{
	public bool Equals(AllowRule? x, AllowRule? y)
	{
		if (x is null || y is null)
		{
			return false;
		}

		// Check SSType
		if (x.SigningScenario != y.SigningScenario)
		{
			return false;
		}

		Allow allowX = x.AllowElement;
		Allow allowY = y.AllowElement;

		// Rule 1: Check if PackageFamilyName is present in both and are equal
		if (!string.IsNullOrWhiteSpace(allowX.PackageFamilyName) &&
			!string.IsNullOrWhiteSpace(allowY.PackageFamilyName) &&
		   string.Equals(allowX.PackageFamilyName, allowY.PackageFamilyName, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		// Rule 2: Check if Hash is present in both and are equal
		if (allowX.Hash is not null && allowY.Hash is not null && BytesArrayComparer.AreByteArraysEqual(allowX.Hash, allowY.Hash))
		{
			return true;
		}

		// Rule 3: Check if FilePath is present in both and are equal
		if (!string.IsNullOrWhiteSpace(allowX.FilePath) &&
			!string.IsNullOrWhiteSpace(allowY.FilePath) &&
			string.Equals(allowX.FilePath, allowY.FilePath, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		// Rule special case: Check if FileName is "*" in both and are equal
		if (string.Equals(allowX.FileName, "*", StringComparison.OrdinalIgnoreCase) && string.Equals(allowY.FileName, "*", StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		// Rule 4: Check for MinimumFileVersion or MaximumFileVersion and the other properties
		bool hasMinX = !string.IsNullOrWhiteSpace(allowX.MinimumFileVersion);
		bool hasMaxX = !string.IsNullOrWhiteSpace(allowX.MaximumFileVersion);
		bool hasMinY = !string.IsNullOrWhiteSpace(allowY.MinimumFileVersion);
		bool hasMaxY = !string.IsNullOrWhiteSpace(allowY.MaximumFileVersion);

		// If both Allow elements have MinimumFileVersion or both have MaximumFileVersion
		if ((hasMinX && hasMinY) || (hasMaxX && hasMaxY))
		{
			// Check if any of the name-related properties are the same
			bool nameMatch =
				(!string.IsNullOrWhiteSpace(allowX.InternalName) && string.Equals(allowX.InternalName, allowY.InternalName, StringComparison.OrdinalIgnoreCase)) ||
				(!string.IsNullOrWhiteSpace(allowX.FileDescription) && string.Equals(allowX.FileDescription, allowY.FileDescription, StringComparison.OrdinalIgnoreCase)) ||
				(!string.IsNullOrWhiteSpace(allowX.ProductName) && string.Equals(allowX.ProductName, allowY.ProductName, StringComparison.OrdinalIgnoreCase)) ||
				(!string.IsNullOrWhiteSpace(allowX.FileName) && string.Equals(allowX.FileName, allowY.FileName, StringComparison.OrdinalIgnoreCase));

			if (nameMatch)
			{
				return true;
			}
		}

		// If one has MinimumFileVersion and the other has MaximumFileVersion, they are not duplicates
		if ((hasMinX && hasMaxY) || (hasMaxX && hasMinY))
		{
			return false;
		}

		// If none of the rules match, the AllowRule objects are not equal
		return false;
	}

	public int GetHashCode(AllowRule obj)
	{
		ArgumentNullException.ThrowIfNull(obj);

		Allow allow = obj.AllowElement;
		long hash = 17;  // Start with an initial value

		// A prime modulus to prevent overflow and ensure valid hash
		const long modulus = 0x7FFFFFFF; // Max value for int

		// Rule 1: Use PackageFamilyName for hash calculation
		if (!string.IsNullOrWhiteSpace(allow.PackageFamilyName))
		{
			hash = (hash * 31 + allow.PackageFamilyName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		// Rule 2: Use Hash for hash calculation
		if (allow.Hash is not null)
		{
			hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(allow.Hash)) % modulus;
		}

		// Rule 3: Use FilePath for hash calculation
		if (!string.IsNullOrWhiteSpace(allow.FilePath))
		{
			hash = (hash * 31 + allow.FilePath.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		// Rule 4: Use MinimumFileVersion, MaximumFileVersion, and name-related properties for hash
		if (!string.IsNullOrWhiteSpace(allow.MinimumFileVersion))
		{
			hash = (hash * 31 + allow.MinimumFileVersion.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		if (!string.IsNullOrWhiteSpace(allow.MaximumFileVersion))
		{
			hash = (hash * 31 + allow.MaximumFileVersion.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		if (!string.IsNullOrWhiteSpace(allow.InternalName))
		{
			hash = (hash * 31 + allow.InternalName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		if (!string.IsNullOrWhiteSpace(allow.FileDescription))
		{
			hash = (hash * 31 + allow.FileDescription.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		if (!string.IsNullOrWhiteSpace(allow.ProductName))
		{
			hash = (hash * 31 + allow.ProductName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		if (!string.IsNullOrWhiteSpace(allow.FileName))
		{
			hash = (hash * 31 + allow.FileName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		// Final adjustment to ensure the result is a non-negative int
		return (int)(hash & 0x7FFFFFFF); // Use only positive values
	}


}
