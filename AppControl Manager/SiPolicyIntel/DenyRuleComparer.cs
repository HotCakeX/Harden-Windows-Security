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

internal sealed class DenyRuleComparer : IEqualityComparer<DenyRule>
{
	public bool Equals(DenyRule? x, DenyRule? y)
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

		Deny denyX = x.DenyElement;
		Deny denyY = y.DenyElement;

		// Rule 1: Check if PackageFamilyName is present in both and are equal
		if (!string.IsNullOrWhiteSpace(denyX.PackageFamilyName) &&
			!string.IsNullOrWhiteSpace(denyY.PackageFamilyName) &&
		   string.Equals(denyX.PackageFamilyName, denyY.PackageFamilyName, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		// Rule 2: Check if Hash is present in both and are equal
		if (denyX.Hash is not null && denyY.Hash is not null && BytesArrayComparer.AreByteArraysEqual(denyX.Hash, denyY.Hash))
		{
			return true;
		}

		// Rule 3: Check if FilePath is present in both and are equal
		if (!string.IsNullOrWhiteSpace(denyX.FilePath) &&
			!string.IsNullOrWhiteSpace(denyY.FilePath) &&
			string.Equals(denyX.FilePath, denyY.FilePath, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		// Rule special case: Check if FileName is "*" in both and are equal
		if (string.Equals(denyX.FileName, "*", StringComparison.OrdinalIgnoreCase) && string.Equals(denyX.FileName, "*", StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		// Rule 4: Check for MinimumFileVersion or MaximumFileVersion and the other properties
		bool hasMinX = !string.IsNullOrWhiteSpace(denyX.MinimumFileVersion);
		bool hasMaxX = !string.IsNullOrWhiteSpace(denyX.MaximumFileVersion);
		bool hasMinY = !string.IsNullOrWhiteSpace(denyY.MinimumFileVersion);
		bool hasMaxY = !string.IsNullOrWhiteSpace(denyY.MaximumFileVersion);

		// If both deny elements have MinimumFileVersion or both have MaximumFileVersion
		if ((hasMinX && hasMinY) || (hasMaxX && hasMaxY))
		{
			// Check if any of the name-related properties are the same
			bool nameMatch =
				(!string.IsNullOrWhiteSpace(denyX.InternalName) && string.Equals(denyX.InternalName, denyY.InternalName, StringComparison.OrdinalIgnoreCase)) ||
				(!string.IsNullOrWhiteSpace(denyX.FileDescription) && string.Equals(denyX.FileDescription, denyY.FileDescription, StringComparison.OrdinalIgnoreCase)) ||
				(!string.IsNullOrWhiteSpace(denyX.ProductName) && string.Equals(denyX.ProductName, denyY.ProductName, StringComparison.OrdinalIgnoreCase)) ||
				(!string.IsNullOrWhiteSpace(denyX.FileName) && string.Equals(denyX.FileName, denyY.FileName, StringComparison.OrdinalIgnoreCase));

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

		// If none of the rules match, the DenyRule objects are not equal
		return false;
	}

	public int GetHashCode(DenyRule obj)
	{
		ArgumentNullException.ThrowIfNull(obj);

		Deny deny = obj.DenyElement;
		long hash = 17;  // Start with an initial value

		// A prime modulus to prevent overflow and ensure valid hash
		const long modulus = 0x7FFFFFFF; // Max value for int

		// Rule 1: Use PackageFamilyName for hash calculation
		if (!string.IsNullOrWhiteSpace(deny.PackageFamilyName))
		{
			hash = (hash * 31 + deny.PackageFamilyName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		// Rule 2: Use Hash for hash calculation
		if (deny.Hash is not null)
		{
			hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(deny.Hash)) % modulus;
		}

		// Rule 3: Use FilePath for hash calculation
		if (!string.IsNullOrWhiteSpace(deny.FilePath))
		{
			hash = (hash * 31 + deny.FilePath.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		// Rule 4: Use MinimumFileVersion, MaximumFileVersion, and name-related properties for hash
		if (!string.IsNullOrWhiteSpace(deny.MinimumFileVersion))
		{
			hash = (hash * 31 + deny.MinimumFileVersion.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		if (!string.IsNullOrWhiteSpace(deny.MaximumFileVersion))
		{
			hash = (hash * 31 + deny.MaximumFileVersion.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		if (!string.IsNullOrWhiteSpace(deny.InternalName))
		{
			hash = (hash * 31 + deny.InternalName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		if (!string.IsNullOrWhiteSpace(deny.FileDescription))
		{
			hash = (hash * 31 + deny.FileDescription.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		if (!string.IsNullOrWhiteSpace(deny.ProductName))
		{
			hash = (hash * 31 + deny.ProductName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		if (!string.IsNullOrWhiteSpace(deny.FileName))
		{
			hash = (hash * 31 + deny.FileName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		// Final adjustment to ensure the result is a non-negative int
		return (int)(hash & 0x7FFFFFFF); // Use only positive values
	}


}
