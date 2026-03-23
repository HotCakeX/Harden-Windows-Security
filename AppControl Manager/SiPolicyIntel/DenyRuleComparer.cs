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
		HashCode hash = new();

		Deny deny = obj.DenyElement;

		if (!deny.Hash.IsEmpty)
		{
			hash.AddBytes(deny.Hash.Span);
		}
		hash.Add(deny.PackageFamilyName, StringComparer.OrdinalIgnoreCase);
		hash.Add(deny.FilePath, StringComparer.OrdinalIgnoreCase);
		hash.Add(deny.MinimumFileVersion, StringComparer.OrdinalIgnoreCase);
		hash.Add(deny.MaximumFileVersion, StringComparer.OrdinalIgnoreCase);
		hash.Add(deny.InternalName, StringComparer.OrdinalIgnoreCase);
		hash.Add(deny.FileDescription, StringComparer.OrdinalIgnoreCase);
		hash.Add(deny.ProductName, StringComparer.OrdinalIgnoreCase);
		hash.Add(deny.FileName, StringComparer.OrdinalIgnoreCase);

		return hash.ToHashCode();
	}
}
