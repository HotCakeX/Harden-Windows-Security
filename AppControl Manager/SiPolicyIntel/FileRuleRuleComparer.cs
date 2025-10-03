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
/// Provides custom equality comparison for <see cref="FileRuleRule"/> objects.
/// Two FileRuleRule objects are considered equal if:
///
/// 1. Their <see cref="FileRuleRule.SigningScenario"/> values match.
/// 2. Their underlying <see cref="FileRuleRule.FileRuleElement"/> objects match based on:
///    - Rule 1: If both have a non-empty <see cref="FileRule.PackageFamilyName"/> and these values are equal (case-insensitive).
///    - Rule 2: If both have non-null <see cref="FileRule.Hash"/> values that are equal according to <see cref="BytesArrayComparer.AreByteArraysEqual"/>.
///    - Rule 3: If both have a non-empty <see cref="FileRule.FilePath"/> and these values are equal (case-insensitive).
///    - Special Rule: If both have <see cref="FileRule.FileName"/> equal to "*" (case-insensitive).
///    - Rule 4: If both have a non-empty <see cref="FileRule.MinimumFileVersion"/> or <see cref="FileRule.MaximumFileVersion"/>,
///              then at least one of the following name-related properties must match (case-insensitive):
///              <see cref="FileRule.InternalName"/>, <see cref="FileRule.FileDescription"/>, <see cref="FileRule.ProductName"/>, or <see cref="FileRule.FileName"/>.
///
/// Additionally, the <see cref="FileRule.Type"/> property is compared. Even if all the other properties match,
/// differing <see cref="FileRule.Type"/> values result in the objects being considered different.
/// </summary>
internal sealed class FileRuleRuleComparer : IEqualityComparer<FileRuleRule>
{
	public bool Equals(FileRuleRule? x, FileRuleRule? y)
	{
		if (x is null || y is null)
		{
			return false;
		}

		FileRule fileRuleX = x.FileRuleElement;
		FileRule fileRuleY = y.FileRuleElement;

		return Merger.CompareCommonRuleProperties(
			x.SigningScenario, y.SigningScenario,
			fileRuleX.Type, fileRuleY.Type,
			fileRuleX.PackageFamilyName, fileRuleY.PackageFamilyName,
			fileRuleX.Hash, fileRuleY.Hash,
			fileRuleX.FilePath, fileRuleY.FilePath,
			fileRuleX.FileName, fileRuleY.FileName,
			fileRuleX.MinimumFileVersion, fileRuleY.MinimumFileVersion,
			fileRuleX.MaximumFileVersion, fileRuleY.MaximumFileVersion,
			fileRuleX.InternalName, fileRuleY.InternalName,
			fileRuleX.FileDescription, fileRuleY.FileDescription,
			fileRuleX.ProductName, fileRuleY.ProductName);
	}

	public int GetHashCode(FileRuleRule obj)
	{
		FileRule fileRule = obj.FileRuleElement;
		long hash = 17; // Starting prime for hash code calculation.

		// Rule 1: Use PackageFamilyName (if available).
		if (!string.IsNullOrWhiteSpace(fileRule.PackageFamilyName))
		{
			hash = (hash * 31 + fileRule.PackageFamilyName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		// Rule 2: Incorporate Hash if available.
		if (fileRule.Hash is not null)
		{
			hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(fileRule.Hash)) % Merger.modulus;
		}

		// Rule 3: Incorporate FilePath if available.
		if (!string.IsNullOrWhiteSpace(fileRule.FilePath))
		{
			hash = (hash * 31 + fileRule.FilePath.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		// Rule 4: Incorporate MinimumFileVersion, MaximumFileVersion and name-related properties.
		if (!string.IsNullOrWhiteSpace(fileRule.MinimumFileVersion))
		{
			hash = (hash * 31 + fileRule.MinimumFileVersion.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}
		if (!string.IsNullOrWhiteSpace(fileRule.MaximumFileVersion))
		{
			hash = (hash * 31 + fileRule.MaximumFileVersion.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}
		if (!string.IsNullOrWhiteSpace(fileRule.InternalName))
		{
			hash = (hash * 31 + fileRule.InternalName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}
		if (!string.IsNullOrWhiteSpace(fileRule.FileDescription))
		{
			hash = (hash * 31 + fileRule.FileDescription.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}
		if (!string.IsNullOrWhiteSpace(fileRule.ProductName))
		{
			hash = (hash * 31 + fileRule.ProductName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}
		if (!string.IsNullOrWhiteSpace(fileRule.FileName))
		{
			hash = (hash * 31 + fileRule.FileName.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		// Incorporate the FileRule Type into the hash to ensure that differing Type values produce different hashes.
		hash = (hash * 31 + fileRule.Type.GetHashCode()) % Merger.modulus;

		// Final adjustment to ensure the hash code is a non-negative int.
		return (int)(hash & 0x7FFFFFFF);
	}
}
