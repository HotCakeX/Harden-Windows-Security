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
///    - Rule 2: If both have non-null <see cref="FileRule.Hash"/> values that are equal.
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
		HashCode hash = new();

		FileRule fileRule = obj.FileRuleElement;

		if (!fileRule.Hash.IsEmpty)
		{
			hash.AddBytes(fileRule.Hash.Span);
		}
		hash.Add(fileRule.PackageFamilyName, StringComparer.OrdinalIgnoreCase);
		hash.Add(fileRule.FilePath, StringComparer.OrdinalIgnoreCase);
		hash.Add(fileRule.MinimumFileVersion, StringComparer.OrdinalIgnoreCase);
		hash.Add(fileRule.MaximumFileVersion, StringComparer.OrdinalIgnoreCase);
		hash.Add(fileRule.InternalName, StringComparer.OrdinalIgnoreCase);
		hash.Add(fileRule.FileDescription, StringComparer.OrdinalIgnoreCase);
		hash.Add(fileRule.ProductName, StringComparer.OrdinalIgnoreCase);
		hash.Add(fileRule.FileName, StringComparer.OrdinalIgnoreCase);
		hash.Add(fileRule.Type);

		return hash.ToHashCode();
	}
}
