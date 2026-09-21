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

namespace CommonCore.Others;

/// <summary>
/// GroupInfoListForPackagedAppView class definition
/// </summary>
/// <param name="items">All of the <see cref="PackagedAppView"/> items in this group.</param>
/// <param name="key">The key for this group, which is based on the first character of the DisplayName of the <see cref="PackagedAppView"/> items.</param>
internal sealed partial class GroupInfoListForPackagedAppView(IEnumerable<PackagedAppView> items, string key) : List<PackagedAppView>(items)
{
	// string is the type for Key since it's based on DisplayName[..1] and will always be a string
	internal string Key => key;

	public override string ToString() => "Group " + Key;
}

/// <summary>
/// Compares the group keys of <see cref="GroupInfoListForPackagedAppView"/> so the SemanticZoom groups are ordered
/// in a way that is useful to the user: letters first, then digits, then every other character.
/// </summary>
internal sealed class PackagedAppGroupKeyComparer : IComparer<string>
{
	/// <summary>
	/// The single shared instance, the comparer is stateless.
	/// </summary>
	internal static readonly PackagedAppGroupKeyComparer Instance = new();

	private PackagedAppGroupKeyComparer() { }

	/// <summary>
	/// Gets the ordering rank of a group key. Lower ranks are displayed first.
	/// </summary>
	/// <param name="key">The group key to rank.</param>
	/// <returns>0 for letters, 1 for digits and 2 for anything else, including empty keys.</returns>
	private static int GetRank(string? key)
	{
		if (string.IsNullOrEmpty(key))
		{
			return 2;
		}

		char firstCharacter = key[0];

		if (char.IsLetter(firstCharacter))
		{
			return 0;
		}

		return char.IsDigit(firstCharacter) ? 1 : 2;
	}

	public int Compare(string? x, string? y)
	{
		int xRank = GetRank(x);
		int yRank = GetRank(y);

		// Groups in different ranks are ordered by their rank alone, so symbol groups always end up at the very end.
		if (xRank != yRank)
		{
			return xRank.CompareTo(yRank);
		}

		// Groups within the same rank keep the previous alphabetical ordering.
		return StringComparer.OrdinalIgnoreCase.Compare(x, y);
	}
}
