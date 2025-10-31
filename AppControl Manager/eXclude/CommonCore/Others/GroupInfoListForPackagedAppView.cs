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

	public override string ToString()
	{
		return "Group " + Key;
	}
}
