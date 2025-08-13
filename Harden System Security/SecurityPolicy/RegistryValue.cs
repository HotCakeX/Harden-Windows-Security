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

namespace HardenSystemSecurity.SecurityPolicy;

/// <summary>
/// Represents a single value defined in the [Registry Values] section of the INF file exported by Secedit.
/// </summary>
/// <param name="name"></param>
/// <param name="type"></param>
/// <param name="value"></param>
internal sealed class RegistryValue(
	string name,
	int type,
	string value)
{
	internal string Name => name;
	internal int Type => type;
	internal string Value => value;
}
