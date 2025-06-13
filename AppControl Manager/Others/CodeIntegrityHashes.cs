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

namespace AppControlManager.Others;

/// <summary>
/// Gets the Code Integrity hashes of a file.
/// Used primarily by the internal methods.
/// Use CodeIntegrityHashesV2 for more hash algorithms.
/// </summary>
/// <param name="sha1Page"></param>
/// <param name="sha256Page"></param>
/// <param name="sha1Authenticode"></param>
/// <param name="sha256Authenticode"></param>
internal sealed class CodeIntegrityHashes(
	string? sha1Page,
	string? sha256Page,
	string? sha1Authenticode,
	string? sha256Authenticode)
{
	internal string? SHA1Page => sha1Page;
	internal string? SHA256Page => sha256Page;
	internal string? SHa1Authenticode => sha1Authenticode;
	internal string? SHA256Authenticode => sha256Authenticode;
}
