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

internal sealed class CodeIntegrityHashesV2(
	string? sha1Page,
	string? sha256Page,
	string? sha1Authenticode,
	string? sha256Authenticode,
	string? sha384Authenticode,
	string? sha512Authenticode,
	string? sha3_256Authenticode,
	string? sha3_384Authenticode,
	string? sha3_512Authenticode,
	string? sha3_384_Flat,
	string? sha3_512_Flat)
{
	internal string? SHA1Page => sha1Page;
	internal string? SHA256Page => sha256Page;
	internal string? SHA1Authenticode => sha1Authenticode;
	internal string? SHA256Authenticode => sha256Authenticode;
	internal string? SHA384Authenticode => sha384Authenticode;
	internal string? SHA512Authenticode => sha512Authenticode;
	internal string? SHA3_256Authenticode => sha3_256Authenticode;
	internal string? SHA3_384Authenticode => sha3_384Authenticode;
	internal string? SHA3_512Authenticode => sha3_512Authenticode;
	internal string? SHA3_384_Flat => sha3_384_Flat;
	internal string? SHA3_512_Flat => sha3_512_Flat;
}
