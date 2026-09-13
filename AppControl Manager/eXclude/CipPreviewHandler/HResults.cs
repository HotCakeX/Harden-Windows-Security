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

namespace CipPreviewHandler;

// The exact HRESULT values returned across the COM boundary.
internal static class HResults
{
	internal const int S_OK = 0;
	internal const int S_FALSE = 1;
	internal const int E_NOTIMPL = unchecked((int)0x80004001);
	internal const int E_POINTER = unchecked((int)0x80004003);
	internal const int E_FAIL = unchecked((int)0x80004005);
	internal const int E_INVALIDARG = unchecked((int)0x80070057);
	internal const int CLASS_E_CLASSNOTAVAILABLE = unchecked((int)0x80040111);
	internal const int CLASS_E_NOAGGREGATION = unchecked((int)0x80040110);
}
