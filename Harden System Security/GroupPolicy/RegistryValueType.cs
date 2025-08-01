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

namespace HardenSystemSecurity.GroupPolicy;

internal enum RegistryValueType : uint
{
	REG_NONE = 0,
	REG_SZ = 1,
	REG_EXPAND_SZ = 2,
	REG_BINARY = 3,
	REG_DWORD = 4,
	REG_DWORD_BIG_ENDIAN = 5,
	REG_LINK = 6,
	REG_MULTI_SZ = 7,
	REG_RESOURCE_LIST = 8,
	REG_FULL_RESOURCE_DESCRIPTOR = 9,
	REG_RESOURCE_REQUIREMENTS_LIST = 10,
	REG_QWORD = 11
}
