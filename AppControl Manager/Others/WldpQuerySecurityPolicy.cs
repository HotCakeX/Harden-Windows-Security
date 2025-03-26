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

using System;
using System.Runtime.InteropServices;

namespace AppControlManager.Others;

/// <summary>
/// Defines different types of secure setting values used in WLDP. Types include Boolean, Integer, None, String, and
/// Flag.
/// </summary>
internal enum WLDP_SECURE_SETTING_VALUE_TYPE
{
	WldpBoolean = 0,
	WldpInteger = 1,
	WldpNone = 2,
	WldpString = 3,
	WldpFlag = 4
}

/// <summary>
/// Represents a Unicode string with a specified length and a pointer to the string's buffer. It includes fields for the
/// string's current length and maximum length.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct UNICODE_STRING
{
	internal ushort Length;
	internal ushort MaximumLength;
	internal IntPtr Buffer;
}

/// <summary>
/// Queries the security policy for a specified provider and key, returning the value type and size.
/// Initializes a UNICODE_STRING structure from a given string.
/// </summary>
internal static partial class WldpQuerySecurityPolicyWrapper
{
	[LibraryImport("Wldp.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int WldpQuerySecurityPolicy(
		ref UNICODE_STRING Provider,
		ref UNICODE_STRING Key,
		ref UNICODE_STRING ValueName,
		out WLDP_SECURE_SETTING_VALUE_TYPE ValueType,
		IntPtr Value,
		ref uint ValueSize);

	internal static UNICODE_STRING InitUnicodeString(string s)
	{
		UNICODE_STRING us;
		us.Length = (ushort)(s.Length * 2);
		us.MaximumLength = (ushort)((s.Length * 2) + 2);
		us.Buffer = Marshal.StringToHGlobalUni(s);
		return us;
	}
}
