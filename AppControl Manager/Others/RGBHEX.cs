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

namespace AppControlManager.Others;

internal static class RGBHEX
{
	/// <summary>
	/// Converts 3 RGB bytes to a 6-character uppercase hex string (no '#').
	/// </summary>
	/// <param name="r"></param>
	/// <param name="g"></param>
	/// <param name="b"></param>
	/// <returns></returns>
	internal static string ToHex(byte r, byte g, byte b)
	{
		Span<char> chars = stackalloc char[6];
		EncodeByte(r, chars, 0);
		EncodeByte(g, chars, 2);
		EncodeByte(b, chars, 4);
		return new string(chars);
	}

	// Parses a 6-char hex RGB, optionally with leading '#'.
	// Accepts upper or lower case. Returns false on any invalid input.
	internal static bool ToRGB(ReadOnlySpan<char> hex, out byte r, out byte g, out byte b)
	{
		if (hex.Length == 7 && hex[0] == '#')
			hex = hex[1..];

		if (hex.Length != 6)
		{
			r = g = b = 0;
			return false;
		}

		if (!TryDecodeByte(hex, 0, out r) ||
			!TryDecodeByte(hex, 2, out g) ||
			!TryDecodeByte(hex, 4, out b))
		{
			r = g = b = 0;
			return false;
		}

		return true;
	}

	private static void EncodeByte(byte value, Span<char> dest, int offset)
	{
		const string hexDigits = "0123456789ABCDEF";
		dest[offset] = hexDigits[value >> 4];
		dest[offset + 1] = hexDigits[value & 0xF];
	}

	private static bool TryDecodeByte(ReadOnlySpan<char> src, int offset, out byte value)
	{
		int hi = FromHex(src[offset]);
		int lo = FromHex(src[offset + 1]);
		if (hi < 0 || lo < 0)
		{
			value = 0;
			return false;
		}
		value = (byte)((hi << 4) | lo);
		return true;
	}

	// Fast hex digit -> value (returns -1 if invalid). Case-insensitive without allocating.
	private static int FromHex(char c)
	{
		if ((uint)(c - '0') <= 9)
			return c - '0';

		c = (char)(c | 0x20); // Fold to lowercase.
		if ((uint)(c - 'a') <= 5)
			return c - 'a' + 10;

		return -1;
	}
}
