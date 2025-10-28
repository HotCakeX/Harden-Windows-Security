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

using System.IO;
using System.Text;

namespace CommonCore.QuantumRelay;

internal static class Helpers
{
	internal static void WriteString(BinaryWriter writer, string? value)
	{
		string safe = value ?? string.Empty;
		byte[] bytes = Encoding.UTF8.GetBytes(safe);
		writer.Write(bytes.Length);
		writer.Write(bytes);
	}

	internal static string ReadString(BinaryReader reader)
	{
		int length = ReadInt32(reader);
		if (length < 0)
		{
			return string.Empty;
		}

		byte[] buffer = new byte[length];
		int offset = 0;
		while (offset < length)
		{
			int n = reader.BaseStream.Read(buffer, offset, length - offset);
			if (n <= 0)
			{
				throw new IOException("Unexpected end of stream while reading string payload.");
			}
			offset += n;
		}

		return Encoding.UTF8.GetString(buffer);
	}

	internal static int ReadInt32(BinaryReader reader)
	{
		byte[] buffer = new byte[4];
		int offset = 0;
		while (offset < 4)
		{
			int n = reader.BaseStream.Read(buffer, offset, 4 - offset);
			if (n <= 0)
			{
				throw new IOException("Unexpected end of stream while reading Int32.");
			}
			offset += n;
		}

		// BinaryReader uses little-endian by default.
		return BitConverter.ToInt32(buffer, 0);
	}
}
