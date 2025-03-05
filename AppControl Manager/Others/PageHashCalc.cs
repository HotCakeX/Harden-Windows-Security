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
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace AppControlManager.Others;

/// <summary>
/// necessary logics for Page hash calculation
/// </summary>
internal static class PageHashCalculator
{

	// a method to get the hash of the first page of a file as a hexadecimal string
	internal static string? GetPageHash(string algName, string fileName) // the method signature
	{
		// initialize the buffer pointer to zero
		IntPtr buffer = IntPtr.Zero;

		// initialize the buffer size to zero
		int bufferSize = 0;

		// create a string builder to append the hash value
		StringBuilder stringBuilder = new(62);

		try
		{
			// call the native function with the given parameters and store the return value
			int firstPageHash1 = WinTrust.ComputeFirstPageHash(algName, fileName, buffer, bufferSize);

			// if the return value is zero, it means the function failed
			if (firstPageHash1 == 0)
			{
				// return null to indicate an error
				return null;
			}

			// allocate memory for the buffer using the return value as the size
			buffer = Marshal.AllocHGlobal(firstPageHash1);

			// call the native function again with the same parameters and the allocated buffer
			int firstPageHash2 = WinTrust.ComputeFirstPageHash(algName, fileName, buffer, firstPageHash1);

			// if the return value is zero, it means the function failed
			if (firstPageHash2 == 0)
			{
				// return null to indicate an error
				return null;
			}

			// loop through the buffer bytes
			for (int ofs = 0; ofs < firstPageHash2; ++ofs)

				// read each byte, convert it to a hexadecimal string, and append it to the string builder
				_ = stringBuilder.Append(Marshal.ReadByte(buffer, ofs).ToString("X2", CultureInfo.InvariantCulture));

			// return the final string
			return stringBuilder.ToString();
		}
		// a finally block to execute regardless of the outcome
		finally
		{
			// if the buffer pointer is not zero, it means it was allocated
			if (buffer != IntPtr.Zero)
			{
				// free the allocated memory
				Marshal.FreeHGlobal(buffer);
			}
		}
	}
}
