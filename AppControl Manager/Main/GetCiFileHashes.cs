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
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using AppControlManager.Others;

namespace AppControlManager.Main;

internal static class CiFileHash
{
	/// <summary>
	/// Method that outputs all 4 kinds of hashes
	/// </summary>
	/// <param name="filePath">The path to the file that is going to be hashed</param>
	/// <returns>CodeIntegrityHashes object that contains all 4 kinds of hashes</returns>
	internal static CodeIntegrityHashes GetCiFileHashes(string filePath)
	{
		return new CodeIntegrityHashes(
			PageHashCalculator.GetPageHash("SHA1", filePath),
			PageHashCalculator.GetPageHash("SHA256", filePath),
			GetAuthenticodeHash(filePath, "SHA1"),
			GetAuthenticodeHash(filePath, "SHA256")
		);
	}

	private static string? GetAuthenticodeHash(string filePath, string hashAlgorithm)
	{
		// A StringBuilder object to store the hash value as a hexadecimal string
		StringBuilder hashString = new(64);
		nint contextHandle = nint.Zero;
		nint hashValue = nint.Zero;

		try
		{
			using FileStream fileStream = File.OpenRead(filePath);

			// DangerousGetHandle returns the handle to the file stream
			nint fileStreamHandle = fileStream.SafeFileHandle.DangerousGetHandle();

			if (fileStreamHandle == nint.Zero)
			{
				return null;
			}

			if (!WinTrust.CryptCATAdminAcquireContext2(ref contextHandle, nint.Zero, hashAlgorithm, nint.Zero, 0))
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.Rizz.GetString("GetAuthenticodeHashAcquireContextError"),
						hashAlgorithm));
			}

			int hashSize = 0;

			if (!WinTrust.CryptCATAdminCalcHashFromFileHandle3(
					contextHandle,
					fileStreamHandle,
					ref hashSize,
					nint.Zero,
					WinTrust.CryptcatadminCalchashFlagNonconformantFilesFallbackFlat))
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.Rizz.GetString("GetAuthenticodeHashCalcFileHashError"),
						filePath,
						hashAlgorithm));
			}

			hashValue = Marshal.AllocHGlobal(hashSize);

			if (!WinTrust.CryptCATAdminCalcHashFromFileHandle3(
					contextHandle,
					fileStreamHandle,
					ref hashSize,
					hashValue,
					WinTrust.CryptcatadminCalchashFlagNonconformantFilesFallbackFlat))
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.Rizz.GetString("GetAuthenticodeHashCalcFileHashError"),
						filePath,
						hashAlgorithm));
			}

			for (int offset = 0; offset < hashSize; offset++)
			{
				// Marshal.ReadByte returns a byte from the hashValue buffer at the specified offset
				byte b = Marshal.ReadByte(hashValue, offset);
				// Append the byte to the hashString as a hexadecimal string
				_ = hashString.Append(b.ToString("X2", CultureInfo.InvariantCulture));
			}
		}
		finally
		{
			if (hashValue != nint.Zero)
			{
				Marshal.FreeHGlobal(hashValue);
			}

			if (contextHandle != nint.Zero)
			{
				_ = WinTrust.CryptCATAdminReleaseContext(contextHandle, 0);
			}
		}

		return hashString.ToString();
	}
}
