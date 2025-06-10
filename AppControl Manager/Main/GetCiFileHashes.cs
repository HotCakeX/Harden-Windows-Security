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
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using AppControlManager.Others;

namespace AppControlManager.Main;

internal static class CiFileHash
{

	// a constant field that defines a flag value for the native function
	// This causes/helps the GetCiFileHashes method to return the flat file hashes whenever a non-conformant file is encountered
	private const uint CryptcatadminCalchashFlagNonconformantFilesFallbackFlat = 1;

	/// <summary>
	/// A method that outputs hashes used primarily by the app.
	/// </summary>
	/// <param name="filePath"></param>
	/// <returns></returns>
	internal static CodeIntegrityHashes GetCiFileHashes(string filePath)
	{
		return new CodeIntegrityHashes(
			PageHashCalculator.GetPageHash("SHA1", filePath),
			PageHashCalculator.GetPageHash("SHA256", filePath),
			GetAuthenticodeHash(filePath, "SHA1"),
			GetAuthenticodeHash(filePath, "SHA256")
		);
	}

	/// <summary>
	/// Method that outputs all 9 kinds of hashes
	/// </summary>
	/// <param name="filePath">The path to the file that is going to be hashed</param>
	/// <returns>CodeIntegrityHashes object that contains all 9 kinds of hashes</returns>
	internal static CodeIntegrityHashesV2 GetCiFileHashesV2(string filePath)
	{
		return new CodeIntegrityHashesV2(
			PageHashCalculator.GetPageHash("SHA1", filePath),
			PageHashCalculator.GetPageHash("SHA256", filePath),
			GetAuthenticodeHash(filePath, "SHA1"),
			GetAuthenticodeHash(filePath, "SHA256"),
			GetAuthenticodeHash(filePath, "SHA384"),
			GetAuthenticodeHash(filePath, "SHA512"),
			GetAuthenticodeHash(filePath, "SHA3_256"),
			GetAuthenticodeHash(filePath, "SHA3_384"),
			GetAuthenticodeHash(filePath, "SHA3_512")
		);
	}

	private static string? GetAuthenticodeHash(string filePath, string hashAlgorithm)
	{
		// For Authenticode-supported algorithms (SHA1, SHA256)
		if (hashAlgorithm.Equals("SHA1", StringComparison.OrdinalIgnoreCase) ||
			hashAlgorithm.Equals("SHA256", StringComparison.OrdinalIgnoreCase))
		{
			return GetAuthenticodeHashLegacy(filePath, hashAlgorithm);
		}

		// For SHA384, SHA512, and SHA3 variants, use manual authenticode hash calculation
		return GetAuthenticodeHashManual(filePath, hashAlgorithm);
	}

	private static string? GetAuthenticodeHashLegacy(string filePath, string hashAlgorithm)
	{
		// A StringBuilder object to store the hash value as a hexadecimal string
		StringBuilder hashString = new(128);
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

			if (!NativeMethods.CryptCATAdminAcquireContext2(ref contextHandle, nint.Zero, hashAlgorithm, nint.Zero, 0))
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.Rizz.GetString("GetAuthenticodeHashAcquireContextError"),
						hashAlgorithm));
			}

			int hashSize = 0;

			if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle3(
					contextHandle,
					fileStreamHandle,
					ref hashSize,
					nint.Zero,
					CryptcatadminCalchashFlagNonconformantFilesFallbackFlat))
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.Rizz.GetString("GetAuthenticodeHashCalcFileHashError"),
						filePath,
						hashAlgorithm));
			}

			hashValue = Marshal.AllocHGlobal(hashSize);

			if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle3(
					contextHandle,
					fileStreamHandle,
					ref hashSize,
					hashValue,
					CryptcatadminCalchashFlagNonconformantFilesFallbackFlat))
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
				_ = NativeMethods.CryptCATAdminReleaseContext(contextHandle, 0);
			}
		}

		return hashString.ToString();
	}

	private static string? GetAuthenticodeHashManual(string filePath, string hashAlgorithm)
	{
		// Map algorithm names to BCrypt identifiers using the exact Microsoft constant values
		string bcryptAlgorithm = hashAlgorithm.ToUpperInvariant() switch
		{
			"SHA384" => "SHA384",
			"SHA512" => "SHA512",
			"SHA3_256" => "SHA3-256",
			"SHA3_384" => "SHA3-384",
			"SHA3_512" => "SHA3-512",
			_ => throw new ArgumentException($"Unsupported hash algorithm for manual calculation: {hashAlgorithm}", nameof(hashAlgorithm))
		};

		nint algorithmHandle = nint.Zero;
		nint hashObjectHandle = nint.Zero;
		nint hashObject = nint.Zero;
		nint hashBuffer = nint.Zero;

		try
		{
			// Open algorithm provider
			int status = NativeMethods.BCryptOpenAlgorithmProvider(
				out algorithmHandle,
				bcryptAlgorithm,
				null,
				0);

			if (status != 0)
			{
				throw new InvalidOperationException($"Failed to open BCrypt algorithm provider for {hashAlgorithm}. Status: 0x{status:X8}");
			}

			// Get hash object size
			if (!BCryptGetProperty(algorithmHandle, "ObjectLength", out uint hashObjectSize))
			{
				throw new InvalidOperationException("Failed to get hash object size");
			}

			// Get hash length
			if (!BCryptGetProperty(algorithmHandle, "HashDigestLength", out uint hashLength))
			{
				throw new InvalidOperationException("Failed to get hash length");
			}

			// Allocate hash object
			hashObject = Marshal.AllocHGlobal((int)hashObjectSize);

			// Create hash
			status = NativeMethods.BCryptCreateHash(
				algorithmHandle,
				out hashObjectHandle,
				hashObject,
				hashObjectSize,
				nint.Zero,
				0,
				0);

			if (status != 0)
			{
				throw new InvalidOperationException($"Failed to create hash object. Status: 0x{status:X8}");
			}

			// Calculate authenticode hash by parsing PE structure
			using (FileStream fileStream = File.OpenRead(filePath))
			{
				// Read entire file into memory for PE parsing
				byte[] fileData = new byte[fileStream.Length];
				fileStream.ReadExactly(fileData);

				// Parse PE structure to get ranges to hash
				var hashRanges = GetAuthenticodeHashRanges(fileData);

				// Hash each range
				foreach (var (Start, Length) in hashRanges)
				{
					status = NativeMethods.BCryptHashData(
						hashObjectHandle,
						fileData.AsSpan(Start, Length).ToArray(),
						(uint)Length,
						0);

					if (status != 0)
					{
						throw new InvalidOperationException($"Failed to hash data range. Status: 0x{status:X8}");
					}
				}
			}

			// Allocate buffer for hash result
			hashBuffer = Marshal.AllocHGlobal((int)hashLength);

			// Finish hash
			status = NativeMethods.BCryptFinishHash(
				hashObjectHandle,
				hashBuffer,
				hashLength,
				0);

			if (status != 0)
			{
				throw new InvalidOperationException($"Failed to finish hash. Status: 0x{status:X8}");
			}

			// Convert hash to hex string
			StringBuilder hashString = new((int)hashLength * 2);
			for (int i = 0; i < hashLength; i++)
			{
				byte b = Marshal.ReadByte(hashBuffer, i);
				_ = hashString.Append(b.ToString("X2", CultureInfo.InvariantCulture));
			}

			return hashString.ToString();
		}
		finally
		{
			if (hashBuffer != nint.Zero)
			{
				Marshal.FreeHGlobal(hashBuffer);
			}

			if (hashObjectHandle != nint.Zero)
			{
				_ = NativeMethods.BCryptDestroyHash(hashObjectHandle);
			}

			if (hashObject != nint.Zero)
			{
				Marshal.FreeHGlobal(hashObject);
			}

			if (algorithmHandle != nint.Zero)
			{
				_ = NativeMethods.BCryptCloseAlgorithmProvider(algorithmHandle, 0);
			}
		}
	}

	private static List<(int Start, int Length)> GetAuthenticodeHashRanges(byte[] fileData)
	{
		var ranges = new List<(int Start, int Length)>();

		// Validate DOS header
		if (fileData.Length < 64 || fileData[0] != 0x4D || fileData[1] != 0x5A) // "MZ"
		{
			// Not a PE file, hash the entire file
			ranges.Add((0, fileData.Length));
			return ranges;
		}

		// Get PE header offset
		int peOffset = BitConverter.ToInt32(fileData, 60);
		if (peOffset < 0 || peOffset + 248 > fileData.Length)
		{
			// Invalid PE, hash entire file
			ranges.Add((0, fileData.Length));
			return ranges;
		}

		// Validate PE signature
		if (fileData[peOffset] != 0x50 || fileData[peOffset + 1] != 0x45) // "PE"
		{
			// Not a valid PE, hash entire file
			ranges.Add((0, fileData.Length));
			return ranges;
		}

		// Determine if PE32 or PE32+
		ushort magic = BitConverter.ToUInt16(fileData, peOffset + 24);
		bool isPE32Plus = magic == 0x20b;

		// Calculate offsets
		int optionalHeaderOffset = peOffset + 24;
		int checksumOffset = optionalHeaderOffset + 64;
		int dataDirectoriesOffset = optionalHeaderOffset + (isPE32Plus ? 112 : 96);
		int certTableOffset = dataDirectoriesOffset + (8 * 4); // Certificate table is the 5th directory (index 4)

		// Get certificate table info
		uint certTableRva = 0;
		uint certTableSize = 0;
		if (certTableOffset + 8 <= fileData.Length)
		{
			certTableRva = BitConverter.ToUInt32(fileData, certTableOffset);
			certTableSize = BitConverter.ToUInt32(fileData, certTableOffset + 4);
		}

		// Hash from start to checksum field (excluding checksum)
		ranges.Add((0, checksumOffset));

		// Hash from after checksum to certificate table entry (excluding certificate table entry)
		ranges.Add((checksumOffset + 4, certTableOffset - (checksumOffset + 4)));

		// Hash from after certificate table entry to start of certificate data or end of file
		int afterCertTableEntry = certTableOffset + 8;
		int endOffset = fileData.Length;

		if (certTableRva > 0 && certTableSize > 0)
		{
			// Certificate table exists, hash up to it
			endOffset = (int)certTableRva;
		}

		if (afterCertTableEntry < endOffset)
		{
			ranges.Add((afterCertTableEntry, endOffset - afterCertTableEntry));
		}

		return ranges;
	}


	/// <summary>
	/// Helper method for BCryptGetProperty
	/// </summary>
	/// <param name="hObject"></param>
	/// <param name="propertyName"></param>
	/// <param name="value"></param>
	/// <returns></returns>
	private static bool BCryptGetProperty(IntPtr hObject, string propertyName, out uint value)
	{
		value = 0;
		IntPtr buffer = Marshal.AllocHGlobal(sizeof(uint));
		try
		{
			int status = NativeMethods.BCryptGetProperty(hObject, propertyName, buffer, sizeof(uint), out uint resultLength, 0);
			if (status == 0 && resultLength == sizeof(uint))
			{
				value = (uint)Marshal.ReadInt32(buffer);
				return true;
			}
			return false;
		}
		finally
		{
			Marshal.FreeHGlobal(buffer);
		}
	}
}
