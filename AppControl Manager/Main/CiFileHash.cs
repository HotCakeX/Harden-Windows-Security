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

using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using AppControlManager.Others;

namespace AppControlManager.Main;

internal static class CiFileHash
{
	// a constant field that defines a flag value for the native function
	// This causes/helps the GetCiFileHashes method to return the flat file hashes whenever a non-conformant file is encountered
	private const uint CryptcatadminCalchashFlagNonconformantFilesFallbackFlat = 1;

	/// <summary>
	/// Pre-allocated buffer pool for better memory management
	/// </summary>
	private static readonly ArrayPool<byte> BufferPool = ArrayPool<byte>.Shared;

	/// <summary>
	/// Lookup table for hex-nibbles (two chars per byte)
	/// </summary>
	private static readonly char[][] HexChars = Enumerable
		.Range(0, 256)
		.Select(i => i.ToString("X2", CultureInfo.InvariantCulture).ToCharArray())
		.ToArray();

	/// <summary>
	/// Cache for PE hash ranges
	/// </summary>
	private static readonly ConcurrentDictionary<string, (List<(long Start, long Length)> Ranges, long FileSize, DateTime LastWriteTime)> HashRangesCache = new(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// 0=SHA384, 1=SHA512, 2=SHA3-256, 3=SHA3-384, 4=SHA3-512
	/// </summary>
	private static readonly string[] HashAlgorithmsManual = ["SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512"];

	/// <summary>
	/// 32MB
	/// </summary>
	private const int ChunkAndBufferSize = 32 * 1024 * 1024;

	/// <summary>
	/// A method that only outputs the hashes used primarily by the app.
	/// Needs to remain as fast as possible since it's called in tight loops.
	/// </summary>
	/// <param name="filePath"></param>
	/// <returns></returns>
	internal static CodeIntegrityHashes GetCiFileHashes(string filePath)
	{
		return new CodeIntegrityHashes(
			GetPageHash("SHA1", filePath),
			GetPageHash("SHA256", filePath),
			GetAuthenticodeHashLegacy(filePath, "SHA1"),
			GetAuthenticodeHashLegacy(filePath, "SHA256")
		);
	}

	/// <summary>
	/// Method that outputs all kinds of hashes.
	/// </summary>
	/// <param name="filePath">The path to the file that is going to be hashed</param>
	/// <returns>CodeIntegrityHashesV2 object that contains all kinds of hashes.</returns>
	internal static CodeIntegrityHashesV2 GetCiFileHashesV2(string filePath)
	{
		try
		{
			(string?, string?) FlatHashResults = GetFlatHash(filePath);

			// Get all authenticode hashes in one operation for better performance
			string?[] authenticodeHashes = GetAllAuthenticodeHashes(filePath);

			return new CodeIntegrityHashesV2(
				GetPageHash("SHA1", filePath),
				GetPageHash("SHA256", filePath),
				authenticodeHashes[0], // SHA1
				authenticodeHashes[1], // SHA256
				authenticodeHashes[2], // SHA384
				authenticodeHashes[3], // SHA512
				authenticodeHashes[4], // SHA3-256
				authenticodeHashes[5], // SHA3-384
				authenticodeHashes[6], // SHA3-512
				FlatHashResults.Item1,
				FlatHashResults.Item2
			);
		}
		finally
		{
			// Remove the file's hash ranges from cache
			_ = HashRangesCache.TryRemove(filePath, out _);
		}
	}

	private static string?[] GetAllAuthenticodeHashes(string filePath)
	{
		// Array indices: 0=SHA1, 1=SHA256, 2=SHA384, 3=SHA512, 4=SHA3-256, 5=SHA3-384, 6=SHA3-512
		string?[] results = new string?[7];

		// Handle legacy algorithms (SHA1, SHA256) using the existing method
		results[0] = GetAuthenticodeHashLegacy(filePath, "SHA1");
		results[1] = GetAuthenticodeHashLegacy(filePath, "SHA256");

		// Handle all other algorithms using manual calculation with single file read
		string?[] manualResults = GetAllAuthenticodeHashesManual(filePath);

		// Copy manual results to the main results array
		// results indices: 2=SHA384, 3=SHA512, 4=SHA3-256, 5=SHA3-384, 6=SHA3-512
		results[2] = manualResults[0]; // SHA384
		results[3] = manualResults[1]; // SHA512
		results[4] = manualResults[2]; // SHA3-256
		results[5] = manualResults[3]; // SHA3-384
		results[6] = manualResults[4]; // SHA3-512

		return results;
	}

	private static string?[] GetAllAuthenticodeHashesManual(string filePath)
	{
		// Results array with same order as input hashAlgorithms array
		string?[] results = new string?[HashAlgorithmsManual.Length];
		nint[] algorithmHandles = new nint[HashAlgorithmsManual.Length];
		nint[] hashObjectHandles = new nint[HashAlgorithmsManual.Length];
		nint[] hashObjects = new nint[HashAlgorithmsManual.Length];
		nint[] hashBuffers = new nint[HashAlgorithmsManual.Length];
		uint[] hashLengths = new uint[HashAlgorithmsManual.Length];

		try
		{
			// Initialize all hash algorithms
			for (int i = 0; i < HashAlgorithmsManual.Length; i++)
			{
				string hashAlgorithm = HashAlgorithmsManual[i];

				// Open algorithm provider
				int status = NativeMethods.BCryptOpenAlgorithmProvider(
					out nint algorithmHandle,
					hashAlgorithm,
					null,
					0);

				if (status != 0)
				{
					throw new InvalidOperationException($"Failed to open BCrypt algorithm provider for {hashAlgorithm}. Status: 0x{status:X8}");
				}
				algorithmHandles[i] = algorithmHandle;

				// Get hash object size and hash length
				if (!BCryptGetProperty(algorithmHandle, "ObjectLength", out uint hashObjectSize))
				{
					throw new InvalidOperationException($"Failed to get hash object size for {hashAlgorithm}");
				}

				if (!BCryptGetProperty(algorithmHandle, "HashDigestLength", out uint hashLength))
				{
					throw new InvalidOperationException($"Failed to get hash length for {hashAlgorithm}");
				}
				hashLengths[i] = hashLength;

				// Allocate hash object
				nint hashObject = Marshal.AllocHGlobal((int)hashObjectSize);
				hashObjects[i] = hashObject;

				// Create hash
				status = NativeMethods.BCryptCreateHash(
					algorithmHandle,
					out nint hashObjectHandle,
					hashObject,
					hashObjectSize,
					nint.Zero,
					0,
					0);

				if (status != 0)
				{
					throw new InvalidOperationException($"Failed to create hash object for {hashAlgorithm}. Status: 0x{status:X8}");
				}
				hashObjectHandles[i] = hashObjectHandle;

				// Allocate buffer for hash result
				hashBuffers[i] = Marshal.AllocHGlobal((int)hashLength);
			}

			using FileStream fileStream = File.OpenRead(filePath);
			using MemoryMappedFile mmf = MemoryMappedFile.CreateFromFile(fileStream, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, false);
			using MemoryMappedViewAccessor accessor = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);

			// Parse PE structure to get ranges to hash
			var hashRanges = GetAuthenticodeHashRangesFromMemoryMappedCached(filePath, accessor, fileStream.Length);

			// Hash each range for all algorithms with optimized chunking
			foreach ((long Start, long Length) in hashRanges)
			{
				long remaining = Length;
				long currentOffset = Start;

				while (remaining > 0)
				{
					int currentChunkSize = (int)Math.Min(remaining, ChunkAndBufferSize);

					byte[] chunkData = BufferPool.Rent(currentChunkSize);
					try
					{
						// Read chunk from memory-mapped file
						_ = accessor.ReadArray(currentOffset, chunkData, 0, currentChunkSize);

						// Hash this chunk for all algorithms
						for (int i = 0; i < HashAlgorithmsManual.Length; i++)
						{
							int status = NativeMethods.BCryptHashData(
								hashObjectHandles[i],
								chunkData,
								(uint)currentChunkSize,
								0);

							if (status != 0)
							{
								throw new InvalidOperationException($"Failed to hash data range for {HashAlgorithmsManual[i]}. Status: 0x{status:X8}");
							}
						}
					}
					finally
					{
						BufferPool.Return(chunkData);
					}

					currentOffset += currentChunkSize;
					remaining -= currentChunkSize;
				}
			}

			// Finish all hashes and convert to hex strings
			for (int i = 0; i < HashAlgorithmsManual.Length; i++)
			{
				// Finish hash
				int status = NativeMethods.BCryptFinishHash(
					hashObjectHandles[i],
					hashBuffers[i],
					hashLengths[i],
					0);

				if (status != 0)
				{
					throw new InvalidOperationException($"Failed to finish hash for {HashAlgorithmsManual[i]}. Status: 0x{status:X8}");
				}

				// Convert hash to hex string
				results[i] = ConvertHashToHexString(hashBuffers[i], (int)hashLengths[i]);
			}
		}
		finally
		{
			// Clean up all resources
			for (int i = 0; i < HashAlgorithmsManual.Length; i++)
			{
				if (hashBuffers[i] != nint.Zero)
				{
					Marshal.FreeHGlobal(hashBuffers[i]);
				}

				if (hashObjectHandles[i] != nint.Zero)
				{
					_ = NativeMethods.BCryptDestroyHash(hashObjectHandles[i]);
				}

				if (hashObjects[i] != nint.Zero)
				{
					Marshal.FreeHGlobal(hashObjects[i]);
				}

				if (algorithmHandles[i] != nint.Zero)
				{
					_ = NativeMethods.BCryptCloseAlgorithmProvider(algorithmHandles[i], 0);
				}
			}
		}

		return results;
	}

	private static string? GetAuthenticodeHashLegacy(string filePath, string hashAlgorithm)
	{
		nint contextHandle = nint.Zero;
		nint hashValue = nint.Zero;

		try
		{
			using FileStream fileStream = File.OpenRead(filePath);

			// DangerousGetHandle returns the raw file handle
			nint fileStreamHandle = fileStream.SafeFileHandle.DangerousGetHandle();
			if (fileStreamHandle == nint.Zero)
				return null;

			if (!NativeMethods.CryptCATAdminAcquireContext2(
					ref contextHandle,
					nint.Zero,
					hashAlgorithm,
					nint.Zero,
					0))
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("GetAuthenticodeHashAcquireContextError"),
						hashAlgorithm));
			}

			int hashSize = 0;

			// First call to get the required buffer size
			if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle3(
					contextHandle,
					fileStreamHandle,
					ref hashSize,
					nint.Zero,
					CryptcatadminCalchashFlagNonconformantFilesFallbackFlat))
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("GetAuthenticodeHashCalcFileHashError"),
						filePath,
						hashAlgorithm));
			}

			// Allocate the buffer for the actual hash
			hashValue = Marshal.AllocHGlobal(hashSize);

			// Second call to compute the hash
			if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle3(
					contextHandle,
					fileStreamHandle,
					ref hashSize,
					hashValue,
					CryptcatadminCalchashFlagNonconformantFilesFallbackFlat))
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("GetAuthenticodeHashCalcFileHashError"),
						filePath,
						hashAlgorithm));
			}

			// Single-allocation conversion of the hash bytes to hex
			return ConvertHashToHexString(hashValue, hashSize);
		}
		finally
		{
			if (hashValue != nint.Zero)
				Marshal.FreeHGlobal(hashValue);

			if (contextHandle != nint.Zero)
				_ = NativeMethods.CryptCATAdminReleaseContext(contextHandle, 0);
		}
	}

	private static List<(long Start, long Length)> GetAuthenticodeHashRangesFromMemoryMappedCached(string filePath, MemoryMappedViewAccessor accessor, long fileLength)
	{
		// Get file info for cache validation
		FileInfo fileInfo = new(filePath);
		DateTime lastWriteTime = fileInfo.LastWriteTime;

		// Check cache first
		if (HashRangesCache.TryGetValue(filePath, out var cachedData))
		{
			// Validate cache entry (file size and last write time must match)
			if (cachedData.FileSize == fileLength && cachedData.LastWriteTime == lastWriteTime)
			{
				// Return cached ranges
				return cachedData.Ranges;
			}
			else
			{
				// Remove stale cache entry
				_ = HashRangesCache.TryRemove(filePath, out _);
			}
		}

		// Compute ranges since not in cache or cache is stale
		var ranges = GetAuthenticodeHashRangesFromMemoryMapped(accessor, fileLength);

		// Cache the result
		_ = HashRangesCache.TryAdd(filePath, (ranges, fileLength, lastWriteTime));

		return ranges;
	}

	private static List<(long Start, long Length)> GetAuthenticodeHashRangesFromMemoryMapped(MemoryMappedViewAccessor accessor, long fileLength)
	{
		List<(long Start, long Length)> ranges = new(3);

		// Validate DOS header
		if (fileLength < 64 || accessor.ReadByte(0) != 0x4D || accessor.ReadByte(1) != 0x5A) // "MZ"
		{
			// Not a PE file, hash the entire file
			ranges.Add((0, fileLength));
			return ranges;
		}

		// Get PE header offset
		int peOffset = accessor.ReadInt32(60);
		if (peOffset < 0 || peOffset + 248 > fileLength)
		{
			// Invalid PE, hash entire file
			ranges.Add((0, fileLength));
			return ranges;
		}

		// Validate PE signature
		if (accessor.ReadByte(peOffset) != 0x50 || accessor.ReadByte(peOffset + 1) != 0x45) // "PE"
		{
			// Not a valid PE, hash entire file
			ranges.Add((0, fileLength));
			return ranges;
		}

		// Determine if PE32 or PE32+
		ushort magic = accessor.ReadUInt16(peOffset + 24);
		bool isPE32Plus = magic == 0x20b;

		// Calculate offsets
		int optionalHeaderOffset = peOffset + 24;
		int checksumOffset = optionalHeaderOffset + 64;
		int dataDirectoriesOffset = optionalHeaderOffset + (isPE32Plus ? 112 : 96);
		int certTableOffset = dataDirectoriesOffset + (8 * 4); // Certificate table is the 5th directory (index 4)

		// Get certificate table info
		uint certTableRva = 0;
		uint certTableSize = 0;
		if (certTableOffset + 8 <= fileLength)
		{
			certTableRva = accessor.ReadUInt32(certTableOffset);
			certTableSize = accessor.ReadUInt32(certTableOffset + 4);
		}

		// Hash from start to checksum field (excluding checksum)
		ranges.Add((0, checksumOffset));

		// Hash from after checksum to certificate table entry (excluding certificate table entry)
		ranges.Add((checksumOffset + 4, certTableOffset - (checksumOffset + 4)));

		// Hash from after certificate table entry to start of certificate data or end of file
		long afterCertTableEntry = certTableOffset + 8;
		long endOffset = fileLength;

		if (certTableRva > 0 && certTableSize > 0)
		{
			// Certificate table exists, hash up to it
			endOffset = certTableRva;
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

	/// <summary>
	/// Convert an unmanaged hash buffer directly into a hex string.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static string ConvertHashToHexString(nint hashBuffer, int hashLength)
	{
		// Allocate a string of exactly hashLength*2 chars and fill it in-place
		return string.Create(hashLength * 2, (hashBuffer, hashLength), (span, state) =>
		{
			(nint ptr, int len) = state;
			for (int i = 0; i < len; i++)
			{
				byte b = Marshal.ReadByte(ptr, i);
				span[2 * i] = HexChars[b][0];
				span[2 * i + 1] = HexChars[b][1];
			}
		});
	}

	/// <summary>
	/// a method to get the hash of the first page of a file as a hexadecimal string
	/// </summary>
	/// <param name="algName"></param>
	/// <param name="fileName"></param>
	/// <returns></returns>
	private static string? GetPageHash(string algName, string fileName)
	{
		// initialize the buffer pointer to zero
		IntPtr buffer = IntPtr.Zero;
		// initialize the buffer size to zero
		int bufferSize = 0;

		try
		{
			// First call: get required buffer size
			int firstPageHash1 = NativeMethods.ComputeFirstPageHash(
				algName,
				fileName,
				buffer,
				bufferSize);

			if (firstPageHash1 == 0)
				return null;

			// Allocate the buffer
			buffer = Marshal.AllocHGlobal(firstPageHash1);

			// Second call: fill the buffer
			int firstPageHash2 = NativeMethods.ComputeFirstPageHash(
				algName,
				fileName,
				buffer,
				firstPageHash1);

			if (firstPageHash2 == 0)
				return null;

			// Single-allocation hex conversion
			return string.Create(firstPageHash2 * 2, (buffer, firstPageHash2), (span, state) =>
			{
				(nint ptr, int len) = state;
				for (int i = 0; i < len; i++)
				{
					byte b = Marshal.ReadByte(ptr, i);
					span[2 * i] = HexChars[b][0];
					span[2 * i + 1] = HexChars[b][1];
				}
			});
		}
		finally
		{
			if (buffer != IntPtr.Zero)
				Marshal.FreeHGlobal(buffer);
		}
	}

	/// <summary>
	/// Calculates Flat file hashes.
	/// </summary>
	/// <param name="fileName"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	private static (string?, string?) GetFlatHash(string fileName)
	{
		if (GlobalVars.IsOlderThan24H2)
		{
			return (null, null);
		}

		string? SHA3_512Hash = null;
		string? SHA3_384Hash = null;

		// Calculate SHA3-512 hash using native BCrypt functions
		nint sha3_512AlgorithmHandle = nint.Zero;
		nint sha3_512HashObjectHandle = nint.Zero;
		nint sha3_512HashObject = nint.Zero;
		nint sha3_512HashBuffer = nint.Zero;

		// Calculate SHA3-384 hash using native BCrypt functions
		nint sha3_384AlgorithmHandle = nint.Zero;
		nint sha3_384HashObjectHandle = nint.Zero;
		nint sha3_384HashObject = nint.Zero;
		nint sha3_384HashBuffer = nint.Zero;

		try
		{
			// Open algorithm providers for both SHA3-512 and SHA3-384
			int status = NativeMethods.BCryptOpenAlgorithmProvider(
				out sha3_512AlgorithmHandle,
				"SHA3-512",
				null,
				0);

			if (status != 0)
			{
				throw new InvalidOperationException($"Failed to open BCrypt algorithm provider for SHA3-512. Status: 0x{status:X8}");
			}

			status = NativeMethods.BCryptOpenAlgorithmProvider(
				out sha3_384AlgorithmHandle,
				"SHA3-384",
				null,
				0);

			if (status != 0)
			{
				throw new InvalidOperationException($"Failed to open BCrypt algorithm provider for SHA3-384. Status: 0x{status:X8}");
			}

			// Get hash object sizes and hash lengths for SHA3-512
			if (!BCryptGetProperty(sha3_512AlgorithmHandle, "ObjectLength", out uint sha3_512HashObjectSize))
			{
				throw new InvalidOperationException("Failed to get SHA3-512 hash object size");
			}

			if (!BCryptGetProperty(sha3_512AlgorithmHandle, "HashDigestLength", out uint sha3_512HashLength))
			{
				throw new InvalidOperationException("Failed to get SHA3-512 hash length");
			}

			// Get hash object sizes and hash lengths for SHA3-384
			if (!BCryptGetProperty(sha3_384AlgorithmHandle, "ObjectLength", out uint sha3_384HashObjectSize))
			{
				throw new InvalidOperationException("Failed to get SHA3-384 hash object size");
			}

			if (!BCryptGetProperty(sha3_384AlgorithmHandle, "HashDigestLength", out uint sha3_384HashLength))
			{
				throw new InvalidOperationException("Failed to get SHA3-384 hash length");
			}

			// Allocate hash objects
			sha3_512HashObject = Marshal.AllocHGlobal((int)sha3_512HashObjectSize);
			sha3_384HashObject = Marshal.AllocHGlobal((int)sha3_384HashObjectSize);

			// Create hash objects
			status = NativeMethods.BCryptCreateHash(
				sha3_512AlgorithmHandle,
				out sha3_512HashObjectHandle,
				sha3_512HashObject,
				sha3_512HashObjectSize,
				nint.Zero,
				0,
				0);

			if (status != 0)
			{
				throw new InvalidOperationException($"Failed to create SHA3-512 hash object. Status: 0x{status:X8}");
			}

			status = NativeMethods.BCryptCreateHash(
				sha3_384AlgorithmHandle,
				out sha3_384HashObjectHandle,
				sha3_384HashObject,
				sha3_384HashObjectSize,
				nint.Zero,
				0,
				0);

			if (status != 0)
			{
				throw new InvalidOperationException($"Failed to create SHA3-384 hash object. Status: 0x{status:X8}");
			}

			// Read file in chunks and update both hash algorithms
			using (FileStream fs = new(fileName, FileMode.Open, FileAccess.Read))
			{
				byte[] buffer = BufferPool.Rent(ChunkAndBufferSize);

				try
				{
					int bytesRead;

					// Read the file in chunks and update both hash algorithms with the chunk data
					while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
					{
						// Update SHA3-512 hash with the current chunk
						status = NativeMethods.BCryptHashData(
							sha3_512HashObjectHandle,
							buffer,
							(uint)bytesRead,
							0);

						if (status != 0)
						{
							throw new InvalidOperationException($"Failed to hash SHA3-512 data. Status: 0x{status:X8}");
						}

						// Update SHA3-384 hash with the current chunk
						status = NativeMethods.BCryptHashData(
							sha3_384HashObjectHandle,
							buffer,
							(uint)bytesRead,
							0);

						if (status != 0)
						{
							throw new InvalidOperationException($"Failed to hash SHA3-384 data. Status: 0x{status:X8}");
						}
					}
				}
				finally
				{
					BufferPool.Return(buffer);
				}
			}

			// Allocate buffers for hash results
			sha3_512HashBuffer = Marshal.AllocHGlobal((int)sha3_512HashLength);
			sha3_384HashBuffer = Marshal.AllocHGlobal((int)sha3_384HashLength);

			// Finish SHA3-512 hash
			status = NativeMethods.BCryptFinishHash(
				sha3_512HashObjectHandle,
				sha3_512HashBuffer,
				sha3_512HashLength,
				0);

			if (status != 0)
			{
				throw new InvalidOperationException($"Failed to finish SHA3-512 hash. Status: 0x{status:X8}");
			}

			// Finish SHA3-384 hash
			status = NativeMethods.BCryptFinishHash(
				sha3_384HashObjectHandle,
				sha3_384HashBuffer,
				sha3_384HashLength,
				0);

			if (status != 0)
			{
				throw new InvalidOperationException($"Failed to finish SHA3-384 hash. Status: 0x{status:X8}");
			}

			// Convert hashes to hex strings
			SHA3_512Hash = ConvertHashToHexString(sha3_512HashBuffer, (int)sha3_512HashLength);
			SHA3_384Hash = ConvertHashToHexString(sha3_384HashBuffer, (int)sha3_384HashLength);
		}
		finally
		{
			// Clean up SHA3-512 resources
			if (sha3_512HashBuffer != nint.Zero)
			{
				Marshal.FreeHGlobal(sha3_512HashBuffer);
			}

			if (sha3_512HashObjectHandle != nint.Zero)
			{
				_ = NativeMethods.BCryptDestroyHash(sha3_512HashObjectHandle);
			}

			if (sha3_512HashObject != nint.Zero)
			{
				Marshal.FreeHGlobal(sha3_512HashObject);
			}

			if (sha3_512AlgorithmHandle != nint.Zero)
			{
				_ = NativeMethods.BCryptCloseAlgorithmProvider(sha3_512AlgorithmHandle, 0);
			}

			// Clean up SHA3-384 resources
			if (sha3_384HashBuffer != nint.Zero)
			{
				Marshal.FreeHGlobal(sha3_384HashBuffer);
			}

			if (sha3_384HashObjectHandle != nint.Zero)
			{
				_ = NativeMethods.BCryptDestroyHash(sha3_384HashObjectHandle);
			}

			if (sha3_384HashObject != nint.Zero)
			{
				Marshal.FreeHGlobal(sha3_384HashObject);
			}

			if (sha3_384AlgorithmHandle != nint.Zero)
			{
				_ = NativeMethods.BCryptCloseAlgorithmProvider(sha3_384AlgorithmHandle, 0);
			}
		}

		return (SHA3_384Hash, SHA3_512Hash);
	}
}
