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

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using CommonCore.IncrementalCollection;
using Windows.Graphics.Imaging;
using Windows.Storage;
using Windows.Storage.Streams;

namespace CommonCore;

internal enum OriginalSelectionStrategy
{
	BiggestFileSize,
	SmallestFileSize,
	BiggestResolution,
	SmallestResolution
}

internal sealed class DuplicateScanResult
{
	internal int TotalProcessed { get; set; }
	internal int DuplicateCount { get; set; }
	internal List<DuplicateGroup> Groups { get; set; } = [];
}

internal sealed class DuplicateGroup(DuplicateFile original, RangedObservableCollection<DuplicateFile> duplicates)
{
	// The file chosen as the "original"
	internal DuplicateFile Original => original;

	// All other files that match the original
	// Using RangedObservableCollection so the UI updates automatically when items are removed
	// and supports efficient bulk adding.
	internal RangedObservableCollection<DuplicateFile> Duplicates => duplicates;
}

internal sealed class DuplicateFile(string filePath, string fileName, ulong fileSizeBytes, uint imageWidth, uint imageHeight)
{
	internal string FilePath => filePath;
	internal string FileName => fileName;
	internal ulong FileSizeBytes => fileSizeBytes;
	internal uint ImageWidth => imageWidth;
	internal uint ImageHeight => imageHeight;
	internal string ResolutionText => $"{ImageWidth} x {ImageHeight}";
	internal string FileSizeText => $"{FileSizeBytes / 1024.0:F2} KB";
}

internal static class RedundantAssetDetection
{
	// Using dHash (Difference Hash).
	// We need an extra column (Width + 1) to compare pixel[x] with pixel[x+1].
	// Target hash size is still 64x64 bits = 4096 bits.
	private const int HashWidth = 64;
	private const int HashHeight = 64;
	private const int ResizeWidth = HashWidth + 1; // 65
	private const int ResizeHeight = HashHeight;   // 64

	private const int TotalPixelsForHash = HashWidth * HashHeight; // 4096
	private const int TotalPixelsForResize = ResizeWidth * ResizeHeight; // 4160

	// 4096 bits / 64 bits-per-ulong = 64 ulongs
	private const int HashSizeInUlongs = TotalPixelsForHash / 64;

	private static readonly string[] Extensions = [".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".ico", ".jxr", ".webp"];

	private static readonly BitmapTransform Transform = new()
	{
		ScaledHeight = ResizeHeight,
		ScaledWidth = ResizeWidth,
		InterpolationMode = BitmapInterpolationMode.Fant
	};

	// Inline array of exactly 64 ulongs
	[InlineArray(HashSizeInUlongs)]
	private struct UlongHash64
	{
		private ulong _element0;
	}

	// Internal container to hold hash + metadata during processing
	private struct ProcessedImage(ulong size, uint width, uint height)
	{
		internal UlongHash64 Hash;
		internal readonly ulong FileSizeBytes => size;
		internal readonly uint Width => width;
		internal readonly uint Height => height;
	}

	/// <summary>
	/// Finds duplicate images in the specified directories and files.
	/// </summary>
	internal static async Task<DuplicateScanResult> Find(
		List<string>? filesToSearch,
		List<string>? directoriesToSearch,
		IProgress<double> progress,
		OriginalSelectionStrategy selectionStrategy,
		double similarityThreshold = 90)
	{
		Stopwatch sw = Stopwatch.StartNew();

		// 1. Collect Files
		(IEnumerable<string> filePaths, int fileCount) = FileUtility.GetFilesFast(
			directoriesToSearch,
			filesToSearch,
			Extensions,
			null);

		if (fileCount == 0)
		{
			return new DuplicateScanResult();
		}

		Logger.Write($"Found {fileCount} images. Processing...");

		// 2. Generate Hashes and Collect Metadata
		ConcurrentDictionary<string, ProcessedImage> fileData = new(concurrencyLevel: Environment.ProcessorCount, capacity: fileCount, comparer: StringComparer.OrdinalIgnoreCase);
		int processedCount = 0;

		await Parallel.ForEachAsync(filePaths, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, async (filePath, ct) =>
		{
			try
			{
				StorageFile file = await StorageFile.GetFileFromPathAsync(filePath);
				using IRandomAccessStream stream = await file.OpenAsync(FileAccessMode.Read);

				BitmapDecoder decoder = await BitmapDecoder.CreateAsync(stream);

				// Get pixel data in BGRA8 format for Hashing
				// We resize to 65x64 (Width+1 x Height)
				PixelDataProvider pixelData = await decoder.GetPixelDataAsync(
					BitmapPixelFormat.Bgra8,
					BitmapAlphaMode.Premultiplied,
					Transform,
					ExifOrientationMode.IgnoreExifOrientation,
					ColorManagementMode.DoNotColorManage
				);

				byte[] pixels = pixelData.DetachPixelData();

				// Get the actual on-disk file size in bytes
				ulong onDiskFileSize = (ulong)new FileInfo(filePath).Length;

				ProcessedImage processed = new(onDiskFileSize, decoder.PixelWidth, decoder.PixelHeight);

				// Stack allocate the luma values to avoid heap allocation
				Span<byte> lumaValues = stackalloc byte[TotalPixelsForResize];

				unsafe
				{
					fixed (byte* ptr = pixels)
					{
						byte* currentPixel = ptr;

						// Convert BGRA to Luma (Grayscale)
						for (int i = 0; i < TotalPixelsForResize; i++)
						{
							// BGRA8 layout
							byte blue = *currentPixel;
							byte green = *(currentPixel + 1);
							byte red = *(currentPixel + 2);

							// Move pointer
							currentPixel += 4;

							// Integer math for luma (Rec. 601)
							// (R * 299 + G * 587 + B * 114) / 1000 approx
							// Using bit shifts: (R * 306 + G * 601 + B * 117) >> 10
							int luma = (red * 306 + green * 601 + blue * 117) >> 10;

							lumaValues[i] = (byte)luma;
						}
					}
				}

				// dHash Calculation:
				// Iterate through rows. For each row, compare pixel[x] with pixel[x+1].
				// If left pixel is brighter than right pixel, bit is 1. Else 0.
				int bitIndex = 0;

				for (int y = 0; y < ResizeHeight; y++)
				{
					int rowStart = y * ResizeWidth;

					for (int x = 0; x < HashWidth; x++) // Iterate up to 64, accessing x and x+1
					{
						byte leftPixel = lumaValues[rowStart + x];
						byte rightPixel = lumaValues[rowStart + x + 1];

						if (leftPixel > rightPixel)
						{
							int ulongIndex = bitIndex >> 6;      // bitIndex / 64
							int bitPosition = bitIndex & 0x3F;   // bitIndex % 64
							processed.Hash[ulongIndex] |= 1UL << bitPosition;
						}

						bitIndex++;
					}
				}

				_ = fileData.TryAdd(filePath, processed);
			}
			catch { }

			int current = Interlocked.Increment(ref processedCount);

			// Report progress for hashing phase
			progress.Report((double)current / fileCount * 100.0);
		});

		// 3. Compare Hashes
		// Max Difference allowed.
		// Total bits = 4096.
		int maxDifference = (int)((1.0 - (similarityThreshold / 100.0)) * TotalPixelsForHash);

		// Converting dictionary keys to list to access by index
		List<string> keys = fileData.Keys.ToList();
		int keysCount = keys.Count;

		// Union-Find (Disjoint Set) to group transitive duplicates
		int[] parent = new int[keysCount];
		for (int i = 0; i < keysCount; i++) parent[i] = i;

		int FindSet(int i)
		{
			// First pass: find the root iteratively
			int root = i;
			while (parent[root] != root)
			{
				root = parent[root];
			}

			// Second pass: path compression - point every node on the path directly to the root
			while (parent[i] != root)
			{
				int next = parent[i];
				parent[i] = root;
				i = next;
			}

			return root;
		}

		void UnionSets(int i, int j)
		{
			int rootI = FindSet(i);
			int rootJ = FindSet(j);
			if (rootI != rootJ)
			{
				parent[rootI] = rootJ;
			}
		}

		// Parallelizing the outer loop for comparison
		Lock unionLock = new();

		_ = Parallel.For(0, keysCount, i =>
		{
			string fileA = keys[i];
			if (!fileData.TryGetValue(fileA, out ProcessedImage dataA)) return;

			for (int j = i + 1; j < keysCount; j++)
			{
				string fileB = keys[j];
				if (!fileData.TryGetValue(fileB, out ProcessedImage dataB)) continue;

				int distance = 0;

				// Compare hash values using inline array indexer
				for (int k = 0; k < HashSizeInUlongs; k++)
				{
					distance += BitOperations.PopCount(dataA.Hash[k] ^ dataB.Hash[k]);
					if (distance > maxDifference) break;
				}

				if (distance <= maxDifference)
				{
					lock (unionLock)
					{
						UnionSets(i, j);
					}
				}
			}
		});

		// 4. Construct Result Groups
		Dictionary<int, List<string>> groups = [];

		for (int i = 0; i < keysCount; i++)
		{
			int root = FindSet(i);
			if (!groups.TryGetValue(root, out List<string>? groupList))
			{
				groupList = [];
				groups[root] = groupList;
			}
			groupList.Add(keys[i]);
		}

		DuplicateScanResult result = new()
		{
			TotalProcessed = keysCount
		};

		static ulong ComputeArea(DuplicateFile file) => (ulong)file.ImageWidth * file.ImageHeight;

		// Helper comparison method to use for tie-breaking:
		// Returns < 0 if 'a' should be preferred (come first).
		// Returns > 0 if 'b' should be preferred.
		// Returns 0 if no preference.
		static int CompareExtensions(DuplicateFile a, DuplicateFile b)
		{
			bool aIsPng = a.FilePath.EndsWith(".png", StringComparison.OrdinalIgnoreCase);
			bool bIsPng = b.FilePath.EndsWith(".png", StringComparison.OrdinalIgnoreCase);
			bool aIsJpg = a.FilePath.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) || a.FilePath.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase);
			bool bIsJpg = b.FilePath.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) || b.FilePath.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase);

			// Preference Rule: PNG > JPG/JPEG.
			// Only apply if strictly comparing PNG vs JPG/JPEG.

			// Case 1: A is PNG, B is JPG/JPEG -> Prefer A (A comes first, so return -1)
			if (aIsPng && bIsJpg) return -1;

			// Case 2: B is PNG, A is JPG/JPEG -> Prefer B (B comes first, so return 1)
			if (bIsPng && aIsJpg) return 1;

			// All other cases (PNG vs PNG, JPG vs JPG, PNG vs WebP, GIF vs JPG, etc.) -> Equal
			return 0;
		}

		foreach (KeyValuePair<int, List<string>> group in groups)
		{
			if (group.Value.Count > 1)
			{
				// Convert paths to DuplicateFile objects first
				List<DuplicateFile> allFiles = new(group.Value.Count);
				foreach (string path in CollectionsMarshal.AsSpan(group.Value))
				{
					if (fileData.TryGetValue(path, out ProcessedImage metadata))
					{
						allFiles.Add(new DuplicateFile
						(
							filePath: path,
							fileName: Path.GetFileName(path),
							fileSizeBytes: metadata.FileSizeBytes,
							imageWidth: metadata.Width,
							imageHeight: metadata.Height
						));
					}
				}

				// Sort based on strategy
				// The first element after sorting will be the "Original" (the one we keep)
				switch (selectionStrategy)
				{
					case OriginalSelectionStrategy.BiggestFileSize:
						// Descending size, tie-break: biggest resolution, then extension
						allFiles.Sort((a, b) =>
						{
							int cmp = b.FileSizeBytes.CompareTo(a.FileSizeBytes); // Descending Size
							if (cmp != 0) return cmp;

							cmp = ComputeArea(b).CompareTo(ComputeArea(a)); // Descending Resolution
							if (cmp != 0) return cmp;

							return CompareExtensions(a, b);
						});
						break;
					case OriginalSelectionStrategy.SmallestFileSize:
						// Ascending size, tie-break: biggest resolution, then extension
						allFiles.Sort((a, b) =>
						{
							int cmp = a.FileSizeBytes.CompareTo(b.FileSizeBytes); // Ascending Size
							if (cmp != 0) return cmp;

							cmp = ComputeArea(b).CompareTo(ComputeArea(a)); // Descending Resolution
							if (cmp != 0) return cmp;

							return CompareExtensions(a, b);
						});
						break;
					case OriginalSelectionStrategy.BiggestResolution:
						// Descending pixel count, tie-break: biggest file size, then extension
						allFiles.Sort((a, b) =>
						{
							int cmp = ComputeArea(b).CompareTo(ComputeArea(a)); // Descending Resolution
							if (cmp != 0) return cmp;

							cmp = b.FileSizeBytes.CompareTo(a.FileSizeBytes); // Descending Size
							if (cmp != 0) return cmp;

							return CompareExtensions(a, b);
						});
						break;
					case OriginalSelectionStrategy.SmallestResolution:
						// Ascending pixel count, tie-break: biggest file size, then extension
						allFiles.Sort((a, b) =>
						{
							int cmp = ComputeArea(a).CompareTo(ComputeArea(b)); // Ascending Resolution
							if (cmp != 0) return cmp;

							cmp = b.FileSizeBytes.CompareTo(a.FileSizeBytes); // Descending Size
							if (cmp != 0) return cmp;

							return CompareExtensions(a, b);
						});
						break;
					default:
						break;
				}

				// Remaining files are duplicates
				List<DuplicateFile> duplicatesList = allFiles.GetRange(1, allFiles.Count - 1);

				// Initialize the RangedObservableCollection with the list
				RangedObservableCollection<DuplicateFile> duplicatesCollection = new(duplicatesList);

				result.Groups.Add(new DuplicateGroup
				(
					original: allFiles[0],
					duplicates: duplicatesCollection
				));

				result.DuplicateCount += duplicatesCollection.Count;
			}
		}

		sw.Stop();
		Logger.Write($"Scan complete in {sw.Elapsed.TotalSeconds:F2} seconds. Total files: {result.TotalProcessed}. Duplicates found: {result.DuplicateCount}.");

		return result;
	}
}
