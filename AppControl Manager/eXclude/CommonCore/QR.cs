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

using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.Graphics.Capture;
using Windows.Graphics.DirectX;
using Windows.Graphics.DirectX.Direct3D11;
using Windows.Graphics.Imaging;
using Windows.Storage;
using Windows.Storage.Streams;

namespace CommonCore;

/// <summary>
/// Compliant with ISO/IEC 2394:2022 and ISO/IEC 18004:2024 which are the latest versions at the time of developing this code.
/// </summary>
internal static partial class QR
{
	internal static partial class Manage
	{
		internal static async Task<List<QrResult>> DecodeAsync(IEnumerable<string> imagePaths)
		{
			return await Task.Run(async () =>
			{
				List<QrResult> fileResults = imagePaths.TryGetNonEnumeratedCount(out int count)
					? new List<QrResult>(count)
					: [];

				foreach (string path in imagePaths)
				{
					long startTimestamp = Stopwatch.GetTimestamp();
					QrResult? result = null;
					Exception? error = null;

					try
					{
						GrayImage image;
						try
						{
							image = await WinRtImageLoader.LoadAsync(path);
						}
						catch (Exception exception)
						{
							throw new QrException($"Failed to load image '{path}'.", exception);
						}

						try
						{
							result = QrDecoder.Decode(image);
						}
						catch (Exception exception)
						{
							throw new QrException($"Failed to decode QR image '{path}'.{Environment.NewLine}{exception.Message}", exception);
						}
					}
					catch (Exception exception)
					{
						error = exception;
					}

					TimeSpan elapsed = Stopwatch.GetElapsedTime(startTimestamp);
					fileResults.Add(result is null
						? new(path, null, null, null, null, elapsed, error)
						: new(path, result.Text, result.Version, result.ErrorCorrectionLevel, result.Mask, elapsed, error));
				}

				return fileResults;
			});
		}

		internal sealed partial class GeneratedQr(bool[] modules, int moduleCount, int version, int utf8ByteCount, char errorCorrectionLevel, int mask, int maximumPayloadBytes) : IDisposable
		{
			private SoftwareBitmap? ownedBitmap = QrEncoder.Render(modules, moduleCount);
			internal SoftwareBitmap Bitmap => ownedBitmap ?? throw new ObjectDisposedException(nameof(GeneratedQr));
			internal int Version => version;
			internal int ModuleCount => moduleCount;
			internal int Utf8ByteCount => utf8ByteCount;
			internal char ErrorCorrectionLevel => errorCorrectionLevel;
			internal int Mask => mask;
			internal int MaximumPayloadBytes => maximumPayloadBytes;
			internal SoftwareBitmap TakeBitmap()
			{
				SoftwareBitmap result = Bitmap;
				ownedBitmap = null;
				return result;
			}
			public void Dispose()
			{
				ownedBitmap?.Dispose();
				ownedBitmap = null;
			}
		}

		internal static GeneratedQr GenerateWithStatistics(string text, char errorCorrectionLevel) => QrEncoder.Generate(text, errorCorrectionLevel);

		/// <summary>
		/// Generates a PNG-encoded QR image.
		/// </summary>
		internal static async Task<byte[]> GeneratePngAsync(string text, char errorCorrectionLevel)
		{
			using GeneratedQr generatedQr = GenerateWithStatistics(text, errorCorrectionLevel);
			using SoftwareBitmap bitmap = generatedQr.TakeBitmap();
			using InMemoryRandomAccessStream stream = new();
			BitmapEncoder encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
			encoder.SetSoftwareBitmap(bitmap);
			await encoder.FlushAsync();
			stream.Seek(0);
			using Stream input = stream.AsStreamForRead();
			using MemoryStream output = stream.Size <= int.MaxValue ? new MemoryStream((int)stream.Size) : new MemoryStream();
			await input.CopyToAsync(output);
			return output.ToArray();
		}

		/// <summary>
		/// Decodes a QR code from encoded image bytes without exposing decoder implementation details.
		/// </summary>
		internal static async Task<QrResult> DecodeAsync(byte[] encodedImage, string sourceName = "In-memory encoded image")
		{
			using InMemoryRandomAccessStream stream = new();
			_ = await stream.WriteAsync(encodedImage.AsBuffer());
			stream.Seek(0);
			BitmapDecoder decoder = await BitmapDecoder.CreateAsync(stream);
			using SoftwareBitmap bitmap = await decoder.GetSoftwareBitmapAsync(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied);
			return await DecodeAsync(bitmap, sourceName);
		}

		/// <summary>
		/// Decodes a QR code directly from an uncompressed in-memory bitmap.
		/// </summary>
		internal static async Task<QrResult> DecodeAsync(SoftwareBitmap softwareBitmap, string sourceName = "In-memory image")
		{
			long started = Stopwatch.GetTimestamp();
			GrayImage image = await Task.Run(() => WinRtImageLoader.Load(softwareBitmap));
			QrResult result = await Task.Run(() => QrDecoder.Decode(image));
			return new(sourceName, result.Text, result.Version, result.ErrorCorrectionLevel, result.Mask, Stopwatch.GetElapsedTime(started), null);
		}

		internal sealed partial class CameraQrCandidate(BooleanMatrix matrix, QrResult result) : IDisposable
		{
			private SoftwareBitmap? ownedBitmap = RenderCameraQrCandidate(matrix);
			internal SoftwareBitmap Bitmap => ownedBitmap ?? throw new ObjectDisposedException(nameof(CameraQrCandidate));
			internal QrResult Result => result;
			public void Dispose()
			{
				ownedBitmap?.Dispose();
				ownedBitmap = null;
			}
		}

		/// <summary>
		/// Performs only QR finder detection, perspective grid sampling, and format validation for a camera frame.
		/// A canonical QR bitmap is returned only after finder detection, perspective sampling, format validation,
		/// Reed-Solomon correction, and payload decoding have all succeeded.
		/// </summary>
		internal static async Task<CameraQrCandidate?> TryExtractCameraQrAsync(SoftwareBitmap softwareBitmap)
		{
			return await Task.Run(() =>
			{
				GrayImage image = WinRtImageLoader.Load(softwareBitmap);
				BooleanMatrix adaptive = Binarizer.Binarize(image);
				CameraQrCandidate? candidate = TryExtractCameraQr(adaptive);
				if (candidate is not null)
				{
					return candidate;
				}
				GrayImage invertedImage = ImagePreprocessor.InvertLuminance(image);
				candidate = TryExtractCameraQr(Binarizer.Binarize(invertedImage));
				if (candidate is not null)
				{
					return candidate;
				}

				candidate = TryExtractCameraQr(MatrixTransforms.Invert(adaptive, image.Padding));
				if (candidate is not null)
				{
					return candidate;
				}
				ReadOnlySpan<byte> cameraThresholds = [96, 128, 160, 192, 224];
				foreach (byte threshold in cameraThresholds)
				{
					BooleanMatrix binary = ImagePreprocessor.Threshold(image, threshold);
					candidate = TryExtractCameraQr(binary);
					if (candidate is not null)
					{
						return candidate;
					}
				}
				return null;
			});
		}

		private static CameraQrCandidate? TryExtractCameraQr(BooleanMatrix binary)
		{
			foreach ((Finder topLeft, Finder topRight, Finder bottomLeft) in FinderDetector.FindTriples(binary))
			{
				BooleanMatrix[] sampledMatrices;
				try
				{
					sampledMatrices = GridSampler.SampleCandidates(binary, topLeft, topRight, bottomLeft);
				}
				catch (Exception exception) when (exception is QrException or ArithmeticException)
				{
					continue;
				}
				foreach (BooleanMatrix sampledMatrix in sampledMatrices)
				{
					foreach (BooleanMatrix orientedMatrix in MatrixTransforms.Orientations(sampledMatrix))
					{
						if (!MatrixParser.HasValidFormatInformation(orientedMatrix))
						{
							continue;
						}
						try
						{
							QrResult result = MatrixParser.Decode(orientedMatrix);
							if (result.Text is { Length: > 0 })
							{
								return new CameraQrCandidate(orientedMatrix, result);
							}
						}
						catch (Exception exception) when (exception is QrException or ArithmeticException)
						{
						}
					}
				}
			}
			return null;
		}

		private static SoftwareBitmap RenderCameraQrCandidate(BooleanMatrix matrix)
		{
			const int pixelsPerModule = 8;
			const int quietZoneModules = 4;
			int outputDimension = (matrix.Width + quietZoneModules * 2) * pixelsPerModule;
			byte[] pixels = GC.AllocateUninitializedArray<byte>(checked(outputDimension * outputDimension * 4));
			Array.Fill(pixels, byte.MaxValue);
			int offset = quietZoneModules * pixelsPerModule;
			for (int moduleY = 0; moduleY < matrix.Height; moduleY++)
			{
				for (int moduleX = 0; moduleX < matrix.Width; moduleX++)
				{
					if (!matrix[moduleX, moduleY])
					{
						continue;
					}
					int firstX = offset + moduleX * pixelsPerModule;
					int firstY = offset + moduleY * pixelsPerModule;
					for (int pixelY = 0; pixelY < pixelsPerModule; pixelY++)
					{
						int row = ((firstY + pixelY) * outputDimension + firstX) * 4;
						Array.Clear(pixels, row, pixelsPerModule * 4);
						for (int pixelX = 0; pixelX < pixelsPerModule; pixelX++)
						{
							pixels[row + pixelX * 4 + 3] = byte.MaxValue;
						}
					}
				}
			}
			return SoftwareBitmap.CreateCopyFromBuffer(pixels.AsBuffer(), BitmapPixelFormat.Bgra8, outputDimension, outputDimension, BitmapAlphaMode.Premultiplied);
		}

		// https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture
		internal static async Task<SoftwareBitmap> CaptureSingleFrameAsync(GraphicsCaptureItem captureItem)
		{
			using IDirect3DDevice device = CreateDirect3DDevice();
			using Direct3D11CaptureFramePool pool = Direct3D11CaptureFramePool.CreateFreeThreaded(device, DirectXPixelFormat.B8G8R8A8UIntNormalized, 1, captureItem.Size);
			using GraphicsCaptureSession session = pool.CreateCaptureSession(captureItem);
			TaskCompletionSource<SoftwareBitmap> source = new(TaskCreationOptions.RunContinuationsAsynchronously);
			async void handler(Direct3D11CaptureFramePool sender, object args)
			{
				if (source.Task.IsCompleted) return;
				try
				{
					using Direct3D11CaptureFrame frame = sender.TryGetNextFrame();
					SoftwareBitmap bitmap = await SoftwareBitmap.CreateCopyFromSurfaceAsync(frame.Surface, BitmapAlphaMode.Premultiplied);
					if (!source.TrySetResult(bitmap))
					{
						bitmap.Dispose();
					}
				}
				catch (Exception exception)
				{
					_ = source.TrySetException(exception);
				}
			}

			pool.FrameArrived += handler;
			try
			{
				session.StartCapture();
				return await source.Task.WaitAsync(TimeSpan.FromSeconds(10D));
			}
			finally
			{
				pool.FrameArrived -= handler;
			}
		}

		private static readonly Guid IdxgiDeviceGuid = new("54EC77FA-1377-44E6-8C32-88FD5F44C84C");

		/// <summary>
		/// Creates the Direct3D device required by Windows.Graphics.Capture without adding Win2D.
		/// </summary>
		private static IDirect3DDevice CreateDirect3DDevice()
		{
			const int D3DDriverTypeHardware = 1;
			const uint D3D11CreateDeviceBgraSupport = 0x20U;
			const uint D3D11SdkVersion = 7U;
			nint d3dDevice = 0;
			nint immediateContext = 0;
			nint dxgiDevice = 0;
			nint inspectableDevice = 0;
			try
			{
				int result = NativeMethods.D3D11CreateDevice(
					0,
					D3DDriverTypeHardware,
					0,
					D3D11CreateDeviceBgraSupport,
					0,
					0,
					D3D11SdkVersion,
					out d3dDevice,
					0,
					out immediateContext);
				Marshal.ThrowExceptionForHR(result);
				result = Marshal.QueryInterface(d3dDevice, in IdxgiDeviceGuid, out dxgiDevice);
				Marshal.ThrowExceptionForHR(result);
				result = NativeMethods.CreateDirect3D11DeviceFromDXGIDevice(dxgiDevice, out inspectableDevice);
				Marshal.ThrowExceptionForHR(result);
				return WinRT.MarshalInterface<IDirect3DDevice>.FromAbi(inspectableDevice);
			}
			finally
			{
				ReleaseComPointer(inspectableDevice);
				ReleaseComPointer(dxgiDevice);
				ReleaseComPointer(immediateContext);
				ReleaseComPointer(d3dDevice);
			}
		}

		private static void ReleaseComPointer(nint unknown)
		{
			if (unknown != 0)
				_ = Marshal.Release(unknown);
		}

	}

	internal sealed class QrResult(string filePath, string? text, int? version, char? errorCorrectionLevel, int? mask, TimeSpan elapsed, Exception? error)
	{
		internal string FilePath => filePath;
		internal string? Text => text;
		internal int? Version => version;
		internal char? ErrorCorrectionLevel => errorCorrectionLevel;
		internal int? Mask => mask;
		internal TimeSpan Elapsed => elapsed;
		internal Exception? Error => error;
	}

	private static class WinRtImageLoader
	{
		internal static GrayImage Load(SoftwareBitmap softwareBitmap)
		{
			using SoftwareBitmap converted = SoftwareBitmap.Convert(softwareBitmap, BitmapPixelFormat.Rgba8, BitmapAlphaMode.Straight);
			int width = converted.PixelWidth;
			int height = converted.PixelHeight;
			byte[] pixels = new byte[checked(width * height * 4)];
			converted.CopyToBuffer(pixels.AsBuffer());
			return CreateGrayImage(pixels, width, height);
		}

		internal static async Task<GrayImage> LoadAsync(string path)
		{
			StorageFile file = await StorageFile.GetFileFromPathAsync(path);
			using IRandomAccessStream stream = await file.OpenAsync(FileAccessMode.Read);
			BitmapDecoder decoder = await BitmapDecoder.CreateAsync(stream);
			PixelDataProvider provider = await decoder.GetPixelDataAsync(
				BitmapPixelFormat.Rgba8,
				BitmapAlphaMode.Straight,
				new BitmapTransform(),
				ExifOrientationMode.RespectExifOrientation,
				ColorManagementMode.ColorManageToSRgb);
			byte[] pixels = provider.DetachPixelData();
			int sourceWidth = (int)decoder.OrientedPixelWidth;
			int sourceHeight = (int)decoder.OrientedPixelHeight;
			return CreateGrayImage(pixels, sourceWidth, sourceHeight);
		}

		private static GrayImage CreateGrayImage(byte[] pixels, int sourceWidth, int sourceHeight)
		{
			int padding = Math.Clamp(Math.Min(sourceWidth, sourceHeight) / 8, 16, 128);
			int width = sourceWidth + padding * 2;
			int height = sourceHeight + padding * 2;
			byte[] luminance = GC.AllocateUninitializedArray<byte>(width * height);
			byte[] colorDistance = GC.AllocateUninitializedArray<byte>(luminance.Length);
			Array.Fill(luminance, byte.MaxValue);
			Array.Fill(colorDistance, byte.MaxValue);
			for (int y = 0; y < sourceHeight; y++)
			{
				int sourceRow = y * sourceWidth * 4;
				int destinationRow = (y + padding) * width + padding;
				for (int x = 0; x < sourceWidth; x++)
				{
					int source = sourceRow + x * 4;
					int alpha = pixels[source + 3];
					int red = pixels[source];
					int green = pixels[source + 1];
					int blue = pixels[source + 2];
					int foregroundLuminance = (red * 77 + green * 150 + blue * 29 + 128) >> 8;
					luminance[destinationRow + x] = (byte)((foregroundLuminance * alpha + 255 * (255 - alpha) + 127) / 255);
					int foregroundColorDistance = Math.Min(red, Math.Min(green, blue));
					colorDistance[destinationRow + x] = (byte)((foregroundColorDistance * alpha + 255 * (255 - alpha) + 127) / 255);
				}
			}
			return new GrayImage(width, height, padding, luminance, colorDistance);
		}
	}

	private sealed class GrayImage(int width, int height, int padding, ReadOnlyMemory<byte> pixels, ReadOnlyMemory<byte> colorDistance)
	{
		internal int Width => width;
		internal int Height => height;
		internal int Padding => padding;
		internal ReadOnlySpan<byte> Pixels => pixels.Span;
		internal ReadOnlySpan<byte> ColorDistance => colorDistance.Span;
	}

	private readonly record struct PointD(double X, double Y);

	private readonly record struct Finder(double X, double Y, double Module, int Count);

	private readonly record struct ThresholdProbe(BooleanMatrix Matrix, int ThresholdIndex, bool Inverted, int TripleIndex, int MatrixIndex);

	private readonly record struct FocusRegion(int Left, int Top, int Width, int Height, int ForegroundPixels)
	{
		internal long Score => (long)ForegroundPixels * ForegroundPixels / Width * Height;
	}

	private readonly record struct WhiteComponent(int Left, int Top, int Width, int Height)
	{
		internal double CenterX => Left + (Width - 1) / 2.0;
		internal double CenterY => Top + (Height - 1) / 2.0;
	}

	private static class QrEncoder
	{
		private const int PixelsPerModule = 8;
		private const int QuietZoneModules = 4;

		internal static Manage.GeneratedQr Generate(string text, char errorCorrectionLevel)
		{
			int errorCorrectionIndex = GetErrorCorrectionIndex(errorCorrectionLevel);
			byte[] payload = Encoding.UTF8.GetBytes(text);
			int version = SelectVersion(payload.Length, errorCorrectionIndex);
			int size = 17 + version * 4;
			int rawCodewords = GetRawCodewords(version);
			int blockCount = GetBlockCount(version, errorCorrectionIndex);
			int errorCorrectionLength = GetErrorCorrectionLength(version, errorCorrectionIndex);
			int dataCodewords = rawCodewords - blockCount * errorCorrectionLength;
			byte[] data = CreateDataCodewords(payload, version, dataCodewords);
			byte[] codewords = AddErrorCorrectionAndInterleave(data, rawCodewords, blockCount, errorCorrectionLength);
			bool[] functionModules = new bool[size * size];
			bool[] baseModules = new bool[size * size];
			DrawFunctionPatterns(baseModules, functionModules, version, size, errorCorrectionIndex);
			DrawCodewords(baseModules, functionModules, codewords, size);
			int bestMask = 0;
			int bestPenalty = int.MaxValue;
			bool[] bestModules = [];
			for (int mask = 0; mask < 8; mask++)
			{
				bool[] candidate = (bool[])baseModules.Clone();
				ApplyMask(candidate, functionModules, size, mask);
				DrawFormatBits(candidate, functionModules, size, mask, errorCorrectionIndex);
				int penalty = GetPenaltyScore(candidate, size);
				if (penalty < bestPenalty)
				{
					bestPenalty = penalty;
					bestMask = mask;
					bestModules = candidate;
				}
			}
			int maximumVersionDataCodewords = GetRawCodewords(40) - GetBlockCount(40, errorCorrectionIndex) * GetErrorCorrectionLength(40, errorCorrectionIndex);
			int maximumPayloadBytes = GetMaximumPayloadBytes(40, maximumVersionDataCodewords);
			return new Manage.GeneratedQr(bestModules, size, version, payload.Length, errorCorrectionLevel, bestMask, maximumPayloadBytes);
		}

		private static int SelectVersion(int byteCount, int errorCorrectionIndex)
		{
			for (int version = 1; version <= 40; version++)
			{
				int capacityBits = (GetRawCodewords(version) - GetBlockCount(version, errorCorrectionIndex) * GetErrorCorrectionLength(version, errorCorrectionIndex)) * 8;
				int countBits = version <= 9 ? 8 : 16;
				int requiredBits = 4 + 8 + 4 + countBits + byteCount * 8;
				if (byteCount < (1 << Math.Min(countBits, 30)) && requiredBits <= capacityBits)
				{
					return version;
				}
			}
			throw new ArgumentException("The text is too large for a QR code.", nameof(byteCount));
		}

		private static int GetMaximumPayloadBytes(int version, int dataCodewords)
		{
			int characterCountBits = version <= 9 ? 8 : 16;
			return Math.Max(0, (dataCodewords * 8 - 4 - 8 - 4 - characterCountBits) / 8);
		}

		private static byte[] CreateDataCodewords(byte[] payload, int version, int dataCodewords)
		{
			List<bool> bits = new(dataCodewords * 8);
			AppendBits(bits, 0x7, 4);
			AppendBits(bits, 26, 8);
			AppendBits(bits, 0x4, 4);
			AppendBits(bits, payload.Length, version <= 9 ? 8 : 16);
			foreach (byte value in payload)
			{
				AppendBits(bits, value, 8);
			}
			int capacity = dataCodewords * 8;
			int terminator = Math.Min(4, capacity - bits.Count);
			AppendBits(bits, 0, terminator);
			while ((bits.Count & 7) != 0)
			{
				bits.Add(false);
			}
			byte[] result = new byte[dataCodewords];
			for (int index = 0; index < bits.Count; index++)
			{
				if (bits[index])
				{
					result[index >> 3] |= (byte)(1 << (7 - (index & 7)));
				}
			}
			for (int index = bits.Count >> 3; index < result.Length; index++)
			{
				result[index] = (index - (bits.Count >> 3) & 1) == 0 ? (byte)0xEC : (byte)0x11;
			}
			return result;
		}

		private static void AppendBits(List<bool> bits, int value, int count)
		{
			for (int shift = count - 1; shift >= 0; shift--)
			{
				bits.Add(((value >> shift) & 1) != 0);
			}
		}

		private static byte[] AddErrorCorrectionAndInterleave(byte[] data, int rawCodewords, int blockCount, int errorCorrectionLength)
		{
			int shortBlockLength = rawCodewords / blockCount;
			int longBlockCount = rawCodewords % blockCount;
			int shortBlockCount = blockCount - longBlockCount;
			int shortDataLength = shortBlockLength - errorCorrectionLength;
			byte[][] blocks = new byte[blockCount][];
			byte[][] errorCorrectionBlocks = new byte[blockCount][];
			byte[] divisor = CreateReedSolomonDivisor(errorCorrectionLength);
			int dataOffset = 0;
			for (int block = 0; block < blockCount; block++)
			{
				int dataLength = shortDataLength + (block >= shortBlockCount ? 1 : 0);
				blocks[block] = data.AsSpan(dataOffset, dataLength).ToArray();
				dataOffset += dataLength;
				errorCorrectionBlocks[block] = CalculateReedSolomonRemainder(blocks[block], divisor);
			}
			byte[] result = new byte[rawCodewords];
			int output = 0;
			for (int index = 0; index <= shortDataLength; index++)
			{
				for (int block = 0; block < blockCount; block++)
				{
					if (index < blocks[block].Length)
					{
						result[output++] = blocks[block][index];
					}
				}
			}
			for (int index = 0; index < errorCorrectionLength; index++)
			{
				for (int block = 0; block < blockCount; block++)
				{
					result[output++] = errorCorrectionBlocks[block][index];
				}
			}
			return result;
		}

		private static byte[] CreateReedSolomonDivisor(int degree)
		{
			byte[] result = new byte[degree];
			result[^1] = 1;
			byte root = 1;
			for (int index = 0; index < degree; index++)
			{
				for (int coefficient = 0; coefficient < result.Length; coefficient++)
				{
					result[coefficient] = (byte)ReedSolomon.Multiply(result[coefficient], root);
					if (coefficient + 1 < result.Length)
					{
						result[coefficient] ^= result[coefficient + 1];
					}
				}
				root = (byte)ReedSolomon.Multiply(root, 2);
			}
			return result;
		}

		private static byte[] CalculateReedSolomonRemainder(byte[] data, byte[] divisor)
		{
			byte[] result = new byte[divisor.Length];
			foreach (byte value in data)
			{
				byte factor = (byte)(value ^ result[0]);
				Array.Copy(result, 1, result, 0, result.Length - 1);
				result[^1] = 0;
				for (int index = 0; index < result.Length; index++)
				{
					result[index] ^= (byte)ReedSolomon.Multiply(divisor[index], factor);
				}
			}
			return result;
		}

		private static void DrawFunctionPatterns(bool[] modules, bool[] functionModules, int version, int size, int errorCorrectionIndex)
		{
			for (int index = 0; index < size; index++)
			{
				SetFunctionModule(modules, functionModules, size, 6, index, (index & 1) == 0);
				SetFunctionModule(modules, functionModules, size, index, 6, (index & 1) == 0);
			}
			DrawFinderPattern(modules, functionModules, size, 3, 3);
			DrawFinderPattern(modules, functionModules, size, size - 4, 3);
			DrawFinderPattern(modules, functionModules, size, 3, size - 4);
			int[] alignmentCenters = GetAlignmentCenters(version);
			foreach (int y in alignmentCenters)
			{
				foreach (int x in alignmentCenters)
				{
					if ((x == 6 && y == 6) || (x == 6 && y == size - 7) || (x == size - 7 && y == 6))
					{
						continue;
					}
					DrawAlignmentPattern(modules, functionModules, size, x, y);
				}
			}
			DrawFormatBits(modules, functionModules, size, 0, errorCorrectionIndex);
			DrawVersion(modules, functionModules, version, size);
		}

		private static void DrawFinderPattern(bool[] modules, bool[] functionModules, int size, int centerX, int centerY)
		{
			for (int y = -4; y <= 4; y++)
			{
				for (int x = -4; x <= 4; x++)
				{
					int distance = Math.Max(Math.Abs(x), Math.Abs(y));
					SetFunctionModule(modules, functionModules, size, centerX + x, centerY + y, distance != 2 && distance != 4);
				}
			}
		}

		private static void DrawAlignmentPattern(bool[] modules, bool[] functionModules, int size, int centerX, int centerY)
		{
			for (int y = -2; y <= 2; y++)
			{
				for (int x = -2; x <= 2; x++)
				{
					SetFunctionModule(modules, functionModules, size, centerX + x, centerY + y, Math.Max(Math.Abs(x), Math.Abs(y)) != 1);
				}
			}
		}

		private static void DrawFormatBits(bool[] modules, bool[] functionModules, int size, int mask, int errorCorrectionIndex)
		{
			int data = GetFormatBits(errorCorrectionIndex) << 3 | mask;
			int remainder = data << 10;
			for (int bit = 14; bit >= 10; bit--)
			{
				if (((remainder >> bit) & 1) != 0)
				{
					remainder ^= 0x537 << (bit - 10);
				}
			}
			int bits = ((data << 10) | remainder) ^ 0x5412;
			for (int index = 0; index <= 5; index++) SetFunctionModule(modules, functionModules, size, 8, index, GetBit(bits, index));
			SetFunctionModule(modules, functionModules, size, 8, 7, GetBit(bits, 6));
			SetFunctionModule(modules, functionModules, size, 8, 8, GetBit(bits, 7));
			SetFunctionModule(modules, functionModules, size, 7, 8, GetBit(bits, 8));
			for (int index = 9; index < 15; index++) SetFunctionModule(modules, functionModules, size, 14 - index, 8, GetBit(bits, index));
			for (int index = 0; index < 8; index++) SetFunctionModule(modules, functionModules, size, size - 1 - index, 8, GetBit(bits, index));
			for (int index = 8; index < 15; index++) SetFunctionModule(modules, functionModules, size, 8, size - 15 + index, GetBit(bits, index));
			SetFunctionModule(modules, functionModules, size, 8, size - 8, true);
		}

		private static void DrawVersion(bool[] modules, bool[] functionModules, int version, int size)
		{
			if (version < 7) return;
			int remainder = version << 12;
			for (int bit = 17; bit >= 12; bit--)
			{
				if (((remainder >> bit) & 1) != 0) remainder ^= 0x1F25 << (bit - 12);
			}
			int bits = version << 12 | remainder;
			for (int index = 0; index < 18; index++)
			{
				bool dark = GetBit(bits, index);
				int x = size - 11 + index % 3;
				int y = index / 3;
				SetFunctionModule(modules, functionModules, size, x, y, dark);
				SetFunctionModule(modules, functionModules, size, y, x, dark);
			}
		}

		private static void DrawCodewords(bool[] modules, bool[] functionModules, byte[] codewords, int size)
		{
			int bitIndex = 0;
			for (int right = size - 1; right >= 1; right -= 2)
			{
				if (right == 6) right--;
				for (int vertical = 0; vertical < size; vertical++)
				{
					int y = ((right + 1) & 2) == 0 ? size - 1 - vertical : vertical;
					for (int offset = 0; offset < 2; offset++)
					{
						int x = right - offset;
						if (!functionModules[y * size + x] && bitIndex < codewords.Length * 8)
						{
							modules[y * size + x] = GetBit(codewords[bitIndex >> 3], 7 - (bitIndex & 7));
							bitIndex++;
						}
					}
				}
			}
		}

		private static void ApplyMask(bool[] modules, bool[] functionModules, int size, int mask)
		{
			for (int y = 0; y < size; y++)
			{
				for (int x = 0; x < size; x++)
				{
					if (!functionModules[y * size + x] && Mask(mask, x, y)) modules[y * size + x] = !modules[y * size + x];
				}
			}
		}

		private static bool Mask(int mask, int x, int y) => mask switch
		{
			0 => ((x + y) & 1) == 0,
			1 => (y & 1) == 0,
			2 => x % 3 == 0,
			3 => (x + y) % 3 == 0,
			4 => ((x / 3 + y / 2) & 1) == 0,
			5 => x * y % 2 + x * y % 3 == 0,
			6 => ((x * y % 2 + x * y % 3) & 1) == 0,
			_ => (((x + y) % 2 + x * y % 3) & 1) == 0
		};

		private static int GetPenaltyScore(bool[] modules, int size)
		{
			int result = 0;
			for (int y = 0; y < size; y++) result += GetRunPenalty(modules, size, y * size, 1);
			for (int x = 0; x < size; x++) result += GetRunPenalty(modules, size, x, size);
			for (int y = 0; y < size - 1; y++)
			{
				for (int x = 0; x < size - 1; x++)
				{
					bool value = modules[y * size + x];
					if (value == modules[y * size + x + 1] && value == modules[(y + 1) * size + x] && value == modules[(y + 1) * size + x + 1]) result += 3;
				}
			}
			int dark = modules.Count(static value => value);
			result += Math.Abs(dark * 20 - modules.Length * 10) / modules.Length * 10;
			return result;
		}

		private static int GetRunPenalty(bool[] modules, int size, int start, int step)
		{
			int result = 0;
			bool color = modules[start];
			int run = 1;
			for (int index = 1; index < size; index++)
			{
				bool next = modules[start + index * step];
				if (next == color) run++;
				else
				{
					if (run >= 5) result += run - 2;
					color = next;
					run = 1;
				}
			}
			if (run >= 5) result += run - 2;
			return result;
		}

		private static void SetFunctionModule(bool[] modules, bool[] functionModules, int size, int x, int y, bool dark)
		{
			// Finder separators intentionally probe one module outside the matrix at the three outer corners.
			if (x < 0 || x >= size || y < 0 || y >= size) return;
			modules[y * size + x] = dark;
			functionModules[y * size + x] = true;
		}

		private static bool GetBit(int value, int index) => ((value >> index) & 1) != 0;

		private static int[] GetAlignmentCenters(int version)
		{
			if (version == 1) return [];
			int count = version / 7 + 2;
			int step = version == 32 ? 26 : (version * 4 + count * 2 + 1) / (count * 2 - 2) * 2;
			int[] result = new int[count];
			result[0] = 6;
			for (int index = count - 1, position = version * 4 + 10; index >= 1; index--, position -= step) result[index] = position;
			return result;
		}

		private static int GetRawCodewords(int version)
		{
			int result = (16 * version + 128) * version + 64;
			if (version >= 2)
			{
				int align = version / 7 + 2;
				result -= (25 * align - 10) * align - 55;
				if (version >= 7) result -= 36;
			}
			return result / 8;
		}

		private static int GetErrorCorrectionIndex(char level) => level switch
		{
			'L' => 0,
			'M' => 1,
			'Q' => 2,
			'H' => 3,
			_ => throw new ArgumentOutOfRangeException(nameof(level))
		};

		private static int GetFormatBits(int errorCorrectionIndex) => errorCorrectionIndex switch
		{
			0 => 1,
			1 => 0,
			2 => 3,
			3 => 2,
			_ => throw new ArgumentOutOfRangeException(nameof(errorCorrectionIndex))
		};

		private static int GetErrorCorrectionLength(int version, int errorCorrectionIndex)
		{
			ReadOnlySpan<byte> values = errorCorrectionIndex switch
			{
				0 => [7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
				1 => [10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
				2 => [13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
				3 => [17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
				_ => throw new ArgumentOutOfRangeException(nameof(errorCorrectionIndex))
			};
			return values[version - 1];
		}

		private static int GetBlockCount(int version, int errorCorrectionIndex)
		{
			ReadOnlySpan<byte> values = errorCorrectionIndex switch
			{
				0 => [1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
				1 => [1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
				2 => [1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
				3 => [1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
				_ => throw new ArgumentOutOfRangeException(nameof(errorCorrectionIndex))
			};
			return values[version - 1];
		}

		internal static SoftwareBitmap Render(bool[] modules, int size)
		{
			int dimension = (size + QuietZoneModules * 2) * PixelsPerModule;
			byte[] pixels = new byte[checked(dimension * dimension * 4)];
			Array.Fill(pixels, byte.MaxValue);
			int offset = QuietZoneModules * PixelsPerModule;
			for (int moduleY = 0; moduleY < size; moduleY++)
			{
				for (int moduleX = 0; moduleX < size; moduleX++)
				{
					if (!modules[moduleY * size + moduleX]) continue;
					int firstX = offset + moduleX * PixelsPerModule;
					int firstY = offset + moduleY * PixelsPerModule;
					for (int y = 0; y < PixelsPerModule; y++)
					{
						int row = ((firstY + y) * dimension + firstX) * 4;
						for (int x = 0; x < PixelsPerModule; x++)
						{
							int pixel = row + x * 4;
							pixels[pixel] = 0;
							pixels[pixel + 1] = 0;
							pixels[pixel + 2] = 0;
							pixels[pixel + 3] = byte.MaxValue;
						}
					}
				}
			}
			return SoftwareBitmap.CreateCopyFromBuffer(pixels.AsBuffer(), BitmapPixelFormat.Bgra8, dimension, dimension, BitmapAlphaMode.Premultiplied);
		}
	}

	private static class QrDecoder
	{
		internal static readonly byte[] s_thresholds = [80, 100, 120, 140, 160, 180, 200, 220];

		internal static QrResult Decode(GrayImage image)
		{
			// Fast path for axis-aligned QR images with bright modules on a dark background.
			QrResult? directResult = TryDecodeAxisAlignedBrightModules(image);
			if (directResult is not null)
			{
				return directResult;
			}
			// Fallback for axis-aligned QR images whose quiet zone is clipped or merged with surrounding screenshot content.
			directResult = TryDecodeClippedAxisAlignedModules(image);
			if (directResult is not null)
			{
				return directResult;
			}
			// Fallback for isolated styled QR images with colored, rounded, merged, or logo-obscured modules.
			directResult = TryDecodeAxisAlignedStyledModules(image);
			if (directResult is not null)
			{
				return directResult;
			}
			#region Cheap Path 1 - Can be safely removed, added to reduce decoding time without reducing accuracy.
			// Cheap structural preflight across all configured thresholds. A result is accepted only after the existing full QR validation succeeds.
			directResult = TryDecodeThresholdPreflight(image);
			#endregion
			if (directResult is not null)
			{
				return directResult;
			}

			List<string> failures = [with(64)];
			GrayImage invertedImage = ImagePreprocessor.InvertLuminance(image);
			QrResult? invertedResult = TryDecodeThresholdPreflight(invertedImage);
			if (invertedResult is not null)
			{
				return invertedResult;
			}
			invertedResult = QrDecoderHelpers.TryDecodeBinarizations(invertedImage, "original-luminance inverted", failures);
			if (invertedResult is not null)
			{
				return invertedResult;
			}

			for (int scale = 1; scale <= 3; scale++)
			{
				GrayImage scaled = scale == 1 ? image : ImagePreprocessor.ScaleBilinear(image, scale);
				QrResult? result = QrDecoderHelpers.TryDecodeBinarizations(scaled, $"scale {scale}", failures);
				if (result is not null)
				{
					return result;
				}
			}
			// Final fallback that isolates likely QR regions inside large screenshots before retrying existing decoders.
			QrResult? focusedResult = TryDecodeFocusedRegions(image, failures);
			if (focusedResult is not null)
			{
				return focusedResult;
			}

			throw new QrException($"QR decoding failed for every scale, threshold and reflectance polarity.{Environment.NewLine}{string.Join(Environment.NewLine + Environment.NewLine, failures)}");
		}

		#region Cheap Path 1 - Can be safely removed, added to reduce decoding time without reducing accuracy.
		private static QrResult? TryDecodeThresholdPreflight(GrayImage image)
		{
			List<ThresholdProbe> probes = [with(s_thresholds.Length * 8)];
			for (int thresholdIndex = 0; thresholdIndex < s_thresholds.Length; thresholdIndex++)
			{
				BooleanMatrix normal = ImagePreprocessor.Threshold(image, s_thresholds[thresholdIndex]);
				CollectThresholdProbes(normal, thresholdIndex, false, probes);
				CollectThresholdProbes(MatrixTransforms.Invert(normal, image.Padding), thresholdIndex, true, probes);
			}
			foreach (ThresholdProbe probe in probes.OrderBy(static probe => probe.MatrixIndex).ThenBy(static probe => probe.TripleIndex).ThenBy(static probe => probe.ThresholdIndex).ThenBy(static probe => probe.Inverted))
			{
				try
				{
					QrResult result = MatrixParser.Decode(probe.Matrix);
					if (result.Text is { Length: > 0 })
					{
						return result;
					}
				}
				catch (Exception exception) when (exception is QrException or ArithmeticException)
				{
				}
				try
				{
					QrResult result = MatrixParser.DecodeStylized(probe.Matrix);
					if (result.Text is { Length: > 0 })
					{
						return result;
					}
				}
				catch (Exception exception) when (exception is QrException or ArithmeticException)
				{
				}
			}
			return null;
		}

		private static void CollectThresholdProbes(BooleanMatrix binary, int thresholdIndex, bool inverted, List<ThresholdProbe> probes)
		{
			int tripleIndex = 0;
			foreach ((Finder topLeft, Finder topRight, Finder bottomLeft) in FinderDetector.FindTriples(binary))
			{
				BooleanMatrix[] sampledMatrices;
				try
				{
					sampledMatrices = GridSampler.SampleCandidates(binary, topLeft, topRight, bottomLeft);
				}
				catch (Exception exception) when (exception is QrException or ArithmeticException)
				{
					tripleIndex++;
					continue;
				}
				for (int matrixIndex = 0; matrixIndex < sampledMatrices.Length; matrixIndex++)
				{
					BooleanMatrix matrix = sampledMatrices[matrixIndex];
					if (MatrixParser.HasValidFormatInformation(matrix))
					{
						probes.Add(new ThresholdProbe(matrix, thresholdIndex, inverted, tripleIndex, matrixIndex));
					}
				}
				tripleIndex++;
			}
		}

		#endregion

		// Isolates likely square QR regions in large screenshots, adds a quiet zone, and retries all existing decode paths.
		private static QrResult? TryDecodeFocusedRegions(GrayImage image, List<string> failures)
		{
			int sourceWidth = image.Width - image.Padding * 2;
			int sourceHeight = image.Height - image.Padding * 2;
			if (sourceWidth < 640 && sourceHeight < 640)
			{
				return null;
			}

			List<FocusRegion> regions = FindFocusRegions(image);
			int limit = Math.Min(regions.Count, 4);
			for (int index = 0; index < limit; index++)
			{
				FocusRegion region = regions[index];
				GrayImage focused = CropWithQuietZone(image, region);
				QrResult? directResult = TryDecodeAxisAlignedBrightModules(focused);
				if (directResult is not null)
				{
					return directResult;
				}

				directResult = TryDecodeClippedAxisAlignedModules(focused);
				if (directResult is not null)
				{
					return directResult;
				}

				directResult = TryDecodeAxisAlignedStyledModules(focused);
				if (directResult is not null)
				{
					return directResult;
				}

				List<string> focusedFailures = [with(16)];
				QrResult? result = QrDecoderHelpers.TryDecodeBinarizations(focused, $"focused region {index + 1}", focusedFailures);
				if (result is not null)
				{
					return result;
				}

				if (failures.Count < 64)
				{
					failures.Add($"[focused region {index + 1}] Bounds {region.Width}x{region.Height} at ({region.Left - image.Padding}, {region.Top - image.Padding}).{Environment.NewLine}{string.Join(Environment.NewLine, focusedFailures)}");
				}
			}
			return null;
		}

		// Finds dense, approximately square foreground regions that may contain an embedded QR code.
		private static List<FocusRegion> FindFocusRegions(GrayImage image)
		{
			int pixelCount = image.Width * image.Height;
			bool[] visited = new bool[pixelCount];
			int[] queue = GC.AllocateUninitializedArray<int>(pixelCount);
			List<FocusRegion> regions = [with(8)];
			int rightBoundary = image.Width - image.Padding;
			int bottomBoundary = image.Height - image.Padding;
			for (int startY = image.Padding; startY < bottomBoundary; startY++)
			{
				for (int startX = image.Padding; startX < rightBoundary; startX++)
				{
					int start = startY * image.Width + startX;
					if (visited[start] || image.ColorDistance[start] >= 180)
					{
						continue;
					}

					visited[start] = true;
					int head = 0;
					int tail = 1;
					queue[0] = start;
					int left = startX;
					int top = startY;
					int right = startX;
					int bottom = startY;
					while (head < tail)
					{
						int current = queue[head++];
						int x = current % image.Width;
						int y = current / image.Width;
						left = Math.Min(left, x);
						top = Math.Min(top, y);
						right = Math.Max(right, x);
						bottom = Math.Max(bottom, y);
						if (x > image.Padding)
						{
							AddFocusNeighbor(current - 1, image, visited, queue, ref tail);
						}

						if (x + 1 < rightBoundary)
						{
							AddFocusNeighbor(current + 1, image, visited, queue, ref tail);
						}

						if (y > image.Padding)
						{
							AddFocusNeighbor(current - image.Width, image, visited, queue, ref tail);
						}

						if (y + 1 < bottomBoundary)
						{
							AddFocusNeighbor(current + image.Width, image, visited, queue, ref tail);
						}
					}
					int width = right - left + 1;
					int height = bottom - top + 1;
					if (width < 128 || height < 128 || Math.Abs(width - height) > Math.Max(width, height) / 10)
					{
						continue;
					}
					int area = width * height;
					if (tail * 2 < area)
					{
						continue;
					}
					regions.Add(new FocusRegion(left, top, width, height, tail));
				}
			}
			regions.Sort(static (first, second) => second.Score.CompareTo(first.Score));
			return regions;
		}

		private static void AddFocusNeighbor(int index, GrayImage image, bool[] visited, int[] queue, ref int tail)
		{
			if (visited[index])
			{
				return;
			}

			visited[index] = true;
			if (image.ColorDistance[index] < 180)
			{
				queue[tail++] = index;
			}
		}

		// Crops a detected screenshot region and surrounds the crop with a synthetic white quiet zone.
		private static GrayImage CropWithQuietZone(GrayImage image, FocusRegion region)
		{
			const int quietZone = 16;
			int width = region.Width + quietZone * 2;
			int height = region.Height + quietZone * 2;
			byte[] pixels = GC.AllocateUninitializedArray<byte>(width * height);
			byte[] colorDistance = GC.AllocateUninitializedArray<byte>(pixels.Length);
			Array.Fill(pixels, byte.MaxValue);
			Array.Fill(colorDistance, byte.MaxValue);
			for (int y = 0; y < region.Height; y++)
			{
				int source = (region.Top + y) * image.Width + region.Left;
				int destination = (quietZone + y) * width + quietZone;
				image.Pixels.Slice(source, region.Width).CopyTo(pixels.AsSpan(destination, region.Width));
				image.ColorDistance.Slice(source, region.Width).CopyTo(colorDistance.AsSpan(destination, region.Width));
			}
			return new GrayImage(width, height, quietZone, pixels, colorDistance);
		}

		// Decodes axis-aligned QR images that use bright modules on a dark background.
		private static QrResult? TryDecodeAxisAlignedBrightModules(GrayImage image)
		{
			int left = image.Width;
			int top = image.Height;
			int right = -1;
			int bottom = -1;
			for (int y = image.Padding; y < image.Height - image.Padding; y++)
			{
				int row = y * image.Width;
				for (int x = image.Padding; x < image.Width - image.Padding; x++)
				{
					if (image.Pixels[row + x] <= 160)
					{
						continue;
					}

					left = Math.Min(left, x);
					top = Math.Min(top, y);
					right = Math.Max(right, x);
					bottom = Math.Max(bottom, y);
				}
			}
			if (right < left || bottom < top)
			{
				return null;
			}

			int pixelWidth = right - left + 1;
			int pixelHeight = bottom - top + 1;
			if (Math.Abs(pixelWidth - pixelHeight) > Math.Max(pixelWidth, pixelHeight) / 20)
			{
				return null;
			}

			for (int version = 1; version <= 40; version++)
			{
				int dimension = 17 + version * 4;
				double moduleWidth = pixelWidth / (double)dimension;
				double moduleHeight = pixelHeight / (double)dimension;
				if (moduleWidth < 2.0 || moduleHeight < 2.0 || Math.Abs(moduleWidth - moduleHeight) > Math.Max(moduleWidth, moduleHeight) * 0.05)
				{
					continue;
				}

				BooleanMatrix modules = new(dimension, dimension);
				for (int moduleY = 0; moduleY < dimension; moduleY++)
				{
					for (int moduleX = 0; moduleX < dimension; moduleX++)
					{
						int pixelX = Math.Clamp((int)Math.Floor(left + (moduleX + 0.5) * moduleWidth), 0, image.Width - 1);
						int pixelY = Math.Clamp((int)Math.Floor(top + (moduleY + 0.5) * moduleHeight), 0, image.Height - 1);
						modules[moduleX, moduleY] = image.Pixels[pixelY * image.Width + pixelX] > 160;
					}
				}
				try
				{
					QrResult result = MatrixParser.Decode(modules);
					if (result.Text is { Length: > 0 })
					{
						return result;
					}
				}
				catch (Exception exception) when (exception is QrException or ArithmeticException)
				{
				}
			}
			return null;
		}

		// Recovers QR images with missing quiet zones by deriving geometry from enclosed finder-pattern regions.
		private static QrResult? TryDecodeClippedAxisAlignedModules(GrayImage image)
		{
			List<WhiteComponent> components = FindWhiteComponents(image);
			for (int firstIndex = 0; firstIndex < components.Count - 2; firstIndex++)
			{
				WhiteComponent topLeft = components[firstIndex];
				for (int secondIndex = 0; secondIndex < components.Count - 1; secondIndex++)
				{
					if (secondIndex == firstIndex)
					{
						continue;
					}

					WhiteComponent topRight = components[secondIndex];
					double estimatedModule = ((topLeft.Width + 1) / 5.0 + (topLeft.Height + 1) / 5.0 + (topRight.Width + 1) / 5.0 + (topRight.Height + 1) / 5.0) / 4.0;
					if (Math.Abs(topLeft.CenterY - topRight.CenterY) > estimatedModule || topRight.CenterX <= topLeft.CenterX + estimatedModule * 10.0)
					{
						continue;
					}

					if (Math.Abs(topLeft.Width - topRight.Width) > estimatedModule || Math.Abs(topLeft.Height - topRight.Height) > estimatedModule)
					{
						continue;
					}

					for (int thirdIndex = 0; thirdIndex < components.Count; thirdIndex++)
					{
						if (thirdIndex == firstIndex || thirdIndex == secondIndex)
						{
							continue;
						}

						WhiteComponent bottomLeft = components[thirdIndex];
						if (Math.Abs(topLeft.CenterX - bottomLeft.CenterX) > estimatedModule || bottomLeft.CenterY <= topLeft.CenterY + estimatedModule * 10.0)
						{
							continue;
						}

						if (Math.Abs(topLeft.Width - bottomLeft.Width) > estimatedModule || Math.Abs(topLeft.Height - bottomLeft.Height) > estimatedModule)
						{
							continue;
						}

						double horizontalDistance = topRight.CenterX - topLeft.CenterX;
						double verticalDistance = bottomLeft.CenterY - topLeft.CenterY;
						if (Math.Abs(horizontalDistance - verticalDistance) > estimatedModule * 2.0)
						{
							continue;
						}

						estimatedModule = (estimatedModule * 4.0 + (bottomLeft.Width + 1) / 5.0 + (bottomLeft.Height + 1) / 5.0) / 6.0;
						int dimension = (int)Math.Round((horizontalDistance + verticalDistance) / (2.0 * estimatedModule) + 7.0);
						if (dimension < 21 || dimension > 177 || ((dimension - 17) & 3) != 0)
						{
							continue;
						}

						double left = topLeft.CenterX - 3.5 * estimatedModule;
						double top = topLeft.CenterY - 3.5 * estimatedModule;
						BooleanMatrix modules = new(dimension, dimension);
						bool inBounds = true;
						for (int moduleY = 0; moduleY < dimension && inBounds; moduleY++)
						{
							for (int moduleX = 0; moduleX < dimension; moduleX++)
							{
								int pixelX = (int)Math.Round(left + (moduleX + 0.5) * estimatedModule);
								int pixelY = (int)Math.Round(top + (moduleY + 0.5) * estimatedModule);
								if (pixelX < 0 || pixelX >= image.Width || pixelY < 0 || pixelY >= image.Height)
								{
									inBounds = false;
									break;
								}
								modules[moduleX, moduleY] = image.Pixels[pixelY * image.Width + pixelX] < 128;
							}
						}
						if (!inBounds)
						{
							continue;
						}

						try
						{
							QrResult result = MatrixParser.Decode(modules);
							if (result.Text is { Length: > 0 })
							{
								return result;
							}
						}
						catch (Exception exception) when (exception is QrException or ArithmeticException)
						{
						}
					}
				}
			}
			return null;
		}

		// Finds enclosed bright components used to recover finder-pattern geometry in clipped QR screenshots.
		private static List<WhiteComponent> FindWhiteComponents(GrayImage image)
		{
			int pixelCount = image.Width * image.Height;
			bool[] visited = new bool[pixelCount];
			int[] queue = GC.AllocateUninitializedArray<int>(pixelCount);
			List<WhiteComponent> components = [with(32)];
			for (int startY = image.Padding; startY < image.Height - image.Padding; startY++)
			{
				for (int startX = image.Padding; startX < image.Width - image.Padding; startX++)
				{
					int start = startY * image.Width + startX;
					if (visited[start] || image.Pixels[start] <= 240)
					{
						continue;
					}

					visited[start] = true;
					int head = 0;
					int tail = 1;
					queue[0] = start;
					int left = startX;
					int top = startY;
					int right = startX;
					int bottom = startY;
					while (head < tail)
					{
						int current = queue[head++];
						int x = current % image.Width;
						int y = current / image.Width;
						left = Math.Min(left, x);
						top = Math.Min(top, y);
						right = Math.Max(right, x);
						bottom = Math.Max(bottom, y);
						if (x > image.Padding)
						{
							AddWhiteNeighbor(current - 1, image, visited, queue, ref tail);
						}

						if (x + 1 < image.Width - image.Padding)
						{
							AddWhiteNeighbor(current + 1, image, visited, queue, ref tail);
						}

						if (y > image.Padding)
						{
							AddWhiteNeighbor(current - image.Width, image, visited, queue, ref tail);
						}

						if (y + 1 < image.Height - image.Padding)
						{
							AddWhiteNeighbor(current + image.Width, image, visited, queue, ref tail);
						}
					}
					int width = right - left + 1;
					int height = bottom - top + 1;
					if (width < 20 || height < 20 || Math.Abs(width - height) > Math.Max(width, height) / 8)
					{
						continue;
					}

					int boundingArea = width * height;
					if (tail * 100 < boundingArea * 45 || tail * 100 > boundingArea * 80)
					{
						continue;
					}

					components.Add(new WhiteComponent(left, top, width, height));
				}
			}
			return components;
		}

		private static void AddWhiteNeighbor(int index, GrayImage image, bool[] visited, int[] queue, ref int tail)
		{
			if (visited[index])
			{
				return;
			}

			visited[index] = true;
			if (image.Pixels[index] > 240)
			{
				queue[tail++] = index;
			}
		}

		// Reconstructs isolated styled QR images whose decorative modules or center logos damage normal sampling.
		private static QrResult? TryDecodeAxisAlignedStyledModules(GrayImage image)
		{
			if (!TryGetStyledBounds(image, out int left, out int top, out int right, out int bottom))
			{
				return null;
			}

			int pixelWidth = right - left + 1;
			int pixelHeight = bottom - top + 1;
			if (Math.Abs(pixelWidth - pixelHeight) > Math.Max(pixelWidth, pixelHeight) / 20)
			{
				return null;
			}

			int[] versions = [.. Enumerable.Range(1, 40)
			.Where(version =>
			{
				int dimension = 17 + version * 4;
				double moduleWidth = pixelWidth / (double)dimension;
				double moduleHeight = pixelHeight / (double)dimension;
				return moduleWidth >= 3.0 && moduleHeight >= 3.0 && Math.Abs(moduleWidth - moduleHeight) <= Math.Max(moduleWidth, moduleHeight) * 0.05;
			})
			.OrderBy(version =>
			{
				int dimension = 17 + version * 4;
				double moduleWidth = pixelWidth / (double)dimension;
				double moduleHeight = pixelHeight / (double)dimension;
				return Math.Abs(moduleWidth - Math.Round(moduleWidth)) + Math.Abs(moduleHeight - Math.Round(moduleHeight));
			})];
			foreach (int version in versions)
			{
				int dimension = 17 + version * 4;
				double moduleWidth = pixelWidth / (double)dimension;
				double moduleHeight = pixelHeight / (double)dimension;
				double integralError = Math.Abs(moduleWidth - Math.Round(moduleWidth)) + Math.Abs(moduleHeight - Math.Round(moduleHeight));
				if (integralError > 0.05)
				{
					continue;
				}

				BooleanMatrix modules = new(dimension, dimension);
				for (int moduleY = 0; moduleY < dimension; moduleY++)
				{
					for (int moduleX = 0; moduleX < dimension; moduleX++)
					{
						modules[moduleX, moduleY] = SampleStyledModule(image, left, top, moduleWidth, moduleHeight, moduleX, moduleY);
					}
				}

				NormalizeStyledFunctionPatterns(modules, version);
				try
				{
					for (int ecIndex = 0; ecIndex < 4; ecIndex++)
					{
						for (int mask = 0; mask < 8; mask++)
						{
							try
							{
								QrResult result = MatrixParser.DecodeWithKnownFormatAndErasures(modules, ecIndex, mask, dimension * 28 / 100, dimension * 38 / 100, dimension * 72 / 100, dimension * 58 / 100);
								if (Uri.TryCreate(result.Text, UriKind.Absolute, out Uri? uri) && (uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) || uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
								{
									return result;
								}
							}
							catch (Exception exception) when (exception is QrException or ArithmeticException)
							{
							}
						}
					}
				}
				catch (Exception exception) when (exception is QrException or ArithmeticException)
				{
				}
			}
			return null;
		}

		// Locates the square foreground bounds of an isolated colored or stylized QR image.
		private static bool TryGetStyledBounds(GrayImage image, out int left, out int top, out int right, out int bottom)
		{
			left = image.Width;
			top = image.Height;
			right = -1;
			bottom = -1;
			for (int y = image.Padding; y < image.Height - image.Padding; y++)
			{
				int row = y * image.Width;
				for (int x = image.Padding; x < image.Width - image.Padding; x++)
				{
					if (image.ColorDistance[row + x] >= 250)
					{
						continue;
					}

					left = Math.Min(left, x);
					top = Math.Min(top, y);
					right = Math.Max(right, x);
					bottom = Math.Max(bottom, y);
				}
			}
			return right >= left && bottom >= top;
		}

		// Classifies decorative QR modules by foreground coverage instead of relying on a single center pixel.
		private static bool SampleStyledModule(GrayImage image, int left, int top, double moduleWidth, double moduleHeight, int moduleX, int moduleY)
		{
			int startX = Math.Clamp((int)Math.Floor(left + moduleX * moduleWidth), 0, image.Width - 1);
			int startY = Math.Clamp((int)Math.Floor(top + moduleY * moduleHeight), 0, image.Height - 1);
			int endX = Math.Clamp((int)Math.Ceiling(left + (moduleX + 1) * moduleWidth), startX + 1, image.Width);
			int endY = Math.Clamp((int)Math.Ceiling(top + (moduleY + 1) * moduleHeight), startY + 1, image.Height);
			int foreground = 0;
			int count = (endX - startX) * (endY - startY);
			for (int y = startY; y < endY; y++)
			{
				int row = y * image.Width;
				for (int x = startX; x < endX; x++)
				{
					if (image.ColorDistance[row + x] < 250)
					{
						foreground++;
					}
				}
			}
			return foreground * 10 >= count;
		}
		// Restores standard finder, timing, alignment, and dark-module patterns damaged by decorative styling.
		private static void NormalizeStyledFunctionPatterns(BooleanMatrix modules, int version)
		{
			int dimension = modules.Width;
			SetStyledFinderPattern(modules, 0, 0);
			SetStyledFinderPattern(modules, dimension - 7, 0);
			SetStyledFinderPattern(modules, 0, dimension - 7);
			for (int index = 8; index < dimension - 8; index++)
			{
				bool value = (index & 1) == 0;
				modules[6, index] = value;
				modules[index, 6] = value;
			}
			int[] centers = GetStyledAlignmentCenters(version);
			foreach (int centerY in centers)
			{
				foreach (int centerX in centers)
				{
					if ((centerX <= 8 && centerY <= 8) || (centerX >= dimension - 8 && centerY <= 8) || (centerX <= 8 && centerY >= dimension - 8))
					{
						continue;
					}

					for (int offsetY = -2; offsetY <= 2; offsetY++)
					{
						for (int offsetX = -2; offsetX <= 2; offsetX++)
						{
							modules[centerX + offsetX, centerY + offsetY] = Math.Max(Math.Abs(offsetX), Math.Abs(offsetY)) is 0 or 2;
						}
					}
				}
			}

			modules[dimension - 8, 8] = true;
		}
		private static void SetStyledFinderPattern(BooleanMatrix modules, int left, int top)
		{
			for (int offsetY = -1; offsetY <= 7; offsetY++)
			{
				for (int offsetX = -1; offsetX <= 7; offsetX++)
				{
					int x = left + offsetX;
					int y = top + offsetY;
					if (x < 0 || x >= modules.Width || y < 0 || y >= modules.Height)
					{
						continue;
					}

					bool inside = offsetX >= 0 && offsetX < 7 && offsetY >= 0 && offsetY < 7;
					modules[x, y] = inside && (offsetX is 0 or 6 || offsetY is 0 or 6 || (offsetX is >= 2 and <= 4 && offsetY is >= 2 and <= 4));
				}
			}
		}
		private static int[] GetStyledAlignmentCenters(int version)
		{
			if (version == 1)
			{
				return [];
			}

			int count = version / 7 + 2;
			int step = version == 32 ? 26 : (version * 4 + count * 2 + 1) / (count * 2 - 2) * 2;
			int[] result = new int[count];
			result[0] = 6;
			for (int index = count - 1, position = version * 4 + 10; index >= 1; index--, position -= step)
			{
				result[index] = position;
			}

			return result;
		}

		internal static QrResult? TryDecodePolarity(BooleanMatrix binary, string label, List<string> failures)
		{
			try
			{
				return DecodePolarity(binary, label, failures);
			}
			catch (Exception exception) when (exception is QrException or ArithmeticException)
			{
				if (failures.Count < 64)
				{
					failures.Add($"[{label}] {exception}");
				}
			}
			return null;
		}

		private static QrResult? DecodePolarity(BooleanMatrix binary, string polarity, List<string> polarityFailures)
		{
			List<string> failures = [with(16)];
			(Finder, Finder, Finder)[] triples = [.. FinderDetector.FindTriples(binary)];
			for (int candidateIndex = 0; candidateIndex < triples.Length; candidateIndex++)
			{
				(Finder topLeft, Finder topRight, Finder bottomLeft) = triples[candidateIndex];
				BooleanMatrix[] sampledMatrices;
				try
				{
					sampledMatrices = GridSampler.SampleCandidates(binary, topLeft, topRight, bottomLeft);
				}
				catch (Exception exception) when (exception is QrException or ArithmeticException)
				{
					if (failures.Count < 16)
					{
						failures.Add($"Candidate {candidateIndex + 1}, grid sampling: {exception.Message}");
					}

					continue;
				}
				foreach (BooleanMatrix modules in sampledMatrices)
				{
					foreach (BooleanMatrix orientedModules in MatrixTransforms.Orientations(modules))
					{
						try
						{
							QrResult result = MatrixParser.Decode(orientedModules);
							if (result.Text is not { Length: > 0 })
							{
								throw new QrException("Decoded payload is empty.");
							}
							return result;
						}
						catch (Exception exception) when (exception is QrException or ArithmeticException)
						{
							if (failures.Count < 16)
							{
								failures.Add($"Candidate {candidateIndex + 1}, {modules.Width}x{modules.Height}: {exception.Message}");
							}
						}
					}
				}
			}
			foreach (BooleanMatrix modules in AxisAlignedGridSampler.SampleCandidates(binary))
			{
				try
				{
					QrResult result = MatrixParser.DecodeStylized(modules);
					if (result.Text is not { Length: > 0 })
					{
						throw new QrException("Decoded payload is empty.");
					}

					return result;
				}
				catch (Exception exception) when (exception is QrException or ArithmeticException)
				{
					if (failures.Count < 16)
					{
						failures.Add($"Axis-aligned {modules.Width}x{modules.Height}: {exception.Message}");
					}
				}
			}
			if (polarityFailures.Count < 64)
			{
				polarityFailures.Add($"[{polarity}] Finder triples: {triples.Length}.{Environment.NewLine}{string.Join(Environment.NewLine, failures)}");
			}
			return null;
		}
	}

	private static class ImagePreprocessor
	{
		internal static GrayImage ScaleBilinear(GrayImage source, int scale)
		{
			int width = source.Width * scale;
			int height = source.Height * scale;
			byte[] pixels = GC.AllocateUninitializedArray<byte>(width * height);
			byte[] colorDistance = GC.AllocateUninitializedArray<byte>(pixels.Length);
			for (int y = 0; y < height; y++)
			{
				double sourceY = (y + 0.5) / scale - 0.5;
				int y0 = Math.Clamp((int)Math.Floor(sourceY), 0, source.Height - 1);
				int y1 = Math.Min(y0 + 1, source.Height - 1);
				double fy = Math.Clamp(sourceY - y0, 0.0, 1.0);
				for (int x = 0; x < width; x++)
				{
					double sourceX = (x + 0.5) / scale - 0.5;
					int x0 = Math.Clamp((int)Math.Floor(sourceX), 0, source.Width - 1);
					int x1 = Math.Min(x0 + 1, source.Width - 1);
					double fx = Math.Clamp(sourceX - x0, 0.0, 1.0);
					double top = source.Pixels[y0 * source.Width + x0] * (1.0 - fx) + source.Pixels[y0 * source.Width + x1] * fx;
					double bottom = source.Pixels[y1 * source.Width + x0] * (1.0 - fx) + source.Pixels[y1 * source.Width + x1] * fx;
					pixels[y * width + x] = (byte)Math.Clamp((int)Math.Round(top * (1.0 - fy) + bottom * fy), 0, 255);
					double colorTop = source.ColorDistance[y0 * source.Width + x0] * (1.0 - fx) + source.ColorDistance[y0 * source.Width + x1] * fx;
					double colorBottom = source.ColorDistance[y1 * source.Width + x0] * (1.0 - fx) + source.ColorDistance[y1 * source.Width + x1] * fx;
					colorDistance[y * width + x] = (byte)Math.Clamp((int)Math.Round(colorTop * (1.0 - fy) + colorBottom * fy), 0, 255);
				}
			}
			return new GrayImage(width, height, source.Padding * scale, pixels, colorDistance);
		}

		internal static GrayImage InvertLuminance(GrayImage image)
		{
			byte[] pixels = new byte[image.Pixels.Length];
			byte[] colorDistance = new byte[image.ColorDistance.Length];
			Array.Fill(pixels, byte.MaxValue);
			Array.Fill(colorDistance, byte.MaxValue);
			int right = image.Width - image.Padding;
			int bottom = image.Height - image.Padding;
			for (int y = image.Padding; y < bottom; y++)
			{
				int row = y * image.Width;
				for (int x = image.Padding; x < right; x++)
				{
					int index = row + x;
					pixels[index] = (byte)(255 - image.Pixels[index]);
					colorDistance[index] = (byte)(255 - image.ColorDistance[index]);
				}
			}
			return new GrayImage(image.Width, image.Height, image.Padding, pixels, colorDistance);
		}

		internal static BooleanMatrix Threshold(GrayImage image, byte threshold)
		{
			BooleanMatrix result = new(image.Width, image.Height);
			for (int y = 0; y < image.Height; y++)
			{
				for (int x = 0; x < image.Width; x++)
				{
					result[x, y] = image.Pixels[y * image.Width + x] < threshold;
				}
			}

			return result;
		}
	}

	private static class MatrixTransforms
	{
		internal static IEnumerable<BooleanMatrix> Orientations(BooleanMatrix source)
		{
			BooleanMatrix current = source;
			for (int rotation = 0; rotation < 4; rotation++)
			{
				yield return current;
				yield return MirrorHorizontal(current);
				current = RotateClockwise(current);
			}
		}

		private static BooleanMatrix RotateClockwise(BooleanMatrix source)
		{
			BooleanMatrix result = new(source.Height, source.Width);
			for (int y = 0; y < source.Height; y++)
			{
				for (int x = 0; x < source.Width; x++)
				{
					result[source.Height - 1 - y, x] = source[x, y];
				}
			}
			return result;
		}

		private static BooleanMatrix MirrorHorizontal(BooleanMatrix source)
		{
			BooleanMatrix result = new(source.Width, source.Height);
			for (int y = 0; y < source.Height; y++)
			{
				for (int x = 0; x < source.Width; x++)
				{
					result[source.Width - 1 - x, y] = source[x, y];
				}
			}
			return result;
		}

		internal static BooleanMatrix Invert(BooleanMatrix source, int padding)
		{
			BooleanMatrix result = new(source.Width, source.Height);
			int right = source.Width - padding;
			int bottom = source.Height - padding;
			for (int y = padding; y < bottom; y++)
			{
				for (int x = padding; x < right; x++)
				{
					result[x, y] = !source[x, y];
				}
			}
			return result;
		}
	}

	internal sealed class BooleanMatrix
	{
		private readonly bool[] _bits;
		internal BooleanMatrix(int width, int height)
		{
			Width = width;
			Height = height;
			_bits = new bool[width * height];
		}
		internal int Width { get; }
		internal int Height { get; }
		internal bool this[int x, int y]
		{
			get => _bits[y * Width + x];
			set => _bits[y * Width + x] = value;
		}
	}

	private static class Binarizer
	{
		internal static BooleanMatrix Binarize(GrayImage image)
		{
			int width = image.Width;
			int height = image.Height;
			int globalMinimum = 255;
			int globalMaximum = 0;
			foreach (byte value in image.Pixels)
			{
				globalMinimum = Math.Min(globalMinimum, value);
				globalMaximum = Math.Max(globalMaximum, value);
			}
			int globalThreshold = (globalMinimum + globalMaximum) >> 1;

			int blockSize = 8;
			int blocksX = (width + blockSize - 1) / blockSize;
			int blocksY = (height + blockSize - 1) / blockSize;
			int[] thresholds = new int[blocksX * blocksY];
			for (int by = 0; by < blocksY; by++)
			{
				for (int bx = 0; bx < blocksX; bx++)
				{
					int min = 255, max = 0;
					int endY = Math.Min(height, (by + 1) * blockSize);
					int endX = Math.Min(width, (bx + 1) * blockSize);
					for (int y = by * blockSize; y < endY; y++)
					{
						for (int x = bx * blockSize; x < endX; x++)
						{
							int value = image.Pixels[y * width + x];
							min = Math.Min(min, value);
							max = Math.Max(max, value);
						}
					}
					int threshold = max - min > 24 ? (min + max) >> 1 : globalThreshold;
					thresholds[by * blocksX + bx] = threshold;
				}
			}

			BooleanMatrix result = new(width, height);
			for (int y = 0; y < height; y++)
			{
				int by = y / blockSize;
				for (int x = 0; x < width; x++)
				{
					int bx = x / blockSize;
					int sum = 0, count = 0;
					for (int yy = Math.Max(0, by - 2); yy <= Math.Min(blocksY - 1, by + 2); yy++)
					{
						for (int xx = Math.Max(0, bx - 2); xx <= Math.Min(blocksX - 1, bx + 2); xx++)
						{
							sum += thresholds[yy * blocksX + xx];
							count++;
						}
					}

					result[x, y] = image.Pixels[y * width + x] < sum / count;
				}
			}
			return result;
		}
	}

	private static class AxisAlignedGridSampler
	{
		internal static IEnumerable<BooleanMatrix> SampleCandidates(BooleanMatrix image)
		{
			if (!TryGetDarkBounds(image, out int left, out int top, out int right, out int bottom))
			{
				yield break;
			}

			int width = right - left + 1;
			int height = bottom - top + 1;
			double aspectRatio = width / (double)height;
			if (aspectRatio < 0.8 || aspectRatio > 1.25)
			{
				yield break;
			}

			for (int version = 1; version <= 40; version++)
			{
				int dimension = 17 + version * 4;
				double moduleWidth = width / (double)dimension;
				double moduleHeight = height / (double)dimension;
				if (moduleWidth < 1.0 || moduleHeight < 1.0)
				{
					continue;
				}

				if (Math.Abs(moduleWidth - moduleHeight) > Math.Max(moduleWidth, moduleHeight) * 0.2)
				{
					continue;
				}

				BooleanMatrix centerModules = new(dimension, dimension);
				BooleanMatrix majorityModules = new(dimension, dimension);
				for (int y = 0; y < dimension; y++)
				{
					for (int x = 0; x < dimension; x++)
					{
						centerModules[x, y] = SampleModuleCenter(image, left, top, moduleWidth, moduleHeight, x, y);
						majorityModules[x, y] = SampleModule(image, left, top, moduleWidth, moduleHeight, x, y);
					}
				}
				yield return centerModules;
				yield return majorityModules;
			}
		}

		private static bool TryGetDarkBounds(BooleanMatrix image, out int left, out int top, out int right, out int bottom)
		{
			left = image.Width;
			top = image.Height;
			right = -1;
			bottom = -1;
			for (int y = 0; y < image.Height; y++)
			{
				for (int x = 0; x < image.Width; x++)
				{
					if (!image[x, y])
					{
						continue;
					}

					left = Math.Min(left, x);
					top = Math.Min(top, y);
					right = Math.Max(right, x);
					bottom = Math.Max(bottom, y);
				}
			}
			return right >= left && bottom >= top;
		}

		private static bool SampleModuleCenter(BooleanMatrix image, int left, int top, double moduleWidth, double moduleHeight, int moduleX, int moduleY)
		{
			int pixelX = (int)Math.Floor(left + (moduleX + 0.5) * moduleWidth);
			int pixelY = (int)Math.Floor(top + (moduleY + 0.5) * moduleHeight);
			return (uint)pixelX < (uint)image.Width && (uint)pixelY < (uint)image.Height && image[pixelX, pixelY];
		}
		private static bool SampleModule(BooleanMatrix image, int left, int top, double moduleWidth, double moduleHeight, int moduleX, int moduleY)
		{
			ReadOnlySpan<double> offsets = [-0.25, 0.0, 0.25];
			int dark = 0;
			foreach (double offsetY in offsets)
			{
				foreach (double offsetX in offsets)
				{
					int pixelX = (int)Math.Floor(left + (moduleX + 0.5 + offsetX) * moduleWidth);
					int pixelY = (int)Math.Floor(top + (moduleY + 0.5 + offsetY) * moduleHeight);
					if ((uint)pixelX < (uint)image.Width && (uint)pixelY < (uint)image.Height && image[pixelX, pixelY])
					{
						dark++;
					}
				}
			}
			return dark >= 5;
		}
	}

	private static class FinderDetector
	{
		internal static IEnumerable<(Finder, Finder, Finder)> FindTriples(BooleanMatrix image)
		{
			List<Finder> candidates = [];
			int[] runs = new int[5];
			for (int y = 0; y < image.Height; y++)
			{
				Array.Clear(runs);
				int state = 0;
				for (int x = 0; x < image.Width; x++)
				{
					if (image[x, y])
					{
						if ((state & 1) == 1)
						{
							state++;
						}
						runs[state]++;
					}
					else if ((state & 1) == 0)
					{
						if (state == 4)
						{
							if (IsPattern(runs))
							{
								TryAdd(image, candidates, x, y, runs);
							}
							runs[0] = runs[2];
							runs[1] = runs[3];
							runs[2] = runs[4];
							runs[3] = 1;
							runs[4] = 0;
							state = 3;
						}
						else
						{
							state++;
							runs[state]++;
						}
					}
					else
					{
						runs[state]++;
					}
				}
				if (IsPattern(runs))
				{
					TryAdd(image, candidates, image.Width, y, runs);
				}
			}

			candidates = [.. candidates.OrderByDescending(static finder => finder.Count).Take(48)];
			List<((Finder, Finder, Finder) Triple, double Score)> strictTriples = [];
			List<((Finder, Finder, Finder) Triple, double Score)> perspectiveTriples = [];
			for (int i = 0; i < candidates.Count - 2; i++)
			{
				for (int j = i + 1; j < candidates.Count - 1; j++)
				{
					for (int k = j + 1; k < candidates.Count; k++)
					{
						Finder[] ordered = Order(candidates[i], candidates[j], candidates[k]);
						double a = Distance(ordered[0], ordered[1]);
						double b = Distance(ordered[0], ordered[2]);
						double c = Distance(ordered[1], ordered[2]);
						double module = (ordered[0].Module + ordered[1].Module + ordered[2].Module) / 3.0;
						double dot = Math.Abs((ordered[1].X - ordered[0].X) * (ordered[2].X - ordered[0].X) + (ordered[1].Y - ordered[0].Y) * (ordered[2].Y - ordered[0].Y));
						double legDifference = Math.Abs(a - b);
						double longestLeg = Math.Max(a, b);

						if (a >= module * 10 && b >= module * 10 && legDifference <= longestLeg * 0.25 && dot <= a * b * 0.25)
						{
							strictTriples.Add(((ordered[0], ordered[1], ordered[2]), legDifference + dot / longestLeg));
							continue;
						}

						// Strong perspective can make the finder-center legs substantially different in image space.
						// These candidates run only after the original strict set and still require full QR validation.
						if (a >= module * 8 && b >= module * 8 && legDifference <= longestLeg * 0.65 && dot <= a * b * 0.45 && c >= longestLeg * 0.90)
						{
							perspectiveTriples.Add(((ordered[0], ordered[1], ordered[2]), legDifference + dot / longestLeg));
						}
					}
				}
			}

			return strictTriples.OrderBy(static item => item.Score).Take(32).Select(static item => item.Triple)
				.Concat(perspectiveTriples.OrderBy(static item => item.Score).Take(32).Select(static item => item.Triple));
		}
		private static bool IsPattern(int[] r)
		{
			int total = r[0] + r[1] + r[2] + r[3] + r[4];
			if (total < 7)
			{
				return false;
			}

			double unit = total / 7.0;
			double tolerance = unit * 0.7;
			return Math.Abs(r[0] - unit) < tolerance && Math.Abs(r[1] - unit) < tolerance && Math.Abs(r[2] - 3 * unit) < 3 * tolerance && Math.Abs(r[3] - unit) < tolerance && Math.Abs(r[4] - unit) < tolerance;
		}

		private static void TryAdd(BooleanMatrix image, List<Finder> candidates, int endX, int y, int[] runs)
		{
			int total = runs[0] + runs[1] + runs[2] + runs[3] + runs[4];
			double centerX = endX - runs[4] - runs[3] - runs[2] / 2.0;
			if (!CrossCheck(image, (int)Math.Round(centerX), y, runs[2], total, true, out double centerY) || !CrossCheck(image, (int)Math.Round(centerY), (int)Math.Round(centerX), runs[2], total, false, out double checkedX))
			{
				return;
			}

			double module = total / 7.0;
			for (int i = 0; i < candidates.Count; i++)
			{
				Finder old = candidates[i];
				if (Math.Abs(old.X - checkedX) <= module && Math.Abs(old.Y - centerY) <= module && Math.Abs(old.Module - module) <= module)
				{
					int count = old.Count + 1;
					candidates[i] = new Finder((old.X * old.Count + checkedX) / count, (old.Y * old.Count + centerY) / count, (old.Module * old.Count + module) / count, count);
					return;
				}
			}
			candidates.Add(new Finder(checkedX, centerY, module, 1));
		}

		private static bool CrossCheck(BooleanMatrix image, int fixedCoordinate, int center, int maxRun, int expectedTotal, bool vertical, out double result)
		{
			result = 0;
			int limit = vertical ? image.Height : image.Width;
			int[] r = new int[5];
			int i = center;
			bool Get(int p) => vertical ? image[fixedCoordinate, p] : image[p, fixedCoordinate];
			while (i >= 0 && Get(i) && r[2] <= maxRun)
			{
				r[2]++;
				i--;
			}
			if (i < 0 || r[2] > maxRun)
			{
				return false;
			}

			while (i >= 0 && !Get(i) && r[1] <= maxRun)
			{
				r[1]++;
				i--;
			}
			if (i < 0 || r[1] > maxRun)
			{
				return false;
			}

			while (i >= 0 && Get(i) && r[0] <= maxRun)
			{
				r[0]++;
				i--;
			}
			if (r[0] > maxRun)
			{
				return false;
			}

			i = center + 1;
			while (i < limit && Get(i) && r[2] <= maxRun)
			{
				r[2]++;
				i++;
			}
			while (i < limit && !Get(i) && r[3] <= maxRun)
			{
				r[3]++;
				i++;
			}
			if (i == limit || r[3] > maxRun)
			{
				return false;
			}

			while (i < limit && Get(i) && r[4] <= maxRun)
			{
				r[4]++;
				i++;
			}
			if (r[4] > maxRun || Math.Abs(r[0] + r[1] + r[2] + r[3] + r[4] - expectedTotal) * 5 >= expectedTotal * 2 || !IsPattern(r))
			{
				return false;
			}

			result = i - r[4] - r[3] - r[2] / 2.0;
			return true;
		}

		private static Finder[] Order(Finder a, Finder b, Finder c)
		{
			double ab = Distance(a, b), ac = Distance(a, c), bc = Distance(b, c);
			Finder topLeft, p1, p2;
			if (bc >= ab && bc >= ac)
			{
				topLeft = a;
				p1 = b;
				p2 = c;
			}
			else if (ac >= ab)
			{
				topLeft = b;
				p1 = a;
				p2 = c;
			}
			else
			{
				topLeft = c;
				p1 = a;
				p2 = b;
			}
			double cross = (p1.X - topLeft.X) * (p2.Y - topLeft.Y) - (p1.Y - topLeft.Y) * (p2.X - topLeft.X);
			return cross > 0 ? [topLeft, p1, p2] : [topLeft, p2, p1];
		}
		private static double Distance(Finder a, Finder b) => Math.Sqrt((a.X - b.X) * (a.X - b.X) + (a.Y - b.Y) * (a.Y - b.Y));
	}

	private static class GridSampler
	{
		internal static BooleanMatrix[] SampleCandidates(BooleanMatrix image, Finder tl, Finder tr, Finder bl)
		{
			double module = (tl.Module + tr.Module + bl.Module) / 3.0;
			if (!double.IsFinite(module) || module <= 0.0)
			{
				throw new QrException("Finder patterns produced an invalid module size.");
			}

			double horizontalModules = Distance(tr.X - tl.X, tr.Y - tl.Y) / module + 7.0;
			double verticalModules = Distance(bl.X - tl.X, bl.Y - tl.Y) / module + 7.0;
			double estimatedDimensionValue = Math.Round((horizontalModules + verticalModules) / 2.0);
			if (!double.IsFinite(estimatedDimensionValue) || estimatedDimensionValue < 21.0 || estimatedDimensionValue > 177.0)
			{
				throw new QrException("Finder patterns produced an invalid QR dimension.");
			}

			int estimatedDimension = (int)estimatedDimensionValue;
			int estimatedVersion = Math.Clamp((estimatedDimension - 17 + 2) / 4, 1, 40);
			const int versionSearchRadius = 4;
			int firstVersion = Math.Max(1, estimatedVersion - versionSearchRadius);
			int lastVersion = Math.Min(40, estimatedVersion + versionSearchRadius);
			int[] versions = [.. Enumerable.Range(firstVersion, lastVersion - firstVersion + 1).OrderBy(version => Math.Abs(version - estimatedVersion))];
			List<BooleanMatrix> candidates = [with(versions.Length)];
			List<string> failures = [with(versions.Length)];
			foreach (int version in versions)
			{
				int dimension = 17 + 4 * version;
				AddSampleCandidate(image, tl, tr, bl, dimension, false, true, candidates, failures);
				AddSampleCandidate(image, tl, tr, bl, dimension, true, true, candidates, failures);

				// A blurred image can create a false alignment-pattern match. Finder-only sampling is
				// an additional candidate and never replaces the existing alignment-based candidates.
				if (dimension > 21)
				{
					AddSampleCandidate(image, tl, tr, bl, dimension, false, false, candidates, failures);
					AddSampleCandidate(image, tl, tr, bl, dimension, true, false, candidates, failures);
				}
			}
			if (candidates.Count == 0)
			{
				throw new QrException($"Every sampled version failed.{Environment.NewLine}{string.Join(Environment.NewLine, failures)}");
			}
			return [.. candidates];
		}

		private static void AddSampleCandidate(BooleanMatrix image, Finder tl, Finder tr, Finder bl, int dimension, bool centerOnly, bool useAlignmentPattern, List<BooleanMatrix> candidates, List<string> failures)
		{
			try
			{
				candidates.Add(SampleVersion(image, tl, tr, bl, dimension, centerOnly, useAlignmentPattern));
			}
			catch (Exception exception) when (exception is QrException or ArithmeticException)
			{
				failures.Add($"{dimension}x{dimension}, {(centerOnly ? "center" : "majority")}, {(useAlignmentPattern ? "alignment" : "finder-only")}: {exception.GetType().Name}: {exception.Message}");
			}
		}

		private static BooleanMatrix SampleVersion(BooleanMatrix image, Finder tl, Finder tr, Finder bl, int dimension, bool centerOnly, bool useAlignmentPattern)
		{
			double horizontalModuleX = (tr.X - tl.X) / (dimension - 7.0);
			double horizontalModuleY = (tr.Y - tl.Y) / (dimension - 7.0);
			double verticalModuleX = (bl.X - tl.X) / (dimension - 7.0);
			double verticalModuleY = (bl.Y - tl.Y) / (dimension - 7.0);
			PointD fourthTarget;
			PointD fourthSource;
			if (useAlignmentPattern && dimension > 21 && TryFindAlignmentPattern(image, tl, horizontalModuleX, horizontalModuleY, verticalModuleX, verticalModuleY, dimension, out PointD alignment))
			{
				fourthTarget = alignment;
				fourthSource = new PointD(dimension - 6.5, dimension - 6.5);
			}
			else
			{
				fourthTarget = new PointD(tr.X + bl.X - tl.X, tr.Y + bl.Y - tl.Y);
				fourthSource = new PointD(dimension - 3.5, dimension - 3.5);
			}
			PointD[] source = [new(3.5, 3.5), new(dimension - 3.5, 3.5), fourthSource, new(3.5, dimension - 3.5)];
			PointD[] target = [new(tl.X, tl.Y), new(tr.X, tr.Y), fourthTarget, new(bl.X, bl.Y)];
			double[] transform = Homography.Compute(source, target);
			BooleanMatrix result = new(dimension, dimension);
			for (int y = 0; y < dimension; y++)
			{
				for (int x = 0; x < dimension; x++)
				{
					result[x, y] = SampleModule(image, transform, x, y, centerOnly);
				}
			}
			return result;
		}

		private static bool TryFindAlignmentPattern(BooleanMatrix image, Finder topLeft, double horizontalX, double horizontalY, double verticalX, double verticalY, int dimension, out PointD alignment)
		{
			double moduleSize = (Math.Sqrt(horizontalX * horizontalX + horizontalY * horizontalY) + Math.Sqrt(verticalX * verticalX + verticalY * verticalY)) / 2.0;
			double offset = dimension - 10.0;
			double predictedX = topLeft.X + offset * horizontalX + offset * verticalX;
			double predictedY = topLeft.Y + offset * horizontalY + offset * verticalY;
			int radius = Math.Max(4, (int)Math.Ceiling(moduleSize * 6.0));
			int step = Math.Max(1, (int)Math.Floor(moduleSize / 2.0));
			int bestScore = int.MaxValue;
			PointD best = default;
			for (int y = (int)Math.Round(predictedY) - radius; y <= (int)Math.Round(predictedY) + radius; y += step)
			{
				for (int x = (int)Math.Round(predictedX) - radius; x <= (int)Math.Round(predictedX) + radius; x += step)
				{
					int score = ScoreAlignmentPattern(image, x, y, horizontalX, horizontalY, verticalX, verticalY);
					if (score < bestScore)
					{
						bestScore = score;
						best = new PointD(x, y);
					}
				}
			}
			alignment = best;
			return bestScore <= 5;
		}

		private static int ScoreAlignmentPattern(BooleanMatrix image, int centerX, int centerY, double horizontalX, double horizontalY, double verticalX, double verticalY)
		{
			int score = 0;
			for (int moduleY = -2; moduleY <= 2; moduleY++)
			{
				for (int moduleX = -2; moduleX <= 2; moduleX++)
				{
					double sampleX = centerX + moduleX * horizontalX + moduleY * verticalX;
					double sampleY = centerY + moduleX * horizontalY + moduleY * verticalY;
					bool expectedDark = Math.Max(Math.Abs(moduleX), Math.Abs(moduleY)) is 0 or 2;
					if (SampleNeighborhood(image, sampleX, sampleY) != expectedDark)
					{
						score++;
					}
				}
			}
			return score;
		}

		private static bool SampleNeighborhood(BooleanMatrix image, double x, double y)
		{
			int centerX = (int)Math.Round(x);
			int centerY = (int)Math.Round(y);
			int dark = 0;
			int valid = 0;
			for (int offsetY = -1; offsetY <= 1; offsetY++)
			{
				for (int offsetX = -1; offsetX <= 1; offsetX++)
				{
					int pixelX = centerX + offsetX;
					int pixelY = centerY + offsetY;
					if ((uint)pixelX >= (uint)image.Width || (uint)pixelY >= (uint)image.Height)
					{
						continue;
					}
					if (image[pixelX, pixelY])
					{
						dark++;
					}
					valid++;
				}
			}
			return valid > 0 && dark * 2 >= valid;
		}

		private static bool SampleModule(BooleanMatrix image, double[] transform, int moduleX, int moduleY, bool centerOnly)
		{
			ReadOnlySpan<double> offsets = centerOnly ? [0.0] : [-0.25, 0.0, 0.25];
			int darkSamples = 0;
			int validSamples = 0;
			foreach (double offsetY in offsets)
			{
				foreach (double offsetX in offsets)
				{
					double x = moduleX + 0.5 + offsetX;
					double y = moduleY + 0.5 + offsetY;
					double denominator = transform[6] * x + transform[7] * y + 1.0;
					if (!double.IsFinite(denominator) || Math.Abs(denominator) < 1e-12)
					{
						continue;
					}

					double transformedX = (transform[0] * x + transform[1] * y + transform[2]) / denominator;
					double transformedY = (transform[3] * x + transform[4] * y + transform[5]) / denominator;
					if (!double.IsFinite(transformedX) || !double.IsFinite(transformedY))
					{
						continue;
					}

					double flooredX = Math.Floor(transformedX);
					double flooredY = Math.Floor(transformedY);
					if (flooredX < 0.0 || flooredX >= image.Width || flooredY < 0.0 || flooredY >= image.Height)
					{
						continue;
					}

					int pixelX = (int)flooredX;
					int pixelY = (int)flooredY;
					if (image[pixelX, pixelY])
					{
						darkSamples++;
					}

					validSamples++;
				}
			}
			if (validSamples < (centerOnly ? 1 : 5))
			{
				throw new QrException($"Insufficient in-bounds samples for module ({moduleX}, {moduleY}).");
			}

			return darkSamples * 2 >= validSamples;
		}

		private static double Distance(double x, double y) => Math.Sqrt(x * x + y * y);
	}

	private static class Homography
	{
		internal static double[] Compute(PointD[] source, PointD[] target)
		{
			double[][] a = [new double[9], new double[9], new double[9], new double[9], new double[9], new double[9], new double[9], new double[9]];
			for (int i = 0; i < 4; i++)
			{
				double x = source[i].X, y = source[i].Y, u = target[i].X, v = target[i].Y;
				int r = i * 2;
				a[r][0] = x;
				a[r][1] = y;
				a[r][2] = 1;
				a[r][6] = -u * x;
				a[r][7] = -u * y;
				a[r][8] = u;
				a[r + 1][3] = x;
				a[r + 1][4] = y;
				a[r + 1][5] = 1;
				a[r + 1][6] = -v * x;
				a[r + 1][7] = -v * y;
				a[r + 1][8] = v;
			}
			for (int column = 0; column < 8; column++)
			{
				int pivot = column;

				for (int row = column + 1; row < 8; row++)
				{
					if (Math.Abs(a[row][column]) > Math.Abs(a[pivot][column]))
					{
						pivot = row;
					}
				}

				if (Math.Abs(a[pivot][column]) < 1e-10)
				{
					throw new QrException("Degenerate perspective transform.");
				}

				for (int j = column; j < 9; j++)
				{
					(a[column][j], a[pivot][j]) = (a[pivot][j], a[column][j]);
				}

				double divisor = a[column][column];

				for (int j = column; j < 9; j++)
				{
					a[column][j] /= divisor;
				}

				for (int row = 0; row < 8; row++)
				{
					if (row != column)
					{
						double factor = a[row][column];
						for (int j = column; j < 9; j++)
						{
							a[row][j] -= factor * a[column][j];
						}
					}
				}
			}
			double[] result = new double[8];
			for (int i = 0; i < 8; i++)
			{
				result[i] = a[i][8];
			}

			return result;
		}
	}

	private static class MatrixParser
	{
		private static readonly int[][] s_eccPerBlock =
		[
			[0,7,10,15,20,26,18,20,24,30,18,20,24,26,30,22,24,28,30,28,28,28,28,30,30,26,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],
		[0,10,16,26,18,24,16,18,22,22,26,30,22,22,24,24,28,28,26,26,26,26,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28],
		[0,13,22,18,26,18,24,18,22,20,24,28,26,24,20,30,24,28,28,26,30,28,30,30,30,30,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],
		[0,17,28,22,16,22,28,26,26,24,28,24,28,22,24,24,30,28,28,26,28,30,24,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30]
		];
		private static readonly int[][] s_blockCount =
		[
			[0,1,1,1,1,1,2,2,2,2,4,4,4,4,4,6,6,6,6,7,8,8,9,9,10,12,12,12,13,14,15,16,17,18,19,19,20,21,22,24,25],
		[0,1,1,1,2,2,4,4,4,5,5,5,8,9,9,10,10,11,13,14,16,17,17,18,20,21,23,25,26,28,29,31,33,35,37,38,40,43,45,47,49],
		[0,1,1,2,2,4,4,6,6,8,8,8,10,12,16,12,17,16,18,21,20,23,23,25,27,29,34,34,35,38,40,43,45,48,51,53,56,59,62,65,68],
		[0,1,1,2,4,4,4,5,6,8,8,11,11,16,16,18,16,19,21,25,25,25,34,30,32,35,37,40,42,45,48,51,54,57,60,63,66,70,74,77,81]
		];

		internal static bool HasValidFormatInformation(BooleanMatrix matrix)
		{
			try
			{
				_ = ReadFormat(matrix);
				return true;
			}
			catch (Exception exception) when (exception is QrException or ArithmeticException)
			{
				return false;
			}
		}

		internal static QrResult Decode(BooleanMatrix matrix) => DecodeCore(matrix, false, false, 0, 0, 0, 0);

		internal static QrResult DecodeStylized(BooleanMatrix matrix) => DecodeCore(matrix, true, false, 0, 0, 0, 0);

		internal static QrResult DecodeWithKnownFormatAndErasures(BooleanMatrix matrix, int ecIndex, int mask, int left, int top, int right, int bottom)
		{
			if ((uint)ecIndex >= 4U || (uint)mask >= 8U)
			{
				throw new QrException("Invalid known QR format parameters.");
			}

			if (matrix.Width != matrix.Height || matrix.Width < 21 || matrix.Width > 177 || ((matrix.Width - 17) & 3) != 0)
			{
				throw new QrException("Invalid QR dimensions.");
			}

			int version = (matrix.Width - 17) / 4;
			bool[][] function = BuildFunctionMap(version);
			byte[] raw = ReadCodewords(matrix, function, mask, GetRawCodewords(version), false, left, top, right, bottom, out bool[] erasedCodewords);
			byte[] data = CorrectAndDeinterleave(raw, erasedCodewords, version, ecIndex, true);
			string text = PayloadDecoder.Decode(data, version);
			char ec = ecIndex switch
			{
				0 => 'L',
				1 => 'M',
				2 => 'Q',
				_ => 'H'
			};
			return new QrResult(string.Empty, text, version, ec, mask, default, null);
		}

		private static QrResult DecodeCore(BooleanMatrix matrix, bool useCenterErasures, bool repairTrailingCodewords, int erasureLeft, int erasureTop, int erasureRight, int erasureBottom)
		{
			if (matrix.Width != matrix.Height || matrix.Width < 21 || matrix.Width > 177 || ((matrix.Width - 17) & 3) != 0)
			{
				throw new QrException("Invalid QR dimensions.");
			}

			int version = (matrix.Width - 17) / 4;
			(int ecIndex, int mask) = ReadFormat(matrix);
			bool[][] function = BuildFunctionMap(version);
			byte[] raw = ReadCodewords(matrix, function, mask, GetRawCodewords(version), useCenterErasures, erasureLeft, erasureTop, erasureRight, erasureBottom, out bool[] erasedCodewords);
			byte[] data = CorrectAndDeinterleave(raw, erasedCodewords, version, ecIndex, repairTrailingCodewords);
			string text = PayloadDecoder.Decode(data, version);
			char ec = ecIndex switch
			{
				0 => 'L',
				1 => 'M',
				2 => 'Q',
				_ => 'H'
			};
			return new QrResult(string.Empty, text, version, ec, mask, default, null);
		}

		private static (int, int) ReadFormat(BooleanMatrix matrix)
		{
			int first = 0;
			for (int i = 0; i <= 5; i++)
			{
				first = (first << 1) | Bit(matrix, 8, i);
			}

			first = (first << 1) | Bit(matrix, 8, 7);
			first = (first << 1) | Bit(matrix, 8, 8);
			first = (first << 1) | Bit(matrix, 7, 8);
			for (int i = 5; i >= 0; i--)
			{
				first = (first << 1) | Bit(matrix, i, 8);
			}

			int second = 0;
			for (int i = matrix.Height - 1; i >= matrix.Height - 7; i--)
			{
				second = (second << 1) | Bit(matrix, 8, i);
			}

			for (int i = matrix.Width - 8; i < matrix.Width; i++)
			{
				second = (second << 1) | Bit(matrix, i, 8);
			}

			int bestDistance = int.MaxValue, bestData = -1;
			for (int data = 0; data < 32; data++)
			{
				int encoded = EncodeFormat(data);
				int distance = Math.Min(System.Numerics.BitOperations.PopCount((uint)(first ^ encoded)), System.Numerics.BitOperations.PopCount((uint)(second ^ encoded)));
				if (distance < bestDistance)
				{
					bestDistance = distance;
					bestData = data;
				}
			}
			if (bestDistance > 3)
			{
				throw new QrException("Format information is too damaged.");
			}

			int ecBits = bestData >> 3;
			int ecIndex = ecBits switch
			{
				1 => 0,
				0 => 1,
				3 => 2,
				2 => 3,
				_ => throw new QrException("Invalid EC level.")
			};
			return (ecIndex, bestData & 7);
		}

		private static int EncodeFormat(int data)
		{
			int value = data << 10;
			int generator = 0x537;
			while (HighestBit(value) >= 10)
			{
				value ^= generator << (HighestBit(value) - 10);
			}

			return ((data << 10) | value) ^ 0x5412;
		}
		private static int HighestBit(int value) => value == 0 ? -1 : 31 - System.Numerics.BitOperations.LeadingZeroCount((uint)value);
		private static int Bit(BooleanMatrix matrix, int x, int y) => matrix[x, y] ? 1 : 0;

		private static bool[][] BuildFunctionMap(int version)
		{
			int size = 17 + version * 4;
			bool[][] map = [.. Enumerable.Range(0, size).Select(_ => new bool[size])];
			MarkRect(map, 0, 0, 9, 9);
			MarkRect(map, size - 8, 0, 8, 9);
			MarkRect(map, 0, size - 8, 9, 8);
			for (int i = 0;
				i < size; i++)
			{
				map[6][i] = true;
				map[i][6] = true;
			}
			int[] centers = AlignmentCenters(version);
			foreach (int y in centers)
			{
				foreach (int x in centers)
				{
					if ((x <= 8 && y <= 8) || (x >= size - 8 && y <= 8) || (x <= 8 && y >= size - 8))
					{
						continue;
					}

					MarkRect(map, x - 2, y - 2, 5, 5);
				}
			}

			if (version >= 7)
			{
				MarkRect(map, size - 11, 0, 3, 6);
				MarkRect(map, 0, size - 11, 6, 3);
			}
			map[8][size - 8] = true;
			return map;
		}

		private static void MarkRect(bool[][] map, int left, int top, int width, int height)
		{
			int size = map.Length;
			for (int y = Math.Max(0, top); y < Math.Min(size, top + height); y++)
			{
				for (int x = Math.Max(0, left); x < Math.Min(size, left + width); x++)
				{
					map[x][y] = true;
				}
			}
		}

		private static int[] AlignmentCenters(int version)
		{
			if (version == 1)
			{
				return [];
			}

			int count = version / 7 + 2;
			int step = version == 32 ? 26 : (version * 4 + count * 2 + 1) / (count * 2 - 2) * 2;
			int[] result = new int[count];
			result[0] = 6;
			for (int i = count - 1, position = version * 4 + 10; i >= 1; i--, position -= step)
			{
				result[i] = position;
			}

			return result;
		}

		private static byte[] ReadCodewords(BooleanMatrix matrix, bool[][] function, int mask, int count, bool useCenterErasures, int erasureLeft, int erasureTop, int erasureRight, int erasureBottom, out bool[] erasedCodewords)
		{
			byte[] result = new byte[count];
			erasedCodewords = new bool[count];
			int center = matrix.Width / 2;
			int erasureRadius = Math.Max(4, matrix.Width / 10);
			int bitIndex = 0;
			bool upward = true;
			for (int right = matrix.Width - 1; right >= 1; right -= 2)
			{
				if (right == 6)
				{
					right--;
				}

				for (int vertical = 0; vertical < matrix.Height; vertical++)
				{
					int y = upward ? matrix.Height - 1 - vertical : vertical;
					for (int offset = 0; offset < 2; offset++)
					{
						int x = right - offset;
						if (function[x][y])
						{
							continue;
						}

						bool value = matrix[x, y] ^ Mask(mask, x, y);
						if (bitIndex < count * 8)
						{
							int codeword = bitIndex >> 3;
							if (value)
							{
								result[codeword] |= (byte)(1 << (7 - (bitIndex & 7)));
							}

							if ((useCenterErasures && Math.Abs(x - center) <= erasureRadius && Math.Abs(y - center) <= erasureRadius) || (x >= erasureLeft && x <= erasureRight && y >= erasureTop && y <= erasureBottom))
							{
								erasedCodewords[codeword] = true;
							}
						}
						bitIndex++;
					}
				}
				upward = !upward;
			}
			if (bitIndex < count * 8)
			{
				throw new QrException("Insufficient codewords.");
			}

			return result;
		}

		private static bool Mask(int mask, int x, int y) => mask switch
		{
			0 => ((x + y) & 1) == 0,
			1 => (y & 1) == 0,
			2 => x % 3 == 0,
			3 => (x + y) % 3 == 0,
			4 => ((y / 2) + (x / 3) & 1) == 0,
			5 => x * y % 2 + x * y % 3 == 0,
			6 => ((x * y % 2 + x * y % 3) & 1) == 0,
			7 => (((x + y) % 2 + x * y % 3) & 1) == 0,
			_ => false
		};

		private static byte[] CorrectAndDeinterleave(byte[] raw, bool[] rawErasures, int version, int ecIndex, bool repairTrailingCodewords)
		{
			int blockCount = s_blockCount[ecIndex][version];
			int ecLength = s_eccPerBlock[ecIndex][version];
			int shortBlockLength = raw.Length / blockCount;
			int longBlockCount = raw.Length % blockCount;
			int shortBlockCount = blockCount - longBlockCount;
			int shortDataLength = shortBlockLength - ecLength;
			byte[][] blocks = new byte[blockCount][];
			bool[][] erasures = new bool[blockCount][];
			for (int block = 0; block < blockCount; block++)
			{
				blocks[block] = new byte[shortBlockLength + (block >= shortBlockCount ? 1 : 0)];
				erasures[block] = new bool[blocks[block].Length];
			}
			int offset = 0;
			for (int i = 0; i < shortDataLength; i++)
			{
				for (int block = 0; block < blockCount; block++)
				{
					blocks[block][i] = raw[offset];
					erasures[block][i] = rawErasures[offset++];
				}
			}

			for (int block = shortBlockCount; block < blockCount; block++)
			{
				blocks[block][shortDataLength] = raw[offset];
				erasures[block][shortDataLength] = rawErasures[offset++];
			}
			for (int i = 0; i < ecLength; i++)
			{
				for (int block = 0; block < blockCount; block++)
				{
					int position = blocks[block].Length - ecLength + i;
					blocks[block][position] = raw[offset];
					erasures[block][position] = rawErasures[offset++];
				}
			}

			if (offset != raw.Length)
			{
				throw new QrException("Interleaving structure is inconsistent.");
			}

			byte[] data = new byte[raw.Length - blockCount * ecLength];
			offset = 0;
			for (int blockIndex = 0; blockIndex < blocks.Length; blockIndex++)
			{
				byte[] block = blocks[blockIndex];
				if (repairTrailingCodewords)
				{
					int firstTrailingPosition = Math.Max(0, block.Length - 3);
					for (int position = firstTrailingPosition; position < block.Length; position++)
					{
						erasures[blockIndex][position] = true;
					}
				}
				int[] erasedPositions = [.. Enumerable.Range(0, erasures[blockIndex].Length).Where(position => erasures[blockIndex][position])];
				ReedSolomon.Correct(block, ecLength, erasedPositions);
				int length = block.Length - ecLength;
				System.Buffer.BlockCopy(block, 0, data, offset, length);
				offset += length;
			}
			return data;
		}

		private static int GetRawCodewords(int version)
		{
			int result = (16 * version + 128) * version + 64;
			if (version >= 2)
			{
				int align = version / 7 + 2;
				result -= (25 * align - 10) * align - 55;
				if (version >= 7)
				{
					result -= 36;
				}
			}
			return result / 8;
		}
	}

	private static class ReedSolomon
	{
		private static readonly int[] s_exp = new int[512];
		private static readonly int[] s_log = new int[256];

		static ReedSolomon()
		{
			int value = 1;
			for (int i = 0; i < 255; i++)
			{
				s_exp[i] = value;
				s_log[value] = i;
				value <<= 1;
				if ((value & 0x100) != 0)
				{
					value ^= 0x11D;
				}
			}
			for (int i = 255; i < s_exp.Length; i++)
			{
				s_exp[i] = s_exp[i - 255];
			}
		}

		internal static void Correct(byte[] received, int ecCount, int[] erasurePositions)
		{
			if (erasurePositions.Length > ecCount)
			{
				throw new QrException($"Reed-Solomon erasure count {erasurePositions.Length} exceeds capacity {ecCount}.");
			}

			if (erasurePositions.Length > 0)
			{
				int[] syndromes = CalculateSyndromes(received, ecCount);
				int[] magnitudes = SolveErrorMagnitudes(syndromes, erasurePositions, received.Length);
				for (int i = 0; i < erasurePositions.Length; i++)
				{
					received[erasurePositions[i]] ^= (byte)magnitudes[i];
				}
			}
			Correct(received, ecCount);
		}

		internal static void Correct(byte[] received, int ecCount)
		{
			int[] syndromes = CalculateSyndromes(received, ecCount);

			if (syndromes.All(static syndrome => syndrome == 0))
			{
				return;
			}

			int[] locator = FindErrorLocator(syndromes, ecCount, out int errorCount);
			if (errorCount <= 0 || errorCount * 2 > ecCount)
			{
				throw new QrException("Reed-Solomon error count exceeds correction capacity.");
			}

			int[] positions = FindErrorPositions(locator, errorCount, received.Length);
			int[] magnitudes = SolveErrorMagnitudes(syndromes, positions, received.Length);
			for (int i = 0; i < positions.Length; i++)
			{
				received[positions[i]] ^= (byte)magnitudes[i];
			}

			int[] correctedSyndromes = CalculateSyndromes(received, ecCount);
			if (correctedSyndromes.Any(static syndrome => syndrome != 0))
			{
				throw new QrException("Reed-Solomon correction failed validation.");
			}
		}

		private static int[] CalculateSyndromes(byte[] received, int ecCount)
		{
			int[] syndromes = new int[ecCount];
			for (int i = 0; i < ecCount; i++)
			{
				int evaluation = 0;
				int alpha = s_exp[i];
				foreach (byte value in received)
				{
					evaluation = Multiply(evaluation, alpha) ^ value;
				}

				syndromes[i] = evaluation;
			}
			return syndromes;
		}

		private static int[] FindErrorLocator(int[] syndromes, int ecCount, out int errorCount)
		{
			int[] locator = new int[ecCount + 1];
			int[] previous = new int[ecCount + 1];
			locator[0] = 1;
			previous[0] = 1;
			int degree = 0;
			int shift = 1;
			int previousDiscrepancy = 1;

			for (int index = 0; index < ecCount; index++)
			{
				int discrepancy = syndromes[index];
				for (int i = 1; i <= degree; i++)
				{
					discrepancy ^= Multiply(locator[i], syndromes[index - i]);
				}

				if (discrepancy == 0)
				{
					shift++;
					continue;
				}

				int[] saved = (int[])locator.Clone();
				int scale = Multiply(discrepancy, Inverse(previousDiscrepancy));
				for (int i = 0; i + shift < locator.Length; i++)
				{
					if (previous[i] != 0)
					{
						locator[i + shift] ^= Multiply(scale, previous[i]);
					}
				}

				if (degree * 2 <= index)
				{
					degree = index + 1 - degree;
					previous = saved;
					previousDiscrepancy = discrepancy;
					shift = 1;
				}
				else
				{
					shift++;
				}
			}

			errorCount = degree;
			return locator;
		}

		private static int[] FindErrorPositions(int[] locator, int errorCount, int receivedLength)
		{
			int[] positions = new int[errorCount];
			int found = 0;
			for (int position = 0; position < receivedLength && found < errorCount; position++)
			{
				int location = s_exp[(receivedLength - 1 - position) % 255];
				int inverseLocation = Inverse(location);
				int evaluation = 0;
				int power = 1;
				for (int degree = 0; degree <= errorCount; degree++)
				{
					evaluation ^= Multiply(locator[degree], power);
					power = Multiply(power, inverseLocation);
				}
				if (evaluation == 0)
				{
					positions[found++] = position;
				}
			}
			if (found != errorCount)
			{
				throw new QrException($"Reed-Solomon located {found} of {errorCount} error positions.");
			}

			return positions;
		}

		private static int[] SolveErrorMagnitudes(int[] syndromes, int[] positions, int receivedLength)
		{
			int count = positions.Length;
			int[][] matrix = [.. Enumerable.Range(0, count).Select(_ => new int[count + 1])];
			for (int row = 0; row < count; row++)
			{
				for (int column = 0; column < count; column++)
				{
					int exponent = (receivedLength - 1 - positions[column]) * row % 255;
					matrix[row][column] = s_exp[exponent];
				}
				matrix[row][count] = syndromes[row];
			}

			for (int column = 0; column < count; column++)
			{
				int pivot = column;
				while (pivot < count && matrix[pivot][column] == 0)
				{
					pivot++;
				}

				if (pivot == count)
				{
					throw new QrException("Reed-Solomon magnitude matrix is singular.");
				}

				if (pivot != column)
				{
					for (int i = column; i <= count; i++)
					{
						(matrix[column][i], matrix[pivot][i]) = (matrix[pivot][i], matrix[column][i]);
					}
				}

				int inversePivot = Inverse(matrix[column][column]);
				for (int i = column; i <= count; i++)
				{
					matrix[column][i] = Multiply(matrix[column][i], inversePivot);
				}

				for (int row = 0; row < count; row++)
				{
					if (row == column)
					{
						continue;
					}

					int factor = matrix[row][column];
					if (factor == 0)
					{
						continue;
					}

					for (int i = column; i <= count; i++)
					{
						matrix[row][i] ^= Multiply(factor, matrix[column][i]);
					}
				}
			}

			int[] magnitudes = new int[count];
			for (int i = 0; i < count; i++)
			{
				magnitudes[i] = matrix[i][count];
			}

			return magnitudes;
		}

		internal static int Multiply(int a, int b) => a == 0 || b == 0 ? 0 : s_exp[s_log[a] + s_log[b]];
		private static int Inverse(int value)
		{
			if (value == 0)
			{
				throw new QrException("GF(256) inverse of zero.");
			}

			return s_exp[255 - s_log[value]];
		}
	}

	private static class PayloadDecoder
	{
		private const string Alphanumeric = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
		private static readonly Encoding s_cp437 = CreateCodePageEncoding(437);
		private static readonly Encoding s_big5 = CreateCodePageEncoding(950);

		internal static string Decode(byte[] data, int version)
		{
			BitReader bits = new(data);
			StringBuilder result = new(data.Length);
			Encoding currentEncoding = Encoding.Latin1;
			bool fnc1 = false;
			while (bits.Available >= 4)
			{
				int mode = bits.Read(4);
				if (mode == 0)
				{
					break;
				}

				switch (mode)
				{
					case 1: DecodeNumeric(bits, ReadCount(bits, version, 10, 12, 14), result); break;
					case 2: DecodeAlphanumeric(bits, ReadCount(bits, version, 9, 11, 13), result, fnc1); break;
					case 3: bits.Skip(16); break;
					case 4: DecodeBytes(bits, ReadCount(bits, version, 8, 16, 16), result, currentEncoding); break;
					case 5:
					case 9: fnc1 = true; if (mode == 9) { bits.Skip(8); } break;
					case 7: currentEncoding = EncodingForEci(ReadEci(bits)); break;
					case 8: DecodeKanjiAsEscapedBytes(bits, ReadCount(bits, version, 8, 10, 12), result); break;
					case 13: DecodeHanziAsEscapedBytes(bits, version, result); break;
					default: throw new QrException($"Unsupported QR mode indicator: {mode}.");
				}
			}
			return result.ToString();
		}

		private static int ReadCount(BitReader bits, int version, int small, int medium, int large) => bits.Read(version <= 9 ? small : version <= 26 ? medium : large);

		private static void DecodeNumeric(BitReader bits, int count, StringBuilder output)
		{
			while (count >= 3)
			{
				int value = bits.Read(10);
				if (value >= 1000)
				{
					throw new QrException("Invalid numeric segment.");
				}

				_ = output.Append((char)('0' + value / 100));
				_ = output.Append((char)('0' + value / 10 % 10));
				_ = output.Append((char)('0' + value % 10));
				count -= 3;
			}
			if (count == 2)
			{
				int value = bits.Read(7);
				if (value >= 100)
				{
					throw new QrException("Invalid numeric segment.");
				}

				_ = output.Append((char)('0' + value / 10));
				_ = output.Append((char)('0' + value % 10));
			}
			else if (count == 1)
			{
				int value = bits.Read(4);
				if (value >= 10)
				{
					throw new QrException("Invalid numeric segment.");
				}

				_ = output.Append((char)('0' + value));
			}
		}

		private static void DecodeAlphanumeric(BitReader bits, int count, StringBuilder output, bool fnc1)
		{
			int start = output.Length;
			while (count >= 2)
			{
				int value = bits.Read(11);
				if (value >= 45 * 45)
				{
					throw new QrException("Invalid alphanumeric segment.");
				}

				_ = output.Append(Alphanumeric[value / 45]);
				_ = output.Append(Alphanumeric[value % 45]);
				count -= 2;
			}
			if (count == 1)
			{
				int value = bits.Read(6);
				if (value >= 45)
				{
					throw new QrException("Invalid alphanumeric segment.");
				}

				_ = output.Append(Alphanumeric[value]);
			}

			if (!fnc1)
			{
				return;
			}

			for (int i = start; i < output.Length; i++)
			{
				if (output[i] == '%')
				{
					if (i + 1 < output.Length && output[i + 1] == '%')
					{
						_ = output.Remove(i + 1, 1);
					}
					else
					{
						output[i] = (char)29;
					}
				}
			}
		}

		private static void DecodeBytes(BitReader bits, int count, StringBuilder output, Encoding encoding)
		{
			byte[] bytes = new byte[count];

			for (int i = 0; i < count; i++)
			{
				bytes[i] = (byte)bits.Read(8);
			}

			_ = ReferenceEquals(encoding, Encoding.Latin1) && IsUtf8(bytes)
				? output.Append(Encoding.UTF8.GetString(bytes))
				: output.Append(encoding.GetString(bytes));
		}

		private static bool IsUtf8(byte[] bytes)
		{
			try
			{
				_ = new UTF8Encoding(false, true).GetString(bytes);
				return bytes.Any(static value => value >= 0x80);
			}
			catch (DecoderFallbackException)
			{
				return false;
			}
		}

		private static int ReadEci(BitReader bits)
		{
			int first = bits.Read(8);
			if ((first & 0x80) == 0)
			{
				return first & 0x7F;
			}

			if ((first & 0xC0) == 0x80)
			{
				return ((first & 0x3F) << 8) | bits.Read(8);
			}

			if ((first & 0xE0) == 0xC0)
			{
				return ((first & 0x1F) << 16) | bits.Read(16);
			}

			throw new QrException("Invalid ECI designator.");
		}

		private static Encoding EncodingForEci(int eci) => eci switch
		{
			0 or 2 => s_cp437,
			1 or 3 => Encoding.Latin1,
			25 => Encoding.BigEndianUnicode,
			26 => Encoding.UTF8,
			27 or 170 => Encoding.ASCII,
			28 => s_big5,
			_ => throw new QrException($"Unsupported ECI assignment {eci} without an external code-page provider.")
		};

		private static Encoding CreateCodePageEncoding(int codePage)
		{
			Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
			return Encoding.GetEncoding(codePage, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
		}

		private static void DecodeKanjiAsEscapedBytes(BitReader bits, int count, StringBuilder output)
		{
			for (int i = 0; i < count; i++)
			{
				int value = bits.Read(13);
				int assembled = (value / 0xC0 << 8) | value % 0xC0;
				assembled += assembled < 0x1F00 ? 0x8140 : 0xC140;
				AppendEscapedByte(output, assembled >> 8);
				AppendEscapedByte(output, assembled & 0xFF);
			}
		}

		private static void DecodeHanziAsEscapedBytes(BitReader bits, int version, StringBuilder output)
		{
			int subset = bits.Read(4);
			if (subset != 1)
			{
				throw new QrException("Unsupported Hanzi subset.");
			}

			int count = ReadCount(bits, version, 8, 10, 12);
			for (int i = 0; i < count; i++)
			{
				int value = bits.Read(13);
				int assembled = (value / 0x60 << 8) | value % 0x60;
				assembled += assembled < 0x03BF ? 0xA1A1 : 0xA6A1;
				AppendEscapedByte(output, assembled >> 8);
				AppendEscapedByte(output, assembled & 0xFF);
			}
		}

		private static void AppendEscapedByte(StringBuilder output, int value) => output.Append("\\x").Append(value.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
	}

	private sealed class BitReader(byte[] data)
	{
		private int _position;
		internal int Available => data.Length * 8 - _position;
		internal int Read(int count)
		{
			if ((uint)count > 31 || count > Available)
			{
				throw new QrException("QR payload ended unexpectedly.");
			}

			int value = 0;
			for (int i = 0; i < count; i++, _position++)
			{
				value = (value << 1) | ((data[_position >> 3] >> (7 - (_position & 7))) & 1);
			}

			return value;
		}
		internal void Skip(int count)
		{
			if (count < 0 || count > Available)
			{
				throw new QrException("QR payload ended unexpectedly.");
			}

			_position += count;
		}
	}

	private sealed class QrException : Exception
	{
		internal QrException(string message) : base(message)
		{
		}
		internal QrException(string message, Exception innerException) : base(message, innerException)
		{
		}
		public QrException()
		{
		}
	}

	private static class QrDecoderHelpers
	{
		internal static QrResult? TryDecodeBinarizations(GrayImage image, string label, List<string> failures)
		{
			BooleanMatrix adaptive = Binarizer.Binarize(image);
			QrResult? result = QrDecoder.TryDecodePolarity(adaptive, $"{label}, adaptive normal", failures);
			if (result is not null)
			{
				return result;
			}

			result = QrDecoder.TryDecodePolarity(MatrixTransforms.Invert(adaptive, image.Padding), $"{label}, adaptive inverted", failures);
			if (result is not null)
			{
				return result;
			}

			foreach (byte threshold in QrDecoder.s_thresholds)
			{
				BooleanMatrix binary = ImagePreprocessor.Threshold(image, threshold);
				result = QrDecoder.TryDecodePolarity(binary, $"{label}, threshold {threshold} normal", failures);
				if (result is not null)
				{
					return result;
				}

				result = QrDecoder.TryDecodePolarity(MatrixTransforms.Invert(binary, image.Padding), $"{label}, threshold {threshold} inverted", failures);
				if (result is not null)
				{
					return result;
				}
			}
			return result;
		}
	}
}
