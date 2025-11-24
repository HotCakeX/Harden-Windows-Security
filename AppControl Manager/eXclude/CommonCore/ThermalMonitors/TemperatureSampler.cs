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
using System.Globalization;
using System.Runtime.InteropServices;

namespace CommonCore.ThermalMonitors;

internal sealed partial class TemperatureSampler : IDisposable
{
	private const string ThermalCounterPath = @"\Thermal Zone Information(*)\Temperature";

	private static readonly List<string> _cpuKeywords =
	[
		"cpu", "package", "pkg", "proc", "soc", "tdie", "tctl", "core", "ccd", "die"
	];

	private IntPtr _hQuery;
	private IntPtr _hCounter;
	private bool _disposed;

	internal TemperatureSampler()
	{
		uint status = NativeMethods.PdhOpenQueryW(null, 0, out _hQuery);
		if (status != ERROR_SUCCESS || _hQuery == IntPtr.Zero)
		{
			throw new InvalidOperationException("PdhOpenQueryW failed: 0x" + status.ToString("X8", CultureInfo.InvariantCulture));
		}

		status = NativeMethods.PdhAddEnglishCounterW(_hQuery, ThermalCounterPath, 0, out _hCounter);
		if (status != ERROR_SUCCESS || _hCounter == IntPtr.Zero)
		{
			_ = NativeMethods.PdhCloseQuery(_hQuery);
			_hQuery = IntPtr.Zero;
			throw new InvalidOperationException("PdhAddEnglishCounterW failed: 0x" + status.ToString("X8", CultureInfo.InvariantCulture));
		}

		status = NativeMethods.PdhCollectQueryData(_hQuery);
		if (status != ERROR_SUCCESS)
		{
			Dispose();
			throw new InvalidOperationException("PdhCollectQueryData warm-up failed: 0x" + status.ToString("X8", CultureInfo.InvariantCulture));
		}
	}

	internal double SampleCelsiusOneShot()
	{
		if (_disposed)
			return double.NaN;

		uint status = NativeMethods.PdhCollectQueryData(_hQuery);
		if (status != ERROR_SUCCESS)
		{
			return double.NaN;
		}

		return ReadCpuLikeOrHottestCelsius(_hCounter);
	}

	private static unsafe double ReadCpuLikeOrHottestCelsius(IntPtr hCounter)
	{
		uint bufferSize = 0;
		uint itemCount = 0;

		uint status = NativeMethods.PdhGetFormattedCounterArrayW(
			hCounter,
			PDH_FMT_DOUBLE,
			ref bufferSize,
			ref itemCount,
			IntPtr.Zero);

		if (status != PDH_MORE_DATA || bufferSize == 0 || itemCount == 0)
		{
			return double.NaN;
		}

		nint buffer = 0;
		try
		{
			buffer = (nint)NativeMemory.Alloc(bufferSize);

			status = NativeMethods.PdhGetFormattedCounterArrayW(
				hCounter,
				PDH_FMT_DOUBLE,
				ref bufferSize,
				ref itemCount,
				buffer);

			if (status != ERROR_SUCCESS || itemCount == 0)
			{
				return double.NaN;
			}

			int itemSize = sizeof(PDH_FMT_COUNTERVALUE_ITEM_DOUBLE);

			double bestCpuLike = double.NaN;
			double hottest = double.NaN;

			for (uint i = 0; i < itemCount; i++)
			{
				int offsetBytes = (int)(i * (uint)itemSize);
				if ((ulong)offsetBytes + (ulong)itemSize > bufferSize)
				{
					break;
				}

				PDH_FMT_COUNTERVALUE_ITEM_DOUBLE* itemPtr = (PDH_FMT_COUNTERVALUE_ITEM_DOUBLE*)((byte*)buffer + offsetBytes);

				if (itemPtr->Value.CStatus != PDH_CSTATUS_VALID_DATA &&
					itemPtr->Value.CStatus != PDH_CSTATUS_NEW_DATA)
				{
					continue;
				}

				double celsius = NormalizeToCelsius(itemPtr->Value.Value);
				if (!IsPlausibleCelsius(celsius))
				{
					continue;
				}

				if (double.IsNaN(hottest) || celsius > hottest)
				{
					hottest = celsius;
				}

				// Using Span to check name to reduce allocation
				if (itemPtr->NamePtr != IntPtr.Zero)
				{
					ReadOnlySpan<char> nameSpan = MemoryMarshal.CreateReadOnlySpanFromNullTerminated((char*)itemPtr->NamePtr);

					if (!nameSpan.IsEmpty && ContainsAnyKeyword(nameSpan))
					{
						if (double.IsNaN(bestCpuLike) || celsius > bestCpuLike)
						{
							bestCpuLike = celsius;
						}
					}
				}
			}

			if (!double.IsNaN(bestCpuLike))
			{
				return bestCpuLike;
			}

			return hottest;
		}
		catch
		{
			return double.NaN;
		}
		finally
		{
			if (buffer != 0)
			{
				NativeMemory.Free((void*)buffer);
			}
		}
	}

	private static double NormalizeToCelsius(double raw)
	{
		// Convert from deci-Kelvin (common for ACPI)
		double cFromDeciK = (raw / 10.0) - 273.15;
		if (IsPlausibleCelsius(cFromDeciK))
		{
			return cFromDeciK;
		}

		// Convert from Kelvin
		double cFromK = raw - 273.15;
		if (IsPlausibleCelsius(cFromK))
		{
			return cFromK;
		}

		// Already Celsius
		double cFromC = raw;
		if (IsPlausibleCelsius(cFromC))
		{
			return cFromC;
		}

		return double.NaN;
	}

	private static bool IsPlausibleCelsius(double c) => (c > -30.0) && (c < 130.0);

	private static bool ContainsAnyKeyword(ReadOnlySpan<char> text)
	{
		foreach (string keyword in CollectionsMarshal.AsSpan(_cpuKeywords))
		{
			if (text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
			{
				return true;
			}
		}
		return false;
	}

	public void Dispose()
	{
		if (_disposed)
			return;

		_disposed = true;

		if (_hCounter != IntPtr.Zero)
		{
			_ = NativeMethods.PdhRemoveCounter(_hCounter);
			_hCounter = IntPtr.Zero;
		}
		if (_hQuery != IntPtr.Zero)
		{
			_ = NativeMethods.PdhCloseQuery(_hQuery);
			_hQuery = IntPtr.Zero;
		}
	}

	private const uint ERROR_SUCCESS = 0x00000000;
	private const uint PDH_MORE_DATA = 0x800007D2;
	private const uint PDH_FMT_DOUBLE = 0x00000200;
	private const uint PDH_CSTATUS_VALID_DATA = 0x00000000;
	private const uint PDH_CSTATUS_NEW_DATA = 0x00000001;
}
