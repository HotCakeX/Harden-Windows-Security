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

namespace CommonCore.ThermalMonitors;

internal static class StorageTemperature
{
	private const uint FILE_SHARE_READ = 0x00000001;
	private const uint FILE_SHARE_WRITE = 0x00000002;
	private const uint OPEN_EXISTING = 3;

	private const uint IOCTL_STORAGE_PREDICT_FAILURE = 0x002D1100;
	private const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
	private const uint StorageDeviceTemperatureProperty = 10;
	private const uint PropertyStandardQuery = 0;

	/// <summary>
	/// Scans PhysicalDrive0 through PhysicalDrive15 and retrieves current temperatures in Celsius.
	/// </summary>
	/// <returns>A list of temperatures found (in Celsius).</returns>
	internal static unsafe List<int> GetDriveTemperatures()
	{
		List<int> temps = new();

		for (int i = 0; i < 16; i++)
		{
			string path = $@"\\.\PhysicalDrive{i}";

			// Request 0 access (Query only)
			IntPtr hDrive = NativeMethods.CreateFileW(
				path,
				0,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				IntPtr.Zero,
				OPEN_EXISTING,
				0,
				IntPtr.Zero);

			if (hDrive == IntPtr.Zero || hDrive == -1)
				continue;

			try
			{
				int currentTemp = -1;

				// Try Windows Storage API first
				int winTemp = GetWindowsPropertyTemp(hDrive);
				if (winTemp > 0)
				{
					currentTemp = winTemp;
				}
				else
				{
					// Fallback to S.M.A.R.T
					STORAGE_PREDICT_FAILURE smart = new();
					uint bytesReturned = 0;

					bool result = NativeMethods.DeviceIoControl(
						hDrive,
						IOCTL_STORAGE_PREDICT_FAILURE,
						null,
						0,
						&smart,
						(uint)sizeof(STORAGE_PREDICT_FAILURE),
						ref bytesReturned,
						IntPtr.Zero);

					if (result)
					{
						int ataTemp = ParseAtaTemp(smart.VendorSpecific);
						if (ataTemp > 0)
						{
							currentTemp = ataTemp;
						}
					}
				}

				if (currentTemp > 0)
				{
					temps.Add(currentTemp);
				}
			}
			finally
			{
				_ = NativeMethods.CloseHandle(hDrive);
			}
		}

		return temps;
	}

	private static unsafe int ParseAtaTemp(byte* buffer)
	{
		// Iterate over SMART attributes in the 512-byte VendorSpecific block
		for (int i = 0; i < 30; i++)
		{
			// SMART attributes usually start at offset 2
			int offset = 2 + (i * 12);

			// Ensure we don't read past buffer (VendorSpecific is 512 bytes)
			if (offset + 12 > 512) break;

			byte id = buffer[offset];
			if (id == 194 || id == 190) // Temperature Attributes
			{
				// Byte 5 of the attribute is usually the raw current value
				return buffer[offset + 5];
			}
		}
		return -1;
	}

	private static unsafe int GetWindowsPropertyTemp(IntPtr hDrive)
	{
		STORAGE_PROPERTY_QUERY query = new()
		{
			PropertyId = StorageDeviceTemperatureProperty,
			QueryType = PropertyStandardQuery
		};

		uint bytesReturned = 0;

		// Allocating buffer for Header + 1 Info struct (~40 bytes total needed)
		const int BufferSize = 128;
		byte* pOutBuffer = stackalloc byte[BufferSize];

		bool result = NativeMethods.DeviceIoControl(
			hDrive,
			IOCTL_STORAGE_QUERY_PROPERTY,
			&query,
			(uint)sizeof(STORAGE_PROPERTY_QUERY),
			pOutBuffer,
			BufferSize,
			ref bytesReturned,
			IntPtr.Zero);

		if (result && bytesReturned > 0)
		{
			STORAGE_TEMPERATURE_DATA_DESCRIPTOR* header = (STORAGE_TEMPERATURE_DATA_DESCRIPTOR*)pOutBuffer;
			if (header->InfoCount > 0)
			{
				// Info struct follows immediately after the descriptor.
				STORAGE_TEMPERATURE_INFO* info = (STORAGE_TEMPERATURE_INFO*)(pOutBuffer + sizeof(STORAGE_TEMPERATURE_DATA_DESCRIPTOR));
				return info->Temperature;
			}
		}

		return -1;
	}
}
