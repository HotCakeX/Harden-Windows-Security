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
using System.Runtime.InteropServices;

namespace HardenSystemSecurity.Hardware;

internal static class GPUInfoManager
{
	private static readonly List<GpuInfo> GPUsList = [];

	/// <summary>
	/// Retrieves a list of all GPUs in the system.
	/// </summary>
	/// <returns></returns>
	private static unsafe List<GpuInfo> GetSystemGPUs()
	{
		// If the list is already populated, return it.
		if (GPUsList.Count > 0)
			return GPUsList;

		IntPtr collectionPtr = IntPtr.Zero;

		try
		{
			collectionPtr = NativeMethods.detect_system_gpus();

			if (collectionPtr == IntPtr.Zero)
			{
				return GPUsList;
			}

			GpuInformationCollection collection = *(GpuInformationCollection*)collectionPtr;

			if (collection.total_count <= 0 || collection.gpu_information == IntPtr.Zero)
			{
				return GPUsList;
			}

			int structSize = sizeof(GpuInformation);

			for (int i = 0; i < collection.total_count; i++)
			{
				// Calculate the pointer to the current structure
				IntPtr currentStructPtr = IntPtr.Add(collection.gpu_information, i * structSize);

				// Marshal the structure
				GpuInformation gpuInfo = *(GpuInformation*)currentStructPtr;

				GpuInfo managedGpuInfo = new(
					name: MarshalStringFromPtr(gpuInfo.name),
					brand: MarshalStringFromPtr(gpuInfo.brand),
					vendorId: gpuInfo.vendor_id,
					deviceId: gpuInfo.device_id,
					description: MarshalStringFromPtr(gpuInfo.description),
					manufacturer: MarshalStringFromPtr(gpuInfo.manufacturer),
					pnpDeviceId: MarshalStringFromPtr(gpuInfo.pnp_device_id),
					adapterRam: gpuInfo.adapter_ram,
					driverVersion: MarshalStringFromPtr(gpuInfo.driver_version),
					driverDate: MarshalStringFromPtr(gpuInfo.driver_date),
					isAvailable: gpuInfo.is_available != 0,
					configManagerErrorCode: gpuInfo.config_manager_error_code,
					errorCode: gpuInfo.error_code,
					errorMessage: MarshalStringFromPtr(gpuInfo.error_message)
				);

				GPUsList.Add(managedGpuInfo);
			}
		}
		finally
		{
			// Gotta always release the memory allocated by Rust
			if (collectionPtr != IntPtr.Zero)
				NativeMethods.release_gpu_information(collectionPtr);
		}

		return GPUsList;
	}

	/// <summary>
	/// Safely marshal strings from IntPtr
	/// </summary>
	/// <param name="ptr"></param>
	/// <returns></returns>
	private static string MarshalStringFromPtr(IntPtr ptr)
	{
		if (ptr == IntPtr.Zero)
			return string.Empty;

		return Marshal.PtrToStringAnsi(ptr) ?? string.Empty;
	}

	/// <summary>
	/// Checks if the system only has 1 GPU and it's Intel.
	/// </summary>
	/// <returns></returns>
	internal static bool HasOnlyIntelGPU()
	{
		if (GetSystemGPUs() is not [GpuInfo singleGpu])
			return false;

		return singleGpu.Brand.Equals("Intel", StringComparison.OrdinalIgnoreCase)
			   || singleGpu.VendorId == 0x8086; // Also check by vendor ID (32902) as backup
	}
}
