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
using System.Threading;

namespace CommonCore.Hardware;

internal static class GPUInfoManager
{
	private static readonly Lock GPUsListLock = new();
	private static List<GpuInfo>? GPUsList;

	/// <summary>
	/// Retrieves a list of all GPUs in the system.
	/// </summary>
	/// <returns></returns>
	internal static unsafe List<GpuInfo> GetSystemGPUs()
	{
		lock (GPUsListLock)
		{
			// Return a snapshot so callers cannot mutate the shared cache.
			if (GPUsList is not null)
			{
				return [.. GPUsList];
			}

			List<GpuInfo> detectedGPUs = [];
			HashSet<string> seenGpuKeys = new(StringComparer.OrdinalIgnoreCase);
			IntPtr collectionPtr = IntPtr.Zero;

			try
			{
				collectionPtr = NativeMethods.detect_system_gpus();

				if (collectionPtr == IntPtr.Zero)
				{
					GPUsList = detectedGPUs;
					return [.. GPUsList];
				}

				GpuInformationCollection collection = *(GpuInformationCollection*)collectionPtr;

				if (collection.total_count <= 0 || collection.gpu_information == IntPtr.Zero)
				{
					GPUsList = detectedGPUs;
					return [.. GPUsList];
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

					// The Rust side already deduplicates within a single WMI result set.
					// Keep a managed safety net here so a native or WMI edge case cannot pollute the cache.
					string deduplicationKey = GetGpuDeduplicationKey(managedGpuInfo);
					if (seenGpuKeys.Add(deduplicationKey))
					{
						detectedGPUs.Add(managedGpuInfo);
					}
				}
			}
			finally
			{
				// Always release the memory allocated by Rust
				if (collectionPtr != IntPtr.Zero)
					NativeMethods.release_gpu_information(collectionPtr);
			}

			GPUsList = detectedGPUs;
			return [.. GPUsList];
		}
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
	/// Builds a stable deduplication key for GPU entries returned by the native library.
	/// </summary>
	/// <param name="gpu"></param>
	/// <returns></returns>
	private static string GetGpuDeduplicationKey(GpuInfo gpu)
	{
		string pnpDeviceId = gpu.PnpDeviceId.Trim().ToUpperInvariant();
		if (!string.IsNullOrWhiteSpace(pnpDeviceId) && !string.Equals(pnpDeviceId, "UNKNOWN", StringComparison.OrdinalIgnoreCase))
		{
			return string.Create(CultureInfo.InvariantCulture, $"pnp:{pnpDeviceId}");
		}

		if (gpu.VendorId != 0U && gpu.DeviceId != 0U)
		{
			return string.Create(CultureInfo.InvariantCulture, $"pci:{gpu.VendorId:X4}:{gpu.DeviceId:X4}");
		}

		string normalizedName = gpu.Name.Trim().ToUpperInvariant();
		string normalizedManufacturer = gpu.Manufacturer.Trim().ToUpperInvariant();
		string normalizedDriverVersion = gpu.DriverVersion.Trim().ToUpperInvariant();

		if (!string.IsNullOrWhiteSpace(normalizedName) || !string.IsNullOrWhiteSpace(normalizedManufacturer) || !string.IsNullOrWhiteSpace(normalizedDriverVersion))
		{
			return string.Create(CultureInfo.InvariantCulture, $"name:{normalizedName}|manufacturer:{normalizedManufacturer}|driver:{normalizedDriverVersion}");
		}

		return string.Create(CultureInfo.InvariantCulture, $"fallback:{gpu.Brand.Trim().ToUpperInvariant()}:{gpu.VendorId:X4}:{gpu.DeviceId:X4}:{gpu.AdapterRam}");
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
