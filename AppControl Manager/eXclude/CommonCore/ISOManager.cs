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
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CommonCore;

internal sealed class PhysicalDiskInfo
{
	internal uint Number { get; set; }
	internal string FriendlyName { get; set; } = string.Empty;
	internal long Size { get; set; }
	internal string DisplayText => $"Disk {Number} - {FriendlyName} - {Size / (1024 * 1024 * 1024)} GB Total";
}

internal static partial class ISOManager
{
	internal static unsafe List<PhysicalDiskInfo> GetPhysicalDisksInfo()
	{
		List<PhysicalDiskInfo> disks = [];

		int hrInit = Interop.NativeMethods.CoInitializeEx(IntPtr.Zero, 0);
		// RPC_E_CHANGED_MODE = -2147417850 (0x80010106)
		if (hrInit < 0 && hrInit != -2147417850)
		{
			return disks;
		}

		bool requiresUninitialize = hrInit >= 0;

		int secHr = NativeMethods.CoInitializeSecurity(IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero, 0, 3, IntPtr.Zero, 0, IntPtr.Zero);
		// RPC_E_TOO_LATE = -2147417831 (0x80010119)
		if (secHr < 0 && secHr != -2147417831)
		{
			if (requiresUninitialize)
			{
				Interop.NativeMethods.CoUninitialize();
			}
			return disks;
		}

		Guid CLSID_WbemLocator = new("4590F811-1D3A-11D0-891F-00AA004B2E24");
		Guid IID_IWbemLocator = new("DC12A687-737F-11CF-884D-00AA004B2E24");

		IWbemLocator* locator = null;
		IWbemServices* services = null;
		IEnumWbemClassObject* enumerator = null;

		IntPtr rootNamespacePtr = IntPtr.Zero;
		IntPtr queryPtr = IntPtr.Zero;
		IntPtr queryLanguagePtr = IntPtr.Zero;

		try
		{
			int hr = NativeMethods.CoCreateInstanceWbemLocator(in CLSID_WbemLocator, IntPtr.Zero, 1, in IID_IWbemLocator, out locator);
			if (hr < 0 || locator == null)
			{
				return disks;
			}

			rootNamespacePtr = Marshal.StringToBSTR("root\\Microsoft\\Windows\\Storage");
			hr = locator->ConnectServer(rootNamespacePtr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, out services);
			if (hr < 0 || services == null)
			{
				return disks;
			}

			hr = NativeMethods.CoSetProxyBlanket(services, 10, 0, IntPtr.Zero, 3, 3, IntPtr.Zero, 0);
			if (hr < 0)
			{
				return disks;
			}

			queryPtr = Marshal.StringToBSTR("SELECT Number, FriendlyName, Size FROM MSFT_Disk");
			queryLanguagePtr = Marshal.StringToBSTR("WQL");

			// WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY (0x20 | 0x10)
			hr = services->ExecQuery(queryLanguagePtr, queryPtr, 0x20 | 0x10, IntPtr.Zero, out enumerator);
			if (hr < 0 || enumerator == null)
			{
				return disks;
			}

			while (true)
			{

				hr = enumerator->Next(-1, 1, out IWbemClassObject* diskObj, out uint returned);
				if (hr != 0 || returned == 0 || diskObj == null)
				{
					break;
				}

				try
				{
					PhysicalDiskInfo info = new();

					IntPtr propName = Marshal.StringToBSTR("Number");
					try
					{
						VARIANT val = default;
						try
						{
							if (diskObj->Get(propName, 0, out val, IntPtr.Zero, IntPtr.Zero) == 0)
							{
								info.Number = val.uintVal;
							}
						}
						finally
						{
							_ = NativeMethods.VariantClear(ref val);
						}
					}
					finally
					{
						Marshal.FreeBSTR(propName);
					}

					propName = Marshal.StringToBSTR("FriendlyName");
					try
					{
						VARIANT val = default;
						try
						{
							if (diskObj->Get(propName, 0, out val, IntPtr.Zero, IntPtr.Zero) == 0)
							{
								if (val.vt == 8 && val.bstrVal != IntPtr.Zero)
								{
									info.FriendlyName = Marshal.PtrToStringBSTR(val.bstrVal) ?? string.Empty;
								}
							}
						}
						finally
						{
							_ = NativeMethods.VariantClear(ref val);
						}
					}
					finally
					{
						Marshal.FreeBSTR(propName);
					}

					propName = Marshal.StringToBSTR("Size");
					try
					{
						VARIANT val = default;
						try
						{
							if (diskObj->Get(propName, 0, out val, IntPtr.Zero, IntPtr.Zero) == 0)
							{
								if (val.vt == 21) // VT_UI8
								{
									info.Size = (long)val.ullVal;
								}
								else if (val.vt == 8 && val.bstrVal != IntPtr.Zero) // string fallback
								{
									_ = long.TryParse(Marshal.PtrToStringBSTR(val.bstrVal), out long parsedSize);
									info.Size = parsedSize;
								}
							}
						}
						finally
						{
							_ = NativeMethods.VariantClear(ref val);
						}
					}
					finally
					{
						Marshal.FreeBSTR(propName);
					}

					disks.Add(info);
				}
				finally
				{
					_ = diskObj->Release();
				}
			}
		}
		finally
		{
			if (queryLanguagePtr != IntPtr.Zero) Marshal.FreeBSTR(queryLanguagePtr);
			if (queryPtr != IntPtr.Zero) Marshal.FreeBSTR(queryPtr);
			if (rootNamespacePtr != IntPtr.Zero) Marshal.FreeBSTR(rootNamespacePtr);

			if (enumerator != null) _ = enumerator->Release();
			if (services != null) _ = services->Release();
			if (locator != null) _ = locator->Release();

			if (requiresUninitialize)
			{
				Interop.NativeMethods.CoUninitialize();
			}
		}

		return disks;
	}

	internal static void CreateBootableDriveAutomatic(uint diskNumber, string isoPath, bool formatRemainingSpace, string remainingFileSystem, IProgress<double> progress)
	{
		string? systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System));
		if (!string.IsNullOrEmpty(systemDrive) && GetPhysicalDiskNumber(systemDrive) == diskNumber)
		{
			throw new InvalidOperationException("The selected disk is the operating system disk. Aborting formatting to protect system.");
		}

		EnablePrivileges();

		if (!File.Exists(isoPath))
		{
			throw new InvalidOperationException($"ISO file not found at '{isoPath}'");
		}

		if (!string.Equals(Path.GetExtension(isoPath), ".iso", StringComparison.OrdinalIgnoreCase))
		{
			throw new InvalidOperationException("File is not an ISO.");
		}

		Logger.Write($"Automatically partitioning Disk {diskNumber} using WMI");

		int hrInit = Interop.NativeMethods.CoInitializeEx(IntPtr.Zero, 0);
		// RPC_E_CHANGED_MODE = -2147417850 (0x80010106)
		// This happens if the thread is already initialized with a different concurrency model (in WinUI 3 apps)
		if (hrInit < 0 && hrInit != -2147417850)
		{
			throw new InvalidOperationException($"CoInitializeEx failed with HRESULT 0x{hrInit:X}");
		}

		// S_OK (0) and S_FALSE (1) indicate success and require balancing with CoUninitialize.
		bool requiresUninitialize = hrInit >= 0;

		try
		{
			int secHr = NativeMethods.CoInitializeSecurity(IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero, 0, 3, IntPtr.Zero, 0, IntPtr.Zero);
			// RPC_E_TOO_LATE = -2147417831 (0x80010119)
			// This happens if COM security is already initialized for the process (in WinUI 3 apps)
			if (secHr < 0 && secHr != -2147417831)
			{
				throw new InvalidOperationException($"CoInitializeSecurity failed with HRESULT 0x{secHr:X}");
			}

			// 1. Wipe and Partition the disk
			ExecuteDiskPartitioningWMI(diskNumber, formatRemainingSpace);

			// 2. Query WMI for the partitions on this disk to find their assigned drive letters.
			List<PartitionDriveLetterInfo> partitions = GetPartitionsOnDisk(diskNumber);

			int expectedPartitions = formatRemainingSpace ? 3 : 2;
			if (partitions.Count < expectedPartitions)
			{
				throw new InvalidOperationException($"Expected at least {expectedPartitions} partitions on Disk {diskNumber} after partitioning, but found {partitions.Count}.");
			}

			// Sort by Offset ascending - first is BOOT (~2GB), next is DATA (~8GB), last is Remaining Space (if exists)
			partitions.Sort((a, b) => a.Offset.CompareTo(b.Offset));

			PartitionDriveLetterInfo bootPartition = partitions[0];
			PartitionDriveLetterInfo dataPartition = partitions[1];

			if (bootPartition.DriveLetter == '\0' || dataPartition.DriveLetter == '\0')
			{
				throw new InvalidOperationException("One or both of the newly created partitions did not receive a drive letter assignment.");
			}

			string bootPartitionPath = $"{bootPartition.DriveLetter}:\\";
			string dataPartitionPath = $"{dataPartition.DriveLetter}:\\";

			Logger.Write($"Partitioning complete. BOOT partition at {bootPartitionPath} ({bootPartition.Size / (1024 * 1024)} MB), DATA partition at {dataPartitionPath} ({dataPartition.Size / (1024 * 1024)} MB).");

			// 3. Format BOOT as FAT32
			Logger.Write($"Formatting BOOT partition ({bootPartitionPath}) as FAT32");
			FormatDrive(bootPartitionPath, "FAT32");

			// 4. Format DATA as NTFS
			Logger.Write($"Formatting DATA partition ({dataPartitionPath}) as NTFS");
			FormatDrive(dataPartitionPath, "NTFS");

			// 5. Format Remaining Space as selected file system (if applicable)
			if (formatRemainingSpace)
			{
				PartitionDriveLetterInfo extraPartition = partitions[2];
				if (extraPartition.DriveLetter == '\0')
				{
					throw new InvalidOperationException("The third partition did not receive a drive letter assignment.");
				}
				string extraPartitionPath = $"{extraPartition.DriveLetter}:\\";
				Logger.Write($"Formatting 3rd partition ({extraPartitionPath}) as {remainingFileSystem}");
				FormatDrive(extraPartitionPath, remainingFileSystem);
			}

			// 6. Mount ISO and copy files
			CopyIsoContentsToDrives(bootPartitionPath, dataPartitionPath, isoPath, progress);
		}
		finally
		{
			if (requiresUninitialize)
			{
				Interop.NativeMethods.CoUninitialize();
			}
		}
	}

	private sealed class PartitionDriveLetterInfo
	{
		internal char DriveLetter { get; set; }
		internal long Size { get; set; }
		internal ulong Offset { get; set; }
	}

	private static unsafe List<PartitionDriveLetterInfo> GetPartitionsOnDisk(uint diskNumber)
	{
		List<PartitionDriveLetterInfo> results = [];

		Guid CLSID_WbemLocator = new("4590F811-1D3A-11D0-891F-00AA004B2E24");
		Guid IID_IWbemLocator = new("DC12A687-737F-11CF-884D-00AA004B2E24");

		IWbemLocator* locator = null;
		IWbemServices* services = null;
		IEnumWbemClassObject* enumerator = null;

		IntPtr rootNamespacePtr = IntPtr.Zero;
		IntPtr queryPtr = IntPtr.Zero;
		IntPtr queryLanguagePtr = IntPtr.Zero;

		try
		{
			int hr = NativeMethods.CoCreateInstanceWbemLocator(in CLSID_WbemLocator, IntPtr.Zero, 1, in IID_IWbemLocator, out locator);
			if (hr < 0 || locator == null)
			{
				return results;
			}

			rootNamespacePtr = Marshal.StringToBSTR("root\\Microsoft\\Windows\\Storage");
			hr = locator->ConnectServer(rootNamespacePtr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, out services);
			if (hr < 0 || services == null)
			{
				return results;
			}

			hr = NativeMethods.CoSetProxyBlanket(services, 10, 0, IntPtr.Zero, 3, 3, IntPtr.Zero, 0);
			if (hr < 0)
			{
				return results;
			}

			// Query MSFT_Partition for all partitions on this disk number
			string query = $"SELECT DriveLetter, Size, Offset FROM MSFT_Partition WHERE DiskNumber = {diskNumber}";
			queryPtr = Marshal.StringToBSTR(query);
			queryLanguagePtr = Marshal.StringToBSTR("WQL");

			hr = services->ExecQuery(queryLanguagePtr, queryPtr, 0x20 | 0x10, IntPtr.Zero, out enumerator);
			if (hr < 0 || enumerator == null)
			{
				return results;
			}

			while (true)
			{
				hr = enumerator->Next(-1, 1, out IWbemClassObject* partObj, out uint returned);
				if (hr != 0 || returned == 0 || partObj == null)
				{
					break;
				}

				try
				{
					PartitionDriveLetterInfo info = new();

					// Get DriveLetter (returned as VT_UI2 = char/ushort, value 0 means no letter assigned)
					IntPtr propName = Marshal.StringToBSTR("DriveLetter");
					try
					{
						VARIANT val = default;
						try
						{
							if (partObj->Get(propName, 0, out val, IntPtr.Zero, IntPtr.Zero) == 0)
							{
								// DriveLetter comes as a UInt16 (character code). 0 means no drive letter.
								ushort driveLetterCode = (ushort)(val.uintVal & 0xFFFF);
								if (driveLetterCode != 0)
								{
									info.DriveLetter = (char)driveLetterCode;
								}
							}
						}
						finally
						{
							_ = NativeMethods.VariantClear(ref val);
						}
					}
					finally
					{
						Marshal.FreeBSTR(propName);
					}

					// Get Size
					propName = Marshal.StringToBSTR("Size");
					try
					{
						VARIANT val = default;
						try
						{
							if (partObj->Get(propName, 0, out val, IntPtr.Zero, IntPtr.Zero) == 0)
							{
								if (val.vt == 21) // VT_UI8
								{
									info.Size = (long)val.ullVal;
								}
								else if (val.vt == 8 && val.bstrVal != IntPtr.Zero) // String fallback for UInt64
								{
									_ = long.TryParse(Marshal.PtrToStringBSTR(val.bstrVal), out long parsedSize);
									info.Size = parsedSize;
								}
							}
						}
						finally
						{
							_ = NativeMethods.VariantClear(ref val);
						}
					}
					finally
					{
						Marshal.FreeBSTR(propName);
					}

					// Get Offset
					propName = Marshal.StringToBSTR("Offset");
					try
					{
						VARIANT val = default;
						try
						{
							if (partObj->Get(propName, 0, out val, IntPtr.Zero, IntPtr.Zero) == 0)
							{
								if (val.vt == 21) // VT_UI8
								{
									info.Offset = val.ullVal;
								}
								else if (val.vt == 8 && val.bstrVal != IntPtr.Zero) // String fallback for UInt64
								{
									_ = ulong.TryParse(Marshal.PtrToStringBSTR(val.bstrVal), out ulong parsedOffset);
									info.Offset = parsedOffset;
								}
							}
						}
						finally
						{
							_ = NativeMethods.VariantClear(ref val);
						}
					}
					finally
					{
						Marshal.FreeBSTR(propName);
					}

					// Only include partitions that have a drive letter and a meaningful size
					// This filters out the Microsoft Reserved Partition (MSR) and EFI system partition
					if (info.DriveLetter != '\0' && info.Size > 0)
					{
						results.Add(info);
					}
				}
				finally
				{
					_ = partObj->Release();
				}
			}
		}
		finally
		{
			if (queryLanguagePtr != IntPtr.Zero) Marshal.FreeBSTR(queryLanguagePtr);
			if (queryPtr != IntPtr.Zero) Marshal.FreeBSTR(queryPtr);
			if (rootNamespacePtr != IntPtr.Zero) Marshal.FreeBSTR(rootNamespacePtr);

			if (enumerator != null) _ = enumerator->Release();
			if (services != null) _ = services->Release();
			if (locator != null) _ = locator->Release();
		}

		return results;
	}

	private static void CopyIsoContentsToDrives(string bootPartitionPath, string dataPartitionPath, string isoPath, IProgress<double> progress)
	{
		IntPtr handle = IntPtr.Zero;
		try
		{
			VIRTUAL_STORAGE_TYPE storageType = new()
			{
				DeviceId = VIRTUAL_STORAGE_TYPE.DeviceIdIso,
				VendorId = VIRTUAL_STORAGE_TYPE.VendorIdMicrosoft
			};

			OPEN_VIRTUAL_DISK_PARAMETERS openParameters = new()
			{
				Version = OPEN_VIRTUAL_DISK_VERSION.Version1,
				Version1 = new OpenVirtualDiskParametersVersion1
				{
					RWDepth = 1 // ISO is read-only
				}
			};

			// Open the Virtual Disk
			int openResult = NativeMethods.OpenVirtualDisk(
				ref storageType,
				isoPath,
				VIRTUAL_DISK_ACCESS_MASK.Read,
				OPEN_VIRTUAL_DISK_FLAG.None,
				ref openParameters,
				out handle);

			if (openResult != 0)
			{
				throw new InvalidOperationException($"Failed to open virtual disk. Error code: {openResult}.");
			}

			ATTACH_VIRTUAL_DISK_PARAMETERS attachParameters = new()
			{
				Version = AttachVirtualDiskVersion.Version1
			};

			// Attach the Virtual Disk (Mount)
			int attachResult = NativeMethods.AttachVirtualDisk(
				handle,
				IntPtr.Zero,
				ATTACH_VIRTUAL_DISK_FLAG.ReadOnly | ATTACH_VIRTUAL_DISK_FLAG.NoDriveLetter,
				0,
				ref attachParameters,
				IntPtr.Zero);

			if (attachResult != 0)
			{
				throw new InvalidOperationException($"Failed to attach virtual disk. Error code: {attachResult}");
			}

			// Get the physical path (Volume GUID path)
			int bufferSize = 260 * 2; // MAX_PATH wide chars
			IntPtr pathBuffer = Marshal.AllocHGlobal(bufferSize);
			try
			{
				int getPathResult = NativeMethods.GetVirtualDiskPhysicalPath(handle, ref bufferSize, pathBuffer);
				if (getPathResult != 0)
				{
					throw new InvalidOperationException($"Failed to get virtual disk physical path. Error code: {getPathResult}");
				}

				string physicalPath = Marshal.PtrToStringUni(pathBuffer) ?? string.Empty;
				if (!string.IsNullOrEmpty(physicalPath))
				{
					// Ensure the physical path has a trailing slash for Directory methods
					if (!physicalPath.EndsWith('\\'))
					{
						physicalPath += "\\";
					}

					Logger.Write($"Successfully mounted ISO at: {physicalPath}");

					// Calculate accurate total bytes accounting for all three copy phases:
					// Phase 1: Full ISO contents to DATA partition
					// Phase 2: ISO contents excluding "sources" folder to BOOT partition
					// Phase 3: boot.wim to BOOT partition's "sources" folder
					long isoTotalBytes = CalculateTotalBytes(physicalPath);
					long sourcesFolderSize = 0L;
					string sourcesDir = Path.Combine(physicalPath, "sources");
					if (Directory.Exists(sourcesDir))
					{
						sourcesFolderSize = CalculateTotalBytes(sourcesDir);
					}
					string bootWimPath = Path.Combine(physicalPath, "sources", "boot.wim");
					long bootWimSize = File.Exists(bootWimPath) ? new FileInfo(bootWimPath).Length : 0L;
					long totalBytesToCopy = isoTotalBytes + (isoTotalBytes - sourcesFolderSize) + bootWimSize;

					long copiedBytes = 0;

					Logger.Write($"Copying all contents from ISO to DATA partition ({dataPartitionPath})");
					copiedBytes = CopyDirectoryWithProgress(physicalPath, dataPartitionPath, totalBytesToCopy, copiedBytes, progress);

					Logger.Write($"Copying contents (excluding 'sources') to BOOT partition ({bootPartitionPath})");
					copiedBytes = CopyToBootPartitionWithProgress(physicalPath, bootPartitionPath, totalBytesToCopy, copiedBytes, progress);

					Logger.Write($"Copying boot.wim to BOOT partition's 'sources' folder");
					_ = CopyBootWimWithProgress(physicalPath, bootPartitionPath, totalBytesToCopy, copiedBytes, progress);

					// Explicitly report 100% completion to account for any minor precision loss or skipped empty items.
					progress.Report(100.0);
				}
			}
			finally
			{
				Marshal.FreeHGlobal(pathBuffer);
			}
		}
		finally
		{
			if (handle != IntPtr.Zero)
			{
				// Detach and close handle
				int detachResult = NativeMethods.DetachVirtualDisk(handle, DetachVirtualDiskFlag.None, 0);
				if (detachResult != 0)
				{
					Logger.Write($"Failed to detach virtual disk. Error code: {detachResult}");
				}

				_ = Interop.NativeMethods.CloseHandle(handle);
			}
		}
	}

	internal static unsafe void ExecuteDiskPartitioningWMI(uint diskNumber, bool formatRemainingSpace)
	{
		Guid CLSID_WbemLocator = new("4590F811-1D3A-11D0-891F-00AA004B2E24");
		Guid IID_IWbemLocator = new("DC12A687-737F-11CF-884D-00AA004B2E24");

		const uint CLSCTX_INPROC_SERVER = 1;
		const uint RPC_C_AUTHN_WINNT = 10;
		const uint RPC_C_AUTHZ_NONE = 0;
		const uint RPC_C_AUTHN_LEVEL_CALL = 3;
		const uint RPC_C_IMP_LEVEL_IMPERSONATE = 3;

		IWbemLocator* locator = null;
		IWbemServices* services = null;

		IntPtr rootNamespacePtr = IntPtr.Zero;

		try
		{
			int hr = NativeMethods.CoCreateInstanceWbemLocator(in CLSID_WbemLocator, IntPtr.Zero, CLSCTX_INPROC_SERVER, in IID_IWbemLocator, out locator);
			if (hr < 0 || locator == null)
			{
				throw new InvalidOperationException($"Failed to create IWbemLocator. HRESULT: 0x{hr:X8}");
			}

			rootNamespacePtr = Marshal.StringToBSTR("root\\Microsoft\\Windows\\Storage");
			hr = locator->ConnectServer(rootNamespacePtr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, out services);
			if (hr < 0 || services == null)
			{
				throw new InvalidOperationException($"Failed to connect to Storage WMI namespace. HRESULT: 0x{hr:X8}");
			}

			hr = NativeMethods.CoSetProxyBlanket(
				services,
				RPC_C_AUTHN_WINNT,
				RPC_C_AUTHZ_NONE,
				IntPtr.Zero,
				RPC_C_AUTHN_LEVEL_CALL,
				RPC_C_IMP_LEVEL_IMPERSONATE,
				IntPtr.Zero,
				0);

			if (hr < 0)
			{
				throw new InvalidOperationException($"Failed to set proxy blanket. HRESULT: 0x{hr:X8}");
			}

			string diskPath = GetDiskWmiPath(services, diskNumber);

			// 1. Clear Disk
			// We pass RemoveData and RemoveOEM to remove all partitions including OEM partitions
			Dictionary<string, VARIANT> clearParams = new()
			{
				{ "RemoveData", new VARIANT { vt = 11, boolVal = -1 } },
				{ "RemoveOEM", new VARIANT { vt = 11, boolVal = -1 } }
			};
			ExecuteMethodOnDisk(services, diskPath, "Clear", clearParams);

			// 2. After Clear, the disk keeps its existing partition style (MBR/GPT).
			//    We need to check: if it's already GPT (2), skip Initialize.
			//    If it's MBR (1) or unknown, wipe the disk header to force RAW, then Initialize as GPT.
			//    If it's RAW (0), just Initialize as GPT.
			uint currentPartitionStyle = GetDiskPartitionStyle(services, diskNumber);

			if (currentPartitionStyle == 2)
			{
				// Already GPT - no need to Initialize
				Logger.Write("Disk is already GPT after Clear. Skipping Initialize.");
			}
			else
			{
				if (currentPartitionStyle != 0)
				{
					// Disk is MBR or unknown - wipe the disk header sectors to force it to RAW
					Logger.Write($"Disk PartitionStyle is {currentPartitionStyle}. Wiping disk header to force RAW state.");
					WipeDiskHeader(diskNumber);
				}

				// Re-fetch disk path after potential header wipe
				diskPath = GetDiskWmiPath(services, diskNumber);

				// Initialize Disk as GPT (2)
				// Using VT_I4 (3) as WMI expects standard 32-bit signed integers for these COM-dispatched method properties.
				Dictionary<string, VARIANT> initParams = new()
				{
					{ "PartitionStyle", new VARIANT { vt = 3, lVal = 2 } }
				};
				ExecuteMethodOnDisk(services, diskPath, "Initialize", initParams);
			}

			diskPath = GetDiskWmiPath(services, diskNumber);

			// 3. Create BOOT Partition (Size = 2048 MB = 2147483648 Bytes, AssignDriveLetter = true)
			Dictionary<string, VARIANT> bootParams = new()
			{
				{ "Size", new VARIANT { vt = 8, bstrVal = Marshal.StringToBSTR("2147483648") } }, // UInt64 uses BSTR string
				{ "AssignDriveLetter", new VARIANT { vt = 11, boolVal = -1 } }
			};

			try
			{
				ExecuteMethodOnDisk(services, diskPath, "CreatePartition", bootParams);
			}
			finally
			{
				if (bootParams["Size"].bstrVal != IntPtr.Zero)
				{
					Marshal.FreeBSTR(bootParams["Size"].bstrVal);
				}
			}

			diskPath = GetDiskWmiPath(services, diskNumber);

			// 4. Create DATA Partition (Size = 8192 MB = 8589934592 Bytes, AssignDriveLetter = true)
			// Remaining space on the disk will intentionally be left unallocated
			Dictionary<string, VARIANT> dataParams = new()
			{
				{ "Size", new VARIANT { vt = 8, bstrVal = Marshal.StringToBSTR("8589934592") } },
				{ "AssignDriveLetter", new VARIANT { vt = 11, boolVal = -1 } }
			};

			try
			{
				ExecuteMethodOnDisk(services, diskPath, "CreatePartition", dataParams);
			}
			finally
			{
				if (dataParams["Size"].bstrVal != IntPtr.Zero)
				{
					Marshal.FreeBSTR(dataParams["Size"].bstrVal);
				}
			}

			// 5. Create Remaining Space Partition (if requested)
			if (formatRemainingSpace)
			{
				diskPath = GetDiskWmiPath(services, diskNumber);
				Dictionary<string, VARIANT> extraParams = new()
				{
					{ "UseMaximumSize", new VARIANT { vt = 11, boolVal = -1 } },
					{ "AssignDriveLetter", new VARIANT { vt = 11, boolVal = -1 } }
				};

				ExecuteMethodOnDisk(services, diskPath, "CreatePartition", extraParams);
			}
		}
		finally
		{
			if (rootNamespacePtr != IntPtr.Zero)
			{
				Marshal.FreeBSTR(rootNamespacePtr);
			}

			if (services != null)
			{
				_ = services->Release();
			}

			if (locator != null)
			{
				_ = locator->Release();
			}
		}
	}

	private static unsafe string GetDiskWmiPath(IWbemServices* services, uint diskNumber)
	{
		const int WBEM_FLAG_FORWARD_ONLY = 0x20;
		const int WBEM_FLAG_RETURN_IMMEDIATELY = 0x10;
		const int WBEM_INFINITE = -1;

		IEnumWbemClassObject* enumerator = null;
		IWbemClassObject* diskObj = null;

		IntPtr queryPtr = IntPtr.Zero;
		IntPtr queryLanguagePtr = IntPtr.Zero;
		IntPtr pathPropName = IntPtr.Zero;

		VARIANT valPath = default;

		try
		{
			string query = $"SELECT * FROM MSFT_Disk WHERE Number = {diskNumber}";
			queryPtr = Marshal.StringToBSTR(query);
			queryLanguagePtr = Marshal.StringToBSTR("WQL");

			int hr = services->ExecQuery(
				queryLanguagePtr,
				queryPtr,
				WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
				IntPtr.Zero,
				out enumerator);

			if (hr < 0 || enumerator == null)
			{
				throw new InvalidOperationException($"Failed to execute WMI query for Disk {diskNumber}. HRESULT: 0x{hr:X8}");
			}

			hr = enumerator->Next(WBEM_INFINITE, 1, out diskObj, out uint returned);
			if (hr != 0 || returned == 0 || diskObj == null)
			{
				throw new InvalidOperationException($"Disk {diskNumber} not found in WMI.");
			}

			pathPropName = Marshal.StringToBSTR("__PATH");
			hr = diskObj->Get(pathPropName, 0, out valPath, IntPtr.Zero, IntPtr.Zero);
			if (hr < 0 || valPath.vt != 8 || valPath.bstrVal == IntPtr.Zero)
			{
				throw new InvalidOperationException("Failed to get disk WMI path.");
			}

			return Marshal.PtrToStringBSTR(valPath.bstrVal) ?? throw new InvalidOperationException("Disk WMI path was empty.");
		}
		finally
		{
			_ = NativeMethods.VariantClear(ref valPath);

			if (pathPropName != IntPtr.Zero)
			{
				Marshal.FreeBSTR(pathPropName);
			}

			if (queryLanguagePtr != IntPtr.Zero)
			{
				Marshal.FreeBSTR(queryLanguagePtr);
			}

			if (queryPtr != IntPtr.Zero)
			{
				Marshal.FreeBSTR(queryPtr);
			}

			if (diskObj != null)
			{
				_ = diskObj->Release();
			}

			if (enumerator != null)
			{
				_ = enumerator->Release();
			}
		}
	}

	private static unsafe void ExecuteMethodOnDisk(IWbemServices* services, string objectPath, string methodName, Dictionary<string, VARIANT>? methodParams)
	{
		IWbemClassObject* classObj = null;
		IWbemClassObject* inParamsDef = null;
		IWbemClassObject* outParamsDef = null;
		IWbemClassObject* inParams = null;
		IWbemClassObject* outParams = null;

		IntPtr classNamePtr = IntPtr.Zero;
		IntPtr methodNamePtr = IntPtr.Zero;
		IntPtr objectPathPtr = IntPtr.Zero;
		IntPtr returnValuePtr = IntPtr.Zero;
		VARIANT valReturn = default;

		List<IntPtr> allocatedBstrs = [];

		try
		{
			classNamePtr = Marshal.StringToBSTR("MSFT_Disk");
			methodNamePtr = Marshal.StringToBSTR(methodName);
			objectPathPtr = Marshal.StringToBSTR(objectPath);

			int hr = services->GetObject(classNamePtr, 0, IntPtr.Zero, out classObj, IntPtr.Zero);
			if (hr < 0 || classObj == null) throw new InvalidOperationException($"Failed to get MSFT_Disk class. HRESULT: 0x{hr:X8}");

			hr = classObj->GetMethod(methodNamePtr, 0, out inParamsDef, out outParamsDef);
			if (hr < 0 || inParamsDef == null) throw new InvalidOperationException($"Failed to get {methodName} method definitions. HRESULT: 0x{hr:X8}");

			hr = inParamsDef->SpawnInstance(0, out inParams);
			if (hr < 0 || inParams == null) throw new InvalidOperationException($"Failed to spawn {methodName} parameters instance. HRESULT: 0x{hr:X8}");

			if (methodParams != null)
			{
				foreach (KeyValuePair<string, VARIANT> kvp in methodParams)
				{
					IntPtr paramNamePtr = Marshal.StringToBSTR(kvp.Key);
					allocatedBstrs.Add(paramNamePtr);

					// Storing in a local variable to be able to pass 'in' by reference
					VARIANT variantValue = kvp.Value;
					hr = PutVariant(inParams, paramNamePtr, in variantValue);

					if (hr < 0) throw new InvalidOperationException($"Failed to set parameter {kvp.Key}. HRESULT: 0x{hr:X8}");
				}
			}

			hr = services->ExecMethod(objectPathPtr, methodNamePtr, 0, IntPtr.Zero, inParams, out outParams, IntPtr.Zero);
			if (hr < 0) throw new InvalidOperationException($"WMI {methodName} method execution failed. HRESULT: 0x{hr:X8}");

			if (outParams != null)
			{
				returnValuePtr = Marshal.StringToBSTR("ReturnValue");
				hr = outParams->Get(returnValuePtr, 0, out valReturn, IntPtr.Zero, IntPtr.Zero);
				if (hr == 0)
				{
					uint retVal = valReturn.uintVal;
					if (retVal != 0)
					{
						throw new InvalidOperationException($"WMI {methodName} returned error code: {retVal}");
					}
				}
			}
		}
		finally
		{
			_ = NativeMethods.VariantClear(ref valReturn);
			if (returnValuePtr != IntPtr.Zero) Marshal.FreeBSTR(returnValuePtr);
			if (objectPathPtr != IntPtr.Zero) Marshal.FreeBSTR(objectPathPtr);
			if (methodNamePtr != IntPtr.Zero) Marshal.FreeBSTR(methodNamePtr);
			if (classNamePtr != IntPtr.Zero) Marshal.FreeBSTR(classNamePtr);

			foreach (IntPtr bstr in allocatedBstrs)
			{
				Marshal.FreeBSTR(bstr);
			}

			if (outParams != null) _ = outParams->Release();
			if (inParams != null) _ = inParams->Release();
			if (outParamsDef != null) _ = outParamsDef->Release();
			if (inParamsDef != null) _ = inParamsDef->Release();
			if (classObj != null) _ = classObj->Release();
		}
	}

	private static void WipeDiskHeader(uint diskNumber)
	{
		// Open the physical drive and overwrite the first 1 MB with zeros.
		// This destroys MBR/GPT headers and forces the disk into RAW state.
		string physicalDrivePath = $@"\\.\PhysicalDrive{diskNumber}";

		IntPtr handle = Interop.NativeMethods.CreateFileW(
			physicalDrivePath,
			0x40000000, // GENERIC_WRITE
			NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE,
			IntPtr.Zero,
			NativeMethods.OPEN_EXISTING,
			0,
			IntPtr.Zero);

		if (handle == new IntPtr(-1))
		{
			throw new InvalidOperationException($"Failed to open {physicalDrivePath} for writing. Ensure the application is running as administrator.");
		}

		try
		{
			// Write 1 MB of zeros to wipe MBR/GPT/protective headers
			byte[] zeros = new byte[1024 * 1024];

			unsafe
			{
				fixed (byte* pZeros = zeros)
				{
					bool success = NativeMethods.WriteFile(
						handle,
						(IntPtr)pZeros,
						(uint)zeros.Length,
						out uint bytesWritten,
						IntPtr.Zero);

					if (!success || bytesWritten != (uint)zeros.Length)
					{
						throw new InvalidOperationException($"Failed to fully write zeros to {physicalDrivePath}.");
					}
				}
			}

			Logger.Write($"Successfully wiped first 1 MB of PhysicalDrive{diskNumber} to force RAW state.");
		}
		finally
		{
			_ = Interop.NativeMethods.CloseHandle(handle);
		}
	}

	private static unsafe uint GetDiskPartitionStyle(IWbemServices* services, uint diskNumber)
	{
		const int WBEM_FLAG_FORWARD_ONLY = 0x20;
		const int WBEM_FLAG_RETURN_IMMEDIATELY = 0x10;
		const int WBEM_INFINITE = -1;

		IEnumWbemClassObject* enumerator = null;
		IWbemClassObject* diskObj = null;

		IntPtr queryPtr = IntPtr.Zero;
		IntPtr queryLanguagePtr = IntPtr.Zero;
		IntPtr propName = IntPtr.Zero;

		VARIANT val = default;

		try
		{
			string query = $"SELECT PartitionStyle FROM MSFT_Disk WHERE Number = {diskNumber}";
			queryPtr = Marshal.StringToBSTR(query);
			queryLanguagePtr = Marshal.StringToBSTR("WQL");

			int hr = services->ExecQuery(
				queryLanguagePtr,
				queryPtr,
				WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
				IntPtr.Zero,
				out enumerator);

			if (hr < 0 || enumerator == null)
			{
				throw new InvalidOperationException($"Failed to query PartitionStyle for Disk {diskNumber}. HRESULT: 0x{hr:X8}");
			}

			hr = enumerator->Next(WBEM_INFINITE, 1, out diskObj, out uint returned);
			if (hr != 0 || returned == 0 || diskObj == null)
			{
				throw new InvalidOperationException($"Disk {diskNumber} not found when querying PartitionStyle.");
			}

			propName = Marshal.StringToBSTR("PartitionStyle");
			hr = diskObj->Get(propName, 0, out val, IntPtr.Zero, IntPtr.Zero);
			if (hr < 0)
			{
				throw new InvalidOperationException($"Failed to get PartitionStyle property. HRESULT: 0x{hr:X8}");
			}

			// PartitionStyle: 0 = RAW, 1 = MBR, 2 = GPT
			// WMI returns this as VT_I4 (3) or VT_UI2 (18) depending on provider version
			return val.uintVal;
		}
		finally
		{
			_ = NativeMethods.VariantClear(ref val);

			if (propName != IntPtr.Zero)
			{
				Marshal.FreeBSTR(propName);
			}

			if (queryLanguagePtr != IntPtr.Zero)
			{
				Marshal.FreeBSTR(queryLanguagePtr);
			}

			if (queryPtr != IntPtr.Zero)
			{
				Marshal.FreeBSTR(queryPtr);
			}

			if (diskObj != null)
			{
				_ = diskObj->Release();
			}

			if (enumerator != null)
			{
				_ = enumerator->Release();
			}
		}
	}
	internal static void CreateBootableDrive(string bootPartitionPath, string dataPartitionPath, string isoPath, IProgress<double> progress)
	{
		int hrInit = Interop.NativeMethods.CoInitializeEx(IntPtr.Zero, 0);

		// RPC_E_CHANGED_MODE = -2147417850 (0x80010106)
		// This happens if the thread is already initialized with a different concurrency model (in WinUI 3 apps)
		if (hrInit < 0 && hrInit != -2147417850)
		{
			throw new InvalidOperationException($"CoInitializeEx failed with HRESULT 0x{hrInit:X}");
		}

		// S_OK (0) and S_FALSE (1) indicate success and require balancing with CoUninitialize.
		bool requiresUninitialize = hrInit >= 0;

		try
		{
			int secHr = NativeMethods.CoInitializeSecurity(
				IntPtr.Zero,
				-1,
				IntPtr.Zero,
				IntPtr.Zero,
				0,
				3,
				IntPtr.Zero,
				0,
				IntPtr.Zero);

			// RPC_E_TOO_LATE = -2147417831 (0x80010119)
			// This happens if COM security is already initialized for the process (in WinUI 3 apps)
			if (secHr < 0 && secHr != -2147417831)
			{
				throw new InvalidOperationException($"CoInitializeSecurity failed with HRESULT 0x{secHr:X}");
			}

			EnablePrivileges();

			if (!File.Exists(isoPath))
			{
				throw new InvalidOperationException($"ISO file not found at '{isoPath}'");
			}

			if (!string.Equals(Path.GetExtension(isoPath), ".iso", StringComparison.OrdinalIgnoreCase))
			{
				throw new InvalidOperationException("File is not an ISO.");
			}

			if (!Directory.Exists(bootPartitionPath) || !Directory.Exists(dataPartitionPath))
			{
				throw new InvalidOperationException("Please ensure both BOOT and DATA partition paths exist and have correct drive letters.");
			}

			PerformSafetyChecks(bootPartitionPath, dataPartitionPath);

			Logger.Write($"Formatting BOOT partition ({bootPartitionPath}) as FAT32");
			FormatDrive(bootPartitionPath, "FAT32");

			Logger.Write($"Formatting DATA partition ({dataPartitionPath}) as NTFS");
			FormatDrive(dataPartitionPath, "NTFS");

			IntPtr handle = IntPtr.Zero;
			try
			{
				VIRTUAL_STORAGE_TYPE storageType = new()
				{
					DeviceId = VIRTUAL_STORAGE_TYPE.DeviceIdIso,
					VendorId = VIRTUAL_STORAGE_TYPE.VendorIdMicrosoft
				};

				OPEN_VIRTUAL_DISK_PARAMETERS openParameters = new()
				{
					Version = OPEN_VIRTUAL_DISK_VERSION.Version1,
					Version1 = new OpenVirtualDiskParametersVersion1
					{
						RWDepth = 1 // ISO is read-only
					}
				};

				// Open the Virtual Disk
				int openResult = NativeMethods.OpenVirtualDisk(
					ref storageType,
					isoPath,
					VIRTUAL_DISK_ACCESS_MASK.Read,
					OPEN_VIRTUAL_DISK_FLAG.None,
					ref openParameters,
					out handle);

				if (openResult != 0)
				{
					throw new InvalidOperationException($"Failed to open virtual disk. Error code: {openResult}.");
				}

				ATTACH_VIRTUAL_DISK_PARAMETERS attachParameters = new()
				{
					Version = AttachVirtualDiskVersion.Version1
				};

				// Attach the Virtual Disk (Mount)
				int attachResult = NativeMethods.AttachVirtualDisk(
					handle,
					IntPtr.Zero,
					ATTACH_VIRTUAL_DISK_FLAG.ReadOnly | ATTACH_VIRTUAL_DISK_FLAG.NoDriveLetter,
					0,
					ref attachParameters,
					IntPtr.Zero);

				if (attachResult != 0)
				{
					throw new InvalidOperationException($"Failed to attach virtual disk. Error code: {attachResult}");
				}

				// Get the physical path (Volume GUID path)
				int bufferSize = 260 * 2; // MAX_PATH wide chars
				IntPtr pathBuffer = Marshal.AllocHGlobal(bufferSize);
				try
				{
					int getPathResult = NativeMethods.GetVirtualDiskPhysicalPath(handle, ref bufferSize, pathBuffer);
					if (getPathResult != 0)
					{
						throw new InvalidOperationException($"Failed to get virtual disk physical path. Error code: {getPathResult}");
					}

					string physicalPath = Marshal.PtrToStringUni(pathBuffer) ?? string.Empty;
					if (!string.IsNullOrEmpty(physicalPath))
					{
						// Ensure the physical path has a trailing slash for Directory methods
						if (!physicalPath.EndsWith('\\'))
						{
							physicalPath += "\\";
						}

						Logger.Write($"Successfully mounted ISO at: {physicalPath}");

						// Calculate accurate total bytes accounting for all three copy phases:
						// Phase 1: Full ISO contents to DATA partition
						// Phase 2: ISO contents excluding "sources" folder to BOOT partition
						// Phase 3: boot.wim to BOOT partition's "sources" folder
						long isoTotalBytes = CalculateTotalBytes(physicalPath);
						long sourcesFolderSize = 0L;
						string sourcesDir = Path.Combine(physicalPath, "sources");
						if (Directory.Exists(sourcesDir))
						{
							sourcesFolderSize = CalculateTotalBytes(sourcesDir);
						}
						string bootWimPath = Path.Combine(physicalPath, "sources", "boot.wim");
						long bootWimSize = File.Exists(bootWimPath) ? new FileInfo(bootWimPath).Length : 0L;
						long totalBytesToCopy = isoTotalBytes + (isoTotalBytes - sourcesFolderSize) + bootWimSize;
						long copiedBytes = 0;

						Logger.Write($"Copying all contents from ISO to DATA partition ({dataPartitionPath})");
						copiedBytes = CopyDirectoryWithProgress(physicalPath, dataPartitionPath, totalBytesToCopy, copiedBytes, progress);

						Logger.Write($"Copying contents (excluding 'sources') to BOOT partition ({bootPartitionPath})");
						copiedBytes = CopyToBootPartitionWithProgress(physicalPath, bootPartitionPath, totalBytesToCopy, copiedBytes, progress);

						Logger.Write($"Copying boot.wim to BOOT partition's 'sources' folder");
						_ = CopyBootWimWithProgress(physicalPath, bootPartitionPath, totalBytesToCopy, copiedBytes, progress);

						// Explicitly report 100% completion to account for any minor precision loss or skipped empty items.
						progress.Report(100.0);
					}
				}
				finally
				{
					Marshal.FreeHGlobal(pathBuffer);
				}
			}
			finally
			{
				if (handle != IntPtr.Zero)
				{
					// Detach and close handle
					int detachResult = NativeMethods.DetachVirtualDisk(handle, DetachVirtualDiskFlag.None, 0);
					if (detachResult != 0)
					{
						Logger.Write($"Failed to detach virtual disk. Error code: {detachResult}");
					}

					_ = Interop.NativeMethods.CloseHandle(handle);
				}
			}
		}
		finally
		{
			if (requiresUninitialize)
			{
				Interop.NativeMethods.CoUninitialize();
			}
		}
	}

	internal static void ExtractISO(string isoPath, string destinationPath, IProgress<double> progress)
	{
		int hrInit = Interop.NativeMethods.CoInitializeEx(IntPtr.Zero, 0);

		// RPC_E_CHANGED_MODE = -2147417850 (0x80010106)
		// This happens if the thread is already initialized with a different concurrency model (in WinUI 3 apps)
		if (hrInit < 0 && hrInit != -2147417850)
		{
			throw new InvalidOperationException($"CoInitializeEx failed with HRESULT 0x{hrInit:X}");
		}

		// S_OK (0) and S_FALSE (1) indicate success and require balancing with CoUninitialize.
		bool requiresUninitialize = hrInit >= 0;

		int secHr = NativeMethods.CoInitializeSecurity(
			IntPtr.Zero,
			-1,
			IntPtr.Zero,
			IntPtr.Zero,
			0,
			3,
			IntPtr.Zero,
			0,
			IntPtr.Zero);

		// RPC_E_TOO_LATE = -2147417831 (0x80010119)
		// This happens if COM security is already initialized for the process (in WinUI 3 apps)
		if (secHr < 0 && secHr != -2147417831)
		{
			throw new InvalidOperationException($"CoInitializeSecurity failed with HRESULT 0x{secHr:X}");
		}

		try
		{
			EnablePrivileges();

			if (!File.Exists(isoPath))
			{
				throw new InvalidOperationException($"ISO file not found at '{isoPath}'");
			}

			if (!Directory.Exists(destinationPath))
			{
				_ = Directory.CreateDirectory(destinationPath);
			}

			IntPtr handle = IntPtr.Zero;
			try
			{
				VIRTUAL_STORAGE_TYPE storageType = new()
				{
					DeviceId = VIRTUAL_STORAGE_TYPE.DeviceIdIso,
					VendorId = VIRTUAL_STORAGE_TYPE.VendorIdMicrosoft
				};

				OPEN_VIRTUAL_DISK_PARAMETERS openParameters = new()
				{
					Version = OPEN_VIRTUAL_DISK_VERSION.Version1,
					Version1 = new OpenVirtualDiskParametersVersion1
					{
						RWDepth = 1 // ISO is read-only
					}
				};

				// Open the Virtual Disk
				int openResult = NativeMethods.OpenVirtualDisk(
					ref storageType,
					isoPath,
					VIRTUAL_DISK_ACCESS_MASK.Read,
					OPEN_VIRTUAL_DISK_FLAG.None,
					ref openParameters,
					out handle);

				if (openResult != 0)
				{
					throw new InvalidOperationException($"Failed to open virtual disk. Error code: {openResult}.");
				}

				ATTACH_VIRTUAL_DISK_PARAMETERS attachParameters = new()
				{
					Version = AttachVirtualDiskVersion.Version1
				};

				// Attach the Virtual Disk (Mount)
				int attachResult = NativeMethods.AttachVirtualDisk(
					handle,
					IntPtr.Zero,
					ATTACH_VIRTUAL_DISK_FLAG.ReadOnly | ATTACH_VIRTUAL_DISK_FLAG.NoDriveLetter,
					0,
					ref attachParameters,
					IntPtr.Zero);

				if (attachResult != 0)
				{
					throw new InvalidOperationException($"Failed to attach virtual disk. Error code: {attachResult}");
				}

				// Get the physical path (Volume GUID path)
				int bufferSize = 260 * 2; // MAX_PATH wide chars
				IntPtr pathBuffer = Marshal.AllocHGlobal(bufferSize);
				try
				{
					int getPathResult = NativeMethods.GetVirtualDiskPhysicalPath(handle, ref bufferSize, pathBuffer);
					if (getPathResult != 0)
					{
						throw new InvalidOperationException($"Failed to get virtual disk physical path. Error code: {getPathResult}");
					}

					string physicalPath = Marshal.PtrToStringUni(pathBuffer) ?? string.Empty;
					if (!string.IsNullOrEmpty(physicalPath))
					{
						// Ensure the physical path has a trailing slash for Directory methods
						if (!physicalPath.EndsWith('\\'))
						{
							physicalPath += "\\";
						}

						Logger.Write($"Successfully mounted ISO at: {physicalPath}. Extracting to: {destinationPath}");

						long totalBytesToCopy = CalculateTotalBytes(physicalPath);
						long copiedBytes = 0;

						_ = CopyDirectoryWithProgress(physicalPath, destinationPath, totalBytesToCopy, copiedBytes, progress);

						// Explicitly report 100% completion to account for any minor precision loss or skipped empty items.
						progress.Report(100.0);
					}
				}
				finally
				{
					Marshal.FreeHGlobal(pathBuffer);
				}
			}
			finally
			{
				if (handle != IntPtr.Zero)
				{
					// Detach and close handle
					int detachResult = NativeMethods.DetachVirtualDisk(handle, DetachVirtualDiskFlag.None, 0);
					if (detachResult != 0)
					{
						Logger.Write($"Failed to detach virtual disk. Error code: {detachResult}");
					}

					_ = Interop.NativeMethods.CloseHandle(handle);
				}
			}
		}
		finally
		{
			if (requiresUninitialize)
			{
				Interop.NativeMethods.CoUninitialize();
			}
		}
	}

	private static long CalculateTotalBytes(string directoryPath)
	{
		long totalSize = 0;
		DirectoryInfo d = new(directoryPath);

		FileInfo[] fis = d.GetFiles();
		foreach (FileInfo fi in fis)
		{
			totalSize += fi.Length;
		}

		DirectoryInfo[] dis = d.GetDirectories();
		foreach (DirectoryInfo di in dis)
		{
			totalSize += CalculateTotalBytes(di.FullName);
		}

		return totalSize;
	}

	private static long CopyDirectoryWithProgress(string sourceDir, string destinationDir, long totalBytesToCopy, long currentCopiedBytes, IProgress<double> progress)
	{
		DirectoryInfo directoryInfo = new(sourceDir);

		if (!directoryInfo.Exists)
		{
			throw new DirectoryNotFoundException($"Source directory not found: {directoryInfo.FullName}");
		}

		DirectoryInfo[] directories = directoryInfo.GetDirectories();
		_ = Directory.CreateDirectory(destinationDir);

		FileInfo[] files = directoryInfo.GetFiles();
		foreach (FileInfo file in files)
		{
			string targetFilePath = Path.Combine(destinationDir, file.Name);
			currentCopiedBytes = CopyFileWithProgress(file.FullName, targetFilePath, file.Length, totalBytesToCopy, currentCopiedBytes, progress);
		}

		foreach (DirectoryInfo subDir in directories)
		{
			string newDestinationDir = Path.Combine(destinationDir, subDir.Name);
			currentCopiedBytes = CopyDirectoryWithProgress(subDir.FullName, newDestinationDir, totalBytesToCopy, currentCopiedBytes, progress);
		}

		return currentCopiedBytes;
	}

	private static long CopyToBootPartitionWithProgress(string sourceDir, string destinationDir, long totalBytesToCopy, long currentCopiedBytes, IProgress<double> progress)
	{
		DirectoryInfo directoryInfo = new(sourceDir);

		if (!directoryInfo.Exists)
		{
			throw new DirectoryNotFoundException($"Source directory not found: {directoryInfo.FullName}");
		}

		DirectoryInfo[] directories = directoryInfo.GetDirectories();
		_ = Directory.CreateDirectory(destinationDir);

		FileInfo[] files = directoryInfo.GetFiles();
		foreach (FileInfo file in files)
		{
			string targetFilePath = Path.Combine(destinationDir, file.Name);
			currentCopiedBytes = CopyFileWithProgress(file.FullName, targetFilePath, file.Length, totalBytesToCopy, currentCopiedBytes, progress);
		}

		foreach (DirectoryInfo subDir in directories)
		{
			// Exclude the "sources" folder completely when copying to the FAT32 partition
			if (string.Equals(subDir.Name, "sources", StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}

			string newDestinationDir = Path.Combine(destinationDir, subDir.Name);
			// For remaining subdirectories, we can use the normal CopyDirectory method
			currentCopiedBytes = CopyDirectoryWithProgress(subDir.FullName, newDestinationDir, totalBytesToCopy, currentCopiedBytes, progress);
		}

		return currentCopiedBytes;
	}

	private static long CopyBootWimWithProgress(string sourceDir, string destinationDir, long totalBytesToCopy, long currentCopiedBytes, IProgress<double> progress)
	{
		string sourceBootWimPath = Path.Combine(sourceDir, "sources", "boot.wim");
		string destSourcesDir = Path.Combine(destinationDir, "sources");
		string destBootWimPath = Path.Combine(destSourcesDir, "boot.wim");

		// Create a new folder in the FAT32 partition and name it "sources"
		_ = Directory.CreateDirectory(destSourcesDir);

		// Copy boot.wim from ISO to the BOOT partition
		if (File.Exists(sourceBootWimPath))
		{
			FileInfo fileInfo = new(sourceBootWimPath);
			currentCopiedBytes = CopyFileWithProgress(sourceBootWimPath, destBootWimPath, fileInfo.Length, totalBytesToCopy, currentCopiedBytes, progress);
			Logger.Write($"Successfully copied boot.wim to {destBootWimPath}");
		}
		else
		{
			throw new InvalidOperationException($"boot.wim not found at {sourceBootWimPath}");
		}

		return currentCopiedBytes;
	}

	private static long CopyFileWithProgress(string source, string destination, long fileSize, long totalBytesToCopy, long currentCopiedBytes, IProgress<double> progress)
	{
		byte[] buffer = new byte[81920];
		using FileStream fs = new(source, FileMode.Open, FileAccess.Read, FileShare.Read);
		using FileStream fd = new(destination, FileMode.Create, FileAccess.Write, FileShare.None);

		int bytesRead;
		while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
		{
			fd.Write(buffer, 0, bytesRead);
			currentCopiedBytes += bytesRead;

			if (totalBytesToCopy > 0)
			{
				double percentage = (double)currentCopiedBytes / totalBytesToCopy * 100.0;
				progress.Report(percentage > 100.0 ? 100.0 : percentage);
			}
		}
		return currentCopiedBytes;
	}

	internal static void CopyDirectory(string sourceDir, string destinationDir)
	{
		DirectoryInfo directoryInfo = new(sourceDir);

		if (!directoryInfo.Exists)
		{
			throw new DirectoryNotFoundException($"Source directory not found: {directoryInfo.FullName}");
		}

		DirectoryInfo[] directories = directoryInfo.GetDirectories();
		_ = Directory.CreateDirectory(destinationDir);

		FileInfo[] files = directoryInfo.GetFiles();
		foreach (FileInfo file in files)
		{
			string targetFilePath = Path.Combine(destinationDir, file.Name);

			// Calculate size in MB
			long sizeInMB = file.Length / (1024 * 1024);
			Logger.Write($"Copying: {file.Name} ({sizeInMB} MB)...");

			_ = file.CopyTo(targetFilePath, overwrite: true);
		}

		foreach (DirectoryInfo subDir in directories)
		{
			string newDestinationDir = Path.Combine(destinationDir, subDir.Name);
			CopyDirectory(subDir.FullName, newDestinationDir);
		}
	}

	internal static void CopyToBootPartition(string sourceDir, string destinationDir)
	{
		DirectoryInfo directoryInfo = new(sourceDir);

		if (!directoryInfo.Exists)
		{
			throw new DirectoryNotFoundException($"Source directory not found: {directoryInfo.FullName}");
		}

		DirectoryInfo[] directories = directoryInfo.GetDirectories();
		_ = Directory.CreateDirectory(destinationDir);

		FileInfo[] files = directoryInfo.GetFiles();
		foreach (FileInfo file in files)
		{
			string targetFilePath = Path.Combine(destinationDir, file.Name);

			long sizeInMB = file.Length / (1024 * 1024);
			Logger.Write($"Copying to BOOT: {file.Name} ({sizeInMB} MB)...");

			_ = file.CopyTo(targetFilePath, overwrite: true);
		}

		foreach (DirectoryInfo subDir in directories)
		{
			// Exclude the "sources" folder completely when copying to the FAT32 partition
			if (string.Equals(subDir.Name, "sources", StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}

			string newDestinationDir = Path.Combine(destinationDir, subDir.Name);

			// For remaining subdirectories, we can use the normal CopyDirectory method
			CopyDirectory(subDir.FullName, newDestinationDir);
		}
	}

	internal static void CopyBootWim(string sourceDir, string destinationDir)
	{
		string sourceBootWimPath = Path.Combine(sourceDir, "sources", "boot.wim");
		string destSourcesDir = Path.Combine(destinationDir, "sources");
		string destBootWimPath = Path.Combine(destSourcesDir, "boot.wim");

		// Create a new folder in the FAT32 partition and name it "sources"
		_ = Directory.CreateDirectory(destSourcesDir);

		// Copy boot.wim from ISO to the BOOT partition
		if (File.Exists(sourceBootWimPath))
		{
			FileInfo fileInfo = new(sourceBootWimPath);
			long sizeInMB = fileInfo.Length / (1024 * 1024);
			Logger.Write($"Copying to BOOT: boot.wim ({sizeInMB} MB)...");

			File.Copy(sourceBootWimPath, destBootWimPath, overwrite: true);
			Logger.Write($"Successfully copied boot.wim to {destBootWimPath}");
		}
		else
		{
			throw new InvalidOperationException($"boot.wim not found at {sourceBootWimPath}");
		}
	}

	internal static void EnablePrivileges()
	{
		const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
		const uint TOKEN_QUERY = 0x0008;
		const uint SE_PRIVILEGE_ENABLED = 0x00000002;

		if (Interop.NativeMethods.OpenProcessToken(Interop.NativeMethods.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr tokenHandle))
		{
			try
			{
				string[] privileges =
				[
					"SeManageVolumePrivilege",
					"SeBackupPrivilege",
					"SeRestorePrivilege",
					"SeSecurityPrivilege"
				];

				foreach (string priv in privileges)
				{
					if (Interop.NativeMethods.LookupPrivilegeValueW(null, priv, out LUID luid))
					{
						TOKEN_PRIVILEGES tp = new()
						{
							PrivilegeCount = 1
						};
						tp.Privileges.Luid = luid;
						tp.Privileges.Attributes = SE_PRIVILEGE_ENABLED;

						_ = Interop.NativeMethods.AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
					}
				}
			}
			finally
			{
				_ = Interop.NativeMethods.CloseHandle(tokenHandle);
			}
		}
	}

	internal static void PerformSafetyChecks(string bootPartitionPath, string dataPartitionPath)
	{
		DriveInfo bootDrive = new(bootPartitionPath);
		DriveInfo dataDrive = new(dataPartitionPath);

		// Check if the drive letters are different
		if (string.Equals(bootDrive.Name, dataDrive.Name, StringComparison.OrdinalIgnoreCase))
		{
			throw new InvalidOperationException("BOOT and DATA partitions must have different drive letters.");
		}

		// Check neither path points to a system drive
		string? systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System));
		if (string.Equals(bootDrive.Name, systemDrive, StringComparison.OrdinalIgnoreCase) ||
			string.Equals(dataDrive.Name, systemDrive, StringComparison.OrdinalIgnoreCase))
		{
			throw new InvalidOperationException("One of the specified target drives is the system drive.");
		}

		// Check both paths are Removable
		if (bootDrive.DriveType != DriveType.Removable || dataDrive.DriveType != DriveType.Removable)
		{
			throw new InvalidOperationException($"Both drives must be removable USB drives. BOOT is {bootDrive.DriveType}, DATA is {dataDrive.DriveType}.");
		}

		// Both belong to the intended USB device (same physical disk)
		uint bootPhysicalDisk = GetPhysicalDiskNumber(bootDrive.Name);
		uint dataPhysicalDisk = GetPhysicalDiskNumber(dataDrive.Name);

		if (bootPhysicalDisk == uint.MaxValue || dataPhysicalDisk == uint.MaxValue)
		{
			throw new InvalidOperationException("Could not determine the physical disk numbers of the provided drives.");
		}

		if (bootPhysicalDisk != dataPhysicalDisk)
		{
			throw new InvalidOperationException($"The BOOT partition (Disk {bootPhysicalDisk}) and DATA partition (Disk {dataPhysicalDisk}) are not located on the same physical USB device.");
		}

		// BOOT partition is FAT32-capable and appropriately sized
		const long minBootSizeBytes = 1900L * 1024 * 1024; // 1900 MB allowed minimum for overhead
		const long maxFat32SizeBytes = 32L * 1024 * 1024 * 1024; // 32 GB maximum
		const long minDataSizeBytes = 7900L * 1024 * 1024; // 7900 MB allowed minimum for overhead

		if (bootDrive.TotalSize < minBootSizeBytes)
		{
			throw new InvalidOperationException($"BOOT partition is smaller than the required 2 GB minimum. Current size: {bootDrive.TotalSize / (1024 * 1024)} MB.");
		}

		if (bootDrive.TotalSize > maxFat32SizeBytes)
		{
			throw new InvalidOperationException($"BOOT partition is larger than 32GB, which cannot be formatted as FAT32. Current size: {bootDrive.TotalSize / (1024 * 1024)} MB.");
		}

		if (dataDrive.TotalSize < minDataSizeBytes)
		{
			throw new InvalidOperationException($"DATA partition is smaller than the required 8 GB minimum. Current size: {dataDrive.TotalSize / (1024 * 1024)} MB.");
		}

		// DATA partition is the intended NTFS partition
		if (dataDrive.TotalSize < bootDrive.TotalSize)
		{
			throw new InvalidOperationException("The DATA partition is smaller than the BOOT partition. Double-check your drive letters to ensure they aren't swapped.");
		}

		// Drives are not read-only
		if (!IsDriveWritable(bootDrive.Name))
		{
			throw new InvalidOperationException($"BOOT partition ({bootDrive.Name}) appears to be read-only.");
		}

		if (!IsDriveWritable(dataDrive.Name))
		{
			throw new InvalidOperationException($"DATA partition ({dataDrive.Name}) appears to be read-only.");
		}
	}

	internal static uint GetPhysicalDiskNumber(string drivePath)
	{
		string driveLetter = Path.GetPathRoot(drivePath) ?? string.Empty;
		if (string.IsNullOrEmpty(driveLetter))
		{
			return uint.MaxValue;
		}

		// Create a device path like "\\.\C:"
		string devicePath = $@"\\.\{driveLetter[0]}:";

		IntPtr handle = Interop.NativeMethods.CreateFileW(
			devicePath,
			0, // 0 = Generic access to query device metadata
			NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE,
			IntPtr.Zero,
			NativeMethods.OPEN_EXISTING,
			0,
			IntPtr.Zero);

		if (handle == new IntPtr(-1)) // INVALID_HANDLE_VALUE
		{
			return uint.MaxValue;
		}

		try
		{
			STORAGE_DEVICE_NUMBER deviceNumber = new();
			uint size;
			unsafe
			{
				size = (uint)sizeof(STORAGE_DEVICE_NUMBER);
			}

			bool success = NativeMethods.DeviceIoControl(
				handle,
				NativeMethods.IOCTL_STORAGE_GET_DEVICE_NUMBER,
				IntPtr.Zero,
				0,
				ref deviceNumber,
				size,
				out uint bytesReturned,
				IntPtr.Zero);

			if (success)
			{
				return deviceNumber.DeviceNumber;
			}
		}
		finally
		{
			_ = Interop.NativeMethods.CloseHandle(handle);
		}

		return uint.MaxValue;
	}

	internal static bool IsDriveWritable(string drivePath)
	{
		string testFilePath = Path.Combine(drivePath, $"write_test_{Guid.CreateVersion7():N}.tmp");

		try
		{
			// FileOptions.DeleteOnClose guarantees the file cleans itself up after the handle drops
			using FileStream fs = new(testFilePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.DeleteOnClose);
			fs.WriteByte(0x00);
			return true;
		}
		catch (UnauthorizedAccessException)
		{
			return false;
		}
		catch (IOException)
		{
			return false;
		}
	}

	private static unsafe int PutVariant(IWbemClassObject* obj, IntPtr paramName, in VARIANT variant)
	{
		fixed (VARIANT* pVariant = &variant)
		{
			return obj->Put(paramName, 0, (IntPtr)pVariant, 0);
		}
	}

	internal static unsafe void FormatDrive(string drivePath, string fileSystem)
	{
		string driveLetter = Path.GetPathRoot(drivePath) ?? string.Empty;

		if (driveLetter.EndsWith('\\'))
		{
			driveLetter = driveLetter[..^1];
		}

		if (string.IsNullOrEmpty(driveLetter) || driveLetter.Length < 2)
		{
			throw new InvalidOperationException("Invalid drive path provided for formatting.");
		}

		char driveChar = driveLetter[0];

		Guid CLSID_WbemLocator = new("4590F811-1D3A-11D0-891F-00AA004B2E24");
		Guid IID_IWbemLocator = new("DC12A687-737F-11CF-884D-00AA004B2E24");

		const uint CLSCTX_INPROC_SERVER = 1;
		const uint RPC_C_AUTHN_WINNT = 10;
		const uint RPC_C_AUTHZ_NONE = 0;
		const uint RPC_C_AUTHN_LEVEL_CALL = 3;
		const uint RPC_C_IMP_LEVEL_IMPERSONATE = 3;
		const int WBEM_FLAG_FORWARD_ONLY = 0x20;
		const int WBEM_FLAG_RETURN_IMMEDIATELY = 0x10;
		const int WBEM_INFINITE = -1;

		IWbemLocator* locator = null;
		IWbemServices* services = null;
		IEnumWbemClassObject* enumerator = null;
		IWbemClassObject* volumeObj = null;
		IWbemClassObject* classObj = null;
		IWbemClassObject* inParamsDef = null;
		IWbemClassObject* outParamsDef = null;
		IWbemClassObject* inParams = null;
		IWbemClassObject* outParams = null;

		IntPtr rootNamespacePtr = IntPtr.Zero;
		IntPtr queryPtr = IntPtr.Zero;
		IntPtr queryLanguagePtr = IntPtr.Zero;
		IntPtr pathPropName = IntPtr.Zero;
		IntPtr classNamePtr = IntPtr.Zero;
		IntPtr methodNamePtr = IntPtr.Zero;
		IntPtr fileSystemNamePtr = IntPtr.Zero;
		IntPtr volumePathPtr = IntPtr.Zero;
		IntPtr returnValuePtr = IntPtr.Zero;

		VARIANT valPath = default;
		VARIANT valReturn = default;

		try
		{
			int hr = NativeMethods.CoCreateInstanceWbemLocator(
				in CLSID_WbemLocator,
				IntPtr.Zero,
				CLSCTX_INPROC_SERVER,
				in IID_IWbemLocator,
				out locator);

			if (hr < 0 || locator == null)
			{
				throw new InvalidOperationException($"Failed to create IWbemLocator. HRESULT: 0x{hr:X8}");
			}

			const string rootNamespace = "root\\Microsoft\\Windows\\Storage";
			rootNamespacePtr = Marshal.StringToBSTR(rootNamespace);

			hr = locator->ConnectServer(
				rootNamespacePtr,
				IntPtr.Zero,
				IntPtr.Zero,
				IntPtr.Zero,
				0,
				IntPtr.Zero,
				IntPtr.Zero,
				out services);

			if (hr < 0 || services == null)
			{
				throw new InvalidOperationException($"Failed to connect to Storage WMI namespace. HRESULT: 0x{hr:X8}");
			}

			hr = NativeMethods.CoSetProxyBlanket(
				services,
				RPC_C_AUTHN_WINNT,
				RPC_C_AUTHZ_NONE,
				IntPtr.Zero,
				RPC_C_AUTHN_LEVEL_CALL,
				RPC_C_IMP_LEVEL_IMPERSONATE,
				IntPtr.Zero,
				0);

			if (hr < 0)
			{
				throw new InvalidOperationException($"Failed to set proxy blanket. HRESULT: 0x{hr:X8}");
			}

			string query = $"SELECT * FROM MSFT_Volume WHERE DriveLetter = '{driveChar}'";
			queryPtr = Marshal.StringToBSTR(query);
			queryLanguagePtr = Marshal.StringToBSTR("WQL");

			hr = services->ExecQuery(
				queryLanguagePtr,
				queryPtr,
				WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
				IntPtr.Zero,
				out enumerator);

			if (hr < 0 || enumerator == null)
			{
				throw new InvalidOperationException($"Failed to execute WMI query. HRESULT: 0x{hr:X8}");
			}

			hr = enumerator->Next(WBEM_INFINITE, 1, out volumeObj, out uint returned);
			if (hr != 0 || returned == 0 || volumeObj == null)
			{
				throw new InvalidOperationException($"Volume with drive letter {driveChar} not found.");
			}

			pathPropName = Marshal.StringToBSTR("__PATH");
			hr = volumeObj->Get(pathPropName, 0, out valPath, IntPtr.Zero, IntPtr.Zero);
			if (hr < 0 || valPath.vt != 8 || valPath.bstrVal == IntPtr.Zero)
			{
				throw new InvalidOperationException("Failed to get volume WMI path.");
			}

			string volumePath = Marshal.PtrToStringBSTR(valPath.bstrVal) ?? string.Empty;

			classNamePtr = Marshal.StringToBSTR("MSFT_Volume");
			methodNamePtr = Marshal.StringToBSTR("Format");

			hr = services->GetObject(classNamePtr, 0, IntPtr.Zero, out classObj, IntPtr.Zero);
			if (hr < 0 || classObj == null)
			{
				throw new InvalidOperationException($"Failed to get MSFT_Volume class. HRESULT: 0x{hr:X8}");
			}

			hr = classObj->GetMethod(methodNamePtr, 0, out inParamsDef, out outParamsDef);
			if (hr < 0 || inParamsDef == null)
			{
				throw new InvalidOperationException($"Failed to get Format method definitions. HRESULT: 0x{hr:X8}");
			}

			hr = inParamsDef->SpawnInstance(0, out inParams);
			if (hr < 0 || inParams == null)
			{
				throw new InvalidOperationException($"Failed to spawn method parameters instance. HRESULT: 0x{hr:X8}");
			}

			fileSystemNamePtr = Marshal.StringToBSTR("FileSystem");

			IntPtr fileSystemValueBstr = IntPtr.Zero;

			try
			{
				fileSystemValueBstr = Marshal.StringToBSTR(fileSystem);
				VARIANT fileSystemValue = new() { vt = 8, bstrVal = fileSystemValueBstr };
				hr = PutVariant(inParams, fileSystemNamePtr, in fileSystemValue);

				if (hr < 0)
				{
					throw new InvalidOperationException($"Failed to set FileSystem. HRESULT: 0x{hr:X8}");
				}
			}
			finally
			{
				if (fileSystemValueBstr != IntPtr.Zero)
				{
					Marshal.FreeBSTR(fileSystemValueBstr);
				}
			}

			volumePathPtr = Marshal.StringToBSTR(volumePath);

			hr = services->ExecMethod(
				volumePathPtr,
				methodNamePtr,
				0,
				IntPtr.Zero,
				inParams,
				out outParams,
				IntPtr.Zero);

			if (hr < 0)
			{
				throw new InvalidOperationException($"WMI Format method execution failed. HRESULT: 0x{hr:X8}");
			}

			if (outParams != null)
			{
				returnValuePtr = Marshal.StringToBSTR("ReturnValue");
				hr = outParams->Get(returnValuePtr, 0, out valReturn, IntPtr.Zero, IntPtr.Zero);
				if (hr == 0)
				{
					uint retVal = valReturn.uintVal;

					if (retVal != 0)
					{
						throw new InvalidOperationException($"WMI Format returned error code: {retVal}");
					}
				}
			}

			Logger.Write($"Successfully formatted {driveLetter} as {fileSystem}.");
		}
		finally
		{
			// Safe cleanup for all allocated pointers, BSTRs and VARIANTs
			_ = NativeMethods.VariantClear(ref valPath);
			_ = NativeMethods.VariantClear(ref valReturn);

			if (returnValuePtr != IntPtr.Zero) Marshal.FreeBSTR(returnValuePtr);
			if (volumePathPtr != IntPtr.Zero) Marshal.FreeBSTR(volumePathPtr);
			if (fileSystemNamePtr != IntPtr.Zero) Marshal.FreeBSTR(fileSystemNamePtr);
			if (methodNamePtr != IntPtr.Zero) Marshal.FreeBSTR(methodNamePtr);
			if (classNamePtr != IntPtr.Zero) Marshal.FreeBSTR(classNamePtr);
			if (pathPropName != IntPtr.Zero) Marshal.FreeBSTR(pathPropName);
			if (queryLanguagePtr != IntPtr.Zero) Marshal.FreeBSTR(queryLanguagePtr);
			if (queryPtr != IntPtr.Zero) Marshal.FreeBSTR(queryPtr);
			if (rootNamespacePtr != IntPtr.Zero) Marshal.FreeBSTR(rootNamespacePtr);

			if (outParams != null) _ = outParams->Release();
			if (inParams != null) _ = inParams->Release();
			if (outParamsDef != null) _ = outParamsDef->Release();
			if (inParamsDef != null) _ = inParamsDef->Release();
			if (classObj != null) _ = classObj->Release();
			if (volumeObj != null) _ = volumeObj->Release();
			if (enumerator != null) _ = enumerator->Release();
			if (services != null) _ = services->Release();
			if (locator != null) _ = locator->Release();
		}
	}

	internal static partial class NativeMethods
	{
		internal const uint FILE_SHARE_READ = 0x00000001;
		internal const uint FILE_SHARE_WRITE = 0x00000002;
		internal const uint OPEN_EXISTING = 3;
		internal const uint IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x2D1080;

		[LibraryImport("kernel32.dll")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static partial bool WriteFile(
		IntPtr hFile,
		IntPtr lpBuffer,
		uint nNumberOfBytesToWrite,
		out uint lpNumberOfBytesWritten,
		IntPtr lpOverlapped);

		[LibraryImport("OLE32")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial int CoInitializeSecurity(
			IntPtr pSecDesc,
			int cAuthSvc,
			IntPtr asAuthSvc,
			IntPtr pReserved1,
			uint dwAuthnLevel,
			uint dwImpLevel,
			IntPtr pAuthList,
			uint dwCapabilities,
			IntPtr pReserved3);

		[LibraryImport("kernel32.dll")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static partial bool DeviceIoControl(
			IntPtr hDevice,
			uint dwIoControlCode,
			IntPtr lpInBuffer,
			uint nInBufferSize,
			ref STORAGE_DEVICE_NUMBER lpOutBuffer,
			uint nOutBufferSize,
			out uint lpBytesReturned,
			IntPtr lpOverlapped);

		[LibraryImport("virtdisk.dll", StringMarshalling = StringMarshalling.Utf16)]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial int OpenVirtualDisk(
			ref VIRTUAL_STORAGE_TYPE virtualStorageType,
			string path,
			VIRTUAL_DISK_ACCESS_MASK virtualDiskAccessMask,
			OPEN_VIRTUAL_DISK_FLAG flags,
			ref OPEN_VIRTUAL_DISK_PARAMETERS parameters,
			out IntPtr handle);

		// https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-attachvirtualdisk
		[LibraryImport("virtdisk.dll")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial int AttachVirtualDisk(
			IntPtr virtualDiskHandle,
			IntPtr securityDescriptor,
			ATTACH_VIRTUAL_DISK_FLAG flags,
			int providerSpecificFlags,
			ref ATTACH_VIRTUAL_DISK_PARAMETERS parameters,
			IntPtr overlapped);

		// https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-detachvirtualdisk
		[LibraryImport("virtdisk.dll")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial int DetachVirtualDisk(
			IntPtr virtualDiskHandle,
			DetachVirtualDiskFlag flags,
			int providerSpecificFlags);

		// https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-getvirtualdiskphysicalpath
		[LibraryImport("virtdisk.dll", StringMarshalling = StringMarshalling.Utf16)]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial int GetVirtualDiskPhysicalPath(
			IntPtr virtualDiskHandle,
			ref int diskPathSizeInBytes,
			IntPtr diskPath);

		[LibraryImport("OLE32", EntryPoint = "CoCreateInstance")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static unsafe partial int CoCreateInstanceWbemLocator(
			in Guid rclsid,
			IntPtr pUnkOuter,
			uint dwClsContext,
			in Guid riid,
			out IWbemLocator* ppv);

		[LibraryImport("OLE32")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static unsafe partial int CoSetProxyBlanket(
			IWbemServices* pProxy,
			uint dwAuthnSvc,
			uint dwAuthzSvc,
			IntPtr pServerPrincName,
			uint dwAuthnLevel,
			uint dwImpLevel,
			IntPtr pAuthInfo,
			uint dwCapabilities);

		[LibraryImport("oleaut32.dll")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial int VariantClear(ref VARIANT pvarg);
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct STORAGE_DEVICE_NUMBER
	{
		internal uint DeviceType;
		internal uint DeviceNumber;
		internal uint PartitionNumber;
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/ns-virtdisk-virtual_storage_type
	[StructLayout(LayoutKind.Sequential)]
	internal struct VIRTUAL_STORAGE_TYPE
	{
		internal uint DeviceId;
		internal Guid VendorId;

		internal const uint DeviceIdIso = 1;
		internal static readonly Guid VendorIdMicrosoft = new("EC984AEC-A0F9-47e9-901F-71415A66345B");
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/ne-virtdisk-virtual_disk_access_mask-r1
	[Flags]
	internal enum VIRTUAL_DISK_ACCESS_MASK : int
	{
		None = 0,
		AttachRo = 0x00010000,
		AttachRw = 0x00020000,
		Detach = 0x00040000,
		GetInfo = 0x00080000,
		Create = 0x00100000,
		Metaops = 0x00200000,
		Read = 0x000d0000,
		All = 0x003f0000,
		WRITABLE = 0x00320000
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/ne-virtdisk-open_virtual_disk_flag
	[Flags]
	internal enum OPEN_VIRTUAL_DISK_FLAG : int
	{
		None = 0x00000000,
		NoParents = 0x00000001,
		BlankFile = 0x00000002,
		BootDrive = 0x00000004,
		CachedIo = 0x00000008,
		CustomDiffChain = 0x00000010,
		ParentCachedIo = 0x00000020,
		VhdsetFileOnly = 0x00000040,
		IgnoreRelativeParentLocator = 0x00000080,
		NoWriteHardening = 0x00000100,
		SupportCompressedVolumes = 0x00000200,
		SupportSparseFilesAnyFs = 0x00000400,
		SupportEncryptedFiles = 0x00000800
	}

	internal enum OPEN_VIRTUAL_DISK_VERSION : int
	{
		VersionUnspecified = 0,
		Version1 = 1,
		Version2 = 2,
		Version3 = 3
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/ns-virtdisk-open_virtual_disk_parameters
	[StructLayout(LayoutKind.Explicit, Size = 32)]
	internal struct OPEN_VIRTUAL_DISK_PARAMETERS
	{
		[FieldOffset(0)]
		internal OPEN_VIRTUAL_DISK_VERSION Version;

		// Native layout places the union at offset 8 because the 4-byte Version
		// field is followed by 4 bytes of padding to satisfy alignment.
		[FieldOffset(8)]
		internal OpenVirtualDiskParametersVersion1 Version1;

		[FieldOffset(8)]
		internal OpenVirtualDiskParametersVersion2 Version2;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct OpenVirtualDiskParametersVersion1
	{
		internal uint RWDepth;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct OpenVirtualDiskParametersVersion2
	{
		// Native BOOL is a 4-byte signed integer.
		internal int GetInfoOnly;

		// Native BOOL is a 4-byte signed integer.
		internal int ReadOnly;

		internal Guid ResiliencyGuid;
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/ne-virtdisk-attach_virtual_disk_flags
	[Flags]
	internal enum ATTACH_VIRTUAL_DISK_FLAG : int
	{
		None = 0x00000000,
		ReadOnly = 0x00000001,
		NoDriveLetter = 0x00000002,
		PermanentLifetime = 0x00000004,
		NoLocalHost = 0x00000008,
		NoSecurityDescriptor = 0x00000010,
		BypassDefaultEncryptionPolicy = 0x00000020,
		NonPnp = 0x00000040,
		RestrictedRange = 0x00000080,
		SinglePartition = 0x00000100,
		RegisterVolume = 0x00000200,
		AtBoot = 0x00000400
	}

	internal enum AttachVirtualDiskVersion : int
	{
		VersionUnspecified = 0,
		Version1 = 1,
		Version2 = 2
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/ns-virtdisk-attach_virtual_disk_parameters
	[StructLayout(LayoutKind.Explicit, Size = 24)]
	internal struct ATTACH_VIRTUAL_DISK_PARAMETERS
	{
		[FieldOffset(0)]
		internal AttachVirtualDiskVersion Version;

		// Offset is 8 due to the 4-byte padding added by the C/C++ compiler
		// to align the 64-bit integers (ulong) in the union to an 8-byte boundary.
		[FieldOffset(8)]
		internal AttachVirtualDiskParametersVersion1 Version1;

		// Union fields share the same starting offset.
		// Adding Version2 ensures the struct is correctly sized to 24 bytes in memory.
		[FieldOffset(8)]
		internal AttachVirtualDiskParametersVersion2 Version2;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct AttachVirtualDiskParametersVersion1
	{
		internal uint Reserved;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct AttachVirtualDiskParametersVersion2
	{
		internal ulong RestrictedOffset;
		internal ulong RestrictedLength;
	}

	[Flags]
	internal enum DetachVirtualDiskFlag : int
	{
		None = 0x00000000
	}

	[StructLayout(LayoutKind.Explicit, Size = 24)]
	internal struct VARIANT
	{
		[FieldOffset(0)] internal ushort vt;
		[FieldOffset(2)] internal ushort wReserved1;
		[FieldOffset(4)] internal ushort wReserved2;
		[FieldOffset(6)] internal ushort wReserved3;
		[FieldOffset(8)] internal IntPtr bstrVal;
		[FieldOffset(8)] internal long llVal;
		[FieldOffset(8)] internal int lVal;
		[FieldOffset(8)] internal uint uintVal;
		[FieldOffset(8)] internal short boolVal;
		[FieldOffset(8)] internal ulong ullVal;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal unsafe struct IWbemLocator
	{
		internal void** lpVtbl;

		internal uint Release()
		{
			return ((delegate* unmanaged<IWbemLocator*, uint>)lpVtbl[2])((IWbemLocator*)Unsafe.AsPointer(ref this));
		}

		internal int ConnectServer(
			IntPtr strNetworkResource,
			IntPtr strUser,
			IntPtr strPassword,
			IntPtr strLocale,
			int lSecurityFlags,
			IntPtr strAuthority,
			IntPtr pCtx,
			out IWbemServices* ppNamespace)
		{
			IWbemServices* pNamespace;
			int hr = ((delegate* unmanaged<IWbemLocator*, IntPtr, IntPtr, IntPtr, IntPtr, int, IntPtr, IntPtr, IWbemServices**, int>)lpVtbl[3])(
				(IWbemLocator*)Unsafe.AsPointer(ref this), strNetworkResource, strUser, strPassword, strLocale, lSecurityFlags, strAuthority, pCtx, &pNamespace);
			ppNamespace = pNamespace;
			return hr;
		}
	}

	[StructLayout(LayoutKind.Sequential)]
	internal unsafe struct IWbemServices
	{
		internal void** lpVtbl;

		internal uint Release()
		{
			return ((delegate* unmanaged<IWbemServices*, uint>)lpVtbl[2])((IWbemServices*)Unsafe.AsPointer(ref this));
		}

		internal int GetObject(
			IntPtr strObjectPath,
			int lFlags,
			IntPtr pCtx,
			out IWbemClassObject* ppObject,
			IntPtr ppCallResult)
		{
			IWbemClassObject* pObject;
			int hr = ((delegate* unmanaged<IWbemServices*, IntPtr, int, IntPtr, IWbemClassObject**, IntPtr, int>)lpVtbl[6])(
				(IWbemServices*)Unsafe.AsPointer(ref this), strObjectPath, lFlags, pCtx, &pObject, ppCallResult);
			ppObject = pObject;
			return hr;
		}

		internal int ExecQuery(
			IntPtr strQueryLanguage,
			IntPtr strQuery,
			int lFlags,
			IntPtr pCtx,
			out IEnumWbemClassObject* ppEnum)
		{
			IEnumWbemClassObject* pEnum;
			int hr = ((delegate* unmanaged<IWbemServices*, IntPtr, IntPtr, int, IntPtr, IEnumWbemClassObject**, int>)lpVtbl[20])(
				(IWbemServices*)Unsafe.AsPointer(ref this), strQueryLanguage, strQuery, lFlags, pCtx, &pEnum);
			ppEnum = pEnum;
			return hr;
		}

		internal int ExecMethod(
			IntPtr strObjectPath,
			IntPtr strMethodName,
			int lFlags,
			IntPtr pCtx,
			IWbemClassObject* pInParams,
			out IWbemClassObject* ppOutParams,
			IntPtr ppCallResult)
		{
			IWbemClassObject* pOutParams;
			int hr = ((delegate* unmanaged<IWbemServices*, IntPtr, IntPtr, int, IntPtr, IWbemClassObject*, IWbemClassObject**, IntPtr, int>)lpVtbl[24])(
				(IWbemServices*)Unsafe.AsPointer(ref this), strObjectPath, strMethodName, lFlags, pCtx, pInParams, &pOutParams, ppCallResult);
			ppOutParams = pOutParams;
			return hr;
		}
	}

	[StructLayout(LayoutKind.Sequential)]
	internal unsafe struct IEnumWbemClassObject
	{
		internal void** lpVtbl;

		internal uint Release()
		{
			return ((delegate* unmanaged<IEnumWbemClassObject*, uint>)lpVtbl[2])((IEnumWbemClassObject*)Unsafe.AsPointer(ref this));
		}

		internal int Next(
			int lTimeout,
			uint uCount,
			out IWbemClassObject* apObject,
			out uint puReturned)
		{
			IWbemClassObject* pObject;
			uint returned;
			int hr = ((delegate* unmanaged<IEnumWbemClassObject*, int, uint, IWbemClassObject**, uint*, int>)lpVtbl[4])(
				(IEnumWbemClassObject*)Unsafe.AsPointer(ref this), lTimeout, uCount, &pObject, &returned);
			apObject = pObject;
			puReturned = returned;
			return hr;
		}
	}

	[StructLayout(LayoutKind.Sequential)]
	internal unsafe struct IWbemClassObject
	{
		internal void** lpVtbl;

		internal uint Release()
		{
			return ((delegate* unmanaged<IWbemClassObject*, uint>)lpVtbl[2])((IWbemClassObject*)Unsafe.AsPointer(ref this));
		}

		internal int Get(
			IntPtr wszName,
			int lFlags,
			out VARIANT pVal,
			IntPtr pType,
			IntPtr plFlavor)
		{
			VARIANT val;
			int hr = ((delegate* unmanaged<IWbemClassObject*, IntPtr, int, VARIANT*, IntPtr, IntPtr, int>)lpVtbl[4])(
				(IWbemClassObject*)Unsafe.AsPointer(ref this), wszName, lFlags, &val, pType, plFlavor);
			pVal = val;
			return hr;
		}

		internal int Put(
			IntPtr wszName,
			int lFlags,
			IntPtr pVal,
			int Type)
		{
			return ((delegate* unmanaged<IWbemClassObject*, IntPtr, int, IntPtr, int, int>)lpVtbl[5])(
				(IWbemClassObject*)Unsafe.AsPointer(ref this), wszName, lFlags, pVal, Type);
		}

		internal int SpawnInstance(
			int lFlags,
			out IWbemClassObject* ppNewInstance)
		{
			IWbemClassObject* pNewInstance;
			int hr = ((delegate* unmanaged<IWbemClassObject*, int, IWbemClassObject**, int>)lpVtbl[15])(
				(IWbemClassObject*)Unsafe.AsPointer(ref this), lFlags, &pNewInstance);
			ppNewInstance = pNewInstance;
			return hr;
		}

		internal int GetMethod(
			IntPtr wszName,
			int lFlags,
			out IWbemClassObject* ppInSignature,
			out IWbemClassObject* ppOutSignature)
		{
			IWbemClassObject* pInSig;
			IWbemClassObject* pOutSig;
			int hr = ((delegate* unmanaged<IWbemClassObject*, IntPtr, int, IWbemClassObject**, IWbemClassObject**, int>)lpVtbl[19])(
				(IWbemClassObject*)Unsafe.AsPointer(ref this), wszName, lFlags, &pInSig, &pOutSig);
			ppInSignature = pInSig;
			ppOutSignature = pOutSig;
			return hr;
		}
	}
}
