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

namespace HardenSystemSecurity.Hardware;

/// <summary>
/// Class that holds the GPU information in managed form from our Rust library that gives us <see cref="GpuInformation"/> Struct.
/// </summary>
internal sealed class GpuInfo(
	string name,
	string brand,
	uint vendorId,
	uint deviceId,
	string description,
	string manufacturer,
	string pnpDeviceId,
	uint adapterRam,
	string driverVersion,
	string driverDate,
	bool isAvailable,
	uint configManagerErrorCode,
	int errorCode,
	string errorMessage)
{
	internal string Name => name;
	internal string Brand => brand;
	internal uint VendorId => vendorId;
	internal uint DeviceId => deviceId;
	internal string Description => description;
	internal string Manufacturer => manufacturer;
	internal string PnpDeviceId => pnpDeviceId;
	internal uint AdapterRam => adapterRam;
	internal string DriverVersion => driverVersion;
	internal string DriverDate => driverDate;
	internal bool IsAvailable => isAvailable;
	internal uint ConfigManagerErrorCode => configManagerErrorCode;
	internal int ErrorCode => errorCode;
	internal string ErrorMessage => errorMessage;
}
