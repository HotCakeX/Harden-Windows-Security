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

using System.Runtime.InteropServices;

namespace HardenSystemSecurity.Hardware;

[StructLayout(LayoutKind.Sequential)]
internal struct GpuInformation
{
	internal IntPtr name;
	internal IntPtr brand;
	internal uint vendor_id;
	internal uint device_id;
	internal IntPtr description;
	internal IntPtr manufacturer;
	internal IntPtr pnp_device_id;
	internal uint adapter_ram;
	internal IntPtr driver_version;
	internal IntPtr driver_date;
	internal int is_available; // Using int for better interop (bool -> int)
	internal uint config_manager_error_code;
	internal int error_code;
	internal IntPtr error_message;
}
