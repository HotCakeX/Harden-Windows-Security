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

using System;
using System.Runtime.InteropServices;

namespace HardenWindowsSecurity;

/// <summary>
/// bootDMAProtection check - checks for Kernel DMA Protection status in System information or msinfo32
/// can be used to find out if the DMA Protection is ON \ OFF.
/// will show this by emitting 1 for True (Kernel DMA Protection Available) and 0 for False (Kernel DMA Protection Not Available)
/// </summary>
internal static class SystemInformationClass
{
	internal enum SYSTEM_DMA_GUARD_POLICY_INFORMATION : int
	{
		SystemDmaGuardPolicyInformation = 202
	}

	internal static byte BootDmaCheck()
	{
		Int32 result;
		Int32 SystemInformationLength = 1;
		IntPtr SystemInformation = Marshal.AllocHGlobal(SystemInformationLength);

		// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
		result = NativeMethods.NtQuerySystemInformation(
			SYSTEM_DMA_GUARD_POLICY_INFORMATION.SystemDmaGuardPolicyInformation,
			SystemInformation,
			SystemInformationLength,
			out _);

		if (result == 0)
		{
			byte info = Marshal.ReadByte(SystemInformation, 0);
			Marshal.FreeHGlobal(SystemInformation);
			return info;
		}

		Marshal.FreeHGlobal(SystemInformation);
		return 0;
	}
}
