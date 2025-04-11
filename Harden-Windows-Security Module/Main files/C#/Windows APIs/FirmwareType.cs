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

namespace HardenWindowsSecurity;

internal static class FirmwareChecker
{

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-firmware_type
	internal enum FirmwareType
	{
		FirmwareTypeUnknown,
		FirmwareTypeBios,
		FirmwareTypeUefi,
		FirmwareTypeMax
	}

	// Check the firmware type
	internal static FirmwareType CheckFirmwareType()
	{
		if (NativeMethods.GetFirmwareType(out FirmwareType firmwareType))
		{
			return firmwareType;
		}
		// Return Unknown if unable to determine firmware type
		return FirmwareType.FirmwareTypeUnknown;
	}
}
