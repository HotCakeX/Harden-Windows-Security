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

namespace CommonCore;

/// <summary>
/// Provides read-only access to selected fields in the user-mode KUSER_SHARED_DATA page.
/// </summary>
internal static class KUSER_SHARED_DATA
{
	// KUSER_SHARED_DATA is mapped read-only into every user-mode process at 0x7FFE0000.
	private const nuint UserSharedDataAddress = 0x7FFE0000;

	// SharedDataFlags is a 32-bit ULONG at offset 0x2F0 in KUSER_SHARED_DATA.
	private const nuint SharedDataFlagsOffset = 0x2F0;

	// SHARED_GLOBAL_FLAGS_SECURE_BOOT_ENABLED, which maps to DbgSecureBootEnabled.
	private const uint SecureBootEnabledMask = 0x00000080;

	/// <summary>
	/// Gets whether Windows reports Secure Boot as enabled in KUSER_SHARED_DATA.SharedDataFlags.
	/// </summary>
	internal static unsafe bool IsSecureBootEnabled =>
		(*(uint*)(UserSharedDataAddress + SharedDataFlagsOffset) & SecureBootEnabledMask) is not 0;

	internal static bool IsSecureBootDisabled => !IsSecureBootEnabled;
}
