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

namespace HardenSystemSecurity.GroupPolicy;

internal static class RefreshPolicies
{
	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-refreshpolicyex
	/// </summary>
	private const uint RP_FORCE = 0x00000001;

	internal static void Refresh()
	{

		// true = machine policy, RP_FORCE = force refresh
		bool result = NativeMethods.RefreshPolicyEx(true, RP_FORCE);

		if (!result)
		{
			int error = Marshal.GetLastPInvokeError();
			throw new InvalidOperationException($"RefreshPolicyEx failed with error code: {error}");
		}

		result = NativeMethods.RefreshPolicyEx(false, RP_FORCE);

		if (!result)
		{
			int error = Marshal.GetLastPInvokeError();
			throw new InvalidOperationException($"RefreshPolicyEx failed with error code: {error}");
		}

		// Using the Save method of the IGroupPolicyObject via this method once before and once after policies are applied, has same effect as gpupdate /force and is faster.
		CSEMgr.RegisterCSEGuids();

		// _ = ProcessStarter.RunCommand("gpupdate", "/force");

	}
}
