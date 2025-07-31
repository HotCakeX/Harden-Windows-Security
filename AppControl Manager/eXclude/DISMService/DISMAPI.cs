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

namespace DISMService;

internal static class DISMAPI
{
	/// <summary>
	/// Structure representing a capability, packed to match native layout (12 bytes)
	/// </summary>
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	internal struct DismCapability
	{
		internal IntPtr Name;                   // Pointer to the capability name (PCWSTR)
		internal DismPackageFeatureState State; // State of the capability (uint)
	}

	internal enum DismLogLevel
	{
		DismLogError = 0,
		DismLogErrorWarning,
		DismLogErrorWarningInfo,
		DismLogErrorWarningInfoDebug
	}

	internal enum DismPackageFeatureState
	{
		DismStateNotPresent = 0,
		DismStateUninstallPending = 1,
		DismStateStaged = 2,
		DismStateRemoved = 3,
		DismStateInstalled = 4,
		DismStateInstallPending = 5,
		DismStateSuperseded = 6,
		DismStatePartiallyInstalled = 7
	}

	internal enum DismRestartType
	{
		None = 0,
		Possible = 1,
		Required = 2
	}

	internal enum DismPackageIdentifier
	{
		DismPackageNone = 0
	}

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 4)]
	internal struct DismFeature
	{
		internal IntPtr FeatureName;
		internal DismPackageFeatureState State;
	}

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 4)]
	internal struct DismFeatureInfo
	{
		internal IntPtr FeatureName;
		internal DismPackageFeatureState FeatureState;
		internal IntPtr DisplayName;
		internal IntPtr Description;
		internal DismRestartType RestartRequired;
		internal IntPtr CustomProperty;
		internal uint CustomPropertyCount;
	}

	[UnmanagedFunctionPointer(CallingConvention.Winapi)]
	internal delegate void DismProgressCallback(
		uint Current,
		uint Total,
		IntPtr UserData
	);

	/// <summary>
	/// Structure representing capability info returned by DismGetCapabilityInfo
	/// </summary>
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 4)]
	internal struct DismCapabilityInfo
	{
		internal IntPtr Name;                     // Capability name (PCWSTR)
		internal DismPackageFeatureState State;   // State of the capability
		internal IntPtr DisplayName;              // Display name (PCWSTR)
		internal IntPtr Description;              // Description (PCWSTR)
		internal uint DownloadSize;               // Download size in bytes
		internal uint InstallSize;                // Install size in bytes
	}

	internal const string OnlineImage = "DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}";

	internal static void ProgressCallback(uint current, uint total, IntPtr userData)
	{
		Program.SendProgressCallback(current, total);
	}
}
