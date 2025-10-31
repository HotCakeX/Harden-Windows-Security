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

namespace CommonCore.DISM;

/// <summary>
/// https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism/dismloglevel-enumeration
/// </summary>
internal enum DismLogLevel
{
	DismLogErrors = 0,
	DismLogErrorsWarnings = 1,
	DismLogErrorsWarningsInfo = 2
}

/// <summary>
/// https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism/dismpackageidentifier-enumeration
/// </summary>
internal enum DismPackageIdentifier
{
	DismPackageNone = 0,
	DismPackageName = 1,
	DismPackagePath = 2
}

/// <summary>
/// Structure representing a capability, packed to match native layout (12 bytes).
/// https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism/dismcapability
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct DismCapability
{
	internal IntPtr Name;                   // Pointer to the capability name (PCWSTR)
	internal DismPackageFeatureState State; // State of the capability (uint)
}

/// <summary>
/// https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism/dismpackagefeaturestate-enumeration
/// </summary>
internal enum DismPackageFeatureState
{
	DismStateNotPresent = 0,
	DismStateUninstallPending = 1,
	DismStateStaged = 2,
	DismStateRemoved = 3,
	DismStateInstalled = 4,
	DismStateInstallPending = 5,
	DismStateSuperseded = 6,
	DismStatePartiallyInstalled = 7,
	NotAvailableOnSystem = 1000 // This is for CBS/DISM HRESULT 0x800F080C 
}

/// <summary>
/// https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism/dismrestarttype-enumeration
/// </summary>
internal enum DismRestartType
{
	None = 0,
	Possible = 1,
	Required = 2
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
internal struct DismFeature
{
	internal IntPtr FeatureName;
	internal DismPackageFeatureState State;
}

/// <summary>
/// https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism/dismfeatureinfo-structure
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 4)]
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

/// <summary>
/// Structure representing capability info returned by DismGetCapabilityInfo.
/// https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism/dismcapabilityinfo
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 4)]
internal struct DismCapabilityInfo
{
	internal IntPtr Name;                     // Capability name (PCWSTR)
	internal DismPackageFeatureState State;   // State of the capability
	internal IntPtr DisplayName;              // Display name (PCWSTR)
	internal IntPtr Description;              // Description (PCWSTR)
	internal uint DownloadSize;               // Download size in bytes
	internal uint InstallSize;                // Install size in bytes
}

internal sealed class DISMOutput(string name, DismPackageFeatureState state, DISMResultType type, string description)
{
	internal string Name => name;
	internal DismPackageFeatureState State => state;
	internal DISMResultType Type => type;
	internal string Description => description;
}

internal enum DISMResultType
{
	Capability,
	Feature
}
