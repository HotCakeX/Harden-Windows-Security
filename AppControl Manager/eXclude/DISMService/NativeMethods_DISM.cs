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

internal static partial class NativeMethods
{

	[LibraryImport("DismApi.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DismInitialize(
		DISMAPI.DismLogLevel LogLevel,
		[MarshalAs(UnmanagedType.LPWStr)] string? LogFilePath,
		[MarshalAs(UnmanagedType.LPWStr)] string? ScratchDirectory);

	[LibraryImport("DismApi.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DismOpenSession(
		[MarshalAs(UnmanagedType.LPWStr)] string ImagePath,
		[MarshalAs(UnmanagedType.LPWStr)] string? WindowsDirectory,
		[MarshalAs(UnmanagedType.LPWStr)] string? SystemDrive,
		out IntPtr Session);

	[LibraryImport("DismApi.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DismGetCapabilities(
	IntPtr Session,
	out IntPtr Capability,
	out uint Count);

	[LibraryImport("DismApi.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DismGetFeatures(
		IntPtr Session,
		[MarshalAs(UnmanagedType.LPWStr)] string? PackageName,
		DISMAPI.DismPackageIdentifier PackageIdentifier,
		out IntPtr FeatureList,
		out uint FeatureCount);

	[LibraryImport("DismApi.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DismGetFeatureInfo(
		IntPtr Session,
		[MarshalAs(UnmanagedType.LPWStr)] string FeatureName,
		[MarshalAs(UnmanagedType.LPWStr)] string? Identifier,
		DISMAPI.DismPackageIdentifier PackageIdentifier,
		out IntPtr FeatureInfo);

	[LibraryImport("DismApi.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DismEnableFeature(
		IntPtr Session,
		[MarshalAs(UnmanagedType.LPWStr)] string FeatureName,
		[MarshalAs(UnmanagedType.LPWStr)] string? Identifier,
		DISMAPI.DismPackageIdentifier PackageIdentifier,
		[MarshalAs(UnmanagedType.Bool)] bool Enable,
		IntPtr SourcePaths,
		uint SourcePathCount,
		[MarshalAs(UnmanagedType.Bool)] bool All,
		IntPtr CancelEvent,
		DISMAPI.DismProgressCallback ProgressCallback,
		IntPtr UserData);

	[LibraryImport("DismApi.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DismDisableFeature(
		IntPtr Session,
		[MarshalAs(UnmanagedType.LPWStr)] string FeatureName,
		[MarshalAs(UnmanagedType.LPWStr)] string? PackageName,
		DISMAPI.DismPackageIdentifier PackageIdentifier,
		IntPtr CancelEvent,
		DISMAPI.DismProgressCallback ProgressCallback,
		IntPtr UserData);

	[LibraryImport("DismApi.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DismDelete(IntPtr ptr);

	[LibraryImport("DismApi.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DismCloseSession(IntPtr Session);

	[LibraryImport("DismApi.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DismShutdown();

	[LibraryImport("DismApi.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DismRemoveCapability(
	IntPtr Session,
	string Name,
	IntPtr CancelEvent,
	DISMAPI.DismProgressCallback ProgressCallback,
	IntPtr UserData
	);

	// https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism/dismaddcapability
	[LibraryImport("DismApi.dll", EntryPoint = "DismAddCapability", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DismAddCapability(
		IntPtr Session,
		string Name,
		[MarshalAs(UnmanagedType.Bool)] bool LimitAccess,
		IntPtr SourcePaths, // PCWSTR* (pointer to array of strings)
		uint SourcePathCount,
		IntPtr CancelEvent,
		DISMAPI.DismProgressCallback ProgressCallback,
		IntPtr UserData
	);

	// https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism/dismgetcapabilityinfo
	[LibraryImport("DismApi.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DismGetCapabilityInfo(
		IntPtr Session,
		[MarshalAs(UnmanagedType.LPWStr)] string CapabilityName,
		out IntPtr CapabilityInfo);

}
