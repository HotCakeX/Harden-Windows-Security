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

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;

namespace CipPreviewHandler;

// The unmanaged entry points that the OS COM runtime calls. These are the only exports of the DLL and are what make
// this Native AOT class library act as an in-process COM server. Registration is handled by the MSIX package
// manifest, so no DllRegisterServer/DllUnregisterServer exports are provided.
internal static unsafe class Exports
{
	// The stable CLSID of this preview handler. Also used as the [Guid] of CipPreviewHandler and must match the
	// com:Class Id in the SurrogateServer registration in Package.appxmanifest
	internal const string HandlerClsid = "C1F0A2D4-3B56-47E8-9A1C-2D8E5F6B0A73";

	// Parsed form of the CLSID, resolved once.
	internal static readonly Guid ClsidGuid = new(HandlerClsid);

	// A single ComWrappers instance is used to build COM callable wrappers for the factory and the handler.
	internal static readonly StrategyBasedComWrappers ComWrappersInstance = new();

	// This is an [UnmanagedCallersOnly] export, so a managed exception escaping it would terminate the host process.
	// The whole body is guarded and any error is turned into a failure HRESULT.
	[UnmanagedCallersOnly(EntryPoint = "DllGetClassObject", CallConvs = new[] { typeof(CallConvStdcall) })]
	internal static int DllGetClassObject(Guid* rclsid, Guid* riid, nint* ppv)
	{
		try
		{
			if (ppv is null)
				return HResults.E_POINTER;

			*ppv = 0;

			if (rclsid is null || riid is null)
				return HResults.E_POINTER;

			// Only our own CLSID is served.
			if (*rclsid != ClsidGuid)
				return HResults.CLASS_E_CLASSNOTAVAILABLE;

			ClassFactory factory = new();
			nint unknown = ComWrappersInstance.GetOrCreateComInterfaceForObject(factory, CreateComInterfaceFlags.None);
			Guid iid = *riid;
			int hr = Marshal.QueryInterface(unknown, in iid, out nint requested);
			_ = Marshal.Release(unknown);

			if (hr >= 0)
				*ppv = requested;

			return hr;
		}
		catch
		{
			if (ppv is not null)
				*ppv = 0;
			return HResults.E_FAIL;
		}
	}

	[UnmanagedCallersOnly(EntryPoint = "DllCanUnloadNow", CallConvs = new[] { typeof(CallConvStdcall) })]
	internal static int DllCanUnloadNow() =>
		// Native AOT libraries cannot be unloaded (FreeLibrary is unsupported for them), so we always keep the DLL
		// resident by returning S_FALSE. This is safe: the surrogate host process is short lived and frees the DLL
		// on exit. It is not a leak, just a resident module for the host's lifetime.
		HResults.S_FALSE;
}
