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
using System.Runtime.InteropServices.Marshalling;

namespace CipPreviewHandler;

// The COM class factory that produces CipPreviewHandler instances for the surrogate host.
[GeneratedComClass]
internal sealed partial class ClassFactory : CommonCore.Interop.IClassFactory
{
	public int CreateInstance(nint pUnkOuter, in Guid riid, out nint ppvObject)
	{
		ppvObject = 0;

		try
		{
			// Aggregation is not supported.
			if (pUnkOuter != 0)
				return HResults.CLASS_E_NOAGGREGATION;

			CipPreviewHandler handler = new();

			// Build the COM callable wrapper for the new object, then hand back the requested interface.
			nint unknown = Exports.ComWrappersInstance.GetOrCreateComInterfaceForObject(handler, CreateComInterfaceFlags.None);
			Guid iid = riid;
			int hr = Marshal.QueryInterface(unknown, in iid, out ppvObject);

			// Release our transient reference; the caller now owns the reference returned through ppvObject.
			_ = Marshal.Release(unknown);
			return hr;
		}
		catch
		{
			ppvObject = 0;
			return HResults.E_FAIL;
		}
	}

	// The module is never unloaded (see DllCanUnloadNow), so there is no server lock count to maintain.
	public int LockServer(int fLock) => HResults.S_OK;
}
