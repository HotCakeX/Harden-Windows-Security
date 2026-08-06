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
using WinRT;

namespace HardenSystemSecurity.Widgets;

/// <summary>
/// The class factory that the COM runtime uses to hand the <see cref="WidgetProvider"/> to the Widgets Board.
/// </summary>
[GeneratedComClass]
internal sealed partial class WidgetProviderFactory : IClassFactory
{
	// https://learn.microsoft.com/windows/win32/com/com-error-codes-1
	private const int CLASS_E_NOAGGREGATION = unchecked((int)0x80040110);
	private const int E_NOINTERFACE = unchecked((int)0x80004002);
	private const int E_UNEXPECTED = unchecked((int)0x8000FFFF);
	private const int S_OK = 0;

	public int CreateInstance(IntPtr pUnkOuter, in Guid riid, out IntPtr ppvObject)
	{
		ppvObject = IntPtr.Zero;

		// Aggregation is not supported by the widget provider.
		if (pUnkOuter != IntPtr.Zero)
		{
			return CLASS_E_NOAGGREGATION;
		}

		IntPtr inspectablePointer = IntPtr.Zero;

		try
		{
			// The provider is a WinRT object, so CsWinRT creates the vtable for it, which also keeps the whole path AOT safe.
			inspectablePointer = MarshalInspectable<WidgetProvider>.FromManaged(WidgetProvider.Instance.Value);

			if (inspectablePointer == IntPtr.Zero)
			{
				return E_UNEXPECTED;
			}

			// Querying instead of comparing the requested IID against a hard coded list keeps this free of any reflection.
			return Marshal.QueryInterface(inspectablePointer, in riid, out ppvObject);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return E_NOINTERFACE;
		}
		finally
		{
			if (inspectablePointer != IntPtr.Zero)
			{
				_ = Marshal.Release(inspectablePointer);
			}
		}
	}

	public int LockServer(int fLock) => S_OK;
}
