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
using Windows.Win32.Foundation;

namespace AppControlManager.Taskbar;

/// <summary>
/// A manual COM wrapper for ITaskbarList3.
/// This class wraps the native COM pointer and invokes methods via the COM vtable.
/// </summary>
/// <param name="pCom"></param>
internal unsafe sealed partial class TaskbarListWrapper(void* pCom) : ITaskbarList3, IDisposable
{
	/// <summary>
	/// Pointer to the native COM object, allowing interaction with COM components. It is used for managing native
	/// resources.
	/// </summary>
	private void* _pCom = pCom;

	/// <summary>
	/// Holds a pointer to the COM object's virtual function table (vtable). This enables calling native methods associated
	/// with the COM object.
	/// </summary>
	private readonly Vtbl* _vtbl = *(Vtbl**)pCom;

	// COM vtable layout for ITaskbarList3 (which inherits from IUnknown, ITaskbarList, and ITaskbarList2)
	// The layout below is based on:
	//   IUnknown (indices 0..2):
	//     0: QueryInterface
	//     1: AddRef
	//     2: Release
	//   ITaskbarList (indices 3..7):
	//     3: HrInit
	//     4: AddTab
	//     5: DeleteTab
	//     6: ActivateTab
	//     7: SetActiveAlt
	//   ITaskbarList2 (index 8):
	//     8: MarkFullscreenWindow
	//   ITaskbarList3 (indices 9..10):
	//     9:  SetProgressValue
	//    10:  SetProgressState
	[StructLayout(LayoutKind.Sequential)]
	private struct Vtbl
	{
		// IUnknown methods
		internal delegate* unmanaged[Stdcall]<void*, Guid*, void**, HRESULT> QueryInterface;     // index 0
		internal delegate* unmanaged[Stdcall]<void*, uint> AddRef;                               // index 1
		internal delegate* unmanaged[Stdcall]<void*, uint> Release;                              // index 2

		// ITaskbarList methods
		internal delegate* unmanaged[Stdcall]<void*, HRESULT> HrInit;                             // index 3
		internal delegate* unmanaged[Stdcall]<void*, IntPtr, HRESULT> AddTab;                     // index 4
		internal delegate* unmanaged[Stdcall]<void*, IntPtr, HRESULT> DeleteTab;                  // index 5
		internal delegate* unmanaged[Stdcall]<void*, IntPtr, HRESULT> ActivateTab;                // index 6
		internal delegate* unmanaged[Stdcall]<void*, IntPtr, HRESULT> SetActiveAlt;               // index 7

		// ITaskbarList2 method
		internal delegate* unmanaged[Stdcall]<void*, IntPtr, BOOL, HRESULT> MarkFullscreenWindow;  // index 8

		// ITaskbarList3 methods
		internal delegate* unmanaged[Stdcall]<void*, IntPtr, ulong, ulong, HRESULT> SetProgressValue; // index 9
		internal delegate* unmanaged[Stdcall]<void*, IntPtr, int, HRESULT> SetProgressState;          // index 10
																									  // (TBPFLAG is typically an enum represented as an int.)
	}

	/// <summary>
	/// Initializes the taskbar list by calling the HrInit method from the vtable (located at vtable slot index 3).
	/// </summary>
	/// <returns>Returns an integer indicating the success or failure of the initialization.</returns>
	int ITaskbarList3.HrInit()
	{
		return _vtbl->HrInit(_pCom);
	}

	/// <summary>
	/// Calls the SetProgressValue method (located at vtable slot index 9) to update the taskbar progress.
	/// </summary>
	/// <param name="hwnd">Specifies the handle to the window for which the progress is being updated.</param>
	/// <param name="completed">Indicates the amount of work that has been completed.</param>
	/// <param name="total">Represents the total amount of work to be done.</param>
	/// <returns>Returns an integer value indicating the result of the operation.</returns>
	int ITaskbarList3.SetProgressValue(IntPtr hwnd, ulong completed, ulong total)
	{
		return _vtbl->SetProgressValue(_pCom, hwnd, completed, total);
	}

	/// <summary>
	/// Releases the native COM pointer by calling Release on the vtable.
	/// </summary>
	void IDisposable.Dispose()
	{
		if (_pCom is not null)
		{
			_ = _vtbl->Release(_pCom);
			_pCom = null;
		}
	}
}
