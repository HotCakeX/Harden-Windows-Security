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
using Windows.Win32.Foundation;
using Windows.Win32.System.Com;

namespace AppControlManager.Taskbar;

/// <summary>
/// A static class that provides methods to create and update taskbar progress.
/// This class encapsulates the process of creating the COM object and updating its progress value.
/// </summary>
internal static unsafe partial class TaskBarProgress
{

	// https://learn.microsoft.com/windows/win32/api/shobjidl_core/nf-shobjidl_core-itaskbarlist3-setprogressvalue
	// https://learn.microsoft.com/windows/win32/api/shobjidl_core/nn-shobjidl_core-itaskbarlist3

	/// <summary>
	/// Represents the flag for an in-process server in COM (Component Object Model) programming. It indicates that the
	/// server runs in the same process as the client.
	/// </summary>
	private const uint CLSCTX_INPROC_SERVER = 1;

	/// <summary>
	/// Represents the CLSID for the TaskbarList COM object, used for interacting with the Windows taskbar.
	/// </summary>
	private static readonly Guid CLSID_TaskbarList = new("56FDF344-FD6D-11d0-958A-006097C9A090");

	/// <summary>
	/// A static object used to synchronize access to the UpdateTaskbarProgress method.
	/// </summary>
	private static readonly System.Threading.Lock _updateLock = new();

	/// <summary>
	/// Creates an instance of ITaskbarList3 wrapped in our manual COM wrapper.
	/// </summary>
	/// <returns>an object that implements ITaskbarList3, which lets us set the taskbar progress.</returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static ITaskbarList3 CreateTaskbarList()
	{
		// The IID for ITaskbarList3.
		Guid iidTaskbarList3 = new("C43DC798-95D1-4BEA-9030-BB99E2983A1A");

		// Calls the CsWin32-generated CoCreateInstance to create the COM object for the taskbar.
		// Note: Built-in COM marshalling is disabled in Native AOT, which is why we manually wrap the pointer.
		HRESULT hr = Windows.Win32.PInvoke.CoCreateInstance(
			in CLSID_TaskbarList,
			(IUnknown*)IntPtr.Zero,
			(CLSCTX)CLSCTX_INPROC_SERVER,
			in iidTaskbarList3,
			out void* pTaskbarListVoid);

		if (hr.Failed)
		{
			// If CoCreateInstance fails, throw an exception with the HRESULT error code.
			throw new InvalidOperationException($"CoCreateInstance failed, HRESULT: 0x{hr:X}");
		}

		// Manually wrap the raw COM pointer in our managed COM wrapper.
		TaskbarListWrapper taskbarList = new(pTaskbarListVoid);

		// Initialize the taskbar list by calling HrInit on the interface.
		hr = (HRESULT)((ITaskbarList3)taskbarList).HrInit();
		if (hr < 0)
		{
			// If initialization fails, dispose of the COM wrapper and throw an exception.
			((IDisposable)taskbarList).Dispose();

			throw new InvalidOperationException($"ITaskbarList3.HrInit failed, HRESULT: 0x{hr:X}");
		}

		// Return the initialized COM interface wrapped in our managed object.
		return taskbarList;
	}

	/// <summary>
	/// Updates the taskbar progress for a specified window using completion and total values.
	/// </summary>
	/// <param name="hwnd">The handle of the window for which the taskbar progress is being updated.</param>
	/// <param name="completed">Represents the amount of work completed towards the total task.</param>
	/// <param name="total">Indicates the total amount of work to be completed.</param>
	internal static void UpdateTaskbarProgress(IntPtr hwnd, ulong completed, ulong total)
	{
		// Ensure that only one thread can execute this block at a time.
		lock (_updateLock)
		{

			// Get the taskbar interface using our wrapper.
			// This creates and initializes a new COM object instance for the taskbar progress.
			ITaskbarList3 taskbarList = CreateTaskbarList();

			try
			{
				// Set the progress value on the taskbar using the provided window handle and progress values.
				int hr = taskbarList.SetProgressValue(hwnd, completed, total);

				if (hr < 0)
				{
					// Handle the error as appropriate by logging the HRESULT value.
					Others.Logger.Write($"SetProgressValue failed with HRESULT: 0x{hr:X}");
				}
			}
			finally
			{
				// Dispose of the taskbarList wrapper when done to release the COM pointer.
				if (taskbarList is IDisposable disposable)
				{
					disposable.Dispose();
				}
			}
		}
	}
}
