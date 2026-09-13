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
using System.Threading;

namespace CipPreviewHandler;

// Owns the single shared window class used by every preview instance, plus the unmanaged window procedure.
// The window procedure retrieves the owning managed handler through a GCHandle stored in the window's user data.
internal static unsafe class PreviewWindowClass
{
	// The class name is process/module unique. It never changes.
	internal const string ClassName = "CipPreviewHandler.Window";

	// Sent during CreateWindowExW, before the call returns. Its lParam points at a CREATESTRUCTW whose first field
	// (lpCreateParams) carries the value passed as the CreateWindowExW lpParam.
	private const uint WM_NCCREATE = 0x0081;

	// Sent as the very last message a window receives while it is being destroyed. We use it as the single, reliable
	// point to release the strong GCHandle that ties the native window back to its managed handler instance.
	private const uint WM_NCDESTROY = 0x0082;

	private static readonly Lock Sync = new();
	private static bool s_registered;

	// This DLL's own module handle, used to register the class and create the windows.
	internal static nint ModuleHandle { get; private set; }

	// Kept alive for the module lifetime so the class name pointer passed to RegisterClassExW stays valid.
	private static nint s_classNamePtr;

	// Window class styles.
	private const uint CS_VREDRAW = 0x0001;
	private const uint CS_HREDRAW = 0x0002;

	// GetModuleHandleExW flags used to resolve this DLL's own module handle from a code address.
	private const uint GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x00000004;
	private const uint GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 0x00000002;

	// Standard arrow cursor id.
	private const nint IDC_ARROW = 32512;

	// GetWindowLongPtr / SetWindowLongPtr index for the per window user data slot (64 bit only builds).
	private const int GWLP_USERDATA = -21;

	// Window messages.
	private const uint WM_ERASEBKGND = 0x0014;
	private const uint WM_SIZE = 0x0005;

	/// <summary>
	/// Registers the window class exactly once for this module and loads the RichEdit library.
	/// </summary>
	internal static void EnsureRegistered()
	{
		if (s_registered)
			return;

		lock (Sync)
		{
			if (s_registered)
				return;

			// Load Msftedit.dll so the RICHEDIT50W (MSFTEDIT_CLASS) window class is registered before the preview
			// control is created. The module is left loaded for the lifetime of this DLL (which is itself resident).
			_ = NativeMethods.LoadLibraryW("Msftedit.dll");

			// Resolve the module handle from the address of the window procedure so window creation uses the
			// correct HINSTANCE (this DLL), not the host process.
			nint procAddress = (nint)(delegate* unmanaged[Stdcall]<nint, uint, nuint, nint, nint>)&WindowProc;
			_ = NativeMethods.GetModuleHandleExW(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				procAddress,
				out nint module);
			ModuleHandle = module;

			s_classNamePtr = Marshal.StringToHGlobalUni(ClassName);

			WNDCLASSEXW windowClass = default;
			windowClass.cbSize = unchecked((uint)sizeof(WNDCLASSEXW));
			windowClass.style = CS_HREDRAW | CS_VREDRAW;
			windowClass.lpfnWndProc = procAddress;
			windowClass.hInstance = module;
			windowClass.hCursor = NativeMethods.LoadCursorW(0, IDC_ARROW);
			windowClass.hbrBackground = 0;
			windowClass.lpszClassName = s_classNamePtr;

			// A zero atom means the class was not registered. That is fine if it already exists from a previous
			// registration in this module; window creation will still succeed by name.
			_ = NativeMethods.RegisterClassExW(in windowClass);

			s_registered = true;
		}
	}

	// The unmanaged window procedure. It must be a static method with no captured state, and it must NEVER let a
	// managed exception escape: an exception crossing this [UnmanagedCallersOnly] boundary would terminate the host
	// process (Explorer / prevhost). The entire body is guarded, then the message falls through to DefWindowProc so
	// the window keeps behaving normally.
	[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
	private static nint WindowProc(nint hwnd, uint msg, nuint wParam, nint lParam)
	{
		try
		{
			switch (msg)
			{
				case WM_NCCREATE:
					{
						// lParam points at a CREATESTRUCTW. Its first field (offset 0) is lpCreateParams, which is
						// the value handed to CreateWindowExW as lpParam (the GCHandle for the owning handler).
						if (lParam != 0)
						{
							nint createParams = *(nint*)lParam;
							if (createParams != 0)
								_ = NativeMethods.SetWindowLongPtrW(hwnd, GWLP_USERDATA, createParams);
						}

						// Fall through to DefWindowProc, which returns TRUE for WM_NCCREATE so creation continues.
						break;
					}

				case WM_ERASEBKGND:
					return 1;

				case WM_SIZE:
					{
						// Keep the child control filling the container as the preview pane is resized.
						CipPreviewHandler? handler = GetHandler(hwnd);
						if (handler is not null)
						{
							handler.ResizeChild(hwnd);
							return 0;
						}
						break;
					}

				case WM_NCDESTROY:
					{
						// The window owns the strong GCHandle for its whole lifetime. This is the last message the
						// window ever receives and it runs on the same thread that destroyed the window, so it is the
						// one safe place to both clear the handler's cached window handles and free the GCHandle.
						nint userData = NativeMethods.GetWindowLongPtrW(hwnd, GWLP_USERDATA);
						if (userData != 0)
						{
							GCHandle handle = GCHandle.FromIntPtr(userData);
							(handle.Target as CipPreviewHandler)?.NotifyWindowDestroyed(hwnd);
							handle.Free();
							_ = NativeMethods.SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
						}
						break;
					}

				default:
					break;
			}
		}
		catch
		{
		}

		return NativeMethods.DefWindowProcW(hwnd, msg, wParam, lParam);
	}

	// Resolves the owning handler instance from the window's user data slot. Never throws.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static CipPreviewHandler? GetHandler(nint hwnd)
	{
		try
		{
			nint userData = NativeMethods.GetWindowLongPtrW(hwnd, GWLP_USERDATA);
			if (userData == 0)
				return null;

			GCHandle handle = GCHandle.FromIntPtr(userData);
			return handle.Target as CipPreviewHandler;
		}
		catch
		{
			return null;
		}
	}
}
