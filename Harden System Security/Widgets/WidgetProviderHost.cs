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
using System.Threading;

namespace HardenSystemSecurity.Widgets;

/// <summary>
/// Hosts the out of process widget provider COM server inside of the very same executable as the app itself.
/// The Widgets Board launches the app with a dedicated command line argument.
/// https://learn.microsoft.com/windows/apps/develop/widgets/implement-widget-provider-cs
/// </summary>
internal static class WidgetProviderHost
{
	/// <summary>
	/// The argument that the package manifest passes to the executable when the Widgets Board activates the COM server.
	/// </summary>
	internal const string ComServerArgument = "-RegisterProcessAsComServer";

	/// <summary>
	/// Must be identical to the CLSID that the package manifest declares for the widget provider.
	/// </summary>
	private static readonly Guid WidgetProviderClsid = new("1483997C-ECDF-42F9-842A-87C912F13155");

	// https://learn.microsoft.com/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx
	private const uint CLSCTX_LOCAL_SERVER = 0x4;

	// https://learn.microsoft.com/windows/win32/api/combaseapi/ne-combaseapi-regcls
	private const uint REGCLS_MULTIPLEUSE = 0x1;

	// https://learn.microsoft.com/windows/win32/api/objbase/ne-objbase-coinit
	private const uint COINIT_MULTITHREADED = 0x0;

	// How often the memory of the process is reclaimed while it serves pinned widgets. A minute keeps the working set of
	// the process visibly flat, and collecting a heap that only ever holds a few kilobytes of card payloads is free.
	private const int MemoryTrimIntervalMilliseconds = 60000;

	/// <summary>
	/// Registers the widget provider class object and blocks until the last pinned widget is removed.
	/// </summary>
	internal static void Run()
	{
		// The app's entry point is single threaded apartment because of XAML, but an out of process COM server that has no
		// message pump has to live in the multi threaded apartment, so the whole server runs on a dedicated MTA thread.
		Thread comServerThread = new(RunComServer)
		{
			Name = "HardenSystemSecurityWidgetProvider",
			IsBackground = false
		};

		comServerThread.SetApartmentState(ApartmentState.MTA);
		comServerThread.Start();
		comServerThread.Join();
	}

	private static void RunComServer()
	{
		int initializationResult = NativeMethods.CoInitializeEx(IntPtr.Zero, COINIT_MULTITHREADED);

		// S_FALSE simply means that the apartment was already initialized, which is not a failure.
		if (initializationResult < 0)
		{
			Logger.Write($"Widget provider: CoInitializeEx failed with HRESULT 0x{initializationResult:X8}", LogTypeIntel.Error);
			return;
		}

		IntPtr factoryPointer = IntPtr.Zero;
		uint registrationCookie = 0;

		try
		{
			StrategyBasedComWrappers comWrappers = new();
			WidgetProviderFactory factory = new();

			factoryPointer = comWrappers.GetOrCreateComInterfaceForObject(factory, CreateComInterfaceFlags.None);

			int registrationResult = NativeMethods.CoRegisterClassObject(
				in WidgetProviderClsid,
				factoryPointer,
				CLSCTX_LOCAL_SERVER,
				REGCLS_MULTIPLEUSE,
				out registrationCookie);

			if (registrationResult < 0)
			{
				registrationCookie = 0;
				Logger.Write($"Widget provider: CoRegisterClassObject failed with HRESULT 0x{registrationResult:X8}", LogTypeIntel.Error);
				return;
			}

			// Blocking until the Widgets Board reports that no instance of the widget is pinned anymore, waking up every
			// so often in order to give the memory of this long running background process a chance to be reclaimed.
			while (!WidgetProvider.NoWidgetsRemainingEvent.WaitOne(MemoryTrimIntervalMilliseconds))
			{
				TrimMemory();
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
		finally
		{
			if (registrationCookie != 0)
			{
				_ = NativeMethods.CoRevokeClassObject(registrationCookie);
			}

			if (factoryPointer != IntPtr.Zero)
			{
				_ = Marshal.Release(factoryPointer);
			}

			NativeMethods.CoUninitialize();
		}
	}

	/// <summary>
	/// Collects the managed memory of the process, runs the finalizers that release whatever COM objects the Widgets
	/// Board handed over in the meantime, and returns the freed pages to the operating system.
	///
	/// A headless provider that only builds a few kilobytes of JSON per tick allocates so little that a generation two
	/// collection would practically never happen on its own, which is what would otherwise let the working set of a
	/// process that runs for days keep creeping upwards.
	/// </summary>
	private static void TrimMemory()
	{
		try
		{
			GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);

			// The runtime callable wrappers of the COM objects that were released by the collection only let go of the
			// underlying native proxies once their finalizers ran, and the memory of those finalized objects is only
			// reclaimed by the collection that follows them.
			GC.WaitForPendingFinalizers();
			GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}
}
