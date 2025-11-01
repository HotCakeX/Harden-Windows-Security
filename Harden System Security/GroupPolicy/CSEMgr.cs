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

using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;

namespace HardenSystemSecurity.GroupPolicy;

/// <summary>
/// GroupPolicyObject wrapper.
/// Extension GUIDs and their friendlier names can be found here: Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{GUID}
///
/// </summary>
internal sealed partial class GroupPolicyObject : IDisposable
{
	private readonly IntPtr _gpoPointer;
	private readonly bool _shouldUninitializeCom; // Track if we should uninitialize COM on disposal
	private readonly bool _createdInSTAThread; // Track if COM object was created in a dedicated STA thread
	private bool _disposed;

	private static readonly Guid CLSID_GroupPolicyObject = new("EA502722-A23D-11d1-A7D3-0000F87571E3");
	private static readonly Guid IID_IGroupPolicyObject = new("EA502723-A23D-11d1-A7D3-0000F87571E3");

	/// <summary>
	/// Creates the GroupPolicyObject COM instance in STA apartment mode if needed
	/// </summary>
	/// <param name="clsid">The class ID of the Group Policy Object</param>
	/// <param name="iid">The interface ID to request</param>
	/// <returns>Pointer to the created COM object and flag indicating if created in dedicated STA thread</returns>
	private static (IntPtr gpoPointer, bool createdInSTAThread) CreateGroupPolicyObjectInSTA(Guid clsid, Guid iid)
	{
		// Check current apartment state
		if (Thread.CurrentThread.GetApartmentState() == ApartmentState.STA)
		{
			// We're already in STA, create directly
			int hr = NativeMethods.CoCreateInstance(
				in clsid,
				IntPtr.Zero,
				CSEMgr.CLSCTX_INPROC_SERVER,
				in iid,
				out IntPtr gpoPointer);

			if (hr != CSEMgr.S_OK)
			{
				string errorMessage = hr switch
				{
					unchecked((int)0x80004002) => "E_NOINTERFACE",
					unchecked((int)0x80040111) => "CLASS_E_CLASSNOTAVAILABLE:.",
					unchecked((int)0x80040154) => "REGDB_E_CLASSNOTREG: Group Policy class not registered.",
					_ => string.Format(GlobalVars.GetStr("FailedToCreateGroupPolicyObjectError"), hr)
				};
				throw new InvalidOperationException(errorMessage);
			}

			return (gpoPointer, false);
		}
		else
		{
			// We're in MTA, need to create in STA thread
			IntPtr resultPointer = IntPtr.Zero;
			Exception? creationException = null;

			Thread staThread = new(() =>
			{
				try
				{
					// Initialize COM in STA mode on this thread
					int initHr = NativeMethods.CoInitializeEx(IntPtr.Zero, CSEMgr.COINIT_APARTMENTTHREADED);
					if (initHr != CSEMgr.S_OK && initHr != CSEMgr.S_FALSE)
					{
						throw new InvalidOperationException(string.Format(GlobalVars.GetStr("FailedToInitializeCOMInSTAError"), initHr));
					}

					try
					{
						int hr = NativeMethods.CoCreateInstance(
							in clsid,
							IntPtr.Zero,
							CSEMgr.CLSCTX_INPROC_SERVER,
							in iid,
							out resultPointer);

						if (hr != CSEMgr.S_OK)
						{
							string errorMessage = hr switch
							{
								unchecked((int)0x80004002) => "E_NOINTERFACE",
								unchecked((int)0x80040111) => "CLASS_E_CLASSNOTAVAILABLE:.",
								unchecked((int)0x80040154) => "REGDB_E_CLASSNOTREG: Group Policy class not registered.",
								_ => string.Format(GlobalVars.GetStr("FailedToCreateGroupPolicyObjectError"), hr)
							};
							throw new InvalidOperationException(errorMessage);
						}
					}
					finally
					{
						// Don't uninitialize COM here as the object needs to stay alive
						// The object will manage its own COM lifetime
					}
				}
				catch (Exception ex)
				{
					creationException = ex;
				}
			})
			{
				IsBackground = false
			};

			staThread.SetApartmentState(ApartmentState.STA);
			staThread.Start();
			staThread.Join();

			if (creationException != null)
			{
				throw creationException;
			}

			if (resultPointer == IntPtr.Zero)
			{
				throw new InvalidOperationException(GlobalVars.GetStr("FailedToCreateGroupPolicyObjectNullPointerError"));
			}

			return (resultPointer, true);
		}
	}

	public GroupPolicyObject()
	{
		// Try to initialize COM, but handle the case where it's already initialized
		bool shouldUninitialize;
		int hr = NativeMethods.CoInitializeEx(IntPtr.Zero, CSEMgr.COINIT_APARTMENTTHREADED);

		if (hr == CSEMgr.S_OK)
		{
			// COM was successfully initialized by us
			shouldUninitialize = true;
		}
		else if (hr == CSEMgr.RPC_E_CHANGED_MODE)
		{
			// COM is already initialized in a different mode, continue without uninitializing
			shouldUninitialize = false;
		}
		else if (hr == CSEMgr.S_FALSE)
		{
			// COM is already initialized in same mode, don't uninitialize
			shouldUninitialize = false;
		}
		else
		{
			// Some other COM initialization error
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("FailedToInitializeCOMError"), hr));
		}

		_shouldUninitializeCom = shouldUninitialize;

		try
		{
			// Create the GroupPolicyObject COM instance, handling apartment issues
			(_gpoPointer, _createdInSTAThread) = CreateGroupPolicyObjectInSTA(CLSID_GroupPolicyObject, IID_IGroupPolicyObject);
		}
		catch
		{
			// Clean up COM if we initialized it
			if (_shouldUninitializeCom)
			{
				NativeMethods.CoUninitialize();
			}
			throw;
		}
	}

	public int OpenLocalMachineGPO(uint dwFlags)
	{
		ThrowIfDisposed();

		// Get the vtable pointer
		IntPtr vtablePtr = Marshal.ReadIntPtr(_gpoPointer);

		// Calculate method pointer offset
		// IUnknown methods: QueryInterface(0), AddRef(1), Release(2)
		// IGroupPolicyObject methods: New(3), OpenDSGPO(4), OpenLocalMachineGPO(5)
		IntPtr methodPtr = Marshal.ReadIntPtr(vtablePtr, 5 * IntPtr.Size);

		unsafe
		{
			// Direct unmanaged stdcall function pointer: (this, dwFlags) -> HRESULT(int)
			delegate* unmanaged[Stdcall]<IntPtr, uint, int> openLocalMachineGPO =
				(delegate* unmanaged[Stdcall]<IntPtr, uint, int>)methodPtr;

			return openLocalMachineGPO(_gpoPointer, dwFlags);
		}
	}

	public int Save(bool bMachine, bool bAdd, Guid pGuidExtension, Guid pGuid)
	{
		ThrowIfDisposed();

		// Get the vtable pointer
		IntPtr vtablePtr = Marshal.ReadIntPtr(_gpoPointer);

		// Calculate method pointer offset
		// IUnknown methods: QueryInterface(0), AddRef(1), Release(2)
		// IGroupPolicyObject methods: New(3), OpenDSGPO(4), OpenLocalMachineGPO(5), OpenRemoteMachineGPO(6), Save(7)
		IntPtr methodPtr = Marshal.ReadIntPtr(vtablePtr, 7 * IntPtr.Size);

		unsafe
		{
			// Signature: (this, int bMachine, int bAdd, GUID*, GUID*) -> HRESULT(int)
			delegate* unmanaged[Stdcall]<IntPtr, int, int, Guid*, Guid*, int> savePtr =
				(delegate* unmanaged[Stdcall]<IntPtr, int, int, Guid*, Guid*, int>)methodPtr;

			// Take addresses of the by-value parameters.
			return savePtr(
				_gpoPointer,
				bMachine ? 1 : 0,
				bAdd ? 1 : 0,
				&pGuidExtension,
				&pGuid);
		}
	}

	private void ThrowIfDisposed()
	{
		ObjectDisposedException.ThrowIf(_disposed, nameof(GroupPolicyObject));
	}

	public void Dispose()
	{
		if (!_disposed)
		{
			if (_gpoPointer != IntPtr.Zero)
			{
				// Release the COM object
				_ = Marshal.Release(_gpoPointer);
			}

			// Only uninitialize COM if we initialized it
			if (_shouldUninitializeCom)
			{
				NativeMethods.CoUninitialize();
			}

			_disposed = true;
		}
	}
}


internal static class CSEMgr
{

	internal const uint COINIT_APARTMENTTHREADED = 0x2;
	internal const uint CLSCTX_INPROC_SERVER = 0x1;
	internal const int S_OK = 0;
	internal const int S_FALSE = 1;
	internal const int RPC_E_CHANGED_MODE = unchecked((int)0x80010106); // COM already initialized in different mode

	private const uint GPO_OPEN_LOAD_REGISTRY = 0x00000001;

	// CSE GUIDs for machine extensions in order
	// CSE (Client Side Extension) GUID and (Administrative Side Extension) GUID pairs.
	private static readonly List<Guid> RequiredMachineExtensionsInOrder = [
		new Guid("2A8FDC61-2347-4C87-92F6-B05EB91A201A"), // Mitigation Options
		new Guid("35378EAC-683F-11D2-A89A-00C04FBBCFA2"), // Registry
		new Guid("4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3"), // Internet Explorer Zone Mapping
		new Guid("827D319E-6EAC-11D2-A4EA-00C04F79F83A"), // Security
		new Guid("D76B9641-3288-4F75-942D-087DE603E3EA"), // LAPS
		new Guid("F312195E-3D9D-447A-A3F5-08DFFA24735E"), // Device Guard Virtualization Based Security
		new Guid("F3CCC681-B74C-4060-9F26-CD84525DCA2A")  // Audit Policy Configuration
	];

	// CSE GUIDs for user extensions in order
	private static readonly List<Guid> RequiredUserExtensionsInOrder = [
		new Guid("2A8FDC61-2347-4C87-92F6-B05EB91A201A"), // Mitigation Options
		new Guid("35378EAC-683F-11D2-A89A-00C04FBBCFA2"), // Registry
		new Guid("4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3"), // Internet Explorer Zone Mapping
		new Guid("F312195E-3D9D-447A-A3F5-08DFFA24735E"), // Device Guard Virtualization Based Security
		new Guid("F3CCC681-B74C-4060-9F26-CD84525DCA2A")  // Audit Policy Configuration
	];

	// NOTE:
	// This GUID: "DF3DC19F-F72C-4030-940E-4C2A65A6B612" which is used by the LGPO.exe is nothing special.
	// It's just a random GUID that is hardcoded into its code.

	/// <summary>
	/// The GUID to use for the 4th parameter (pGuid) in all calls.
	/// This is the GUID generated for the Harden System Security App and is unique to it.
	/// https://learn.microsoft.com/windows/win32/api/gpedit/nf-gpedit-igrouppolicyobject-save
	/// </summary>
	private static readonly Guid HWSAppAdminToolGUID = new("01985C43-EA44-749A-97FA-7BC348C33484");

	/// <summary>
	/// Registers all required CSE GUIDs for both machine and user configurations.
	/// Basically what's needed for the Harden System Security app's policies as well as Microsoft Security Baselines.
	/// Automatically creates the folder structure at "C:\Windows\System32\GroupPolicy" too if it doesn't exist, including the main POL files.
	/// Increases the version in the GPT.INI file every time.
	/// LGPO.exe also increases the version in that file every time it merges a POL file.
	/// Max value is 4294967295
	/// Lower 16 bits represent the user version.
	/// Upper 16 bits represent the machine version.
	/// It's okay if the value in the GPT.INI file exceeds the max value, it just rolls over. It is entirely managed by Windows.
	/// </summary>
	internal static void RegisterCSEGuids()
	{

		using GroupPolicyObject gpo = new();

		try
		{
			// Open the local machine GPO
			int result = gpo.OpenLocalMachineGPO(GPO_OPEN_LOAD_REGISTRY);
			if (result != 0) // S_OK = 0
			{
				throw new InvalidOperationException(string.Format(GlobalVars.GetStr("FailedToOpenLocalMachineGPOError"), result));
			}

			// Register machine CSE GUIDs
			// Logger.Write("Registering Machine CSE GUIDs:");
			RegisterExtensionGuids(gpo, RequiredMachineExtensionsInOrder, true);

			// Register user CSE GUIDs
			// Logger.Write("Registering User CSE GUIDs:");
			RegisterExtensionGuids(gpo, RequiredUserExtensionsInOrder, false);

			Thread.Sleep(1000);
		}
		catch (COMException ex)
		{
			Logger.Write(string.Format(GlobalVars.GetStr("COMExceptionMessage"), ex.Message, ex.HResult));
			throw;
		}
	}

	/// <summary>
	/// Registers a list of extension GUIDs using the IGroupPolicyObject::Save method
	/// </summary>
	/// <param name="gpo">The Group Policy Object instance</param>
	/// <param name="extensionGuids">List of CSE GUIDs to register</param>
	/// <param name="isMachine">True for machine configuration, false for user configuration</param>
	private static void RegisterExtensionGuids(GroupPolicyObject gpo, List<Guid> extensionGuids, bool isMachine)
	{
		string configurationType = isMachine ? "Machine" : "User";

		for (int i = 0; i < extensionGuids.Count; i++)
		{
			Guid extensionGuid = extensionGuids[i];

			//	Logger.Write($"  [{i + 1}/{extensionGuids.Count}] Registering {configurationType} CSE GUID: {extensionGuid:B}");

			try
			{
				// 1st param: isMachine (true for machine extensions, false for user extensions)
				// 2nd param: true
				// 3rd param: extensionGuid (the actual CSE GUID from the list)
				// 4th param: HWSAppAdminToolGUID
				int result = gpo.Save(
					bMachine: isMachine,
					bAdd: true,
					pGuidExtension: extensionGuid,
					pGuid: HWSAppAdminToolGUID);

				if (result != 0 && result != -2147024864) // S_OK = 0 And -2147024864 is for file in use.
				{
					throw new InvalidOperationException(string.Format(GlobalVars.GetStr("FailedToRegisterCSEGUIDError"), configurationType, extensionGuid, result));
				}

				// Logger.Write($"Successfully registered {configurationType} CSE GUID: {extensionGuid:B}");
			}
			catch (COMException ex)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("FailedToRegisterCSEGUIDCOMError"), configurationType, extensionGuid, ex.Message, ex.HResult));
				throw;
			}
		}
	}

}
