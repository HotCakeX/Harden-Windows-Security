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

using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;

namespace HardenSystemSecurity.Protect;

/// <summary>
/// https://learn.microsoft.com/previous-versions/windows/desktop/bcd/bcdosloader-nxpolicy
/// bcdedit /enum
/// </summary>
internal static class BCDManager
{
	/// <summary>
	/// BcdOSLoaderInteger_NxPolicy
	/// </summary>
	private const uint NX_ELEMENT_TYPE_ID = 0x25000020;
	private const string CURRENT_ENTRY_GUID = "{fa926493-6f1c-4193-a414-58f0b2456d1e}";
	private const int STATUS_SUCCESS = 0;
	private const int STATUS_OBJECT_NAME_NOT_FOUND = unchecked((int)0xC0000034);

	[StructLayout(LayoutKind.Sequential)]
	private struct BcdElementDataType
	{
		internal uint Value;

		internal readonly uint Class => (Value >> 28) & 0xF;
		internal readonly uint Format => (Value >> 24) & 0xF;
		internal readonly uint SubType => Value & 0xFFFFFF;
	}

	internal static void SetNxElement(long value)
	{
		IntPtr storeHandle = IntPtr.Zero;
		IntPtr objectHandle = IntPtr.Zero;

		try
		{
			// Open the system BCD store
			int result = NativeMethods.BcdOpenSystemStore(out storeHandle);
			if (result != STATUS_SUCCESS)
			{
				int error = NativeMethods.RtlNtStatusToDosError(result);
				throw new Win32Exception(error, GlobalVars.GetStr("FailedToOpenBCDSystemStore"));
			}

			// Parse the current entry GUID
			if (!Guid.TryParse(CURRENT_ENTRY_GUID, CultureInfo.InvariantCulture, out Guid currentGuid))
			{
				throw new InvalidOperationException(GlobalVars.GetStr("FailedToParseCurrentEntryGUID"));
			}

			// Open the current BCD object
			result = NativeMethods.BcdOpenObject(storeHandle, ref currentGuid, out objectHandle);
			if (result != STATUS_SUCCESS)
			{
				if (result == STATUS_OBJECT_NAME_NOT_FOUND)
				{
					throw new InvalidOperationException(GlobalVars.GetStr("CurrentBootEntryNotFoundAdministrator"));
				}
				int error = NativeMethods.RtlNtStatusToDosError(result);
				throw new Win32Exception(error, GlobalVars.GetStr("FailedToOpenBCDObject"));
			}

			// Set the nx element
			SetIntegerElement(objectHandle, NX_ELEMENT_TYPE_ID, value);
		}
		finally
		{
			if (objectHandle != IntPtr.Zero)
			{
				_ = NativeMethods.BcdCloseObject(objectHandle);
			}
			if (storeHandle != IntPtr.Zero)
			{
				_ = NativeMethods.BcdCloseStore(storeHandle);
			}
		}
	}

	private static void SetIntegerElement(IntPtr objectHandle, uint elementType, long value)
	{
		IntPtr dataPtr = Marshal.AllocHGlobal(sizeof(long));
		try
		{
			Marshal.WriteInt64(dataPtr, value);

			int result = NativeMethods.BcdSetElementDataWithFlags(
				objectHandle,
				elementType,
				0, // flags
				dataPtr,
				sizeof(long));

			if (result != STATUS_SUCCESS)
			{
				int error = NativeMethods.RtlNtStatusToDosError(result);
				throw new Win32Exception(error, GlobalVars.GetStr("FailedToSetBCDElement"));
			}
		}
		finally
		{
			Marshal.FreeHGlobal(dataPtr);
		}
	}

	internal static long? GetNxElement()
	{
		IntPtr storeHandle = IntPtr.Zero;
		IntPtr objectHandle = IntPtr.Zero;

		try
		{
			int result = NativeMethods.BcdOpenSystemStore(out storeHandle);
			if (result != STATUS_SUCCESS)
			{
				return null;
			}

			if (!Guid.TryParse(CURRENT_ENTRY_GUID, CultureInfo.InvariantCulture, out Guid currentGuid))
			{
				return null;
			}

			result = NativeMethods.BcdOpenObject(storeHandle, ref currentGuid, out objectHandle);
			if (result != STATUS_SUCCESS)
			{
				return null;
			}

			return GetIntegerElement(objectHandle, NX_ELEMENT_TYPE_ID);
		}
		catch
		{
			return null;
		}
		finally
		{
			if (objectHandle != IntPtr.Zero)
			{
				_ = NativeMethods.BcdCloseObject(objectHandle);
			}
			if (storeHandle != IntPtr.Zero)
			{
				_ = NativeMethods.BcdCloseStore(storeHandle);
			}
		}
	}

	private static long? GetIntegerElement(IntPtr objectHandle, uint elementType)
	{
		uint dataSize = sizeof(long);
		IntPtr dataPtr = Marshal.AllocHGlobal((int)dataSize);
		try
		{
			int result = NativeMethods.BcdGetElementDataWithFlags(
				objectHandle,
				elementType,
				0, // flags
				dataPtr,
				ref dataSize);

			if (result == STATUS_SUCCESS)
			{
				return Marshal.ReadInt64(dataPtr);
			}
			return null;
		}
		catch
		{
			return null;
		}
		finally
		{
			Marshal.FreeHGlobal(dataPtr);
		}
	}
}
