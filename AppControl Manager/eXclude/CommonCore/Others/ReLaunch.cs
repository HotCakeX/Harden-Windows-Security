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

namespace CommonCore.Others;

internal static unsafe class Relaunch
{
	internal enum Context : int
	{
		Elevated = 0x20000000, // Administrator privileges
		Unelevated = 0x00000000 // AO_NONE
	}

	/// <summary>
	/// Relaunches the application with the specified <see cref="Context"/> using the Rust implementation.
	/// </summary>
	/// <param name="aumid">Application User Model ID of the app to relaunch</param>
	/// <param name="arguments">Optional command line arguments for the app</param>
	/// <param name="context"></param>
	/// <returns>True if launch was successful</returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static bool Start(string aumid, string? arguments, Context context)
	{
		uint processId = 0;
		int hr = NativeMethods.launch_app(aumid, arguments, &processId, (int)context);

		if (hr < 0)
		{
			// Check for specific error code that indicates user cancelled UAC prompt
			if (context is Context.Elevated && hr == -2147023673) // ERROR_CANCELLED (0x800704C7)
			{
				Logger.Write(Atlas.GetStr("ElevationRequestCancelledByUserMessage"));
				return false;
			}

			// For other errors, log and throw exception
			Exception? ex = Marshal.GetExceptionForHR(hr);
			if (ex != null)
			{
				Logger.Write(ex);
			}

			throw new InvalidOperationException(
				string.Format(
					Atlas.GetStr("ActivationManagerFailedWithHRESULTMessage"),
					hr
				)
			);
		}

		return true;
	}
}
