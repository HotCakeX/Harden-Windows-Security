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
	/// <summary>
	/// Relaunches the application with Administrator privileges using Rust implementation.
	/// </summary>
	/// <param name="aumid">Application User Model ID of the app to relaunch</param>
	/// <param name="arguments">Optional command line arguments for the app</param>
	/// <returns>True if elevation was successful and user accepted the UAC prompt</returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static bool RelaunchAppElevated(string aumid, string? arguments = null)
	{
		uint processId = 0;
		int hr = NativeMethods.relaunch_app_elevated(aumid, arguments, &processId);

		if (hr < 0)
		{
			// Check for specific error code that indicates user cancelled UAC prompt
			if (hr == -2147023673) // ERROR_CANCELLED (0x800704C7)
			{
				Logger.Write(
					GlobalVars.GetStr("ElevationRequestCancelledByUserMessage")
				);
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
					GlobalVars.GetStr("ActivationManagerFailedWithHRESULTMessage"),
					(uint)hr
				)
			);
		}

		return true;
	}
}
