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

namespace AppControlManager.Others;

internal static unsafe class ReLaunch
{

	// Won't work if Explorer.exe is not available like early in boot process

	/*
		AO_NONE (0x00000000)
		AO_DESIGNMODE (0x00000001)
		AO_NOERRORUI (0x00000002)
		AO_NOSPLASHSCREEN (0x00000004)
		AO_PRELAUNCH (0x02000000)

		AO_BACKGROUNDTASK (0x00010000)
		AO_REMEDIATION (0x00080000)
		AO_TERMINATEBEFOREACTIVATE (0x00200000)
		AO_NOFOREGROUND (0x01000000)
		AO_NOMINSPLASHSCREENTIMER (0x04000000)
		AO_EXTENDEDTIMEOUT (0x08000000)
		AO_COMPONENT (0x10000000)
		AO_ELEVATE (0x20000000)
		AO_HOSTEDVIEW (0x40000000)
	 */


	/// <summary>
	/// CLSCTX_LOCAL_SERVER (0x4) is used for out-of-process COM objects.
	/// </summary>
	private const uint CLSCTX_LOCAL_SERVER = 0x4;

	/// <summary>
	/// The CLSID of the Application Activation Manager.
	/// </summary>
	private static readonly Guid clsidApplicationActivationManager = new("45BA127D-10A8-46EA-8AB7-56EA9078943C");

	/// <summary>
	/// The command-line arguments to pass to the application.
	/// </summary>
	private static readonly string arguments = string.Empty;

	/// <summary>
	/// Relaunches the application with Administrator privileges
	/// </summary>
	/// <returns>True if elevation was successful and user accepted the UAC prompt</returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static bool Action()
	{
		// Create an instance of the Application Activation Manager.
		int hr = Windows.Win32.PInvoke.CoCreateInstance(
			clsidApplicationActivationManager,
			pUnkOuter: null,
			(Windows.Win32.System.Com.CLSCTX)CLSCTX_LOCAL_SERVER,
			out Windows.Win32.UI.Shell.IApplicationActivationManager* activationManager);

		if (hr < 0)
		{
			throw new InvalidOperationException(
				string.Format(
					GlobalVars.Rizz.GetString("CoCreateInstanceFailedHResultMessage"),
					(uint)hr
				)
			);
		}

		try
		{
			activationManager->ActivateApplication(
				App.AUMID,
				arguments,
				(Windows.Win32.UI.Shell.ACTIVATEOPTIONS)0x20000000,
				out uint processId);
		}
		catch (Exception ex) when (ex.HResult == -2147023673)
		{
			Logger.Write(
				GlobalVars.Rizz.GetString("ElevationRequestCancelledByUserMessage")
			);
			return false;
		}
		catch (Exception ex)
		{
			Logger.Write(ErrorWriter.FormatException(ex));
			throw new InvalidOperationException(
				string.Format(
					GlobalVars.Rizz.GetString("ActivationManagerFailedWithHRESULTMessage"),
					(uint)hr
				)
			);
		}
		finally
		{
			if (activationManager is not null)
			{
				_ = ((Windows.Win32.System.Com.IUnknown*)activationManager)->Release();
			}
		}

		return true;
	}
}
