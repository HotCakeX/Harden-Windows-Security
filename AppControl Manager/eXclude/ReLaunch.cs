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

// This class requires the following CsWin32 auto generated type in the NativeMethods.txt file: IApplicationActivationManager
internal static unsafe class ReLaunch
{

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
