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

using System.IO;
using System.Runtime.InteropServices;

namespace AppControlManager.Others;

internal static class ConfigureISGServices
{

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/services/service-security-and-access-rights#access-rights-for-the-service-control-manager
	/// </summary>
	private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw
	/// </summary>
	private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;


	/// <summary>
	/// Sets the start mode of a Windows service.
	/// </summary>
	/// <param name="serviceName">The short name of the service.</param>
	/// <param name="startType">Desired start type.</param>
	private static void SetServiceStartType(string serviceName, ServiceStartType startType)
	{
		IntPtr scmHandle = NativeMethods.OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);

		if (scmHandle == IntPtr.Zero)
		{
			int error = Marshal.GetLastPInvokeError();

			throw new IOException($"OpenSCManagerW failed with the error code: {error}");
		}

		try
		{
			IntPtr serviceHandle = NativeMethods.OpenServiceW(scmHandle, serviceName, SC_MANAGER_ALL_ACCESS);

			if (serviceHandle == IntPtr.Zero)
			{
				int error = Marshal.GetLastPInvokeError();

				throw new IOException($"OpenServiceW failed with the error code: {error}");
			}
			try
			{
				bool result = NativeMethods.ChangeServiceConfigW(
					serviceHandle,
					SERVICE_NO_CHANGE,                // Service type: no change
					(uint)startType,                  // New start type
					SERVICE_NO_CHANGE,                // Error control: no change
					null,                             // Binary path: no change
					null,                             // Load order group: no change
					IntPtr.Zero,                      // Tag ID: no change
					IntPtr.Zero,                      // Dependencies: no change
					null,                             // Account name: no change
					null,                             // Password: no change
					null                              // Display name: no change
				);

				if (!result)
				{
					int error = Marshal.GetLastPInvokeError();

					throw new IOException($"ChangeServiceConfigW failed with the error code: {error}");
				}
			}
			finally
			{
				_ = NativeMethods.CloseServiceHandle(serviceHandle);
			}
		}
		finally
		{
			_ = NativeMethods.CloseServiceHandle(scmHandle);
		}
	}

	/// <summary>
	/// Available service start types.
	/// </summary>
	private enum ServiceStartType : uint
	{
		Boot = 0x00000000,
		System = 0x00000001,
		Automatic = 0x00000002,
		Manual = 0x00000003,
		Disabled = 0x00000004
	}


	/// <summary>
	/// Starts the AppIdTel and sets the AppIDSvc service to auto start
	/// </summary>
	internal static void Configure()
	{
		Logger.Write(GlobalVars.GetStr("ConfiguringAndStartingRequiredIsgServicesMessage"));

		_ = ProcessStarter.RunCommand("appidtel.exe", "start");

		SetServiceStartType("appidsvc", ServiceStartType.Automatic);
	}
}
