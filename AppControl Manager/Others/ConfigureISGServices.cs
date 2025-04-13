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

namespace AppControlManager.Others;

internal static class ConfigureISGServices
{
	/// <summary>
	/// Starts the AppIdTel and sets the AppIDSvc service to auto start
	/// </summary>
	internal static void Configure()
	{
		Logger.Write("Configuring and starting the required ISG related services");


		/*

            // Start the AppID Service
            using ServiceController AppIDService = new("AppIDSvc");

            if (AppIDService.Status is not ServiceControllerStatus.Running)
            {
                Logger.Write("Starting the AppIDSvc service...");
                AppIDService.Start();
                AppIDService.WaitForStatus(ServiceControllerStatus.Running);
                Logger.Write("Service started successfully.");
            }
            else
            {
                Logger.Write("AppIDSvc Service is already running.");
            }

            */


		_ = ProcessStarter.RunCommand("appidtel.exe", "start");

		_ = ProcessStarter.RunCommand("sc.exe", "config appidsvc start=auto");

	}
}
