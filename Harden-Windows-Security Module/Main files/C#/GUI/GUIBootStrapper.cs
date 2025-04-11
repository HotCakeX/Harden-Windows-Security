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
using System.Threading;

namespace HardenWindowsSecurity;

public static class GUIHandOff
{
	/// <summary>
	/// Starts and takes control of the entire GUI bootstrapping, startup and exit workflows
	/// Can be started from PowerShell and C# environments.
	/// That means you can use this during development in both Visual Studio and Visual Studio Code.
	/// Runs everything in a new STA thread to satisfy the GUI requirements.
	/// </summary>
	public static void Boot()
	{
		Thread thread = new(() =>
		{
			try
			{
				// Initialize and run the WPF GUI
				GUIMain.LoadMainXaml();
				_ = GUIMain.app.Run(GUIMain.mainGUIWindow);
			}
			catch (Exception ex)
			{
				Logger.LogMessage($"An error occurred: {ex.Message}", LogTypeIntel.Error);
				throw;
			}
			finally
			{
				// Ensure proper cleanup
				ControlledFolderAccessHandler.Reset();
				Miscellaneous.CleanUp();
			}
		});

		thread.SetApartmentState(ApartmentState.STA);
		thread.Start();
		thread.Join();
	}
}
