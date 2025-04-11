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
using System.IO;

namespace HardenWindowsSecurity;

public static class Program
{
	/// <summary>
	/// The hybrid design of the Harden Windows Security allows for debug/usage in PowerShell in VS Code and natively in Visual Studio.
	/// </summary>
	/// <param name="args"></param>
	public static void Main()
	{
		#region misc
		// The following are the required code that are handled in module manifest .psm1 file

		// Acts as PSScriptRoot assignment in the module manifest for the GlobalVars.path variable
		GlobalVars.path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Main files");

		// Save the valid values of the Protect-WindowsSecurity categories to a variable since the process can be time consuming and shouldn't happen every time the categories are fetched
		GlobalVars.HardeningCategorieX = ProtectionCategoriex.GetValidValues();

		// Prepare the environment and variables
		Initializer.Initialize();

		if (Environment.IsPrivilegedProcess)
		{
			ControlledFolderAccessHandler.Start(true, false);
			Miscellaneous.RequirementsCheck();
		}
		#endregion

		// Launch the GUI
		GUIHandOff.Boot();
	}
}
