using System;
using System.IO;

namespace HardenWindowsSecurity;

public static class Program
{
	/// <summary>
	/// You can use this method when working on the module in Visual Studio
	/// Simply press F5 and the UI will boot. The same can be done in Visual Studio Code in PowerShell environment.
	/// The hybrid design allows for both environments to be completely usable.
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

		GlobalVars.Offline = true;

		// Launch the GUI
		GUIHandOff.Boot();

	}
}
