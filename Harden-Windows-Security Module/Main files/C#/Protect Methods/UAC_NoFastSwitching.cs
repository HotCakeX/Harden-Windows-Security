using System;
using System.IO;

namespace HardenWindowsSecurity;

public static partial class UserAccountControl
{
	/// <summary>
	/// Applies the No Fast User Switching optional sub-category policy
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void UAC_NoFastSwitching()
	{
		Logger.LogMessage("Applying the Hide the entry points for Fast User Switching policy", LogTypeIntel.Information);
		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "User Account Control UAC Policies", "Hides the entry points for Fast User Switching", "registry.pol"), LGPORunner.FileType.POL);
	}
}
