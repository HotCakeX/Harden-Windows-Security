using System;
using System.IO;

namespace HardenWindowsSecurity;

public static partial class MicrosoftDefender
{
	/// <summary>
	/// Enables diagnostic data to ensure security components of the OS will be able to work as expected and communicate with the services
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void MSFTDefender_EnableDiagData()
	{
		Logger.LogMessage("Enabling Optional Diagnostic Data", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Microsoft Defender Policies", "Optional Diagnostic Data", "registry.pol"), LGPORunner.FileType.POL);
	}
}
