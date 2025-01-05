using System;
using System.IO;

namespace HardenWindowsSecurity;

public static partial class MiscellaneousConfigurations
{
	/// <summary>
	/// Enables strong key protection for saved certificates with private keys
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void MiscellaneousConfigurations_StrongKeyProtection()
	{
		Logger.LogMessage("Enabling force strong key protection policy", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Miscellaneous Policies", "Strong key protection", "GptTmpl.inf"), LGPORunner.FileType.INF);
	}
}
