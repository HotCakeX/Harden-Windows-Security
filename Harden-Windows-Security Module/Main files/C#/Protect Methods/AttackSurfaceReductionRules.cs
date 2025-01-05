using System;
using System.IO;

namespace HardenWindowsSecurity;

public static class AttackSurfaceReductionRules
{
	/// <summary>
	/// Applies Attack Surface Reduction rules
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void Invoke()
	{
		ChangePSConsoleTitle.Set("🪷 ASR Rules");

		Logger.LogMessage("Running the Attack Surface Reduction Rules category", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Attack Surface Reduction Rules Policies", "registry.pol"), LGPORunner.FileType.POL);
	}
}
