using System;
using System.IO;

namespace HardenWindowsSecurity;

public static partial class UserAccountControl
{
	/// <summary>
	/// Applies the Only Elevate Signed apps optional sub-category policy
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void UAC_OnlyElevateSigned()
	{
		Logger.LogMessage("Applying the Only elevate executables that are signed and validated policy", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "User Account Control UAC Policies", "Only elevate executables that are signed and validated", "GptTmpl.inf"), LGPORunner.FileType.INF);
	}
}
