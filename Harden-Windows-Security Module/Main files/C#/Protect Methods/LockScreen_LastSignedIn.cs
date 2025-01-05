using System;
using System.IO;

namespace HardenWindowsSecurity;

public static partial class LockScreen
{
	/// <summary>
	/// Will not display who last signed into the device on lock screen
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void LockScreen_LastSignedIn()
	{
		Logger.LogMessage("Applying the Don't display last signed-in policy", LogTypeIntel.Information);
		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Lock Screen Policies", "Don't display last signed-in", "GptTmpl.inf"), LGPORunner.FileType.INF);
	}
}
