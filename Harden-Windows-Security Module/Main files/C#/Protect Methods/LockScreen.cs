using System;
using System.IO;

namespace HardenWindowsSecurity;

public static partial class LockScreen
{
	/// <summary>
	/// Applies the LockScreen category policies
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void Invoke()
	{
		ChangePSConsoleTitle.Set("💻 Lock Screen");

		Logger.LogMessage("Running the Lock Screen category", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Lock Screen Policies", "registry.pol"), LGPORunner.FileType.POL);
		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Lock Screen Policies", "GptTmpl.inf"), LGPORunner.FileType.INF);
	}
}
