using System;
using System.IO;

namespace HardenWindowsSecurity;

public static partial class MiscellaneousConfigurations
{
	/// <summary>
	/// Enables support for long paths in Windows for programs
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void MiscellaneousConfigurations_LongPathSupport()
	{
		Logger.LogMessage("Enabling support for long paths", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Miscellaneous Policies", "Long Path Support", "registry.pol"), LGPORunner.FileType.POL);
	}
}
