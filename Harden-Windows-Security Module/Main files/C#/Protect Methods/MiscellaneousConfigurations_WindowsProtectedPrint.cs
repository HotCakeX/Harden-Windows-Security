using System;
using System.IO;

namespace HardenWindowsSecurity;

public static partial class MiscellaneousConfigurations
{
	/// <summary>
	/// Only lets printers who are compatible with the new secure drivers to work
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void MiscellaneousConfigurations_WindowsProtectedPrint()
	{
		Logger.LogMessage("Enabling Windows Protected Print", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Miscellaneous Policies", "Windows Protected Print", "registry.pol"), LGPORunner.FileType.POL);
	}
}
