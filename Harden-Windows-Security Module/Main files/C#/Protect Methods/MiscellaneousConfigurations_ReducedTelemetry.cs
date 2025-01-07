using System.IO;

namespace HardenWindowsSecurity;

public static partial class MiscellaneousConfigurations
{
	/// <summary>
	/// This sub-category applies the reduced telemetry policies on the system
	/// </summary>
	public static void MiscellaneousConfigurations_ReducedTelemetry()
	{
		Logger.LogMessage("Applying the Reduced Telemetry policies", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Miscellaneous Policies", "Reduced Telemetry", "registry.pol"), LGPORunner.FileType.POL);

	}
}
