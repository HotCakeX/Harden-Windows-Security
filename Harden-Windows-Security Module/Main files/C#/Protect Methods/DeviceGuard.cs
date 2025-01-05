using System;
using System.IO;

namespace HardenWindowsSecurity;

public static partial class DeviceGuard
{

	/// <summary>
	/// Applies the Device Guard category policies
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void Invoke()
	{

		ChangePSConsoleTitle.Set("🖥️ Device Guard");

		Logger.LogMessage("Running the Device Guard category", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Device Guard Policies", "registry.pol"), LGPORunner.FileType.POL);

		Logger.LogMessage("Applying the Device Guard registry settings", LogTypeIntel.Information);

		foreach (HardeningRegistryKeys.CsvRecord Item in GlobalVars.RegistryCSVItems)
		{
			if (string.Equals(Item.Category, "DeviceGuard", StringComparison.OrdinalIgnoreCase))
			{
				RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
			}
		}

	}
}
