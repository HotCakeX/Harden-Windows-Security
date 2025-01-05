using System;

namespace HardenWindowsSecurity;

public static partial class NonAdminCommands
{
	/// <summary>
	/// Applies Non-Admin security measures
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void Invoke()
	{
		ChangePSConsoleTitle.Set("🏷️ Non-Admins");

		Logger.LogMessage("Running the Non-Admin category", LogTypeIntel.Information);
		Logger.LogMessage("Applying the Non-Admin registry settings", LogTypeIntel.Information);

		foreach (HardeningRegistryKeys.CsvRecord Item in GlobalVars.RegistryCSVItems)
		{
			if (string.Equals(Item.Category, "NonAdmin", StringComparison.OrdinalIgnoreCase))
			{
				RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
			}
		}

	}
}
