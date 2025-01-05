using System;
using System.IO;

namespace HardenWindowsSecurity;

public static partial class WindowsNetworking
{
	/// <summary>
	///  Runs the Windows Networking Hardening category
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void Invoke()
	{

		ChangePSConsoleTitle.Set("📶 Networking");

		Logger.LogMessage("Running the Windows Networking category", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Networking Policies", "registry.pol"), LGPORunner.FileType.POL);
		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Networking Policies", "GptTmpl.inf"), LGPORunner.FileType.INF);

		Logger.LogMessage("Disabling LMHOSTS lookup protocol on all network adapters", LogTypeIntel.Information);
		RegistryEditor.EditRegistry(@"Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "EnableLMHOSTS", "0", "DWORD", "AddOrModify");

		Logger.LogMessage("Applying the Windows Networking registry settings", LogTypeIntel.Information);

		foreach (HardeningRegistryKeys.CsvRecord Item in GlobalVars.RegistryCSVItems)
		{
			if (string.Equals(Item.Category, "WindowsNetworking", StringComparison.OrdinalIgnoreCase))
			{
				RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
			}
		}

	}
}
