using System;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class WindowsNetworking
    {
        /// <summary>
        ///  Runs the Windows Networking Hardening category
        /// </summary>
        /// <exception cref="System.ArgumentNullException"></exception>
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("📶 Networking");

            HardenWindowsSecurity.Logger.LogMessage("Running the Windows Networking category", LogTypeIntel.Information);

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Networking Policies", "registry.pol"), LGPORunner.FileType.POL);
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Networking Policies", "GptTmpl.inf"), LGPORunner.FileType.INF);

            HardenWindowsSecurity.Logger.LogMessage("Disabling LMHOSTS lookup protocol on all network adapters", LogTypeIntel.Information);
            HardenWindowsSecurity.RegistryEditor.EditRegistry(@"Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "EnableLMHOSTS", "0", "DWORD", "AddOrModify");

            HardenWindowsSecurity.Logger.LogMessage("Applying the Windows Networking registry settings", LogTypeIntel.Information);
#nullable disable
            foreach (HardeningRegistryKeys.CsvRecord Item in (HardenWindowsSecurity.GlobalVars.RegistryCSVItems))
            {
                if (string.Equals(Item.Category, "WindowsNetworking", StringComparison.OrdinalIgnoreCase))
                {
                    HardenWindowsSecurity.RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
                }
            }
#nullable enable

        }
    }
}
