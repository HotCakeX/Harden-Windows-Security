using System;
using System.IO;

namespace HardenWindowsSecurity
{
    public static class WindowsUpdateConfigurations
    {
        /// <summary>
        /// Applies Windows Update category
        /// </summary>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Invoke()
        {
            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🪟 Windows Update");

            Logger.LogMessage("Running the Windows Update category", LogTypeIntel.Information);

            Logger.LogMessage("Enabling restart notification for Windows update", LogTypeIntel.Information);
            RegistryEditor.EditRegistry(@"Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings", "RestartNotificationsAllowed2", "1", "DWORD", "AddOrModify");

            Logger.LogMessage("Applying the Windows Update Group Policies", LogTypeIntel.Information);
            LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Update Policies", "registry.pol"), LGPORunner.FileType.POL);

        }
    }
}
