#nullable enable

namespace HardenWindowsSecurity
{
    public static class WindowsUpdateConfigurations
    {
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🪟 Windows Update");

            HardenWindowsSecurity.Logger.LogMessage("Running the Windows Update category", LogTypeIntel.Information);

            HardenWindowsSecurity.Logger.LogMessage("Enabling restart notification for Windows update", LogTypeIntel.Information);
            HardenWindowsSecurity.RegistryEditor.EditRegistry(@"Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings", "RestartNotificationsAllowed2", "1", "DWORD", "AddOrModify");

            HardenWindowsSecurity.Logger.LogMessage("Applying the Windows Update Group Policies", LogTypeIntel.Information);
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Update Policies", "registry.pol"), LGPORunner.FileType.POL);

        }
    }
}
