
#nullable enable

namespace HardenWindowsSecurity
{
    public static class DeviceGuard
    {

        /// <summary>
        /// Applies the Device Guard category policies
        /// </summary>
        /// <exception cref="System.ArgumentNullException"></exception>
        public static void Invoke()
        {

            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🖥️ Device Guard");

            HardenWindowsSecurity.Logger.LogMessage("Running the Device Guard category", LogTypeIntel.Information);

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Device Guard Policies", "registry.pol"), LGPORunner.FileType.POL);

        }
    }
}
