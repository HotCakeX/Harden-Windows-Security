using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class DeviceGuard
    {

        /// <summary>
        /// Applies the Device Guard category policies
        /// </summary>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Invoke()
        {

            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🖥️ Device Guard");

            Logger.LogMessage("Running the Device Guard category", LogTypeIntel.Information);

            LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Device Guard Policies", "registry.pol"), LGPORunner.FileType.POL);

        }
    }
}
