using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class MiscellaneousConfigurations
    {
        /// <summary>
        /// Only lets printers who are compatible with the new secure drivers to work
        /// </summary>
        /// <exception cref="ArgumentNullException"></exception>
        public static void MiscellaneousConfigurations_WindowsProtectedPrint()
        {
            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            Logger.LogMessage("Enabling Windows Protected Print", LogTypeIntel.Information);

            LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Miscellaneous Policies", "Windows Protected Print", "registry.pol"), LGPORunner.FileType.POL);

        }
    }
}
