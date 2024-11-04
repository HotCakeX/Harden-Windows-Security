using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class MiscellaneousConfigurations
    {
        /// <summary>
        /// Enables support for long paths in Windows for programs
        /// </summary>
        /// <exception cref="ArgumentNullException"></exception>
        public static void MiscellaneousConfigurations_LongPathSupport()
        {
            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            Logger.LogMessage("Enabling support for long paths", LogTypeIntel.Information);

            LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Miscellaneous Policies", "Long Path Support", "registry.pol"), LGPORunner.FileType.POL);

        }
    }
}
