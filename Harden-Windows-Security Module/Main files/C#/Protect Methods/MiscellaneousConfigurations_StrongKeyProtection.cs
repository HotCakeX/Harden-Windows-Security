using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class MiscellaneousConfigurations
    {
        public static void MiscellaneousConfigurations_StrongKeyProtection()
        {
            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            Logger.LogMessage("Enabling force strong key protection policy", LogTypeIntel.Information);

            LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Miscellaneous Policies", "Strong key protection", "GptTmpl.inf"), LGPORunner.FileType.INF);

        }
    }
}
