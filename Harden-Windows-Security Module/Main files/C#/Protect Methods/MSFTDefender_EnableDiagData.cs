using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class MicrosoftDefender
    {
        public static void MSFTDefender_EnableDiagData()
        {

            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            Logger.LogMessage("Enabling Optional Diagnostic Data", LogTypeIntel.Information);

            LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Microsoft Defender Policies", "Optional Diagnostic Data", "registry.pol"), LGPORunner.FileType.POL);

        }
    }
}
