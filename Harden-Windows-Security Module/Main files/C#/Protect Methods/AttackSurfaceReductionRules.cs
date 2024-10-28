using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class AttackSurfaceReductionRules
    {
        public static void Invoke()
        {
            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🪷 ASR Rules");

            Logger.LogMessage("Running the Attack Surface Reduction Rules category", LogTypeIntel.Information);

            LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Attack Surface Reduction Rules Policies", "registry.pol"), LGPORunner.FileType.POL);
        }
    }
}
