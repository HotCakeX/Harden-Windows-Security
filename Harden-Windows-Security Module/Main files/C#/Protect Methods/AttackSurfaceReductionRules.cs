using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public class AttackSurfaceReductionRules
    {
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Running the Attack Surface Reduction Rules category", LogTypeIntel.Information);

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Attack Surface Reduction Rules Policies", "registry.pol"), LGPORunner.FileType.POL);
        }
    }
}
