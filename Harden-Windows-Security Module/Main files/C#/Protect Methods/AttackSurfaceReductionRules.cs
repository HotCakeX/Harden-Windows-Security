#nullable enable

namespace HardenWindowsSecurity
{
    public static class AttackSurfaceReductionRules
    {
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🪷 ASR Rules");

            HardenWindowsSecurity.Logger.LogMessage("Running the Attack Surface Reduction Rules category", LogTypeIntel.Information);

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Attack Surface Reduction Rules Policies", "registry.pol"), LGPORunner.FileType.POL);
        }
    }
}
