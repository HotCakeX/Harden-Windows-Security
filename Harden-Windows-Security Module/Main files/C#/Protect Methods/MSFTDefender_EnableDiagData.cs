#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class MicrosoftDefender
    {
        public static void MSFTDefender_EnableDiagData()
        {

            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Enabling Optional Diagnostic Data", LogTypeIntel.Information);

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Microsoft Defender Policies", "Optional Diagnostic Data", "registry.pol"), LGPORunner.FileType.POL);

        }
    }
}
