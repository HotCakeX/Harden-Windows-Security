#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class MiscellaneousConfigurations
    {
        public static void MiscellaneousConfigurations_WindowsProtectedPrint()
        {
            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Enabling Windows Protected Print", LogTypeIntel.Information);

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Miscellaneous Policies", "Windows Protected Print", "registry.pol"), LGPORunner.FileType.POL);

        }
    }
}
