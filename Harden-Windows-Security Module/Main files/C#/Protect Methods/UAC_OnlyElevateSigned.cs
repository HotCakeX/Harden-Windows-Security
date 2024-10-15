#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class UserAccountControl
    {
        /// <summary>
        /// Applies the Only Elevate Signed apps optional sub-category policy
        /// </summary>
        /// <exception cref="System.ArgumentNullException"></exception>
        public static void UAC_OnlyElevateSigned()
        {
            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Applying the Only elevate executables that are signed and validated policy", LogTypeIntel.Information);
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "User Account Control UAC Policies", "Only elevate executables that are signed and validated", "GptTmpl.inf"), LGPORunner.FileType.INF);
        }
    }
}
