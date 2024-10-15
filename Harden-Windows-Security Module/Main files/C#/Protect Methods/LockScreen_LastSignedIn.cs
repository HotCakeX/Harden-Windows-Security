#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class LockScreen
    {

        public static void LockScreen_LastSignedIn()
        {

            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Applying the Don't display last signed-in policy", LogTypeIntel.Information);
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Lock Screen Policies", "Don't display last signed-in", "GptTmpl.inf"), LGPORunner.FileType.INF);

        }
    }
}
