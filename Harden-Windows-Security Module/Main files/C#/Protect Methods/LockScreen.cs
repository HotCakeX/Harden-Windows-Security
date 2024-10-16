#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class LockScreen
    {
        public static void Invoke()
        {

            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("💻 Lock Screen");

            HardenWindowsSecurity.Logger.LogMessage("Running the Lock Screen category", LogTypeIntel.Information);

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Lock Screen Policies", "registry.pol"), LGPORunner.FileType.POL);
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Lock Screen Policies", "GptTmpl.inf"), LGPORunner.FileType.INF);
        }
    }
}
