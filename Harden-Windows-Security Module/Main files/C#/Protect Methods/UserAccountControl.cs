#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class UserAccountControl
    {
        /// <summary>
        /// Runs the User Account Control (UAC) hardening category
        /// </summary>
        /// <exception cref="System.ArgumentNullException"></exception>
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("💎 UAC");

            HardenWindowsSecurity.Logger.LogMessage("Running the User Account Control category", LogTypeIntel.Information);
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "User Account Control UAC Policies", "GptTmpl.inf"), LGPORunner.FileType.INF);
        }
    }
}
